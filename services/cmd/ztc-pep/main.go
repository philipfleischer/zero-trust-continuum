// Command ztc-pep is the Policy Enforcement Point of ZTC: a gateway in front
// of protected services that authenticates every request, asks the PDP and
// forwards the request only if it was allowed (NIST SP 800-207).
//
// Environment:
//
//	ZTC_LISTEN             address to listen on (default :8080)
//	ZTC_LOG_LEVEL          debug, info, warn or error (default info)
//	ZTC_PEP_NAME           name of this PEP, and the audience its tokens must
//	                       be issued for (default ztc-pep)
//	ZTC_PEP_ROUTES_FILE    the protected routes as JSON (required), see
//	                       deploy/pep/routes.json
//	ZTC_PEP_SOURCE_ZONE    the network zone the clients of this PEP are in;
//	                       unset means no rule that needs a source zone allows
//	ZTC_PEP_LAYER          the layer this PEP runs on (default fog)
//	ZTC_PDP_URL            the PDP (default http://localhost:8181)
//	ZTC_PDP_TOKEN          bearer token for trust signals; unset sends none
//	ZTC_PLACEMENT          cloud or hierarchical (default cloud), see RQ1
//	ZTC_PEP_CACHE_SIZE     decisions the hierarchical cache holds (default 4096)
//	ZTC_CA_URL             ztc-ca, whose GET /v1/keys verifies tokens
//	                       (default http://localhost:8090)
//	ZTC_PEP_KEYS_WAIT      how long to wait for ztc-ca at start (default 30s)
//	ZTC_CAP_ROOT_KEY_FILE  root key for capabilities; unset accepts none
//	ZTC_TRUST_DOMAIN       SPIFFE trust domain of the subjects (default grid.example)
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/config"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/model"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/observability"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/pdp"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/pep"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/svc"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/token"
)

// How often the verification keys are fetched again, and how much clock
// difference a token may have. The CA allows verifiers to cache its keys for
// five minutes.
const (
	keyRefreshInterval = 5 * time.Minute
	tokenLeeway        = 30 * time.Second
)

func main() {
	// Cancel the context on Ctrl+C (SIGINT) or when Docker or Kubernetes
	// stops the container (SIGTERM), so the server shuts down gracefully.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := run(ctx, config.New(), os.Stdout)
	stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, "ztc-pep:", err)
		os.Exit(1)
	}
}

// run starts the PEP and blocks until ctx is cancelled or the server fails.
// It takes its dependencies as parameters so tests can call it directly.
func run(ctx context.Context, environment config.Env, logOutput io.Writer) error {
	service, err := svc.New("ztc-pep", environment, logOutput)
	if err != nil {
		return err
	}
	app, checks, err := setup(ctx, environment, service)
	if err != nil {
		return err
	}
	return service.Serve(ctx, ":8080", app, checks)
}

// setup builds the PEP from the configuration and returns the proxy and its
// readiness checks. It waits for the first key set from ztc-ca, and refuses
// to start without one: a PEP that cannot verify tokens would only answer 401.
// The keys are refreshed until ctx is done.
func setup(ctx context.Context, environment config.Env, service *svc.Service) (http.Handler, map[string]observability.Check, error) {
	name := environment.String("pep_name", "ztc-pep")
	routesPath := environment.String("pep_routes_file", "")
	if routesPath == "" {
		return nil, nil, errors.New("ZTC_PEP_ROUTES_FILE is not set; see deploy/pep/routes.json")
	}
	routes, err := loadRoutes(routesPath)
	if err != nil {
		return nil, nil, err
	}
	layer, err := model.ParseLayer(environment.String("pep_layer", "fog"))
	if err != nil {
		return nil, nil, fmt.Errorf("ZTC_PEP_LAYER: %w", err)
	}
	placement, err := pdp.ParsePlacement(environment.String("placement", "cloud"))
	if err != nil {
		return nil, nil, err
	}

	pdpURL := environment.String("pdp_url", "http://localhost:8181")
	pdpToken := environment.String("pdp_token", "")
	cloudPDP := &pdp.RemoteClient{BaseURL: pdpURL, Token: pdpToken}
	decider, err := pep.DeciderFor(placement, cloudPDP, name+"-cache", environment.Int("pep_cache_size", 4096))
	if err != nil {
		return nil, nil, err
	}
	var signals pep.SignalSender
	if pdpToken != "" {
		signals = cloudPDP
	} else {
		service.Logger.Warn("ZTC_PDP_TOKEN is not set: no authentication signals, so new subjects have trust 0")
	}

	keys, err := fetchKeys(ctx, environment, name)
	if err != nil {
		return nil, nil, err
	}
	go keys.KeepFresh(ctx, keyRefreshInterval, service.Logger)

	var capabilityRootKey []byte
	if rootKeyPath := environment.String("cap_root_key_file", ""); rootKeyPath != "" {
		if capabilityRootKey, err = token.ReadSecretFile(rootKeyPath); err != nil {
			return nil, nil, err
		}
	}

	sourceZone := environment.String("pep_source_zone", "")
	if sourceZone == "" {
		service.Logger.Warn("ZTC_PEP_SOURCE_ZONE is not set: rules that need a source zone deny everything")
	}
	enforcer, err := pep.NewEnforcer(pep.Config{
		Name:   name,
		Routes: routes,
		Authenticator: pep.Authenticator{
			Tokens:            keys,
			CapabilityRootKey: capabilityRootKey,
			TrustDomain:       environment.String("trust_domain", "grid.example"),
			Layer:             layer,
		},
		Decider:    decider,
		SourceZone: sourceZone,
		Signals:    signals,
		Logger:     service.Logger,
		Metrics:    service.Metrics,
	})
	if err != nil {
		return nil, nil, err
	}
	service.Logger.Info("PEP ready", "name", name, "placement", placement, "pdp", pdpURL, "sourceZone", sourceZone,
		"capabilities", capabilityRootKey != nil)

	checks := map[string]observability.Check{
		"keys": func(context.Context) error {
			if !keys.Loaded() {
				return pep.ErrNoKeys
			}
			return nil
		},
		"pdp": func(ctx context.Context) error { return reachable(ctx, pdpURL+"/healthz") },
	}
	return pep.NewProxy(enforcer, nil), checks, nil
}

// fetchKeys returns the verification keys of ztc-ca for tokens issued to
// audience, trying once a second for up to ZTC_PEP_KEYS_WAIT: at start-up the
// CA may not be listening yet.
func fetchKeys(ctx context.Context, environment config.Env, audience string) (*pep.RemoteKeys, error) {
	keySetURL := environment.String("ca_url", "http://localhost:8090") + "/v1/keys"
	keys := pep.NewRemoteKeys(keySetURL, token.Verifier{Audience: audience, Leeway: tokenLeeway}, &http.Client{Timeout: 5 * time.Second})
	waitCtx, cancel := context.WithTimeout(ctx, environment.Duration("pep_keys_wait", 30*time.Second))
	defer cancel()
	for {
		err := keys.Refresh(waitCtx)
		if err == nil {
			return keys, nil
		}
		select {
		case <-waitCtx.Done():
			return nil, fmt.Errorf("no verification keys from %s: %w", keySetURL, err)
		case <-time.After(time.Second):
		}
	}
}

// reachable reports whether url answers 200, within ctx.
func reachable(ctx context.Context, url string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("%s answered %s", url, response.Status)
	}
	return nil
}
