// Command ztc-pdp is the Policy Decision Point of ZTC: the service a Policy
// Enforcement Point asks whether a request may go ahead (NIST SP 800-207).
//
// It serves the decision API of package pdp next to the operational endpoints
// /healthz, /readyz and /metrics.
//
// Environment:
//
//	ZTC_LISTEN        address to listen on (default :8181)
//	ZTC_LOG_LEVEL     debug, info, warn or error (default info)
//	ZTC_PDP_NAME      name in Decision.DecidedBy (default cloud-pdp)
//	ZTC_POLICY_FILE   JSON policy to load (default: the built-in substation policy)
//	ZTC_PDP_TOKEN     bearer token for signals, policy and emergency mode;
//	                  if unset, those endpoints are disabled
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

	"github.com/philipfleischer/zero-trust-continuum/services/internal/config"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/observability"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/pdp"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/policy"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/svc"
)

func main() {
	// Cancel the context on Ctrl+C (SIGINT) or when Docker or Kubernetes
	// stops the container (SIGTERM), so the server shuts down gracefully.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := run(ctx, config.New(), os.Stdout)
	stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, "ztc-pdp:", err)
		os.Exit(1)
	}
}

// run starts the PDP and blocks until ctx is cancelled or the server fails.
// It takes its dependencies as parameters so tests can call it directly.
func run(ctx context.Context, environment config.Env, logOutput io.Writer) error {
	service, err := svc.New("ztc-pdp", environment, logOutput)
	if err != nil {
		return err
	}
	app, checks, err := setup(environment, service)
	if err != nil {
		return err
	}
	return service.Serve(ctx, ":8181", app, checks)
}

// setup builds the PDP from the configuration and returns its HTTP API and
// readiness checks. A policy file that cannot be loaded is an error, so the
// service never starts with a policy the operator did not ask for.
func setup(environment config.Env, service *svc.Service) (http.Handler, map[string]observability.Check, error) {
	startPolicy := policy.DefaultSubstationPolicy()
	policySource := "built-in substation policy"
	if path := environment.String("policy_file", ""); path != "" {
		loaded, err := policy.LoadFile(path)
		if err != nil {
			return nil, nil, err
		}
		startPolicy, policySource = loaded, path
	}
	decisionPoint := pdp.New(environment.String("pdp_name", "cloud-pdp"), policy.NewEngine(startPolicy))

	token := environment.String("pdp_token", "")
	if token == "" {
		service.Logger.Warn("ZTC_PDP_TOKEN is not set: signals, policy and emergency endpoints are disabled")
	}
	service.Logger.Info("policy loaded", "source", policySource, "version", startPolicy.Version, "rules", len(startPolicy.Rules))

	checks := map[string]observability.Check{
		"policy": func(context.Context) error {
			if decisionPoint.Engine.Policy().Version == 0 {
				return errors.New("no policy installed")
			}
			return nil
		},
	}
	return pdp.NewHandler(decisionPoint, token, service.Metrics), checks, nil
}
