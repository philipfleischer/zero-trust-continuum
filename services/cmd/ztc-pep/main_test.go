// Tests for ztc-pep: the acceptance criteria of issue #16 against a real PDP,
// a stand-in for ztc-ca and an upstream, all in one process.

package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/config"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/pdp"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/policy"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/svc"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/token"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/trust"
)

// pdpToken is the write token of the PDP in these tests.
const pdpToken = "pdp-token-for-tests" //nolint:gosec // G101: a token for tests only

// environmentFrom returns a config.Env that reads from variables instead of
// the process environment.
func environmentFrom(variables map[string]string) config.Env {
	return config.NewWithLookup(func(name string) (string, bool) {
		value, found := variables[name]
		return value, found
	})
}

// chain is everything around the PEP: the PDP, a key set server standing in
// for ztc-ca, the upstream, and the variables that point the PEP at them.
type chain struct {
	decisionPoint *pdp.PDP
	pdpServer     *httptest.Server
	signer        token.Signer
	variables     map[string]string
}

func newChain(t *testing.T) *chain {
	t.Helper()
	// The PDP runs with the operational endpoints of svc, like ztc-pdp, so
	// the PEP's readiness check finds /healthz.
	decisionPoint := pdp.New("cloud-pdp", policy.NewEngine(policy.DefaultSubstationPolicy()))
	pdpService, err := svc.New("ztc-pdp", environmentFrom(nil), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	pdpAPI := pdp.NewHandler(decisionPoint, pdpToken, pdpService.Metrics)
	pdpServer := httptest.NewServer(pdpService.Handler(pdpAPI, nil))
	t.Cleanup(pdpServer.Close)

	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keySet := token.JSONWebKeySet{Keys: []token.JSONWebKey{token.NewJSONWebKey(publicKey)}}
	keyServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(writer).Encode(keySet)
	}))
	t.Cleanup(keyServer.Close)

	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte("stored"))
	}))
	t.Cleanup(upstream.Close)

	routesPath := writeFile(t, "routes.json", `[{"prefix": "/bay-1/telemetry/", "upstream": "`+upstream.URL+
		`", "resourceType": "telemetry", "zone": "bay-1", "layer": "fog", "sensitivity": 1}]`)
	return &chain{
		decisionPoint: decisionPoint,
		pdpServer:     pdpServer,
		signer:        token.Signer{KeyID: token.KeyIDOf(publicKey), Key: privateKey},
		variables: map[string]string{
			"ZTC_PEP_ROUTES_FILE": routesPath,
			"ZTC_PEP_SOURCE_ZONE": "substation-lan",
			"ZTC_PDP_URL":         pdpServer.URL,
			"ZTC_PDP_TOKEN":       pdpToken,
			"ZTC_CA_URL":          keyServer.URL,
		},
	}
}

// writeFile writes contents to a new file called name and returns its path.
func writeFile(t *testing.T, name, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// startPEP starts the complete PEP service, operational endpoints included.
func (chain *chain) startPEP(t *testing.T) *httptest.Server {
	t.Helper()
	environment := environmentFrom(chain.variables)
	service, err := svc.New("ztc-pep", environment, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	app, checks, err := setup(t.Context(), environment, service)
	if err != nil {
		t.Fatalf("setup() = %v", err)
	}
	server := httptest.NewServer(service.Handler(app, checks))
	t.Cleanup(server.Close)
	return server
}

// pmuToken is a token from the CA for the PMU of bay 1.
func (chain *chain) pmuToken(t *testing.T) string {
	t.Helper()
	now := time.Now()
	signedToken, err := chain.signer.Sign(token.Claims{
		Issuer:    "ztc-ca",
		Subject:   "spiffe://grid.example/edge/pmu/1",
		Audience:  []string{"ztc-pep"},
		ExpiresAt: now.Add(time.Minute).Unix(),
		IssuedAt:  now.Unix(),
		ID:        token.NewTokenID(),
		Zone:      "bay-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	return signedToken
}

// post sends a measurement through the PEP with authorization as the
// Authorization header and returns the status code.
func post(t *testing.T, server *httptest.Server, authorization string) int {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, server.URL+"/bay-1/telemetry/pmu-1", strings.NewReader(`{"voltage":230.1}`))
	if err != nil {
		t.Fatal(err)
	}
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	return response.StatusCode
}

// TestAcceptanceCriteria walks through the status codes issue #16 asks for,
// in the order the demo script shows them.
func TestAcceptanceCriteria(t *testing.T) {
	chain := newChain(t)
	server := chain.startPEP(t)
	bearer := "Bearer " + chain.pmuToken(t)

	if code := post(t, server, bearer); code != http.StatusOK {
		t.Errorf("valid token: %d, want 200", code)
	}
	if code := post(t, server, "Bearer not-a-token"); code != http.StatusUnauthorized {
		t.Errorf("invalid token: %d, want 401", code)
	}
	// The IDS reports the PMU as malicious, so its trust drops to 0.
	compromise := trust.Signal{Subject: "spiffe://grid.example/edge/pmu/1", Kind: trust.Behaviour, Value: 0.95, Source: "test-ids"}
	if _, err := chain.decisionPoint.RecordSignal(compromise); err != nil {
		t.Fatal(err)
	}
	if code := post(t, server, bearer); code != http.StatusForbidden {
		t.Errorf("low trust: %d, want 403", code)
	}
	chain.pdpServer.Close()
	if code := post(t, server, bearer); code != http.StatusServiceUnavailable {
		t.Errorf("PDP stopped: %d, want 503", code)
	}
}

func TestReadiness(t *testing.T) {
	chain := newChain(t)
	server := chain.startPEP(t)
	readyz := func() int {
		response, err := http.Get(server.URL + "/readyz")
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		return response.StatusCode
	}
	if code := readyz(); code != http.StatusOK {
		t.Errorf("/readyz with the PDP up: %d, want 200", code)
	}
	chain.pdpServer.Close()
	if code := readyz(); code != http.StatusServiceUnavailable {
		t.Errorf("/readyz with the PDP down: %d, want 503", code)
	}
}

func TestRefusesToStart(t *testing.T) {
	stoppedServer := httptest.NewServer(http.NotFoundHandler())
	stoppedServer.Close()
	tests := []struct {
		name   string
		change func(t *testing.T, variables map[string]string)
	}{
		{"no routes file", func(_ *testing.T, variables map[string]string) { delete(variables, "ZTC_PEP_ROUTES_FILE") }},
		{"routes file without routes", func(t *testing.T, variables map[string]string) {
			variables["ZTC_PEP_ROUTES_FILE"] = writeFile(t, "empty.json", `[]`)
		}},
		{"misspelt route field", func(t *testing.T, variables map[string]string) {
			variables["ZTC_PEP_ROUTES_FILE"] = writeFile(t, "misspelt.json",
				`[{"prefix": "/a/", "upstreem": "http://localhost:9000", "resourceType": "telemetry", "layer": "fog"}]`)
		}},
		{"route with an unknown layer", func(t *testing.T, variables map[string]string) {
			variables["ZTC_PEP_ROUTES_FILE"] = writeFile(t, "layer.json",
				`[{"prefix": "/a/", "upstream": "http://localhost:9000", "resourceType": "telemetry", "layer": "moon"}]`)
		}},
		{"route without a trailing slash", func(t *testing.T, variables map[string]string) {
			variables["ZTC_PEP_ROUTES_FILE"] = writeFile(t, "slash.json",
				`[{"prefix": "/a", "upstream": "http://localhost:9000", "resourceType": "telemetry", "layer": "fog"}]`)
		}},
		{"unknown PEP layer", func(_ *testing.T, variables map[string]string) { variables["ZTC_PEP_LAYER"] = "moon" }},
		{"unknown placement", func(_ *testing.T, variables map[string]string) { variables["ZTC_PLACEMENT"] = "edge" }},
		{"fog placement before M3", func(_ *testing.T, variables map[string]string) { variables["ZTC_PLACEMENT"] = "fog" }},
		{"CA unreachable", func(_ *testing.T, variables map[string]string) {
			variables["ZTC_CA_URL"] = stoppedServer.URL
			variables["ZTC_PEP_KEYS_WAIT"] = "100ms"
		}},
		{"missing capability root key", func(t *testing.T, variables map[string]string) {
			variables["ZTC_CAP_ROOT_KEY_FILE"] = filepath.Join(t.TempDir(), "missing.key")
		}},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			chain := newChain(t)
			testCase.change(t, chain.variables)
			chain.variables["ZTC_LISTEN"] = "127.0.0.1:0"
			// If run starts after all, it stops after two seconds and returns
			// nil, so a missing check fails the test instead of hanging it.
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err := run(ctx, environmentFrom(chain.variables), io.Discard); err == nil {
				t.Error("run started anyway")
			}
		})
	}
}

func TestRunStopsWhenContextIsCancelled(t *testing.T) {
	chain := newChain(t)
	chain.variables["ZTC_LISTEN"] = "127.0.0.1:0"
	ctx, cancel := context.WithCancel(context.Background())
	runResult := make(chan error, 1)
	go func() { runResult <- run(ctx, environmentFrom(chain.variables), io.Discard) }()
	time.Sleep(100 * time.Millisecond) // let it fetch the keys and start serving
	cancel()

	select {
	case err := <-runResult:
		if err != nil {
			t.Fatalf("run returned %v after cancel, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return after the context was cancelled")
	}
}
