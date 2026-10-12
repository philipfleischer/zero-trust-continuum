package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/config"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/policy"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/svc"
)

// environmentFrom returns a config.Env that reads from variables instead of
// the process environment.
func environmentFrom(variables map[string]string) config.Env {
	return config.NewWithLookup(func(name string) (string, bool) {
		value, found := variables[name]
		return value, found
	})
}

func TestRunStopsWhenContextIsCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	runResult := make(chan error, 1)
	go func() {
		runResult <- run(ctx, environmentFrom(map[string]string{"ZTC_LISTEN": "127.0.0.1:0"}), io.Discard)
	}()
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

func TestRunFailsOnInvalidConfiguration(t *testing.T) {
	err := run(context.Background(), environmentFrom(map[string]string{"ZTC_LOG_LEVEL": "verbose"}), io.Discard)
	if err == nil {
		t.Fatal("run accepted ZTC_LOG_LEVEL=verbose")
	}
}

// startServer starts the complete service, operational endpoints included, with
// the given environment.
func startServer(t *testing.T, variables map[string]string) *httptest.Server {
	t.Helper()
	environment := environmentFrom(variables)
	service, err := svc.New("ztc-pdp", environment, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	app, checks, err := setup(environment, service)
	if err != nil {
		t.Fatalf("setup() = %v", err)
	}
	server := httptest.NewServer(service.Handler(app, checks))
	t.Cleanup(server.Close)
	return server
}

// call sends a request and returns the status code and the body.
func call(t *testing.T, method, url, body, bearerToken string) (int, string) {
	t.Helper()
	request, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if bearerToken != "" {
		request.Header.Set("Authorization", "Bearer "+bearerToken)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, string(data)
}

const unknownPMU = `{"subject":{"id":"spiffe://grid.example/edge/pmu/1","layer":1,"zone":"bay-1"},
	"action":"write","resource":{"id":"bay-1/telemetry/1","type":"telemetry","zone":"bay-1","layer":1}}`

func TestServesDecisionsWithTheDefaultPolicy(t *testing.T) {
	server := startServer(t, nil)
	if code, body := call(t, "POST", server.URL+"/v1/decide", unknownPMU, ""); code != 200 || !strings.Contains(body, `"effect":"deny"`) {
		t.Errorf("POST /v1/decide = %d %s", code, body)
	}
	if code, _ := call(t, "GET", server.URL+"/readyz", "", ""); code != 200 {
		t.Errorf("GET /readyz = %d, want 200", code)
	}
	if _, body := call(t, "GET", server.URL+"/metrics", "", ""); !strings.Contains(body, `ztc_pdp_decisions_total{effect="deny"} 1`) {
		t.Errorf("/metrics has no deny counter:\n%s", body)
	}
	if code, _ := call(t, "PUT", server.URL+"/v1/emergency", `{"on":true}`, "anything"); code != 403 {
		t.Errorf("PUT /v1/emergency without ZTC_PDP_TOKEN = %d, want 403", code)
	}
}

func TestLoadsThePolicyFile(t *testing.T) {
	data, err := policy.Marshal(&policy.Policy{Version: 7, Rules: []policy.Rule{{ID: "allow-all", Effect: "allow"}}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	server := startServer(t, map[string]string{"ZTC_POLICY_FILE": path, "ZTC_PDP_TOKEN": "secret"})
	if _, body := call(t, "GET", server.URL+"/v1/policy", "", ""); !strings.Contains(body, `"version":7`) {
		t.Errorf("GET /v1/policy = %s, want version 7", body)
	}
	if code, _ := call(t, "PUT", server.URL+"/v1/emergency", `{"on":true}`, "secret"); code != 204 {
		t.Errorf("PUT /v1/emergency with the token = %d, want 204", code)
	}
}

func TestRefusesABrokenPolicyFile(t *testing.T) {
	broken := filepath.Join(t.TempDir(), "broken.json")
	if err := os.WriteFile(broken, []byte(`{"version":1,"rules":[{"id":"a","effect":"allow","sujbects":["x"]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{broken, filepath.Join(t.TempDir(), "missing.json")} {
		err := run(context.Background(), environmentFrom(map[string]string{"ZTC_POLICY_FILE": path, "ZTC_LISTEN": "127.0.0.1:0"}), io.Discard)
		if err == nil {
			t.Errorf("run started with ZTC_POLICY_FILE=%s", path)
		}
	}
}
