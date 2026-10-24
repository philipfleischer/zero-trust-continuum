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
	"github.com/philipfleischer/zero-trust-continuum/services/internal/svc"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/token"
)

// pmuSecret is the client secret of the PMU in the test clients file.
const pmuSecret = "pmu-1-secret-for-tests" //nolint:gosec // G101: a secret for tests only

// environmentFrom returns a config.Env that reads from variables instead of
// the process environment.
func environmentFrom(variables map[string]string) config.Env {
	return config.NewWithLookup(func(name string) (string, bool) {
		value, found := variables[name]
		return value, found
	})
}

// writeFile writes contents to name in directory and returns the path.
func writeFile(t *testing.T, directory, name, contents string) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// testSetup writes a signing key and a clients file with one PMU to a new
// directory and returns the environment variables that point to them.
func testSetup(t *testing.T) map[string]string {
	t.Helper()
	directory := t.TempDir()
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(directory, "ca.key")
	if err := token.WritePrivateKeyFile(keyPath, privateKey); err != nil {
		t.Fatal(err)
	}
	clientsPath := writeFile(t, directory, "clients.json", `{"clients": [{
		"secretSHA256": "`+secretHash(pmuSecret)+`",
		"subject": "spiffe://grid.example/edge/pmu/1",
		"audience": ["ztc-pep"],
		"scope": ["telemetry:write"]}]}`)
	return map[string]string{"ZTC_CA_KEY_FILE": keyPath, "ZTC_CA_CLIENTS_FILE": clientsPath}
}

// startServer starts the complete service, operational endpoints included.
func startServer(t *testing.T, variables map[string]string) *httptest.Server {
	t.Helper()
	environment := environmentFrom(variables)
	service, err := svc.New("ztc-ca", environment, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	app, err := setup(environment, service)
	if err != nil {
		t.Fatalf("setup() = %v", err)
	}
	server := httptest.NewServer(service.Handler(app, nil))
	t.Cleanup(server.Close)
	return server
}

// requestToken sends POST /v1/token with authorization as the Authorization
// header and returns the status code and the body.
func requestToken(t *testing.T, server *httptest.Server, authorization, body string) (int, string) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, server.URL+"/v1/token", strings.NewReader(body))
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
	defer func() { _ = response.Body.Close() }()
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, string(responseBody)
}

// fetchVerificationKeys reads GET /v1/keys the way a PEP will.
func fetchVerificationKeys(t *testing.T, server *httptest.Server) map[string]ed25519.PublicKey {
	t.Helper()
	response, err := http.Get(server.URL + "/v1/keys")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	var keySet token.JSONWebKeySet
	if err := json.NewDecoder(response.Body).Decode(&keySet); err != nil {
		t.Fatal(err)
	}
	keysByID, err := keySet.VerificationKeys()
	if err != nil {
		t.Fatal(err)
	}
	return keysByID
}

// TestTokenVerifiesWithPublishedKeys is the acceptance criterion of issue
// #15: a token from ztc-ca verifies with the key from GET /v1/keys.
func TestTokenVerifiesWithPublishedKeys(t *testing.T) {
	server := startServer(t, testSetup(t))
	code, body := requestToken(t, server, "Bearer "+pmuSecret, "")
	if code != http.StatusOK {
		t.Fatalf("POST /v1/token = %d %s", code, body)
	}
	var issued tokenResponse
	if err := json.Unmarshal([]byte(body), &issued); err != nil {
		t.Fatal(err)
	}

	verifier := token.Verifier{Keys: fetchVerificationKeys(t, server), Audience: "ztc-pep"}
	claims, err := verifier.Verify(issued.Token)
	if err != nil {
		t.Fatalf("token from ztc-ca rejected with the published keys: %v", err)
	}
	if claims.Subject != "spiffe://grid.example/edge/pmu/1" || claims.Issuer != "ztc-ca" || !claims.HasScope("telemetry:write") {
		t.Errorf("claims = %+v", claims)
	}
	if lifetime := claims.ExpiresAt - claims.IssuedAt; lifetime != 300 {
		t.Errorf("token lifetime = %d s, want 300", lifetime)
	}
	if issued.ExpiresAt.Unix() != claims.ExpiresAt {
		t.Errorf("expiresAt in the response %v differs from exp %d", issued.ExpiresAt, claims.ExpiresAt)
	}
}

// TestClientCannotChooseItsIdentity is the flaw of the original: the request
// named the subject and scope, so any client could ask for an admin token.
func TestClientCannotChooseItsIdentity(t *testing.T) {
	server := startServer(t, testSetup(t))
	wish := `{"subject":"spiffe://grid.example/cloud/admin/mallory","scope":["policy:*"]}`
	code, body := requestToken(t, server, "Bearer "+pmuSecret, wish)
	if code != http.StatusOK {
		t.Fatalf("POST /v1/token = %d %s", code, body)
	}
	var issued tokenResponse
	if err := json.Unmarshal([]byte(body), &issued); err != nil {
		t.Fatal(err)
	}
	verifier := token.Verifier{Keys: fetchVerificationKeys(t, server), Audience: "ztc-pep"}
	claims, err := verifier.Verify(issued.Token)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "spiffe://grid.example/edge/pmu/1" || claims.HasScope("policy:write") {
		t.Errorf("the request chose its own identity: %+v", claims)
	}
}

func TestTokenRequestRejects(t *testing.T) {
	server := startServer(t, testSetup(t))
	tests := []struct {
		name          string
		authorization string
	}{
		{"no Authorization header", ""},
		{"unknown secret", "Bearer guess"},
		{"empty secret", "Bearer "},
		{"secret hash instead of secret", "Bearer " + secretHash(pmuSecret)},
		{"other scheme", "Basic " + pmuSecret},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			if code, body := requestToken(t, server, testCase.authorization, ""); code != http.StatusUnauthorized {
				t.Errorf("POST /v1/token = %d %s, want 401", code, body)
			}
		})
	}
	response, err := http.Get(server.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	metrics, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(metrics), `ztc_ca_token_requests_total{result="unauthorized"} 5`) {
		t.Errorf("/metrics does not count the five rejected requests:\n%s", metrics)
	}
}

func TestStartsWithoutClients(t *testing.T) {
	variables := testSetup(t)
	delete(variables, "ZTC_CA_CLIENTS_FILE")
	server := startServer(t, variables)
	if keysByID := fetchVerificationKeys(t, server); len(keysByID) != 1 {
		t.Errorf("GET /v1/keys has %d keys, want 1", len(keysByID))
	}
	if code, _ := requestToken(t, server, "Bearer "+pmuSecret, ""); code != http.StatusUnauthorized {
		t.Errorf("POST /v1/token without a clients file = %d, want 401", code)
	}
}

func TestRefusesToStart(t *testing.T) {
	directory := t.TempDir()
	validHash := secretHash(pmuSecret)
	clientsWith := func(name, client string) string {
		return writeFile(t, directory, name, `{"clients": [`+client+`]}`)
	}
	tests := []struct {
		name   string
		change func(variables map[string]string)
	}{
		{"no key file", func(variables map[string]string) { delete(variables, "ZTC_CA_KEY_FILE") }},
		{"missing key file", func(variables map[string]string) {
			variables["ZTC_CA_KEY_FILE"] = filepath.Join(directory, "missing.key")
		}},
		{"key file readable by others", func(variables map[string]string) {
			if err := os.Chmod(variables["ZTC_CA_KEY_FILE"], 0o644); err != nil { //nolint:gosec // G302: too open on purpose
				t.Fatal(err)
			}
		}},
		{"zero token lifetime", func(variables map[string]string) { variables["ZTC_TOKEN_TTL"] = "0s" }},
		{"token lifetime above an hour", func(variables map[string]string) { variables["ZTC_TOKEN_TTL"] = "2h" }},
		{"missing clients file", func(variables map[string]string) {
			variables["ZTC_CA_CLIENTS_FILE"] = filepath.Join(directory, "missing.json")
		}},
		{"misspelt field", func(variables map[string]string) {
			variables["ZTC_CA_CLIENTS_FILE"] = clientsWith("misspelt.json",
				`{"secretSHA256":"`+validHash+`","subject":"spiffe://grid.example/edge/pmu/1","audience":["a"],"scpoe":["x"]}`)
		}},
		{"secret instead of its hash", func(variables map[string]string) {
			variables["ZTC_CA_CLIENTS_FILE"] = clientsWith("plain.json",
				`{"secretSHA256":"`+pmuSecret+`","subject":"spiffe://grid.example/edge/pmu/1","audience":["a"]}`)
		}},
		{"upper-case hash", func(variables map[string]string) {
			variables["ZTC_CA_CLIENTS_FILE"] = clientsWith("upper.json",
				`{"secretSHA256":"`+strings.ToUpper(validHash)+`","subject":"spiffe://grid.example/edge/pmu/1","audience":["a"]}`)
		}},
		{"subject in another trust domain", func(variables map[string]string) {
			variables["ZTC_CA_CLIENTS_FILE"] = clientsWith("domain.json",
				`{"secretSHA256":"`+validHash+`","subject":"spiffe://evil.example/edge/pmu/1","audience":["a"]}`)
		}},
		{"no audience", func(variables map[string]string) {
			variables["ZTC_CA_CLIENTS_FILE"] = clientsWith("audience.json",
				`{"secretSHA256":"`+validHash+`","subject":"spiffe://grid.example/edge/pmu/1"}`)
		}},
		{"hash of the empty secret", func(variables map[string]string) {
			variables["ZTC_CA_CLIENTS_FILE"] = clientsWith("empty.json",
				`{"secretSHA256":"`+secretHash("")+`","subject":"spiffe://grid.example/edge/pmu/1","audience":["a"]}`)
		}},
		{"same secret twice", func(variables map[string]string) {
			client := `{"secretSHA256":"` + validHash + `","subject":"spiffe://grid.example/edge/pmu/1","audience":["a"]}`
			variables["ZTC_CA_CLIENTS_FILE"] = clientsWith("twice.json", client+","+client)
		}},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			variables := testSetup(t)
			testCase.change(variables)
			variables["ZTC_LISTEN"] = "127.0.0.1:0"
			// If run starts after all, it stops after a second and returns nil,
			// so a missing check fails the test instead of hanging it.
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := run(ctx, environmentFrom(variables), io.Discard); err == nil {
				t.Error("run started anyway")
			}
		})
	}
}

func TestRunStopsWhenContextIsCancelled(t *testing.T) {
	variables := testSetup(t)
	variables["ZTC_LISTEN"] = "127.0.0.1:0"
	ctx, cancel := context.WithCancel(context.Background())
	runResult := make(chan error, 1)
	go func() { runResult <- run(ctx, environmentFrom(variables), io.Discard) }()
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
