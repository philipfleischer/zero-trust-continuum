// Tests for the reverse proxy: what reaches the upstream, and what does not.

package pep

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/model"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/observability"
)

// recordingUpstream is a protected service that remembers the requests it got.
type recordingUpstream struct {
	server   *httptest.Server
	mutex    sync.Mutex
	requests []*http.Request
	bodies   []string
}

func newRecordingUpstream(t *testing.T, answer string) *recordingUpstream {
	t.Helper()
	upstream := &recordingUpstream{}
	upstream.server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		upstream.mutex.Lock()
		upstream.requests = append(upstream.requests, request)
		upstream.bodies = append(upstream.bodies, string(body))
		upstream.mutex.Unlock()
		_, _ = writer.Write([]byte(answer))
	}))
	t.Cleanup(upstream.server.Close)
	return upstream
}

func (upstream *recordingUpstream) received() int {
	upstream.mutex.Lock()
	defer upstream.mutex.Unlock()
	return len(upstream.requests)
}

// proxyPEP is a PEP proxying telemetry and breaker requests to two upstreams.
type proxyPEP struct {
	handler     http.Handler
	credentials testCredentials
	logs        *bytes.Buffer
	metrics     *observability.Registry
}

func newProxyPEP(t *testing.T, decider *fakeDecider, telemetryURL, breakerURL string) *proxyPEP {
	t.Helper()
	routes, err := NewRouteTable([]Route{
		{Prefix: "/bay-1/telemetry/", Upstream: telemetryURL, ResourceType: "telemetry", Zone: "bay-1"},
		{Prefix: "/bay-1/breaker/", Upstream: breakerURL, ResourceType: "breaker", Zone: "bay-1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	pep := &proxyPEP{credentials: newTestCredentials(t), logs: &bytes.Buffer{}, metrics: observability.NewRegistry()}
	enforcer, err := NewEnforcer(Config{
		Name:          "ztc-pep-test",
		Routes:        routes,
		Authenticator: pep.credentials.authenticator,
		Decider:       decider,
		Logger:        slog.New(slog.NewTextHandler(pep.logs, nil)),
		Metrics:       pep.metrics,
		Now:           pep.credentials.authenticator.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	pep.handler = NewProxy(enforcer, nil)
	return pep
}

func (pep *proxyPEP) send(t *testing.T, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+pep.credentials.signToken(t, "spiffe://grid.example/edge/pmu/1"))
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	recorder := httptest.NewRecorder()
	pep.handler.ServeHTTP(recorder, request)
	return recorder
}

func TestProxyForwardsAllowedRequests(t *testing.T) {
	telemetry := newRecordingUpstream(t, "stored")
	breaker := newRecordingUpstream(t, "switched")
	pep := newProxyPEP(t, allowEverything(), telemetry.server.URL, breaker.server.URL)

	spoofed := map[string]string{
		SubjectHeader:     "spiffe://grid.example/cloud/admin/mallory",
		RuleHeader:        "policy-admin",
		CapabilityHeader:  "a-capability",
		"x-ztc-emergency": "true", // any spelling of an X-ZTC-* header
	}
	recorder := pep.send(t, http.MethodPost, "/bay-1/telemetry/pmu-1", `{"voltage":230.1}`, spoofed)
	if recorder.Code != http.StatusOK || recorder.Body.String() != "stored" {
		t.Fatalf("status %d, body %q", recorder.Code, recorder.Body)
	}
	if telemetry.received() != 1 || breaker.received() != 0 {
		t.Fatalf("telemetry upstream got %d requests and breaker upstream %d, want 1 and 0", telemetry.received(), breaker.received())
	}

	forwarded := telemetry.requests[0]
	if forwarded.Method != http.MethodPost || forwarded.URL.Path != "/bay-1/telemetry/pmu-1" || telemetry.bodies[0] != `{"voltage":230.1}` {
		t.Errorf("forwarded %s %s with body %q", forwarded.Method, forwarded.URL.Path, telemetry.bodies[0])
	}
	if got := forwarded.Header.Get(SubjectHeader); got != "spiffe://grid.example/edge/pmu/1" {
		t.Errorf("%s = %q, want the authenticated subject", SubjectHeader, got)
	}
	if got := forwarded.Header.Get(RuleHeader); got != "allow-all" {
		t.Errorf("%s = %q, want the rule that allowed it", RuleHeader, got)
	}
	for _, removed := range []string{"Authorization", CapabilityHeader, "X-ZTC-Emergency"} {
		if value := forwarded.Header.Get(removed); value != "" {
			t.Errorf("the upstream got %s: %q", removed, value)
		}
	}
	if forwarded.Header.Get("X-Forwarded-For") == "" {
		t.Error("X-Forwarded-For is missing")
	}
}

func TestProxyRoutesToTheRightUpstream(t *testing.T) {
	telemetry := newRecordingUpstream(t, "stored")
	breaker := newRecordingUpstream(t, "switched")
	pep := newProxyPEP(t, allowEverything(), telemetry.server.URL, breaker.server.URL)
	if recorder := pep.send(t, http.MethodPost, "/bay-1/breaker/Q1", "", nil); recorder.Body.String() != "switched" {
		t.Errorf("body %q, want the breaker upstream", recorder.Body)
	}
	if telemetry.received() != 0 || breaker.received() != 1 {
		t.Errorf("telemetry upstream got %d requests and breaker upstream %d, want 0 and 1", telemetry.received(), breaker.received())
	}
}

func TestProxyNeverForwardsDeniedRequests(t *testing.T) {
	telemetry := newRecordingUpstream(t, "stored")
	deny := &fakeDecider{answer: func(model.AccessRequest) (model.Decision, error) {
		return model.Decision{Effect: model.Deny}, nil
	}}
	pep := newProxyPEP(t, deny, telemetry.server.URL, telemetry.server.URL)
	if recorder := pep.send(t, http.MethodPost, "/bay-1/telemetry/pmu-1", "x", nil); recorder.Code != http.StatusForbidden {
		t.Errorf("status %d, want 403", recorder.Code)
	}
	if telemetry.received() != 0 {
		t.Error("a denied request reached the upstream")
	}
}

func TestProxyUpstreamDown(t *testing.T) {
	stopped := httptest.NewServer(http.NotFoundHandler())
	stopped.Close() // nothing listens on this address any more
	pep := newProxyPEP(t, allowEverything(), stopped.URL, stopped.URL)
	if recorder := pep.send(t, http.MethodPost, "/bay-1/telemetry/pmu-1", "x", nil); recorder.Code != http.StatusBadGateway {
		t.Errorf("status %d, want 502", recorder.Code)
	}
	if !strings.Contains(pep.logs.String(), "upstream unavailable") {
		t.Errorf("the failure was not logged:\n%s", pep.logs)
	}
	if got := pep.metrics.Counter("ztc_pep_upstream_errors_total", "").Value(); got != 1 {
		t.Errorf("upstream errors counted %v times, want 1", got)
	}
}
