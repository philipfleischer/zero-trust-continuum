// Tests for the middleware: every status code, what the PDP is asked, what
// the client is not told, and when trust signals are sent.

package pep

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/model"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/observability"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/trust"
)

// fakeDecider answers with answer and remembers what it was asked.
type fakeDecider struct {
	mutex   sync.Mutex
	asked   []model.AccessRequest
	answer  func(model.AccessRequest) (model.Decision, error)
	onAsked func() // called first on every Decide, if set
}

func (decider *fakeDecider) Decide(_ context.Context, accessRequest model.AccessRequest) (model.Decision, error) {
	if decider.onAsked != nil {
		decider.onAsked()
	}
	decider.mutex.Lock()
	decider.asked = append(decider.asked, accessRequest)
	decider.mutex.Unlock()
	return decider.answer(accessRequest)
}

func (decider *fakeDecider) timesAsked() int {
	decider.mutex.Lock()
	defer decider.mutex.Unlock()
	return len(decider.asked)
}

// allowEverything is a decider that allows every request.
func allowEverything() *fakeDecider {
	return &fakeDecider{answer: func(model.AccessRequest) (model.Decision, error) {
		return model.Decision{Effect: model.Allow, RuleID: "allow-all", DecidedBy: "fake-pdp"}, nil
	}}
}

// recordingSignals remembers the signals it is sent, and fails if failWith is set.
type recordingSignals struct {
	mutex    sync.Mutex
	signals  []trust.Signal
	failWith error
}

func (recorder *recordingSignals) RecordSignal(_ context.Context, signal trust.Signal) error {
	recorder.mutex.Lock()
	defer recorder.mutex.Unlock()
	recorder.signals = append(recorder.signals, signal)
	return recorder.failWith
}

func (recorder *recordingSignals) count() int {
	recorder.mutex.Lock()
	defer recorder.mutex.Unlock()
	return len(recorder.signals)
}

// testPEP is an enforcer in front of an upstream that records what reached it.
type testPEP struct {
	enforcer    *Enforcer
	handler     http.Handler
	credentials testCredentials
	signals     *recordingSignals
	metrics     *observability.Registry
	logs        *bytes.Buffer
	now         *time.Time
	upstreamGot []model.Subject
}

func newTestPEP(t *testing.T, decider *fakeDecider) *testPEP {
	t.Helper()
	routes, err := NewRouteTable([]Route{telemetryRoute, taskRoute})
	if err != nil {
		t.Fatal(err)
	}
	now := referenceTime
	pep := &testPEP{
		credentials: newTestCredentials(t),
		signals:     &recordingSignals{},
		metrics:     observability.NewRegistry(),
		logs:        &bytes.Buffer{},
		now:         &now,
	}
	pep.enforcer, err = NewEnforcer(Config{
		Name:          "ztc-pep-test",
		Routes:        routes,
		Authenticator: pep.credentials.authenticator,
		Decider:       decider,
		SourceZone:    "substation-lan",
		Signals:       pep.signals,
		Logger:        slog.New(slog.NewTextHandler(pep.logs, nil)),
		Metrics:       pep.metrics,
		Now:           func() time.Time { return *pep.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	upstream := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		subject, _ := SubjectFrom(request.Context())
		pep.upstreamGot = append(pep.upstreamGot, subject)
		_, _ = writer.Write([]byte("upstream"))
	})
	pep.handler = pep.enforcer.Middleware(upstream)
	return pep
}

// send sends a request through the PEP and returns the recorder.
func (pep *testPEP) send(method, path string, headers map[string]string) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	pep.handler.ServeHTTP(recorder, requestWith(method, path, headers))
	return recorder
}

// bearer returns the Authorization header of a token for the PMU.
func (pep *testPEP) bearer(t *testing.T) map[string]string {
	t.Helper()
	return map[string]string{"Authorization": "Bearer " + pep.credentials.signToken(t, "spiffe://grid.example/edge/pmu/1")}
}

func TestMiddlewareAllows(t *testing.T) {
	decider := allowEverything()
	pep := newTestPEP(t, decider)
	headers := pep.bearer(t)
	// Claims a client could try: none of them may reach the PDP.
	headers["X-ZTC-Source-Zone"] = "control-centre"
	headers["X-ZTC-Emergency"] = "true"

	recorder := pep.send(http.MethodPost, "/bay-1/telemetry/pmu-1", headers)
	if recorder.Code != http.StatusOK || recorder.Body.String() != "upstream" {
		t.Fatalf("status %d, body %q", recorder.Code, recorder.Body)
	}
	if len(pep.upstreamGot) != 1 || pep.upstreamGot[0].ID != "spiffe://grid.example/edge/pmu/1" {
		t.Errorf("the upstream did not get the subject in the context: %+v", pep.upstreamGot)
	}

	asked := decider.asked[0]
	wantResource := model.Resource{ID: "bay-1/telemetry/pmu-1", Type: "telemetry", Zone: "bay-1"}
	if asked.Action != "write" || !reflect.DeepEqual(asked.Resource, wantResource) {
		t.Errorf("the PDP was asked about %s on %+v", asked.Action, asked.Resource)
	}
	if asked.Context.SourceZone != "substation-lan" || asked.Context.Emergency {
		t.Errorf("context %+v: the source zone must come from the PEP and emergency from nobody", asked.Context)
	}
	if asked.Subject.Layer != model.LayerEdge || asked.Subject.Zone != "control-centre" {
		t.Errorf("subject %+v: layer and zone must come from the token", asked.Subject)
	}
}

func TestMiddlewareRejects(t *testing.T) {
	deny := func(model.AccessRequest) (model.Decision, error) {
		return model.Decision{Effect: model.Deny, RuleID: "deny-untrusted", Reason: "denied by rule deny-untrusted"}, nil
	}
	failingAllow := func(model.AccessRequest) (model.Decision, error) {
		return model.Decision{Effect: model.Allow}, errors.New("dial tcp 10.0.3.7:8181: connection refused")
	}
	withObligation := func(model.AccessRequest) (model.Decision, error) {
		return model.Decision{Effect: model.Allow, Obligations: []string{"rate-limit:50/s"}}, nil
	}
	tests := []struct {
		name         string
		method, path string
		withToken    bool
		answer       func(model.AccessRequest) (model.Decision, error)
		wantStatus   int
		wantOutcome  string
		wantPDPAsked bool
		mustNotTell  string // must not appear in the response body
	}{
		{"no route", http.MethodGet, "/bay-9/telemetry/x", true, nil, http.StatusNotFound, "no-route", false, ""},
		{"no action for the method", http.MethodOptions, "/bay-1/telemetry/x", true, nil, http.StatusMethodNotAllowed, "no-action", false, ""},
		{"no credential", http.MethodGet, "/bay-1/telemetry/x", false, nil, http.StatusUnauthorized, "unauthenticated", false, "no credential"},
		{"denied", http.MethodGet, "/bay-1/telemetry/x", true, deny, http.StatusForbidden, "denied", true, "deny-untrusted"},
		{"PDP error with an allow", http.MethodGet, "/bay-1/telemetry/x", true, failingAllow, http.StatusServiceUnavailable, "pdp-unavailable", true, "10.0.3.7"},
		{"obligation the PEP cannot fulfil", http.MethodGet, "/bay-1/telemetry/x", true, withObligation, http.StatusForbidden, "obligation-failed", true, "rate-limit"},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			decider := &fakeDecider{answer: testCase.answer}
			pep := newTestPEP(t, decider)
			var headers map[string]string
			if testCase.withToken {
				headers = pep.bearer(t)
			}
			recorder := pep.send(testCase.method, testCase.path, headers)
			if recorder.Code != testCase.wantStatus {
				t.Errorf("status %d, want %d", recorder.Code, testCase.wantStatus)
			}
			if len(pep.upstreamGot) != 0 {
				t.Error("the request reached the upstream")
			}
			if pdpAsked := decider.timesAsked() > 0; pdpAsked != testCase.wantPDPAsked {
				t.Errorf("PDP asked %v, want %v", pdpAsked, testCase.wantPDPAsked)
			}
			if testCase.mustNotTell != "" && strings.Contains(recorder.Body.String(), testCase.mustNotTell) {
				t.Errorf("the response %q tells the client %q", recorder.Body, testCase.mustNotTell)
			}
			if got := pep.metrics.Counter("ztc_pep_requests_total", "").Value("outcome", testCase.wantOutcome); got != 1 {
				t.Errorf("outcome %s counted %v times, want 1", testCase.wantOutcome, got)
			}
		})
	}
}

func TestUnauthenticatedResponse(t *testing.T) {
	pep := newTestPEP(t, allowEverything())
	recorder := pep.send(http.MethodGet, "/bay-1/telemetry/x", map[string]string{"Authorization": "Bearer garbage"})
	if recorder.Header().Get("WWW-Authenticate") != `Bearer realm="ztc"` {
		t.Errorf("WWW-Authenticate = %q", recorder.Header().Get("WWW-Authenticate"))
	}
	if !strings.Contains(pep.logs.String(), "malformed") {
		t.Errorf("the reason was not logged:\n%s", pep.logs)
	}
}

// TestFirstAuthenticationReachesThePDPFirst is the flaw the original fixed
// late: a signal sent after the decision, or in the background, leaves the
// first request of a subject decided with no authentication counted.
func TestFirstAuthenticationReachesThePDPFirst(t *testing.T) {
	decider := allowEverything()
	pep := newTestPEP(t, decider)
	signalsWhenAsked := -1
	decider.onAsked = func() { signalsWhenAsked = pep.signals.count() }

	pep.send(http.MethodGet, "/bay-1/telemetry/x", pep.bearer(t))
	if signalsWhenAsked != 1 {
		t.Fatalf("the PDP was asked with %d signals sent, want 1", signalsWhenAsked)
	}
	signal := pep.signals.signals[0]
	wantSignal := trust.Signal{Subject: "spiffe://grid.example/edge/pmu/1", Kind: trust.Authentication, Value: 0.5, Time: referenceTime, Source: "ztc-pep-test"}
	if signal != wantSignal {
		t.Errorf("signal = %+v, want %+v", signal, wantSignal)
	}
}

func TestSignalsAtMostOncePerInterval(t *testing.T) {
	pep := newTestPEP(t, allowEverything())
	headers := pep.bearer(t)
	pep.send(http.MethodGet, "/bay-1/telemetry/x", headers)
	*pep.now = referenceTime.Add(59 * time.Second)
	pep.send(http.MethodGet, "/bay-1/telemetry/x", headers)
	if pep.signals.count() != 1 {
		t.Errorf("%d signals within one interval, want 1", pep.signals.count())
	}
	*pep.now = referenceTime.Add(time.Minute)
	pep.send(http.MethodGet, "/bay-1/telemetry/x", headers)
	if pep.signals.count() != 2 {
		t.Errorf("%d signals after one interval, want 2", pep.signals.count())
	}
}

func TestFailedSignalDoesNotStopTheRequest(t *testing.T) {
	decider := allowEverything()
	pep := newTestPEP(t, decider)
	pep.signals.failWith = errors.New("PDP answered 401")
	if recorder := pep.send(http.MethodGet, "/bay-1/telemetry/x", pep.bearer(t)); recorder.Code != http.StatusOK {
		t.Errorf("status %d, want 200 from the decider", recorder.Code)
	}
	if !strings.Contains(pep.logs.String(), "authentication signal not sent") {
		t.Errorf("the failed signal was not logged:\n%s", pep.logs)
	}
}

func TestNewEnforcerRequiresItsParts(t *testing.T) {
	if _, err := NewEnforcer(Config{Name: "incomplete"}); err == nil {
		t.Error("NewEnforcer accepted a config without routes, decider, logger and metrics")
	}
}
