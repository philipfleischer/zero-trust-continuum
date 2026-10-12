// Tests for the PDP's HTTP API, through httptest without a real server.

package pdp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/model"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/observability"
)

const token = "test-token"

// apiUnderTest is a PDP behind its HTTP handler.
type apiUnderTest struct {
	t       *testing.T
	pdp     *PDP
	handler http.Handler
	metrics *observability.Registry
}

func newAPI(t *testing.T) *apiUnderTest {
	t.Helper()
	now := referenceTime
	registry := observability.NewRegistry()
	pdp := newPDP(t, &now)
	return &apiUnderTest{t: t, pdp: pdp, handler: NewHandler(pdp, token, registry), metrics: registry}
}

// do sends a request with body (a string is sent as is, anything else as
// JSON) and the given bearer token, and returns the response.
func (api *apiUnderTest) do(method, target string, body any, bearerToken string) *httptest.ResponseRecorder {
	api.t.Helper()
	var bodyText string
	switch typedBody := body.(type) {
	case nil:
	case string:
		bodyText = typedBody
	default:
		data, err := json.Marshal(typedBody)
		if err != nil {
			api.t.Fatal(err)
		}
		bodyText = string(data)
	}
	request := httptest.NewRequest(method, target, strings.NewReader(bodyText))
	if bearerToken != "" {
		request.Header.Set("Authorization", "Bearer "+bearerToken)
	}
	recorder := httptest.NewRecorder()
	api.handler.ServeHTTP(recorder, request)
	return recorder
}

// askDecision decodes a 200 response from POST /v1/decide.
func (api *apiUnderTest) askDecision(request model.AccessRequest) model.Decision {
	api.t.Helper()
	recorder := api.do(http.MethodPost, "/v1/decide", request, "")
	if recorder.Code != http.StatusOK {
		api.t.Fatalf("POST /v1/decide = %d %s", recorder.Code, recorder.Body)
	}
	var decision model.Decision
	if err := json.NewDecoder(recorder.Body).Decode(&decision); err != nil {
		api.t.Fatal(err)
	}
	return decision
}

func TestHTTPDecide(t *testing.T) {
	api := newAPI(t)
	if decision := api.askDecision(writeTelemetry("bay-1")); decision.Allowed() {
		t.Fatalf("unknown PMU allowed: %+v", decision)
	}
	for _, signal := range []string{
		`{"subject":"` + pmu + `","kind":"authentication","value":0.8}`,
		`{"subject":"` + pmu + `","kind":"posture","value":1}`,
	} {
		if recorder := api.do(http.MethodPost, "/v1/signals", signal, token); recorder.Code != http.StatusNoContent {
			t.Fatalf("POST /v1/signals = %d %s", recorder.Code, recorder.Body)
		}
	}
	if decision := api.askDecision(writeTelemetry("bay-1")); !decision.Allowed() || decision.DecidedBy != "cloud-pdp" {
		t.Errorf("authenticated PMU: %+v", decision)
	}
	deny := api.metrics.Counter("ztc_pdp_decisions_total", "").Value("effect", "deny")
	allow := api.metrics.Counter("ztc_pdp_decisions_total", "").Value("effect", "allow")
	if deny != 1 || allow != 1 {
		t.Errorf("decisions metric: deny %v, allow %v, want 1 and 1", deny, allow)
	}
}

func TestHTTPStatusCodes(t *testing.T) {
	api := newAPI(t)
	tooLarge := `{"subject":{"id":"` + strings.Repeat("x", 2<<20) + `"}}`
	tests := []struct {
		name, method, target string
		body                 any
		bearerToken          string
		want                 int
	}{
		{"decide: not JSON", "POST", "/v1/decide", `{`, "", 400},
		{"decide: unknown field", "POST", "/v1/decide", `{"subjekt":{}}`, "", 400},
		{"decide: body too large", "POST", "/v1/decide", tooLarge, "", 413},
		{"decide: wrong method", "GET", "/v1/decide", nil, "", 405},
		{"signal: no token", "POST", "/v1/signals", `{"subject":"a","kind":"posture","value":1}`, "", 401},
		{"signal: wrong token", "POST", "/v1/signals", `{"subject":"a","kind":"posture","value":1}`, "guess", 401},
		{"signal: unknown kind", "POST", "/v1/signals", `{"subject":"a","kind":"reset"}`, token, 400},
		{"signal: no subject", "POST", "/v1/signals", `{"kind":"posture","value":1}`, token, 400},
		{"trust: no subject", "GET", "/v1/trust", nil, "", 400},
		{"policy: no token", "PUT", "/v1/policy", `{"version":2,"rules":[]}`, "", 401},
		{"policy: misspelt field", "PUT", "/v1/policy", `{"version":2,"rulez":[]}`, token, 400},
		{"policy: not newer", "PUT", "/v1/policy", `{"version":1,"rules":[]}`, token, 409},
		{"emergency: no token", "PUT", "/v1/emergency", `{"on":true}`, "", 401},
		{"unknown path", "GET", "/v1/nothing", nil, "", 404},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			if recorder := api.do(testCase.method, testCase.target, testCase.body, testCase.bearerToken); recorder.Code != testCase.want {
				t.Errorf("%s %s = %d %s, want %d", testCase.method, testCase.target, recorder.Code, recorder.Body, testCase.want)
			}
		})
	}
	if api.pdp.Engine.Policy().Version != 1 || api.pdp.Emergency() {
		t.Error("a rejected request changed the PDP")
	}
}

func TestHTTPWritesDisabledWithoutToken(t *testing.T) {
	now := referenceTime
	handler := NewHandler(newPDP(t, &now), "", observability.NewRegistry())
	request := httptest.NewRequest(http.MethodPut, "/v1/emergency", strings.NewReader(`{"on":true}`))
	request.Header.Set("Authorization", "Bearer ")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Errorf("PUT /v1/emergency with no token configured = %d, want 403", recorder.Code)
	}
}

func TestHTTPTrust(t *testing.T) {
	api := newAPI(t)
	authenticate(t, api.pdp, pmu)
	recorder := api.do(http.MethodGet, "/v1/trust?subject="+url.QueryEscape(pmu), nil, "")
	var got TrustResponse
	if err := json.NewDecoder(recorder.Body).Decode(&got); err != nil || recorder.Code != http.StatusOK {
		t.Fatalf("GET /v1/trust = %d, %v", recorder.Code, err)
	}
	if got.Subject != pmu || got.Level != "high" {
		t.Errorf("GET /v1/trust = %+v", got)
	}
}

func TestHTTPPolicy(t *testing.T) {
	api := newAPI(t)
	nextPolicy := `{"version":2,"rules":[{"id":"allow-all","effect":"allow"}]}`
	if recorder := api.do(http.MethodPut, "/v1/policy", nextPolicy, token); recorder.Code != http.StatusNoContent {
		t.Fatalf("PUT /v1/policy = %d %s", recorder.Code, recorder.Body)
	}
	recorder := api.do(http.MethodGet, "/v1/policy", nil, "")
	var got struct{ Version uint64 }
	if err := json.NewDecoder(recorder.Body).Decode(&got); err != nil || got.Version != 2 {
		t.Errorf("GET /v1/policy after PUT: version %d, %v", got.Version, err)
	}
	authenticate(t, api.pdp, pmu)
	if decision := api.askDecision(writeTelemetry("bay-2")); !decision.Allowed() || decision.RuleID != "allow-all" {
		t.Errorf("the new policy is not used: %+v", decision)
	}
}

func TestHTTPEmergency(t *testing.T) {
	api := newAPI(t)
	if recorder := api.do(http.MethodPut, "/v1/emergency", EmergencyState{On: true}, token); recorder.Code != http.StatusNoContent {
		t.Fatalf("PUT /v1/emergency = %d %s", recorder.Code, recorder.Body)
	}
	recorder := api.do(http.MethodGet, "/v1/emergency", nil, "")
	var got EmergencyState
	if err := json.NewDecoder(recorder.Body).Decode(&got); err != nil || !got.On {
		t.Errorf("GET /v1/emergency = %+v, %v", got, err)
	}
	authenticate(t, api.pdp, operator)
	if decision := api.askDecision(operateBreaker()); decision.RuleID != "break-glass-breaker" {
		t.Errorf("operator in emergency mode: %+v", decision)
	}
}
