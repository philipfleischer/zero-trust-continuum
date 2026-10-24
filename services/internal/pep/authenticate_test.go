// Tests for authentication: what a token and a capability turn into, and
// every reason a request is rejected.

package pep

import (
	"crypto/ed25519"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/model"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/token"
)

// referenceTime is the clock of every test in this package.
var referenceTime = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)

// testRootKey is the capability root key of the tests: 32 bytes.
var testRootKey = []byte("root-key-of-the-pdp-0123456789ab")

// telemetryRoute and taskRoute are the routes the requests go to.
var (
	telemetryRoute = Route{Prefix: "/bay-1/telemetry/", Upstream: "http://localhost:9000", ResourceType: "telemetry", Zone: "bay-1"}
	taskRoute      = Route{Prefix: "/bay-1/task/", Upstream: "http://localhost:9000", ResourceType: "task", Zone: "bay-1"}
)

// testCredentials holds an authenticator and what is needed to make
// credentials it accepts.
type testCredentials struct {
	authenticator Authenticator
	signer        token.Signer
}

func newTestCredentials(t *testing.T) testCredentials {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	clock := func() time.Time { return referenceTime }
	return testCredentials{
		authenticator: Authenticator{
			Tokens: &token.Verifier{
				Keys:     map[string]ed25519.PublicKey{token.KeyIDOf(publicKey): publicKey},
				Audience: "ztc-pep",
				Now:      clock,
			},
			CapabilityRootKey: testRootKey,
			TrustDomain:       "grid.example",
			Layer:             model.LayerFog,
			Now:               clock,
		},
		signer: token.Signer{KeyID: token.KeyIDOf(publicKey), Key: privateKey},
	}
}

// signToken signs a token for subject that is valid at referenceTime.
func (credentials testCredentials) signToken(t *testing.T, subject string) string {
	t.Helper()
	signedToken, err := credentials.signer.Sign(token.Claims{
		Issuer:    "ztc-ca",
		Subject:   subject,
		Audience:  []string{"ztc-pep"},
		ExpiresAt: referenceTime.Add(time.Minute).Unix(),
		ID:        "jti-" + subject,
		Roles:     []string{"operator"},
		Zone:      "control-centre",
	})
	if err != nil {
		t.Fatal(err)
	}
	return signedToken
}

// taskCapability is a capability for executing task t-7 in bay 1 from the
// fog layer, valid for one minute after referenceTime.
func taskCapability(t *testing.T) string {
	t.Helper()
	capability, err := token.NewCapability(testRootKey, "grant-42", "ztc-pep")
	if err != nil {
		t.Fatal(err)
	}
	expiresAt := strconv.FormatInt(referenceTime.Add(time.Minute).Unix(), 10)
	return capability.Attenuate("action = execute").
		Attenuate("resource ^= bay-1/task/").
		Attenuate("task = t-7").
		Attenuate("layer <= fog").
		Attenuate("expires < " + expiresAt).
		Encode()
}

// requestWith builds a request to path with the given headers.
func requestWith(method, path string, headers map[string]string) *http.Request {
	request := httptest.NewRequest(method, path, nil)
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	return request
}

func TestAuthenticateToken(t *testing.T) {
	credentials := newTestCredentials(t)
	operatorToken := credentials.signToken(t, "spiffe://grid.example/cloud/operator/alice")
	request := requestWith(http.MethodGet, "/bay-1/telemetry/pmu-1", map[string]string{"Authorization": "Bearer " + operatorToken})

	subject, err := credentials.authenticator.Authenticate(request, telemetryRoute, "read")
	if err != nil {
		t.Fatal(err)
	}
	want := model.Subject{
		ID:         "spiffe://grid.example/cloud/operator/alice",
		Layer:      model.LayerCloud,
		Roles:      []string{"operator"},
		Zone:       "control-centre",
		AuthMethod: "token",
	}
	if !reflect.DeepEqual(subject, want) {
		t.Errorf("subject = %+v, want %+v", subject, want)
	}
}

func TestAuthenticateCapability(t *testing.T) {
	credentials := newTestCredentials(t)
	request := requestWith(http.MethodPost, "/bay-1/task/t-7", map[string]string{CapabilityHeader: taskCapability(t)})

	subject, err := credentials.authenticator.Authenticate(request, taskRoute, "execute")
	if err != nil {
		t.Fatal(err)
	}
	if subject.ID != "capability:grant-42" || subject.AuthMethod != "capability" || subject.Layer != model.LayerUnknown {
		t.Errorf("subject = %+v", subject)
	}
}

func TestAuthenticateRejects(t *testing.T) {
	credentials := newTestCredentials(t)
	validToken := credentials.signToken(t, "spiffe://grid.example/edge/pmu/1")
	otherDomainToken := credentials.signToken(t, "spiffe://evil.example/edge/pmu/1")
	unknownLayerToken := credentials.signToken(t, "spiffe://grid.example/moon/pmu/1")
	capability := taskCapability(t)

	withoutTokens := credentials.authenticator
	withoutTokens.Tokens = nil
	withoutCapabilities := credentials.authenticator
	withoutCapabilities.CapabilityRootKey = nil

	tests := []struct {
		name          string
		authenticator Authenticator
		path          string
		route         Route
		action        string
		headers       map[string]string
		wantReason    error // checked with errors.Is next to ErrUnauthenticated; nil skips it
	}{
		{"no credential", credentials.authenticator, "/bay-1/telemetry/pmu-1", telemetryRoute, "read", nil, nil},
		{"basic authentication", credentials.authenticator, "/bay-1/telemetry/pmu-1", telemetryRoute, "read",
			map[string]string{"Authorization": "Basic cG11OnNlY3JldA=="}, nil},
		{"tampered token", credentials.authenticator, "/bay-1/telemetry/pmu-1", telemetryRoute, "read",
			map[string]string{"Authorization": "Bearer " + validToken + "x"}, token.ErrSignature},
		{"subject in another trust domain", credentials.authenticator, "/bay-1/telemetry/pmu-1", telemetryRoute, "read",
			map[string]string{"Authorization": "Bearer " + otherDomainToken}, nil},
		{"subject with an unknown layer", credentials.authenticator, "/bay-1/telemetry/pmu-1", telemetryRoute, "read",
			map[string]string{"Authorization": "Bearer " + unknownLayerToken}, nil},
		{"tokens not accepted", withoutTokens, "/bay-1/telemetry/pmu-1", telemetryRoute, "read",
			map[string]string{"Authorization": "Bearer " + validToken}, nil},
		{"bad token next to a good capability", credentials.authenticator, "/bay-1/task/t-7", taskRoute, "execute",
			map[string]string{"Authorization": "Bearer garbage", CapabilityHeader: capability}, token.ErrMalformed},
		{"capability for another action", credentials.authenticator, "/bay-1/task/t-7", taskRoute, "read",
			map[string]string{CapabilityHeader: capability}, token.ErrCaveat},
		{"capability for another task", credentials.authenticator, "/bay-1/task/t-8", taskRoute, "execute",
			map[string]string{CapabilityHeader: capability, "X-ZTC-Task": "t-7"}, token.ErrCaveat},
		{"capabilities not accepted", withoutCapabilities, "/bay-1/task/t-7", taskRoute, "execute",
			map[string]string{CapabilityHeader: capability}, nil},
		{"capability that is not one", credentials.authenticator, "/bay-1/task/t-7", taskRoute, "execute",
			map[string]string{CapabilityHeader: "not-a-capability"}, token.ErrMalformed},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			request := requestWith(http.MethodPost, testCase.path, testCase.headers)
			subject, err := testCase.authenticator.Authenticate(request, testCase.route, testCase.action)
			if !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("Authenticate error %v, want ErrUnauthenticated", err)
			}
			if testCase.wantReason != nil && !errors.Is(err, testCase.wantReason) {
				t.Errorf("Authenticate error %v, want it to wrap %v", err, testCase.wantReason)
			}
			if subject.ID != "" {
				t.Errorf("Authenticate returned subject %+v together with an error", subject)
			}
		})
	}
}

func TestTaskOf(t *testing.T) {
	tests := []struct {
		resource string
		route    Route
		want     string
	}{
		{"bay-1/task/t-7", taskRoute, "t-7"},
		{"bay-1/task/t-7/", taskRoute, "t-7"},
		{"bay-1/telemetry/t-7", telemetryRoute, ""},
	}
	for _, testCase := range tests {
		if got := taskOf(testCase.resource, testCase.route); got != testCase.want {
			t.Errorf("taskOf(%q) = %q, want %q", testCase.resource, got, testCase.want)
		}
	}
}
