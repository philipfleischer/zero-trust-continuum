// Tests for obligations: the three the PEP carries out, and the ones that
// make it refuse.

package pep

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/model"
)

// allowWith is a decider that allows every request with the given obligations.
func allowWith(obligations ...string) *fakeDecider {
	return &fakeDecider{answer: func(model.AccessRequest) (model.Decision, error) {
		return model.Decision{Effect: model.Allow, RuleID: "operate-breaker", Obligations: obligations}, nil
	}}
}

func TestObligationsCarriedOut(t *testing.T) {
	tests := []struct {
		name         string
		obligations  []string
		wantLogLine  string // must appear in the log
		wantReverify string // the value of ReverifyHeader
	}{
		{"log", []string{"log"}, `msg="request allowed"`, ""},
		{"alert", []string{"alert:soc"}, `level=WARN msg=alert target=soc`, ""},
		{"reverify", []string{"reverify:10s"}, "", "10s"},
		{"all three", []string{"log", "alert:soc", "reverify:10s"}, `rule=operate-breaker`, "10s"},
		{"none", nil, "", ""},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			pep := newTestPEP(t, allowWith(testCase.obligations...))
			recorder := pep.send(http.MethodGet, "/bay-1/telemetry/x", pep.bearer(t))
			if recorder.Code != http.StatusOK {
				t.Fatalf("status %d, want 200", recorder.Code)
			}
			if testCase.wantLogLine != "" && !strings.Contains(pep.logs.String(), testCase.wantLogLine) {
				t.Errorf("the log is missing %q:\n%s", testCase.wantLogLine, pep.logs)
			}
			if got := recorder.Header().Get(ReverifyHeader); got != testCase.wantReverify {
				t.Errorf("%s = %q, want %q", ReverifyHeader, got, testCase.wantReverify)
			}
		})
	}
}

func TestObligationsRefused(t *testing.T) {
	tests := []struct {
		name        string
		obligations []string
	}{
		{"unknown obligation", []string{"mfa"}},
		{"rate limiting before M5", []string{"rate-limit:50/s"}},
		{"alert without a target", []string{"alert:"}},
		{"log with an argument", []string{"log:everything"}},
		{"reverify that is not a duration", []string{"reverify:soon"}},
		{"reverify that is not positive", []string{"reverify:-5s"}},
		{"a good one next to a bad one", []string{"log", "rate-limit:50/s"}},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			pep := newTestPEP(t, allowWith(testCase.obligations...))
			recorder := pep.send(http.MethodGet, "/bay-1/telemetry/x", pep.bearer(t))
			if recorder.Code != http.StatusForbidden || len(pep.upstreamGot) != 0 {
				t.Errorf("status %d with %d upstream requests, want 403 and none", recorder.Code, len(pep.upstreamGot))
			}
			if strings.Contains(pep.logs.String(), "request allowed") {
				t.Errorf("a refused request left an audit record saying it was allowed:\n%s", pep.logs)
			}
		})
	}
}

func TestParseObligation(t *testing.T) {
	duty, err := parseObligation("reverify:1m30s")
	if err != nil || duty.kind != "reverify" || duty.argument != "1m30s" {
		t.Errorf("parseObligation = %+v, %v", duty, err)
	}
	if interval, _ := time.ParseDuration(duty.argument); interval != 90*time.Second {
		t.Errorf("the argument %q is not 90 s", duty.argument)
	}
}
