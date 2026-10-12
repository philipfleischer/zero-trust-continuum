// Tests for the PDP: trust in decisions, facts the PDP will not take from the
// request, denials as trust signals, and compromise escalation.

package pdp

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/model"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/policy"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/trust"
)

const (
	pmu      = "spiffe://grid.example/edge/pmu/1"
	operator = "spiffe://grid.example/cloud/operator/alice"
)

// referenceTime is 14:00, inside working hours.
var referenceTime = time.Date(2026, 10, 9, 14, 0, 0, 0, time.UTC)

// newPDP returns a PDP with the default substation policy whose clock reads *now.
func newPDP(t *testing.T, now *time.Time) *PDP {
	t.Helper()
	pdp := New("cloud-pdp", policy.NewEngine(policy.DefaultSubstationPolicy()))
	pdp.Trust.SetClock(func() time.Time { return *now })
	return pdp
}

// authenticate gives subject mTLS authentication, good posture and one
// location signal: 0.35·0.8 + 0.25 + 0.30 + 0.10·0.5 = 0.88.
func authenticate(t *testing.T, pdp *PDP, subject string) {
	t.Helper()
	for _, signal := range []trust.Signal{
		{Subject: subject, Kind: trust.Authentication, Value: 0.8},
		{Subject: subject, Kind: trust.Posture, Value: 1},
		{Subject: subject, Kind: trust.Location, Value: 1},
	} {
		if _, err := pdp.RecordSignal(signal); err != nil {
			t.Fatal(err)
		}
	}
}

// writeTelemetry is the PMU sending a measurement to a bay.
func writeTelemetry(bay string) model.AccessRequest {
	return model.AccessRequest{
		Subject:  model.Subject{ID: pmu, Layer: model.LayerEdge, Zone: "bay-1"},
		Action:   "write",
		Resource: model.Resource{ID: bay + "/telemetry/pmu-1", Type: "telemetry", Zone: bay},
	}
}

// operateBreaker is the operator switching a breaker from the enterprise zone.
func operateBreaker() model.AccessRequest {
	return model.AccessRequest{
		Subject:  model.Subject{ID: operator, Layer: model.LayerCloud, Zone: "enterprise", Roles: []string{"operator"}},
		Action:   "operate",
		Resource: model.Resource{ID: "bay-1/breaker/Q1", Type: "breaker", Zone: "bay-1"},
		Context:  model.Context{SourceZone: "enterprise"},
	}
}

// decide fails the test if the PDP returns an error.
func decide(t *testing.T, pdp *PDP, request model.AccessRequest) model.Decision {
	t.Helper()
	decision, err := pdp.Decide(context.Background(), request)
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	return decision
}

func TestDecideUnknownSubject(t *testing.T) {
	now := referenceTime
	pdp := newPDP(t, &now)
	decision := decide(t, pdp, writeTelemetry("bay-1"))
	if decision.Allowed() || decision.RuleID != "deny-untrusted" || decision.TrustScore != 0 || decision.DecidedBy != "cloud-pdp" {
		t.Errorf("unknown PMU: %+v", decision)
	}
}

func TestDecideAuthenticated(t *testing.T) {
	now := referenceTime
	pdp := newPDP(t, &now)
	authenticate(t, pdp, pmu)
	decision := decide(t, pdp, writeTelemetry("bay-1"))
	if !decision.Allowed() || decision.RuleID != "edge-write-telemetry" || math.Abs(decision.TrustScore-0.88) > 1e-9 {
		t.Errorf("authenticated PMU: %+v", decision)
	}
}

func TestDecideIgnoresClaimedTrust(t *testing.T) {
	now := referenceTime
	pdp := newPDP(t, &now)
	request := writeTelemetry("bay-1")
	request.Context.TrustScore = 1 // a PEP must not be able to raise trust
	if decision := decide(t, pdp, request); decision.Allowed() || decision.TrustScore != 0 {
		t.Errorf("claimed trust was used: %+v", decision)
	}
}

func TestDecideIgnoresClaimedEmergency(t *testing.T) {
	now := referenceTime
	pdp := newPDP(t, &now)
	authenticate(t, pdp, operator)
	request := operateBreaker()
	request.Context.Emergency = true
	if decision := decide(t, pdp, request); decision.Allowed() {
		t.Errorf("claimed emergency was used: %+v", decision)
	}
	pdp.SetEmergency(true)
	if decision := decide(t, pdp, operateBreaker()); !decision.Allowed() || decision.RuleID != "break-glass-breaker" {
		t.Errorf("emergency declared by the PDP: %+v", decision)
	}
}

func TestDecideIgnoresClaimedTime(t *testing.T) {
	now := referenceTime
	pdp := New("cloud-pdp", policy.NewEngine(&policy.Policy{Version: 1, Rules: []policy.Rule{
		{ID: "allow-all", Effect: model.Allow},
		{ID: "deny-night", Effect: model.Deny, Conditions: []policy.Condition{{Attribute: "context.hour", Operator: "lt", Value: "6"}}},
	}}))
	pdp.Trust.SetClock(func() time.Time { return now })
	authenticate(t, pdp, pmu)

	request := writeTelemetry("bay-1")
	request.Context.Time = time.Date(2026, 10, 9, 3, 0, 0, 0, time.UTC) // claims night
	if decision := decide(t, pdp, request); !decision.Allowed() {
		t.Errorf("claimed time was used: %+v", decision)
	}
	now = time.Date(2026, 10, 10, 3, 0, 0, 0, time.UTC) // it really is night
	if decision := decide(t, pdp, writeTelemetry("bay-1")); decision.RuleID != "deny-night" {
		t.Errorf("PDP clock at night: %+v", decision)
	}
}

func TestDenialLowersTrust(t *testing.T) {
	now := referenceTime
	pdp := newPDP(t, &now)
	authenticate(t, pdp, pmu)
	if decision := decide(t, pdp, writeTelemetry("bay-2")); decision.Allowed() {
		t.Fatalf("PMU wrote to another bay: %+v", decision)
	}
	// 0.88 − 0.1 for one fresh denial
	if got := pdp.Trust.Score(pmu); math.Abs(got-0.78) > 1e-9 {
		t.Errorf("score after a denial = %v, want 0.78", got)
	}
}

func TestDecideCancelled(t *testing.T) {
	now := referenceTime
	pdp := newPDP(t, &now)
	authenticate(t, pdp, pmu)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	decision, err := pdp.Decide(ctx, writeTelemetry("bay-1"))
	if err == nil || decision.Allowed() {
		t.Errorf("cancelled request: %+v, %v", decision, err)
	}
}

func TestRecordSignalEscalation(t *testing.T) {
	now := referenceTime
	pdp := newPDP(t, &now)
	authenticate(t, pdp, pmu)
	tests := []struct {
		name  string
		value float64
		want  bool
	}{
		{"weak alert", 0.5, false},
		{"NaN is not an alert", math.NaN(), false},
		{"strong alert", 0.95, true},
		{"already compromised", 0.99, false},
	}
	for _, testCase := range tests {
		got, err := pdp.RecordSignal(trust.Signal{Subject: pmu, Kind: trust.Behaviour, Value: testCase.value, Source: "ztc-ids"})
		if err != nil || got != testCase.want {
			t.Errorf("%s: RecordSignal() = %v, %v, want %v", testCase.name, got, err, testCase.want)
		}
	}
	if decision := decide(t, pdp, writeTelemetry("bay-1")); decision.Allowed() || decision.TrustScore != 0 {
		t.Errorf("compromised PMU: %+v", decision)
	}
}

func TestRecordSignalRejectsInvalid(t *testing.T) {
	now := referenceTime
	pdp := newPDP(t, &now)
	if _, err := pdp.RecordSignal(trust.Signal{Subject: pmu, Kind: "reset"}); err == nil {
		t.Error("RecordSignal() of an unknown kind = nil error")
	}
}
