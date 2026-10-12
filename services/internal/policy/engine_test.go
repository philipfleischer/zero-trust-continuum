// Tests for the evaluation engine: rule matching, every condition operator,
// deny-overrides, decision fields, Install and concurrent use. Written before
// the engine, so they fail until it is implemented.

package policy

import (
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/model"
)

// condition is shorthand for a Condition in the test tables.
func condition(attribute, operator, value string) Condition {
	return Condition{Attribute: attribute, Operator: operator, Value: value}
}

func TestEvaluate(t *testing.T) {
	allowAll := Rule{ID: "allow-all", Effect: model.Allow}
	tests := []struct {
		name     string
		rules    []Rule
		mutate   func(request *model.AccessRequest) // nil means sampleRequest() as is
		want     model.Effect
		wantRule string
	}{
		// Combining algorithm.
		{"no rules: default deny", nil, nil, model.Deny, ""},
		{"matching allow", []Rule{allowAll}, nil, model.Allow, "allow-all"},
		{"deny before allow wins", []Rule{{ID: "d", Effect: model.Deny}, allowAll}, nil, model.Deny, "d"},
		{"deny after allow wins", []Rule{allowAll, {ID: "d", Effect: model.Deny}}, nil, model.Deny, "d"},
		{"non-matching deny is ignored", []Rule{allowAll, {ID: "d", Effect: model.Deny, Actions: []string{"write"}}}, nil, model.Allow, "allow-all"},
		{"first matching allow is reported", []Rule{{ID: "a1", Effect: model.Allow}, {ID: "a2", Effect: model.Allow}}, nil, model.Allow, "a1"},

		// Subjects, resources and actions.
		{"action matches", []Rule{{ID: "a", Effect: model.Allow, Actions: []string{"read"}}}, nil, model.Allow, "a"},
		{"action differs", []Rule{{ID: "a", Effect: model.Allow, Actions: []string{"write"}}}, nil, model.Deny, ""},
		{"role pattern", []Rule{{ID: "a", Effect: model.Allow, Subjects: []string{"role:operator"}}}, nil, model.Allow, "a"},
		{"role pattern, role missing", []Rule{{ID: "a", Effect: model.Allow, Subjects: []string{"role:auditor"}}}, nil, model.Deny, ""},
		{"SPIFFE pattern", []Rule{{ID: "a", Effect: model.Allow, Subjects: []string{"spiffe://*/fog/*"}}}, nil, model.Allow, "a"},
		{"SPIFFE pattern, other layer", []Rule{{ID: "a", Effect: model.Allow, Subjects: []string{"spiffe://*/edge/*"}}}, nil, model.Deny, ""},
		{"resource type pattern", []Rule{{ID: "a", Effect: model.Allow, Resources: []string{"type:breaker"}}}, nil, model.Allow, "a"},
		{"resource type differs", []Rule{{ID: "a", Effect: model.Allow, Resources: []string{"type:telemetry"}}}, nil, model.Deny, ""},
		{"resource ID pattern", []Rule{{ID: "a", Effect: model.Allow, Resources: []string{"substation-1/*"}}}, nil, model.Allow, "a"},

		// Condition operators.
		{"eq", []Rule{{ID: "a", Effect: model.Allow, Conditions: []Condition{condition("subject.zone", "eq", "substation-1")}}}, nil, model.Allow, "a"},
		{"neq", []Rule{{ID: "a", Effect: model.Allow, Conditions: []Condition{condition("subject.zone", "neq", "substation-1")}}}, nil, model.Deny, ""},
		{"in", []Rule{{ID: "a", Effect: model.Allow, Conditions: []Condition{condition("context.sourceZone", "in", "control-centre, substation-hmi")}}}, nil, model.Allow, "a"},
		{"nin", []Rule{{ID: "a", Effect: model.Allow, Conditions: []Condition{condition("context.sourceZone", "nin", "control-centre,substation-hmi")}}}, nil, model.Deny, ""},
		{"in on multi-valued role", []Rule{{ID: "a", Effect: model.Allow, Conditions: []Condition{condition("subject.role", "in", "engineer")}}}, nil, model.Allow, "a"},
		{"glob", []Rule{{ID: "a", Effect: model.Allow, Conditions: []Condition{condition("resource.id", "glob", "*/breaker/*")}}}, nil, model.Allow, "a"},
		{"gte at the threshold", []Rule{{ID: "a", Effect: model.Allow, Conditions: []Condition{condition("context.trustScore", "gte", "0.8")}}},
			func(request *model.AccessRequest) { request.Context.TrustScore = 0.8 }, model.Allow, "a"},
		{"gte just below the threshold", []Rule{{ID: "a", Effect: model.Allow, Conditions: []Condition{condition("context.trustScore", "gte", "0.8")}}},
			func(request *model.AccessRequest) { request.Context.TrustScore = 0.79 }, model.Deny, ""},
		{"gt at the threshold", []Rule{{ID: "a", Effect: model.Allow, Conditions: []Condition{condition("context.trustScore", "gt", "0.85")}}}, nil, model.Deny, ""},
		{"lt", []Rule{{ID: "a", Effect: model.Allow, Conditions: []Condition{condition("resource.sensitivity", "lt", "5")}}}, nil, model.Allow, "a"},
		{"lte", []Rule{{ID: "a", Effect: model.Allow, Conditions: []Condition{condition("resource.sensitivity", "lte", "3")}}}, nil, model.Deny, ""},
		{"numeric op on text never matches", []Rule{{ID: "a", Effect: model.Allow, Conditions: []Condition{condition("subject.zone", "gt", "1")}}}, nil, model.Deny, ""},
		{"sameAs", []Rule{{ID: "a", Effect: model.Allow, Conditions: []Condition{condition("subject.zone", "sameAs", "resource.zone")}}}, nil, model.Allow, "a"},
		{"sameAs, other zone", []Rule{{ID: "a", Effect: model.Allow, Conditions: []Condition{condition("subject.zone", "sameAs", "resource.zone")}}},
			func(request *model.AccessRequest) { request.Resource.Zone = "substation-2" }, model.Deny, ""},
		{"sameAs, both empty", []Rule{{ID: "a", Effect: model.Allow, Conditions: []Condition{condition("subject.zone", "sameAs", "resource.zone")}}},
			func(request *model.AccessRequest) { request.Subject.Zone, request.Resource.Zone = "", "" }, model.Deny, ""},
		{"missing attribute never matches", []Rule{{ID: "a", Effect: model.Allow, Conditions: []Condition{condition("subject.attr.clearance", "eq", "")}}}, nil, model.Deny, ""},
		{"all conditions must hold", []Rule{{ID: "a", Effect: model.Allow, Conditions: []Condition{
			condition("subject.zone", "eq", "substation-1"), condition("action", "eq", "write")}}}, nil, model.Deny, ""},

		// Time.
		{"night deny, daytime request", []Rule{allowAll, {ID: "deny-night", Effect: model.Deny, Conditions: []Condition{condition("context.hour", "lt", "6")}}}, nil, model.Allow, "allow-all"},
		{"night deny, night request", []Rule{allowAll, {ID: "deny-night", Effect: model.Deny, Conditions: []Condition{condition("context.hour", "lt", "6")}}},
			func(request *model.AccessRequest) {
				request.Context.Time = time.Date(2026, 10, 7, 3, 0, 0, 0, time.UTC)
			}, model.Deny, "deny-night"},
		{"time condition without time", []Rule{{ID: "a", Effect: model.Allow, Conditions: []Condition{condition("context.hour", "gte", "0")}}},
			func(request *model.AccessRequest) { request.Context.Time = time.Time{} }, model.Deny, ""},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			request := sampleRequest()
			if testCase.mutate != nil {
				testCase.mutate(&request)
			}
			decision := NewEngine(&Policy{Version: 1, Rules: testCase.rules}).Evaluate(request)
			if decision.Effect != testCase.want || decision.RuleID != testCase.wantRule {
				t.Errorf("Evaluate() = %s by %q (%s), want %s by %q", decision.Effect, decision.RuleID, decision.Reason, testCase.want, testCase.wantRule)
			}
		})
	}
}

func TestEvaluateDecisionFields(t *testing.T) {
	engine := NewEngine(&Policy{Version: 7, Rules: []Rule{
		{ID: "read", Effect: model.Allow, Actions: []string{"read"}, Obligations: []string{"log", "reverify:10s"}, TTLSeconds: 10},
		{ID: "write", Effect: model.Allow, Actions: []string{"write"}},
	}})

	decision := engine.Evaluate(sampleRequest())
	if decision.RuleID != "read" || decision.PolicyVersion != 7 || decision.TTL != 10*time.Second || decision.Reason == "" {
		t.Errorf("allow decision = %+v", decision)
	}
	if !slices.Equal(decision.Obligations, []string{"log", "reverify:10s"}) {
		t.Fatalf("obligations = %v", decision.Obligations)
	}
	decision.Obligations[0] = "changed" // the caller owns its copy
	if got := installed(t, engine).Rules[0].Obligations[0]; got != "log" {
		t.Errorf("changing the decision changed the policy: %q", got)
	}

	write := sampleRequest()
	write.Action = "write"
	if decision := engine.Evaluate(write); decision.TTL != engine.DefaultTTL || decision.TTL != 30*time.Second {
		t.Errorf("rule without TTL: TTL = %v, want DefaultTTL 30s", decision.TTL)
	}

	execute := sampleRequest()
	execute.Action = "execute"
	decision = engine.Evaluate(execute)
	if decision.Allowed() || decision.PolicyVersion != 7 || decision.Reason == "" || len(decision.Obligations) != 0 {
		t.Errorf("default deny decision = %+v", decision)
	}
}

// installed returns the engine's policy and stops the test if there is none,
// so a missing policy is reported as a failure instead of a nil-pointer panic.
func installed(t *testing.T, engine *Engine) *Policy {
	t.Helper()
	policy := engine.Policy()
	if policy == nil {
		t.Fatal("Policy() = nil, want the installed policy")
	}
	return policy
}

func TestNewEngineNil(t *testing.T) {
	engine := NewEngine(nil)
	installed(t, engine)
	if decision := engine.Evaluate(sampleRequest()); decision.Allowed() {
		t.Errorf("empty engine allowed: %+v", decision)
	}
}

func TestInstall(t *testing.T) {
	engine := NewEngine(&Policy{Version: 1})
	allowAll := []Rule{{ID: "allow-all", Effect: model.Allow}}

	if err := engine.Install(nil); err == nil {
		t.Error("Install(nil) = nil, want error")
	}
	invalid := &Policy{Version: 2, Rules: []Rule{{ID: "x", Effect: "maybe"}}}
	if err := engine.Install(invalid); err == nil {
		t.Error("invalid policy installed")
	}
	if err := engine.Install(&Policy{Version: 1, Rules: allowAll}); !errors.Is(err, ErrStalePolicy) {
		t.Errorf("same version: err = %v, want ErrStalePolicy", err)
	}
	if version := installed(t, engine).Version; version != 1 {
		t.Fatalf("a rejected Install changed the policy: version %d", version)
	}

	if err := engine.Install(&Policy{Version: 2, Rules: allowAll}); err != nil {
		t.Fatalf("Install(v2) = %v", err)
	}
	if version := installed(t, engine).Version; version != 2 {
		t.Errorf("version = %d, want 2", version)
	}
	if !engine.Evaluate(sampleRequest()).Allowed() {
		t.Error("the new policy is not used")
	}
	if err := engine.Install(&Policy{Version: 1}); !errors.Is(err, ErrStalePolicy) {
		t.Errorf("older version: err = %v, want ErrStalePolicy", err)
	}
}

// TestConcurrentEvaluateAndInstall is for the race detector (make test runs
// with -race): readers must never see a half-installed policy.
func TestConcurrentEvaluateAndInstall(t *testing.T) {
	engine := NewEngine(&Policy{Version: 1})
	request := sampleRequest()
	var workers sync.WaitGroup
	for range 4 {
		workers.Go(func() {
			for range 1000 {
				engine.Evaluate(request)
			}
		})
	}
	for version := uint64(2); version <= 100; version++ {
		if err := engine.Install(&Policy{Version: version, Rules: []Rule{{ID: "allow-all", Effect: model.Allow}}}); err != nil {
			t.Errorf("Install(v%d) = %v", version, err)
		}
	}
	workers.Wait()
	if version := installed(t, engine).Version; version != 100 {
		t.Errorf("version = %d, want 100", version)
	}
}
