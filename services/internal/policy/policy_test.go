// Tests for the policy types and Validate.
package policy

import (
	"strings"
	"testing"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/model"
)

// validPolicy returns a small policy that passes Validate; each test case
// breaks one thing in its own copy.
func validPolicy() *Policy {
	return &Policy{
		Version: 1,
		Rules: []Rule{
			{ID: "deny-untrusted", Effect: model.Deny,
				Conditions: []Condition{{Attribute: "context.trustScore", Operator: "lt", Value: "0.3"}}},
			{ID: "edge-write-telemetry", Effect: model.Allow, Actions: []string{"write"},
				Resources:  []string{"type:telemetry"},
				Conditions: []Condition{{Attribute: "subject.zone", Operator: "sameAs", Value: "resource.zone"}},
				TTLSeconds: 60},
		},
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(policy *Policy)
		wantError string // "" means the policy must be valid
	}{
		{"valid", func(*Policy) {}, ""},
		{"no rules is valid (engine denies everything)", func(policy *Policy) { policy.Rules = nil }, ""},
		{"empty id", func(policy *Policy) { policy.Rules[0].ID = "" }, "empty id"},
		{"duplicate id", func(policy *Policy) { policy.Rules[1].ID = policy.Rules[0].ID }, "duplicate id"},
		{"unknown effect", func(policy *Policy) { policy.Rules[0].Effect = "maybe" }, "unknown effect"},
		{"empty effect", func(policy *Policy) { policy.Rules[0].Effect = "" }, "unknown effect"},
		{"negative ttl", func(policy *Policy) { policy.Rules[1].TTLSeconds = -1 }, "negative ttlSeconds"},
		{"unknown op", func(policy *Policy) { policy.Rules[0].Conditions[0].Operator = "approx" }, "unknown op"},
		{"numeric op with text value", func(policy *Policy) { policy.Rules[0].Conditions[0].Value = "0,3" }, "needs a number"},
		{"unknown attribute", func(policy *Policy) { policy.Rules[0].Conditions[0].Attribute = "context.trustscore" }, "unknown attribute"},
		{"sameAs unknown attribute", func(policy *Policy) { policy.Rules[1].Conditions[0].Value = "resource.zon" }, "unknown attribute"},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			policy := validPolicy()
			testCase.mutate(policy)
			err := Validate(policy)
			if testCase.wantError == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), testCase.wantError) {
				t.Fatalf("Validate() = %v, want error containing %q", err, testCase.wantError)
			}
		})
	}
}

func TestValidateNil(t *testing.T) {
	if Validate(nil) == nil {
		t.Fatal("Validate(nil) = nil, want error")
	}
}
