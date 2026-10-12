// Package policy is an attribute-based access control (ABAC) engine.
//
// A Policy is an ordered list of Rules. Each Rule matches on subject,
// resource and action, plus a list of Conditions over attributes such as
// "subject.layer", "resource.sensitivity" or "context.trustScore". The
// combining algorithm is deny-overrides with default deny: if any matching
// rule denies, the request is denied; otherwise it is allowed only if at least
// one matching rule allows. This is the least-privilege default of zero trust.
//
// The trust score is not a special field: the PDP writes it into
// context.trustScore before evaluation, so a trust threshold is an ordinary
// condition and this package does not depend on the trust package.
//
// Policies are plain JSON (see deploy/policies/) so they can be reviewed in
// pull requests and, later, replicated through Raft.
//
// Industry equivalents: Open Policy Agent (Rego), AWS Cedar, XACML.
package policy

import (
	"errors"
	"fmt"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/model"
)

// Policy is a versioned set of rules. The version increases with every
// change, so a cached decision can tell which policy produced it.
type Policy struct {
	Version     uint64 `json:"version"`
	Description string `json:"description,omitempty"`
	Rules       []Rule `json:"rules"`
}

// Rule is one ABAC rule. It matches a request when every non-empty pattern
// list and every condition matches; its Effect then counts towards the
// deny-overrides decision.
type Rule struct {
	ID          string       `json:"id"`
	Description string       `json:"description,omitempty"`
	Effect      model.Effect `json:"effect"`
	// Subjects, Resources and Actions are glob patterns ("*" matches any
	// sequence). Empty means "any". Subjects match the SPIFFE ID or "role:<r>";
	// Resources match the resource ID or "type:<t>".
	Subjects    []string    `json:"subjects,omitempty"`
	Resources   []string    `json:"resources,omitempty"`
	Actions     []string    `json:"actions,omitempty"`
	Conditions  []Condition `json:"conditions,omitempty"`
	Obligations []string    `json:"obligations,omitempty"` // duties for the PEP when the rule allows, e.g. "log"
	TTLSeconds  int         `json:"ttlSeconds,omitempty"`  // how long the decision may be cached; 0 = engine default
}

// Condition compares one request attribute with a value.
//
// Operators: eq, neq, in, nin (comma-separated list), gt, gte, lt, lte
// (numeric), glob, and sameAs (Value is another attribute name, e.g.
// subject.zone sameAs resource.zone).
type Condition struct {
	Attribute string `json:"attr"`
	Operator  string `json:"op"`
	Value     string `json:"value"`
}

// validOperators is the set of operators a Condition may use.
var validOperators = map[string]bool{
	"eq": true, "neq": true, "in": true, "nin": true,
	"gt": true, "gte": true, "lt": true, "lte": true,
	"glob": true, "sameAs": true,
}

// Validate reports the first mistake in policy: a nil policy, an empty or
// duplicate rule ID, an effect other than allow or deny, a negative TTL, or a
// condition with an unknown attribute or operator, a numeric operator without
// a number, or sameAs naming an unknown attribute. A policy that does not
// validate must never be installed (fail closed).
func Validate(policy *Policy) error {
	if policy == nil {
		return errors.New("policy: nil policy")
	}
	seenRuleIDs := make(map[string]bool, len(policy.Rules))
	for ruleIndex := range policy.Rules {
		rule := &policy.Rules[ruleIndex]
		if rule.ID == "" {
			return fmt.Errorf("policy: rule %d: empty id", ruleIndex)
		}
		if seenRuleIDs[rule.ID] {
			return fmt.Errorf("policy: rule %q: duplicate id", rule.ID)
		}
		seenRuleIDs[rule.ID] = true
		if rule.Effect != model.Allow && rule.Effect != model.Deny {
			return fmt.Errorf("policy: rule %q: unknown effect %q", rule.ID, rule.Effect)
		}
		if rule.TTLSeconds < 0 {
			return fmt.Errorf("policy: rule %q: negative ttlSeconds %d", rule.ID, rule.TTLSeconds)
		}
		for _, condition := range rule.Conditions {
			if err := validateCondition(condition); err != nil {
				return fmt.Errorf("policy: rule %q: %w", rule.ID, err)
			}
		}
	}
	return nil
}

// validateCondition reports the first mistake in one condition.
func validateCondition(condition Condition) error {
	if !KnownAttribute(condition.Attribute) {
		return fmt.Errorf("unknown attribute %q", condition.Attribute)
	}
	if !validOperators[condition.Operator] {
		return fmt.Errorf("unknown op %q", condition.Operator)
	}
	if isNumericOperator(condition.Operator) {
		if _, err := parseNumber(condition.Value); err != nil {
			return fmt.Errorf("%s needs a number, got %q", condition.Operator, condition.Value)
		}
	}
	if condition.Operator == "sameAs" && !KnownAttribute(condition.Value) {
		return fmt.Errorf("sameAs refers to unknown attribute %q", condition.Value)
	}
	return nil
}
