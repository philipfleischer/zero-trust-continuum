// The evaluation engine: holds the installed policy and turns an access
// request into a decision with deny-overrides and default deny.

package policy

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/model"
)

// ErrStalePolicy is returned by Install for a policy whose version is not
// newer than the installed one, so an old policy can never replace a newer.
var ErrStalePolicy = errors.New("policy: version is not newer than the installed policy")

// Engine evaluates access requests against the installed policy. Evaluate may
// be called from many goroutines while Install replaces the policy.
type Engine struct {
	current    atomic.Pointer[Policy] // never nil after NewEngine; readers never lock
	DefaultTTL time.Duration          // cache lifetime of a decision when the rule sets none
}

// NewEngine returns an engine with initialPolicy installed and DefaultTTL
// 30 s. A nil initialPolicy installs an empty policy, which denies everything.
func NewEngine(initialPolicy *Policy) *Engine {
	if initialPolicy == nil {
		initialPolicy = &Policy{}
	}
	engine := &Engine{DefaultTTL: 30 * time.Second}
	engine.current.Store(initialPolicy)
	return engine
}

// Policy returns the installed policy. Callers must not modify it.
func (engine *Engine) Policy() *Policy { return engine.current.Load() }

// Install validates newPolicy and installs it if its version is newer than
// the installed version. On any error the installed policy is kept.
func (engine *Engine) Install(newPolicy *Policy) error {
	if err := Validate(newPolicy); err != nil {
		return err
	}
	for {
		installed := engine.current.Load()
		if newPolicy.Version <= installed.Version {
			return fmt.Errorf("%w (have %d, got %d)", ErrStalePolicy, installed.Version, newPolicy.Version)
		}
		if engine.current.CompareAndSwap(installed, newPolicy) {
			return nil
		}
		// Another Install won the race; compare against its version and retry.
	}
}

// Evaluate returns the decision for request with deny-overrides and default
// deny: the first matching deny rule decides; otherwise the first matching
// allow rule decides; otherwise the request is denied. The decision carries
// RuleID, Reason, TTL and PolicyVersion, and an allow also carries a copy of
// the rule's obligations. Evaluate never fails: every problem becomes a deny.
func (engine *Engine) Evaluate(request model.AccessRequest) model.Decision {
	policy := engine.current.Load() // one snapshot for the whole evaluation
	var firstAllowRule *Rule
	for ruleIndex := range policy.Rules {
		rule := &policy.Rules[ruleIndex]
		if !ruleMatches(rule, request) {
			continue
		}
		if rule.Effect == model.Deny {
			return model.Decision{
				Effect:        model.Deny,
				Reason:        "denied by rule " + rule.ID,
				RuleID:        rule.ID,
				TTL:           engine.cacheLifetime(rule),
				PolicyVersion: policy.Version,
			}
		}
		if firstAllowRule == nil {
			firstAllowRule = rule
		}
	}
	if firstAllowRule == nil {
		return model.Decision{
			Effect:        model.Deny,
			Reason:        "no rule matched (default deny)",
			TTL:           engine.DefaultTTL,
			PolicyVersion: policy.Version,
		}
	}
	return model.Decision{
		Effect:        model.Allow,
		Reason:        "allowed by rule " + firstAllowRule.ID,
		RuleID:        firstAllowRule.ID,
		TTL:           engine.cacheLifetime(firstAllowRule),
		PolicyVersion: policy.Version,
		Obligations:   slices.Clone(firstAllowRule.Obligations),
	}
}

// cacheLifetime returns how long a decision made by rule may be cached.
func (engine *Engine) cacheLifetime(rule *Rule) time.Duration {
	if rule.TTLSeconds > 0 {
		return time.Duration(rule.TTLSeconds) * time.Second
	}
	return engine.DefaultTTL
}

// ruleMatches reports whether rule applies to request: every non-empty
// pattern list has a match and every condition holds.
func ruleMatches(rule *Rule, request model.AccessRequest) bool {
	if len(rule.Subjects) > 0 && !subjectMatchesAny(rule.Subjects, request.Subject) {
		return false
	}
	if len(rule.Resources) > 0 && !resourceMatchesAny(rule.Resources, request.Resource) {
		return false
	}
	if len(rule.Actions) > 0 && !textMatchesAny(rule.Actions, request.Action) {
		return false
	}
	for _, condition := range rule.Conditions {
		if !conditionHolds(condition, request) {
			return false
		}
	}
	return true
}

// textMatchesAny reports whether text matches at least one of the glob patterns.
func textMatchesAny(patterns []string, text string) bool {
	for _, pattern := range patterns {
		if Glob(pattern, text) {
			return true
		}
	}
	return false
}

// subjectMatchesAny matches "role:<glob>" against each of the subject's roles
// and any other pattern against its SPIFFE ID.
func subjectMatchesAny(patterns []string, subject model.Subject) bool {
	for _, pattern := range patterns {
		rolePattern, isRolePattern := strings.CutPrefix(pattern, "role:")
		if isRolePattern {
			for _, role := range subject.Roles {
				if Glob(rolePattern, role) {
					return true
				}
			}
			continue
		}
		if Glob(pattern, subject.ID) {
			return true
		}
	}
	return false
}

// resourceMatchesAny matches "type:<glob>" against the resource type and any
// other pattern against the resource ID.
func resourceMatchesAny(patterns []string, resource model.Resource) bool {
	for _, pattern := range patterns {
		typePattern, isTypePattern := strings.CutPrefix(pattern, "type:")
		if isTypePattern {
			if Glob(typePattern, resource.Type) {
				return true
			}
			continue
		}
		if Glob(pattern, resource.ID) {
			return true
		}
	}
	return false
}

// conditionHolds reports whether condition holds for request. A missing
// attribute, an unknown operator or a value that is not a number for a
// numeric operator all give false (fail closed).
func conditionHolds(condition Condition, request model.AccessRequest) bool {
	actual, found := Resolve(condition.Attribute, request)
	if !found {
		return false
	}
	expected := condition.Value
	switch condition.Operator {
	case "eq":
		return actual == expected
	case "neq":
		return actual != expected
	case "in":
		return listsOverlap(splitList(actual), splitList(expected))
	case "nin":
		return !listsOverlap(splitList(actual), splitList(expected))
	case "glob":
		return Glob(expected, actual)
	case "sameAs":
		other, otherFound := Resolve(expected, request)
		return otherFound && actual != "" && actual == other
	case "gt", "gte", "lt", "lte":
		return compareNumbers(actual, condition.Operator, expected)
	}
	return false
}

// compareNumbers reports whether "actual operator expected" holds when both
// are parsed as numbers. Text that is not a number gives false.
func compareNumbers(actual, operator, expected string) bool {
	actualNumber, actualError := parseNumber(actual)
	expectedNumber, expectedError := parseNumber(expected)
	if actualError != nil || expectedError != nil {
		return false
	}
	switch operator {
	case "gt":
		return actualNumber > expectedNumber
	case "gte":
		return actualNumber >= expectedNumber
	case "lt":
		return actualNumber < expectedNumber
	default:
		return actualNumber <= expectedNumber
	}
}

// isNumericOperator reports whether operator compares numbers.
func isNumericOperator(operator string) bool {
	return operator == "gt" || operator == "gte" || operator == "lt" || operator == "lte"
}

// parseNumber parses a decimal number such as "0.8", ignoring surrounding spaces.
func parseNumber(text string) (float64, error) {
	return strconv.ParseFloat(strings.TrimSpace(text), 64)
}

// splitList splits a comma-separated list and drops spaces and empty items.
func splitList(text string) []string {
	var items []string
	for _, item := range strings.Split(text, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			items = append(items, item)
		}
	}
	return items
}

// listsOverlap reports whether first and second have at least one item in common.
func listsOverlap(first, second []string) bool {
	for _, item := range first {
		if slices.Contains(second, item) {
			return true
		}
	}
	return false
}
