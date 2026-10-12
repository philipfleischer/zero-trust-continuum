// Tests for attribute names, attribute resolution and glob matching.

package policy

import (
	"path"
	"testing"
	"time"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/model"
)

func TestGlob(t *testing.T) {
	tests := []struct {
		pattern, text string
		want          bool
	}{
		{"", "", true},
		{"*", "", true},
		{"*", "abc", true},
		{"a*c", "abc", true},
		{"a*c", "ac", true},
		{"a*c", "abcd", false},
		{"ab*", "a", false},
		{"a", "b", false},
		{"*b*b*", "abxbyb", true},
		{"spiffe://*/edge/*", "spiffe://grid.example/edge/pmu/1", true}, // "*" crosses "/"
		{"spiffe://*/edge/*", "spiffe://grid.example/fog/gw/1", false},
		{"role:[*]", "role:[*]", true}, // brackets are literal
		{"[ab]", "a", false},           // not a character class
		{"a?c", "abc", false},          // "?" is literal
	}
	for _, testCase := range tests {
		if got := Glob(testCase.pattern, testCase.text); got != testCase.want {
			t.Errorf("Glob(%q, %q) = %v, want %v", testCase.pattern, testCase.text, got, testCase.want)
		}
	}
}

// TestGlobDiffersFromPathMatch documents why Glob is not path.Match: the
// standard library treats "[" as a character class and stops "*" at "/".
func TestGlobDiffersFromPathMatch(t *testing.T) {
	if matched, _ := path.Match("spiffe://*/edge/*", "spiffe://grid.example/edge/pmu/1"); matched {
		t.Error("path.Match crossed a slash; the reason for Glob is gone")
	}
	if matched, _ := path.Match("[ab]", "a"); !matched {
		t.Error("path.Match did not treat [ab] as a class; the reason for Glob is gone")
	}
}

func TestKnownAttribute(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"subject.id", true},
		{"context.trustScore", true},
		{"subject.attr.site", true},
		{"context.attr.migration", true},
		{"subject.attr.", false}, // prefix without a key
		{"context.trustscore", false},
		{"subject.password", false},
		{"", false},
	}
	for _, testCase := range tests {
		if got := KnownAttribute(testCase.name); got != testCase.want {
			t.Errorf("KnownAttribute(%q) = %v, want %v", testCase.name, got, testCase.want)
		}
	}
}

// sampleRequest is an operator at a fog gateway asking to read a breaker.
func sampleRequest() model.AccessRequest {
	return model.AccessRequest{
		Subject: model.Subject{
			ID: "spiffe://grid.example/fog/gateway/1", Layer: model.LayerFog, Class: "gateway",
			Zone: "substation-1", Roles: []string{"operator", "engineer"},
			Attributes: map[string]string{"site": "oslo"},
		},
		Action: "read",
		Resource: model.Resource{
			ID: "substation-1/breaker/Q1", Type: "breaker", Zone: "substation-1",
			Layer: model.LayerEdge, Sensitivity: 4,
		},
		Context: model.Context{
			Time: time.Date(2026, 10, 6, 14, 30, 0, 0, time.UTC), TrustScore: 0.85,
			SourceZone: "control-centre", SourceLayer: model.LayerCloud,
		},
	}
}

func TestResolve(t *testing.T) {
	request := sampleRequest()
	tests := []struct {
		name      string
		want      string
		wantFound bool
	}{
		{"subject.layer", "fog", true},
		{"subject.class", "gateway", true},
		{"subject.role", "operator,engineer", true},
		{"subject.owner", "", true}, // known but empty
		{"resource.type", "breaker", true},
		{"resource.layer", "edge", true},
		{"resource.sensitivity", "4", true},
		{"action", "read", true},
		{"context.trustScore", "0.85", true},
		{"context.sourceLayer", "cloud", true},
		{"context.emergency", "false", true},
		{"context.hour", "14", true},
		{"subject.attr.site", "oslo", true},
		{"subject.attr.missing", "", false},
		{"context.attr.migration", "", false}, // nil map
		{"subject.password", "", false},
	}
	for _, testCase := range tests {
		got, found := Resolve(testCase.name, request)
		if got != testCase.want || found != testCase.wantFound {
			t.Errorf("Resolve(%q) = %q, %v, want %q, %v", testCase.name, got, found, testCase.want, testCase.wantFound)
		}
	}
}

func TestResolveHourWithoutTime(t *testing.T) {
	request := sampleRequest()
	request.Context.Time = time.Time{}
	if value, found := Resolve("context.hour", request); found {
		t.Errorf("Resolve(context.hour) with zero time = %q, true, want false", value)
	}
}
