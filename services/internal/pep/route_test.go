// Tests for the route table and the action mapping.

package pep

import (
	"errors"
	"net/http"
	"slices"
	"testing"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/model"
)

// testRoutes protect the telemetry of bay 1, the breakers of bay 1, and an
// admin route inside the telemetry route.
func testRoutes() []Route {
	return []Route{
		{Prefix: "/bay-1/telemetry/", Upstream: "http://localhost:9000", ResourceType: "telemetry", Zone: "bay-1", Layer: model.LayerFog, Sensitivity: 1},
		{Prefix: "/bay-1/breaker/", Upstream: "http://localhost:9001", ResourceType: "breaker", Zone: "bay-1", Layer: model.LayerEdge, Sensitivity: 4},
		{Prefix: "/bay-1/telemetry/admin/", Upstream: "http://localhost:9000", ResourceType: "policy", Zone: "bay-1", Layer: model.LayerFog, Sensitivity: 3},
	}
}

// TestLongestPrefixWins checks the admin route in both orders, so neither a
// table that takes the first match nor one that takes the last can pass.
func TestLongestPrefixWins(t *testing.T) {
	routes := testRoutes()
	reversed := slices.Clone(routes)
	slices.Reverse(reversed)
	for _, ordered := range [][]Route{routes, reversed} {
		table, err := NewRouteTable(ordered)
		if err != nil {
			t.Fatal(err)
		}
		if route, _ := table.Match("/bay-1/telemetry/admin/reset"); route.Prefix != "/bay-1/telemetry/admin/" {
			t.Errorf("Match = %q, want the longer prefix /bay-1/telemetry/admin/", route.Prefix)
		}
	}
}

func TestRouteTableMatch(t *testing.T) {
	table, err := NewRouteTable(testRoutes())
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		path       string
		wantPrefix string // "" means no route
	}{
		{"/bay-1/telemetry/pmu-1", "/bay-1/telemetry/"},
		{"/bay-1/telemetry/", "/bay-1/telemetry/"},
		{"/bay-1/telemetry", "/bay-1/telemetry/"},
		{"/bay-1/telemetry/admin/reset", "/bay-1/telemetry/admin/"}, // the longest prefix wins
		{"/bay-1/breaker/Q1", "/bay-1/breaker/"},

		// A prefix covers whole segments only.
		{"/bay-1/telemetryX/pmu-1", ""},
		{"/bay-1/tele", ""},
		{"/bay-2/telemetry/pmu-1", ""},

		// Paths that could reach another resource than the route says.
		{"/bay-1/telemetry/../breaker/Q1", ""},
		{"/bay-1/telemetry/./pmu-1", ""},
		{"/bay-1/telemetry//pmu-1", ""},
		{"/bay-1/telemetry/..", ""},
		{"bay-1/telemetry/pmu-1", ""},
		{"", ""},
	}
	for _, testCase := range tests {
		route, found := table.Match(testCase.path)
		wantFound := testCase.wantPrefix != ""
		if found != wantFound || route.Prefix != testCase.wantPrefix {
			t.Errorf("Match(%q) = %q, %v; want %q", testCase.path, route.Prefix, found, testCase.wantPrefix)
		}
	}
}

func TestNewRouteTableRejects(t *testing.T) {
	valid := testRoutes()[0]
	changed := func(change func(*Route)) []Route {
		route := valid
		change(&route)
		return []Route{route}
	}
	tests := []struct {
		name   string
		routes []Route
	}{
		{"prefix without leading slash", changed(func(route *Route) { route.Prefix = "bay-1/telemetry/" })},
		{"prefix without trailing slash", changed(func(route *Route) { route.Prefix = "/bay-1/telemetry" })},
		{"prefix with ..", changed(func(route *Route) { route.Prefix = "/bay-1/../telemetry/" })},
		{"prefix with an empty segment", changed(func(route *Route) { route.Prefix = "/bay-1//telemetry/" })},
		{"upstream without scheme", changed(func(route *Route) { route.Upstream = "localhost:9000" })},
		{"upstream with another scheme", changed(func(route *Route) { route.Upstream = "file:///etc/passwd" })},
		{"upstream without host", changed(func(route *Route) { route.Upstream = "http://" })},
		{"no resource type", changed(func(route *Route) { route.ResourceType = "" })},
		{"sensitivity above 4", changed(func(route *Route) { route.Sensitivity = 5 })},
		{"negative sensitivity", changed(func(route *Route) { route.Sensitivity = -1 })},
		{"same prefix twice", []Route{valid, valid}},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := NewRouteTable(testCase.routes); !errors.Is(err, ErrInvalidRoute) {
				t.Errorf("NewRouteTable error %v, want ErrInvalidRoute", err)
			}
		})
	}
}

// TestRouteTableKeepsItsOwnCopy checks that changing the slice given to
// NewRouteTable afterwards does not change the table.
func TestRouteTableKeepsItsOwnCopy(t *testing.T) {
	routes := testRoutes()
	table, err := NewRouteTable(routes)
	if err != nil {
		t.Fatal(err)
	}
	routes[0].Zone = "bay-2"
	if route, _ := table.Match("/bay-1/telemetry/pmu-1"); route.Zone != "bay-1" {
		t.Errorf("zone = %q after the caller changed its slice, want bay-1", route.Zone)
	}
}

func TestActionFor(t *testing.T) {
	tests := []struct {
		method, resourceType string
		want                 string // "" means no action
	}{
		{http.MethodGet, "telemetry", "read"},
		{http.MethodHead, "breaker", "read"},
		{http.MethodPost, "telemetry", "write"},
		{http.MethodPut, "setpoint", "write"},
		{http.MethodPatch, "setpoint", "write"},
		{http.MethodPost, "breaker", "operate"},
		{http.MethodPut, "breaker", "write"}, // only POST operates
		{http.MethodPost, "task", "execute"},
		{http.MethodPost, "service", "migrate"},
		{http.MethodDelete, "policy", "admin"},
		{http.MethodOptions, "telemetry", ""},
		{"TRACE", "telemetry", ""},
		{"get", "telemetry", ""}, // methods are case-sensitive
	}
	for _, testCase := range tests {
		got, found := ActionFor(testCase.method, testCase.resourceType)
		wantFound := testCase.want != ""
		if got != testCase.want || found != wantFound {
			t.Errorf("ActionFor(%s, %s) = %q, %v; want %q", testCase.method, testCase.resourceType, got, found, testCase.want)
		}
	}
}
