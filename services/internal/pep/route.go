// Package pep is the Policy Enforcement Point of NIST SP 800-207: an HTTP
// gateway in front of a protected service. For every request it finds the
// route, authenticates the caller, builds an access request, asks a PDP and
// either forwards the request to the upstream or rejects it.
//
// The PEP decides nothing itself. Everything it puts into the access request
// comes from the route table, the verified credential or its own
// configuration, never from what the client claims in headers.
//
// Industry equivalents: Envoy with ext_authz, Istio sidecars, Pomerium,
// Google Identity-Aware Proxy.
package pep

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/model"
)

// ErrInvalidRoute is returned by NewRouteTable for a route it cannot use.
var ErrInvalidRoute = errors.New("pep: invalid route")

// Route maps a path prefix to a protected resource and the upstream that
// serves it.
type Route struct {
	Prefix       string      `json:"prefix"`       // e.g. "/bay-1/telemetry/"; starts and ends with "/"
	Upstream     string      `json:"upstream"`     // e.g. "http://localhost:9000"
	ResourceType string      `json:"resourceType"` // e.g. "telemetry" or "breaker"
	Zone         string      `json:"zone"`         // IEC 62443 zone of the resource
	Layer        model.Layer `json:"layer"`        // layer that hosts the resource
	Sensitivity  int         `json:"sensitivity"`  // 0 (public) to 4 (safety-critical)
}

// RouteTable is the checked set of routes of one PEP.
type RouteTable struct {
	routes []Route
}

// NewRouteTable checks every route and returns the table. A prefix must start
// and end with "/" and hold no "." or ".." segment, the upstream must be an
// absolute http or https URL, the resource type must be set, the sensitivity
// must be 0 to 4, and no prefix may appear twice.
func NewRouteTable(routes []Route) (*RouteTable, error) {
	seenPrefixes := make(map[string]bool, len(routes))
	for _, route := range routes {
		if err := validateRoute(route); err != nil {
			return nil, err
		}
		if seenPrefixes[route.Prefix] {
			return nil, fmt.Errorf("%w: prefix %q appears twice", ErrInvalidRoute, route.Prefix)
		}
		seenPrefixes[route.Prefix] = true
	}
	return &RouteTable{routes: slices.Clone(routes)}, nil
}

// validateRoute reports the first mistake in one route.
func validateRoute(route Route) error {
	isDirectoryPrefix := strings.HasPrefix(route.Prefix, "/") && strings.HasSuffix(route.Prefix, "/")
	if !isDirectoryPrefix || !isCleanPath(route.Prefix) {
		return fmt.Errorf("%w: prefix %q must start and end with / and have no empty, . or .. segment", ErrInvalidRoute, route.Prefix)
	}
	upstream, err := url.Parse(route.Upstream)
	isHTTPURL := err == nil && (upstream.Scheme == "http" || upstream.Scheme == "https") && upstream.Host != ""
	if !isHTTPURL {
		return fmt.Errorf("%w: upstream %q of %s is not an http or https URL", ErrInvalidRoute, route.Upstream, route.Prefix)
	}
	if route.ResourceType == "" {
		return fmt.Errorf("%w: %s has no resource type", ErrInvalidRoute, route.Prefix)
	}
	if route.Sensitivity < 0 || route.Sensitivity > 4 {
		return fmt.Errorf("%w: %s has sensitivity %d, want 0 to 4", ErrInvalidRoute, route.Prefix, route.Sensitivity)
	}
	return nil
}

// Match returns the route with the longest prefix that path starts with. The
// prefix itself without its last "/" also matches, so "/bay-1/telemetry" is
// in the route "/bay-1/telemetry/". A path with an empty, "." or ".."
// segment matches nothing: the upstream might resolve it to a resource the
// route does not cover.
func (table *RouteTable) Match(path string) (Route, bool) {
	if !strings.HasPrefix(path, "/") || !isCleanPath(path) {
		return Route{}, false
	}
	var best Route
	found := false
	for _, route := range table.routes {
		isInRoute := strings.HasPrefix(path, route.Prefix) || path+"/" == route.Prefix
		isLonger := !found || len(route.Prefix) > len(best.Prefix)
		if isInRoute && isLonger {
			best, found = route, true
		}
	}
	return best, found
}

// isCleanPath reports whether path, which starts with "/", has no empty, "."
// or ".." segment. A trailing "/" is allowed.
func isCleanPath(path string) bool {
	segments := strings.Split(strings.TrimSuffix(path[1:], "/"), "/")
	if len(segments) == 1 && segments[0] == "" {
		return true // the path "/"
	}
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

// ActionFor returns the action of an HTTP request: GET and HEAD read, PUT and
// PATCH write, DELETE is admin, and POST writes, except that it operates a
// breaker, executes a task and migrates a service. Any other method has no
// action and reports false, so the PEP can reject it before asking the PDP.
func ActionFor(method, resourceType string) (string, bool) {
	switch method {
	case http.MethodGet, http.MethodHead:
		return "read", true
	case http.MethodPut, http.MethodPatch:
		return "write", true
	case http.MethodDelete:
		return "admin", true
	case http.MethodPost:
		switch resourceType {
		case "breaker":
			return "operate", true
		case "task":
			return "execute", true
		case "service":
			return "migrate", true
		}
		return "write", true
	}
	return "", false
}
