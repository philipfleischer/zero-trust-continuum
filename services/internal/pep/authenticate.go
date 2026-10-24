// Authentication: turning the credential of an HTTP request into the
// subject the PDP decides about.

package pep

import (
	"errors"
	"fmt"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/model"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/token"
)

// ErrUnauthenticated wraps every reason Authenticate rejects a request.
var ErrUnauthenticated = errors.New("pep: unauthenticated")

// CapabilityHeader is the request header that carries a capability.
const CapabilityHeader = "X-ZTC-Capability"

// Authenticator turns the credential of a request into a subject. It accepts
// a bearer token in the Authorization header, and otherwise a capability in
// CapabilityHeader; which of the two are accepted is configurable, because
// RQ2 compares them.
type Authenticator struct {
	Tokens            *token.Verifier  // nil means bearer tokens are not accepted
	CapabilityRootKey []byte           // nil means capabilities are not accepted
	TrustDomain       string           // a token's subject must be spiffe://<TrustDomain>/...
	Layer             model.Layer      // the layer this PEP runs on, for "layer <=" caveats
	Now               func() time.Time // nil means time.Now
}

// Authenticate returns the subject of request for route and action, or an
// error wrapping ErrUnauthenticated and the reason. A request with an
// Authorization header is decided by that header alone: an invalid token is
// never followed by a look at the capability.
//
// From a token the subject gets the SPIFFE ID, the layer named in it, and
// the roles and zone the issuer vouched for. A capability names no holder,
// so its subject is "capability:<grant ID>" with no layer, roles or zone.
func (authenticator Authenticator) Authenticate(request *http.Request, route Route, action string) (model.Subject, error) {
	authorization := request.Header.Get("Authorization")
	capability := request.Header.Get(CapabilityHeader)
	switch {
	case authorization != "":
		return authenticator.fromToken(authorization)
	case capability != "":
		return authenticator.fromCapability(capability, request.URL.Path, route, action)
	}
	return model.Subject{}, fmt.Errorf("%w: no credential", ErrUnauthenticated)
}

// fromToken checks a bearer token and returns its subject.
func (authenticator Authenticator) fromToken(authorization string) (model.Subject, error) {
	if authenticator.Tokens == nil {
		return model.Subject{}, fmt.Errorf("%w: bearer tokens are not accepted", ErrUnauthenticated)
	}
	signedToken, isBearer := strings.CutPrefix(authorization, "Bearer ")
	if !isBearer {
		return model.Subject{}, fmt.Errorf("%w: Authorization is not a bearer token", ErrUnauthenticated)
	}
	claims, err := authenticator.Tokens.Verify(signedToken)
	if err != nil {
		return model.Subject{}, fmt.Errorf("%w: %w", ErrUnauthenticated, err)
	}
	layer, err := layerOfSPIFFEID(claims.Subject, authenticator.TrustDomain)
	if err != nil {
		return model.Subject{}, fmt.Errorf("%w: %w", ErrUnauthenticated, err)
	}
	return model.Subject{
		ID:         claims.Subject,
		Layer:      layer,
		Roles:      claims.Roles,
		Zone:       claims.Zone,
		AuthMethod: "token",
	}, nil
}

// fromCapability checks a capability against the request it came with.
func (authenticator Authenticator) fromCapability(encoded, requestPath string, route Route, action string) (model.Subject, error) {
	if authenticator.CapabilityRootKey == nil {
		return model.Subject{}, fmt.Errorf("%w: capabilities are not accepted", ErrUnauthenticated)
	}
	capability, err := token.DecodeCapability(encoded)
	if err != nil {
		return model.Subject{}, fmt.Errorf("%w: %w", ErrUnauthenticated, err)
	}
	now := time.Now
	if authenticator.Now != nil {
		now = authenticator.Now
	}
	resource := ResourceID(requestPath)
	checker := token.StandardChecker(token.Request{
		Action:   action,
		Resource: resource,
		Task:     taskOf(resource, route),
		Layer:    authenticator.Layer,
		Now:      now(),
	})
	if err := capability.Verify(authenticator.CapabilityRootKey, checker); err != nil {
		return model.Subject{}, fmt.Errorf("%w: %w", ErrUnauthenticated, err)
	}
	return model.Subject{ID: "capability:" + capability.ID, AuthMethod: "capability"}, nil
}

// ResourceID returns the resource ID of a request path: the path without its
// leading "/", e.g. "bay-1/telemetry/pmu-1".
func ResourceID(requestPath string) string {
	return strings.TrimPrefix(requestPath, "/")
}

// taskOf returns the ID of the task a request is about: the last segment of
// the resource ID on a task route, and "" on any other route. It comes from
// the path, never from a header, so a "task = t-7" caveat cannot be met by a
// request for another task that merely claims to be about t-7.
func taskOf(resource string, route Route) string {
	if route.ResourceType != "task" {
		return ""
	}
	return path.Base(resource)
}

// layerOfSPIFFEID returns the layer of a SPIFFE ID of the form
// spiffe://<trustDomain>/<layer>/<kind>/<name>, and an error for an ID in
// another trust domain or with an unknown layer. The full SPIFFE parser comes
// with the identity package in M5.
func layerOfSPIFFEID(spiffeID, trustDomain string) (model.Layer, error) {
	pathAfterDomain, isInTrustDomain := strings.CutPrefix(spiffeID, "spiffe://"+trustDomain+"/")
	if !isInTrustDomain {
		return model.LayerUnknown, fmt.Errorf("subject %q is not in the trust domain %s", spiffeID, trustDomain)
	}
	layerName, _, _ := strings.Cut(pathAfterDomain, "/")
	return model.ParseLayer(layerName)
}
