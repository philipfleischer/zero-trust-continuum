// Capabilities: macaroon-style bearer credentials that any holder can narrow
// but nobody can widen.

package token

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/model"
)

// MinRootKeySize is the shortest root key accepted, in bytes. HMAC-SHA256 is
// only as strong as its key; 32 random bytes match the size of the hash.
const MinRootKeySize = 32

// MaxCaveats is the most caveats a capability may carry. Verify computes one
// HMAC per caveat, so without a limit a long chain costs the verifier CPU.
const MaxCaveats = 32

// Capability is a macaroon-style credential (Birgisson et al., NDSS 2014):
//
//	sig_0 = HMAC(rootKey, ID)
//	sig_i = HMAC(sig_{i-1}, caveat_i)
//
// A holder can add a caveat by computing the next HMAC from Signature, but cannot
// remove one, because that would mean finding sig_{i-1} from sig_i. Only the
// issuer, who knows the root key, can verify. In ZTC the PDP gives a
// capability to an edge device, and when the device offloads a task to a fog
// node it hands over a narrower copy: "only task t-7", "for 30 seconds",
// "only on the fog layer".
type Capability struct {
	Location  string   `json:"loc"` // which service verifies it; a hint, not covered by Signature
	ID        string   `json:"id"`  // names the grant and the root key
	Caveats   []string `json:"cav"` // restrictions, e.g. "action = read"
	Signature []byte   `json:"sig"` // the last HMAC-SHA256 of the chain
}

// Errors returned by the capability functions.
var (
	ErrRootKey             = errors.New("capability: root key too short")
	ErrCapabilitySignature = errors.New("capability: bad signature")
	ErrCaveat              = errors.New("capability: caveat not satisfied")
)

// chainLink returns HMAC-SHA256(key, message), one link of the chain.
func chainLink(key []byte, message string) []byte {
	hash := hmac.New(sha256.New, key)
	hash.Write([]byte(message))
	return hash.Sum(nil)
}

// NewCapability mints a capability without caveats for the grant grantID. The
// root key must be at least MinRootKeySize bytes.
func NewCapability(rootKey []byte, grantID, location string) (Capability, error) {
	if len(rootKey) < MinRootKeySize {
		return Capability{}, ErrRootKey
	}
	return Capability{Location: location, ID: grantID, Signature: chainLink(rootKey, grantID)}, nil
}

// Attenuate returns a copy of capability with one more caveat. It does not
// change capability, so one capability can be narrowed in different ways for
// different holders.
func (capability Capability) Attenuate(caveat string) Capability {
	return Capability{
		Location:  capability.Location,
		ID:        capability.ID,
		Caveats:   append(slices.Clone(capability.Caveats), caveat),
		Signature: chainLink(capability.Signature, caveat),
	}
}

// CaveatChecker decides whether one caveat holds for the current request. It
// must return an error wrapping ErrCaveat for a caveat it does not understand.
type CaveatChecker func(caveat string) error

// Verify recomputes the HMAC chain from rootKey, compares it with
// capability.Signature in constant time, and then asks check about every caveat. All
// caveats must hold. A nil check accepts only a capability without caveats.
func (capability Capability) Verify(rootKey []byte, check CaveatChecker) error {
	if len(rootKey) < MinRootKeySize {
		return ErrRootKey
	}
	if len(capability.Caveats) > MaxCaveats {
		return ErrMalformed
	}
	expectedSignature := chainLink(rootKey, capability.ID)
	for _, caveat := range capability.Caveats {
		expectedSignature = chainLink(expectedSignature, caveat)
	}
	if !hmac.Equal(expectedSignature, capability.Signature) {
		return ErrCapabilitySignature
	}
	for _, caveat := range capability.Caveats {
		if check == nil {
			return fmt.Errorf("%w: no checker for %q", ErrCaveat, caveat)
		}
		if err := check(caveat); err != nil {
			return err
		}
	}
	return nil
}

// Encode returns capability as base64url JSON, for an HTTP header.
func (capability Capability) Encode() string {
	jsonBytes, _ := json.Marshal(capability) // cannot fail: only strings and bytes
	return base64URL.EncodeToString(jsonBytes)
}

// DecodeCapability is the inverse of Encode. It rejects input longer than
// MaxTokenSize, more than MaxCaveats caveats, an empty ID and a signature that
// is not one HMAC-SHA256 long.
func DecodeCapability(encoded string) (Capability, error) {
	if len(encoded) > MaxTokenSize {
		return Capability{}, ErrMalformed
	}
	var capability Capability
	if err := decodePart(encoded, &capability); err != nil {
		return Capability{}, err
	}
	hasValidShape := capability.ID != "" &&
		len(capability.Signature) == sha256.Size &&
		len(capability.Caveats) <= MaxCaveats
	if !hasValidShape {
		return Capability{}, ErrMalformed
	}
	return capability, nil
}

// Request is what StandardChecker compares the caveats with.
type Request struct {
	Action   string      // e.g. "execute"
	Resource string      // e.g. "substation-1/task/t-7"
	Task     string      // ID of the offloaded task, if any
	Layer    model.Layer // the layer of the node that verifies
	Now      time.Time
}

// StandardChecker returns a CaveatChecker for the caveats used in ZTC, each
// of the form "<key> <op> <value>":
//
//	action = <a>          the request's action is a
//	resource ^= <prefix>  the resource ID starts with prefix
//	task = <id>           the request is for this offloaded task
//	layer <= <layer>      the verifying node is on this layer or nearer the edge
//	expires < <unix>      the time is before this Unix second
//
// Anything else, including an unknown key, is not satisfied: fail closed.
func StandardChecker(request Request) CaveatChecker {
	return func(caveat string) error {
		key, operator, value, isWellFormed := splitCaveat(caveat)
		if !isWellFormed {
			return fmt.Errorf("%w: malformed %q", ErrCaveat, caveat)
		}
		var holds bool
		switch key + " " + operator {
		case "action =":
			holds = request.Action == value
		case "resource ^=":
			holds = strings.HasPrefix(request.Resource, value)
		case "task =":
			holds = request.Task == value
		case "layer <=":
			limit, err := model.ParseLayer(value)
			knowsItsLayer := request.Layer != model.LayerUnknown
			holds = err == nil && knowsItsLayer && request.Layer <= limit
		case "expires <":
			expiresAt, err := strconv.ParseInt(value, 10, 64)
			holds = err == nil && request.Now.Before(time.Unix(expiresAt, 0))
		default:
			return fmt.Errorf("%w: unknown caveat %q", ErrCaveat, caveat)
		}
		if !holds {
			return fmt.Errorf("%w: %q", ErrCaveat, caveat)
		}
		return nil
	}
}

// splitCaveat splits "key operator value" at the first two spaces.
func splitCaveat(caveat string) (key, operator, value string, isWellFormed bool) {
	key, rest, hasFirstSpace := strings.Cut(caveat, " ")
	operator, value, hasSecondSpace := strings.Cut(rest, " ")
	return key, operator, value, hasFirstSpace && hasSecondSpace
}
