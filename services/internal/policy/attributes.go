// Attribute names that policy conditions can use: which names exist, how each
// one is read from an access request, and the glob matching used by patterns.

package policy

import (
	"strconv"
	"strings"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/model"
)

// plainAttributes are the names that map to one fixed field of a request.
var plainAttributes = map[string]bool{
	"subject.id": true, "subject.layer": true, "subject.class": true, "subject.owner": true,
	"subject.zone": true, "subject.role": true, "subject.authMethod": true,
	"resource.id": true, "resource.type": true, "resource.zone": true, "resource.layer": true,
	"resource.sensitivity": true, "action": true,
	"context.trustScore": true, "context.sourceZone": true, "context.sourceLayer": true,
	"context.emergency": true, "context.hour": true,
}

// mapPrefixes name the free-form attribute maps: "subject.attr.site" reads the
// key "site" from Subject.Attributes.
var mapPrefixes = []string{"subject.attr.", "resource.attr.", "context.attr."}

// KnownAttribute reports whether name is an attribute that Resolve can read:
// one of the fixed names, or a map prefix followed by a non-empty key.
func KnownAttribute(name string) bool {
	if plainAttributes[name] {
		return true
	}
	for _, prefix := range mapPrefixes {
		key, hasPrefix := strings.CutPrefix(name, prefix)
		if hasPrefix && key != "" {
			return true
		}
	}
	return false
}

// Resolve returns the value of the attribute name in request as a string, and
// whether the attribute exists. Numbers are formatted with strconv so the
// numeric operators can parse them back, and subject.role is the roles joined
// by commas. A missing map key or an unset time reports false, so a condition
// on it can never match (fail closed).
func Resolve(name string, request model.AccessRequest) (string, bool) {
	subject, resource, requestContext := request.Subject, request.Resource, request.Context
	switch name {
	case "subject.id":
		return subject.ID, true
	case "subject.layer":
		return subject.Layer.String(), true
	case "subject.class":
		return string(subject.Class), true
	case "subject.owner":
		return subject.Owner, true
	case "subject.zone":
		return subject.Zone, true
	case "subject.role":
		return strings.Join(subject.Roles, ","), true
	case "subject.authMethod":
		return subject.AuthMethod, true
	case "resource.id":
		return resource.ID, true
	case "resource.type":
		return resource.Type, true
	case "resource.zone":
		return resource.Zone, true
	case "resource.layer":
		return resource.Layer.String(), true
	case "resource.sensitivity":
		return strconv.Itoa(resource.Sensitivity), true
	case "action":
		return request.Action, true
	case "context.trustScore":
		return strconv.FormatFloat(requestContext.TrustScore, 'f', -1, 64), true
	case "context.sourceZone":
		return requestContext.SourceZone, true
	case "context.sourceLayer":
		return requestContext.SourceLayer.String(), true
	case "context.emergency":
		return strconv.FormatBool(requestContext.Emergency), true
	case "context.hour":
		if requestContext.Time.IsZero() {
			return "", false
		}
		return strconv.Itoa(requestContext.Time.UTC().Hour()), true
	}
	if key, isSubjectAttribute := strings.CutPrefix(name, "subject.attr."); isSubjectAttribute {
		value, found := subject.Attributes[key]
		return value, found
	}
	if key, isResourceAttribute := strings.CutPrefix(name, "resource.attr."); isResourceAttribute {
		value, found := resource.Attributes[key]
		return value, found
	}
	if key, isContextAttribute := strings.CutPrefix(name, "context.attr."); isContextAttribute {
		value, found := requestContext.Attributes[key]
		return value, found
	}
	return "", false
}

// Glob reports whether text matches pattern, where "*" matches any sequence
// of characters (also empty, also across "/") and every other character,
// including "[", "]" and "?", matches only itself. It runs in linear time:
// on a mismatch it backtracks to the last star instead of trying every split.
func Glob(pattern, text string) bool {
	patternPosition, textPosition := 0, 0
	lastStar := -1          // position of the last star in pattern, -1 if none yet
	textPositionAtStar := 0 // where in text that star started matching
	for textPosition < len(text) {
		atStar := patternPosition < len(pattern) && pattern[patternPosition] == '*'
		sameCharacter := patternPosition < len(pattern) && pattern[patternPosition] == text[textPosition]
		switch {
		case atStar:
			// Remember the star and first try letting it match nothing.
			lastStar, textPositionAtStar = patternPosition, textPosition
			patternPosition++
		case sameCharacter:
			patternPosition++
			textPosition++
		case lastStar >= 0:
			// Let the last star swallow one more character and try again.
			patternPosition = lastStar + 1
			textPositionAtStar++
			textPosition = textPositionAtStar
		default:
			return false
		}
	}
	for patternPosition < len(pattern) && pattern[patternPosition] == '*' {
		patternPosition++ // trailing stars match the empty rest
	}
	return patternPosition == len(pattern)
}
