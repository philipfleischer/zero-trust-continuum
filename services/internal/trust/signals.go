// Package trust implements the trust algorithm of NIST SP 800-207: a
// continuously updated score in [0, 1] for every subject, computed from
// signals about it. The PDP writes the score into context.trustScore before
// the policy is evaluated, so a rule can say "operating a breaker requires
// trust >= 0.8".
//
// Verification is continuous: the authentication part of the score decays
// with time since the last authentication, and negative signals (an IDS
// alert, a denied request, a compromise verdict) lower it at once. How fast
// and how much is what research question RQ4 evaluates.
//
// The same formula is implemented in C++ in sim/core (M6) and described in
// Docs/architecture/trust-algorithm.md. Change all three together.
//
// Industry equivalents: Google BeyondCorp access levels, Microsoft Entra
// Conditional Access risk, device posture checks in Zscaler and Cloudflare.
package trust

import "time"

// Kind is the category of a signal.
type Kind string

// The signal kinds. Value is always in [0, 1]; values outside are clamped.
const (
	// Authentication is a successful authentication. Value is its strength:
	// 0.5 bearer token, 0.6 capability, 0.8 mTLS, 1.0 mTLS with attestation.
	Authentication Kind = "authentication"
	// Posture is device health: 1 is patched and attested, 0 is unknown or failed.
	Posture Kind = "posture"
	// Behaviour is an anomaly score from the IDS: 0 is normal, 1 is certainly malicious.
	Behaviour Kind = "behaviour"
	// Location is whether the request came from the subject's expected zone (1) or not (0).
	Location Kind = "location"
	// Denial is a request by the subject that the PDP denied. Value is ignored.
	Denial Kind = "denial"
	// Compromise is a verdict that the subject is compromised. It forces the score to 0.
	Compromise Kind = "compromise"
)

// Valid reports whether kind is one of the defined signal kinds, so an API can
// reject a signal it would otherwise ignore.
func (kind Kind) Valid() bool {
	switch kind {
	case Authentication, Posture, Behaviour, Location, Denial, Compromise:
		return true
	}
	return false
}

// Signal is one observation about a subject.
type Signal struct {
	Subject string    `json:"subject"`          // SPIFFE ID of the subject
	Kind    Kind      `json:"kind"`             // what was observed
	Value   float64   `json:"value"`            // strength of the observation, see Kind
	Time    time.Time `json:"time"`             // when it was observed; zero means "now"
	Source  string    `json:"source,omitempty"` // who reported it, e.g. "ztc-ids@fog-1"
}

// State is everything the trust algorithm remembers about one subject.
// The zero value is a subject that has never authenticated, which scores 0.
type State struct {
	AuthStrength float64   `json:"authStrength"` // strength of the last authentication
	LastAuth     time.Time `json:"lastAuth"`     // zero = never authenticated
	Posture      float64   `json:"posture"`      // last posture value
	Anomaly      float64   `json:"anomaly"`      // smoothed behaviour score
	Location     float64   `json:"location"`     // smoothed location score
	Denials      float64   `json:"denials"`      // denial count, decayed to LastDenial
	LastDenial   time.Time `json:"lastDenial"`   // time of the last denial
	Compromised  bool      `json:"compromised"`  // hard override to 0
	LastUpdate   time.Time `json:"lastUpdate"`   // time of the newest signal
}

// Level is a coarse class of a score, for logs and dashboards.
type Level string

// The levels, from best to worst. The bounds match the thresholds in the
// default substation policy.
const (
	High      Level = "high"      // >= 0.8: may operate a breaker
	Medium    Level = "medium"    // >= 0.5: may read telemetry and run tasks
	Low       Level = "low"       // >= 0.3: above the zero trust floor
	Untrusted Level = "untrusted" // < 0.3 or not a number: denied everything
)

// LevelOf returns the level of score. NaN is Untrusted.
func LevelOf(score float64) Level {
	switch {
	case score >= 0.8:
		return High
	case score >= 0.5:
		return Medium
	case score >= 0.3:
		return Low
	default:
		return Untrusted
	}
}
