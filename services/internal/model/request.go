package model

import "time"

// Subject is the "who" of an access request: a workload, a device or a human,
// identified by a SPIFFE-style ID (spiffe://<trust-domain>/<layer>/<kind>/<name>).
type Subject struct {
	ID          string            `json:"id"`    // SPIFFE ID
	Layer       Layer             `json:"layer"` // layer the subject currently runs on
	Class       DeviceClass       `json:"class,omitempty"`
	Roles       []string          `json:"roles,omitempty"`      // e.g.: "operator"
	Owner       string            `json:"owner,omitempty"`      // organisation that owns the node
	Zone        string            `json:"zone,omitempty"`       // IEC 62443 zone
	Attributes  map[string]string `json:"attributes,omitempty"` // attribute used by ABAC rules
	AuthMethod  string            `json:"authMethod,omitempty"` // "mtls", "token", "capability" or "none"
	Credentials string            `json:"-"`                    // raw credential, never serialised
}

// Resource is the "what" of an access request.
type Resource struct {
	ID          string            `json:"id"`                   // e.g.: "substation-1/breaker/Q1"
	Type        string            `json:"type"`                 // e.g.: "telemetry", "setpoint", "breaker", "policy", "task"
	Zone        string            `json:"zone,omitempty"`       // IEC 62443 zone that owns the resource
	Layer       Layer             `json:"layer"`                // layer that hosts the resource
	Sensitivity int               `json:"sensitivity"`          // 0 (public) to 4 (safety-critical), maps to IEC 62443 SL
	Attributes  map[string]string `json:"attributes,omitempty"` // extra ABAC attributes
}

// Context carries the environment of the request: when, from
// where, and what the system currently believes about the subject.
type Context struct {
	Time        time.Time         `json:"time"`
	SourceZone  string            `json:"sourceZone,omitempty"`
	SourceLayer Layer             `json:"sourceLayer"`
	TrustScore  float64           `json:"trustScore"`           // filled in by the PDP from the trust store
	Emergency   bool              `json:"emergency,omitempty"`  // break-glass mode during grid incidents
	Attributes  map[string]string `json:"attributes,omitempty"` // e.g. "migration": "in-progress"
}

// AccessRequest is what a PEP sends to a PDP: may Subject perform Action on Resource in Context?
type AccessRequest struct {
	Subject  Subject  `json:"subject"`
	Action   string   `json:"action"` // "read", "write", "operate", "execute", "migrate" or "admin"
	Resource Resource `json:"resource"`
	Context  Context  `json:"context"`
}

// Effect is the outcome of a policy decision.
type Effect string

const (
	// Allow permits the request.
	Allow Effect = "allow"
	// Deny rejects the request. In zero trust, Deny is the default.
	Deny Effect = "deny"
)

// Decision is what a PDP returns to a PEP.
type Decision struct {
	Effect          Effect        `json:"effect"`
	Reason          string        `json:"reason"`                // human-readable, for audit log
	RuleID          string        `json:"ruleId,omitempty"`      // rule that produced the effect
	Obligations     []string      `json:"obligations,omitempty"` // e.g.: "log", "mfa", "rate-limit:10/s"
	TTL             time.Duration `json:"ttl"`                   // Time-To-Live: how long a PEP or fog cache may reuse the decision
	PolicyVersion   uint64        `json:"policyVersion"`         // version of the policy set that was evaluated
	RevocationEpoch uint64        `json:"revocationEpoch"`       // revocation list version seen by the PDP
	TrustScore      float64       `json:"trustScore"`            // trust score used in the decision making
	DecidedBy       string        `json:"decidedBy,omitempty"`   // "cloud-pdp", "fog-cache" and so on (RQ1 measurements)
}

// Allowed reports whether the decision permits the request.
// Anything other than an explicit Allow counts as deny, including the zero value.
func (decision Decision) Allowed() bool { return decision.Effect == Allow }
