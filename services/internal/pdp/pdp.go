// Package pdp is the Policy Decision Point of NIST SP 800-207: the service a
// Policy Enforcement Point (PEP) asks whether a request may go ahead.
//
// A decision combines the ABAC policy (package policy) with the subject's
// current trust score (package trust). Every denial is fed back into the trust
// store as a signal, so a subject that keeps probing loses trust.
//
// The PDP fills in the facts about a request that it must not take from the
// PEP: the time, the trust score and whether the grid is in emergency mode. A
// compromised or buggy PEP can therefore not raise its own trust, claim an
// emergency or pick an hour at which a rule does not apply.
//
// Industry equivalents: the policy engine of Open Policy Agent, AWS Verified
// Access, Google BeyondCorp's access control engine.
package pdp

import (
	"context"
	"sync/atomic"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/model"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/policy"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/trust"
)

// Decider answers access requests. The PDP, a decision cache and a client for
// a remote PDP all implement it, so a PEP does not know which one it talks to.
// On an error the decision is always a deny.
type Decider interface {
	Decide(ctx context.Context, request model.AccessRequest) (model.Decision, error)
}

// PDP decides access requests from a policy engine and a trust store.
type PDP struct {
	Name   string         // copied into Decision.DecidedBy, e.g. "cloud-pdp"
	Engine *policy.Engine // the installed policy
	Trust  *trust.Store   // trust scores, and the clock of every decision
	// CompromiseThreshold is the behaviour signal at or above which a
	// subject is declared compromised. 0 turns the escalation off.
	CompromiseThreshold float64

	emergency atomic.Bool
}

// New returns a PDP called name with the given engine, an empty trust store
// with default parameters, and a compromise threshold of 0.9.
func New(name string, engine *policy.Engine) *PDP {
	return &PDP{Name: name, Engine: engine, Trust: trust.NewStore(nil), CompromiseThreshold: 0.9}
}

// SetEmergency turns emergency (break-glass) mode on or off for every
// decision. Only the PDP decides this; a request cannot claim it.
func (pdp *PDP) SetEmergency(on bool) { pdp.emergency.Store(on) }

// Emergency reports whether emergency mode is on.
func (pdp *PDP) Emergency() bool { return pdp.emergency.Load() }

// Decide evaluates request and returns the decision. It sets the request time
// from the trust store's clock, the trust score from the trust store and the
// emergency flag from the PDP, whatever the request said, then evaluates the
// policy. A denial is recorded as a trust signal for the subject. The error is
// non-nil only if ctx is done, and the decision is then a deny.
func (pdp *PDP) Decide(ctx context.Context, request model.AccessRequest) (model.Decision, error) {
	if err := ctx.Err(); err != nil {
		return model.Decision{Effect: model.Deny, Reason: "request cancelled", DecidedBy: pdp.Name}, err
	}
	subjectID := request.Subject.ID
	request.Context.Time = pdp.Trust.Now()
	request.Context.TrustScore = pdp.Trust.Score(subjectID)
	request.Context.Emergency = pdp.Emergency()

	decision := pdp.Engine.Evaluate(request)
	if !decision.Allowed() && subjectID != "" {
		// A denial lowers trust, which slows down a subject that probes for
		// what it may do. The signal is valid, so Record cannot fail.
		denial := trust.Signal{Subject: subjectID, Kind: trust.Denial, Time: request.Context.Time, Source: pdp.Name}
		_ = pdp.Trust.Record(denial)
	}
	decision.DecidedBy = pdp.Name
	decision.TrustScore = request.Context.TrustScore
	return decision, nil
}

// RecordSignal feeds signal into the trust store. A behaviour signal at or
// above CompromiseThreshold also declares the subject compromised, which drops
// its trust to 0. It reports whether this signal newly declared a compromise,
// and returns the store's error for an invalid signal.
func (pdp *PDP) RecordSignal(signal trust.Signal) (bool, error) {
	if err := pdp.Trust.Record(signal); err != nil {
		return false, err
	}
	escalationIsOn := pdp.CompromiseThreshold > 0
	reachesThreshold := signal.Value >= pdp.CompromiseThreshold // false for NaN
	if signal.Kind != trust.Behaviour || !escalationIsOn || !reachesThreshold {
		return false, nil
	}
	state, _ := pdp.Trust.State(signal.Subject)
	if state.Compromised {
		return false, nil
	}
	compromise := trust.Signal{Subject: signal.Subject, Kind: trust.Compromise, Time: signal.Time, Source: signal.Source}
	if err := pdp.Trust.Record(compromise); err != nil {
		return false, err
	}
	return true, nil
}

// Check at compile time that *PDP satisfies Decider.
var _ Decider = (*PDP)(nil)
