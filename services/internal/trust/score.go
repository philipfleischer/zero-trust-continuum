// The trust score: how signals change a subject's State, and how a State
// becomes a number in [0, 1] at a given time.

package trust

import (
	"math"
	"time"
)

// Weights are the shares of the four components of the score. They sum to 1,
// so a subject that is perfect in every component scores 1.
type Weights struct {
	Authentication float64 `json:"authentication"`
	Posture        float64 `json:"posture"`
	Behaviour      float64 `json:"behaviour"`
	Location       float64 `json:"location"`
}

// DefaultWeights favour the signals that change within seconds
// (authentication and behaviour) over posture, which changes slowly, and
// location, which is weak evidence where devices never move.
var DefaultWeights = Weights{Authentication: 0.35, Posture: 0.25, Behaviour: 0.30, Location: 0.10}

// Evaluator holds the parameters of the trust algorithm. RQ4 varies them.
type Evaluator struct {
	Weights Weights
	// AuthHalfLife is how fast authentication fades: after one half-life
	// without a new authentication it counts half.
	AuthHalfLife time.Duration
	// DenialPenalty is subtracted from the score per recent denial.
	DenialPenalty float64
	// DenialHalfLife is how fast the denial penalty fades.
	DenialHalfLife time.Duration
	// Alpha is the smoothing factor for behaviour and location (0..1): the
	// weight of the newest signal against the history.
	Alpha float64
}

// NewEvaluator returns an evaluator with DefaultWeights, a 5 min
// authentication half-life, a 0.1 penalty per denial with a 10 min half-life,
// and Alpha 0.5.
func NewEvaluator() *Evaluator {
	return &Evaluator{
		Weights:        DefaultWeights,
		AuthHalfLife:   5 * time.Minute,
		DenialPenalty:  0.1,
		DenialHalfLife: 10 * time.Minute,
		Alpha:          0.5,
	}
}

// Apply returns state updated with signal; state itself is not changed.
// Values are clamped to [0, 1] and NaN counts as 0. A signal without a time is
// applied at state.LastUpdate. An authentication with strength 0, or older
// than the last one, is ignored, and an unknown kind changes nothing.
func (evaluator *Evaluator) Apply(state State, signal Signal) State {
	observedAt := signal.Time
	if observedAt.IsZero() {
		observedAt = state.LastUpdate
	}
	value := clampToUnitInterval(signal.Value)
	smoothing := evaluator.Alpha
	switch signal.Kind {
	case Authentication:
		hasNoProof := value == 0 || observedAt.IsZero()
		isOlderThanLastProof := observedAt.Before(state.LastAuth)
		if hasNoProof || isOlderThanLastProof {
			return state
		}
		state.AuthStrength, state.LastAuth = value, observedAt
	case Posture:
		state.Posture = value
	case Behaviour:
		state.Anomaly = smoothing*value + (1-smoothing)*state.Anomaly
	case Location:
		state.Location = smoothing*value + (1-smoothing)*state.Location
	case Denial:
		// Decay the old count to observedAt, then add this denial.
		decayFactor := halfLifeFactor(observedAt.Sub(state.LastDenial), evaluator.DenialHalfLife)
		state.Denials = state.Denials*decayFactor + 1
		if observedAt.After(state.LastDenial) {
			state.LastDenial = observedAt
		}
	case Compromise:
		state.Compromised = true
	default:
		return state
	}
	if observedAt.After(state.LastUpdate) {
		state.LastUpdate = observedAt
	}
	return state
}

// Score returns the trust score of state at time now, in [0, 1]:
//
//	auth  = AuthStrength · 0.5^((now − LastAuth) / AuthHalfLife)
//	score = wA·auth + wP·Posture + wB·(1 − Anomaly) + wL·Location
//	        − DenialPenalty · Denials · 0.5^((now − LastDenial) / DenialHalfLife)
//
// A compromised subject, and a subject that has never authenticated, scores 0.
func (evaluator *Evaluator) Score(state State, now time.Time) float64 {
	if state.Compromised || state.LastAuth.IsZero() {
		return 0
	}
	weights := evaluator.Weights
	authentication := state.AuthStrength * halfLifeFactor(now.Sub(state.LastAuth), evaluator.AuthHalfLife)
	score := weights.Authentication*authentication +
		weights.Posture*state.Posture +
		weights.Behaviour*(1-state.Anomaly) +
		weights.Location*state.Location
	denialDecay := halfLifeFactor(now.Sub(state.LastDenial), evaluator.DenialHalfLife)
	score -= evaluator.DenialPenalty * state.Denials * denialDecay
	return clampToUnitInterval(score)
}

// halfLifeFactor returns 0.5^(age/halfLife): 1 for a fresh event, 0.5 after
// one half-life. A negative age (clock skew) counts as 0, and a half-life of
// 0 or less makes everything older than now worthless.
func halfLifeFactor(age, halfLife time.Duration) float64 {
	if age <= 0 {
		return 1
	}
	if halfLife <= 0 {
		return 0
	}
	return math.Pow(0.5, float64(age)/float64(halfLife))
}

// clampToUnitInterval limits number to [0, 1] and turns NaN into 0, the least
// trusted value.
func clampToUnitInterval(number float64) float64 {
	switch {
	case math.IsNaN(number) || number < 0:
		return 0
	case number > 1:
		return 1
	}
	return number
}
