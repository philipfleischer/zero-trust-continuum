// Test vectors for the trust score, computed by hand before the code existed.
// The C++ core in sim/core (M6) must produce the same numbers.

package trust

import (
	"math"
	"testing"
	"time"
)

// referenceTime is the reference time of every vector.
var referenceTime = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

// near reports whether got and want are equal within 1e-9, enough for float64
// arithmetic and strict enough to catch any wrong term in the formula.
func near(got, want float64) bool { return math.Abs(got-want) < 1e-9 }

// verified is a subject that authenticated with full strength at referenceTime and is
// perfect in every other component.
func verified() State {
	return State{AuthStrength: 1, LastAuth: referenceTime, Posture: 1, Anomaly: 0, Location: 1, LastUpdate: referenceTime}
}

func TestNewEvaluatorDefaults(t *testing.T) {
	evaluator := NewEvaluator()
	weights := evaluator.Weights
	if !near(weights.Authentication+weights.Posture+weights.Behaviour+weights.Location, 1) {
		t.Errorf("weights %+v do not sum to 1", weights)
	}
	if evaluator.AuthHalfLife != 5*time.Minute || evaluator.DenialHalfLife != 10*time.Minute || evaluator.DenialPenalty != 0.1 || evaluator.Alpha != 0.5 {
		t.Errorf("NewEvaluator() = %+v", evaluator)
	}
}

// TestScoreVectors checks the formula on fixed states. Each row shows the
// arithmetic, with weights 0.35 / 0.25 / 0.30 / 0.10.
func TestScoreVectors(t *testing.T) {
	tests := []struct {
		name  string
		state func() State
		now   time.Time
		want  float64
	}{
		// 0.35·1 + 0.25·1 + 0.30·(1−0) + 0.10·1
		{"verified, just authenticated", verified, referenceTime, 1.0},
		// auth = 1·0.5¹ = 0.5 → 0.175 + 0.25 + 0.30 + 0.10
		{"one half-life later", verified, referenceTime.Add(5 * time.Minute), 0.825},
		// auth = 1·0.5² = 0.25 → 0.0875 + 0.65
		{"two half-lives later", verified, referenceTime.Add(10 * time.Minute), 0.7375},
		// auth = 1·0.5¹² → 0.35/4096 + 0.65
		{"one hour later", verified, referenceTime.Add(time.Hour), 0.65 + 0.35/4096},
		// a clock behind LastAuth gives no extra credit: age counts as 0
		{"clock skew", verified, referenceTime.Add(-time.Minute), 1.0},
		// bearer token: 0.35·0.5 + 0.65
		{"token, just authenticated", func() State { state := verified(); state.AuthStrength = 0.5; return state }, referenceTime, 0.825},
		// 0.35·0.5·0.5 + 0.65: below 0.8, so a breaker needs a fresh, stronger login (step-up)
		{"token, one half-life later", func() State { state := verified(); state.AuthStrength = 0.5; return state }, referenceTime.Add(5 * time.Minute), 0.7375},
		// 0.35 + 0.25 + 0.30·(1−0.5) + 0.10
		{"anomaly 0.5", func() State { state := verified(); state.Anomaly = 0.5; return state }, referenceTime, 0.85},
		// 1.0 − 0.1·1·0.5⁰
		{"one denial just now", func() State { state := verified(); state.Denials, state.LastDenial = 1, referenceTime; return state }, referenceTime, 0.9},
		// 1.0 − 0.1·3
		{"three denials just now", func() State { state := verified(); state.Denials, state.LastDenial = 3, referenceTime; return state }, referenceTime, 0.7},
		// fresh login at referenceTime+10m, denial at referenceTime: 1.0 − 0.1·1·0.5¹
		{"denial ten minutes old", func() State {
			state := verified()
			state.LastAuth, state.Denials, state.LastDenial = referenceTime.Add(10*time.Minute), 1, referenceTime
			return state
		}, referenceTime.Add(10 * time.Minute), 0.95},
		// 0.175 + 0 + 0 + 0 − 0.5 = −0.325, clamped
		{"clamped at 0", func() State {
			return State{AuthStrength: 0.5, LastAuth: referenceTime, Anomaly: 1, Denials: 5, LastDenial: referenceTime}
		}, referenceTime, 0},
		{"compromised", func() State { state := verified(); state.Compromised = true; return state }, referenceTime, 0},
		// perfect in everything but authentication: no proof, no trust
		{"never authenticated", func() State { state := verified(); state.AuthStrength, state.LastAuth = 0, time.Time{}; return state }, referenceTime, 0},
		{"zero state", func() State { return State{} }, referenceTime, 0},
	}
	evaluator := NewEvaluator()
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			if got := evaluator.Score(testCase.state(), testCase.now); !near(got, testCase.want) {
				t.Errorf("Score() = %.12f, want %.12f", got, testCase.want)
			}
		})
	}
}

func TestScoreNaNWeights(t *testing.T) {
	evaluator := NewEvaluator()
	evaluator.Weights.Posture = math.NaN()
	if got := evaluator.Score(verified(), referenceTime); got != 0 {
		t.Errorf("Score() with a NaN weight = %v, want 0", got)
	}
}

// TestApply checks how each kind of signal changes the state.
func TestApply(t *testing.T) {
	later := referenceTime.Add(10 * time.Minute)
	tests := []struct {
		name    string
		start   State
		signals []Signal
		check   func(state State) bool
	}{
		{"authentication sets strength and time", State{}, []Signal{{Kind: Authentication, Value: 0.8, Time: referenceTime}},
			func(state State) bool {
				return state.AuthStrength == 0.8 && state.LastAuth.Equal(referenceTime) && state.LastUpdate.Equal(referenceTime)
			}},
		{"authentication above 1 is clamped", State{}, []Signal{{Kind: Authentication, Value: 7, Time: referenceTime}},
			func(state State) bool { return state.AuthStrength == 1 }},
		{"authentication with strength 0 is ignored", State{}, []Signal{{Kind: Authentication, Value: 0, Time: referenceTime}},
			func(state State) bool { return state.LastAuth.IsZero() }},
		{"authentication with NaN is ignored", State{}, []Signal{{Kind: Authentication, Value: math.NaN(), Time: referenceTime}},
			func(state State) bool { return state.LastAuth.IsZero() }},
		{"older authentication is ignored", State{}, []Signal{
			{Kind: Authentication, Value: 0.5, Time: later}, {Kind: Authentication, Value: 1, Time: referenceTime}},
			func(state State) bool {
				return state.AuthStrength == 0.5 && state.LastAuth.Equal(later) && state.LastUpdate.Equal(later)
			}},
		{"posture NaN counts as 0", State{Posture: 1}, []Signal{{Kind: Posture, Value: math.NaN(), Time: referenceTime}},
			func(state State) bool { return state.Posture == 0 }},
		// 0.5·1 + 0.5·0 = 0.5, then 0.5·1 + 0.5·0.5 = 0.75
		{"behaviour is smoothed", State{}, []Signal{{Kind: Behaviour, Value: 1, Time: referenceTime}, {Kind: Behaviour, Value: 1, Time: referenceTime}},
			func(state State) bool { return near(state.Anomaly, 0.75) }},
		// 0.5·0 + 0.5·1
		{"one unexpected location halves it", State{Location: 1}, []Signal{{Kind: Location, Value: 0, Time: referenceTime}},
			func(state State) bool { return near(state.Location, 0.5) }},
		// 1·0.5¹ + 1
		{"denials decay from the last denial", State{}, []Signal{{Kind: Denial, Time: referenceTime}, {Kind: Denial, Time: later}},
			func(state State) bool { return near(state.Denials, 1.5) && state.LastDenial.Equal(later) }},
		{"other signals leave the denial clock alone", State{}, []Signal{{Kind: Denial, Time: referenceTime}, {Kind: Posture, Value: 1, Time: later}},
			func(state State) bool {
				return state.Denials == 1 && state.LastDenial.Equal(referenceTime) && state.LastUpdate.Equal(later)
			}},
		{"compromise", State{}, []Signal{{Kind: Compromise, Time: referenceTime}},
			func(state State) bool { return state.Compromised }},
		{"signal without time uses LastUpdate", State{LastUpdate: referenceTime}, []Signal{{Kind: Authentication, Value: 1}},
			func(state State) bool { return state.LastAuth.Equal(referenceTime) }},
		{"unknown kind changes nothing", State{Posture: 1, LastUpdate: referenceTime}, []Signal{{Kind: "reset", Value: 1, Time: later}},
			func(state State) bool { return state == State{Posture: 1, LastUpdate: referenceTime} }},
	}
	evaluator := NewEvaluator()
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			state := testCase.start
			for _, signal := range testCase.signals {
				state = evaluator.Apply(state, signal)
			}
			if !testCase.check(state) {
				t.Errorf("state = %+v", state)
			}
		})
	}
}

// TestDenialDoesNotCreateTrust is the first flaw of the original algorithm:
// a subject that never authenticated reached 0.3 by being denied once.
func TestDenialDoesNotCreateTrust(t *testing.T) {
	evaluator := NewEvaluator()
	state := evaluator.Apply(State{}, Signal{Kind: Denial, Time: referenceTime})
	for _, now := range []time.Time{referenceTime, referenceTime.Add(time.Hour)} {
		if got := evaluator.Score(state, now); got != 0 {
			t.Errorf("Score(%v) = %v, want 0", now.Sub(referenceTime), got)
		}
	}
}

// TestGoodSignalNeverLowersScore is the second flaw of the original: a posture
// signal after a denial reset the denial penalty to full strength.
func TestGoodSignalNeverLowersScore(t *testing.T) {
	evaluator := NewEvaluator()
	state := evaluator.Apply(verified(), Signal{Kind: Denial, Time: referenceTime})
	later := referenceTime.Add(10 * time.Minute)
	without := evaluator.Score(state, later)
	with := evaluator.Score(evaluator.Apply(state, Signal{Kind: Posture, Value: 1, Time: later}), later)
	if with < without {
		t.Errorf("a good posture signal lowered the score from %v to %v", without, with)
	}
}
