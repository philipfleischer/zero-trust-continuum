// Attacks: what a compromised device sends instead of its honest samples.
// ztc-edge switches one on with ZTC_ATTACK, and the IDS and trust score are
// tested against them.

package devices

import (
	"fmt"
	"time"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/telemetry"
)

// Attack turns the honest sample of a compromised device into what it sends.
// An attack keeps state, so each device needs its own.
type Attack interface {
	// Name is the name NewAttack knows the attack by.
	Name() string
	// Technique is the MITRE ATT&CK for ICS technique the attack stands for.
	Technique() string
	// Apply returns the points to send instead of the honest sample. Before
	// the attack starts, that is the sample itself.
	Apply(sample telemetry.Point) []telemetry.Point
}

// The attack names NewAttack accepts.
const (
	AttackFDI     = "fdi"
	AttackFDIRamp = "fdi-ramp"
	AttackReplay  = "replay"
	AttackFlood   = "flood"
)

// rampDuration is how long the slow FDI attack takes to reach its full bias.
const rampDuration = 5 * time.Minute

// falseDataTargets says which field false data injection changes for each
// kind, and by how much: several times the noise of the field, so an anomaly
// detector can see it, but small enough to look plausible to an operator. A
// breaker reports a position, not a measured value, so it has no target.
var falseDataTargets = map[Kind]struct {
	field string
	bias  float64
}{
	PMU:       {"voltage_kv", 4},
	Meter:     {"power_kw", 2},
	RTU:       {"oil_temperature_c", 5},
	EVCharger: {"power_kw", 5},
}

// NewAttack returns the attack called name for a device of the given kind,
// starting at start. An attack that cannot change the kind's samples is an
// error, so ZTC_ATTACK=fdi on a breaker does not run as a silent no-op.
func NewAttack(name string, kind Kind, start time.Time) (Attack, error) {
	switch name {
	case AttackFDI, AttackFDIRamp:
		target, found := falseDataTargets[kind]
		if !found {
			return nil, fmt.Errorf("devices: attack %q cannot change the samples of a %s", name, kind)
		}
		injection := &FalseDataInjection{Field: target.field, Bias: target.bias, Start: start}
		if name == AttackFDIRamp {
			injection.Ramp = rampDuration
		}
		return injection, nil
	case AttackReplay:
		return &Replay{Start: start, Keep: 100}, nil
	case AttackFlood:
		return &Flood{Factor: 20, Start: start}, nil
	}
	return nil, fmt.Errorf("devices: unknown attack %q, want %s, %s, %s or %s", name, AttackFDI, AttackFDIRamp, AttackReplay, AttackFlood)
}

// FalseDataInjection adds Bias to Field from Start on. With a Ramp, the bias
// grows linearly from 0 over that time: a slow drift that an EWMA detector
// adapts to, but CUSUM catches.
type FalseDataInjection struct {
	Field string
	Bias  float64
	Ramp  time.Duration // 0 means the full bias at once
	Start time.Time
}

// Name implements Attack.
func (injection *FalseDataInjection) Name() string {
	if injection.Ramp > 0 {
		return AttackFDIRamp
	}
	return AttackFDI
}

// Technique implements Attack: T0832 Manipulation of View.
func (*FalseDataInjection) Technique() string { return "T0832" }

// Apply implements Attack.
func (injection *FalseDataInjection) Apply(sample telemetry.Point) []telemetry.Point {
	value, found := sample.Fields[injection.Field]
	if sample.Time.Before(injection.Start) || !found {
		return []telemetry.Point{sample}
	}
	share := 1.0
	if injection.Ramp > 0 {
		share = min(1, float64(sample.Time.Sub(injection.Start))/float64(injection.Ramp))
	}
	forged := sample.Clone()
	forged.Fields[injection.Field] = value + injection.Bias*share
	return []telemetry.Point{forged}
}

// Replay records the first Keep honest samples and, from Start on, sends
// them again in a loop with the current time: old, plausible values that
// hide what the device really measures now.
type Replay struct {
	Start time.Time
	Keep  int

	recorded []telemetry.Point
	next     int
}

// Name implements Attack.
func (*Replay) Name() string { return AttackReplay }

// Technique implements Attack: T0856 Spoof Reporting Message.
func (*Replay) Technique() string { return "T0856" }

// Apply implements Attack.
func (replay *Replay) Apply(sample telemetry.Point) []telemetry.Point {
	isRecording := sample.Time.Before(replay.Start) || len(replay.recorded) == 0
	if isRecording {
		if len(replay.recorded) < replay.Keep {
			replay.recorded = append(replay.recorded, sample.Clone())
		}
		return []telemetry.Point{sample}
	}
	replayed := replay.recorded[replay.next%len(replay.recorded)].Clone()
	replay.next++
	replayed.Time = sample.Time
	return []telemetry.Point{replayed}
}

// Flood sends Factor copies of every sample from Start on, a microsecond
// apart, to load the PEP, the fog node and the network.
type Flood struct {
	Factor int
	Start  time.Time
}

// Name implements Attack.
func (*Flood) Name() string { return AttackFlood }

// Technique implements Attack: T0814 Denial of Service.
func (*Flood) Technique() string { return "T0814" }

// Apply implements Attack.
func (flood *Flood) Apply(sample telemetry.Point) []telemetry.Point {
	if sample.Time.Before(flood.Start) || flood.Factor <= 1 {
		return []telemetry.Point{sample}
	}
	copies := make([]telemetry.Point, flood.Factor)
	for i := range copies {
		copies[i] = sample.Clone()
		copies[i].Time = sample.Time.Add(time.Duration(i) * time.Microsecond)
	}
	return copies
}
