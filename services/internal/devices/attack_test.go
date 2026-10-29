// Tests for the attacks: honest before the start, the effect after it, the
// kinds each attack supports, and the names and MITRE techniques.

package devices

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/telemetry"
)

// attackStart is when the attacks in these tests begin.
var attackStart = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)

func newTestAttack(t *testing.T, name string, kind Kind) Attack {
	t.Helper()
	attack, err := NewAttack(name, kind, attackStart)
	if err != nil {
		t.Fatal(err)
	}
	return attack
}

// pmuSample is an honest PMU sample with a fixed voltage at the given offset
// from attackStart.
func pmuSample(offset time.Duration, voltage float64) telemetry.Point {
	return telemetry.Point{
		Measurement: "pmu",
		Tags:        map[string]string{"device": "pmu-b1-1"},
		Fields:      map[string]float64{"voltage_kv": voltage, "frequency_hz": 50},
		Time:        attackStart.Add(offset),
	}
}

// only returns the single point an attack sent, or fails the test.
func only(t *testing.T, points []telemetry.Point) telemetry.Point {
	t.Helper()
	if len(points) != 1 {
		t.Fatalf("got %d points, want 1", len(points))
	}
	return points[0]
}

func TestNewAttack(t *testing.T) {
	tests := []struct {
		name          string
		kind          Kind
		wantTechnique string
	}{
		{AttackFDI, PMU, "T0832"},
		{AttackFDIRamp, PMU, "T0832"},
		{AttackFDI, Meter, "T0832"},
		{AttackFDI, RTU, "T0832"},
		{AttackFDI, EVCharger, "T0832"},
		{AttackReplay, Breaker, "T0856"},
		{AttackFlood, Breaker, "T0814"},
	}
	for _, testCase := range tests {
		attack := newTestAttack(t, testCase.name, testCase.kind)
		if attack.Name() != testCase.name || attack.Technique() != testCase.wantTechnique {
			t.Errorf("NewAttack(%s, %s) = %s %s, want %s %s",
				testCase.name, testCase.kind, attack.Name(), attack.Technique(), testCase.name, testCase.wantTechnique)
		}
	}
}

func TestNewAttackRejects(t *testing.T) {
	if _, err := NewAttack("ddos", PMU, attackStart); err == nil || !strings.Contains(err.Error(), AttackReplay) {
		t.Errorf("unknown attack: error = %v, want one that lists the attacks", err)
	}
	// The original changed only voltage_kv, so FDI on anything but a PMU
	// ran without changing a single value.
	for _, name := range []string{AttackFDI, AttackFDIRamp} {
		if _, err := NewAttack(name, Breaker, attackStart); err == nil {
			t.Errorf("%s on a breaker was accepted, but it has no measured value to change", name)
		}
	}
}

// TestFalseDataChangesEveryKind runs FDI against real samples of every kind
// it supports, so a renamed field in devices.go cannot turn it into a no-op.
func TestFalseDataChangesEveryKind(t *testing.T) {
	for kind, target := range falseDataTargets {
		device, err := New("x", kind, "s1", "bay-1", 1)
		if err != nil {
			t.Fatal(err)
		}
		at := time.Date(2026, 10, 25, 18, 0, 0, 0, time.UTC) // evening: the EV charger is on
		attack, err := NewAttack(AttackFDI, kind, at)
		if err != nil {
			t.Fatal(err)
		}
		honest := device.Sample(at)
		if _, found := honest.Fields[target.field]; !found {
			t.Errorf("%s samples have no field %s", kind, target.field)
			continue
		}
		forged := only(t, attack.Apply(honest))
		if got := forged.Fields[target.field] - honest.Fields[target.field]; math.Abs(got-target.bias) > 1e-9 {
			t.Errorf("%s: FDI changed %s by %v, want %v", kind, target.field, got, target.bias)
		}
	}
}

func TestFalseDataInjection(t *testing.T) {
	attack := newTestAttack(t, AttackFDI, PMU)

	before := pmuSample(-time.Second, 132)
	if got := only(t, attack.Apply(before)); got.Fields["voltage_kv"] != 132 {
		t.Errorf("before the start: voltage %v, want the honest 132", got.Fields["voltage_kv"])
	}

	after := pmuSample(time.Second, 132)
	forged := only(t, attack.Apply(after))
	if forged.Fields["voltage_kv"] != 136 || forged.Fields["frequency_hz"] != 50 {
		t.Errorf("after the start: %v, want voltage 136 and the frequency unchanged", forged.Fields)
	}
	if after.Fields["voltage_kv"] != 132 {
		t.Error("the attack changed the honest sample it was given")
	}
}

func TestFalseDataRamp(t *testing.T) {
	attack := newTestAttack(t, AttackFDIRamp, PMU)
	tests := []struct {
		offset time.Duration
		want   float64
	}{
		{0, 132},
		{rampDuration / 4, 133},
		{rampDuration / 2, 134},
		{rampDuration, 136},
		{2 * rampDuration, 136}, // stays at the full bias
	}
	for _, testCase := range tests {
		got := only(t, attack.Apply(pmuSample(testCase.offset, 132))).Fields["voltage_kv"]
		if math.Abs(got-testCase.want) > 1e-9 {
			t.Errorf("after %v: voltage %v, want %v", testCase.offset, got, testCase.want)
		}
	}
}

func TestFalseDataSkipsSamplesWithoutTheField(t *testing.T) {
	attack := newTestAttack(t, AttackFDI, PMU)
	sample := telemetry.Point{Measurement: "pmu", Fields: map[string]float64{"frequency_hz": 50}, Time: attackStart}
	if got := only(t, attack.Apply(sample)); len(got.Fields) != 1 || got.Fields["frequency_hz"] != 50 {
		t.Errorf("got %v, want the sample unchanged", got.Fields)
	}
}

func TestReplay(t *testing.T) {
	attack := newTestAttack(t, AttackReplay, PMU)
	for i := range 3 { // recorded before the start
		offset := time.Duration(i-3) * time.Second
		honest := pmuSample(offset, float64(130+i))
		if got := only(t, attack.Apply(honest)); got.Fields["voltage_kv"] != float64(130+i) {
			t.Fatalf("before the start: voltage %v, want the honest %v", got.Fields["voltage_kv"], 130+i)
		}
	}

	wantVoltages := []float64{130, 131, 132, 130, 131} // the recording, in a loop
	for i, want := range wantVoltages {
		now := time.Duration(i) * time.Second
		replayed := only(t, attack.Apply(pmuSample(now, 999)))
		if replayed.Fields["voltage_kv"] != want {
			t.Errorf("replayed sample %d: voltage %v, want %v", i, replayed.Fields["voltage_kv"], want)
		}
		if !replayed.Time.Equal(attackStart.Add(now)) {
			t.Errorf("replayed sample %d has time %v, want the current %v", i, replayed.Time, attackStart.Add(now))
		}
	}
}

func TestReplayKeepsALimitedRecording(t *testing.T) {
	replay := &Replay{Start: attackStart, Keep: 2}
	for i := range 5 {
		replay.Apply(pmuSample(time.Duration(i-5)*time.Second, float64(i)))
	}
	if len(replay.recorded) != 2 {
		t.Errorf("recorded %d samples, want at most Keep (2)", len(replay.recorded))
	}
}

func TestReplayWithoutRecordingSendsTheSample(t *testing.T) {
	attack := newTestAttack(t, AttackReplay, PMU)
	// The attack starts before anything was recorded: the first sample is
	// sent as it is, and becomes the recording.
	first := only(t, attack.Apply(pmuSample(time.Second, 140)))
	second := only(t, attack.Apply(pmuSample(2*time.Second, 999)))
	if first.Fields["voltage_kv"] != 140 || second.Fields["voltage_kv"] != 140 {
		t.Errorf("voltages %v and %v, want 140 twice", first.Fields["voltage_kv"], second.Fields["voltage_kv"])
	}
}

func TestReplayedPointsAreCopies(t *testing.T) {
	attack := newTestAttack(t, AttackReplay, PMU)
	attack.Apply(pmuSample(-time.Second, 130))
	sent := only(t, attack.Apply(pmuSample(time.Second, 999)))
	sent.Fields["voltage_kv"] = 0 // the caller changes what it got
	if again := only(t, attack.Apply(pmuSample(2*time.Second, 999))); again.Fields["voltage_kv"] != 130 {
		t.Errorf("the recording changed to %v with the caller's copy", again.Fields["voltage_kv"])
	}
}

func TestFlood(t *testing.T) {
	attack := newTestAttack(t, AttackFlood, PMU)
	if got := attack.Apply(pmuSample(-time.Second, 132)); len(got) != 1 {
		t.Errorf("before the start: %d points, want 1", len(got))
	}
	copies := attack.Apply(pmuSample(time.Second, 132))
	if len(copies) != 20 {
		t.Fatalf("after the start: %d points, want 20", len(copies))
	}
	seen := map[time.Time]bool{}
	for _, copied := range copies {
		seen[copied.Time] = true
	}
	if len(seen) != 20 {
		t.Errorf("%d distinct times, want 20 so the copies are not merged as duplicates", len(seen))
	}
	copies[0].Fields["voltage_kv"] = 0
	if copies[1].Fields["voltage_kv"] != 132 {
		t.Error("the copies share their fields")
	}
}

func TestFloodWithFactorOneSendsTheSample(t *testing.T) {
	flood := &Flood{Factor: 1, Start: attackStart}
	if got := flood.Apply(pmuSample(time.Second, 132)); len(got) != 1 {
		t.Errorf("got %d points, want 1", len(got))
	}
}
