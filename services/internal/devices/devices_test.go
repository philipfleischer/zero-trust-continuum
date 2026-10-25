// Tests for the simulated devices: kinds, repeatable samples, plausible
// values for every kind, the daily profiles and the breaker.

package devices

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/telemetry"
)

// eveningPeak is 18:00 UTC, the top of the daily load profile.
var eveningPeak = time.Date(2026, 10, 25, 18, 0, 0, 0, time.UTC)

func newTestDevice(t *testing.T, kind Kind, seed uint64) *Device {
	t.Helper()
	device, err := New(string(kind)+"-b1-1", kind, "s1", "bay-1", seed)
	if err != nil {
		t.Fatal(err)
	}
	return device
}

func TestParseKind(t *testing.T) {
	for _, name := range []string{"pmu", "PMU", "Meter", "breaker", "rtu", "evcharger"} {
		if _, err := ParseKind(name); err != nil {
			t.Errorf("ParseKind(%q): %v", name, err)
		}
	}
	_, err := ParseKind("toaster")
	if err == nil || !strings.Contains(err.Error(), "pmu") {
		t.Errorf("ParseKind(toaster) error = %v, want one that lists the known kinds", err)
	}
}

func TestNewRejectsUnknownKind(t *testing.T) {
	if _, err := New("x", Kind("toaster"), "s1", "bay-1", 1); err == nil {
		t.Error("New accepted an unknown kind")
	}
}

func TestSameSeedGivesSameSamples(t *testing.T) {
	first := newTestDevice(t, PMU, 42)
	second := newTestDevice(t, PMU, 42)
	other := newTestDevice(t, PMU, 43)
	differs := false
	for i := range 100 {
		at := eveningPeak.Add(time.Duration(i) * 20 * time.Millisecond)
		firstSample, secondSample, otherSample := first.Sample(at), second.Sample(at), other.Sample(at)
		if firstSample.Line() != secondSample.Line() {
			t.Fatalf("sample %d differs with the same seed:\n%s\n%s", i, firstSample.Line(), secondSample.Line())
		}
		if firstSample.Line() != otherSample.Line() {
			differs = true
		}
	}
	if !differs {
		t.Error("seeds 42 and 43 gave the same 100 samples")
	}
}

func TestSamplesArePlausible(t *testing.T) {
	type valueRange struct{ lowest, highest float64 }
	tests := []struct {
		kind Kind
		want map[string]valueRange
	}{
		{PMU, map[string]valueRange{"voltage_kv": {128, 136}, "frequency_hz": {49.9, 50.1}}},
		{Meter, map[string]valueRange{"power_kw": {0, 7}, "reactive_power_kvar": {0, 2.1}}},
		{Breaker, map[string]valueRange{"closed": {1, 1}, "operations": {0, 0}}},
		{RTU, map[string]valueRange{"tap_position": {1, 17}, "oil_temperature_c": {55, 80}}},
		{EVCharger, map[string]valueRange{"power_kw": {0, 11}}},
	}
	for _, testCase := range tests {
		t.Run(string(testCase.kind), func(t *testing.T) {
			device := newTestDevice(t, testCase.kind, 7)
			for minute := range 24 * 60 { // one sample a minute for a whole day
				at := eveningPeak.Add(time.Duration(minute) * time.Minute)
				point := device.Sample(at)
				if point.Measurement != string(testCase.kind) || !point.Time.Equal(at) {
					t.Fatalf("point %s at %v, want measurement %s at %v", point.Measurement, point.Time, testCase.kind, at)
				}
				if len(point.Fields) != len(testCase.want) {
					t.Fatalf("fields %v, want exactly %v", point.Fields, testCase.want)
				}
				for field, allowed := range testCase.want {
					value, found := point.Fields[field]
					isInside := found && value >= allowed.lowest && value <= allowed.highest
					if !isInside {
						t.Fatalf("%s at %v = %v, want within [%v, %v]", field, at, value, allowed.lowest, allowed.highest)
					}
				}
			}
		})
	}
}

func TestSampleTags(t *testing.T) {
	point := newTestDevice(t, Meter, 1).Sample(eveningPeak)
	want := map[string]string{"device": "meter-b1-1", "substation": "s1", "bay": "bay-1"}
	for key, value := range want {
		if point.Tags[key] != value {
			t.Errorf("tag %s = %q, want %q", key, point.Tags[key], value)
		}
	}
}

func TestMeterFollowsTheDailyProfile(t *testing.T) {
	meter := newTestDevice(t, Meter, 1)
	evening := meter.Sample(eveningPeak).Fields["power_kw"]
	night := meter.Sample(eveningPeak.Add(9 * time.Hour)).Fields["power_kw"] // 03:00 UTC
	if evening < 2*night {
		t.Errorf("power at 18:00 is %v kW and at 03:00 %v kW, want the evening at least twice the night", evening, night)
	}
}

// TestProfilesUseUTC gives the same instant in two time zones: the original
// used the local hour, so the same seed gave different data on another
// machine.
func TestProfilesUseUTC(t *testing.T) {
	oslo := time.FixedZone("CET", 3600)
	newYork := time.FixedZone("EST", -5*3600)
	for _, kind := range []Kind{Meter, RTU, EVCharger} {
		inOslo := newTestDevice(t, kind, 3).Sample(eveningPeak.In(oslo))
		inNewYork := newTestDevice(t, kind, 3).Sample(eveningPeak.In(newYork))
		for field, value := range inOslo.Fields {
			if inNewYork.Fields[field] != value {
				t.Errorf("%s %s is %v in Oslo and %v in New York for the same instant", kind, field, value, inNewYork.Fields[field])
			}
		}
	}
}

func TestEVChargerChargesInTheEvening(t *testing.T) {
	charger := newTestDevice(t, EVCharger, 1)
	tests := []struct {
		hour int
		want float64
	}{{16, 0}, {17, 11}, {22, 11}, {23, 0}, {3, 0}}
	for _, testCase := range tests {
		at := time.Date(2026, 10, 25, testCase.hour, 30, 0, 0, time.UTC)
		if got := charger.Sample(at).Fields["power_kw"]; got != testCase.want {
			t.Errorf("power at %02d:30 = %v kW, want %v", testCase.hour, got, testCase.want)
		}
	}
}

func TestPMUValuesVary(t *testing.T) {
	pmu := newTestDevice(t, PMU, 5)
	lowest, highest := math.Inf(1), math.Inf(-1)
	for second := range 60 {
		voltage := pmu.Sample(eveningPeak.Add(time.Duration(second) * time.Second)).Fields["voltage_kv"]
		lowest, highest = math.Min(lowest, voltage), math.Max(highest, voltage)
	}
	if highest-lowest < 1 {
		t.Errorf("voltage stayed within %v–%v kV for a minute, want the ±1 %% wave", lowest, highest)
	}
}

func TestTrip(t *testing.T) {
	breaker := newTestDevice(t, Breaker, 1)
	breaker.Trip()
	breaker.Trip() // an open breaker cannot trip again
	fields := breaker.Sample(eveningPeak).Fields
	if fields["closed"] != 0 || fields["operations"] != 1 {
		t.Errorf("after two trips: closed %v, operations %v; want 0 and 1", fields["closed"], fields["operations"])
	}

	pmu := newTestDevice(t, PMU, 1)
	pmu.Trip()
	if _, found := pmu.Sample(eveningPeak).Fields["closed"]; found {
		t.Error("Trip on a PMU gave it a breaker position")
	}
}

// TestSamplesPassTheParser checks that every kind produces points that
// survive line protocol, which is how ztc-edge sends them.
func TestSamplesPassTheParser(t *testing.T) {
	for _, kind := range kinds {
		point := newTestDevice(t, kind, 1).Sample(eveningPeak)
		if _, err := telemetry.ParseLine(point.Line()); err != nil {
			t.Errorf("%s: %v", kind, err)
		}
	}
}
