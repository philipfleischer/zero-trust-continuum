// Tests for the pipeline stages, Apply and Run, and for Point.Clone, which
// the stages rely on.

package telemetry

import (
	"context"
	"math"
	"testing"
	"time"
)

// referenceTime is "now" in the pipeline tests.
var referenceTime = time.Unix(1_700_000_000, 0)

func fixedNow() time.Time { return referenceTime }

// pmuPoint is a valid PMU sample at the given time.
func pmuPoint(at time.Time) Point {
	return Point{
		Measurement: "pmu",
		Tags:        map[string]string{"device": "pmu-1"},
		Fields:      map[string]float64{"frequency_hz": 50},
		Time:        at,
	}
}

func TestValidate(t *testing.T) {
	validate := Validate(5*time.Second, fixedNow)
	tests := []struct {
		name     string
		point    Point
		wantKept bool
	}{
		{"on time", pmuPoint(referenceTime), true},
		{"just inside the skew in the future", pmuPoint(referenceTime.Add(5 * time.Second)), true},
		{"just inside the skew in the past", pmuPoint(referenceTime.Add(-5 * time.Second)), true},
		{"too far in the future", pmuPoint(referenceTime.Add(5*time.Second + time.Nanosecond)), false},
		{"too far in the past, as a replay would be", pmuPoint(referenceTime.Add(-time.Hour)), false},
		{"far in the past, as a broken clock would be", pmuPoint(time.Unix(0, 0)), false},
		{"no measurement", Point{Fields: map[string]float64{"frequency_hz": 50}, Time: referenceTime}, false},
		{"no fields", Point{Measurement: "pmu", Time: referenceTime}, false},
		{"NaN", Point{Measurement: "pmu", Fields: map[string]float64{"frequency_hz": math.NaN()}, Time: referenceTime}, false},
		{"infinity", Point{Measurement: "pmu", Fields: map[string]float64{"frequency_hz": math.Inf(-1)}, Time: referenceTime}, false},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			_, kept := validate(testCase.point)
			if kept != testCase.wantKept {
				t.Errorf("kept = %v, want %v", kept, testCase.wantKept)
			}
		})
	}
}

func TestValidateStampsPointsWithoutTime(t *testing.T) {
	got, kept := Validate(time.Second, fixedNow)(pmuPoint(time.Time{}))
	if !kept || !got.Time.Equal(referenceTime) {
		t.Errorf("got time %v, kept %v; want the arrival time %v", got.Time, kept, referenceTime)
	}
}

func TestValidateDefaultsToTheClock(t *testing.T) {
	_, kept := Validate(time.Minute, nil)(pmuPoint(time.Now()))
	if !kept {
		t.Error("a point stamped now was dropped with the default clock")
	}
}

func TestEnrich(t *testing.T) {
	fogTags := map[string]string{"fog": "fog-1", "zone": "bay-1"}
	enrich := Enrich(fogTags)
	fogTags["zone"] = "control-centre" // must not reach points enriched later

	sent := pmuPoint(referenceTime)
	sent.Tags["zone"] = "control-centre" // the device claims another zone
	got, kept := enrich(sent)

	if !kept {
		t.Fatal("Enrich dropped a point")
	}
	want := map[string]string{"device": "pmu-1", "fog": "fog-1", "zone": "bay-1"}
	for key, value := range want {
		if got.Tags[key] != value {
			t.Errorf("tag %s = %q, want %q", key, got.Tags[key], value)
		}
	}
	if sent.Tags["zone"] != "control-centre" || sent.Tags["fog"] != "" {
		t.Errorf("Enrich changed the point it received: %v", sent.Tags)
	}
}

func TestEnrichPointWithoutTags(t *testing.T) {
	got, _ := Enrich(map[string]string{"fog": "fog-1"})(Point{Measurement: "pmu", Fields: map[string]float64{"v": 1}})
	if got.Tags["fog"] != "fog-1" {
		t.Errorf("tags = %v, want fog=fog-1", got.Tags)
	}
}

func TestRange(t *testing.T) {
	tests := []struct {
		name     string
		fields   map[string]float64
		wantKept bool
	}{
		{"normal frequency", map[string]float64{"frequency_hz": 50}, true},
		{"lowest allowed", map[string]float64{"frequency_hz": 45}, true},
		{"highest allowed", map[string]float64{"frequency_hz": 55}, true},
		{"too low", map[string]float64{"frequency_hz": 44.999}, false},
		{"too high", map[string]float64{"frequency_hz": 61}, false},
		{"NaN", map[string]float64{"frequency_hz": math.NaN()}, false},
		{"field missing", map[string]float64{"voltage_kv": 132}, true},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			var rejected []Point
			frequency := Range("frequency_hz", 45, 55, func(point Point) { rejected = append(rejected, point) })
			_, kept := frequency(Point{Measurement: "pmu", Fields: testCase.fields})
			if kept != testCase.wantKept {
				t.Errorf("kept = %v, want %v", kept, testCase.wantKept)
			}
			wantRejected := 0
			if !testCase.wantKept {
				wantRejected = 1
			}
			if len(rejected) != wantRejected {
				t.Errorf("onReject called %d times, want %d", len(rejected), wantRejected)
			}
		})
	}
}

func TestRangeWithoutOnReject(t *testing.T) {
	_, kept := Range("frequency_hz", 45, 55, nil)(pmuPoint(referenceTime).withField("frequency_hz", 70))
	if kept {
		t.Error("an out-of-range point was kept")
	}
}

func TestApplyStopsAtTheFirstDrop(t *testing.T) {
	var calls []string
	stage := func(name string, keep bool) Stage {
		return func(point Point) (Point, bool) {
			calls = append(calls, name)
			return point, keep
		}
	}
	pipeline := Pipeline{Stages: []Stage{stage("first", true), stage("second", false), stage("third", true)}}
	if _, kept := pipeline.Apply(pmuPoint(referenceTime)); kept {
		t.Error("the point got through a stage that drops it")
	}
	if len(calls) != 2 || calls[0] != "first" || calls[1] != "second" {
		t.Errorf("stages called: %v, want [first second]", calls)
	}
}

func TestApplyWithoutStagesKeepsThePoint(t *testing.T) {
	sent := pmuPoint(referenceTime)
	got, kept := Pipeline{}.Apply(sent)
	if !kept || !samePoint(got, sent) {
		t.Errorf("Apply() = %+v, %v; want the point unchanged", got, kept)
	}
}

func TestRun(t *testing.T) {
	var outOfRange int
	pipeline := Pipeline{Stages: []Stage{
		Validate(time.Second, fixedNow),
		Range("frequency_hz", 45, 55, func(Point) { outOfRange++ }),
		Enrich(map[string]string{"fog": "fog-1"}),
	}}
	input := make(chan Point, 10)
	input <- pmuPoint(referenceTime).withField("frequency_hz", 49.9)
	input <- pmuPoint(referenceTime).withField("frequency_hz", 61)         // out of range
	input <- pmuPoint(referenceTime.Add(time.Hour))                        // from the future
	input <- pmuPoint(time.Time{}).withField("frequency_hz", 50.1)         // stamped on arrival
	input <- Point{Measurement: "pmu", Fields: map[string]float64{"x": 1}} // no frequency, passes Range
	close(input)

	var got []Point
	for point := range pipeline.Run(context.Background(), input) {
		got = append(got, point)
	}

	if len(got) != 3 {
		t.Fatalf("got %d points, want 3: %+v", len(got), got)
	}
	if got[0].Fields["frequency_hz"] != 49.9 || got[1].Fields["frequency_hz"] != 50.1 || got[2].Fields["x"] != 1 {
		t.Errorf("points out of order: %+v", got)
	}
	for _, point := range got {
		if point.Tags["fog"] != "fog-1" || !point.Time.Equal(referenceTime) {
			t.Errorf("point %+v is missing the fog tag or the arrival time", point)
		}
	}
	if outOfRange != 1 {
		t.Errorf("onReject called %d times, want 1", outOfRange)
	}
}

// TestRunStopsWhenCancelled checks that cancelling ends Run even though the
// input is never closed, so a service shutting down does not leak the
// goroutine.
func TestRunStopsWhenCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	input := make(chan Point) // never closed
	output := Pipeline{}.Run(ctx, input)
	cancel()
	select {
	case _, open := <-output:
		if open {
			t.Error("got a point, want the output closed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not close its output after cancel")
	}
}

// TestRunStopsWhenCancelledWhileSending checks the second place Run waits:
// nobody reads the output, so the send blocks until ctx is cancelled.
func TestRunStopsWhenCancelledWhileSending(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	input := make(chan Point, 100)
	for range 100 { // more than the output buffer holds
		input <- pmuPoint(referenceTime)
	}
	output := Pipeline{}.Run(ctx, input)
	time.Sleep(50 * time.Millisecond) // let Run fill the buffer and block
	cancel()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case _, open := <-output:
			if !open {
				return
			}
		case <-deadline:
			t.Fatal("Run did not close its output after cancel")
		}
	}
}

func TestClone(t *testing.T) {
	original := pmuPoint(referenceTime)
	clone := original.Clone()
	clone.Tags["device"] = "pmu-2"
	clone.Fields["frequency_hz"] = 0
	if original.Tags["device"] != "pmu-1" || original.Fields["frequency_hz"] != 50 {
		t.Errorf("changing the clone changed the original: %+v", original)
	}
	if !clone.Time.Equal(original.Time) || clone.Measurement != original.Measurement {
		t.Errorf("clone %+v lost the time or measurement of %+v", clone, original)
	}

	empty := Point{}.Clone()
	if empty.Tags == nil || empty.Fields == nil {
		t.Error("Clone of a point without maps must give empty maps, not nil, so stages can write to them")
	}
}

// withField returns a copy of the point with one field set.
func (point Point) withField(name string, value float64) Point {
	changed := point.Clone()
	changed.Fields[name] = value
	return changed
}
