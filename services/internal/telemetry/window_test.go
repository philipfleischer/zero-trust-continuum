// Tests for the tumbling window: aggregation, series and fields kept apart,
// late points, flushing each window once, and concurrent use under -race.

package telemetry

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// windowStart is the start of the first window in the window tests.
var windowStart = time.Unix(100, 0)

func newTestWindow(t *testing.T) *Tumbling {
	t.Helper()
	window, err := NewTumbling(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return window
}

// sample is one value of field "v" from the given device at the given time.
func sample(device string, value float64, at time.Time) Point {
	return Point{
		Measurement: "pmu",
		Tags:        map[string]string{"device": device},
		Fields:      map[string]float64{"v": value},
		Time:        at,
	}
}

func TestNewTumblingRejectsSize(t *testing.T) {
	for _, size := range []time.Duration{0, -time.Second} {
		if _, err := NewTumbling(size); !errors.Is(err, ErrWindowSize) {
			t.Errorf("NewTumbling(%v) error = %v, want ErrWindowSize", size, err)
		}
	}
}

// TestFiftyHertzBecomesOneHertz is the fog argument in numbers: 150 samples
// over three seconds become three aggregates.
func TestFiftyHertzBecomesOneHertz(t *testing.T) {
	window := newTestWindow(t)
	var aggregates []Aggregate
	for i := range 150 {
		at := windowStart.Add(time.Duration(i) * 20 * time.Millisecond)
		aggregates = append(aggregates, window.Add(sample("pmu-1", float64(i%50), at))...)
	}
	if len(aggregates) != 2 {
		t.Errorf("Add closed %d windows, want 2: the third is still open", len(aggregates))
	}
	aggregates = append(aggregates, window.Flush()...)
	if len(aggregates) != 3 {
		t.Fatalf("got %d aggregates, want 3", len(aggregates))
	}
	for i, aggregate := range aggregates {
		wantStart := windowStart.Add(time.Duration(i) * time.Second)
		if !aggregate.Start.Equal(wantStart) {
			t.Errorf("window %d starts at %v, want %v", i, aggregate.Start, wantStart)
		}
		if aggregate.Count != 50 || aggregate.Min != 0 || aggregate.Max != 49 || aggregate.Mean() != 24.5 {
			t.Errorf("window %d = count %d, min %v, max %v, mean %v; want 50, 0, 49, 24.5",
				i, aggregate.Count, aggregate.Min, aggregate.Max, aggregate.Mean())
		}
	}
}

func TestAggregatePoint(t *testing.T) {
	aggregate := Aggregate{
		Measurement: "pmu",
		Tags:        map[string]string{"device": "pmu-1"},
		Field:       "v",
		Start:       windowStart,
		Count:       4,
		Min:         1,
		Max:         7,
		Sum:         16,
	}
	point := aggregate.Point()
	want := "pmu_agg,device=pmu-1 v_count=4,v_max=7,v_mean=4,v_min=1 100000000000"
	if got := point.Line(); got != want {
		t.Errorf("Point().Line() = %q, want %q", got, want)
	}
	point.Tags["device"] = "pmu-2"
	if aggregate.Tags["device"] != "pmu-1" {
		t.Error("changing the point changed the aggregate's tags")
	}
}

func TestEmptyAggregateMean(t *testing.T) {
	if mean := (Aggregate{}).Mean(); mean != 0 {
		t.Errorf("Mean() = %v, want 0", mean)
	}
}

func TestSeriesAndFieldsHaveTheirOwnWindows(t *testing.T) {
	window := newTestWindow(t)
	window.Add(sample("pmu-1", 1, windowStart))
	window.Add(sample("pmu-2", 100, windowStart))
	window.Add(Point{Measurement: "pmu", Tags: map[string]string{"device": "pmu-1"}, Fields: map[string]float64{"w": 5}, Time: windowStart})

	// The original keyed windows by "series|field", so these two shared one.
	window.Add(Point{Measurement: "a|b", Fields: map[string]float64{"c": 1}, Time: windowStart})
	window.Add(Point{Measurement: "a", Fields: map[string]float64{"b|c": 2}, Time: windowStart})

	aggregates := window.Flush()
	if len(aggregates) != 5 {
		t.Fatalf("got %d aggregates, want 5: %+v", len(aggregates), aggregates)
	}
	for _, aggregate := range aggregates {
		if aggregate.Count != 1 {
			t.Errorf("%s %s has %d values, want 1", aggregate.Series, aggregate.Field, aggregate.Count)
		}
	}
	isSorted := aggregates[0].Series <= aggregates[1].Series && aggregates[1].Series <= aggregates[2].Series
	if !isSorted {
		t.Errorf("Flush is not sorted by series: %+v", aggregates)
	}
}

func TestLatePointInsideAnOpenSeriesIsDropped(t *testing.T) {
	window := newTestWindow(t)
	window.Add(sample("pmu-1", 1, windowStart.Add(1500*time.Millisecond))) // opens [101, 102)
	closed := window.Add(sample("pmu-1", 2, windowStart.Add(500*time.Millisecond)))
	if len(closed) != 0 {
		t.Errorf("a late point closed %d windows", len(closed))
	}
	if late := window.LatePoints(); late != 1 {
		t.Errorf("LatePoints() = %d, want 1", late)
	}
	aggregates := window.Flush()
	if len(aggregates) != 1 || aggregates[0].Count != 1 {
		t.Errorf("Flush() = %+v, want only the window with the on-time point", aggregates)
	}
}

func TestFlushBeforeClosesOnlyEndedWindows(t *testing.T) {
	window := newTestWindow(t)
	window.Add(sample("pmu-1", 1, windowStart.Add(300*time.Millisecond))) // window [100, 101)

	if flushed := window.FlushBefore(windowStart.Add(999 * time.Millisecond)); len(flushed) != 0 {
		t.Errorf("FlushBefore(100.999) = %+v, want nothing: the window has not ended", flushed)
	}
	if flushed := window.FlushBefore(windowStart.Add(time.Second)); len(flushed) != 1 {
		t.Errorf("FlushBefore(101) returned %d windows, want 1: a window ending at now is due", len(flushed))
	}
	if flushed := window.Flush(); len(flushed) != 0 {
		t.Errorf("Flush() after FlushBefore = %+v, want nothing left", flushed)
	}
}

// TestWindowIsSentOnce is the flaw in the original: a point for a flushed
// window opened it again, and the fog node sent two aggregates for one second.
func TestWindowIsSentOnce(t *testing.T) {
	window := newTestWindow(t)
	window.Add(sample("pmu-1", 1, windowStart.Add(200*time.Millisecond)))
	first := window.FlushBefore(windowStart.Add(time.Second))
	if len(first) != 1 {
		t.Fatalf("first flush returned %d windows, want 1", len(first))
	}

	window.Add(sample("pmu-1", 2, windowStart.Add(900*time.Millisecond))) // same series, same window
	window.Add(sample("pmu-2", 3, windowStart.Add(900*time.Millisecond))) // another series, same second

	if again := window.Flush(); len(again) != 0 {
		t.Errorf("the closed window came back: %+v", again)
	}
	if late := window.LatePoints(); late != 2 {
		t.Errorf("LatePoints() = %d, want 2", late)
	}

	window.Add(sample("pmu-1", 4, windowStart.Add(time.Second))) // the next window is open
	if next := window.Flush(); len(next) != 1 || next[0].Sum != 4 {
		t.Errorf("Flush() = %+v, want the next window with value 4", next)
	}
}

func TestAggregateKeepsItsOwnTags(t *testing.T) {
	window := newTestWindow(t)
	point := sample("pmu-1", 1, windowStart)
	window.Add(point)
	point.Tags["device"] = "pmu-2" // the caller reuses its map
	aggregates := window.Flush()
	if aggregates[0].Tags["device"] != "pmu-1" {
		t.Errorf("tags = %v: the window shares the caller's map", aggregates[0].Tags)
	}
}

// TestConcurrentUse is where the original crashed with "concurrent map
// writes": many handlers add while the flush loop runs. Run it with -race.
func TestConcurrentUse(t *testing.T) {
	window := newTestWindow(t)
	const writers, pointsPerWriter = 10, 500
	var group sync.WaitGroup
	for writer := range writers {
		group.Go(func() {
			for i := range pointsPerWriter {
				at := windowStart.Add(time.Duration(i) * time.Millisecond) // all in [100, 101)
				window.Add(sample("pmu-1", float64(writer), at))
			}
		})
	}
	group.Go(func() {
		for range 100 {
			window.FlushBefore(windowStart) // nothing has ended yet
			window.LatePoints()
		}
	})
	group.Wait()

	aggregates := window.Flush()
	if len(aggregates) != 1 {
		t.Fatalf("got %d aggregates, want 1", len(aggregates))
	}
	wantSum := float64(pointsPerWriter * (0 + 1 + 2 + 3 + 4 + 5 + 6 + 7 + 8 + 9))
	if aggregates[0].Count != writers*pointsPerWriter || aggregates[0].Sum != wantSum {
		t.Errorf("count %d, sum %v; want %d, %v", aggregates[0].Count, aggregates[0].Sum, writers*pointsPerWriter, wantSum)
	}
	if aggregates[0].Min != 0 || aggregates[0].Max != writers-1 {
		t.Errorf("min %v, max %v; want 0, %d", aggregates[0].Min, aggregates[0].Max, writers-1)
	}
}
