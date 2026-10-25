// Tests for the time-series store: the ring buffer per series, the series
// limit, queries by measurement and time, and concurrent use under -race.

package telemetry

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// storeStart is the time of the first point in the store tests.
var storeStart = time.Unix(0, 0)

func newTestStore(t *testing.T, capacity, maxSeries int) *Store {
	t.Helper()
	store, err := NewStore(capacity, maxSeries)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

// mustAppend appends the point and fails the test on an error.
func mustAppend(t *testing.T, store *Store, point Point) {
	t.Helper()
	if err := store.Append(point); err != nil {
		t.Fatalf("Append(%s): %v", point.Line(), err)
	}
}

// reading is one value of field "v" for a measurement and device, the given
// number of seconds after storeStart.
func reading(measurement, device string, value float64, second int) Point {
	return Point{
		Measurement: measurement,
		Tags:        map[string]string{"device": device},
		Fields:      map[string]float64{"v": value},
		Time:        storeStart.Add(time.Duration(second) * time.Second),
	}
}

// values returns field "v" of each point, to compare results in one line.
func values(points []Point) []float64 {
	result := make([]float64, 0, len(points))
	for _, point := range points {
		result = append(result, point.Fields["v"])
	}
	return result
}

func TestNewStoreRejectsSize(t *testing.T) {
	for _, size := range [][2]int{{0, 10}, {10, 0}, {-1, 10}} {
		if _, err := NewStore(size[0], size[1]); !errors.Is(err, ErrStoreSize) {
			t.Errorf("NewStore(%d, %d) error = %v, want ErrStoreSize", size[0], size[1], err)
		}
	}
}

func TestRingKeepsTheNewestPoints(t *testing.T) {
	store := newTestStore(t, 3, 10)
	for second := range 8 {
		mustAppend(t, store, reading("pmu", "pmu-1", float64(second), second))
	}
	got := values(store.Query("pmu", time.Time{}, time.Time{}))
	if fmt.Sprint(got) != "[5 6 7]" {
		t.Errorf("Query() values = %v, want [5 6 7]", got)
	}
	if length := store.Len(); length != 3 {
		t.Errorf("Len() = %d, want 3", length)
	}
}

func TestQueryTimeRange(t *testing.T) {
	store := newTestStore(t, 10, 10)
	for second := range 5 {
		mustAppend(t, store, reading("pmu", "pmu-1", float64(second), second))
	}
	at := func(second int) time.Time { return storeStart.Add(time.Duration(second) * time.Second) }
	tests := []struct {
		name     string
		from, to time.Time
		want     string
	}{
		{"open at both ends", time.Time{}, time.Time{}, "[0 1 2 3 4]"},
		{"from is included, to is not", at(1), at(3), "[1 2]"},
		{"only from", at(3), time.Time{}, "[3 4]"},
		{"only to", time.Time{}, at(2), "[0 1]"},
		{"empty range", at(2), at(2), "[]"},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			got := fmt.Sprint(values(store.Query("pmu", testCase.from, testCase.to)))
			if got != testCase.want {
				t.Errorf("values = %s, want %s", got, testCase.want)
			}
		})
	}
}

func TestQueryMatchesTheWholeMeasurement(t *testing.T) {
	store := newTestStore(t, 10, 10)
	mustAppend(t, store, reading("pmu", "pmu-1", 1, 2))
	mustAppend(t, store, reading("pmu", "pmu-2", 2, 1))
	mustAppend(t, store, reading("pmu_agg", "pmu-1", 3, 0))
	mustAppend(t, store, reading("pmu main", "pmu-1", 4, 0)) // escaped as pmu\ main in the key

	got := store.Query("pmu", time.Time{}, time.Time{})
	if fmt.Sprint(values(got)) != "[2 1]" {
		t.Errorf("Query(pmu) values = %v, want [2 1]: both devices, sorted by time, no pmu_agg", values(got))
	}
	if escaped := store.Query("pmu main", time.Time{}, time.Time{}); len(escaped) != 1 {
		t.Errorf("Query(pmu main) returned %d points, want 1", len(escaped))
	}
	if unknown := store.Query("meter", time.Time{}, time.Time{}); len(unknown) != 0 {
		t.Errorf("Query(meter) = %v, want nothing", unknown)
	}
}

func TestQueryOrdersEqualTimesBySeries(t *testing.T) {
	store := newTestStore(t, 10, 10)
	for _, device := range []string{"pmu-3", "pmu-1", "pmu-2"} {
		mustAppend(t, store, reading("pmu", device, 0, 0))
	}
	for range 10 { // map order is random, the result must not be
		got := store.Query("pmu", time.Time{}, time.Time{})
		order := got[0].Tags["device"] + " " + got[1].Tags["device"] + " " + got[2].Tags["device"]
		if order != "pmu-1 pmu-2 pmu-3" {
			t.Fatalf("devices in order %s, want pmu-1 pmu-2 pmu-3", order)
		}
	}
}

// TestSeriesLimit is the flaw in the original: only the points per series
// were limited, so new tag values could grow the store without end.
func TestSeriesLimit(t *testing.T) {
	store := newTestStore(t, 10, 2)
	mustAppend(t, store, reading("pmu", "pmu-1", 1, 0))
	mustAppend(t, store, reading("pmu", "pmu-2", 2, 0))

	if err := store.Append(reading("pmu", "pmu-3", 3, 0)); !errors.Is(err, ErrStoreFull) {
		t.Errorf("Append of a third series: error = %v, want ErrStoreFull", err)
	}
	mustAppend(t, store, reading("pmu", "pmu-1", 4, 1)) // existing series still accepted

	if series := store.Series(); fmt.Sprint(series) != "[pmu,device=pmu-1 pmu,device=pmu-2]" {
		t.Errorf("Series() = %v", series)
	}
	if length := store.Len(); length != 3 {
		t.Errorf("Len() = %d, want 3", length)
	}
}

func TestAppendStoresACopy(t *testing.T) {
	store := newTestStore(t, 10, 10)
	point := reading("pmu", "pmu-1", 1, 0)
	mustAppend(t, store, point)
	point.Fields["v"] = 999 // the caller reuses its maps
	point.Tags["device"] = "pmu-9"
	if got := store.Query("pmu", time.Time{}, time.Time{}); got[0].Fields["v"] != 1 || got[0].Tags["device"] != "pmu-1" {
		t.Errorf("stored point changed with the caller's maps: %+v", got[0])
	}
}

func TestEmptyStore(t *testing.T) {
	store := newTestStore(t, 10, 10)
	if store.Len() != 0 || len(store.Series()) != 0 || len(store.Query("pmu", time.Time{}, time.Time{})) != 0 {
		t.Error("a new store is not empty")
	}
}

// TestStoreConcurrentUse lets writers and readers run at once, as the
// handlers of ztc-ingest will. Run it with -race.
func TestStoreConcurrentUse(t *testing.T) {
	const writers, pointsPerWriter, capacity = 8, 300, 100
	store := newTestStore(t, capacity, writers)
	var group sync.WaitGroup
	for writer := range writers {
		group.Go(func() {
			device := fmt.Sprintf("pmu-%d", writer)
			for second := range pointsPerWriter {
				if err := store.Append(reading("pmu", device, float64(second), second)); err != nil {
					t.Error(err)
					return
				}
			}
		})
	}
	for range 4 {
		group.Go(func() {
			for range 50 {
				store.Query("pmu", time.Time{}, time.Time{})
				store.Series()
				store.Len()
			}
		})
	}
	group.Wait()

	if length := store.Len(); length != writers*capacity {
		t.Errorf("Len() = %d, want %d", length, writers*capacity)
	}
	newest := store.Query("pmu", storeStart.Add((pointsPerWriter-1)*time.Second), time.Time{})
	if len(newest) != writers {
		t.Errorf("got %d points for the last second, want one per writer (%d)", len(newest), writers)
	}
}
