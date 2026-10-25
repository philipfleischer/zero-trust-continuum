// Tumbling windows: fixed, non-overlapping time windows that summarise each
// field of each series, so a fog node sends one aggregate per second upstream
// instead of fifty raw PMU samples.

package telemetry

import (
	"cmp"
	"errors"
	"maps"
	"math"
	"slices"
	"sync"
	"time"
)

// ErrWindowSize is returned by NewTumbling for a size that is not positive.
var ErrWindowSize = errors.New("telemetry: window size must be positive")

// Aggregate summarises one field of one series in one window.
type Aggregate struct {
	Series      string            `json:"series"`
	Measurement string            `json:"measurement"`
	Tags        map[string]string `json:"tags"`
	Field       string            `json:"field"`
	Start       time.Time         `json:"start"`
	Count       int               `json:"count"`
	Min         float64           `json:"min"`
	Max         float64           `json:"max"`
	Sum         float64           `json:"sum"`
}

// Mean returns the average value in the window, or 0 for an empty window.
func (aggregate Aggregate) Mean() float64 {
	if aggregate.Count == 0 {
		return 0
	}
	return aggregate.Sum / float64(aggregate.Count)
}

// Point turns the aggregate into a point that can be sent upstream as line
// protocol: measurement "<measurement>_agg", the same tags, the fields
// <field>_mean, _min, _max and _count, and the window start as its time.
func (aggregate Aggregate) Point() Point {
	tags := make(map[string]string, len(aggregate.Tags))
	maps.Copy(tags, aggregate.Tags)
	return Point{
		Measurement: aggregate.Measurement + "_agg",
		Tags:        tags,
		Fields: map[string]float64{
			aggregate.Field + "_mean":  aggregate.Mean(),
			aggregate.Field + "_min":   aggregate.Min,
			aggregate.Field + "_max":   aggregate.Max,
			aggregate.Field + "_count": float64(aggregate.Count),
		},
		Time: aggregate.Start,
	}
}

// windowKey identifies the open window of one field of one series. A struct
// instead of the original "series|field" string, where measurement "a|b"
// with field "c" and measurement "a" with field "b|c" shared one window.
type windowKey struct {
	series string
	field  string
}

// Tumbling aggregates points into windows of a fixed size, by the time in
// the point. It is safe for concurrent use: HTTP handlers add points while a
// background loop flushes.
//
// A window is handed out at most once. After it has been flushed, points that
// belong to it are dropped and counted as late, instead of opening the same
// window again as the original did, which sent two aggregates for one second.
type Tumbling struct {
	size time.Duration

	mutex         sync.Mutex
	open          map[windowKey]*Aggregate
	flushedBefore time.Time // every window ending at or before this is closed
	latePoints    int
}

// NewTumbling returns an empty aggregator with windows of the given size.
func NewTumbling(size time.Duration) (*Tumbling, error) {
	if size <= 0 {
		return nil, ErrWindowSize
	}
	return &Tumbling{size: size, open: map[windowKey]*Aggregate{}}, nil
}

// Add adds every field of the point to the window its time falls in. It
// returns the windows of this series that the point closed, because its time
// lies in a later window. A point for a window that is already closed is
// dropped and counted by LatePoints.
func (window *Tumbling) Add(point Point) []Aggregate {
	window.mutex.Lock()
	defer window.mutex.Unlock()

	start := point.Time.Truncate(window.size)
	isFlushed := !start.Add(window.size).After(window.flushedBefore)
	if isFlushed {
		window.latePoints++
		return nil
	}
	series := point.Key()
	var closed []Aggregate
	isLate := false
	for _, field := range slices.Sorted(maps.Keys(point.Fields)) {
		key := windowKey{series: series, field: field}
		current, found := window.open[key]
		if found && start.Before(current.Start) {
			isLate = true
			continue
		}
		if found && start.After(current.Start) {
			closed = append(closed, *current)
			found = false
		}
		if !found {
			current = &Aggregate{
				Series:      series,
				Measurement: point.Measurement,
				Tags:        maps.Clone(point.Tags),
				Field:       field,
				Start:       start,
				Min:         math.Inf(1),
				Max:         math.Inf(-1),
			}
			window.open[key] = current
		}
		value := point.Fields[field]
		current.Count++
		current.Sum += value
		current.Min = math.Min(current.Min, value)
		current.Max = math.Max(current.Max, value)
	}
	if isLate {
		window.latePoints++
	}
	return closed
}

// FlushBefore closes and returns every window that ends at or before now,
// so a device that goes silent does not keep its last window open forever.
// To accept points that arrive a little late, pass now minus that delay.
func (window *Tumbling) FlushBefore(now time.Time) []Aggregate {
	return window.flush(func(end time.Time) bool { return !end.After(now) })
}

// Flush closes and returns every open window, for example at shutdown.
func (window *Tumbling) Flush() []Aggregate {
	return window.flush(func(time.Time) bool { return true })
}

// LatePoints returns how many points were dropped because their window was
// already closed.
func (window *Tumbling) LatePoints() int {
	window.mutex.Lock()
	defer window.mutex.Unlock()
	return window.latePoints
}

// flush closes the open windows whose end isDue accepts, sorted by series and
// field so the output does not depend on map order.
func (window *Tumbling) flush(isDue func(end time.Time) bool) []Aggregate {
	window.mutex.Lock()
	defer window.mutex.Unlock()

	var flushed []Aggregate
	for key, aggregate := range window.open {
		end := aggregate.Start.Add(window.size)
		if !isDue(end) {
			continue
		}
		flushed = append(flushed, *aggregate)
		delete(window.open, key)
		if end.After(window.flushedBefore) {
			window.flushedBefore = end
		}
	}
	slices.SortFunc(flushed, func(first, second Aggregate) int {
		return cmp.Or(cmp.Compare(first.Series, second.Series), cmp.Compare(first.Field, second.Field))
	})
	return flushed
}
