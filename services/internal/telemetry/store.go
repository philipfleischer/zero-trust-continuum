// An in-memory time-series store with a fixed memory ceiling: a ring buffer
// per series and a limit on the number of series. Enough for the demo and
// the analytics; a real deployment would point Telegraf at InfluxDB.

package telemetry

import (
	"cmp"
	"errors"
	"maps"
	"slices"
	"sync"
	"time"
)

// ErrStoreSize is returned by NewStore for a capacity or series limit that
// is not positive.
var ErrStoreSize = errors.New("telemetry: store capacity and series limit must be positive")

// ErrStoreFull is returned by Append for a point of a new series when the
// store already holds its maximum number of series.
var ErrStoreFull = errors.New("telemetry: store has reached its series limit")

// ring holds the newest points of one series. It grows to the capacity and
// from then on overwrites its oldest point, so an append never moves data.
type ring struct {
	measurement string
	points      []Point
	oldest      int // index of the oldest point once the ring is full
}

// add stores the point, overwriting the oldest one when the ring is full.
func (buffer *ring) add(point Point, capacity int) {
	if len(buffer.points) < capacity {
		buffer.points = append(buffer.points, point)
		return
	}
	buffer.points[buffer.oldest] = point
	buffer.oldest = (buffer.oldest + 1) % capacity
}

// inOrder returns the points from the oldest to the newest.
func (buffer *ring) inOrder() []Point {
	ordered := make([]Point, 0, len(buffer.points))
	ordered = append(ordered, buffer.points[buffer.oldest:]...)
	return append(ordered, buffer.points[:buffer.oldest]...)
}

// Store keeps the newest points of every series in memory. It never holds
// more than capacity points per series and maxSeries series, so a device
// that invents a new tag value for every point cannot exhaust the memory of
// the service; the original limited only the points per series. It is safe
// for concurrent use.
type Store struct {
	capacity  int
	maxSeries int

	mutex  sync.RWMutex
	series map[string]*ring
}

// NewStore returns an empty store that keeps at most capacity points per
// series and at most maxSeries series.
func NewStore(capacity, maxSeries int) (*Store, error) {
	if capacity <= 0 || maxSeries <= 0 {
		return nil, ErrStoreSize
	}
	return &Store{capacity: capacity, maxSeries: maxSeries, series: map[string]*ring{}}, nil
}

// Append stores a copy of the point in its series, dropping the oldest point
// of that series when it is full. A point of a new series is refused with
// ErrStoreFull when the store already holds maxSeries series.
func (store *Store) Append(point Point) error {
	key := point.Key()
	stored := point.Clone()

	store.mutex.Lock()
	defer store.mutex.Unlock()
	buffer, found := store.series[key]
	if !found {
		if len(store.series) >= store.maxSeries {
			return ErrStoreFull
		}
		buffer = &ring{measurement: point.Measurement}
		store.series[key] = buffer
	}
	buffer.add(stored, store.capacity)
	return nil
}

// Query returns the points of every series of the measurement, whatever
// their tags, with a time in [from, to). A zero from or to leaves that end
// open. The points are sorted by time, then by series. They share their maps
// with the store and must not be modified.
func (store *Store) Query(measurement string, from, to time.Time) []Point {
	store.mutex.RLock()
	defer store.mutex.RUnlock()

	var matches []Point
	for _, buffer := range store.series {
		if buffer.measurement != measurement {
			continue
		}
		for _, point := range buffer.inOrder() {
			isBeforeFrom := !from.IsZero() && point.Time.Before(from)
			isAtOrAfterTo := !to.IsZero() && !point.Time.Before(to)
			if isBeforeFrom || isAtOrAfterTo {
				continue
			}
			matches = append(matches, point)
		}
	}
	slices.SortStableFunc(matches, func(first, second Point) int {
		if order := first.Time.Compare(second.Time); order != 0 {
			return order
		}
		// Key builds a string, so it is only called for equal times.
		return cmp.Compare(first.Key(), second.Key())
	})
	return matches
}

// Series returns the keys of all series, sorted.
func (store *Store) Series() []string {
	store.mutex.RLock()
	defer store.mutex.RUnlock()
	return slices.Sorted(maps.Keys(store.series))
}

// Len returns the number of points in the store.
func (store *Store) Len() int {
	store.mutex.RLock()
	defer store.mutex.RUnlock()
	total := 0
	for _, buffer := range store.series {
		total += len(buffer.points)
	}
	return total
}
