// Pipeline stages: small functions that check, change or drop one point at a
// time, chained in a fixed order and run over channels.

package telemetry

import (
	"context"
	"maps"
	"math"
	"time"
)

// Stage handles one point. It returns the point, changed or not, and true to
// pass it on, or false to drop it. A stage must not modify the maps of the
// point it receives; Clone first.
type Stage func(point Point) (Point, bool)

// Pipeline runs its stages in order. The first stage that drops a point
// ends the pipeline for that point.
type Pipeline struct {
	Stages []Stage
}

// Apply runs every stage on one point and reports whether it got through.
func (pipeline Pipeline) Apply(point Point) (Point, bool) {
	for _, stage := range pipeline.Stages {
		var kept bool
		if point, kept = stage(point); !kept {
			return Point{}, false
		}
	}
	return point, true
}

// Run applies the pipeline to every point from input in its own goroutine
// and sends the points that get through on the returned channel, in the
// order they arrived. The returned channel is closed when input is closed or
// ctx is cancelled, so a reader can simply range over it.
func (pipeline Pipeline) Run(ctx context.Context, input <-chan Point) <-chan Point {
	output := make(chan Point, 64)
	go func() {
		defer close(output)
		for {
			select {
			case <-ctx.Done():
				return
			case point, open := <-input:
				if !open {
					return
				}
				point, kept := pipeline.Apply(point)
				if !kept {
					continue
				}
				select {
				case output <- point:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return output
}

// Validate drops points without a measurement or fields, points with a NaN
// or infinite value, and points whose time is more than maxSkew away from
// now in either direction. A point without a time gets now. A nil now means
// time.Now.
//
// The original only dropped points from the future. A point far in the past
// is as wrong: either the device clock is broken, or old samples are being
// replayed, and either way the window it belongs to has long been closed.
func Validate(maxSkew time.Duration, now func() time.Time) Stage {
	if now == nil {
		now = time.Now
	}
	return func(point Point) (Point, bool) {
		if point.Measurement == "" || len(point.Fields) == 0 {
			return Point{}, false
		}
		for _, value := range point.Fields {
			if math.IsNaN(value) || math.IsInf(value, 0) {
				return Point{}, false
			}
		}
		arrival := now()
		if point.Time.IsZero() {
			point.Time = arrival
			return point, true
		}
		skew := point.Time.Sub(arrival).Abs()
		if skew > maxSkew {
			return Point{}, false
		}
		return point, true
	}
}

// Enrich sets the given tags on every point, for example the fog node and
// the zone. These tags win over tags with the same key sent by the device, so
// a device cannot claim another zone. The tags are copied when Enrich is
// called, so changing the map afterwards changes nothing.
func Enrich(tags map[string]string) Stage {
	fixedTags := maps.Clone(tags)
	return func(point Point) (Point, bool) {
		enriched := point.Clone()
		maps.Copy(enriched.Tags, fixedTags)
		return enriched, true
	}
}

// Range drops points whose field lies outside [lowest, highest], such as a
// grid frequency outside 45–55 Hz, which no healthy sensor reports. Points
// without the field pass. Each dropped point is passed to onReject if it is
// not nil, so the caller can count or report it.
func Range(field string, lowest, highest float64, onReject func(Point)) Stage {
	return func(point Point) (Point, bool) {
		value, found := point.Fields[field]
		if !found {
			return point, true
		}
		// Written so that NaN, for which every comparison is false, is dropped.
		isInside := value >= lowest && value <= highest
		if isInside {
			return point, true
		}
		if onReject != nil {
			onReject(point)
		}
		return Point{}, false
	}
}
