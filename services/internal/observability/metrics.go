// Package observability gives every ZTC service metrics in the Prometheus
// text exposition format, health and readiness endpoints, request
// instrumentation and structured logging, using only the standard library.
//
// Industry equivalent: prometheus/client_golang and OpenTelemetry.
package observability

import (
	"fmt"
	"io"
	"maps"
	"math"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// metric is implemented by every metric type so the registry can render them
// without knowing which kind each one is.
type metric interface {
	writeTo(output *strings.Builder)
}

// Registry holds the metrics of one service. It is safe for concurrent use.
type Registry struct {
	mutex   sync.Mutex
	metrics map[string]metric
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{metrics: map[string]metric{}}
}

// register returns the metric called name, creating it with create if it does
// not exist yet. Registering the same name as two different kinds of metric
// is a programming error, so it panics.
func register[Metric metric](registry *Registry, name string, create func() Metric) Metric {
	registry.mutex.Lock()
	defer registry.mutex.Unlock()
	existing, found := registry.metrics[name]
	if !found {
		created := create()
		registry.metrics[name] = created
		return created
	}
	sameKind, isSameKind := existing.(Metric)
	if !isSameKind {
		panic(fmt.Sprintf("observability: %q is already registered as %T", name, existing))
	}
	return sameKind
}

// Counter returns the counter called name, creating it if needed.
func (registry *Registry) Counter(name, help string) *Counter {
	return register(registry, name, func() *Counter {
		return &Counter{series{name: name, help: help, kind: "counter", values: map[string]float64{}}}
	})
}

// Gauge returns the gauge called name, creating it if needed.
func (registry *Registry) Gauge(name, help string) *Gauge {
	return register(registry, name, func() *Gauge {
		return &Gauge{series{name: name, help: help, kind: "gauge", values: map[string]float64{}}}
	})
}

// Histogram returns the histogram called name with the given bucket upper
// bounds, creating it if needed. The buckets of an existing histogram are kept.
func (registry *Registry) Histogram(name, help string, buckets []float64) *Histogram {
	return register(registry, name, func() *Histogram {
		sortedBuckets := slices.Clone(buckets)
		slices.Sort(sortedBuckets)
		return &Histogram{name: name, help: help, buckets: sortedBuckets, series: map[string]*histogramSeries{}}
	})
}

// Write renders every metric, sorted by name, in the Prometheus text format.
func (registry *Registry) Write(output io.Writer) error {
	// Copy the metric list while holding the lock, so a metric registered
	// concurrently by another goroutine cannot change the map under us.
	registry.mutex.Lock()
	names := slices.Sorted(maps.Keys(registry.metrics))
	metricsByName := make([]metric, len(names))
	for i, name := range names {
		metricsByName[i] = registry.metrics[name]
	}
	registry.mutex.Unlock()

	var text strings.Builder
	for _, oneMetric := range metricsByName {
		oneMetric.writeTo(&text)
	}
	_, err := io.WriteString(output, text.String())
	return err
}

// Handler serves the registry as a Prometheus scrape endpoint.
func (registry *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_ = registry.Write(writer)
	})
}

// series is the shared part of counters and gauges: one float64 per label set.
type series struct {
	name, help, kind string
	mutex            sync.Mutex
	values           map[string]float64 // rendered label set -> value
}

func (series *series) add(amount float64, labels []string) {
	labelSet := renderLabels(labels)
	series.mutex.Lock()
	series.values[labelSet] += amount
	series.mutex.Unlock()
}

func (series *series) value(labels []string) float64 {
	series.mutex.Lock()
	defer series.mutex.Unlock()
	return series.values[renderLabels(labels)]
}

func (series *series) writeTo(output *strings.Builder) {
	series.mutex.Lock()
	defer series.mutex.Unlock()
	fmt.Fprintf(output, "# HELP %s %s\n# TYPE %s %s\n", series.name, escapeHelp(series.help), series.name, series.kind)
	for _, labelSet := range slices.Sorted(maps.Keys(series.values)) {
		fmt.Fprintf(output, "%s%s %s\n", series.name, labelSet, formatFloat(series.values[labelSet]))
	}
}

// Counter is a value that only goes up, for example the number of requests.
// Labels are given as key, value pairs: counter.Inc("outcome", "allow").
type Counter struct{ series }

// Inc adds 1 for the given labels.
func (counter *Counter) Inc(labels ...string) { counter.Add(1, labels...) }

// Add adds amount for the given labels. Negative amounts are ignored, because
// a counter never goes down.
func (counter *Counter) Add(amount float64, labels ...string) {
	if amount < 0 {
		return
	}
	counter.add(amount, labels)
}

// Value returns the current value for the given labels.
func (counter *Counter) Value(labels ...string) float64 { return counter.value(labels) }

// Gauge is a value that can go up and down, for example a trust score.
type Gauge struct{ series }

// Set sets the gauge for the given labels.
func (gauge *Gauge) Set(value float64, labels ...string) {
	labelSet := renderLabels(labels)
	gauge.mutex.Lock()
	gauge.values[labelSet] = value
	gauge.mutex.Unlock()
}

// Add adds amount (which may be negative) for the given labels.
func (gauge *Gauge) Add(amount float64, labels ...string) { gauge.add(amount, labels) }

// Value returns the current value for the given labels.
func (gauge *Gauge) Value(labels ...string) float64 { return gauge.value(labels) }

// Histogram counts observations, such as request latencies, in buckets.
type Histogram struct {
	name, help string
	buckets    []float64 // sorted upper bounds
	mutex      sync.Mutex
	series     map[string]*histogramSeries
}

type histogramSeries struct {
	countPerBucket []uint64 // observations per bucket; made cumulative when rendered
	sum            float64
	count          uint64
}

// Observe records one value for the given labels.
func (histogram *Histogram) Observe(value float64, labels ...string) {
	labelSet := renderLabels(labels)
	histogram.mutex.Lock()
	defer histogram.mutex.Unlock()
	oneSeries, found := histogram.series[labelSet]
	if !found {
		oneSeries = &histogramSeries{countPerBucket: make([]uint64, len(histogram.buckets))}
		histogram.series[labelSet] = oneSeries
	}
	// The first bucket whose upper bound is >= value; values above every
	// bound are only counted in the implicit +Inf bucket.
	bucketIndex, _ := slices.BinarySearch(histogram.buckets, value)
	if bucketIndex < len(oneSeries.countPerBucket) {
		oneSeries.countPerBucket[bucketIndex]++
	}
	oneSeries.sum += value
	oneSeries.count++
}

func (histogram *Histogram) writeTo(output *strings.Builder) {
	histogram.mutex.Lock()
	defer histogram.mutex.Unlock()
	name := histogram.name
	fmt.Fprintf(output, "# HELP %s %s\n# TYPE %s histogram\n", name, escapeHelp(histogram.help), name)
	for _, labelSet := range slices.Sorted(maps.Keys(histogram.series)) {
		oneSeries := histogram.series[labelSet]
		var cumulative uint64
		for i, upperBound := range histogram.buckets {
			cumulative += oneSeries.countPerBucket[i]
			bucketLabels := withLabel(labelSet, "le", formatFloat(upperBound))
			fmt.Fprintf(output, "%s_bucket%s %d\n", name, bucketLabels, cumulative)
		}
		fmt.Fprintf(output, "%s_bucket%s %d\n", name, withLabel(labelSet, "le", "+Inf"), oneSeries.count)
		fmt.Fprintf(output, "%s_sum%s %s\n", name, labelSet, formatFloat(oneSeries.sum))
		fmt.Fprintf(output, "%s_count%s %d\n", name, labelSet, oneSeries.count)
	}
}

// DefaultLatencyBuckets are latency buckets in seconds suited to
// authorization decisions, from 0.5 ms to 5 s.
var DefaultLatencyBuckets = []float64{0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5}

// renderLabels turns ("b", "2", "a", "1") into {a="1",b="2"}. Pairs are sorted
// by key so the same label set always renders the same way; a trailing key
// without a value is ignored.
func renderLabels(labels []string) string {
	if len(labels) < 2 {
		return ""
	}
	type labelPair struct{ key, value string }
	pairs := make([]labelPair, 0, len(labels)/2)
	for i := 0; i+1 < len(labels); i += 2 {
		pairs = append(pairs, labelPair{key: labels[i], value: labels[i+1]})
	}
	slices.SortFunc(pairs, func(first, second labelPair) int { return strings.Compare(first.key, second.key) })

	var text strings.Builder
	text.WriteByte('{')
	for i, pair := range pairs {
		if i > 0 {
			text.WriteByte(',')
		}
		fmt.Fprintf(&text, `%s="%s"`, pair.key, escapeLabel(pair.value))
	}
	text.WriteByte('}')
	return text.String()
}

// withLabel adds one more label to an already rendered label set.
func withLabel(renderedLabels, key, value string) string {
	extraLabel := fmt.Sprintf(`%s="%s"`, key, escapeLabel(value))
	if renderedLabels == "" {
		return "{" + extraLabel + "}"
	}
	withoutClosingBrace := renderedLabels[:len(renderedLabels)-1]
	return withoutClosingBrace + "," + extraLabel + "}"
}

var (
	labelEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	helpEscaper  = strings.NewReplacer(`\`, `\\`, "\n", `\n`)
)

func escapeLabel(text string) string { return labelEscaper.Replace(text) }

func escapeHelp(text string) string { return helpEscaper.Replace(text) }

func formatFloat(number float64) string {
	switch {
	case math.IsInf(number, 1):
		return "+Inf"
	case math.IsInf(number, -1):
		return "-Inf"
	case math.IsNaN(number):
		return "NaN"
	}
	return strconv.FormatFloat(number, 'g', -1, 64)
}
