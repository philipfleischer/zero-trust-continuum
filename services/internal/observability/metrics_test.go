package observability

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func TestExposition(t *testing.T) {
	registry := NewRegistry()
	requests := registry.Counter("ztc_requests_total", "Requests.")
	requests.Inc("outcome", "allow", "pep", "fog-1")
	requests.Inc("pep", "fog-1", "outcome", "allow") // same label set, other order
	requests.Add(-5, "outcome", "allow")             // ignored: counters never go down
	registry.Gauge("ztc_trust_score", "Trust score.").Set(0.75, "subject", `a"b`)
	latency := registry.Histogram("ztc_latency_seconds", "Latency.", []float64{1, 0.1}) // unsorted on purpose
	latency.Observe(0.05)
	latency.Observe(0.5)
	latency.Observe(5)

	var text strings.Builder
	if err := registry.Write(&text); err != nil {
		t.Fatal(err)
	}
	output := text.String()
	for _, wantLine := range []string{
		"# HELP ztc_requests_total Requests.",
		"# TYPE ztc_requests_total counter",
		`ztc_requests_total{outcome="allow",pep="fog-1"} 2`,
		"# TYPE ztc_trust_score gauge",
		`ztc_trust_score{subject="a\"b"} 0.75`,
		"# TYPE ztc_latency_seconds histogram",
		`ztc_latency_seconds_bucket{le="0.1"} 1`,
		`ztc_latency_seconds_bucket{le="1"} 2`,
		`ztc_latency_seconds_bucket{le="+Inf"} 3`,
		"ztc_latency_seconds_sum 5.55",
		"ztc_latency_seconds_count 3",
	} {
		if !strings.Contains(output, wantLine) {
			t.Errorf("output is missing %q\n%s", wantLine, output)
		}
	}
	if got := requests.Value("pep", "fog-1", "outcome", "allow"); got != 2 {
		t.Errorf("Value = %v, want 2", got)
	}
}

func TestSameNameReturnsSameMetric(t *testing.T) {
	registry := NewRegistry()
	registry.Counter("ztc_x_total", "X.").Inc()
	registry.Counter("ztc_x_total", "X.").Inc()
	if got := registry.Counter("ztc_x_total", "X.").Value(); got != 2 {
		t.Errorf("Value = %v, want 2", got)
	}
}

func TestRegisteringNameAsOtherKindPanics(t *testing.T) {
	registry := NewRegistry()
	registry.Counter("ztc_x", "X.")
	defer func() {
		if recover() == nil {
			t.Error("registering a counter name as a gauge did not panic")
		}
	}()
	registry.Gauge("ztc_x", "X.")
}

func TestHandler(t *testing.T) {
	registry := NewRegistry()
	registry.Counter("ztc_up_total", "Up.").Inc()
	recorder := httptest.NewRecorder()
	registry.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if contentType := recorder.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain", contentType)
	}
	if !strings.Contains(recorder.Body.String(), "ztc_up_total 1") {
		t.Errorf("body = %q, want it to contain ztc_up_total 1", recorder.Body.String())
	}
}

// TestConcurrentUse registers, updates and renders metrics from several
// goroutines at once. Run it with -race: it fails if Write reads the metric
// map without holding the registry lock.
func TestConcurrentUse(t *testing.T) {
	registry := NewRegistry()
	var workers sync.WaitGroup
	for worker := range 8 {
		workers.Go(func() {
			for i := range 100 {
				counterName := fmt.Sprintf("ztc_c%d_total", i%5)
				registry.Counter(counterName, "C.").Inc("worker", strconv.Itoa(worker))
				_ = registry.Write(io.Discard)
			}
		})
	}
	workers.Wait()

	var total float64
	for worker := range 8 {
		total += registry.Counter("ztc_c0_total", "C.").Value("worker", strconv.Itoa(worker))
	}
	if total != 8*20 {
		t.Errorf("ztc_c0_total summed over workers = %v, want %d", total, 8*20)
	}
}
