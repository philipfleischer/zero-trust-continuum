// Tests for ztc-ingest: writing line protocol, queries as JSON and CSV,
// rejected input, configuration and the service lifecycle.

package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/config"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/httpx"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/svc"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/telemetry"
)

// environmentFrom returns a config.Env that reads from variables instead of
// the process environment.
func environmentFrom(variables map[string]string) config.Env {
	return config.NewWithLookup(func(name string) (string, bool) {
		value, found := variables[name]
		return value, found
	})
}

// startServer starts the complete service, operational endpoints included.
func startServer(t *testing.T, variables map[string]string) *httptest.Server {
	t.Helper()
	environment := environmentFrom(variables)
	service, err := svc.New("ztc-ingest", environment, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	app, err := setup(environment, service)
	if err != nil {
		t.Fatalf("setup() = %v", err)
	}
	server := httptest.NewServer(service.Handler(app, nil))
	t.Cleanup(server.Close)
	return server
}

// send makes a request and returns the status code, the Content-Type and
// the body.
func send(t *testing.T, method, address, body string) (int, string, string) {
	t.Helper()
	request, err := http.NewRequest(method, address, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, response.Header.Get("Content-Type"), string(responseBody)
}

// write posts line protocol to /v1/write and decodes the result.
func write(t *testing.T, server *httptest.Server, lines string) writeResult {
	t.Helper()
	code, _, body := send(t, http.MethodPost, server.URL+"/v1/write", lines)
	if code != http.StatusOK {
		t.Fatalf("POST /v1/write = %d %s", code, body)
	}
	var result writeResult
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		t.Fatal(err)
	}
	return result
}

// queryPoints asks /v1/query for JSON and decodes the points.
func queryPoints(t *testing.T, server *httptest.Server, parameters url.Values) []telemetry.Point {
	t.Helper()
	code, _, body := send(t, http.MethodGet, server.URL+"/v1/query?"+parameters.Encode(), "")
	if code != http.StatusOK {
		t.Fatalf("GET /v1/query?%s = %d %s", parameters.Encode(), code, body)
	}
	var points []telemetry.Point
	if err := json.Unmarshal([]byte(body), &points); err != nil {
		t.Fatal(err)
	}
	return points
}

// nanoseconds formats a time as a line-protocol timestamp.
func nanoseconds(at time.Time) string {
	return strconv.FormatInt(at.UnixNano(), 10)
}

// TestWriteAndQuery is the acceptance criterion of issue #28: a line
// written to ztc-ingest comes back from /v1/query as JSON and as CSV.
func TestWriteAndQuery(t *testing.T) {
	server := startServer(t, nil)
	windowStart := time.Now().Truncate(time.Second).Add(-2 * time.Second)
	lines := "pmu_agg,device=pmu-1 frequency_hz_mean=49.98,frequency_hz_count=50 " + nanoseconds(windowStart) + "\n" +
		"pmu_agg,device=pmu-2 frequency_hz_mean=50.01,frequency_hz_count=50 " + nanoseconds(windowStart) + "\n"
	if result := write(t, server, lines); result.Stored != 2 || result.Rejected != 0 {
		t.Fatalf("write result = %+v, want 2 stored", result)
	}

	points := queryPoints(t, server, url.Values{"measurement": {"pmu_agg"}})
	if len(points) != 2 {
		t.Fatalf("got %d points, want 2: %+v", len(points), points)
	}
	first := points[0]
	if first.Tags["device"] != "pmu-1" || first.Fields["frequency_hz_mean"] != 49.98 || !first.Time.Equal(windowStart) {
		t.Errorf("first point = %+v", first)
	}

	code, contentType, body := send(t, http.MethodGet, server.URL+"/v1/query?measurement=pmu_agg&format=csv", "")
	if code != http.StatusOK || !strings.HasPrefix(contentType, "text/csv") {
		t.Fatalf("CSV query = %d %s", code, contentType)
	}
	rows, err := csv.NewReader(strings.NewReader(body)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 5 {
		t.Fatalf("got %d CSV rows, want a header and two fields of two points:\n%s", len(rows), body)
	}
	wantHeader := []string{"time", "series", "field", "value"}
	wantFirstRow := []string{windowStart.UTC().Format(time.RFC3339Nano), "pmu_agg,device=pmu-1", "frequency_hz_count", "50"}
	if strings.Join(rows[0], ",") != strings.Join(wantHeader, ",") || strings.Join(rows[1], "|") != strings.Join(wantFirstRow, "|") {
		t.Errorf("CSV starts with %q and %q, want %q and %q", rows[0], rows[1], wantHeader, wantFirstRow)
	}
}

func TestWriteRejectsBadLinesButKeepsTheRest(t *testing.T) {
	server := startServer(t, nil)
	now := time.Now()
	lines := "pmu_agg,device=pmu-1 v=1 " + nanoseconds(now) + "\n" +
		"this is not line protocol\n" +
		"pmu_agg,device=pmu-1 v=NaN\n" + // rejected by the parser
		"pmu_agg,device=pmu-1 v=2 " + nanoseconds(now.Add(-time.Hour)) + "\n" + // rejected by Validate
		"# a comment is not counted\n" +
		"pmu_agg,device=pmu-1 v=3\n" // no timestamp: stamped on arrival
	result := write(t, server, lines)
	if result.Stored != 2 || result.Rejected != 3 {
		t.Errorf("write result = %+v, want 2 stored and 3 rejected", result)
	}

	_, _, metrics := send(t, http.MethodGet, server.URL+"/metrics", "")
	for _, want := range []string{
		`ztc_ingest_points_total{result="stored"} 2`,
		`ztc_ingest_points_total{result="unparsable"} 2`,
		`ztc_ingest_points_total{result="invalid"} 1`,
	} {
		if !strings.Contains(metrics, want) {
			t.Errorf("/metrics has no %q", want)
		}
	}
}

func TestWriteReportsAFullStore(t *testing.T) {
	server := startServer(t, map[string]string{"ZTC_INGEST_MAX_SERIES": "1"})
	result := write(t, server, "pmu_agg,device=pmu-1 v=1\npmu_agg,device=pmu-2 v=1\n")
	if result.Stored != 1 || result.Rejected != 1 {
		t.Errorf("write result = %+v, want the second series rejected", result)
	}
	_, _, metrics := send(t, http.MethodGet, server.URL+"/metrics", "")
	if !strings.Contains(metrics, `ztc_ingest_points_total{result="store_full"} 1`) {
		t.Error("/metrics does not count the point the full store refused")
	}
}

func TestWriteRefusesAnOversizedBody(t *testing.T) {
	server := startServer(t, nil)
	line := "pmu_agg,device=pmu-1 v=1\n"
	oversized := strings.Repeat(line, httpx.MaxBody/len(line)+1)
	code, _, body := send(t, http.MethodPost, server.URL+"/v1/write", oversized)
	if code != http.StatusRequestEntityTooLarge {
		t.Errorf("POST /v1/write with %d bytes = %d %s, want 413", len(oversized), code, body)
	}
	if points := queryPoints(t, server, url.Values{"measurement": {"pmu_agg"}}); len(points) != 0 {
		t.Errorf("an oversized body stored %d points, want none", len(points))
	}
}

func TestQueryTimeRange(t *testing.T) {
	server := startServer(t, nil)
	base := time.Now().Truncate(time.Second).Add(-5 * time.Second)
	var lines strings.Builder
	for second := range 4 {
		at := base.Add(time.Duration(second) * time.Second)
		lines.WriteString("pmu_agg,device=pmu-1 v=" + strconv.Itoa(second) + " " + nanoseconds(at) + "\n")
	}
	write(t, server, lines.String())

	points := queryPoints(t, server, url.Values{
		"measurement": {"pmu_agg"},
		"from":        {base.Add(time.Second).Format(time.RFC3339)},
		"to":          {base.Add(3 * time.Second).Format(time.RFC3339)},
	})
	if len(points) != 2 || points[0].Fields["v"] != 1 || points[1].Fields["v"] != 2 {
		t.Errorf("points in [1 s, 3 s) = %+v, want v=1 and v=2", points)
	}
}

func TestQueryWithoutMatchesIsAnEmptyList(t *testing.T) {
	server := startServer(t, nil)
	code, _, body := send(t, http.MethodGet, server.URL+"/v1/query?measurement=meter", "")
	if code != http.StatusOK || strings.TrimSpace(body) != "[]" {
		t.Errorf("GET /v1/query?measurement=meter = %d %q, want 200 []", code, body)
	}
}

func TestQueryRejectsBadParameters(t *testing.T) {
	server := startServer(t, nil)
	tests := []struct {
		name  string
		query string
	}{
		{"no measurement", ""},
		{"from is not RFC 3339", "measurement=pmu_agg&from=yesterday"},
		{"to is a Unix time", "measurement=pmu_agg&to=1700000000"},
		{"unknown format", "measurement=pmu_agg&format=xml"},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			code, _, body := send(t, http.MethodGet, server.URL+"/v1/query?"+testCase.query, "")
			if code != http.StatusBadRequest {
				t.Errorf("GET /v1/query?%s = %d %s, want 400", testCase.query, code, body)
			}
		})
	}
}

func TestSeries(t *testing.T) {
	server := startServer(t, nil)
	write(t, server, "pmu_agg,device=pmu-2 v=1\npmu_agg,device=pmu-1 v=1\nmeter_agg v=1\n")
	code, _, body := send(t, http.MethodGet, server.URL+"/v1/series", "")
	var series []string
	if err := json.Unmarshal([]byte(body), &series); err != nil {
		t.Fatal(err)
	}
	want := "meter_agg pmu_agg,device=pmu-1 pmu_agg,device=pmu-2"
	if code != http.StatusOK || strings.Join(series, " ") != want {
		t.Errorf("GET /v1/series = %d %v, want %s", code, series, want)
	}
}

func TestWrongMethods(t *testing.T) {
	server := startServer(t, nil)
	for _, request := range [][2]string{{http.MethodGet, "/v1/write"}, {http.MethodPost, "/v1/query"}, {http.MethodDelete, "/v1/series"}} {
		if code, _, _ := send(t, request[0], server.URL+request[1], ""); code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s = %d, want 405", request[0], request[1], code)
		}
	}
}

func TestOperationalEndpoints(t *testing.T) {
	server := startServer(t, nil)
	for _, path := range []string{"/healthz", "/readyz", "/metrics"} {
		if code, _, body := send(t, http.MethodGet, server.URL+path, ""); code != http.StatusOK {
			t.Errorf("GET %s = %d %s", path, code, body)
		}
	}
}

func TestSetupRejectsConfiguration(t *testing.T) {
	tests := []struct {
		name      string
		variables map[string]string
	}{
		{"capacity zero", map[string]string{"ZTC_INGEST_CAPACITY": "0"}},
		{"series limit negative", map[string]string{"ZTC_INGEST_MAX_SERIES": "-1"}},
		{"skew zero", map[string]string{"ZTC_INGEST_MAX_SKEW": "0s"}},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			environment := environmentFrom(testCase.variables)
			service, err := svc.New("ztc-ingest", environment, io.Discard)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := setup(environment, service); err == nil {
				t.Error("setup() accepted the configuration")
			}
		})
	}
}

// TestRunRefusesInvalidConfiguration checks the fail-fast path through run:
// a value that is not a number stops the service before it listens.
func TestRunRefusesInvalidConfiguration(t *testing.T) {
	environment := environmentFrom(map[string]string{"ZTC_INGEST_CAPACITY": "many", "ZTC_LISTEN": "127.0.0.1:0"})
	if err := run(context.Background(), environment, io.Discard); err == nil {
		t.Error("run() started with ZTC_INGEST_CAPACITY=many")
	}
}

// TestRunServesUntilCancelled starts the real service on a free port and
// stops it through its context, as SIGTERM would.
func TestRunServesUntilCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan error, 1)
	go func() {
		stopped <- run(ctx, environmentFrom(map[string]string{"ZTC_LISTEN": "127.0.0.1:0"}), io.Discard)
	}()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case err := <-stopped:
		if err != nil {
			t.Errorf("run() = %v, want a clean shutdown", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run() did not stop after cancel")
	}
}
