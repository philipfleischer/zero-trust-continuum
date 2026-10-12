package observability

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// get sends a GET request for path to handler and returns the status code and body.
func get(t *testing.T, handler http.Handler, path string) (int, string) {
	t.Helper()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
	return recorder.Code, recorder.Body.String()
}

func TestHealthMux(t *testing.T) {
	pdpError := error(nil)
	checks := map[string]Check{
		"pdp":   func(context.Context) error { return pdpError },
		"audit": func(context.Context) error { return nil },
	}
	var logs bytes.Buffer
	mux := HealthMux(NewRegistry(), slog.New(slog.NewTextHandler(&logs, nil)), checks)

	if code, _ := get(t, mux, "/healthz"); code != http.StatusOK {
		t.Errorf("/healthz = %d, want 200", code)
	}
	if code, _ := get(t, mux, "/readyz"); code != http.StatusOK {
		t.Errorf("/readyz with healthy checks = %d, want 200", code)
	}

	pdpError = errors.New("dial tcp 10.0.3.7:8181: connection refused")
	code, body := get(t, mux, "/readyz")
	if code != http.StatusServiceUnavailable || !strings.Contains(body, "pdp") {
		t.Errorf("/readyz with failing check = %d %q, want 503 naming pdp", code, body)
	}
	if strings.Contains(body, "10.0.3.7") {
		t.Errorf("/readyz leaks the internal error to the client: %q", body)
	}
	if !strings.Contains(logs.String(), "10.0.3.7") {
		t.Errorf("the check error was not logged; logs = %q", logs.String())
	}

	if code, _ := get(t, mux, "/metrics"); code != http.StatusOK {
		t.Errorf("/metrics = %d, want 200", code)
	}
}

func TestReadyzGivesChecksADeadline(t *testing.T) {
	var hadDeadline bool
	checks := map[string]Check{"slow": func(ctx context.Context) error {
		_, hadDeadline = ctx.Deadline()
		return nil
	}}
	mux := HealthMux(NewRegistry(), slog.New(slog.NewTextHandler(io.Discard, nil)), checks)
	get(t, mux, "/readyz")
	if !hadDeadline {
		t.Error("checks were called without a deadline")
	}
}

func TestInstrument(t *testing.T) {
	registry := NewRegistry()
	handler := Instrument(registry, "ztc-pdp", http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/deny" {
			writer.WriteHeader(http.StatusForbidden)
			writer.WriteHeader(http.StatusInternalServerError) // ignored by net/http; the first code counts
			return
		}
		_, _ = writer.Write([]byte("ok")) // implicit 200
	}))

	for _, request := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/allow", nil),
		httptest.NewRequest(http.MethodPost, "/deny", nil),
		httptest.NewRequest("EVIL-METHOD", "/allow", nil),
	} {
		handler.ServeHTTP(httptest.NewRecorder(), request)
	}

	requestCount := registry.Counter("ztc_http_requests_total", "")
	tests := []struct {
		method, code string
		want         float64
	}{
		{"GET", "200", 1},
		{"POST", "403", 1},
		{"OTHER", "200", 1},
		{"EVIL-METHOD", "200", 0},
	}
	for _, testCase := range tests {
		got := requestCount.Value("service", "ztc-pdp", "method", testCase.method, "code", testCase.code)
		if got != testCase.want {
			t.Errorf("requests{method=%s,code=%s} = %v, want %v", testCase.method, testCase.code, got, testCase.want)
		}
	}

	var text strings.Builder
	if err := registry.Write(&text); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text.String(), `ztc_http_request_seconds_count{service="ztc-pdp"} 3`) {
		t.Errorf("latency histogram did not record 3 requests:\n%s", text.String())
	}
}

func TestNewLogger(t *testing.T) {
	var output bytes.Buffer
	logger, err := NewLogger(&output, "ztc-pdp", "warn")
	if err != nil {
		t.Fatal(err)
	}
	logger.Info("hidden")
	logger.Warn("shown", "subject", "pmu-7")

	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("got %d log lines, want 1 (info is below warn):\n%s", len(lines), output.String())
	}
	var record map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &record); err != nil {
		t.Fatalf("log line is not JSON: %v", err)
	}
	if record["service"] != "ztc-pdp" || record["msg"] != "shown" || record["subject"] != "pmu-7" {
		t.Errorf("log record = %v, want service, msg and subject fields", record)
	}

	if _, err := NewLogger(&output, "ztc-pdp", "verbose"); err == nil {
		t.Error("NewLogger accepted the unknown level \"verbose\"")
	}
}
