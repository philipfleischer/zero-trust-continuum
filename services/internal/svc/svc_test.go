package svc

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/config"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/observability"
)

// environmentFrom returns a config.Env that reads from variables instead of
// the process environment.
func environmentFrom(variables map[string]string) config.Env {
	return config.NewWithLookup(func(name string) (string, bool) {
		value, found := variables[name]
		return value, found
	})
}

func newTestService(t *testing.T, variables map[string]string) *Service {
	t.Helper()
	service, err := New("ztc-test", environmentFrom(variables), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func TestNewRejectsUnknownLogLevel(t *testing.T) {
	environment := environmentFrom(map[string]string{"ZTC_LOG_LEVEL": "verbose"})
	if _, err := New("ztc-test", environment, io.Discard); err == nil {
		t.Fatal("New accepted ZTC_LOG_LEVEL=verbose")
	}
}

func TestNewLogsJSONWithServiceName(t *testing.T) {
	var logs bytes.Buffer
	service, err := New("ztc-test", environmentFrom(nil), &logs)
	if err != nil {
		t.Fatal(err)
	}
	service.Logger.Info("hello")
	if !strings.Contains(logs.String(), `"service":"ztc-test"`) {
		t.Errorf("log line = %q, want a JSON record with the service name", logs.String())
	}
}

func TestHandlerRoutesAppAndOperationalEndpoints(t *testing.T) {
	service := newTestService(t, nil)
	app := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte("app"))
	})
	handler := service.Handler(app, nil)

	get := func(path string) (int, string) {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		return recorder.Code, recorder.Body.String()
	}

	if code, body := get("/v1/anything"); code != http.StatusOK || body != "app" {
		t.Errorf("app route = %d %q, want 200 \"app\"", code, body)
	}
	if code, _ := get("/healthz"); code != http.StatusOK {
		t.Errorf("/healthz = %d, want 200", code)
	}
	if code, _ := get("/readyz"); code != http.StatusOK {
		t.Errorf("/readyz = %d, want 200", code)
	}
	_, metrics := get("/metrics")
	if !strings.Contains(metrics, `ztc_http_requests_total{code="200",method="GET",service="ztc-test"} 1`) {
		t.Errorf("/metrics does not count the app request:\n%s", metrics)
	}
}

func TestServeRefusesInvalidConfiguration(t *testing.T) {
	service := newTestService(t, map[string]string{"ZTC_TIMEOUT": "5"}) // no unit: invalid duration
	_ = service.Environment.Duration("timeout", time.Second)

	err := service.Serve(context.Background(), "127.0.0.1:0", http.NotFoundHandler(), nil)
	if err == nil || !strings.Contains(err.Error(), "ZTC_TIMEOUT") {
		t.Fatalf("Serve error = %v, want an error naming ZTC_TIMEOUT", err)
	}
}

func TestServeStopsWhenContextIsCancelled(t *testing.T) {
	service := newTestService(t, map[string]string{"ZTC_LISTEN": "127.0.0.1:0"})
	ctx, cancel := context.WithCancel(context.Background())

	serveResult := make(chan error, 1)
	noChecks := map[string]observability.Check{}
	go func() { serveResult <- service.Serve(ctx, ":8181", http.NotFoundHandler(), noChecks) }()
	cancel()

	select {
	case err := <-serveResult:
		if err != nil {
			t.Fatalf("Serve returned %v after cancel, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after the context was cancelled")
	}
}
