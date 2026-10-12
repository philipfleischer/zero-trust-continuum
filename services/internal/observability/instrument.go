package observability

import (
	"net/http"
	"strconv"
	"time"
)

// Instrument wraps handler and records the RED metrics (rate, errors,
// duration) of every request in registry:
//
//	ztc_http_requests_total{service, method, code}
//	ztc_http_request_seconds{service}
//
// The URL path is deliberately not a label, and unknown methods are recorded
// as "OTHER": label values chosen by clients would let anyone create
// unlimited time series and exhaust the service's memory (denial of service).
func Instrument(registry *Registry, service string, handler http.Handler) http.Handler {
	requestCount := registry.Counter("ztc_http_requests_total", "HTTP requests by service, method and status code.")
	latency := registry.Histogram("ztc_http_request_seconds", "HTTP request latency in seconds.", DefaultLatencyBuckets)
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		startedAt := time.Now()
		recorder := &statusRecorder{ResponseWriter: writer, status: http.StatusOK}
		handler.ServeHTTP(recorder, request)
		statusCode := strconv.Itoa(recorder.status)
		requestCount.Inc("service", service, "method", methodLabel(request.Method), "code", statusCode)
		latency.Observe(time.Since(startedAt).Seconds(), "service", service)
	})
}

// methodLabel maps the HTTP request method to a bounded set of label values.
func methodLabel(method string) string {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut,
		http.MethodPatch, http.MethodDelete, http.MethodOptions:
		return method
	}
	return "OTHER"
}

// statusRecorder remembers the status code a handler writes. A handler that
// never calls WriteHeader implicitly answers 200.
type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

// WriteHeader records the first status code and passes every call on.
func (recorder *statusRecorder) WriteHeader(statusCode int) {
	if !recorder.wroteHeader {
		recorder.status = statusCode
		recorder.wroteHeader = true
	}
	recorder.ResponseWriter.WriteHeader(statusCode)
}

// Unwrap lets http.ResponseController reach the underlying ResponseWriter,
// for example to flush or to set per-request deadlines.
func (recorder *statusRecorder) Unwrap() http.ResponseWriter { return recorder.ResponseWriter }
