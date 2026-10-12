package observability

import (
	"context"
	"log/slog"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"
)

// Check reports whether one dependency of the service is usable.
// nil means ready. It must return promptly once ctx is cancelled.
type Check func(ctx context.Context) error

// CheckTimeout bounds how long /readyz waits for all checks together.
const CheckTimeout = 2 * time.Second

// HealthMux returns a mux that serves the operational endpoints:
//
//	GET /healthz   liveness: 200 while the process can serve HTTP at all
//	GET /readyz    readiness: 200 if every check passes, else 503
//	GET /metrics   the Prometheus scrape endpoint of registry
//
// /readyz names the failing checks but not their errors, because these
// endpoints are unauthenticated. The errors go to logger instead.
func HealthMux(registry *Registry, logger *slog.Logger, checks map[string]Check) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /readyz", func(writer http.ResponseWriter, request *http.Request) {
		ctx, cancel := context.WithTimeout(request.Context(), CheckTimeout)
		defer cancel()
		var failedChecks []string
		for _, checkName := range slices.Sorted(maps.Keys(checks)) {
			check := checks[checkName]
			if err := check(ctx); err != nil {
				logger.Warn("readiness check failed", "check", checkName, "err", err)
				failedChecks = append(failedChecks, checkName)
			}
		}
		if len(failedChecks) > 0 {
			http.Error(writer, "not ready: "+strings.Join(failedChecks, ", "), http.StatusServiceUnavailable)
			return
		}
		_, _ = writer.Write([]byte("ready\n"))
	})
	mux.Handle("GET /metrics", registry.Handler())
	return mux
}
