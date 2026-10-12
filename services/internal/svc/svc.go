// Package svc is the start-up scaffolding shared by every ZTC service: it
// reads the configuration, creates the logger and the metrics registry, and
// serves the application next to the operational endpoints /healthz, /readyz
// and /metrics until the service is told to stop.
package svc

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/config"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/httpx"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/observability"
)

// Service holds what every service's main function needs.
type Service struct {
	Name        string
	Environment config.Env
	Logger      *slog.Logger
	Metrics     *observability.Registry
}

// New creates a Service called name that reads its configuration from
// environment and writes JSON logs to logOutput. ZTC_LOG_LEVEL sets the log
// level (default info); an unknown level is an error.
func New(name string, environment config.Env, logOutput io.Writer) (*Service, error) {
	logLevel := environment.String("log_level", "info")
	logger, err := observability.NewLogger(logOutput, name, logLevel)
	if err != nil {
		return nil, err
	}
	return &Service{Name: name, Environment: environment, Logger: logger, Metrics: observability.NewRegistry()}, nil
}

// Handler returns the complete HTTP handler of the service: the operational
// endpoints, and app instrumented with request metrics for every other path.
// checks are the readiness checks behind /readyz.
func (service *Service) Handler(app http.Handler, checks map[string]observability.Check) http.Handler {
	mux := observability.HealthMux(service.Metrics, service.Logger, checks)
	mux.Handle("/", observability.Instrument(service.Metrics, service.Name, app))
	return mux
}

// Serve listens on ZTC_LISTEN (default defaultAddress) and serves
// Handler(app, checks) until ctx is cancelled, then shuts down gracefully. It
// refuses to start if any configuration value read so far was invalid, so
// every service fails fast on a typo in its environment.
func (service *Service) Serve(ctx context.Context, defaultAddress string, app http.Handler, checks map[string]observability.Check) error {
	address := service.Environment.String("listen", defaultAddress)
	if err := service.Environment.Err(); err != nil {
		return fmt.Errorf("svc: invalid configuration: %w", err)
	}
	server := httpx.NewServer(address, service.Handler(app, checks))
	service.Logger.Info("listening", "addr", address)
	err := httpx.Run(ctx, server)
	service.Logger.Info("stopped", "err", err)
	return err
}
