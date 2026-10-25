// Command ztc-ingest is the cloud end of the telemetry pipeline: fog nodes
// write their aggregates to it as line protocol, and dashboards and the
// analytics read them back as JSON or CSV.
//
// API:
//
//	POST /v1/write    line protocol, one point per line
//	                  → {"stored": n, "rejected": n}
//	GET  /v1/series   → the keys of all stored series
//	GET  /v1/query?measurement=<name>&from=<RFC 3339>&to=<RFC 3339>[&format=csv]
//	                  → the points of the measurement in [from, to), as JSON
//	                    or as CSV with the columns time, series, field, value
//
// Environment:
//
//	ZTC_LISTEN               address to listen on (default :8086)
//	ZTC_LOG_LEVEL            debug, info, warn or error (default info)
//	ZTC_INGEST_CAPACITY      points kept per series (default 3600, one hour
//	                         of one aggregate per second)
//	ZTC_INGEST_MAX_SERIES    series kept at most (default 10000)
//	ZTC_INGEST_MAX_SKEW      how far a point's time may be from the clock of
//	                         this service (default 10s)
package main

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"syscall"
	"time"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/config"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/httpx"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/observability"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/svc"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/telemetry"
)

func main() {
	// Cancel the context on Ctrl+C (SIGINT) or when Docker or Kubernetes
	// stops the container (SIGTERM), so the server shuts down gracefully.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := run(ctx, config.New(), os.Stdout)
	stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, "ztc-ingest:", err)
		os.Exit(1)
	}
}

// run starts the ingest service and blocks until ctx is cancelled or the
// server fails. It takes its dependencies as parameters so tests can call it
// directly.
func run(ctx context.Context, environment config.Env, logOutput io.Writer) error {
	service, err := svc.New("ztc-ingest", environment, logOutput)
	if err != nil {
		return err
	}
	app, err := setup(environment, service)
	if err != nil {
		return err
	}
	return service.Serve(ctx, ":8086", app, nil)
}

// setup creates the store from the configuration and returns the HTTP API.
func setup(environment config.Env, service *svc.Service) (http.Handler, error) {
	capacity := environment.Int("ingest_capacity", 3600)
	maxSeries := environment.Int("ingest_max_series", 10000)
	maxSkew := environment.Duration("ingest_max_skew", 10*time.Second)
	if maxSkew <= 0 {
		return nil, fmt.Errorf("ZTC_INGEST_MAX_SKEW is %v, want above 0", maxSkew)
	}
	store, err := telemetry.NewStore(capacity, maxSeries)
	if err != nil {
		return nil, fmt.Errorf("ZTC_INGEST_CAPACITY is %d and ZTC_INGEST_MAX_SERIES is %d: %w", capacity, maxSeries, err)
	}
	ingest := &ingester{
		store:    store,
		pipeline: telemetry.Pipeline{Stages: []telemetry.Stage{telemetry.Validate(maxSkew, nil)}},
		points:   service.Metrics.Counter("ztc_ingest_points_total", "Points written to the ingest service, by result."),
		logger:   service.Logger,
	}
	service.Logger.Info("store ready", "capacity", capacity, "maxSeries", maxSeries, "maxSkew", maxSkew.String())

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/write", ingest.write)
	mux.HandleFunc("GET /v1/series", ingest.series)
	mux.HandleFunc("GET /v1/query", ingest.query)
	return mux, nil
}

// ingester holds what the endpoints share.
type ingester struct {
	store    *telemetry.Store
	pipeline telemetry.Pipeline
	points   *observability.Counter
	logger   *slog.Logger
}

// writeResult is the body of a successful POST /v1/write.
type writeResult struct {
	Stored   int `json:"stored"`
	Rejected int `json:"rejected"`
}

// write answers POST /v1/write. It stores every line that parses, passes
// Validate and fits in the store, and reports how many it stored and
// rejected, so one bad line does not cost the fog node the whole batch.
func (ingest *ingester) write(writer http.ResponseWriter, request *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(writer, request.Body, httpx.MaxBody))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			httpx.Error(writer, http.StatusRequestEntityTooLarge, fmt.Sprintf("body larger than %d bytes", tooLarge.Limit))
			return
		}
		httpx.Error(writer, http.StatusBadRequest, "could not read the body")
		return
	}

	points, unparsable := telemetry.ParseLines(string(body))
	result := writeResult{Rejected: unparsable}
	ingest.points.Add(float64(unparsable), "result", "unparsable")
	for _, point := range points {
		validated, isValid := ingest.pipeline.Apply(point)
		if !isValid {
			result.Rejected++
			ingest.points.Inc("result", "invalid")
			continue
		}
		if err := ingest.store.Append(validated); err != nil {
			result.Rejected++
			ingest.points.Inc("result", "store_full")
			continue
		}
		result.Stored++
		ingest.points.Inc("result", "stored")
	}
	if result.Rejected > 0 {
		ingest.logger.Warn("rejected points", "stored", result.Stored, "rejected", result.Rejected)
	}
	httpx.WriteJSON(writer, http.StatusOK, result)
}

// series answers GET /v1/series with the keys of all stored series.
func (ingest *ingester) series(writer http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(writer, http.StatusOK, ingest.store.Series())
}

// query answers GET /v1/query. A missing measurement, a time that is not
// RFC 3339 or an unknown format is a 400, not an empty or unbounded answer,
// so a typo in a dashboard shows up as an error.
func (ingest *ingester) query(writer http.ResponseWriter, request *http.Request) {
	parameters := request.URL.Query()
	measurement := parameters.Get("measurement")
	if measurement == "" {
		httpx.Error(writer, http.StatusBadRequest, "the measurement parameter is required")
		return
	}
	from, err := timeParameter(parameters, "from")
	if err != nil {
		httpx.Error(writer, http.StatusBadRequest, err.Error())
		return
	}
	to, err := timeParameter(parameters, "to")
	if err != nil {
		httpx.Error(writer, http.StatusBadRequest, err.Error())
		return
	}

	switch parameters.Get("format") {
	case "", "json":
		points := ingest.store.Query(measurement, from, to)
		if points == nil {
			points = []telemetry.Point{} // [] instead of null for an empty result
		}
		httpx.WriteJSON(writer, http.StatusOK, points)
	case "csv":
		ingest.writeCSV(writer, ingest.store.Query(measurement, from, to))
	default:
		httpx.Error(writer, http.StatusBadRequest, "format must be json or csv")
	}
}

// writeCSV writes one row per field of every point: time, series, field,
// value. This long format reads straight into pandas or a spreadsheet.
func (ingest *ingester) writeCSV(writer http.ResponseWriter, points []telemetry.Point) {
	writer.Header().Set("Content-Type", "text/csv; charset=utf-8")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	rows := csv.NewWriter(writer)
	_ = rows.Write([]string{"time", "series", "field", "value"})
	for _, point := range points {
		timestamp := point.Time.UTC().Format(time.RFC3339Nano)
		series := point.Key()
		for _, field := range slices.Sorted(maps.Keys(point.Fields)) {
			value := strconv.FormatFloat(point.Fields[field], 'g', -1, 64)
			_ = rows.Write([]string{timestamp, series, field, value})
		}
	}
	rows.Flush()
	// The status is already sent, so a failed write, such as a client that
	// hung up, can only be logged.
	if err := rows.Error(); err != nil {
		ingest.logger.Warn("could not write CSV", "err", err)
	}
}

// timeParameter reads an RFC 3339 time from the query parameter name. A
// missing parameter gives the zero time, which leaves that end of the range
// open.
func timeParameter(parameters url.Values, name string) (time.Time, error) {
	text := parameters.Get(name)
	if text == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339, text)
	if err != nil {
		return time.Time{}, fmt.Errorf("%s must be an RFC 3339 time such as 2026-10-25T12:00:00Z", name)
	}
	return parsed, nil
}
