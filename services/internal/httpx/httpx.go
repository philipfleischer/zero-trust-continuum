// Package httpx holds small HTTP helpers shared by all ZTC services:
// JSON responses, strict JSON request decoding with a size limit,
// and an http.Server with defensive timeouts and graceful shutdown.
package httpx

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

// MaxBody is the largest request body ReadJSON accepts (1 MiB). It protects
// services from memory exhaustion by oversized requests.
const MaxBody = 1 << 20

// WriteJSON writes body as JSON with the given status code. nosniff stops
// browsers from guessing a different content type for the response.
func WriteJSON(writer http.ResponseWriter, status int, body any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(body)
}

// Error writes {"error": message} with the given status code.
func Error(writer http.ResponseWriter, status int, message string) {
	WriteJSON(writer, status, map[string]string{"error": message})
}

// ReadJSON decodes the request body into destination. It rejects unknown
// fields, trailing data after the JSON value, and bodies larger than MaxBody;
// for an oversized body the error is an *http.MaxBytesError, which callers
// can map to 413 Request Entity Too Large.
func ReadJSON(writer http.ResponseWriter, request *http.Request, destination any) error {
	limitedBody := http.MaxBytesReader(writer, request.Body, MaxBody)
	decoder := json.NewDecoder(limitedBody)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if decoder.More() {
		return errors.New("httpx: trailing data after JSON body")
	}
	return nil
}

// NewServer returns an http.Server for address with timeouts that stop slow
// clients (slowloris) from holding connections open forever.
func NewServer(address string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              address,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}
}

// ShutdownTimeout is how long Run waits for in-flight requests to finish.
const ShutdownTimeout = 10 * time.Second

// Run serves server (over TLS if server.TLSConfig is set) until ctx is
// cancelled, then shuts it down gracefully: no new connections are accepted
// and in-flight requests get ShutdownTimeout to finish. It returns early with
// an error if the server cannot start, for example because the port is in use.
func Run(ctx context.Context, server *http.Server) error {
	startupFailed := make(chan error, 1)
	go func() {
		var err error
		if server.TLSConfig != nil {
			err = server.ListenAndServeTLS("", "")
		} else {
			err = server.ListenAndServe()
		}
		if !errors.Is(err, http.ErrServerClosed) {
			startupFailed <- err
		}
		close(startupFailed)
	}()

	select {
	case err := <-startupFailed:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), ShutdownTimeout)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	}
}
