package observability

import (
	"fmt"
	"io"
	"log/slog"
)

// NewLogger returns a JSON logger that writes to output and tags every record
// with the service name. levelName is "debug", "info", "warn" or "error".
// Anything else is an error rather than a silent fallback.
func NewLogger(output io.Writer, service, levelName string) (*slog.Logger, error) {
	var level slog.Level
	if err := level.UnmarshalText([]byte(levelName)); err != nil {
		return nil, fmt.Errorf("observability: log level %q: %w", levelName, err)
	}
	handler := slog.NewJSONHandler(output, &slog.HandlerOptions{Level: level})
	return slog.New(handler).With("service", service), nil
}
