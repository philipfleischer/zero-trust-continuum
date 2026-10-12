// Package config reads service configuration from environment variables
// (twelve-factor style), which is how Docker Compose, Kubernetes ConfigMaps
// and Helm values reach a process. Every variable is prefixed "ZTC_".
//
// A variable that is set but cannot be parsed falls back to its default and is
// recorded, so main() can refuse to start (see Env.Err) instead of silently
// running with a value the operator did not ask for.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Env reads variables that share a prefix. Create it with New or NewWithLookup.
// It is meant to be used during start-up from one goroutine.
type Env struct {
	Prefix      string
	lookup      func(name string) (value string, found bool)
	parseErrors *[]error
}

// New returns an Env that reads the process environment with the "ZTC_" prefix.
func New() Env { return NewWithLookup(os.LookupEnv) }

// NewWithLookup returns an Env with the "ZTC_" prefix that reads variables
// through lookup instead of the process environment, so tests can inject values.
func NewWithLookup(lookup func(name string) (value string, found bool)) Env {
	return Env{Prefix: "ZTC_", lookup: lookup, parseErrors: new([]error)}
}

// variableName returns the full variable name: "listen" becomes "ZTC_LISTEN".
func (environment Env) variableName(key string) string {
	return environment.Prefix + strings.ToUpper(key)
}

// Err returns every parse error seen so far joined into one error, or nil.
func (environment Env) Err() error { return errors.Join(*environment.parseErrors...) }

// String returns the variable, or defaultValue if it is unset or empty.
func (environment Env) String(key, defaultValue string) string {
	value, found := environment.lookup(environment.variableName(key))
	if !found || value == "" {
		return defaultValue
	}
	return value
}

// Int returns the variable parsed as an int, or defaultValue if it is unset, empty or invalid.
func (environment Env) Int(key string, defaultValue int) int {
	return parse(environment, key, defaultValue, strconv.Atoi)
}

// Float returns the variable parsed as a float64, or defaultValue if it is unset, empty or invalid.
func (environment Env) Float(key string, defaultValue float64) float64 {
	parseFloat := func(text string) (float64, error) { return strconv.ParseFloat(text, 64) }
	return parse(environment, key, defaultValue, parseFloat)
}

// Bool returns the variable parsed by strconv.ParseBool
// ("true", "1", "false", "0", ...), or defaultValue if it is unset, empty or invalid.
func (environment Env) Bool(key string, defaultValue bool) bool {
	return parse(environment, key, defaultValue, strconv.ParseBool)
}

// Duration returns the variable parsed by time.ParseDuration ("250ms", "5s", "1m"),
// or defaultValue if it is unset, empty or invalid. A number without a unit is invalid.
func (environment Env) Duration(key string, defaultValue time.Duration) time.Duration {
	return parse(environment, key, defaultValue, time.ParseDuration)
}

// List returns a comma-separated variable as a slice with surrounding spaces
// trimmed and empty items dropped, or defaultValue if it is unset or empty.
func (environment Env) List(key string, defaultValue []string) []string {
	value, found := environment.lookup(environment.variableName(key))
	if !found || value == "" {
		return defaultValue
	}

	var items []string
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			items = append(items, item)
		}
	}
	return items
}

// parse is shared by the typed getters. An unset or empty variable returns
// defaultValue; a value that convert rejects is recorded in environment and
// also returns defaultValue.
func parse[Value any](environment Env, key string, defaultValue Value, convert func(string) (Value, error)) Value {
	name := environment.variableName(key)
	text, found := environment.lookup(name)
	if !found || text == "" {
		return defaultValue
	}
	value, err := convert(text)
	if err != nil {
		*environment.parseErrors = append(*environment.parseErrors, fmt.Errorf("config: %s: %w", name, err))
		return defaultValue
	}
	return value
}
