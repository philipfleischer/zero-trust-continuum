package config

import (
	"slices"
	"strings"
	"testing"
	"time"
)

// fakeEnvironment returns an Env that reads from variables instead of the
// process environment.
func fakeEnvironment(variables map[string]string) Env {
	return NewWithLookup(func(name string) (string, bool) {
		value, found := variables[name]
		return value, found
	})
}

func TestString(t *testing.T) {
	environment := fakeEnvironment(map[string]string{"ZTC_LISTEN": ":8181", "ZTC_EMPTY": ""})
	tests := []struct{ key, defaultValue, want string }{
		{"listen", ":9999", ":8181"},
		{"LISTEN", ":9999", ":8181"},
		{"missing", ":9999", ":9999"},
		{"empty", "fallback", "fallback"},
	}
	for _, testCase := range tests {
		if got := environment.String(testCase.key, testCase.defaultValue); got != testCase.want {
			t.Errorf("String(%q, %q) = %q, want %q", testCase.key, testCase.defaultValue, got, testCase.want)
		}
	}
}

func TestTypedValues(t *testing.T) {
	environment := fakeEnvironment(map[string]string{
		"ZTC_PORT":    "8181",
		"ZTC_ALPHA":   "0.5",
		"ZTC_TLS":     "true",
		"ZTC_TIMEOUT": "250ms",
	})
	if got := environment.Int("port", 0); got != 8181 {
		t.Errorf("Int(port) = %d, want 8181", got)
	}
	if got := environment.Float("alpha", 0); got != 0.5 {
		t.Errorf("Float(alpha) = %v, want 0.5", got)
	}
	if got := environment.Bool("tls", false); !got {
		t.Errorf("Bool(tls) = false, want true")
	}
	if got := environment.Duration("timeout", time.Second); got != 250*time.Millisecond {
		t.Errorf("Duration(timeout) = %v, want 250ms", got)
	}
	if got := environment.Int("missing", 7); got != 7 {
		t.Errorf("Int(missing) = %d, want default 7", got)
	}
	if err := environment.Err(); err != nil {
		t.Errorf("Err() = %v, want nil", err)
	}
}

func TestInvalidValuesFallBackAndAreReported(t *testing.T) {
	environment := fakeEnvironment(map[string]string{
		"ZTC_PORT":    "eighty",
		"ZTC_TLS":     "ture",
		"ZTC_TIMEOUT": "5",
	})
	if got := environment.Int("port", 8181); got != 8181 {
		t.Errorf("Int(port) = %d, want default 8181", got)
	}
	if got := environment.Bool("tls", false); got {
		t.Errorf("Bool(tls) = true, want default false")
	}
	if got := environment.Duration("timeout", time.Second); got != time.Second {
		t.Errorf("Duration(timeout) = %v, want default 1s", got)
	}
	err := environment.Err()
	if err == nil {
		t.Fatal("Err() = nil, want an error naming the three invalid variables")
	}
	for _, name := range []string{"ZTC_PORT", "ZTC_TLS", "ZTC_TIMEOUT"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("Err() = %q, want it to mention %s", err, name)
		}
	}
}

func TestList(t *testing.T) {
	environment := fakeEnvironment(map[string]string{"ZTC_PEERS": " a, ,b ,c", "ZTC_NONE": ""})
	tests := []struct {
		key                string
		defaultValue, want []string
	}{
		{"peers", nil, []string{"a", "b", "c"}},
		{"none", []string{"x"}, []string{"x"}},
		{"missing", []string{"x"}, []string{"x"}},
	}
	for _, testCase := range tests {
		if got := environment.List(testCase.key, testCase.defaultValue); !slices.Equal(got, testCase.want) {
			t.Errorf("List(%q) = %q, want %q", testCase.key, got, testCase.want)
		}
	}
}
