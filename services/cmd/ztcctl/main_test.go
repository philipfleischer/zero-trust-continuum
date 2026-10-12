package main

import (
	"bytes"
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/config"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/observability"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/pdp"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/policy"
)

// environmentFrom returns a config.Env that reads from variables instead of
// the process environment.
func environmentFrom(variables map[string]string) config.Env {
	return config.NewWithLookup(func(name string) (string, bool) {
		value, found := variables[name]
		return value, found
	})
}

// ztcctl runs one command and returns its exit status, stdout and stderr.
func ztcctl(t *testing.T, variables map[string]string, arguments ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), arguments, environmentFrom(variables), &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestPolicyDefault(t *testing.T) {
	code, stdout, _ := ztcctl(t, nil, "policy", "default")
	want, err := policy.Marshal(policy.DefaultSubstationPolicy())
	if code != exitOK || err != nil || stdout != string(want) {
		t.Errorf("policy default: exit %d, output differs from policy.Marshal: %v", code, err)
	}
}

func TestPolicyValidate(t *testing.T) {
	directory := t.TempDir()
	goodPolicyFile, badPolicyFile := filepath.Join(directory, "good.json"), filepath.Join(directory, "bad.json")
	for path, body := range map[string]string{
		goodPolicyFile: `{"version":4,"rules":[{"id":"a","effect":"allow"}]}`,
		badPolicyFile:  `{"version":4,"rules":[{"id":"a","effect":"allow","sujbects":["x"]}]}`,
	} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if code, stdout, _ := ztcctl(t, nil, "policy", "validate", goodPolicyFile); code != exitOK || !strings.Contains(stdout, "version 4 with 1 rules") {
		t.Errorf("validate good: exit %d, %q", code, stdout)
	}
	if code, _, stderr := ztcctl(t, nil, "policy", "validate", badPolicyFile); code != exitError || !strings.Contains(stderr, "sujbects") {
		t.Errorf("validate bad: exit %d, %q", code, stderr)
	}
}

// TestDecideAndSignal runs ztcctl against a real PDP over HTTP.
func TestDecideAndSignal(t *testing.T) {
	decisionPoint := pdp.New("cloud-pdp", policy.NewEngine(policy.DefaultSubstationPolicy()))
	server := httptest.NewServer(pdp.NewHandler(decisionPoint, "secret", observability.NewRegistry()))
	defer server.Close()
	variables := map[string]string{"ZTC_PDP_URL": server.URL, "ZTC_PDP_TOKEN": "secret"}
	pmu := "spiffe://grid.example/edge/pmu/1"
	writeTelemetryTo := func(resourceZone string) []string {
		return []string{"decide", "-subject", pmu, "-action", "write", "-resource", resourceZone + "/telemetry/pmu-1",
			"-type", "telemetry", "-zone", "bay-1", "-resource-zone", resourceZone}
	}

	if code, stdout, _ := ztcctl(t, variables, writeTelemetryTo("bay-1")...); code != exitDeny || !strings.HasPrefix(stdout, "deny: denied by rule deny-untrusted") {
		t.Errorf("unknown PMU: exit %d, %q", code, stdout)
	}
	signals := []struct{ kind, value string }{{"authentication", "0.8"}, {"posture", "1"}}
	for _, signal := range signals {
		code, _, stderr := ztcctl(t, variables, "signal", "-subject", pmu, "-kind", signal.kind, "-value", signal.value)
		if code != exitOK {
			t.Fatalf("signal %s: exit %d, %s", signal.kind, code, stderr)
		}
	}
	if code, stdout, _ := ztcctl(t, variables, writeTelemetryTo("bay-1")...); code != exitOK || !strings.HasPrefix(stdout, "allow: allowed by rule edge-write-telemetry") {
		t.Errorf("own bay: exit %d, %q", code, stdout)
	}
	if code, stdout, _ := ztcctl(t, variables, writeTelemetryTo("bay-2")...); code != exitDeny || !strings.Contains(stdout, "default deny") {
		t.Errorf("other bay: exit %d, %q", code, stdout)
	}
}

func TestErrors(t *testing.T) {
	unreachable := map[string]string{"ZTC_PDP_URL": "http://127.0.0.1:1", "ZTC_PDP_TOKEN": "x"}
	decideArguments := []string{"decide", "-subject", "spiffe://grid.example/edge/pmu/1", "-resource", "r", "-type", "telemetry"}
	tests := []struct {
		name      string
		variables map[string]string
		arguments []string
		want      int
	}{
		{"no command", nil, nil, exitUsage},
		{"unknown command", nil, []string{"reboot"}, exitUsage},
		{"help", nil, []string{"decide", "-h"}, exitOK},
		{"unknown flag", nil, []string{"decide", "-subjct", "x"}, exitUsage},
		{"missing flags", nil, []string{"decide", "-subject", "spiffe://grid.example/edge/pmu/1"}, exitUsage},
		{"not a SPIFFE ID", nil, []string{"decide", "-subject", "pmu-1", "-resource", "r", "-type", "t"}, exitUsage},
		{"unknown layer", nil, []string{"decide", "-subject", "spiffe://grid.example/moon/pmu/1", "-resource", "r", "-type", "t"}, exitUsage},
		{"PDP unreachable", unreachable, decideArguments, exitError},
		{"signal without token", nil, []string{"signal", "-subject", "s", "-kind", "posture"}, exitError},
		{"signal with unknown kind", unreachable, []string{"signal", "-subject", "s", "-kind", "reset"}, exitUsage},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			if code, _, stderr := ztcctl(t, testCase.variables, testCase.arguments...); code != testCase.want {
				t.Errorf("exit %d, want %d; stderr:\n%s", code, testCase.want, stderr)
			}
		})
	}
}
