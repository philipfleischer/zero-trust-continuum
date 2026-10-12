// Tests for JSON loading, the canonical encoding and the policy file in
// deploy/policies that must always equal DefaultSubstationPolicy.

package policy

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// update rewrites the canonical policy file instead of comparing with it:
// go test ./internal/policy -run TestDefaultPolicyMatchesJSON -update
var update = flag.Bool("update", false, "rewrite deploy/policies/substation.json from DefaultSubstationPolicy")

// substationJSON is the canonical policy file, relative to this package.
const substationJSON = "../../../deploy/policies/substation.json"

func TestLoad(t *testing.T) {
	input := `{"version": 3, "rules": [{"id": "a", "effect": "allow", "actions": ["read"]}]}`
	loaded, err := Load(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if loaded.Version != 3 || len(loaded.Rules) != 1 || loaded.Rules[0].ID != "a" {
		t.Errorf("Load() = %+v", loaded)
	}
}

func TestLoadRejects(t *testing.T) {
	tests := []struct {
		name, input, wantError string
	}{
		{"misspelt field", `{"version": 1, "rules": [{"id": "a", "effect": "allow", "sujbects": ["x"]}]}`, "unknown field"},
		{"not JSON", `version: 1`, "decode"},
		{"empty input", ``, "decode"},
		{"wrong type", `{"version": "one"}`, "decode"},
		{"two policies", `{"version": 1} {"version": 2}`, "after the policy"},
		{"invalid policy", `{"version": 1, "rules": [{"id": "a", "effect": "maybe"}]}`, "unknown effect"},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := Load(strings.NewReader(testCase.input))
			if err == nil || !strings.Contains(err.Error(), testCase.wantError) {
				t.Fatalf("Load() = %v, want error containing %q", err, testCase.wantError)
			}
		})
	}
}

func TestLoadFileMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.json")
	if _, err := LoadFile(path); err == nil {
		t.Fatal("LoadFile() of a missing file = nil, want error")
	}
}

func TestLoadFileNamesThePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte(`{"rules": [{"id": ""}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadFile(path)
	if err == nil || !strings.Contains(err.Error(), path) {
		t.Fatalf("LoadFile() = %v, want error naming %s", err, path)
	}
}

func TestMarshalRoundTrip(t *testing.T) {
	want := DefaultSubstationPolicy()
	data, err := Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(data, []byte("}\n")) {
		t.Error("Marshal() output does not end with a newline")
	}
	got, err := Load(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("Load(Marshal()) = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("round trip changed the policy:\n got %+v\nwant %+v", got, want)
	}
}

// TestDefaultPolicyMatchesJSON keeps deploy/policies/substation.json and
// DefaultSubstationPolicy byte for byte equal, so neither can change alone.
func TestDefaultPolicyMatchesJSON(t *testing.T) {
	want, err := Marshal(DefaultSubstationPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if *update {
		// 0o644, not 0o600: a repository file that container images must be able to read.
		if err := os.WriteFile(substationJSON, want, 0o644); err != nil { //nolint:gosec // G306, see above
			t.Fatal(err)
		}
		t.Logf("wrote %s", substationJSON)
	}
	got, err := os.ReadFile(substationJSON)
	if err != nil {
		t.Fatalf("%v (create it with: go test ./internal/policy -run TestDefaultPolicyMatchesJSON -update)", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s differs from DefaultSubstationPolicy(); if the Go policy is right, regenerate the file with -update", substationJSON)
	}
	if _, err := LoadFile(substationJSON); err != nil {
		t.Fatalf("the canonical file does not load: %v", err)
	}
}
