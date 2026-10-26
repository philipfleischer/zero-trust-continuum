// Tests for the inventory: SPIFFE IDs, lookup, validation, strict JSON
// loading, and the demo inventory that must equal its JSON file.

package inventory

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/devices"
)

// update rewrites the canonical inventory file instead of comparing with it:
// go test ./internal/inventory -run TestDemoMatchesJSON -update
var update = flag.Bool("update", false, "rewrite deploy/inventory/substation.json from Demo")

// substationJSON is the canonical inventory file, relative to this package.
const substationJSON = "../../../deploy/inventory/substation.json"

func TestSubjectID(t *testing.T) {
	inventory := Demo()
	got := inventory.SubjectID(inventory.Devices[0])
	if want := "spiffe://grid.example/edge/pmu/pmu-b1-1"; got != want {
		t.Errorf("SubjectID() = %q, want %q", got, want)
	}
}

func TestLookup(t *testing.T) {
	inventory := Demo()
	device, found := inventory.Lookup("spiffe://grid.example/edge/rtu/rtu-b2-1")
	if !found || device.ID != "rtu-b2-1" || device.Zone != "bay-2" || device.Kind != devices.RTU {
		t.Errorf("Lookup(rtu-b2-1) = %+v, %v", device, found)
	}

	for _, unknown := range []string{
		"spiffe://grid.example/edge/pmu/pmu-b9-9",   // not in the inventory
		"spiffe://grid.example/edge/meter/pmu-b1-1", // right ID, wrong kind
		"spiffe://other.example/edge/pmu/pmu-b1-1",  // another trust domain
		"spiffe://grid.example/edge/pmu/pmu-b1-1/x", // longer path
		"",
	} {
		if device, found := inventory.Lookup(unknown); found {
			t.Errorf("Lookup(%q) found %+v", unknown, device)
		}
	}
}

func TestLookupReturnsACopy(t *testing.T) {
	inventory := Demo()
	device, _ := inventory.Lookup(inventory.SubjectID(inventory.Devices[0]))
	device.Roles[0] = "operator"
	if inventory.Devices[0].Roles[0] != "sensor" {
		t.Error("changing the roles of a looked-up device changed the inventory")
	}
}

func TestValidateRejects(t *testing.T) {
	tests := []struct {
		name   string
		change func(*Inventory)
	}{
		{"empty trust domain", func(inventory *Inventory) { inventory.TrustDomain = "" }},
		{"trust domain with a slash", func(inventory *Inventory) { inventory.TrustDomain = "grid.example/edge" }},
		{"trust domain in upper case", func(inventory *Inventory) { inventory.TrustDomain = "Grid.example" }},
		{"no substation", func(inventory *Inventory) { inventory.Substation = "" }},
		{"empty device ID", func(inventory *Inventory) { inventory.Devices[0].ID = "" }},
		{"device ID with a slash", func(inventory *Inventory) { inventory.Devices[0].ID = "pmu/1" }},
		{"device ID with a space", func(inventory *Inventory) { inventory.Devices[0].ID = "pmu 1" }},
		{"device ID with a dot", func(inventory *Inventory) { inventory.Devices[0].ID = "pmu.1" }},
		{"same ID twice", func(inventory *Inventory) { inventory.Devices[1].ID = inventory.Devices[0].ID }},
		{"unknown kind", func(inventory *Inventory) { inventory.Devices[0].Kind = "toaster" }},
		{"kind in upper case", func(inventory *Inventory) { inventory.Devices[0].Kind = "PMU" }},
		{"no zone", func(inventory *Inventory) { inventory.Devices[0].Zone = "" }},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			inventory := Demo()
			testCase.change(&inventory)
			if err := inventory.Validate(); err == nil {
				t.Error("Validate() accepted the inventory")
			}
		})
	}
}

func TestDemoIsValid(t *testing.T) {
	if err := Demo().Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestDemoHasEveryKind(t *testing.T) {
	kinds := map[devices.Kind]bool{}
	for _, device := range Demo().Devices {
		kinds[device.Kind] = true
		if _, err := devices.New(device.ID, device.Kind, "s1", device.Zone, 1); err != nil {
			t.Errorf("device %s cannot be simulated: %v", device.ID, err)
		}
	}
	if len(kinds) != 5 {
		t.Errorf("the demo has %d kinds of device, want all 5", len(kinds))
	}
}

func TestLoad(t *testing.T) {
	input := `{"trustDomain": "grid.example", "substation": "s1",
		"devices": [{"id": "pmu-1", "kind": "pmu", "zone": "bay-1", "roles": ["sensor"]}]}`
	loaded, err := Load(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if len(loaded.Devices) != 1 || loaded.SubjectID(loaded.Devices[0]) != "spiffe://grid.example/edge/pmu/pmu-1" {
		t.Errorf("Load() = %+v", loaded)
	}
}

func TestLoadRejects(t *testing.T) {
	tests := []struct {
		name, input, wantError string
	}{
		{"misspelt field", `{"trustDomain": "grid.example", "substation": "s1", "devices": [{"id": "p", "kind": "pmu", "zoen": "bay-1"}]}`, "unknown field"},
		{"not JSON", `trustDomain: grid.example`, "decode"},
		{"empty input", ``, "decode"},
		{"two inventories", `{"trustDomain": "a", "substation": "s"} {}`, "unexpected data"},
		{"invalid device", `{"trustDomain": "grid.example", "substation": "s1", "devices": [{"id": "p", "kind": "toaster", "zone": "bay-1"}]}`, "unknown kind"},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := Load(strings.NewReader(testCase.input))
			if err == nil || !strings.Contains(err.Error(), testCase.wantError) {
				t.Errorf("Load() error = %v, want one containing %q", err, testCase.wantError)
			}
		})
	}
}

func TestLoadFile(t *testing.T) {
	directory := t.TempDir()
	data, err := Marshal(Demo())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "inventory.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadFile(path)
	if err != nil || len(loaded.Devices) != len(Demo().Devices) {
		t.Errorf("LoadFile() = %+v, %v", loaded, err)
	}

	if _, err := LoadFile(filepath.Join(directory, "missing.json")); err == nil {
		t.Error("LoadFile of a missing file succeeded")
	}
	broken := filepath.Join(directory, "broken.json")
	if err := os.WriteFile(broken, []byte(`{"trustDomain": ""}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(broken); err == nil || !strings.Contains(err.Error(), "broken.json") {
		t.Errorf("LoadFile(broken) error = %v, want one that names the file", err)
	}
}

// TestDemoMatchesJSON keeps deploy/inventory/substation.json and Demo byte for
// byte equal, so neither can change alone.
func TestDemoMatchesJSON(t *testing.T) {
	want, err := Marshal(Demo())
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
		t.Fatalf("%v (create it with: go test ./internal/inventory -run TestDemoMatchesJSON -update)", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s differs from Demo(); regenerate it with -update", substationJSON)
	}
	if _, err := Load(bytes.NewReader(got)); err != nil {
		t.Errorf("%s does not load: %v", substationJSON, err)
	}
}
