// Package inventory is the asset register of the substation: the one list of
// field devices, with the SPIFFE ID, kind, zone and roles of each. IEC
// 62443-2-1 starts every ICS security programme with such an inventory.
//
// It is the single source for everything that must agree about a device:
// ztcctl turns it into the clients file of ztc-ca, which puts the zone and
// roles into each device's token, and ztc-edge starts the devices it lists.
// The format is deploy/inventory/substation.json.
package inventory

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/devices"
)

// Device is one field device in the inventory.
type Device struct {
	ID    string       `json:"id"`   // unique, also the last segment of its SPIFFE ID, such as "pmu-b1-1"
	Kind  devices.Kind `json:"kind"` // pmu, meter, breaker, rtu or evcharger
	Zone  string       `json:"zone"` // IEC 62443 zone, also the bay it reports as
	Roles []string     `json:"roles,omitempty"`
}

// Inventory lists the field devices of one substation.
type Inventory struct {
	TrustDomain string   `json:"trustDomain"` // such as "grid.example"
	Substation  string   `json:"substation"`
	Devices     []Device `json:"devices"`
}

// SubjectID returns the SPIFFE ID of the device:
// spiffe://<trust domain>/edge/<kind>/<id>. The first path segment is the
// layer, which the PEP reads from the ID.
func (inventory Inventory) SubjectID(device Device) string {
	return "spiffe://" + inventory.TrustDomain + "/edge/" + string(device.Kind) + "/" + device.ID
}

// Lookup returns the device whose SPIFFE ID is subjectID, and whether there
// is one.
func (inventory Inventory) Lookup(subjectID string) (Device, bool) {
	for _, device := range inventory.Devices {
		if inventory.SubjectID(device) == subjectID {
			device.Roles = slices.Clone(device.Roles)
			return device, true
		}
	}
	return Device{}, false
}

// Validate reports the first mistake in the inventory: an invalid trust
// domain, a missing substation, or a device with an invalid or repeated ID,
// an unknown kind or no zone.
func (inventory Inventory) Validate() error {
	if !isName(inventory.TrustDomain, ".") {
		return fmt.Errorf("inventory: trust domain %q must be lowercase letters, digits, '-' and '.'", inventory.TrustDomain)
	}
	if inventory.Substation == "" {
		return errors.New("inventory: no substation")
	}
	seen := map[string]bool{}
	for index, device := range inventory.Devices {
		if !isName(device.ID, "") {
			return fmt.Errorf("inventory: device %d: ID %q must be lowercase letters, digits and '-'", index, device.ID)
		}
		if seen[device.ID] {
			return fmt.Errorf("inventory: device %d: ID %q appears twice", index, device.ID)
		}
		seen[device.ID] = true
		parsedKind, err := devices.ParseKind(string(device.Kind))
		if err != nil || parsedKind != device.Kind {
			return fmt.Errorf("inventory: device %s: unknown kind %q", device.ID, device.Kind)
		}
		if device.Zone == "" {
			return fmt.Errorf("inventory: device %s: no zone", device.ID)
		}
	}
	return nil
}

// isName reports whether text is not empty and uses only lowercase letters,
// digits, '-' and the extra characters given. These are safe in a SPIFFE ID
// path, a metric label and a line-protocol tag without escaping.
func isName(text, extra string) bool {
	if text == "" {
		return false
	}
	for _, character := range text {
		isAllowed := character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' ||
			character == '-' || strings.ContainsRune(extra, character)
		if !isAllowed {
			return false
		}
	}
	return true
}

// Load reads exactly one JSON inventory from input and validates it. Unknown
// fields and data after the inventory are errors, so a misspelt "zoen" is
// reported instead of leaving a device without a zone.
func Load(input io.Reader) (Inventory, error) {
	decoder := json.NewDecoder(input)
	decoder.DisallowUnknownFields()
	var loaded Inventory
	if err := decoder.Decode(&loaded); err != nil {
		return Inventory{}, fmt.Errorf("inventory: decode: %w", err)
	}
	if decoder.More() {
		return Inventory{}, errors.New("inventory: unexpected data after the inventory")
	}
	if err := loaded.Validate(); err != nil {
		return Inventory{}, err
	}
	return loaded, nil
}

// LoadFile reads and validates the JSON inventory in the file at path.
func LoadFile(path string) (Inventory, error) {
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return Inventory{}, err
	}
	defer func() { _ = file.Close() }() // read-only, so a close error cannot lose data
	loaded, err := Load(file)
	if err != nil {
		return Inventory{}, fmt.Errorf("%s: %w", path, err)
	}
	return loaded, nil
}

// Marshal returns the inventory as JSON indented by two spaces with a
// trailing newline, the canonical form of the inventory files.
func Marshal(inventory Inventory) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(inventory); err != nil {
		return nil, fmt.Errorf("inventory: encode: %w", err)
	}
	return buffer.Bytes(), nil
}

// Demo returns the inventory of the demo substation: two bays, each its own
// zone, with the five kinds of device. deploy/inventory/substation.json holds
// the same inventory, and a test keeps the two equal.
func Demo() Inventory {
	sensor := []string{"sensor"}
	return Inventory{
		TrustDomain: "grid.example",
		Substation:  "s1",
		Devices: []Device{
			{ID: "pmu-b1-1", Kind: devices.PMU, Zone: "bay-1", Roles: sensor},
			{ID: "meter-b1-1", Kind: devices.Meter, Zone: "bay-1", Roles: sensor},
			{ID: "breaker-b1-1", Kind: devices.Breaker, Zone: "bay-1", Roles: sensor},
			{ID: "pmu-b2-1", Kind: devices.PMU, Zone: "bay-2", Roles: sensor},
			{ID: "rtu-b2-1", Kind: devices.RTU, Zone: "bay-2", Roles: sensor},
			{ID: "evcharger-b2-1", Kind: devices.EVCharger, Zone: "bay-2", Roles: sensor},
		},
	}
}
