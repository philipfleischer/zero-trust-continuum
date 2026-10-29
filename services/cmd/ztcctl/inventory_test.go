// Tests for ztcctl inventory: the master secret, and a clients file that
// matches the inventory and the derived device secrets.

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/inventory"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/token"
)

// inventoryFiles writes the demo inventory and a new master secret to a new
// directory and returns their paths.
func inventoryFiles(t *testing.T) (inventoryPath, masterSecretPath string) {
	t.Helper()
	directory := t.TempDir()
	inventoryPath = filepath.Join(directory, "inventory.json")
	data, err := inventory.Marshal(inventory.Demo())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inventoryPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	masterSecretPath = filepath.Join(directory, "master.secret")
	if code, _, stderr := ztcctl(t, nil, "inventory", "secret", "-out", masterSecretPath); code != exitOK {
		t.Fatalf("inventory secret: exit %d, %s", code, stderr)
	}
	return inventoryPath, masterSecretPath
}

func TestInventorySecret(t *testing.T) {
	_, masterSecretPath := inventoryFiles(t)
	masterSecret, err := token.ReadSecretFile(masterSecretPath)
	if err != nil {
		t.Fatalf("the master secret file cannot be read as a secret: %v", err)
	}
	if len(masterSecret) != inventory.MinMasterSecretSize {
		t.Errorf("master secret has %d bytes, want %d", len(masterSecret), inventory.MinMasterSecretSize)
	}

	code, _, stderr := ztcctl(t, nil, "inventory", "secret", "-out", masterSecretPath)
	if code != exitError || !strings.Contains(stderr, "exists") {
		t.Errorf("inventory secret over an existing file: exit %d, %q", code, stderr)
	}
}

func TestInventoryClients(t *testing.T) {
	inventoryPath, masterSecretPath := inventoryFiles(t)
	code, stdout, stderr := ztcctl(t, nil, "inventory", "clients", "-inventory", inventoryPath, "-master-secret", masterSecretPath)
	if code != exitOK {
		t.Fatalf("inventory clients: exit %d, %s", code, stderr)
	}
	var file caClientsFile
	decoder := json.NewDecoder(strings.NewReader(stdout))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&file); err != nil {
		t.Fatal(err)
	}

	demo := inventory.Demo()
	if len(file.Clients) != len(demo.Devices) {
		t.Fatalf("got %d clients, want one per device (%d)", len(file.Clients), len(demo.Devices))
	}
	masterSecret, err := token.ReadSecretFile(masterSecretPath)
	if err != nil {
		t.Fatal(err)
	}
	for i, device := range demo.Devices {
		client := file.Clients[i]
		subjectID := demo.SubjectID(device)
		secret, err := inventory.DeviceSecret(masterSecret, subjectID)
		if err != nil {
			t.Fatal(err)
		}
		secretHash := sha256.Sum256([]byte(secret))
		if client.SecretSHA256 != hex.EncodeToString(secretHash[:]) {
			t.Errorf("%s: secretSHA256 is not the hash of the derived secret", device.ID)
		}
		if client.Subject != subjectID || client.Zone != device.Zone || !slices.Equal(client.Roles, device.Roles) {
			t.Errorf("%s: client %+v does not match the inventory", device.ID, client)
		}
		if !slices.Equal(client.Audience, []string{"ztc-pep"}) || !slices.Equal(client.Scope, []string{"telemetry:write"}) {
			t.Errorf("%s: audience %v and scope %v, want the defaults", device.ID, client.Audience, client.Scope)
		}
	}
	if strings.Contains(stdout, mustDeviceSecret(t, masterSecret, demo.SubjectID(demo.Devices[0]))) {
		t.Error("the clients file contains a device secret, not only its hash")
	}
	if !strings.Contains(stderr, "6 clients") {
		t.Errorf("stderr = %q, want a count of the clients", stderr)
	}
}

func TestInventoryClientsAudienceAndScope(t *testing.T) {
	inventoryPath, masterSecretPath := inventoryFiles(t)
	code, stdout, stderr := ztcctl(t, nil, "inventory", "clients", "-inventory", inventoryPath,
		"-master-secret", masterSecretPath, "-audience", "ztc-pep,ztc-fog", "-scope", "telemetry:write, task:run")
	if code != exitOK {
		t.Fatalf("exit %d, %s", code, stderr)
	}
	var file caClientsFile
	if err := json.Unmarshal([]byte(stdout), &file); err != nil {
		t.Fatal(err)
	}
	client := file.Clients[0]
	if !slices.Equal(client.Audience, []string{"ztc-pep", "ztc-fog"}) || !slices.Equal(client.Scope, []string{"telemetry:write", "task:run"}) {
		t.Errorf("audience %v, scope %v", client.Audience, client.Scope)
	}
}

func TestInventoryClientsRejects(t *testing.T) {
	inventoryPath, masterSecretPath := inventoryFiles(t)
	directory := t.TempDir()

	openSecretPath := filepath.Join(directory, "open.secret")
	if err := os.WriteFile(openSecretPath, make([]byte, 32), 0o644); err != nil { //nolint:gosec // G306: too open on purpose, to test the refusal
		t.Fatal(err)
	}
	shortSecretPath := filepath.Join(directory, "short.secret")
	if err := os.WriteFile(shortSecretPath, make([]byte, 16), 0o600); err != nil {
		t.Fatal(err)
	}
	brokenInventoryPath := filepath.Join(directory, "broken.json")
	if err := os.WriteFile(brokenInventoryPath, []byte(`{"trustDomain": ""}`), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		arguments []string
		wantCode  int
		wantError string
	}{
		{"no subcommand", []string{"inventory"}, exitUsage, "secret or clients"},
		{"unknown subcommand", []string{"inventory", "list"}, exitUsage, "unknown subcommand"},
		{"secret without -out", []string{"inventory", "secret"}, exitUsage, "needs -out"},
		{"clients without flags", []string{"inventory", "clients"}, exitUsage, "needs -inventory"},
		{"unknown flag", []string{"inventory", "clients", "-zone", "x"}, exitUsage, "flag provided but not defined"},
		{"missing inventory", []string{"inventory", "clients", "-inventory", filepath.Join(directory, "none.json"), "-master-secret", masterSecretPath}, exitError, "no such file"},
		{"invalid inventory", []string{"inventory", "clients", "-inventory", brokenInventoryPath, "-master-secret", masterSecretPath}, exitError, "trust domain"},
		{"secret others can read", []string{"inventory", "clients", "-inventory", inventoryPath, "-master-secret", openSecretPath}, exitError, "0600"},
		{"secret too short", []string{"inventory", "clients", "-inventory", inventoryPath, "-master-secret", shortSecretPath}, exitError, "at least 32"},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			code, stdout, stderr := ztcctl(t, nil, testCase.arguments...)
			if code != testCase.wantCode || !strings.Contains(stderr, testCase.wantError) {
				t.Errorf("exit %d, stderr %q; want exit %d and %q", code, stderr, testCase.wantCode, testCase.wantError)
			}
			if stdout != "" {
				t.Errorf("printed %q on a failure", stdout)
			}
		})
	}
}

func TestInventoryHelp(t *testing.T) {
	for _, subcommand := range []string{"secret", "clients"} {
		if code, _, _ := ztcctl(t, nil, "inventory", subcommand, "-h"); code != exitOK {
			t.Errorf("inventory %s -h: exit %d, want 0", subcommand, code)
		}
	}
}

func mustDeviceSecret(t *testing.T, masterSecret []byte, subjectID string) string {
	t.Helper()
	secret, err := inventory.DeviceSecret(masterSecret, subjectID)
	if err != nil {
		t.Fatal(err)
	}
	return secret
}
