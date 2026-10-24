package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/model"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/token"
)

// generateKeys runs keys gen in a new directory and returns the paths of the
// private key and of the public key, which the test saves from stdout.
func generateKeys(t *testing.T) (privateKeyPath, publicKeyPath string) {
	t.Helper()
	directory := t.TempDir()
	privateKeyPath = filepath.Join(directory, "signing.key")
	publicKeyPath = filepath.Join(directory, "signing.pub")
	code, stdout, stderr := ztcctl(t, nil, "keys", "gen", "-out", privateKeyPath)
	if code != exitOK {
		t.Fatalf("keys gen: exit %d, %s", code, stderr)
	}
	if err := os.WriteFile(publicKeyPath, []byte(stdout), 0o600); err != nil {
		t.Fatal(err)
	}
	return privateKeyPath, publicKeyPath
}

func TestKeysGen(t *testing.T) {
	privateKeyPath, publicKeyPath := generateKeys(t)
	privateKey, err := token.LoadPrivateKeyFile(privateKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	publicPEM, err := os.ReadFile(filepath.Clean(publicKeyPath))
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := token.ParsePublicKeyPEM(publicPEM)
	if err != nil || !publicKey.Equal(privateKey.Public()) {
		t.Fatalf("stdout is not the public key of the written private key: %v", err)
	}

	code, _, stderr := ztcctl(t, nil, "keys", "gen", "-out", privateKeyPath)
	if code != exitError || !strings.Contains(stderr, "exists") {
		t.Errorf("keys gen over an existing key: exit %d, %q", code, stderr)
	}
}

func TestTokenIssueAndVerify(t *testing.T) {
	privateKeyPath, publicKeyPath := generateKeys(t)
	code, signedToken, stderr := ztcctl(t, nil, "token", "issue", "-key", privateKeyPath,
		"-subject", "spiffe://grid.example/edge/pmu/1", "-audience", "ztc-pep", "-scope", "telemetry:write", "-zone", "bay-1")
	if code != exitOK {
		t.Fatalf("token issue: exit %d, %s", code, stderr)
	}

	verify := func(input, audience string) (int, string) {
		code, stdout, _ := ztcctlWithInput(t, nil, input, "token", "verify", "-pub", publicKeyPath, "-audience", audience)
		return code, stdout
	}
	code, stdout := verify(signedToken, "ztc-pep")
	showsSubjectAndZone := strings.Contains(stdout, `"sub": "spiffe://grid.example/edge/pmu/1"`) && strings.Contains(stdout, `"zone": "bay-1"`)
	if code != exitOK || !showsSubjectAndZone {
		t.Errorf("valid token: exit %d, %q", code, stdout)
	}
	if code, stdout := verify(signedToken, "ztc-historian"); code != exitDeny || !strings.Contains(stdout, "audience") {
		t.Errorf("wrong audience: exit %d, %q", code, stdout)
	}
	tampered := strings.Replace(signedToken, ".", ".x", 1)
	if code, _ := verify(tampered, "ztc-pep"); code != exitDeny {
		t.Errorf("tampered token: exit %d, want %d", code, exitDeny)
	}
	if code, _ := verify("", "ztc-pep"); code != exitUsage {
		t.Errorf("no token on standard input: exit %d, want %d", code, exitUsage)
	}
}

func TestTokenIssueRejects(t *testing.T) {
	privateKeyPath, _ := generateKeys(t)
	issue := []string{"token", "issue", "-key", privateKeyPath, "-subject", "spiffe://grid.example/edge/pmu/1", "-audience", "ztc-pep"}
	tests := []struct {
		name      string
		arguments []string
		want      int
	}{
		{"no subcommand", []string{"token"}, exitUsage},
		{"unknown subcommand", []string{"token", "forge"}, exitUsage},
		{"no audience", []string{"token", "issue", "-key", privateKeyPath, "-subject", "s"}, exitUsage},
		{"zero lifetime", append(issue, "-ttl", "0s"), exitUsage},
		{"lifetime above a day", append(issue, "-ttl", "25h"), exitUsage},
		{"missing key file", []string{"token", "issue", "-key", "/nonexistent", "-subject", "s", "-audience", "a"}, exitError},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			if code, _, stderr := ztcctl(t, nil, testCase.arguments...); code != testCase.want {
				t.Errorf("exit %d, want %d; stderr:\n%s", code, testCase.want, stderr)
			}
		})
	}
}

func TestCapabilityCommands(t *testing.T) {
	rootKeyPath := filepath.Join(t.TempDir(), "root.key")
	if code, _, stderr := ztcctl(t, nil, "cap", "rootkey", "-out", rootKeyPath); code != exitOK {
		t.Fatalf("cap rootkey: exit %d, %s", code, stderr)
	}
	code, minted, stderr := ztcctl(t, nil, "cap", "mint", "-root-key", rootKeyPath, "-id", "grant-42",
		"action = execute", "resource ^= substation-1/")
	if code != exitOK {
		t.Fatalf("cap mint: exit %d, %s", code, stderr)
	}
	code, attenuated, stderr := ztcctlWithInput(t, nil, minted, "cap", "attenuate", "task = t-7", "layer <= fog")
	if code != exitOK {
		t.Fatalf("cap attenuate: exit %d, %s", code, stderr)
	}

	_, shown, _ := ztcctlWithInput(t, nil, attenuated, "cap", "show")
	for _, wantLine := range []string{"grant grant-42", "4 caveats", "  action = execute", "  task = t-7"} {
		if !strings.Contains(shown, wantLine) {
			t.Errorf("cap show is missing %q:\n%s", wantLine, shown)
		}
	}

	// Only the root key can check a capability; the test plays the PDP.
	rootKey, err := token.ReadSecretFile(rootKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	capability, err := token.DecodeCapability(strings.TrimSpace(attenuated))
	if err != nil {
		t.Fatal(err)
	}
	fogRequest := token.Request{Action: "execute", Resource: "substation-1/task/t-7", Task: "t-7", Layer: model.LayerFog, Now: time.Now()}
	if err := capability.Verify(rootKey, token.StandardChecker(fogRequest)); err != nil {
		t.Errorf("attenuated capability rejected: %v", err)
	}
	otherTask := fogRequest
	otherTask.Task = "t-8"
	if err := capability.Verify(rootKey, token.StandardChecker(otherTask)); err == nil {
		t.Error("the attenuated capability was accepted for another task")
	}
}

func TestCapabilityCommandsReject(t *testing.T) {
	directory := t.TempDir()
	shortKeyPath := filepath.Join(directory, "short.key")
	if err := os.WriteFile(shortKeyPath, []byte("too short"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		input     string
		arguments []string
		want      int
	}{
		{"no subcommand", "", []string{"cap"}, exitUsage},
		{"rootkey without -out", "", []string{"cap", "rootkey"}, exitUsage},
		{"mint without -id", "", []string{"cap", "mint", "-root-key", shortKeyPath}, exitUsage},
		{"mint with a short root key", "", []string{"cap", "mint", "-root-key", shortKeyPath, "-id", "g"}, exitError},
		{"attenuate without caveats", "abc", []string{"cap", "attenuate"}, exitUsage},
		{"attenuate with empty input", "", []string{"cap", "attenuate", "task = t-1"}, exitUsage},
		{"show garbage", "not a capability", []string{"cap", "show"}, exitError},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			if code, _, stderr := ztcctlWithInput(t, nil, testCase.input, testCase.arguments...); code != testCase.want {
				t.Errorf("exit %d, want %d; stderr:\n%s", code, testCase.want, stderr)
			}
		})
	}
}
