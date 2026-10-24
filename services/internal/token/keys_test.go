// Tests for key files and IDs: PEM round trips, what the parsers reject, file
// permissions, stable key IDs and random token IDs.

package token

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func newKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return publicKey, privateKey
}

func TestPEMRoundTrip(t *testing.T) {
	publicKey, privateKey := newKeyPair(t)

	privatePEM, err := EncodePrivateKeyPEM(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	parsedPrivate, err := ParsePrivateKeyPEM(privatePEM)
	if err != nil || !parsedPrivate.Equal(privateKey) {
		t.Fatalf("private key round trip: %v", err)
	}

	publicPEM, err := EncodePublicKeyPEM(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	parsedPublic, err := ParsePublicKeyPEM(publicPEM)
	if err != nil || !parsedPublic.Equal(publicKey) {
		t.Fatalf("public key round trip: %v", err)
	}
}

func TestParseKeyPEMRejects(t *testing.T) {
	publicKey, privateKey := newKeyPair(t)
	privatePEM, err := EncodePrivateKeyPEM(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	publicPEM, err := EncodePublicKeyPEM(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecdsaDER, err := x509.MarshalPKCS8PrivateKey(ecdsaKey)
	if err != nil {
		t.Fatal(err)
	}
	ecdsaPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ecdsaDER})
	garbagePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not DER")})
	validKeyBlock, _ := pem.Decode(privatePEM)
	wrongTypePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: validKeyBlock.Bytes})

	tests := []struct {
		name  string
		input []byte
		want  error
	}{
		{"not PEM", []byte("hello"), ErrKeyFormat},
		{"empty", nil, ErrKeyFormat},
		{"public key where a private key belongs", publicPEM, ErrKeyFormat},
		{"valid key under the wrong block type", wrongTypePEM, ErrKeyFormat},
		{"two keys in one file", append(append([]byte(nil), privatePEM...), privatePEM...), ErrKeyFormat},
		{"not DER inside the PEM", garbagePEM, ErrKeyFormat},
		{"an ECDSA key", ecdsaPEM, ErrNotEd25519},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := ParsePrivateKeyPEM(testCase.input); !errors.Is(err, testCase.want) {
				t.Errorf("ParsePrivateKeyPEM error %v, want %v", err, testCase.want)
			}
		})
	}
	if _, err := ParsePublicKeyPEM(privatePEM); !errors.Is(err, ErrKeyFormat) {
		t.Errorf("ParsePublicKeyPEM of a private key: %v, want ErrKeyFormat", err)
	}
}

func TestPrivateKeyFile(t *testing.T) {
	_, privateKey := newKeyPair(t)
	path := filepath.Join(t.TempDir(), "signing-key.pem")

	if err := WritePrivateKeyFile(path, privateKey); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("key file mode %v, want 0600", info.Mode().Perm())
	}
	loaded, err := LoadPrivateKeyFile(path)
	if err != nil || !loaded.Equal(privateKey) {
		t.Fatalf("LoadPrivateKeyFile: %v", err)
	}

	_, otherKey := newKeyPair(t)
	if err := WritePrivateKeyFile(path, otherKey); !errors.Is(err, os.ErrExist) {
		t.Errorf("writing over an existing key file: %v, want os.ErrExist", err)
	}
	if loaded, _ := LoadPrivateKeyFile(path); !loaded.Equal(privateKey) {
		t.Error("the existing key was replaced")
	}

	if err := os.Chmod(path, 0o644); err != nil { //nolint:gosec // G302: too open on purpose, to test the refusal
		t.Fatal(err)
	}
	if _, err := LoadPrivateKeyFile(path); !errors.Is(err, ErrKeyFilePermissions) {
		t.Errorf("loading a key file others can read: %v, want ErrKeyFilePermissions", err)
	}

	missing := filepath.Join(t.TempDir(), "missing.pem")
	if _, err := LoadPrivateKeyFile(missing); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("loading a missing file: %v, want os.ErrNotExist", err)
	}
}

// TestLoadedKeySignsVerifiableTokens is the reason for key files: a key that
// is written, loaded again after a restart, and used to sign must produce
// tokens that verify with the public key from before the restart.
func TestLoadedKeySignsVerifiableTokens(t *testing.T) {
	publicKey, privateKey := newKeyPair(t)
	path := filepath.Join(t.TempDir(), "signing-key.pem")
	if err := WritePrivateKeyFile(path, privateKey); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadPrivateKeyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	keyID := KeyIDOf(loaded.Public().(ed25519.PublicKey))
	token, err := Signer{KeyID: keyID, Key: loaded}.Sign(pmuClaims())
	if err != nil {
		t.Fatal(err)
	}
	_, verifier := newTestSigner(t)
	verifier.Keys = map[string]ed25519.PublicKey{KeyIDOf(publicKey): publicKey}
	if _, err := verifier.Verify(token); err != nil {
		t.Errorf("token from the reloaded key rejected: %v", err)
	}
}

func TestKeyIDOf(t *testing.T) {
	publicKey, _ := newKeyPair(t)
	otherPublicKey, _ := newKeyPair(t)
	keyID := KeyIDOf(publicKey)
	if len(keyID) != 16 || keyID != KeyIDOf(publicKey) {
		t.Errorf("KeyIDOf = %q, want 16 characters, the same every time", keyID)
	}
	if keyID == KeyIDOf(otherPublicKey) {
		t.Error("two keys have the same key ID")
	}
}

func TestNewTokenID(t *testing.T) {
	seen := map[string]bool{}
	for range 1000 {
		tokenID := NewTokenID()
		if len(tokenID) < 26 || seen[tokenID] {
			t.Fatalf("NewTokenID() = %q: too short or repeated", tokenID)
		}
		seen[tokenID] = true
	}
}
