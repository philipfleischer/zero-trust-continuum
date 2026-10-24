package token

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"
)

// referenceTime is the reference time of the tests.
var referenceTime = time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)

// newTestSigner returns a signer with a fresh key and a verifier for "ztc-pep"
// that trusts it and whose clock stands at referenceTime.
func newTestSigner(t *testing.T) (Signer, Verifier) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return Signer{KeyID: "k1", Key: privateKey},
		Verifier{Keys: map[string]ed25519.PublicKey{"k1": publicKey}, Audience: "ztc-pep", Now: func() time.Time { return referenceTime }}
}

// pmuClaims are valid at referenceTime for one minute.
func pmuClaims() Claims {
	return Claims{
		Issuer:    "ztc-ca",
		Subject:   "spiffe://grid.example/edge/pmu/1",
		Audience:  []string{"ztc-pep"},
		ExpiresAt: referenceTime.Add(time.Minute).Unix(),
		NotBefore: referenceTime.Unix(),
		IssuedAt:  referenceTime.Unix(),
		ID:        "jti-1",
		Scope:     []string{"telemetry:write"},
		Zone:      "bay-1",
	}
}

func TestSignVerify(t *testing.T) {
	signer, verifier := newTestSigner(t)
	token, err := signer.Sign(pmuClaims())
	if err != nil {
		t.Fatal(err)
	}
	got, err := verifier.Verify(token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Subject != "spiffe://grid.example/edge/pmu/1" || got.ID != "jti-1" || !got.HasScope("telemetry:write") {
		t.Errorf("Verify returned %+v", got)
	}
	if got.Zone != "bay-1" || len(got.Roles) != 0 {
		t.Errorf("zone %q and roles %q, want bay-1 and none", got.Zone, got.Roles)
	}
}

func TestSignRequiresClaims(t *testing.T) {
	signer, _ := newTestSigner(t)
	for name, change := range map[string]func(*Claims){
		"no subject":  func(claims *Claims) { claims.Subject = "" },
		"no audience": func(claims *Claims) { claims.Audience = nil },
		"no expiry":   func(claims *Claims) { claims.ExpiresAt = 0 },
		"no ID":       func(claims *Claims) { claims.ID = "" },
	} {
		claims := pmuClaims()
		change(&claims)
		if _, err := signer.Sign(claims); !errors.Is(err, ErrMissingClaim) {
			t.Errorf("%s: Sign error %v, want ErrMissingClaim", name, err)
		}
	}
	if _, err := (Signer{KeyID: "k1"}).Sign(pmuClaims()); err == nil {
		t.Error("Sign without a key succeeded")
	}
}

func TestHasScope(t *testing.T) {
	claims := Claims{Scope: []string{"telemetry:*", "breaker:read"}}
	tests := []struct {
		scope string
		want  bool
	}{
		{"telemetry:read", true},
		{"telemetry:write", true},
		{"breaker:read", true},
		{"breaker:operate", false},
		{"telemetryx:read", false}, // the wildcard ends at the colon
		{"", false},
	}
	for _, testCase := range tests {
		if got := claims.HasScope(testCase.scope); got != testCase.want {
			t.Errorf("HasScope(%q) = %v, want %v", testCase.scope, got, testCase.want)
		}
	}
	if (Claims{Scope: []string{"*"}}).HasScope("breaker:operate") {
		t.Error(`a bare "*" must not grant everything`)
	}
}

func TestKeyThumbprint(t *testing.T) {
	publicKey := make(ed25519.PublicKey, ed25519.PublicKeySize)
	// SHA-256 is 32 bytes, which is 43 characters of base64url without padding.
	if got := KeyThumbprint(publicKey); len(got) != 43 || got != KeyThumbprint(publicKey) {
		t.Errorf("KeyThumbprint = %q", got)
	}
	other := make(ed25519.PublicKey, ed25519.PublicKeySize)
	other[0] = 1
	if KeyThumbprint(publicKey) == KeyThumbprint(other) {
		t.Error("two keys have the same thumbprint")
	}
}
