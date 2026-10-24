// Tests for the JSON Web Key Set: the JSON a verifier receives, and every way
// a key set can be wrong.

package token

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestJSONWebKeyFormat(t *testing.T) {
	publicKey, _ := newKeyPair(t)
	encoded, err := json.Marshal(JSONWebKeySet{Keys: []JSONWebKey{NewJSONWebKey(publicKey)}})
	if err != nil {
		t.Fatal(err)
	}
	for _, wantField := range []string{`"kty":"OKP"`, `"crv":"Ed25519"`, `"use":"sig"`, `"kid":"` + KeyIDOf(publicKey) + `"`} {
		if !strings.Contains(string(encoded), wantField) {
			t.Errorf("key set %s is missing %s", encoded, wantField)
		}
	}

	var decoded JSONWebKeySet
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	keysByID, err := decoded.VerificationKeys()
	if err != nil || !keysByID[KeyIDOf(publicKey)].Equal(publicKey) {
		t.Fatalf("VerificationKeys() = %v, %v", keysByID, err)
	}
}

// TestKeySetVerifiesTokens is the acceptance criterion of issue #15 at the
// package level: a token verifies with the keys from the issuer's key set.
func TestKeySetVerifiesTokens(t *testing.T) {
	publicKey, privateKey := newKeyPair(t)
	signedToken, err := Signer{KeyID: KeyIDOf(publicKey), Key: privateKey}.Sign(pmuClaims())
	if err != nil {
		t.Fatal(err)
	}
	keysByID, err := JSONWebKeySet{Keys: []JSONWebKey{NewJSONWebKey(publicKey)}}.VerificationKeys()
	if err != nil {
		t.Fatal(err)
	}
	_, verifier := newTestSigner(t)
	verifier.Keys = keysByID
	if _, err := verifier.Verify(signedToken); err != nil {
		t.Errorf("token rejected with the key set: %v", err)
	}
}

func TestKeySetRejects(t *testing.T) {
	publicKey, _ := newKeyPair(t)
	otherPublicKey, _ := newKeyPair(t)
	validKey := NewJSONWebKey(publicKey)
	changed := func(change func(*JSONWebKey)) JSONWebKey {
		webKey := validKey
		change(&webKey)
		return webKey
	}
	tests := []struct {
		name string
		keys []JSONWebKey
	}{
		{"no keys", nil},
		{"RSA key type", []JSONWebKey{changed(func(webKey *JSONWebKey) { webKey.KeyType = "RSA" })}},
		{"X25519 curve", []JSONWebKey{changed(func(webKey *JSONWebKey) { webKey.Curve = "X25519" })}},
		{"encryption key", []JSONWebKey{changed(func(webKey *JSONWebKey) { webKey.Use = "enc" })}},
		{"key not base64url", []JSONWebKey{changed(func(webKey *JSONWebKey) { webKey.PublicKey = "!!!" })}},
		// "AAAA" is three zero bytes; the key ID matches them, so only the length check can catch it.
		{"key too short", []JSONWebKey{changed(func(webKey *JSONWebKey) {
			webKey.PublicKey, webKey.KeyID = "AAAA", KeyIDOf(ed25519.PublicKey{0, 0, 0})
		})}},
		{"key ID of another key", []JSONWebKey{changed(func(webKey *JSONWebKey) { webKey.KeyID = KeyIDOf(otherPublicKey) })}},
		{"same key twice", []JSONWebKey{validKey, validKey}},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := (JSONWebKeySet{Keys: testCase.keys}).VerificationKeys(); !errors.Is(err, ErrKeySet) {
				t.Errorf("VerificationKeys() error %v, want ErrKeySet", err)
			}
		})
	}
	withoutUse := changed(func(webKey *JSONWebKey) { webKey.Use = "" })
	if _, err := (JSONWebKeySet{Keys: []JSONWebKey{withoutUse}}).VerificationKeys(); err != nil {
		t.Errorf("a key without use was rejected: %v", err)
	}
}
