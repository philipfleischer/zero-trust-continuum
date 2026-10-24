// Public keys as a JSON Web Key Set (RFC 7517, Ed25519 keys per RFC 8037):
// the format an issuer publishes so verifiers can fetch its keys.

package token

import (
	"crypto/ed25519"
	"errors"
	"fmt"
)

// ErrKeySet is returned for a key set a verifier must not use.
var ErrKeySet = errors.New("token: invalid key set")

// The JWK values of an Ed25519 signing key.
const (
	octetKeyPair = "OKP"     // RFC 8037: the key type of Ed25519 and X25519
	curveEd25519 = "Ed25519" // RFC 8037: the curve
	useSignature = "sig"     // RFC 7517: the key verifies signatures
)

// JSONWebKey is one public key in a key set.
type JSONWebKey struct {
	KeyType   string `json:"kty"`
	Curve     string `json:"crv"`
	KeyID     string `json:"kid"`
	Use       string `json:"use,omitempty"`
	PublicKey string `json:"x"` // the 32 key bytes as base64url without padding
}

// JSONWebKeySet is the body of GET /v1/keys on ztc-ca.
type JSONWebKeySet struct {
	Keys []JSONWebKey `json:"keys"`
}

// NewJSONWebKey returns publicKey as a JWK with the key ID KeyIDOf(publicKey).
func NewJSONWebKey(publicKey ed25519.PublicKey) JSONWebKey {
	return JSONWebKey{
		KeyType:   octetKeyPair,
		Curve:     curveEd25519,
		KeyID:     KeyIDOf(publicKey),
		Use:       useSignature,
		PublicKey: base64URL.EncodeToString(publicKey),
	}
}

// VerificationKeys returns the keys of the set as Verifier.Keys expects them.
// Every key must be an Ed25519 signing key of 32 bytes whose key ID is
// KeyIDOf of the key itself; a key ID that does not match its key, or that
// appears twice, makes the whole set invalid. An empty set is invalid too, so
// a verifier never runs without keys by accident.
func (keySet JSONWebKeySet) VerificationKeys() (map[string]ed25519.PublicKey, error) {
	if len(keySet.Keys) == 0 {
		return nil, fmt.Errorf("%w: no keys", ErrKeySet)
	}
	keysByID := make(map[string]ed25519.PublicKey, len(keySet.Keys))
	for _, webKey := range keySet.Keys {
		publicKey, err := webKey.verificationKey()
		if err != nil {
			return nil, err
		}
		if _, duplicate := keysByID[webKey.KeyID]; duplicate {
			return nil, fmt.Errorf("%w: key ID %q appears twice", ErrKeySet, webKey.KeyID)
		}
		keysByID[webKey.KeyID] = publicKey
	}
	return keysByID, nil
}

// verificationKey checks one JWK and returns its public key.
func (webKey JSONWebKey) verificationKey() (ed25519.PublicKey, error) {
	isEd25519 := webKey.KeyType == octetKeyPair && webKey.Curve == curveEd25519
	if !isEd25519 {
		return nil, fmt.Errorf("%w: key %q is %s/%s, want OKP/Ed25519", ErrKeySet, webKey.KeyID, webKey.KeyType, webKey.Curve)
	}
	if webKey.Use != "" && webKey.Use != useSignature {
		return nil, fmt.Errorf("%w: key %q has use %q, want sig", ErrKeySet, webKey.KeyID, webKey.Use)
	}
	keyBytes, err := base64URL.DecodeString(webKey.PublicKey)
	if err != nil || len(keyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: key %q is not 32 bytes of base64url", ErrKeySet, webKey.KeyID)
	}
	publicKey := ed25519.PublicKey(keyBytes)
	if webKey.KeyID != KeyIDOf(publicKey) {
		return nil, fmt.Errorf("%w: key ID %q does not belong to its key", ErrKeySet, webKey.KeyID)
	}
	return publicKey, nil
}
