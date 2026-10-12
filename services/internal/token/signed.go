// Package token implements the credentials of research question RQ2:
//
//   - signed tokens (signed.go): JWT-like bearer tokens signed with Ed25519.
//     A verifier needs only the issuer's public key, so a fog node can check a
//     token while the link to the cloud is down. The price is that a token is
//     valid until it expires unless the verifier keeps a revocation list.
//   - capabilities (capability.go): macaroon-style HMAC chains. The holder
//     can narrow one without asking the issuer, which suits offloading:
//     edge -> fog -> cloud, each hop with fewer rights.
//   - certificates come with mutual TLS in M5.
//
// Industry equivalents: JWT (RFC 7519) with go-jose or golang-jwt, Google's
// macaroons, Biscuit tokens.
package token

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"
)

// MaxTokenSize is the longest token Verify accepts, in bytes. Tokens travel in
// HTTP headers; a longer one is an attack on the verifier's memory and CPU.
const MaxTokenSize = 4096

// Claims is the payload of a signed token. The names follow RFC 7519.
type Claims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`             // SPIFFE ID of the holder
	Audience  []string `json:"aud"`             // services that may accept the token
	ExpiresAt int64    `json:"exp"`             // Unix seconds
	NotBefore int64    `json:"nbf,omitempty"`   // Unix seconds; 0 means no lower bound
	IssuedAt  int64    `json:"iat,omitempty"`   // Unix seconds
	ID        string   `json:"jti"`             // unique ID, used for revocation
	Scope     []string `json:"scope,omitempty"` // e.g. "telemetry:read", "breaker:*"
	// Confirmation binds the token to the holder's key (RFC 7800): the
	// KeyThumbprint of its public key. Verify does not check it; a PEP that
	// asks the client to prove it holds the key does.
	Confirmation string `json:"cnf,omitempty"`
}

// Errors returned by Sign and Verify. Every way a token can fail has its own
// error, so tests and the audit log can tell why a token was rejected.
var (
	ErrMalformed    = errors.New("token: malformed")
	ErrAlgorithm    = errors.New("token: algorithm or type not accepted")
	ErrUnknownKey   = errors.New("token: unknown key id")
	ErrSignature    = errors.New("token: bad signature")
	ErrMissingClaim = errors.New("token: missing required claim")
	ErrExpired      = errors.New("token: expired")
	ErrNotYetValid  = errors.New("token: not yet valid")
	ErrAudience     = errors.New("token: audience mismatch")
)

// The only header values this package writes and accepts.
const (
	algorithm = "EdDSA"
	tokenType = "ZTC"
)

type header struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
	KeyID     string `json:"kid"`
}

// base64URL is base64url without padding, the encoding of JWT (RFC 7515).
var base64URL = base64.RawURLEncoding

// Signer creates signed tokens with one Ed25519 key.
type Signer struct {
	KeyID string             // written as "kid", so verifiers can pick the key during rotation
	Key   ed25519.PrivateKey // the signing key
}

// Sign returns claims as header.payload.signature, each part base64url
// without padding, with the header {"alg":"EdDSA","typ":"ZTC","kid":KeyID}.
// It refuses claims a verifier would reject for missing a required claim.
func (signer Signer) Sign(claims Claims) (string, error) {
	if len(signer.Key) != ed25519.PrivateKeySize {
		return "", errors.New("token: signer has no Ed25519 key")
	}
	if err := claims.checkRequired(); err != nil {
		return "", err
	}
	headerJSON, err := json.Marshal(header{Algorithm: algorithm, Type: tokenType, KeyID: signer.KeyID})
	if err != nil {
		return "", err
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := base64URL.EncodeToString(headerJSON) + "." + base64URL.EncodeToString(payloadJSON)
	signature := ed25519.Sign(signer.Key, []byte(signingInput))
	return signingInput + "." + base64URL.EncodeToString(signature), nil
}

// Verifier checks signed tokens for one service.
type Verifier struct {
	Keys     map[string]ed25519.PublicKey // kid -> public key of the issuer
	Audience string                       // this service; must be in the token's aud
	Leeway   time.Duration                // allowed clock difference, fog nodes drift
	Now      func() time.Time             // nil means time.Now
}

// Verify checks the format, algorithm, signature, required claims, time
// window and audience of token, in that order, and returns its claims. On any
// failure it returns empty claims and one of the errors above, so a caller
// cannot use the claims of a rejected token by mistake.
//
// A verifier without an Audience rejects every token: a configuration
// mistake must not turn into "any audience will do".
func (verifier Verifier) Verify(token string) (Claims, error) {
	if len(token) > MaxTokenSize {
		return Claims{}, ErrMalformed
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, ErrMalformed
	}
	encodedHeader, encodedPayload, encodedSignature := parts[0], parts[1], parts[2]

	var tokenHeader header
	if err := decodePart(encodedHeader, &tokenHeader); err != nil {
		return Claims{}, err
	}
	// The algorithm is fixed by the verifier, never chosen by the token.
	if tokenHeader.Algorithm != algorithm || tokenHeader.Type != tokenType {
		return Claims{}, ErrAlgorithm
	}
	publicKey, found := verifier.Keys[tokenHeader.KeyID]
	if !found || len(publicKey) != ed25519.PublicKeySize {
		return Claims{}, ErrUnknownKey
	}
	signature, err := base64URL.DecodeString(encodedSignature)
	if err != nil {
		return Claims{}, ErrMalformed
	}
	signedPart := encodedHeader + "." + encodedPayload
	if !ed25519.Verify(publicKey, []byte(signedPart), signature) {
		return Claims{}, ErrSignature
	}

	var claims Claims
	if err := decodePart(encodedPayload, &claims); err != nil {
		return Claims{}, err
	}
	if err := claims.checkRequired(); err != nil {
		return Claims{}, err
	}
	now := time.Now
	if verifier.Now != nil {
		now = verifier.Now
	}
	currentTime := now()
	lastValidMoment := time.Unix(claims.ExpiresAt, 0).Add(verifier.Leeway)
	if !currentTime.Before(lastValidMoment) {
		return Claims{}, ErrExpired
	}
	hasNotBefore := claims.NotBefore != 0
	firstValidMoment := time.Unix(claims.NotBefore, 0).Add(-verifier.Leeway)
	if hasNotBefore && currentTime.Before(firstValidMoment) {
		return Claims{}, ErrNotYetValid
	}
	if verifier.Audience == "" || !slices.Contains(claims.Audience, verifier.Audience) {
		return Claims{}, ErrAudience
	}
	return claims, nil
}

// decodePart decodes one base64url JSON part of a token into destination.
func decodePart(encodedPart string, destination any) error {
	jsonBytes, err := base64URL.DecodeString(encodedPart)
	if err != nil {
		return ErrMalformed
	}
	if err := json.Unmarshal(jsonBytes, destination); err != nil {
		return ErrMalformed
	}
	return nil
}

// checkRequired returns ErrMissingClaim unless claims has a subject, an
// audience, an expiry and an ID. Without an expiry a token is valid forever,
// and without an ID it cannot be revoked.
func (claims Claims) checkRequired() error {
	if claims.Subject == "" || len(claims.Audience) == 0 || claims.ExpiresAt == 0 || claims.ID == "" {
		return ErrMissingClaim
	}
	return nil
}

// HasScope reports whether claims grants the scope wanted, for example
// "telemetry:read". A granted scope "telemetry:*" covers every scope that
// starts with "telemetry:".
func (claims Claims) HasScope(wanted string) bool {
	for _, granted := range claims.Scope {
		if granted == wanted {
			return true
		}
		prefix, isWildcard := strings.CutSuffix(granted, "*")
		coversWholeGroup := isWildcard && strings.HasSuffix(prefix, ":")
		if coversWholeGroup && strings.HasPrefix(wanted, prefix) {
			return true
		}
	}
	return false
}

// KeyThumbprint returns the value of Claims.Confirmation for a public key:
// base64url of its SHA-256 hash.
func KeyThumbprint(publicKey ed25519.PublicKey) string {
	hash := sha256.Sum256(publicKey)
	return base64URL.EncodeToString(hash[:])
}
