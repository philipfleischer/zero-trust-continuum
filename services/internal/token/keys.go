// Keys and IDs: Ed25519 keys in PEM files that survive a restart, the key ID
// derived from a public key, and random token IDs.

package token

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Errors returned by the key functions.
var (
	ErrKeyFormat          = errors.New("token: not a single PEM key of the expected kind")
	ErrNotEd25519         = errors.New("token: key is not an Ed25519 key")
	ErrKeyFilePermissions = errors.New("token: key file is readable by other users")
)

// PEM block types of PKCS #8 private keys and PKIX public keys. These are the
// formats openssl and every TLS library use, so "openssl pkey -in key.pem
// -text" can inspect the files.
const (
	privateKeyBlockType = "PRIVATE KEY"
	publicKeyBlockType  = "PUBLIC KEY"
)

// EncodePrivateKeyPEM returns privateKey as a PKCS #8 PEM block.
func EncodePrivateKeyPEM(privateKey ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: privateKeyBlockType, Bytes: der}), nil
}

// ParsePrivateKeyPEM is the inverse of EncodePrivateKeyPEM. The data must be
// exactly one PEM block of type PRIVATE KEY holding an Ed25519 key.
func ParsePrivateKeyPEM(data []byte) (ed25519.PrivateKey, error) {
	der, err := singlePEMBlock(data, privateKeyBlockType)
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrKeyFormat, err)
	}
	privateKey, isEd25519 := parsed.(ed25519.PrivateKey)
	if !isEd25519 {
		return nil, fmt.Errorf("%w: got %T", ErrNotEd25519, parsed)
	}
	return privateKey, nil
}

// EncodePublicKeyPEM returns publicKey as a PKIX PEM block.
func EncodePublicKeyPEM(publicKey ed25519.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: publicKeyBlockType, Bytes: der}), nil
}

// ParsePublicKeyPEM is the inverse of EncodePublicKeyPEM. The data must be
// exactly one PEM block of type PUBLIC KEY holding an Ed25519 key.
func ParsePublicKeyPEM(data []byte) (ed25519.PublicKey, error) {
	der, err := singlePEMBlock(data, publicKeyBlockType)
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrKeyFormat, err)
	}
	publicKey, isEd25519 := parsed.(ed25519.PublicKey)
	if !isEd25519 {
		return nil, fmt.Errorf("%w: got %T", ErrNotEd25519, parsed)
	}
	return publicKey, nil
}

// singlePEMBlock returns the bytes of the only PEM block in data, which must
// have the type wantType. Anything after the block other than white space is
// an error, so a file cannot hide a second key.
func singlePEMBlock(data []byte, wantType string) ([]byte, error) {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != wantType {
		return nil, ErrKeyFormat
	}
	if secondBlock, _ := pem.Decode(rest); secondBlock != nil {
		return nil, ErrKeyFormat
	}
	return block.Bytes, nil
}

// WritePrivateKeyFile writes privateKey as PEM to a new file at path with
// WriteSecretFile.
func WritePrivateKeyFile(path string, privateKey ed25519.PrivateKey) error {
	data, err := EncodePrivateKeyPEM(privateKey)
	if err != nil {
		return err
	}
	return WriteSecretFile(path, data)
}

// LoadPrivateKeyFile reads the PEM private key at path with ReadSecretFile.
func LoadPrivateKeyFile(path string) (ed25519.PrivateKey, error) {
	data, err := ReadSecretFile(path)
	if err != nil {
		return nil, err
	}
	privateKey, err := ParsePrivateKeyPEM(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return privateKey, nil
}

// WriteSecretFile writes data to a new file at path that only its owner can
// read (0600). It never overwrites an existing file: replacing a signing key
// or a root key by mistake would make every credential issued with it
// unverifiable.
func WriteSecretFile(path string, data []byte) error {
	file, err := os.OpenFile(filepath.Clean(path), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

// ReadSecretFile reads the file at path. Like ssh, it refuses a file that
// users other than the owner can read, because then the secret may already be
// known to someone else.
func ReadSecretFile(path string) ([]byte, error) {
	cleanPath := filepath.Clean(path)
	info, err := os.Stat(cleanPath)
	if err != nil {
		return nil, err
	}
	readableByOthers := info.Mode().Perm()&0o077 != 0
	if readableByOthers {
		return nil, fmt.Errorf("%w: %s has mode %v, want 0600", ErrKeyFilePermissions, path, info.Mode().Perm())
	}
	return os.ReadFile(cleanPath)
}

// KeyIDOf returns the key ID ("kid") of publicKey: the first 16 characters of
// its KeyThumbprint. The same key always gets the same ID, so a verifier that
// knows the key can match tokens to it after the issuer restarts.
func KeyIDOf(publicKey ed25519.PublicKey) string {
	return KeyThumbprint(publicKey)[:16]
}

// NewTokenID returns a random token ID (the jti claim): at least 128 random
// bits from crypto/rand, written as base32 (26 characters today). A collision,
// which would let one revocation hit two tokens, is then practically
// impossible.
func NewTokenID() string {
	return rand.Text()
}
