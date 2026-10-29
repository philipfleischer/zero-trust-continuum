// Device secrets derived from one master secret, so the operator keeps one
// secret instead of one per device.

package inventory

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// MinMasterSecretSize is the smallest master secret DeviceSecret accepts, in
// bytes: 256 bits, the strength of the HMAC-SHA256 that derives from it.
const MinMasterSecretSize = 32

// derivationLabel separates these secrets from any other use of the same
// master secret, and lets a later version derive different ones.
const derivationLabel = "ztc device secret v1\x00"

// DeviceSecret returns the secret the device with this SPIFFE ID presents to
// ztc-ca for a token: the hex HMAC-SHA256 of the SPIFFE ID under the master
// secret. The same master secret and ID always give the same secret, so
// ztcctl can write the CA's clients file and ztc-edge can find each device's
// secret without either storing them. Knowing one device's secret reveals
// nothing about another's or about the master secret.
func DeviceSecret(masterSecret []byte, subjectID string) (string, error) {
	if len(masterSecret) < MinMasterSecretSize {
		return "", fmt.Errorf("inventory: master secret has %d bytes, want at least %d", len(masterSecret), MinMasterSecretSize)
	}
	mac := hmac.New(sha256.New, masterSecret)
	mac.Write([]byte(derivationLabel + subjectID))
	return hex.EncodeToString(mac.Sum(nil)), nil
}
