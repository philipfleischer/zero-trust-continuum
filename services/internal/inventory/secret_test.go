// Tests for the derived device secrets.

package inventory

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// testMasterSecret is 32 bytes, the minimum.
var testMasterSecret = bytes.Repeat([]byte{7}, MinMasterSecretSize)

func TestDeviceSecretIsStable(t *testing.T) {
	first, err := DeviceSecret(testMasterSecret, "spiffe://grid.example/edge/pmu/pmu-b1-1")
	if err != nil {
		t.Fatal(err)
	}
	second, _ := DeviceSecret(testMasterSecret, "spiffe://grid.example/edge/pmu/pmu-b1-1")
	if first != second {
		t.Errorf("the same input gave %s and %s", first, second)
	}
	if len(first) != 64 {
		t.Errorf("secret %q has %d characters, want 64 hex characters", first, len(first))
	}
}

// TestDeviceSecretMatchesHMAC pins the derivation, so ztcctl and ztc-edge
// built from different versions cannot drift apart unnoticed.
func TestDeviceSecretMatchesHMAC(t *testing.T) {
	subjectID := "spiffe://grid.example/edge/meter/meter-b1-1"
	mac := hmac.New(sha256.New, testMasterSecret)
	mac.Write([]byte("ztc device secret v1\x00" + subjectID))
	want := hex.EncodeToString(mac.Sum(nil))
	if got, _ := DeviceSecret(testMasterSecret, subjectID); got != want {
		t.Errorf("DeviceSecret() = %s, want %s", got, want)
	}
}

func TestDeviceSecretsDiffer(t *testing.T) {
	inventory := Demo()
	seen := map[string]string{}
	for _, device := range inventory.Devices {
		secret, err := DeviceSecret(testMasterSecret, inventory.SubjectID(device))
		if err != nil {
			t.Fatal(err)
		}
		if other, found := seen[secret]; found {
			t.Errorf("%s and %s have the same secret", device.ID, other)
		}
		seen[secret] = device.ID
	}

	otherMaster := bytes.Repeat([]byte{8}, MinMasterSecretSize)
	subjectID := inventory.SubjectID(inventory.Devices[0])
	withFirst, _ := DeviceSecret(testMasterSecret, subjectID)
	withOther, _ := DeviceSecret(otherMaster, subjectID)
	if withFirst == withOther {
		t.Error("two master secrets gave the same device secret")
	}
}

func TestDeviceSecretRejectsAShortMasterSecret(t *testing.T) {
	for _, size := range []int{0, 16, MinMasterSecretSize - 1} {
		if _, err := DeviceSecret(make([]byte, size), "spiffe://grid.example/edge/pmu/pmu-b1-1"); err == nil {
			t.Errorf("a master secret of %d bytes was accepted", size)
		}
	}
}
