// Tests for the revocation list: the epoch, pruning with leeway, replication
// by snapshot, the link into Verify, and concurrent use.

package token

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestRevokeIncreasesEpochOnlyOnChange(t *testing.T) {
	list := NewRevocationList()
	inOneMinute := referenceTime.Add(time.Minute)
	steps := []struct {
		name        string
		tokenID     string
		expiresAt   time.Time
		wantChanged bool
		wantEpoch   uint64
	}{
		{"first revocation", "jti-1", inOneMinute, true, 1},
		{"same ID again", "jti-1", inOneMinute, false, 1},
		{"same ID, earlier expiry", "jti-1", referenceTime, false, 1},
		{"same ID, later expiry", "jti-1", inOneMinute.Add(time.Hour), true, 2},
		{"another ID", "jti-2", inOneMinute, true, 3},
		{"empty ID", "", inOneMinute, false, 3},
	}
	for _, step := range steps {
		changed := list.Revoke(step.tokenID, step.expiresAt)
		if changed != step.wantChanged || list.Epoch() != step.wantEpoch {
			t.Errorf("%s: changed %v, epoch %d, want %v and %d",
				step.name, changed, list.Epoch(), step.wantChanged, step.wantEpoch)
		}
	}
	if !list.IsRevoked("jti-1") || !list.IsRevoked("jti-2") || list.IsRevoked("jti-3") {
		t.Error("IsRevoked does not match what was revoked")
	}
	if list.Len() != 2 {
		t.Errorf("Len() = %d, want 2", list.Len())
	}
}

// TestPruneKeepsIDsWithinLeeway is a flaw of the original: Prune removed an
// ID as soon as its token expired, but a verifier with leeway still accepts
// the token for a while, so for that while a revoked token was accepted again.
func TestPruneKeepsIDsWithinLeeway(t *testing.T) {
	list := NewRevocationList()
	expiresAt := referenceTime.Add(time.Minute)
	list.Revoke("short-lived", expiresAt)
	list.Revoke("long-lived", referenceTime.Add(time.Hour))
	leeway := 30 * time.Second

	if removed := list.Prune(expiresAt.Add(10*time.Second), leeway); removed != 0 {
		t.Errorf("Prune within the leeway removed %d IDs, want 0", removed)
	}
	if removed := list.Prune(expiresAt.Add(leeway+time.Second), leeway); removed != 1 {
		t.Errorf("Prune after the leeway removed %d IDs, want 1", removed)
	}
	if list.IsRevoked("short-lived") || !list.IsRevoked("long-lived") {
		t.Error("Prune removed the wrong ID")
	}
	if list.Epoch() != 2 {
		t.Errorf("Prune changed the epoch to %d, want 2", list.Epoch())
	}
}

func TestSnapshotAndReplace(t *testing.T) {
	cloud := NewRevocationList()
	cloud.Revoke("jti-1", referenceTime.Add(time.Hour))
	cloud.Revoke("jti-2", referenceTime.Add(time.Hour))
	snapshot, snapshotEpoch := cloud.Snapshot()

	delete(snapshot, "jti-1")
	if !cloud.IsRevoked("jti-1") {
		t.Fatal("changing the snapshot changed the list it came from")
	}

	fog := NewRevocationList()
	if !fog.Replace(snapshot, snapshotEpoch) || fog.Epoch() != 2 || !fog.IsRevoked("jti-2") {
		t.Fatalf("Replace with a newer snapshot: epoch %d, len %d", fog.Epoch(), fog.Len())
	}
	delete(snapshot, "jti-2")
	if !fog.IsRevoked("jti-2") {
		t.Fatal("changing the snapshot after Replace changed the list")
	}
	if fog.Replace(map[string]time.Time{}, 2) || fog.Replace(map[string]time.Time{}, 1) {
		t.Error("a snapshot with an equal or older epoch was installed")
	}
	if !fog.IsRevoked("jti-2") {
		t.Error("an old snapshot undid a revocation")
	}

	if !fog.Replace(nil, 5) || fog.Len() != 0 {
		t.Fatalf("Replace with a nil snapshot: replaced, len %d", fog.Len())
	}
	if !fog.Revoke("jti-3", referenceTime.Add(time.Hour)) {
		t.Error("Revoke after Replace(nil) failed")
	}
}

func TestVerifyRejectsRevokedToken(t *testing.T) {
	signer, verifier := newTestSigner(t)
	token, err := signer.Sign(pmuClaims())
	if err != nil {
		t.Fatal(err)
	}
	verifier.Revocations = NewRevocationList()
	if _, err := verifier.Verify(token); err != nil {
		t.Fatalf("token rejected before it was revoked: %v", err)
	}

	verifier.Revocations.Revoke("jti-1", referenceTime.Add(time.Minute))
	claims, err := verifier.Verify(token)
	if !errors.Is(err, ErrRevoked) || claims.Subject != "" {
		t.Errorf("revoked token: claims %+v, error %v, want no claims and ErrRevoked", claims, err)
	}
}

// TestRevocationListConcurrentUse is for the race detector.
func TestRevocationListConcurrentUse(t *testing.T) {
	list := NewRevocationList()
	var workers sync.WaitGroup
	for worker := range 4 {
		workers.Go(func() {
			for i := range 100 {
				tokenID := fmt.Sprintf("jti-%d-%d", worker, i)
				list.Revoke(tokenID, referenceTime.Add(time.Duration(i)*time.Second))
				list.IsRevoked(tokenID)
				list.Snapshot()
			}
		})
	}
	workers.Go(func() { list.Prune(referenceTime.Add(time.Minute), 0) })
	workers.Wait()
	if list.Epoch() != 400 {
		t.Errorf("epoch = %d, want 400 (one per new ID)", list.Epoch())
	}
}
