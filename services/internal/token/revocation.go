// The revocation list: token IDs that must be rejected before they expire,
// with an epoch that tells caches and replicas whether their copy is stale.

package token

import (
	"maps"
	"sync"
	"time"
)

// RevocationList is the set of revoked token IDs (the jti claim). Each ID is
// kept until the token would have expired anyway; after that the expiry check
// in Verify rejects the token by itself.
//
// Every change that can turn an accepted token into a rejected one increases
// the epoch. A fog cache that has seen epoch 7 and then gets an answer with
// epoch 8 knows that its cached allows may now be wrong (RQ1 measures that
// delay as revocation staleness). Snapshot and Replace copy the list from the
// cloud to fog nodes, and later through Raft (M3).
//
// It is safe for concurrent use.
type RevocationList struct {
	mutex     sync.RWMutex
	expiresAt map[string]time.Time // token ID -> when the token expires
	epoch     uint64
}

// NewRevocationList returns an empty list at epoch 0.
func NewRevocationList() *RevocationList {
	return &RevocationList{expiresAt: map[string]time.Time{}}
}

// Revoke adds tokenID, whose token expires at tokenExpiresAt, and increases
// the epoch. It reports whether the list changed: revoking an ID again with
// the same or an earlier expiry changes nothing and keeps the epoch, so fog
// caches are not flushed for nothing. An empty tokenID is ignored.
func (list *RevocationList) Revoke(tokenID string, tokenExpiresAt time.Time) bool {
	if tokenID == "" {
		return false
	}
	list.mutex.Lock()
	defer list.mutex.Unlock()
	knownExpiry, alreadyRevoked := list.expiresAt[tokenID]
	if alreadyRevoked && !tokenExpiresAt.After(knownExpiry) {
		return false
	}
	list.expiresAt[tokenID] = tokenExpiresAt
	list.epoch++
	return true
}

// IsRevoked reports whether tokenID is on the list.
func (list *RevocationList) IsRevoked(tokenID string) bool {
	list.mutex.RLock()
	defer list.mutex.RUnlock()
	_, revoked := list.expiresAt[tokenID]
	return revoked
}

// Prune removes the IDs whose tokens expired more than leeway before now, and
// returns how many it removed. leeway must be at least the largest
// Verifier.Leeway that uses the list: a verifier still accepts a token for
// leeway after its expiry, so the ID must stay on the list until then.
//
// Pruning does not change the epoch, because no verifier can accept the
// removed tokens any more.
func (list *RevocationList) Prune(now time.Time, leeway time.Duration) int {
	list.mutex.Lock()
	defer list.mutex.Unlock()
	removed := 0
	for tokenID, tokenExpiresAt := range list.expiresAt {
		noVerifierAcceptsItAnyMore := tokenExpiresAt.Add(leeway).Before(now)
		if noVerifierAcceptsItAnyMore {
			delete(list.expiresAt, tokenID)
			removed++
		}
	}
	return removed
}

// Epoch returns the current version of the list.
func (list *RevocationList) Epoch() uint64 {
	list.mutex.RLock()
	defer list.mutex.RUnlock()
	return list.epoch
}

// Len returns the number of revoked IDs on the list.
func (list *RevocationList) Len() int {
	list.mutex.RLock()
	defer list.mutex.RUnlock()
	return len(list.expiresAt)
}

// Snapshot returns a copy of the list and its epoch, to send to a replica.
// Changing the returned map does not change the list.
func (list *RevocationList) Snapshot() (map[string]time.Time, uint64) {
	list.mutex.RLock()
	defer list.mutex.RUnlock()
	return maps.Clone(list.expiresAt), list.epoch
}

// Replace installs a snapshot from upstream if its epoch is newer than the
// list's own, and reports whether it did. An older or equal epoch is
// ignored, so snapshots that arrive out of order can never undo a revocation.
func (list *RevocationList) Replace(snapshot map[string]time.Time, snapshotEpoch uint64) bool {
	list.mutex.Lock()
	defer list.mutex.Unlock()
	if snapshotEpoch <= list.epoch {
		return false
	}
	list.expiresAt = maps.Clone(snapshot)
	if list.expiresAt == nil {
		list.expiresAt = map[string]time.Time{}
	}
	list.epoch = snapshotEpoch
	return true
}
