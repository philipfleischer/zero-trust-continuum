// The decision cache: a Decider that remembers allows from the Decider behind
// it, for the hierarchical placement of RQ1.

package pdp

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"sync"
	"time"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/model"
)

// Cache sits on a fog node in front of a slower Decider, usually a
// RemoteClient to the cloud PDP, and answers repeated requests from memory.
//
// Only allows are cached. A cached allow is forgotten when:
//   - its TTL (Decision.TTL, set by the policy rule) runs out;
//   - an answer from upstream carries a newer policy version or a newer
//     revocation epoch, which drops every entry;
//   - upstream denies the subject anything, which drops the subject's entries;
//   - InvalidateSubject is called, for example on an IDS alert.
//
// When upstream fails, an expired entry is never used: the answer is a deny.
type Cache struct {
	name     string
	upstream Decider
	maxSize  int

	mutex           sync.Mutex
	now             func() time.Time
	entries         map[cacheKey]cacheEntry
	policyVersion   uint64 // newest policy version seen
	revocationEpoch uint64 // newest revocation epoch seen, a separate sequence
	hits, misses    uint64
}

// cacheKey identifies a request by a hash of everything a decision can depend
// on, so two requests share an entry only if the policy cannot tell them apart.
type cacheKey [sha256.Size]byte

type cacheEntry struct {
	subject   string
	decision  model.Decision
	expiresAt time.Time
}

// NewCache returns a cache called name in front of upstream that holds at
// most maxSize decisions (at least 1).
func NewCache(name string, upstream Decider, maxSize int) *Cache {
	return &Cache{
		name:     name,
		upstream: upstream,
		maxSize:  max(maxSize, 1),
		now:      time.Now,
		entries:  make(map[cacheKey]cacheEntry),
	}
}

// SetClock replaces the clock used for TTLs, for tests.
func (cache *Cache) SetClock(now func() time.Time) {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()
	cache.now = now
}

// Decide answers request from the cache if a live allow is stored for it, and
// asks upstream otherwise. A cached answer has DecidedBy set to the cache's
// name. If upstream fails, the answer is a deny and the error.
func (cache *Cache) Decide(ctx context.Context, request model.AccessRequest) (model.Decision, error) {
	key, cacheable := keyOf(request)
	if cacheable {
		cache.mutex.Lock()
		entry, found := cache.entries[key]
		isLive := found && cache.now().Before(entry.expiresAt)
		if isLive {
			cache.hits++
			cache.mutex.Unlock()
			entry.decision.DecidedBy = cache.name
			return entry.decision, nil
		}
		cache.misses++
		cache.mutex.Unlock()
	}

	decision, err := cache.upstream.Decide(ctx, request)
	if err != nil {
		return model.Decision{Effect: model.Deny, Reason: "no decision: " + err.Error(), DecidedBy: cache.name}, err
	}

	cache.mutex.Lock()
	defer cache.mutex.Unlock()
	cache.observe(decision.PolicyVersion, decision.RevocationEpoch)
	if !decision.Allowed() {
		cache.dropSubject(request.Subject.ID)
		return decision, nil
	}
	isStale := decision.PolicyVersion < cache.policyVersion || decision.RevocationEpoch < cache.revocationEpoch
	if cacheable && decision.TTL > 0 && !isStale {
		entry := cacheEntry{subject: request.Subject.ID, decision: decision, expiresAt: cache.now().Add(decision.TTL)}
		cache.store(key, entry)
	}
	return decision, nil
}

// InvalidateSubject drops every cached decision for subject.
func (cache *Cache) InvalidateSubject(subject string) {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()
	cache.dropSubject(subject)
}

// Stats returns the number of hits and misses so far and the number of
// cached decisions.
func (cache *Cache) Stats() (hits, misses uint64, size int) {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()
	return cache.hits, cache.misses, len(cache.entries)
}

// observe records the versions of an upstream answer and drops every entry if
// either is newer than seen before. The two are separate sequences: policy
// version 3 says nothing about revocation epoch 3. cache.mutex must be held.
func (cache *Cache) observe(policyVersion, revocationEpoch uint64) {
	nothingIsNewer := policyVersion <= cache.policyVersion && revocationEpoch <= cache.revocationEpoch
	if nothingIsNewer {
		return
	}
	cache.policyVersion = max(cache.policyVersion, policyVersion)
	cache.revocationEpoch = max(cache.revocationEpoch, revocationEpoch)
	clear(cache.entries)
}

// dropSubject removes the entries of subject. cache.mutex must be held.
func (cache *Cache) dropSubject(subject string) {
	for key, entry := range cache.entries {
		if entry.subject == subject {
			delete(cache.entries, key)
		}
	}
}

// store adds newEntry, first removing expired entries and, if the cache is
// still full, the entry that would expire first. cache.mutex must be held.
func (cache *Cache) store(key cacheKey, newEntry cacheEntry) {
	_, alreadyStored := cache.entries[key]
	if !alreadyStored && len(cache.entries) >= cache.maxSize {
		cache.makeRoom()
	}
	cache.entries[key] = newEntry
}

// makeRoom removes every expired entry and, if the cache is still full, the
// entry that expires first. cache.mutex must be held.
func (cache *Cache) makeRoom() {
	now := cache.now()
	var soonestKey cacheKey
	var soonestExpiry time.Time
	for key, entry := range cache.entries {
		if !now.Before(entry.expiresAt) {
			delete(cache.entries, key)
			continue
		}
		if soonestExpiry.IsZero() || entry.expiresAt.Before(soonestExpiry) {
			soonestKey, soonestExpiry = key, entry.expiresAt
		}
	}
	if len(cache.entries) >= cache.maxSize {
		delete(cache.entries, soonestKey)
	}
}

// keyOf hashes request without the fields the PDP sets itself (time, trust
// score, emergency). It reports false if request cannot be encoded; such a
// request is never cached.
func keyOf(request model.AccessRequest) (cacheKey, bool) {
	request.Context.Time = time.Time{}
	request.Context.TrustScore = 0
	request.Context.Emergency = false
	encoded, err := json.Marshal(request)
	if err != nil {
		return cacheKey{}, false
	}
	return sha256.Sum256(encoded), true
}

// Check at compile time that *Cache satisfies Decider.
var _ Decider = (*Cache)(nil)
