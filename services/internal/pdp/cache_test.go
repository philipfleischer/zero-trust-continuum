// Tests for the decision cache: what it remembers, every way it forgets, and
// that it never hides a failing upstream.

package pdp

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/model"
)

// fakeUpstream answers with whatever answer returns and counts the calls.
type fakeUpstream struct {
	mutex  sync.Mutex
	calls  int
	answer func(request model.AccessRequest) (model.Decision, error)
}

func (fake *fakeUpstream) Decide(_ context.Context, request model.AccessRequest) (model.Decision, error) {
	fake.mutex.Lock()
	fake.calls++
	fake.mutex.Unlock()
	return fake.answer(request)
}

func (fake *fakeUpstream) count() int {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	return fake.calls
}

// allowFor returns an upstream that allows everything with the given TTL and
// versions, as a cloud PDP would.
func allowFor(ttl time.Duration, policyVersion, revocationEpoch uint64) *fakeUpstream {
	return &fakeUpstream{answer: func(model.AccessRequest) (model.Decision, error) {
		return model.Decision{
			Effect:          model.Allow,
			TTL:             ttl,
			PolicyVersion:   policyVersion,
			RevocationEpoch: revocationEpoch,
			DecidedBy:       "cloud-pdp",
		}, nil
	}}
}

// newCache returns a cache in front of upstream whose clock reads *now.
func newCache(upstream Decider, now *time.Time) *Cache {
	cache := NewCache("fog-cache", upstream, 100)
	cache.SetClock(func() time.Time { return *now })
	return cache
}

// ask fails the test on an error and returns the decision.
func ask(t *testing.T, cache *Cache, request model.AccessRequest) model.Decision {
	t.Helper()
	decision, err := cache.Decide(context.Background(), request)
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	return decision
}

func TestCacheHitWithinTTL(t *testing.T) {
	now := referenceTime
	upstream := allowFor(time.Minute, 1, 0)
	cache := newCache(upstream, &now)
	if decision := ask(t, cache, writeTelemetry("bay-1")); decision.DecidedBy != "cloud-pdp" {
		t.Errorf("first answer from %q, want cloud-pdp", decision.DecidedBy)
	}
	now = now.Add(59 * time.Second)
	if decision := ask(t, cache, writeTelemetry("bay-1")); !decision.Allowed() || decision.DecidedBy != "fog-cache" {
		t.Errorf("second answer: %+v", decision)
	}
	if hits, misses, size := cache.Stats(); upstream.count() != 1 || hits != 1 || misses != 1 || size != 1 {
		t.Errorf("upstream calls %d, stats %d/%d/%d, want 1, 1/1/1", upstream.count(), hits, misses, size)
	}
}

func TestCacheExpires(t *testing.T) {
	now := referenceTime
	upstream := allowFor(time.Minute, 1, 0)
	cache := newCache(upstream, &now)
	ask(t, cache, writeTelemetry("bay-1"))
	now = now.Add(time.Minute)
	ask(t, cache, writeTelemetry("bay-1"))
	if upstream.count() != 2 {
		t.Errorf("upstream calls = %d, want 2 after the TTL ran out", upstream.count())
	}
}

func TestCacheDoesNotCache(t *testing.T) {
	tests := []struct {
		name     string
		upstream *fakeUpstream
	}{
		{"deny", &fakeUpstream{answer: func(model.AccessRequest) (model.Decision, error) {
			return model.Decision{Effect: model.Deny, TTL: time.Minute}, nil
		}}},
		{"allow without TTL", allowFor(0, 1, 0)},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			now := referenceTime
			cache := newCache(testCase.upstream, &now)
			ask(t, cache, writeTelemetry("bay-1"))
			ask(t, cache, writeTelemetry("bay-1"))
			if testCase.upstream.count() != 2 {
				t.Errorf("upstream calls = %d, want 2", testCase.upstream.count())
			}
		})
	}
}

// TestCacheKeyCoversTheRequest is a flaw of the original, which keyed entries
// by subject, action and resource ID only: an allow from the control centre
// was reused for the same request from the enterprise network.
func TestCacheKeyCoversTheRequest(t *testing.T) {
	now := referenceTime
	upstream := &fakeUpstream{answer: func(request model.AccessRequest) (model.Decision, error) {
		if request.Context.SourceZone != "control-centre" {
			return model.Decision{Effect: model.Deny}, nil
		}
		return model.Decision{Effect: model.Allow, TTL: 10 * time.Second}, nil
	}}
	cache := newCache(upstream, &now)
	fromControl := operateBreaker()
	fromControl.Context.SourceZone = "control-centre"
	if decision := ask(t, cache, fromControl); !decision.Allowed() {
		t.Fatalf("from the control centre: %+v", decision)
	}
	if decision := ask(t, cache, operateBreaker()); decision.Allowed() {
		t.Errorf("an allow from the control centre was reused for the enterprise network: %+v", decision)
	}
}

// TestCacheKeysDoNotCollide is another flaw of the original: keys were
// "subject|action|resource", so subject "a|b" with action "c" and subject "a"
// with action "b|c" shared an entry.
func TestCacheKeysDoNotCollide(t *testing.T) {
	now := referenceTime
	upstream := allowFor(time.Minute, 1, 0)
	cache := newCache(upstream, &now)
	first := model.AccessRequest{Subject: model.Subject{ID: "a|b"}, Action: "c", Resource: model.Resource{ID: "r"}}
	second := model.AccessRequest{Subject: model.Subject{ID: "a"}, Action: "b|c", Resource: model.Resource{ID: "r"}}
	ask(t, cache, first)
	if decision := ask(t, cache, second); decision.DecidedBy == "fog-cache" {
		t.Errorf("another subject's allow was served from the cache: %+v", decision)
	}
}

func TestCacheIgnoresFieldsThePDPSets(t *testing.T) {
	now := referenceTime
	upstream := allowFor(time.Minute, 1, 0)
	cache := newCache(upstream, &now)
	ask(t, cache, writeTelemetry("bay-1"))
	request := writeTelemetry("bay-1")
	request.Context.Time, request.Context.TrustScore = referenceTime.Add(time.Second), 0.9
	if decision := ask(t, cache, request); decision.DecidedBy != "fog-cache" {
		t.Errorf("time and trust score in the request split the entry: %+v", decision)
	}
}

// TestCacheInvalidatesOnDeny is the RQ4 finding of the original: without it a
// subject whose trust had just dropped kept using its cached allows.
func TestCacheInvalidatesOnDeny(t *testing.T) {
	now := referenceTime
	compromised := false
	upstream := &fakeUpstream{answer: func(model.AccessRequest) (model.Decision, error) {
		if compromised {
			return model.Decision{Effect: model.Deny}, nil
		}
		return model.Decision{Effect: model.Allow, TTL: time.Minute}, nil
	}}
	cache := newCache(upstream, &now)
	ask(t, cache, writeTelemetry("bay-1"))
	compromised = true
	ask(t, cache, writeTelemetry("bay-2")) // a miss, and upstream denies the subject
	if decision := ask(t, cache, writeTelemetry("bay-1")); decision.Allowed() {
		t.Errorf("a cached allow outlived a deny for the same subject: %+v", decision)
	}
}

func TestCacheInvalidateSubject(t *testing.T) {
	now := referenceTime
	upstream := allowFor(time.Minute, 1, 0)
	cache := newCache(upstream, &now)
	ask(t, cache, writeTelemetry("bay-1"))
	ask(t, cache, operateBreaker())
	cache.InvalidateSubject(pmu)
	if _, _, size := cache.Stats(); size != 1 {
		t.Errorf("size after InvalidateSubject = %d, want 1 (the operator's entry)", size)
	}
}

// TestCacheVersions checks that a newer policy version or revocation epoch
// drops every entry, tracked as two separate counters, and that an answer
// from an older policy is not cached.
func TestCacheVersions(t *testing.T) {
	tests := []struct {
		name                           string
		policyVersion, revocationEpoch uint64
		wantKeptOldEntry               bool
	}{
		{"same versions", 5, 1, true},
		{"newer policy", 6, 1, false},
		{"newer revocation epoch below the policy version", 5, 2, false},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			now := referenceTime
			upstream := allowFor(time.Minute, 5, 1)
			cache := newCache(upstream, &now)
			ask(t, cache, writeTelemetry("bay-1"))
			upstream.answer = allowFor(time.Minute, testCase.policyVersion, testCase.revocationEpoch).answer
			ask(t, cache, operateBreaker())
			if decision := ask(t, cache, writeTelemetry("bay-1")); (decision.DecidedBy == "fog-cache") != testCase.wantKeptOldEntry {
				t.Errorf("old entry kept = %v, want %v", decision.DecidedBy == "fog-cache", testCase.wantKeptOldEntry)
			}
		})
	}

	now := referenceTime
	upstream := allowFor(time.Minute, 5, 1)
	cache := newCache(upstream, &now)
	ask(t, cache, writeTelemetry("bay-1"))
	upstream.answer = allowFor(time.Minute, 4, 1).answer // a replica that is behind
	ask(t, cache, operateBreaker())
	if _, _, size := cache.Stats(); size != 1 {
		t.Errorf("an answer from an older policy was cached: size %d, want 1", size)
	}
}

func TestCacheUpstreamFailure(t *testing.T) {
	now := referenceTime
	fail := false
	upstream := &fakeUpstream{answer: func(model.AccessRequest) (model.Decision, error) {
		if fail {
			return model.Decision{Effect: model.Deny}, errors.New("WAN down")
		}
		return model.Decision{Effect: model.Allow, TTL: time.Minute}, nil
	}}
	cache := newCache(upstream, &now)
	ask(t, cache, writeTelemetry("bay-1"))
	fail = true
	if decision := ask(t, cache, writeTelemetry("bay-1")); !decision.Allowed() {
		t.Errorf("a live entry should still be served while upstream is down: %+v", decision)
	}
	now = now.Add(time.Minute)
	decision, err := cache.Decide(context.Background(), writeTelemetry("bay-1"))
	if err == nil || decision.Allowed() {
		t.Errorf("expired entry with upstream down: %+v, %v, want a deny and an error", decision, err)
	}
}

func TestCacheMaxSize(t *testing.T) {
	now := referenceTime
	upstream := &fakeUpstream{answer: func(request model.AccessRequest) (model.Decision, error) {
		ttl := time.Minute
		if request.Resource.ID == "short" {
			ttl = time.Second
		}
		return model.Decision{Effect: model.Allow, TTL: ttl}, nil
	}}
	cache := NewCache("fog-cache", upstream, 2)
	cache.SetClock(func() time.Time { return now })
	for _, resourceID := range []string{"short", "a", "b"} {
		ask(t, cache, model.AccessRequest{Subject: model.Subject{ID: "s"}, Resource: model.Resource{ID: resourceID}})
	}
	if _, _, size := cache.Stats(); size != 2 {
		t.Errorf("size = %d, want 2", size)
	}
	before := upstream.count()
	ask(t, cache, model.AccessRequest{Subject: model.Subject{ID: "s"}, Resource: model.Resource{ID: "a"}})
	if upstream.count() != before {
		t.Error("the entry that expires first should have been evicted, not a")
	}
}

// TestCacheConcurrentUse is for the race detector.
func TestCacheConcurrentUse(t *testing.T) {
	now := referenceTime
	upstream := allowFor(time.Minute, 1, 0)
	cache := NewCache("fog-cache", upstream, 4)
	var workers sync.WaitGroup
	for worker := range 8 {
		workers.Go(func() {
			for round := range 100 {
				request := writeTelemetry("bay-1")
				request.Resource.ID = string(rune('a' + (worker+round)%6))
				if _, err := cache.Decide(context.Background(), request); err != nil {
					t.Error(err)
				}
				if round%10 == 0 {
					cache.InvalidateSubject(pmu)
				}
			}
		})
	}
	workers.Go(func() { cache.SetClock(func() time.Time { return now }) })
	workers.Wait()
	if _, _, size := cache.Stats(); size > 4 {
		t.Errorf("size = %d, above the maximum of 4", size)
	}
}
