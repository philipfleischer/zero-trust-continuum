// Tests for the trust store: unknown subjects, the injectable clock, input
// checks and concurrent use under the race detector.

package trust

import (
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"
)

// fixedClock returns a store whose clock reads *now, so a test can move time.
func fixedClock(now *time.Time) *Store {
	store := NewStore(nil)
	store.SetClock(func() time.Time { return *now })
	return store
}

// record fails the test if the store rejects signal.
func record(t *testing.T, store *Store, signal Signal) {
	t.Helper()
	if err := store.Record(signal); err != nil {
		t.Fatalf("Record(%+v) = %v", signal, err)
	}
}

func TestStoreUnknownSubject(t *testing.T) {
	store := NewStore(nil)
	if got := store.Score("spiffe://grid.example/edge/pmu/9"); got != 0 {
		t.Errorf("Score(unknown) = %v, want 0", got)
	}
	if _, known := store.State("spiffe://grid.example/edge/pmu/9"); known {
		t.Error("State(unknown) reported a known subject")
	}
}

func TestStoreScoreFollowsTheClock(t *testing.T) {
	now := referenceTime
	store := fixedClock(&now)
	pmu := "spiffe://grid.example/edge/pmu/1"
	record(t, store, Signal{Subject: pmu, Kind: Authentication, Value: 1})
	record(t, store, Signal{Subject: pmu, Kind: Posture, Value: 1})
	record(t, store, Signal{Subject: pmu, Kind: Location, Value: 1})

	state, _ := store.State(pmu)
	if !state.LastAuth.Equal(referenceTime) {
		t.Errorf("signal without time: LastAuth = %v, want the store clock %v", state.LastAuth, referenceTime)
	}
	// 0.35 + 0.25 + 0.30 + 0.10·0.5 (one location signal from 0)
	if got := store.Score(pmu); !near(got, 0.95) || LevelOf(got) != High {
		t.Errorf("Score() = %v (%s), want 0.95 (high)", got, LevelOf(got))
	}
	now = referenceTime.Add(time.Hour) // twelve half-lives without a new authentication
	// 0.35/4096 + 0.25 + 0.30 + 0.05
	if got := store.Score(pmu); !near(got, 0.6+0.35/4096) || LevelOf(got) != Medium {
		t.Errorf("Score() after an hour = %v (%s), want 0.600085 (medium)", got, LevelOf(got))
	}
}

func TestStoreNow(t *testing.T) {
	now := referenceTime
	store := fixedClock(&now)
	if got := store.Now(); !got.Equal(referenceTime) {
		t.Errorf("Now() = %v, want %v", got, referenceTime)
	}
}

func TestStoreDenialOfUnknownSubject(t *testing.T) {
	store := NewStore(nil)
	record(t, store, Signal{Subject: "spiffe://grid.example/edge/attacker", Kind: Denial})
	if got := store.Score("spiffe://grid.example/edge/attacker"); got != 0 {
		t.Errorf("Score() after a denial = %v, want 0", got)
	}
}

func TestStoreCompromise(t *testing.T) {
	store := NewStore(nil)
	record(t, store, Signal{Subject: "a", Kind: Authentication, Value: 1})
	record(t, store, Signal{Subject: "a", Kind: Compromise})
	if got := store.Score("a"); got != 0 {
		t.Errorf("Score() of a compromised subject = %v, want 0", got)
	}
}

func TestStoreRejects(t *testing.T) {
	store := NewStore(nil)
	for _, signal := range []Signal{
		{Kind: Authentication, Value: 1},
		{Subject: "a", Kind: "reset"},
		{Subject: "a"},
	} {
		if err := store.Record(signal); err == nil {
			t.Errorf("Record(%+v) = nil, want error", signal)
		}
	}
	if subjectIDs := store.Subjects(); len(subjectIDs) != 0 {
		t.Errorf("a rejected signal created subjects %v", subjectIDs)
	}
}

func TestStoreSubjectsSorted(t *testing.T) {
	store := NewStore(nil)
	for _, subjectID := range []string{"c", "a", "b"} {
		record(t, store, Signal{Subject: subjectID, Kind: Posture, Value: 1})
	}
	if got := store.Subjects(); !slices.Equal(got, []string{"a", "b", "c"}) {
		t.Errorf("Subjects() = %v", got)
	}
}

// TestStoreConcurrentUse is for the race detector (make test runs with
// -race): writers, readers and a clock change at the same time.
func TestStoreConcurrentUse(t *testing.T) {
	store := NewStore(nil)
	var workers sync.WaitGroup
	for worker := range 4 {
		workers.Go(func() {
			for i := range 200 {
				subject := fmt.Sprintf("spiffe://grid.example/edge/pmu/%d", i%10)
				if err := store.Record(Signal{Subject: subject, Kind: Authentication, Value: float64(worker+1) / 4}); err != nil {
					t.Error(err)
				}
			}
		})
	}
	for range 4 {
		workers.Go(func() {
			for i := range 200 {
				store.Score(fmt.Sprintf("spiffe://grid.example/edge/pmu/%d", i%10))
				store.Subjects()
			}
		})
	}
	workers.Go(func() { store.SetClock(time.Now) })
	workers.Wait()
	if got := len(store.Subjects()); got != 10 {
		t.Errorf("len(Subjects()) = %d, want 10", got)
	}
}
