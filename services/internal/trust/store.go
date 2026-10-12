// The trust store: the State of every subject, shared by the goroutines that
// record signals and the ones that ask for scores.

package trust

import (
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"
)

// Store keeps the trust State of every subject. It is safe for concurrent
// use: PEPs, the IDS and the PDP record signals while the PDP reads scores.
type Store struct {
	mutex          sync.RWMutex
	evaluator      *Evaluator
	stateBySubject map[string]State
	now            func() time.Time
}

// NewStore returns an empty store that scores with evaluator, or with
// NewEvaluator() if evaluator is nil, and reads time from the system clock.
func NewStore(evaluator *Evaluator) *Store {
	if evaluator == nil {
		evaluator = NewEvaluator()
	}
	return &Store{evaluator: evaluator, stateBySubject: make(map[string]State), now: time.Now}
}

// SetClock replaces the clock the store reads "now" from, for tests and for
// replaying recorded signals. It is safe to call while the store is in use.
func (store *Store) SetClock(now func() time.Time) {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	store.now = now
}

// Now returns the time on the store's clock,
// so a caller can use the same clock for a whole decision.
func (store *Store) Now() time.Time {
	store.mutex.RLock()
	defer store.mutex.RUnlock()
	return store.now()
}

// Record applies signal to the state of its subject. A signal without a time
// is stamped with the store's clock. A signal without a subject or with an
// unknown kind is rejected and changes nothing.
func (store *Store) Record(signal Signal) error {
	if signal.Subject == "" {
		return errors.New("trust: signal without subject")
	}
	if !signal.Kind.Valid() {
		return fmt.Errorf("trust: unknown signal kind %q", signal.Kind)
	}
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if signal.Time.IsZero() {
		signal.Time = store.now()
	}
	previous := store.stateBySubject[signal.Subject]
	store.stateBySubject[signal.Subject] = store.evaluator.Apply(previous, signal)
	return nil
}

// Score returns the current trust score of subject. An unknown subject
// scores 0: zero trust until proven otherwise.
func (store *Store) Score(subject string) float64 {
	store.mutex.RLock()
	state := store.stateBySubject[subject]
	now := store.now()
	store.mutex.RUnlock()
	return store.evaluator.Score(state, now)
}

// State returns a copy of the state of subject and whether it is known.
func (store *Store) State(subject string) (State, bool) {
	store.mutex.RLock()
	defer store.mutex.RUnlock()
	state, known := store.stateBySubject[subject]
	return state, known
}

// Subjects returns the IDs of all known subjects in sorted order.
func (store *Store) Subjects() []string {
	store.mutex.RLock()
	defer store.mutex.RUnlock()
	subjectIDs := make([]string, 0, len(store.stateBySubject))
	for subjectID := range store.stateBySubject {
		subjectIDs = append(subjectIDs, subjectID)
	}
	slices.Sort(subjectIDs)
	return subjectIDs
}
