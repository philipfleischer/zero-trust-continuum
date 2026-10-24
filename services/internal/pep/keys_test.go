// Tests for RemoteKeys: fetching, rotation, keeping old keys on failure, and
// verifying while the keys are replaced.

package pep

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/token"
)

// fakeIssuer publishes the key set of its current signing key, like
// GET /v1/keys on ztc-ca, and can rotate the key or start failing.
type fakeIssuer struct {
	server  *httptest.Server
	mutex   sync.Mutex
	signer  token.Signer
	keySet  token.JSONWebKeySet
	failing bool
}

func newFakeIssuer(t *testing.T) *fakeIssuer {
	t.Helper()
	issuer := &fakeIssuer{}
	issuer.rotate(t)
	issuer.server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		issuer.mutex.Lock()
		defer issuer.mutex.Unlock()
		if issuer.failing {
			http.Error(writer, "down", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(writer).Encode(issuer.keySet)
	}))
	t.Cleanup(issuer.server.Close)
	return issuer
}

// rotate gives the issuer a new signing key and publishes only that one.
func (issuer *fakeIssuer) rotate(t *testing.T) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	issuer.mutex.Lock()
	defer issuer.mutex.Unlock()
	issuer.signer = token.Signer{KeyID: token.KeyIDOf(publicKey), Key: privateKey}
	issuer.keySet = token.JSONWebKeySet{Keys: []token.JSONWebKey{token.NewJSONWebKey(publicKey)}}
}

func (issuer *fakeIssuer) setFailing(failing bool) {
	issuer.mutex.Lock()
	defer issuer.mutex.Unlock()
	issuer.failing = failing
}

// signToken signs a token for the PMU with the issuer's current key.
func (issuer *fakeIssuer) signToken(t *testing.T) string {
	t.Helper()
	issuer.mutex.Lock()
	signer := issuer.signer
	issuer.mutex.Unlock()
	signedToken, err := signer.Sign(token.Claims{
		Subject:   "spiffe://grid.example/edge/pmu/1",
		Audience:  []string{"ztc-pep"},
		ExpiresAt: referenceTime.Add(time.Minute).Unix(),
		ID:        token.NewTokenID(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return signedToken
}

func newTestRemoteKeys(issuer *fakeIssuer) *RemoteKeys {
	template := token.Verifier{Audience: "ztc-pep", Now: func() time.Time { return referenceTime }}
	return NewRemoteKeys(issuer.server.URL, template, issuer.server.Client())
}

func TestRemoteKeysVerify(t *testing.T) {
	issuer := newFakeIssuer(t)
	keys := newTestRemoteKeys(issuer)
	signedToken := issuer.signToken(t)

	if _, err := keys.Verify(signedToken); !errors.Is(err, ErrNoKeys) || keys.Loaded() {
		t.Fatalf("before the first refresh: %v, loaded %v; want ErrNoKeys", err, keys.Loaded())
	}
	if err := keys.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	claims, err := keys.Verify(signedToken)
	if err != nil || claims.Subject != "spiffe://grid.example/edge/pmu/1" {
		t.Errorf("Verify = %+v, %v", claims, err)
	}
}

func TestRemoteKeysFollowRotation(t *testing.T) {
	issuer := newFakeIssuer(t)
	keys := newTestRemoteKeys(issuer)
	if err := keys.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	issuer.rotate(t)
	newToken := issuer.signToken(t)
	if _, err := keys.Verify(newToken); !errors.Is(err, token.ErrUnknownKey) {
		t.Fatalf("a token with the new key before the refresh: %v, want ErrUnknownKey", err)
	}
	if err := keys.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := keys.Verify(newToken); err != nil {
		t.Errorf("a token with the new key after the refresh: %v", err)
	}
}

func TestRemoteKeysKeepOldKeysOnFailure(t *testing.T) {
	issuer := newFakeIssuer(t)
	keys := newTestRemoteKeys(issuer)
	signedToken := issuer.signToken(t)
	if err := keys.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	issuer.setFailing(true)
	if err := keys.Refresh(context.Background()); err == nil {
		t.Error("Refresh against a failing issuer succeeded")
	}
	issuer.setFailing(false)
	issuer.mutex.Lock()
	issuer.keySet = token.JSONWebKeySet{} // an empty set is invalid
	issuer.mutex.Unlock()
	if err := keys.Refresh(context.Background()); !errors.Is(err, token.ErrKeySet) {
		t.Errorf("Refresh with an empty key set: %v, want ErrKeySet", err)
	}
	if _, err := keys.Verify(signedToken); err != nil {
		t.Errorf("the old keys were dropped after failed refreshes: %v", err)
	}
}

// TestRemoteKeysKeepFresh rotates the key while KeepFresh runs, and verifies
// tokens at the same time, for the race detector.
func TestRemoteKeysKeepFresh(t *testing.T) {
	issuer := newFakeIssuer(t)
	keys := newTestRemoteKeys(issuer)
	if err := keys.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() {
		keys.KeepFresh(ctx, 10*time.Millisecond, slog.New(slog.NewTextHandler(io.Discard, nil)))
		close(stopped)
	}()

	issuer.rotate(t)
	newToken := issuer.signToken(t)
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, err := keys.Verify(newToken)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the new key was not picked up: %v", err)
		}
		time.Sleep(5 * time.Millisecond)
	}

	cancel()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("KeepFresh did not stop when the context was cancelled")
	}
}
