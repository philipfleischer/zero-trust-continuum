// Verification keys fetched from the issuer: the PEP's copy of GET /v1/keys
// on ztc-ca, replaced while requests are being verified.

package pep

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/token"
)

// ErrNoKeys is returned by RemoteKeys.Verify before the first key set has
// been fetched.
var ErrNoKeys = errors.New("pep: no verification keys yet")

// maxKeySetSize is the largest key set response RemoteKeys reads (64 KiB).
const maxKeySetSize = 64 << 10

// RemoteKeys verifies tokens with the key set published at a URL and
// refreshes it, so a key rotation at the issuer reaches the PEP. It is safe
// for concurrent use: a refresh replaces the whole verifier in one step, and
// a request in progress keeps the one it started with.
type RemoteKeys struct {
	keySetURL string
	client    *http.Client
	template  token.Verifier // audience, leeway and clock; Keys is filled in
	current   atomic.Pointer[token.Verifier]
}

// NewRemoteKeys returns a RemoteKeys for the key set at keySetURL. Every
// verifier it builds is a copy of template with the fetched keys.
func NewRemoteKeys(keySetURL string, template token.Verifier, client *http.Client) *RemoteKeys {
	return &RemoteKeys{keySetURL: keySetURL, client: client, template: template}
}

// Refresh fetches the key set and, if every key in it is valid, starts using
// it. On any error the keys in use are kept: a CA that is briefly unreachable
// must not stop the PEP from verifying tokens it already could.
func (keys *RemoteKeys) Refresh(ctx context.Context) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, keys.keySetURL, nil)
	if err != nil {
		return err
	}
	response, err := keys.client.Do(request)
	if err != nil {
		return fmt.Errorf("pep: fetch key set: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("pep: fetch key set: %s", response.Status)
	}
	var keySet token.JSONWebKeySet
	if err := json.NewDecoder(io.LimitReader(response.Body, maxKeySetSize)).Decode(&keySet); err != nil {
		return fmt.Errorf("pep: decode key set: %w", err)
	}
	keysByID, err := keySet.VerificationKeys()
	if err != nil {
		return err
	}
	verifier := keys.template
	verifier.Keys = keysByID
	keys.current.Store(&verifier)
	return nil
}

// Loaded reports whether a key set has been fetched.
func (keys *RemoteKeys) Loaded() bool { return keys.current.Load() != nil }

// Verify checks signedToken with the keys in use, and returns ErrNoKeys
// before the first successful Refresh.
func (keys *RemoteKeys) Verify(signedToken string) (token.Claims, error) {
	verifier := keys.current.Load()
	if verifier == nil {
		return token.Claims{}, ErrNoKeys
	}
	return verifier.Verify(signedToken)
}

// KeepFresh calls Refresh every interval until ctx is done, and logs the
// refreshes that fail.
func (keys *RemoteKeys) KeepFresh(ctx context.Context, interval time.Duration, logger *slog.Logger) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := keys.Refresh(ctx); err != nil {
				logger.Warn("key set not refreshed, keeping the old keys", "url", keys.keySetURL, "reason", err)
			}
		}
	}
}

// Check at compile time that both verifiers satisfy TokenVerifier.
var (
	_ TokenVerifier = (*RemoteKeys)(nil)
	_ TokenVerifier = token.Verifier{}
)
