// Ways to reach a decision other than calling a PDP directly: a client for a
// remote PDP, a chain of deciders, and the placement modes RQ1 compares.

package pdp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/model"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/trust"
)

// Placement is where access decisions are made (research question RQ1).
type Placement string

// The placements.
const (
	// PlacementCloud sends every decision to the PDP in the cloud: always
	// fresh, but slow, and nothing is allowed while the WAN is down.
	PlacementCloud Placement = "cloud"
	// PlacementFog runs a full PDP on every fog node: fast and available
	// during a WAN outage, but policy changes arrive late.
	PlacementFog Placement = "fog"
	// PlacementHierarchical puts a decision cache on the fog node in front of
	// the cloud PDP: fast on a hit, fresh on a miss.
	PlacementHierarchical Placement = "hierarchical"
)

// ParsePlacement returns the placement called name, or an error if there is none.
func ParsePlacement(name string) (Placement, error) {
	placement := Placement(name)
	switch placement {
	case PlacementCloud, PlacementFog, PlacementHierarchical:
		return placement, nil
	}
	return "", fmt.Errorf("pdp: unknown placement %q (want cloud, fog or hierarchical)", name)
}

// DefaultTimeout is how long a RemoteClient waits for an answer when its
// Timeout is 0.
const DefaultTimeout = 2 * time.Second

// maxResponseSize is the largest response body a RemoteClient reads (1 MiB).
const maxResponseSize = 1 << 20

// RemoteClient asks a PDP over HTTP. It implements Decider.
type RemoteClient struct {
	BaseURL string        // e.g. "http://localhost:8181"
	Token   string        // bearer token for writes such as RecordSignal
	Timeout time.Duration // per request; 0 means DefaultTimeout
	// HTTP is the client to use. nil means a client that does not follow
	// redirects, so a decision can only come from BaseURL.
	HTTP *http.Client
}

// clientWithoutRedirects is the default HTTP client of a RemoteClient.
var clientWithoutRedirects = &http.Client{
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// Decide sends request to POST /v1/decide. Any failure (unreachable, timeout,
// a status other than 200, a body that is not a decision) returns a deny and
// the error, so a PEP fails closed.
func (client *RemoteClient) Decide(ctx context.Context, request model.AccessRequest) (model.Decision, error) {
	deny := model.Decision{Effect: model.Deny, Reason: "remote PDP unavailable"}
	response, err := client.post(ctx, "/v1/decide", request, "")
	if err != nil {
		return deny, err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return deny, statusError(response)
	}
	var decision model.Decision
	limitedBody := io.LimitReader(response.Body, maxResponseSize)
	if err := json.NewDecoder(limitedBody).Decode(&decision); err != nil {
		return deny, fmt.Errorf("pdp: decode decision: %w", err)
	}
	if decision.Effect != model.Allow && decision.Effect != model.Deny {
		return deny, fmt.Errorf("pdp: remote PDP returned effect %q", decision.Effect)
	}
	return decision, nil
}

// RecordSignal sends signal to POST /v1/signals with the client's token.
func (client *RemoteClient) RecordSignal(ctx context.Context, signal trust.Signal) error {
	response, err := client.post(ctx, "/v1/signals", signal, client.Token)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusNoContent {
		return statusError(response)
	}
	return nil
}

// post sends body as JSON to BaseURL+path within the client's timeout.
func (client *RemoteClient) post(ctx context.Context, path string, body any, bearerToken string) (*http.Response, error) {
	encodedBody, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	timeout := client.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.BaseURL+path, bytes.NewReader(encodedBody))
	if err != nil {
		cancel()
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	if bearerToken != "" {
		request.Header.Set("Authorization", "Bearer "+bearerToken)
	}
	httpClient := client.HTTP
	if httpClient == nil {
		httpClient = clientWithoutRedirects
	}
	response, err := httpClient.Do(request)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("pdp: %w", err)
	}
	response.Body = cancelOnClose{ReadCloser: response.Body, cancel: cancel}
	return response, nil
}

// cancelOnClose releases the request's timeout when the body is closed, so
// the caller can still read the body after post returns.
type cancelOnClose struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (body cancelOnClose) Close() error {
	err := body.ReadCloser.Close()
	body.cancel()
	return err
}

// statusError turns an unexpected response into an error that carries the
// status and the start of the body.
func statusError(response *http.Response) error {
	bodyStart, _ := io.ReadAll(io.LimitReader(response.Body, 512))
	return fmt.Errorf("pdp: remote PDP answered %s: %s", response.Status, bytes.TrimSpace(bodyStart))
}

// Chain asks each Decider in order and returns the first answer. A deny is an
// answer; only an error moves on to the next Decider. If none answers, the
// result is a deny and all errors joined.
type Chain []Decider

// Decide implements Decider.
func (chain Chain) Decide(ctx context.Context, request model.AccessRequest) (model.Decision, error) {
	failures := []error{errors.New("pdp: no decider answered")}
	for _, decider := range chain {
		decision, err := decider.Decide(ctx, request)
		if err == nil {
			return decision, nil
		}
		failures = append(failures, err)
	}
	return model.Decision{Effect: model.Deny, Reason: "no decider answered"}, errors.Join(failures...)
}

// DeciderFunc lets an ordinary function act as a Decider, for tests and
// small adapters.
type DeciderFunc func(ctx context.Context, request model.AccessRequest) (model.Decision, error)

// Decide calls decide.
func (decide DeciderFunc) Decide(ctx context.Context, request model.AccessRequest) (model.Decision, error) {
	return decide(ctx, request)
}

// Check at compile time that the deciders satisfy Decider.
var (
	_ Decider = (*RemoteClient)(nil)
	_ Decider = Chain(nil)
	_ Decider = DeciderFunc(nil)
)
