// Tests for the remote client against a real HTTP server, the decider chain
// and placement parsing.

package pdp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/model"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/observability"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/trust"
)

func TestParsePlacement(t *testing.T) {
	for _, name := range []string{"cloud", "fog", "hierarchical"} {
		if placement, err := ParsePlacement(name); err != nil || string(placement) != name {
			t.Errorf("ParsePlacement(%q) = %q, %v", name, placement, err)
		}
	}
	for _, name := range []string{"", "Cloud", "edge"} {
		if _, err := ParsePlacement(name); err == nil {
			t.Errorf("ParsePlacement(%q) = nil error", name)
		}
	}
}

// TestRemoteClient runs a real PDP behind a real HTTP server on localhost.
func TestRemoteClient(t *testing.T) {
	now := referenceTime
	server := httptest.NewServer(NewHandler(newPDP(t, &now), token, observability.NewRegistry()))
	defer server.Close()
	client := &RemoteClient{BaseURL: server.URL, Token: token}
	ctx := context.Background()

	if decision, err := client.Decide(ctx, writeTelemetry("bay-1")); err != nil || decision.Allowed() {
		t.Fatalf("unknown PMU: %+v, %v", decision, err)
	}
	for _, signal := range []trust.Signal{
		{Subject: pmu, Kind: trust.Authentication, Value: 0.8},
		{Subject: pmu, Kind: trust.Posture, Value: 1},
	} {
		if err := client.RecordSignal(ctx, signal); err != nil {
			t.Fatalf("RecordSignal() = %v", err)
		}
	}
	decision, err := client.Decide(ctx, writeTelemetry("bay-1"))
	if err != nil || !decision.Allowed() || decision.DecidedBy != "cloud-pdp" {
		t.Errorf("authenticated PMU: %+v, %v", decision, err)
	}

	wrong := &RemoteClient{BaseURL: server.URL, Token: "guess"}
	if err := wrong.RecordSignal(ctx, trust.Signal{Subject: pmu, Kind: trust.Authentication, Value: 1}); err == nil {
		t.Error("RecordSignal() with a wrong token = nil error")
	}
}

// TestRemoteClientFailsClosed checks that every way the remote PDP can fail
// gives a deny and an error.
func TestRemoteClientFailsClosed(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		timeout time.Duration
	}{
		{"server error", func(writer http.ResponseWriter, _ *http.Request) {
			http.Error(writer, "boom", http.StatusInternalServerError)
		}, 0},
		{"not JSON", func(writer http.ResponseWriter, _ *http.Request) { _, _ = writer.Write([]byte("allow")) }, 0},
		{"unknown effect", func(writer http.ResponseWriter, _ *http.Request) {
			_, _ = writer.Write([]byte(`{"effect":"maybe"}`))
		}, 0},
		{"redirect", func(writer http.ResponseWriter, request *http.Request) {
			http.Redirect(writer, request, "http://attacker.example/v1/decide", http.StatusTemporaryRedirect)
		}, 0},
		{"too slow", func(writer http.ResponseWriter, request *http.Request) {
			select {
			case <-request.Context().Done():
			case <-time.After(300 * time.Millisecond):
				_, _ = writer.Write([]byte(`{"effect":"allow"}`))
			}
		}, 50 * time.Millisecond},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			server := httptest.NewServer(testCase.handler)
			defer server.Close()
			client := &RemoteClient{BaseURL: server.URL, Timeout: testCase.timeout}
			startedAt := time.Now()
			decision, err := client.Decide(context.Background(), writeTelemetry("bay-1"))
			if err == nil || decision.Allowed() {
				t.Errorf("Decide() = %+v, %v, want a deny and an error", decision, err)
			}
			// The slow server answers "allow" after 300 ms; the client must
			// have given up long before.
			if elapsed := time.Since(startedAt); elapsed > 250*time.Millisecond {
				t.Errorf("Decide() took %v", elapsed)
			}
		})
	}
}

func TestRemoteClientUnreachable(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	server.Close() // nothing listens on this address any more
	decision, err := (&RemoteClient{BaseURL: server.URL}).Decide(context.Background(), writeTelemetry("bay-1"))
	if err == nil || decision.Allowed() {
		t.Errorf("Decide() = %+v, %v, want a deny and an error", decision, err)
	}
}

func TestChain(t *testing.T) {
	down := DeciderFunc(func(context.Context, model.AccessRequest) (model.Decision, error) {
		return model.Decision{Effect: model.Deny}, errors.New("down")
	})
	answer := func(effect model.Effect, decidedBy string, calls *int) Decider {
		return DeciderFunc(func(context.Context, model.AccessRequest) (model.Decision, error) {
			*calls++
			return model.Decision{Effect: effect, DecidedBy: decidedBy}, nil
		})
	}
	var firstCalls, secondCalls int
	tests := []struct {
		name          string
		chain         Chain
		want          model.Effect
		wantDecidedBy string
		wantError     bool
	}{
		{"first answers", Chain{answer(model.Allow, "fog", &firstCalls), answer(model.Allow, "cloud", &secondCalls)}, model.Allow, "fog", false},
		{"falls back on error", Chain{down, answer(model.Allow, "cloud", &secondCalls)}, model.Allow, "cloud", false},
		{"a deny is an answer", Chain{answer(model.Deny, "fog", &firstCalls), answer(model.Allow, "cloud", &secondCalls)}, model.Deny, "fog", false},
		{"all fail", Chain{down, down}, model.Deny, "", true},
		{"empty", Chain{}, model.Deny, "", true},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			decision, err := testCase.chain.Decide(context.Background(), writeTelemetry("bay-1"))
			gotError := err != nil
			if decision.Effect != testCase.want || decision.DecidedBy != testCase.wantDecidedBy || gotError != testCase.wantError {
				t.Errorf("Decide() = %+v, %v", decision, err)
			}
		})
	}
	if secondCalls != 1 {
		t.Errorf("the second decider was asked %d times, want 1 (only after an error)", secondCalls)
	}
	_, err := Chain{down, down}.Decide(context.Background(), writeTelemetry("bay-1"))
	if err == nil || strings.Count(err.Error(), "down") != 2 {
		t.Errorf("all errors should be joined: %v", err)
	}
}
