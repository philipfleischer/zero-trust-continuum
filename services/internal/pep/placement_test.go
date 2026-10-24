// Tests for the placements of RQ1.

package pep

import (
	"context"
	"testing"
	"time"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/model"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/pdp"
)

func TestDeciderForCloud(t *testing.T) {
	cloudPDP := allowEverything()
	decider, err := DeciderFor(pdp.PlacementCloud, cloudPDP, "fog-cache", 100)
	if err != nil || decider != pdp.Decider(cloudPDP) {
		t.Errorf("cloud placement = %v, %v; want the cloud PDP itself", decider, err)
	}
}

func TestDeciderForHierarchical(t *testing.T) {
	cloudPDP := &fakeDecider{answer: func(model.AccessRequest) (model.Decision, error) {
		return model.Decision{Effect: model.Allow, TTL: time.Minute, DecidedBy: "cloud-pdp"}, nil
	}}
	decider, err := DeciderFor(pdp.PlacementHierarchical, cloudPDP, "fog-cache", 100)
	if err != nil {
		t.Fatal(err)
	}
	accessRequest := model.AccessRequest{Subject: model.Subject{ID: "spiffe://grid.example/edge/pmu/1"}, Action: "write"}
	for range 3 {
		if _, err := decider.Decide(context.Background(), accessRequest); err != nil {
			t.Fatal(err)
		}
	}
	decision, _ := decider.Decide(context.Background(), accessRequest)
	if cloudPDP.timesAsked() != 1 || decision.DecidedBy != "fog-cache" {
		t.Errorf("cloud PDP asked %d times, last decided by %q; want 1 and fog-cache", cloudPDP.timesAsked(), decision.DecidedBy)
	}
}

func TestDeciderForRefuses(t *testing.T) {
	for _, placement := range []pdp.Placement{pdp.PlacementFog, "edge", ""} {
		if decider, err := DeciderFor(placement, allowEverything(), "fog-cache", 100); err == nil {
			t.Errorf("placement %q gave %v, want an error", placement, decider)
		}
	}
}
