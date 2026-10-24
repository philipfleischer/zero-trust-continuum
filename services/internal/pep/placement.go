// Placement: where the PEP gets its decisions from, the variable of RQ1.

package pep

import (
	"fmt"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/pdp"
)

// DeciderFor returns the decider of a placement in front of cloudPDP, the
// client of the PDP in the cloud:
//
//	cloud         cloudPDP itself: every decision is fresh, none is available
//	              while the cloud cannot be reached
//	hierarchical  a decision cache on this node, called cacheName and holding
//	              at most cacheSize allows, in front of cloudPDP
//
// The fog placement needs a full PDP replica on the node, which comes with
// Raft in M3, so it is an error here, like any unknown placement.
func DeciderFor(placement pdp.Placement, cloudPDP pdp.Decider, cacheName string, cacheSize int) (pdp.Decider, error) {
	switch placement {
	case pdp.PlacementCloud:
		return cloudPDP, nil
	case pdp.PlacementHierarchical:
		return pdp.NewCache(cacheName, cloudPDP, cacheSize), nil
	case pdp.PlacementFog:
		return nil, fmt.Errorf("pep: placement %q needs a PDP replica, which comes with Raft in M3", placement)
	}
	return nil, fmt.Errorf("pep: unknown placement %q", placement)
}
