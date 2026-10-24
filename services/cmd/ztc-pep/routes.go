// The routes file of ztc-pep: the same routes as pep.Route, with the layer
// written as a word.

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/model"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/pep"
)

// routeEntry is one route in the file. It differs from pep.Route only in the
// layer, which is "edge", "fog" or "cloud" instead of a number.
type routeEntry struct {
	Prefix       string `json:"prefix"`
	Upstream     string `json:"upstream"`
	ResourceType string `json:"resourceType"`
	Zone         string `json:"zone"`
	Layer        string `json:"layer"`
	Sensitivity  int    `json:"sensitivity"`
}

// loadRoutes reads the JSON array of routes at path and checks it with
// pep.NewRouteTable. A file without routes is an error, because a PEP that
// protects nothing has most likely been given the wrong file. Unknown fields
// are errors too, so a misspelt field name is reported instead of ignored.
func loadRoutes(path string) (*pep.RouteTable, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var entries []routeEntry
	if err := decoder.Decode(&entries); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("%s: %w", path, errors.New("no routes"))
	}
	routes := make([]pep.Route, 0, len(entries))
	for _, entry := range entries {
		layer, err := model.ParseLayer(entry.Layer)
		if err != nil {
			return nil, fmt.Errorf("%s: route %s: %w", path, entry.Prefix, err)
		}
		routes = append(routes, pep.Route{
			Prefix:       entry.Prefix,
			Upstream:     entry.Upstream,
			ResourceType: entry.ResourceType,
			Zone:         entry.Zone,
			Layer:        layer,
			Sensitivity:  entry.Sensitivity,
		})
	}
	table, err := pep.NewRouteTable(routes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return table, nil
}
