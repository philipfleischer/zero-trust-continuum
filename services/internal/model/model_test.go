package model

import "testing"

func TestParseLayer(t *testing.T) {
	tests := []struct {
		input     string
		want      Layer
		wantError bool
	}{
		{"edge", LayerEdge, false},
		{"FOG", LayerFog, false},
		{"  cloud ", LayerCloud, false},
		{"datacenter", LayerUnknown, true},
		{"", LayerUnknown, true},
	}
	for _, testCase := range tests {
		got, err := ParseLayer(testCase.input)
		gotError := err != nil
		if gotError != testCase.wantError {
			t.Errorf("ParseLayer(%q) error = %v, wantError %v", testCase.input, err, testCase.wantError)
		}
		if got != testCase.want {
			t.Errorf("ParseLayer(%q) = %v, want %v", testCase.input, got, testCase.want)
		}
	}
}

func TestLayerStringRoundTrip(t *testing.T) {
	for _, layer := range []Layer{LayerEdge, LayerFog, LayerCloud} {
		got, err := ParseLayer(layer.String())
		if err != nil || got != layer {
			t.Errorf("ParseLayer(%v.String()) = %v, %v; want %v, nil", layer, got, err, layer)
		}
	}
	if name := LayerUnknown.String(); name != "unknown" {
		t.Errorf("LayerUnknown.String() = %q, want %q", name, "unknown")
	}
}

func TestDistance(t *testing.T) {
	tests := []struct {
		from, to Layer
		want     int
	}{
		{LayerEdge, LayerEdge, 0},
		{LayerEdge, LayerFog, 1},
		{LayerFog, LayerEdge, 1},
		{LayerCloud, LayerEdge, 2},
	}
	for _, testCase := range tests {
		if got := Distance(testCase.from, testCase.to); got != testCase.want {
			t.Errorf("Distance(%v, %v) = %d, want %d", testCase.from, testCase.to, got, testCase.want)
		}
	}
}

func TestDecisionAllowedFailsClosed(t *testing.T) {
	tests := []struct {
		name     string
		decision Decision
		want     bool
	}{
		{"explicit allow", Decision{Effect: Allow}, true},
		{"explicit deny", Decision{Effect: Deny}, false},
		{"zero value", Decision{}, false},
		{"unknown effect", Decision{Effect: "maybe"}, false},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			if got := testCase.decision.Allowed(); got != testCase.want {
				t.Errorf("Allowed() = %v, want %v", got, testCase.want)
			}
		})
	}
}
