package token

import (
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/model"
)

// rootKey is a fixed 32-byte test key.
var rootKey = []byte("root-key-of-the-pdp-0123456789ab")

// offload is the capability an edge device hands a fog node for task t-7:
// execute, under substation-1/, task t-7, on fog or edge, before referenceTime + 30 s.
func offload(t *testing.T) Capability {
	t.Helper()
	capability, err := NewCapability(rootKey, "grant-42", "ztc-fog")
	if err != nil {
		t.Fatal(err)
	}
	return capability.Attenuate("action = execute").
		Attenuate("resource ^= substation-1/").
		Attenuate("task = t-7").
		Attenuate("layer <= fog").
		Attenuate("expires < " + strconv.FormatInt(referenceTime.Add(30*time.Second).Unix(), 10))
}

// fogRequest satisfies every caveat of offload.
func fogRequest() Request {
	return Request{Action: "execute", Resource: "substation-1/task/t-7", Task: "t-7", Layer: model.LayerFog, Now: referenceTime}
}

func TestCapabilityVerify(t *testing.T) {
	capability := offload(t)
	if err := capability.Verify(rootKey, StandardChecker(fogRequest())); err != nil {
		t.Fatalf("valid capability rejected: %v", err)
	}
	tests := []struct {
		name   string
		change func(*Request)
	}{
		{"other action", func(request *Request) { request.Action = "write" }},
		{"other substation", func(request *Request) { request.Resource = "substation-2/task/t-7" }},
		{"other task", func(request *Request) { request.Task = "t-8" }},
		{"cloud layer", func(request *Request) { request.Layer = model.LayerCloud }},
		{"unknown layer", func(request *Request) { request.Layer = model.LayerUnknown }},
		{"at expiry", func(request *Request) { request.Now = referenceTime.Add(30 * time.Second) }},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			request := fogRequest()
			testCase.change(&request)
			if err := capability.Verify(rootKey, StandardChecker(request)); !errors.Is(err, ErrCaveat) {
				t.Errorf("Verify error %v, want ErrCaveat", err)
			}
		})
	}
	edgeRequest := fogRequest()
	edgeRequest.Layer = model.LayerEdge
	if err := capability.Verify(rootKey, StandardChecker(edgeRequest)); err != nil {
		t.Errorf("layer <= fog must hold on the edge: %v", err)
	}
}

// TestCapabilityCannotBeWidened is the acceptance criterion of issue #15: a
// holder who changes the chain in any way breaks the signature.
func TestCapabilityCannotBeWidened(t *testing.T) {
	capability := offload(t)
	acceptsFogRequest := StandardChecker(fogRequest())
	tests := []struct {
		name   string
		change func(*Capability)
	}{
		{"last caveat removed", func(capability *Capability) { capability.Caveats = capability.Caveats[:len(capability.Caveats)-1] }},
		{"first caveat removed", func(capability *Capability) { capability.Caveats = capability.Caveats[1:] }},
		{"caveat changed", func(capability *Capability) { capability.Caveats[0] = "action = operate" }},
		{"caveats reordered", func(capability *Capability) {
			capability.Caveats[0], capability.Caveats[1] = capability.Caveats[1], capability.Caveats[0]
		}},
		{"all caveats removed", func(capability *Capability) { capability.Caveats = nil }},
		{"other grant", func(capability *Capability) { capability.ID = "grant-1" }},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			changed := capability
			changed.Caveats = append([]string(nil), capability.Caveats...)
			testCase.change(&changed)
			if err := changed.Verify(rootKey, acceptsFogRequest); !errors.Is(err, ErrCapabilitySignature) {
				t.Errorf("Verify error %v, want ErrCapabilitySignature", err)
			}
		})
	}
	if err := capability.Verify([]byte("another-root-key-0123456789abcde"), acceptsFogRequest); !errors.Is(err, ErrCapabilitySignature) {
		t.Errorf("wrong root key: %v", err)
	}
}

func TestAttenuateCopies(t *testing.T) {
	capability, err := NewCapability(rootKey, "grant-42", "ztc-fog")
	if err != nil {
		t.Fatal(err)
	}
	// Three caveats: a slice grown by append now has room for a fourth, so a
	// shared backing array would let b overwrite a's last caveat.
	parent := capability.Attenuate("action = execute").Attenuate("resource ^= substation-1/").Attenuate("layer <= fog")
	forTask1 := parent.Attenuate("task = t-1")
	forTask2 := parent.Attenuate("task = t-2")
	if len(parent.Caveats) != 3 || forTask1.Caveats[3] != "task = t-1" || forTask2.Caveats[3] != "task = t-2" {
		t.Errorf("Attenuate shares caveats: parent %q, a %q, b %q", parent.Caveats, forTask1.Caveats, forTask2.Caveats)
	}
}

func TestCapabilityFailsClosed(t *testing.T) {
	capability, err := NewCapability(rootKey, "grant-42", "ztc-fog")
	if err != nil {
		t.Fatal(err)
	}
	acceptsFogRequest := StandardChecker(fogRequest())
	if err := capability.Verify(rootKey, nil); err != nil {
		t.Errorf("no caveats, no checker: %v", err)
	}
	tests := []struct {
		name       string
		capability Capability
		check      CaveatChecker
	}{
		{"caveat without checker", capability.Attenuate("action = execute"), nil},
		{"unknown caveat", capability.Attenuate("colour = blue"), acceptsFogRequest},
		{"no spaces", capability.Attenuate("action=execute"), acceptsFogRequest},
		{"unknown operator", capability.Attenuate("action != write"), acceptsFogRequest},
		{"expiry not a number", capability.Attenuate("expires < soon"), acceptsFogRequest},
		{"layer not a layer", capability.Attenuate("layer <= moon"), acceptsFogRequest},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			if err := testCase.capability.Verify(rootKey, testCase.check); !errors.Is(err, ErrCaveat) {
				t.Errorf("Verify error %v, want ErrCaveat", err)
			}
		})
	}
	if _, err := NewCapability([]byte("short"), "grant-42", "ztc-fog"); !errors.Is(err, ErrRootKey) {
		t.Errorf("NewCapability with a short key: %v", err)
	}
	if err := capability.Verify([]byte("short"), acceptsFogRequest); !errors.Is(err, ErrRootKey) {
		t.Errorf("Verify with a short key: %v", err)
	}
	tooLong := capability
	for range MaxCaveats + 1 {
		tooLong = tooLong.Attenuate("action = execute")
	}
	if err := tooLong.Verify(rootKey, acceptsFogRequest); !errors.Is(err, ErrMalformed) {
		t.Errorf("%d caveats: %v", len(tooLong.Caveats), err)
	}
}

func TestCapabilityEncoding(t *testing.T) {
	capability := offload(t)
	got, err := DecodeCapability(capability.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if err := got.Verify(rootKey, StandardChecker(fogRequest())); err != nil {
		t.Errorf("decoded capability rejected: %v", err)
	}
	encode := func(text string) string { return base64URL.EncodeToString([]byte(text)) }
	for name, input := range map[string]string{
		"not base64url": "!!!",
		"not JSON":      encode("grant-42"),
		"no ID":         encode(`{"sig":"` + strings.Repeat("A", 43) + `="}`),
		"short sig":     encode(`{"id":"grant-42","sig":"AAAA"}`),
		"too long":      strings.Repeat("A", MaxTokenSize+1),
	} {
		if _, err := DecodeCapability(input); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: error %v, want ErrMalformed", name, err)
		}
	}
}
