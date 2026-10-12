// Package model holds the domain types that are shared by all ZTC services:
// the continuum layers, device classes, and the access request / decision pair
// that flows between a Policy Enforcement Point (PEP) and a Policy Decision Point (PDP).
//
// Keeping these types in one small package with no dependencies avoids import cycles between policy, trust, pdp and pep.
package model

import (
	"fmt"
	"strings"
)

// Layer is a tier of the edge-fog-cloud continuum.
//
// The numeric order matters: a higher value is further from the physical process, so rules can compare layers numerically.
type Layer int

const (
	// LayerUnknown is the zero value and is never trusted.
	LayerUnknown Layer = iota
	// LayerEdge is Purdue level 0-1: sensors, actuators, IEDs, PMUs, RTUs, smart meters.
	LayerEdge
	// LayerFog is Purdue level 2-3.5: substation gateways, fog nodes, the industrial DMZ.
	LayerFog
	// LayerCloud is Purdue level 4-5: control centre, enterprise IT, public or private cloud.
	LayerCloud
)

// String returns the lower-case name used in SPIFFE paths, config files and metric labels.
func (layer Layer) String() string {
	switch layer {
	case LayerEdge:
		return "edge"
	case LayerFog:
		return "fog"
	case LayerCloud:
		return "cloud"
	default:
		return "unknown"
	}
}

// ParseLayer converts "edge", "fog" or "cloud" (case-insensitive, surrounding spaces ignored)
// to a Layer. Anything else is an error.
func ParseLayer(name string) (Layer, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "edge":
		return LayerEdge, nil
	case "fog":
		return LayerFog, nil
	case "cloud":
		return LayerCloud, nil
	}
	return LayerUnknown, fmt.Errorf("model: unknown layer %q", name)
}

// Distance returns how many layer hops separate from and to (0, 1 or 2).
func Distance(from, to Layer) int {
	hops := int(from) - int(to)
	if hops < 0 {
		hops = -hops
	}
	return hops
}

// DeviceClass describes how capable and how exposed a device is.
// The trust algorithm and the crypto cost model use it: a constrained sensor cannot do a TLS handshake every second.
type DeviceClass string

const (
	// ClassConstrained is an RFC 7228 class 0/1 device (microcontroller, a few kB of RAM).
	ClassConstrained DeviceClass = "constrained"
	// ClassIED is an intelligent electronic device (protection relay, bay controller).
	ClassIED DeviceClass = "ied"
	// ClassGateway is an embedded Linux box (Raspberry Pi class, substation gateway).
	ClassGateway DeviceClass = "gateway"
	// ClassServer is a rack server in a fog micro data center or in the cloud.
	ClassServer DeviceClass = "server"
	// ClassWorkstation is a human operator or engineering workstation.
	ClassWorkstation DeviceClass = "workstation"
)
