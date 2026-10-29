// Package devices simulates the field devices of a digital substation, so
// the whole system runs without hardware:
//
//   - PMU (phasor measurement unit): voltage and grid frequency
//   - smart meter: active and reactive power following a daily load profile
//   - breaker IED: breaker position and operation counter
//   - RTU: transformer tap position and oil temperature
//   - EV charger: charging power in the evening
//
// A device with a given seed produces the same samples for the same times,
// so experiments can be repeated. attack.go adds compromised variants that
// the IDS and the trust score are tested against.
package devices

import (
	"fmt"
	"math"
	"math/rand/v2"
	"slices"
	"strings"
	"time"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/telemetry"
)

// Kind is the type of a device. It is also the measurement name of its
// samples.
type Kind string

// The kinds of device in the simulated substation.
const (
	PMU       Kind = "pmu"
	Meter     Kind = "meter"
	Breaker   Kind = "breaker"
	RTU       Kind = "rtu"
	EVCharger Kind = "evcharger"
)

// kinds lists every Kind, for validation and error messages.
var kinds = []Kind{PMU, Meter, Breaker, RTU, EVCharger}

// ParseKind returns the Kind called name, ignoring case, or an error that
// lists the known kinds.
func ParseKind(name string) (Kind, error) {
	kind := Kind(strings.ToLower(name))
	if !slices.Contains(kinds, kind) {
		return "", fmt.Errorf("devices: unknown kind %q, want one of %v", name, kinds)
	}
	return kind, nil
}

// Device is one simulated field device. It is not safe for concurrent use:
// each device belongs to the goroutine that samples it.
type Device struct {
	ID         string // the last part of its SPIFFE ID, such as "pmu-b1-1"
	Kind       Kind
	Substation string
	Bay        string

	random            *rand.Rand
	isBreakerClosed   bool
	breakerOperations int
}

// New returns a device whose noise comes from a random source seeded with
// seed. An unknown kind is an error, so a typo in the configuration stops
// ztc-edge instead of producing a device that sends nothing.
func New(id string, kind Kind, substation, bay string, seed uint64) (*Device, error) {
	if !slices.Contains(kinds, kind) {
		return nil, fmt.Errorf("devices: unknown kind %q, want one of %v", kind, kinds)
	}
	return &Device{
		ID:              id,
		Kind:            kind,
		Substation:      substation,
		Bay:             bay,
		random:          rand.New(rand.NewPCG(seed, seed)), //nolint:gosec // G404: simulated measurement noise, not a secret
		isBreakerClosed: true,
	}, nil
}

// Trip opens the breaker and counts the operation, as a protection relay
// would. It does nothing for other kinds.
func (device *Device) Trip() {
	if device.Kind != Breaker || !device.isBreakerClosed {
		return
	}
	device.isBreakerClosed = false
	device.breakerOperations++
}

// Sample returns the measurement of the device at the given time:
//
//	pmu        voltage_kv   132 kV ± 1 % over a minute, plus noise
//	           frequency_hz 50 Hz ± 0.02 Hz over five minutes, plus noise
//	meter      power_kw, reactive_power_kvar  daily load profile, plus noise
//	breaker    closed (1 or 0), operations
//	rtu        tap_position (1–17), oil_temperature_c  follow the load
//	evcharger  power_kw  11 kW from 17:00 to 23:00 UTC, otherwise 0
//
// The daily profiles use UTC, so the same time gives the same sample on
// every machine, whatever its time zone.
func (device *Device) Sample(at time.Time) telemetry.Point {
	fields := map[string]float64{}
	switch device.Kind {
	case PMU:
		seconds := float64(at.UnixNano()) / 1e9
		fields["voltage_kv"] = 132*(1+0.01*math.Sin(2*math.Pi*seconds/60)) + device.random.NormFloat64()*0.2
		fields["frequency_hz"] = 50 + 0.02*math.Sin(2*math.Pi*seconds/300) + device.random.NormFloat64()*0.005
	case Meter:
		power := math.Max(0, 5*loadProfile(at)+device.random.NormFloat64()*0.2)
		fields["power_kw"] = power
		fields["reactive_power_kvar"] = power * 0.3
	case Breaker:
		fields["closed"] = 0
		if device.isBreakerClosed {
			fields["closed"] = 1
		}
		fields["operations"] = float64(device.breakerOperations)
	case RTU:
		load := loadProfile(at)
		fields["tap_position"] = math.Round(9 + 4*(load-0.6))
		fields["oil_temperature_c"] = 55 + 20*load + device.random.NormFloat64()*0.3
	case EVCharger:
		hour := at.UTC().Hour()
		isCharging := hour >= 17 && hour < 23
		fields["power_kw"] = 0
		if isCharging {
			fields["power_kw"] = 11
		}
	}
	return telemetry.Point{
		Measurement: string(device.Kind),
		Tags:        map[string]string{"device": device.ID, "substation": device.Substation, "bay": device.Bay},
		Fields:      fields,
		Time:        at,
	}
}

// loadProfile returns the share of peak load at the given time, between 0.3
// at night and about 1 at the evening peak, with a smaller morning peak.
func loadProfile(at time.Time) float64 {
	utc := at.UTC()
	hour := float64(utc.Hour()) + float64(utc.Minute())/60
	peak := func(center, width float64) float64 {
		distance := hour - center
		return math.Exp(-distance * distance / (2 * width * width))
	}
	return 0.3 + 0.35*peak(8, 1.5) + 0.55*peak(18, 2)
}
