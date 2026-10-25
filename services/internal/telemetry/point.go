// Package telemetry carries measurements from edge devices through fog
// aggregation to cloud storage: parsing, pipeline stages, time windows and a
// bounded store.
//
// The wire format is the InfluxDB line protocol: text, one point per line,
// and understood by Telegraf, InfluxDB, QuestDB and VictoriaMetrics.
//
//	pmu,substation=s1,bay=b3 voltage_kv=132.4,frequency_hz=49.98 1700000000000000000
//
// Industry equivalents: Telegraf, Kafka and Flink in front of InfluxDB or
// TimescaleDB; Azure IoT Hub or AWS IoT Core with Kinesis.
package telemetry

import (
	"errors"
	"fmt"
	"maps"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Point is one measurement: what was measured (Measurement), where and by
// which device (Tags), the values (Fields) and when (Time).
type Point struct {
	Measurement string             `json:"measurement"`
	Tags        map[string]string  `json:"tags"`
	Fields      map[string]float64 `json:"fields"`
	Time        time.Time          `json:"time"`
}

// ErrSyntax is returned for a line that is not valid line protocol.
var ErrSyntax = errors.New("telemetry: line protocol syntax error")

// The characters that must be escaped with a backslash in each element of a
// line. A backslash is always escaped too, so that Line and ParseLine undo
// each other.
const (
	measurementSpecials = ", "
	keyValueSpecials    = ",= "
)

// ParseLine parses one line of line protocol: a measurement with optional
// tags, at least one field and an optional timestamp in nanoseconds. Spaces,
// commas and equals signs can be escaped with a backslash. Field values are
// floats, integers (12i), unsigned integers (12u) or booleans, all stored as
// float64. A line without a timestamp gets a zero Time, which the receiver
// replaces with the arrival time.
func ParseLine(line string) (Point, error) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return Point{}, fmt.Errorf("%w: empty line or comment", ErrSyntax)
	}
	sections := withoutEmpty(splitUnescaped(line, ' '))
	if len(sections) < 2 || len(sections) > 3 {
		return Point{}, fmt.Errorf("%w: want measurement, fields and an optional timestamp", ErrSyntax)
	}
	point, err := parseSeries(sections[0])
	if err != nil {
		return Point{}, err
	}
	if point.Fields, err = parseFields(sections[1]); err != nil {
		return Point{}, err
	}
	if len(sections) == 3 {
		nanoseconds, err := strconv.ParseInt(sections[2], 10, 64)
		if err != nil {
			return Point{}, fmt.Errorf("%w: timestamp %q", ErrSyntax, sections[2])
		}
		point.Time = time.Unix(0, nanoseconds)
	}
	return point, nil
}

// ParseLines parses a body with one point per line, as a device sends a batch
// in one request. Blank lines and comments are skipped. It returns the points
// it could parse and the number of lines it rejected, so one bad line does
// not cost the rest of the batch.
func ParseLines(body string) (points []Point, rejected int) {
	for line := range strings.Lines(body) {
		line = strings.TrimSpace(line)
		isBlankOrComment := line == "" || strings.HasPrefix(line, "#")
		if isBlankOrComment {
			continue
		}
		point, err := ParseLine(line)
		if err != nil {
			rejected++
			continue
		}
		points = append(points, point)
	}
	return points, rejected
}

// Line formats the point as line protocol. Tags and fields are sorted by key,
// so the same point always gives the same line. A zero Time is left out.
func (point Point) Line() string {
	var builder strings.Builder
	builder.WriteString(point.Key())
	builder.WriteByte(' ')
	for i, key := range slices.Sorted(maps.Keys(point.Fields)) {
		if i > 0 {
			builder.WriteByte(',')
		}
		builder.WriteString(escape(key, keyValueSpecials))
		builder.WriteByte('=')
		builder.WriteString(strconv.FormatFloat(point.Fields[key], 'g', -1, 64))
	}
	if !point.Time.IsZero() {
		builder.WriteByte(' ')
		builder.WriteString(strconv.FormatInt(point.Time.UnixNano(), 10))
	}
	return builder.String()
}

// Key identifies the series the point belongs to: the measurement and its
// tags, escaped and sorted as in Line. The escaping keeps series apart that
// would otherwise get the same key, such as one tag bay="1,phase=a" and the
// two tags bay=1 and phase=a.
func (point Point) Key() string {
	var builder strings.Builder
	builder.WriteString(escape(point.Measurement, measurementSpecials))
	for _, key := range slices.Sorted(maps.Keys(point.Tags)) {
		builder.WriteByte(',')
		builder.WriteString(escape(key, keyValueSpecials))
		builder.WriteByte('=')
		builder.WriteString(escape(point.Tags[key], keyValueSpecials))
	}
	return builder.String()
}

// parseSeries parses the first section of a line, "measurement,tag=value,...",
// into a point without fields.
func parseSeries(section string) (Point, error) {
	parts := splitUnescaped(section, ',')
	point := Point{Measurement: unescape(parts[0]), Tags: map[string]string{}}
	if point.Measurement == "" {
		return Point{}, fmt.Errorf("%w: empty measurement", ErrSyntax)
	}
	for _, pair := range parts[1:] {
		key, rawValue, err := splitKeyValue(pair)
		if err != nil {
			return Point{}, err
		}
		if _, found := point.Tags[key]; found {
			return Point{}, fmt.Errorf("%w: tag %q appears twice", ErrSyntax, key)
		}
		point.Tags[key] = unescape(rawValue)
	}
	return point, nil
}

// parseFields parses the second section of a line, "field=value,...".
func parseFields(section string) (map[string]float64, error) {
	fields := map[string]float64{}
	for _, pair := range splitUnescaped(section, ',') {
		key, rawValue, err := splitKeyValue(pair)
		if err != nil {
			return nil, err
		}
		if _, found := fields[key]; found {
			return nil, fmt.Errorf("%w: field %q appears twice", ErrSyntax, key)
		}
		value, ok := parseFieldValue(rawValue)
		if !ok {
			return nil, fmt.Errorf("%w: field %q has value %q", ErrSyntax, key, rawValue)
		}
		fields[key] = value
	}
	return fields, nil
}

// splitKeyValue splits "key=value" at the unescaped equals sign. It returns
// the key without escapes and the value as written, and refuses an empty key
// or value.
func splitKeyValue(pair string) (key, rawValue string, err error) {
	parts := splitUnescaped(pair, '=')
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("%w: %q is not key=value", ErrSyntax, pair)
	}
	return unescape(parts[0]), parts[1], nil
}

// parseFieldValue reads a float, an integer (12i), an unsigned integer (12u)
// or a boolean as a float64. NaN and infinities are refused: a single one
// would turn every mean and z-score computed from the series into NaN.
func parseFieldValue(rawValue string) (float64, bool) {
	switch rawValue {
	case "t", "T", "true", "True", "TRUE":
		return 1, true
	case "f", "F", "false", "False", "FALSE":
		return 0, true
	}
	if digits, isInteger := strings.CutSuffix(rawValue, "i"); isInteger {
		value, err := strconv.ParseInt(digits, 10, 64)
		return float64(value), err == nil
	}
	if digits, isUnsigned := strings.CutSuffix(rawValue, "u"); isUnsigned {
		value, err := strconv.ParseUint(digits, 10, 64)
		return float64(value), err == nil
	}
	value, err := strconv.ParseFloat(rawValue, 64)
	isFinite := !math.IsNaN(value) && !math.IsInf(value, 0)
	return value, err == nil && isFinite
}

// splitUnescaped splits text at every separator that is not escaped with a
// backslash. The parts keep their escapes; unescape removes them.
func splitUnescaped(text string, separator byte) []string {
	var parts []string
	start := 0
	for i := 0; i < len(text); i++ {
		switch text[i] {
		case '\\':
			i++ // the next byte is escaped, whatever it is
		case separator:
			parts = append(parts, text[start:i])
			start = i + 1
		}
	}
	return append(parts, text[start:])
}

// unescape removes the backslashes that escape the byte after them.
func unescape(text string) string {
	if !strings.Contains(text, `\`) {
		return text
	}
	var builder strings.Builder
	for i := 0; i < len(text); i++ {
		isEscape := text[i] == '\\' && i+1 < len(text)
		if isEscape {
			i++
		}
		builder.WriteByte(text[i])
	}
	return builder.String()
}

// escape puts a backslash in front of every backslash and every byte in specials.
func escape(text, specials string) string {
	var builder strings.Builder
	for i := 0; i < len(text); i++ {
		needsEscape := text[i] == '\\' || strings.IndexByte(specials, text[i]) >= 0
		if needsEscape {
			builder.WriteByte('\\')
		}
		builder.WriteByte(text[i])
	}
	return builder.String()
}

// withoutEmpty drops empty strings, so that several spaces between the
// sections of a line are accepted.
func withoutEmpty(parts []string) []string {
	return slices.DeleteFunc(parts, func(part string) bool { return part == "" })
}
