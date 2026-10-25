// Tests for the line-protocol parser: valid and invalid lines, the round
// trip through Line, series keys and batches, and a fuzz target that looks
// for lines the round trip gets wrong.

package telemetry

import (
	"errors"
	"maps"
	"testing"
	"time"
)

// samePoint reports whether two points have the same measurement, tags,
// fields and time. Times are compared with Equal, since the same instant can
// be stored with different locations.
func samePoint(first, second Point) bool {
	return first.Measurement == second.Measurement &&
		maps.Equal(first.Tags, second.Tags) &&
		maps.Equal(first.Fields, second.Fields) &&
		first.Time.Equal(second.Time)
}

func TestParseLine(t *testing.T) {
	tests := []struct {
		name string
		line string
		want Point
	}{
		{
			name: "PMU with tags and timestamp",
			line: "pmu,substation=s1,bay=b3 voltage_kv=132.4,frequency_hz=49.98 1700000000000000000",
			want: Point{
				Measurement: "pmu",
				Tags:        map[string]string{"substation": "s1", "bay": "b3"},
				Fields:      map[string]float64{"voltage_kv": 132.4, "frequency_hz": 49.98},
				Time:        time.Unix(0, 1700000000000000000),
			},
		},
		{
			name: "no tags and no timestamp",
			line: "meter power_kw=3.5",
			want: Point{Measurement: "meter", Tags: map[string]string{}, Fields: map[string]float64{"power_kw": 3.5}},
		},
		{
			name: "escaped space, comma and equals sign",
			line: `pmu\ main,bay\=id=b\,3\ west phase\ a=1`,
			want: Point{
				Measurement: "pmu main",
				Tags:        map[string]string{"bay=id": "b,3 west"},
				Fields:      map[string]float64{"phase a": 1},
			},
		},
		{
			name: "escaped backslash at the end of a tag value",
			line: `rtu,path=c:\\ status=1`,
			want: Point{Measurement: "rtu", Tags: map[string]string{"path": `c:\`}, Fields: map[string]float64{"status": 1}},
		},
		{
			name: "integer, unsigned, boolean and exponent values",
			line: "breaker trips=3i,count=7u,closed=true,open=F,current=-1.5e3",
			want: Point{
				Measurement: "breaker",
				Tags:        map[string]string{},
				Fields:      map[string]float64{"trips": 3, "count": 7, "closed": 1, "open": 0, "current": -1500},
			},
		},
		{
			name: "several spaces between sections",
			line: "  meter   power_kw=1   5  ",
			want: Point{Measurement: "meter", Tags: map[string]string{}, Fields: map[string]float64{"power_kw": 1}, Time: time.Unix(0, 5)},
		},
		{
			name: "negative timestamp is before 1970",
			line: "meter power_kw=1 -1000000000",
			want: Point{Measurement: "meter", Tags: map[string]string{}, Fields: map[string]float64{"power_kw": 1}, Time: time.Unix(-1, 0)},
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			got, err := ParseLine(testCase.line)
			if err != nil {
				t.Fatalf("ParseLine(%q): %v", testCase.line, err)
			}
			if !samePoint(got, testCase.want) {
				t.Errorf("ParseLine(%q) = %+v, want %+v", testCase.line, got, testCase.want)
			}
		})
	}
}

func TestParseLineRejects(t *testing.T) {
	tests := []struct {
		name string
		line string
	}{
		{"empty line", ""},
		{"only spaces", "   "},
		{"comment", "# pmu voltage_kv=1"},
		{"no fields", "pmu"},
		{"no fields after tags", "pmu,bay=b3"},
		{"four sections", "pmu voltage_kv=1 5 6"},
		{"empty measurement", ",bay=b3 voltage_kv=1"},
		{"tag without value", "pmu,bay= voltage_kv=1"},
		{"tag without key", "pmu,=b3 voltage_kv=1"},
		{"tag without equals sign", "pmu,bay voltage_kv=1"},
		{"unescaped equals sign in a tag value", "pmu,bay=b=3 voltage_kv=1"},
		{"same tag twice", "pmu,bay=b3,bay=b4 voltage_kv=1"},
		{"field without value", "pmu voltage_kv="},
		{"field without key", "pmu =1"},
		{"empty field between commas", "pmu voltage_kv=1,,frequency_hz=50"},
		{"same field twice", "pmu voltage_kv=1,voltage_kv=900"},
		{"string field", `pmu status="ok"`},
		{"NaN", "pmu voltage_kv=NaN"},
		{"infinity", "pmu voltage_kv=+Inf"},
		{"too large for float64", "pmu voltage_kv=1e400"},
		{"integer with decimals", "pmu trips=1.5i"},
		{"negative unsigned", "pmu count=-1u"},
		{"timestamp that is not a number", "pmu voltage_kv=1 yesterday"},
		{"timestamp with decimals", "pmu voltage_kv=1 1.5"},
		{"escaped space hides the fields", `pmu,bay=b3\ voltage_kv=1`},

		// The first two were found by FuzzParseLineRoundTrip: accepted, but
		// Line turned them into something else. The rest are the same flaw
		// with other control characters.
		{"measurement that starts with #", `\#pmu voltage_kv=1`},
		{"line break in a field key", "pmu voltage\n_kv=1"},
		{"line break in a tag value", "pmu,bay=b3\npmu voltage_kv=1"},
		{"carriage return", "pmu,bay=b3\r voltage_kv=1"},
		{"tab", "pmu,bay=b\t3 voltage_kv=1"},
		{"NUL byte", "pmu,bay=b3\x00 voltage_kv=1"},
		{"DEL", "pmu,bay=b3\x7f voltage_kv=1"},
		{"C1 control character", "pmu,bay=b3\u0085 voltage_kv=1"},
		{"invalid UTF-8", "pmu,bay=b\xff3 voltage_kv=1"},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			point, err := ParseLine(testCase.line)
			if !errors.Is(err, ErrSyntax) {
				t.Errorf("ParseLine(%q) = %+v, %v; want ErrSyntax", testCase.line, point, err)
			}
		})
	}
}

// TestLineRoundTrip builds points in Go, so it also covers characters that
// no hand-written line in the tables above happens to use.
func TestLineRoundTrip(t *testing.T) {
	points := []Point{
		{Measurement: "pmu", Tags: map[string]string{"bay": "b3"}, Fields: map[string]float64{"voltage_kv": 132.4}, Time: time.Unix(0, 1700000000000000000)},
		{Measurement: "a b,c", Tags: map[string]string{"k=1 ,": `v\ =,`}, Fields: map[string]float64{"f, =": -0.1}},
		{Measurement: "meter", Tags: map[string]string{}, Fields: map[string]float64{"tiny": 5e-324, "huge": 1.7976931348623157e308, "zero": 0}},
		{Measurement: "måler", Tags: map[string]string{"stasjon": "Østre"}, Fields: map[string]float64{"effekt": 1}},
	}
	for _, point := range points {
		line := point.Line()
		got, err := ParseLine(line)
		if err != nil {
			t.Errorf("ParseLine(%q): %v", line, err)
			continue
		}
		if !samePoint(got, point) {
			t.Errorf("ParseLine(%q) = %+v, want %+v", line, got, point)
		}
	}
}

// TestLineIsSorted checks that map order cannot change the line: Go iterates
// maps in a random order, so an unsorted Line would differ between runs.
func TestLineIsSorted(t *testing.T) {
	point := Point{
		Measurement: "pmu",
		Tags:        map[string]string{"substation": "s1", "bay": "b3", "phase": "a"},
		Fields:      map[string]float64{"voltage_kv": 132.4, "frequency_hz": 49.98, "angle": -12},
		Time:        time.Unix(0, 42),
	}
	want := "pmu,bay=b3,phase=a,substation=s1 angle=-12,frequency_hz=49.98,voltage_kv=132.4 42"
	for range 20 {
		if got := point.Line(); got != want {
			t.Fatalf("Line() = %q, want %q", got, want)
		}
	}
}

func TestKeyKeepsSeriesApart(t *testing.T) {
	oneTag := Point{Measurement: "pmu", Tags: map[string]string{"bay": "1,phase=a"}}
	twoTags := Point{Measurement: "pmu", Tags: map[string]string{"bay": "1", "phase": "a"}}
	if oneTag.Key() == twoTags.Key() {
		t.Errorf("both points have the key %q", oneTag.Key())
	}

	measurementWithComma := Point{Measurement: "pmu,bay=1"}
	measurementWithTag := Point{Measurement: "pmu", Tags: map[string]string{"bay": "1"}}
	if measurementWithComma.Key() == measurementWithTag.Key() {
		t.Errorf("both points have the key %q", measurementWithComma.Key())
	}

	sameSeriesLater := Point{Measurement: "pmu", Tags: map[string]string{"bay": "1", "phase": "a"}, Fields: map[string]float64{"voltage_kv": 1}, Time: time.Unix(5, 0)}
	if sameSeriesLater.Key() != twoTags.Key() {
		t.Errorf("Key() = %q, want %q: fields and time are not part of the series", sameSeriesLater.Key(), twoTags.Key())
	}
}

func TestParseLines(t *testing.T) {
	body := "# batch from pmu-1\r\n" +
		"pmu,bay=b3 voltage_kv=132.4 1\r\n" +
		"\r\n" +
		"pmu,bay=b3 voltage_kv=NaN 2\r\n" +
		"   \n" +
		"pmu,bay=b3 voltage_kv=132.5 3" // the last line has no line break
	points, rejected := ParseLines(body)
	if rejected != 1 {
		t.Errorf("rejected = %d, want 1 (the NaN line)", rejected)
	}
	if len(points) != 2 {
		t.Fatalf("got %d points, want 2: %+v", len(points), points)
	}
	if points[0].Fields["voltage_kv"] != 132.4 || points[1].Fields["voltage_kv"] != 132.5 {
		t.Errorf("points = %+v, want 132.4 then 132.5 in the order they were sent", points)
	}

	points, rejected = ParseLines("")
	if len(points) != 0 || rejected != 0 {
		t.Errorf("ParseLines(\"\") = %v, %d; want nothing", points, rejected)
	}
}

// FuzzParseLineRoundTrip feeds ParseLine random variations of the seed lines.
// Whatever it accepts must survive Line unchanged, and must come back as
// exactly one point when sent as a batch: a point that turns into two lines
// would let one value inject a forged measurement into the fog node's
// upstream batch. `go test` runs only the seeds; `go test -fuzz` searches.
func FuzzParseLineRoundTrip(f *testing.F) {
	seeds := []string{
		"pmu,substation=s1,bay=b3 voltage_kv=132.4,frequency_hz=49.98 1700000000000000000",
		`pmu\ main,bay\=id=b\,3\ west phase\ a=1`,
		`rtu,path=c:\\ status=1`,
		"breaker trips=3i,count=7u,closed=true,open=F,current=-1.5e3",
		"meter power_kw=1 -1000000000",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, line string) {
		point, err := ParseLine(line)
		if err != nil {
			return // rejecting is always allowed
		}
		formatted := point.Line()
		again, err := ParseLine(formatted)
		if err != nil {
			t.Fatalf("ParseLine(%q) accepted, but its Line %q is rejected: %v", line, formatted, err)
		}
		if !samePoint(again, point) {
			t.Fatalf("ParseLine(%q) = %+v, but its Line %q parses as %+v", line, point, formatted, again)
		}
		points, rejected := ParseLines(formatted)
		if len(points) != 1 || rejected != 0 {
			t.Fatalf("the Line %q of %q is %d points and %d rejected lines in a batch, want one point", formatted, line, len(points), rejected)
		}
	})
}
