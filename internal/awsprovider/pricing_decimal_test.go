package awsprovider

import (
	"math"
	"testing"
)

func TestDecimalMicrosUsesDeterministicHalfUpRounding(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value string
		want  uint64
	}{
		{name: "integer", value: "12", want: 12_000_000},
		{name: "six decimals", value: "0.123456", want: 123_456},
		{name: "round down", value: "0.1234564", want: 123_456},
		{name: "round half up", value: "0.1234565", want: 123_457},
		{name: "smallest rounded micro", value: "0.0000005", want: 1},
		{name: "maximum", value: "18446744073709.551615", want: math.MaxUint64},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := decimalMicros(test.value)
			if err != nil {
				t.Fatalf("decimalMicros(%q): %v", test.value, err)
			}
			if got != test.want {
				t.Fatalf("decimalMicros(%q) = %d, want %d", test.value, got, test.want)
			}
		})
	}
}

func TestDecimalMicrosRejectsInvalidOrOverflowingValues(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"", "-0.01", "+1", "1e-3", " 1", "1.", ".1", "18446744073709.5516155"} {
		if _, err := decimalMicros(value); err == nil {
			t.Fatalf("decimalMicros(%q) unexpectedly succeeded", value)
		}
	}
}

func TestScaleMicrosRoundsRationalQuantitiesWithoutFloatingPoint(t *testing.T) {
	t.Parallel()

	got, err := scaleMicros(500_000, 1536, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if got != 750_000 {
		t.Fatalf("scaleMicros = %d, want 750000", got)
	}
	if _, err := scaleMicros(math.MaxUint64, 2, 1); err == nil {
		t.Fatal("expected overflow")
	}
	if _, err := scaleMicros(1, 1, 0); err == nil {
		t.Fatal("expected zero denominator error")
	}
}
