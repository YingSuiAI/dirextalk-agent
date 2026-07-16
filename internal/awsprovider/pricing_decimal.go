package awsprovider

import (
	"errors"
	"math"
	"math/big"
	"regexp"
	"strings"
)

var unsignedDecimalPattern = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+)?$`)

// decimalMicros converts an AWS decimal price to integer currency micros. AWS
// price-list and Spot APIs expose prices as decimal strings; retaining that
// representation here prevents binary floating-point amounts from entering a
// quote. Fractions beyond six places are rounded half up.
func decimalMicros(value string) (uint64, error) {
	if !unsignedDecimalPattern.MatchString(value) {
		return 0, errors.New("price must be an unsigned plain decimal")
	}
	parts := strings.SplitN(value, ".", 2)
	fraction := ""
	if len(parts) == 2 {
		fraction = parts[1]
	}
	padded := fraction
	if len(padded) < 6 {
		padded += strings.Repeat("0", 6-len(padded))
	}
	if len(padded) > 6 {
		padded = padded[:6]
	}

	result := new(big.Int)
	if _, ok := result.SetString(parts[0]+padded, 10); !ok {
		return 0, errors.New("price is not a decimal")
	}
	if len(fraction) > 6 && fraction[6] >= '5' {
		result.Add(result, big.NewInt(1))
	}
	if result.Sign() < 0 || result.BitLen() > 64 {
		return 0, errors.New("price micros overflow uint64")
	}
	return result.Uint64(), nil
}

// scaleMicros multiplies a micros-denominated unit price by numerator /
// denominator using integer arithmetic and half-up rounding.
func scaleMicros(unitMicros, numerator, denominator uint64) (uint64, error) {
	if denominator == 0 {
		return 0, errors.New("scale denominator must be positive")
	}
	product := new(big.Int).Mul(new(big.Int).SetUint64(unitMicros), new(big.Int).SetUint64(numerator))
	divisor := new(big.Int).SetUint64(denominator)
	quotient, remainder := new(big.Int), new(big.Int)
	quotient.QuoRem(product, divisor, remainder)
	if remainder.Lsh(remainder, 1).Cmp(divisor) >= 0 {
		quotient.Add(quotient, big.NewInt(1))
	}
	if quotient.Sign() < 0 || quotient.BitLen() > 64 || quotient.Uint64() > math.MaxUint64 {
		return 0, errors.New("scaled price micros overflow uint64")
	}
	return quotient.Uint64(), nil
}

// decimalCeilUnits converts non-monetary quota evidence to whole units. AWS
// quota and CloudWatch SDK values are encoded as JSON numbers; rounding up
// prevents fractional quota usage from being understated.
func decimalCeilUnits(value string) (uint64, error) {
	if !unsignedDecimalPattern.MatchString(value) {
		return 0, errors.New("quota value must be an unsigned plain decimal")
	}
	parts := strings.SplitN(value, ".", 2)
	result := new(big.Int)
	if _, ok := result.SetString(parts[0], 10); !ok || result.Sign() < 0 || result.BitLen() > 64 {
		return 0, errors.New("quota value overflows uint64")
	}
	if len(parts) == 2 && strings.Trim(parts[1], "0") != "" {
		result.Add(result, big.NewInt(1))
		if result.BitLen() > 64 {
			return 0, errors.New("quota value overflows uint64")
		}
	}
	return result.Uint64(), nil
}
