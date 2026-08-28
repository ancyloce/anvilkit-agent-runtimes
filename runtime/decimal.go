package runtime

import (
	"fmt"
	"math/big"
	"strings"
)

// Money is never floated here. Cost arrives from the governed gateway as a
// canonical decimal string, and a runtime that summed several attempts' costs
// in binary floating point would report a number nobody could reconcile against
// the invocation records the control plane settled from.
//
// The accumulator keeps an exact scaled integer instead: every amount is read
// as digits and a scale, amounts are brought to a common scale before adding,
// and the total is rendered back at that scale.
type decimalAccumulator struct {
	total *big.Int
	scale int
}

// add takes one canonical decimal string into the accumulator.
func (a *decimalAccumulator) add(amount string) error {
	value, scale, err := parseDecimal(amount)
	if err != nil {
		return err
	}
	if a.total == nil {
		a.total, a.scale = value, scale
		return nil
	}
	if scale > a.scale {
		a.total = shiftDecimal(a.total, scale-a.scale)
		a.scale = scale
	} else if scale < a.scale {
		value = shiftDecimal(value, a.scale-scale)
	}
	a.total = new(big.Int).Add(a.total, value)
	return nil
}

// string renders the accumulated total as a canonical decimal string. An
// accumulator nothing was added to is zero, which is the honest value for an
// attempt whose cost the gateway attributed nothing to.
func (a *decimalAccumulator) string() string {
	if a.total == nil {
		return "0"
	}
	digits := a.total.String()
	negative := strings.HasPrefix(digits, "-")
	digits = strings.TrimPrefix(digits, "-")
	if a.scale == 0 {
		return sign(negative, digits)
	}
	for len(digits) <= a.scale {
		digits = "0" + digits
	}
	whole, fraction := digits[:len(digits)-a.scale], digits[len(digits)-a.scale:]
	fraction = strings.TrimRight(fraction, "0")
	if fraction == "" {
		return sign(negative, whole)
	}
	return sign(negative, whole+"."+fraction)
}

// sign renders a value's sign, never as a negative zero: "-0" is a value the
// canonical decimal pattern does not admit, and it is not a cost either.
func sign(negative bool, digits string) string {
	if !negative || strings.Trim(digits, "0.") == "" {
		return digits
	}
	return "-" + digits
}

// parseDecimal reads a canonical decimal string into a scaled integer. It is
// deliberately strict: an amount outside the canonical pattern is not one the
// governed gateway produced, and guessing what it meant would put an invented
// number into a usage report.
func parseDecimal(amount string) (*big.Int, int, error) {
	if amount == "" {
		return nil, 0, fmt.Errorf("decimal: an empty amount is not a decimal string")
	}
	body := amount
	negative := strings.HasPrefix(body, "-")
	body = strings.TrimPrefix(body, "-")
	whole, fraction, hasFraction := strings.Cut(body, ".")
	if whole == "" || (hasFraction && fraction == "") {
		return nil, 0, fmt.Errorf("decimal: %q is not a canonical decimal string", amount)
	}
	if len(whole) > 1 && whole[0] == '0' {
		return nil, 0, fmt.Errorf("decimal: %q carries a leading zero", amount)
	}
	digits := whole + fraction
	for _, character := range digits {
		if character < '0' || character > '9' {
			return nil, 0, fmt.Errorf("decimal: %q is not a canonical decimal string", amount)
		}
	}
	value, ok := new(big.Int).SetString(digits, 10)
	if !ok {
		return nil, 0, fmt.Errorf("decimal: %q is not a canonical decimal string", amount)
	}
	if negative {
		value.Neg(value)
	}
	return value, len(fraction), nil
}

// shiftDecimal rescales a value by powers of ten.
func shiftDecimal(value *big.Int, places int) *big.Int {
	multiplier := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(places)), nil)
	return new(big.Int).Mul(value, multiplier)
}
