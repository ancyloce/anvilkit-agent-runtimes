package runtime

import "testing"

// Cost is money. These exist because the obvious implementation — sum the
// amounts as float64 — produces totals that do not reconcile against the
// invocation records the control plane settles from, and the discrepancy only
// shows up once, in production, on an invoice.

func TestCostsAreSummedExactlyAtWhateverScaleTheyArriveIn(t *testing.T) {
	for name, testCase := range map[string]struct {
		amounts []string
		want    string
	}{
		"nothing added":        {nil, "0"},
		"one amount":           {[]string{"0.002"}, "0.002"},
		"same scale":           {[]string{"0.002", "0.0015"}, "0.0035"},
		"different scales":     {[]string{"1", "0.25", "0.000001"}, "1.250001"},
		"a float would drift":  {[]string{"0.1", "0.2"}, "0.3"},
		"trailing zeros trim":  {[]string{"0.10", "0.20"}, "0.3"},
		"carries into a whole": {[]string{"0.6", "0.4"}, "1"},
		"negatives":            {[]string{"1.5", "-0.5"}, "1"},
		"cancels to zero":      {[]string{"0.5", "-0.5"}, "0"},
	} {
		t.Run(name, func(t *testing.T) {
			var accumulator decimalAccumulator
			for _, amount := range testCase.amounts {
				if err := accumulator.add(amount); err != nil {
					t.Fatalf("add %q: %v", amount, err)
				}
			}
			if got := accumulator.string(); got != testCase.want {
				t.Fatalf("total = %q, want %q", got, testCase.want)
			}
		})
	}
}

func TestAnAmountOutsideTheCanonicalFormIsNotGuessedAt(t *testing.T) {
	for _, amount := range []string{"", "1.", ".5", "01", "1,5", "1e3", "abc", "--1", "1.2.3", " 1"} {
		var accumulator decimalAccumulator
		// An amount the governed gateway did not produce is not one to
		// interpret: guessing what it meant would put an invented number into a
		// usage report.
		if err := accumulator.add(amount); err == nil {
			t.Fatalf("%q was accepted as a canonical decimal amount", amount)
		}
	}
}

func TestATotalIsNeverRenderedAsNegativeZero(t *testing.T) {
	var accumulator decimalAccumulator
	if err := accumulator.add("-0.000"); err != nil {
		t.Fatalf("add: %v", err)
	}
	// "-0" is not a value the canonical decimal pattern admits, and it is not a
	// cost either.
	if got := accumulator.string(); got != "0" {
		t.Fatalf("total = %q, want %q", got, "0")
	}
}
