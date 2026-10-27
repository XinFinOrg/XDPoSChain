package countdown

import (
	"math"
	"sync"
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/stretchr/testify/assert"
)

func TestExpDuration(t *testing.T) {
	base := float64(2.0)
	max_exponent := uint8(2)
	duration := time.Second * 59
	helper, err := NewExpTimeoutDuration(duration, base, max_exponent)
	assert.Nil(t, err)
	// round 10 = 9+1, normal case, should be base
	currentRound := types.Round(10)
	highestQCRound := types.Round(9)
	result := helper.GetTimeoutDuration(currentRound, highestQCRound)
	assert.Equal(t, duration, result)

	// round 11 = 9+2, already 1 round timeout, should be base*exponent
	currentRound++
	result = helper.GetTimeoutDuration(currentRound, highestQCRound)
	assert.Equal(t, duration*time.Duration(base), result)

	// round 12 = 9+3, already 2 rounds timeout, should be base*exponent^2
	currentRound++
	result = helper.GetTimeoutDuration(currentRound, highestQCRound)
	assert.Equal(t, duration*time.Duration(base)*time.Duration(base), result)

	// test SetParams
	duration++
	max_exponent++
	base++
	assert.NoError(t, helper.SetParams(duration, base, max_exponent))
	result = helper.GetTimeoutDuration(currentRound, highestQCRound)
	assert.Equal(t, duration*time.Duration(base)*time.Duration(base), result)
	// round 14 = 9+5, already 4 rounds timeout, but max_exponent=3, should be base*exponent^3
	currentRound++
	currentRound++
	result = helper.GetTimeoutDuration(currentRound, highestQCRound)
	assert.Equal(t, duration*time.Duration(math.Pow(base, float64(3))), result)

	// extreme case
	assert.NoError(t, helper.SetParams(duration, float64(0), uint8(0)))
	result = helper.GetTimeoutDuration(currentRound, highestQCRound)
	assert.Equal(t, duration, result)
}

// TestExpDurationRoundDiff pins the exponent at literal round differences
// instead of re-deriving it from the implementation formula. A round
// difference of 257 or more whose low 8 bits fall in [1, maxExponent] makes
// the uint8-truncated exponent too small (e.g. 513); 256 sits exactly on the
// wrap point, where uint8(256)-1 wraps to 255 and the old formula happens to
// be correct, so it is kept as a control.
func TestExpDurationRoundDiff(t *testing.T) {
	const duration = time.Second
	base := float64(2.0)
	tests := []struct {
		name        string
		maxExponent uint8
		diff        uint64
		want        time.Duration
	}{
		{"maxExponent=0 diff=1", 0, 1, duration},
		{"maxExponent=0 diff=256", 0, 256, duration},
		{"maxExponent=0 diff=513", 0, 513, duration},
		{"maxExponent=3 diff=1", 3, 1, duration},
		{"maxExponent=3 diff=2", 3, 2, 2 * duration},
		{"maxExponent=3 diff=4 saturates", 3, 4, 8 * duration},
		{"maxExponent=3 diff=5 saturates", 3, 5, 8 * duration},
		{"maxExponent=3 diff=256 saturates", 3, 256, 8 * duration},
		{"maxExponent=3 diff=257 saturates", 3, 257, 8 * duration},
		{"maxExponent=3 diff=258 saturates", 3, 258, 8 * duration},
		{"maxExponent=3 diff=259 saturates", 3, 259, 8 * duration},
		{"maxExponent=3 diff=513 saturates", 3, 513, 8 * duration},
		{"maxExponent=31 diff=1", 31, 1, duration},
		{"maxExponent=31 diff=32 saturates", 31, 32, duration * (1 << 31)},
		{"maxExponent=31 diff=256 saturates", 31, 256, duration * (1 << 31)},
		{"maxExponent=31 diff=257 saturates", 31, 257, duration * (1 << 31)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			helper, err := NewExpTimeoutDuration(duration, base, test.maxExponent)
			assert.NoError(t, err)
			got := helper.GetTimeoutDuration(types.Round(test.diff), types.Round(0))
			assert.Equal(t, test.want, got)
		})
	}
}

// TestExpDurationOverflowSaturates checks that a timeout outside the int64 range
// saturates at the maximum duration instead of wrapping around to a negative
// (or arbitrarily small) one.
func TestExpDurationOverflowSaturates(t *testing.T) {
	helper, err := NewExpTimeoutDuration(59*time.Second, float64(2.0), 31)
	assert.NoError(t, err)
	// 59s * 2^27 fits in a time.Duration (about 251 years), 59s * 2^28 overflows.
	assert.Equal(t, 59*time.Second*(1<<27), helper.GetTimeoutDuration(types.Round(28), types.Round(0)))
	assert.Equal(t, time.Duration(math.MaxInt64), helper.GetTimeoutDuration(types.Round(29), types.Round(0)))
	assert.Equal(t, time.Duration(math.MaxInt64), helper.GetTimeoutDuration(types.Round(31), types.Round(0)))
	assert.Equal(t, time.Duration(math.MaxInt64), helper.GetTimeoutDuration(types.Round(256), types.Round(0)))
	assert.Equal(t, time.Duration(math.MaxInt64), helper.GetTimeoutDuration(types.Round(257), types.Round(0)))
	assert.Equal(t, time.Duration(math.MaxInt64), helper.GetTimeoutDuration(types.Round(513), types.Round(0)))
	// The guard must be a strict inequality: at the exact boundary the product
	// is MaxInt64-1 and still fits, so it must not saturate.
	exact, err := NewExpTimeoutDuration(9223372036854775806/3, float64(3.0), 1)
	assert.NoError(t, err)
	assert.Equal(t, time.Duration(9223372036854775806), exact.GetTimeoutDuration(types.Round(2), types.Round(0)))
}

func TestInvalidParameter(t *testing.T) {
	base := float64(2.0)
	max_exponent := uint8(32)
	duration := time.Second * 59
	helper, err := NewExpTimeoutDuration(duration, base, max_exponent)
	assert.Error(t, err)
	assert.Nil(t, helper)

	base = float64(3.0)
	max_exponent = uint8(21)
	duration = time.Second * 59
	helper, err = NewExpTimeoutDuration(duration, base, max_exponent)
	assert.Error(t, err)
	assert.Nil(t, helper)
}

// TestExpTimeoutDurationConcurrentSetParams runs the countdown-goroutine read
// path against the checkpoint-loop write path. It reproduces #2828 under
// -race; without -race the value checks below catch only some torn reads.
func TestExpTimeoutDurationConcurrentSetParams(t *testing.T) {
	// GetTimeoutDuration(3, 1) gives exp = min(1, maxExponent) = 1, so each
	// set yields a distinct, easily recognised timeout.
	setA := struct {
		duration    time.Duration
		base        float64
		maxExponent uint8
	}{duration: time.Second, base: 2, maxExponent: 3}
	setB := struct {
		duration    time.Duration
		base        float64
		maxExponent uint8
	}{duration: 5 * time.Second, base: 3, maxExponent: 1}
	wantA := time.Second * 2
	wantB := time.Second * 15

	d, err := NewExpTimeoutDuration(setA.duration, setA.base, setA.maxExponent)
	if err != nil {
		t.Fatalf("NewExpTimeoutDuration: %v", err)
	}

	const iterations = 2000
	start := make(chan struct{})
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < iterations; i++ {
			set := setA
			if i%2 == 0 {
				set = setB
			}
			if err := d.SetParams(set.duration, set.base, set.maxExponent); err != nil {
				t.Errorf("SetParams: %v", err)
				return
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < iterations; i++ {
			got := d.GetTimeoutDuration(3, 1)
			// A torn read can mix the sets, e.g. setA.duration with setB.base
			// (3s); a torn maxExponent alone is invisible (exp = 1 for both sets).
			if got != wantA && got != wantB {
				t.Errorf("GetTimeoutDuration returned %v, want %v or %v (mixed parameter set)", got, wantA, wantB)
				return
			}
		}
	}()

	close(start)
	wg.Wait()
}

// TestSetParamsRejectedKeepsTimeout pins that a rejected set leaves the
// previous parameters untouched.
func TestSetParamsRejectedKeepsTimeout(t *testing.T) {
	cases := []struct {
		name        string
		duration    time.Duration
		base        float64
		maxExponent uint8
	}{
		{"max exponent out of range", 9 * time.Second, 3, maxExponentUpperbound},
		{"base power overflow", 9 * time.Second, 3, 21},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := NewExpTimeoutDuration(time.Second, 2, 1)
			assert.NoError(t, err)
			// exp = min(3, maxExponent), so all three parameters affect the
			// result and a partial write would be visible.
			before := d.GetTimeoutDuration(5, 1)

			assert.Error(t, d.SetParams(tc.duration, tc.base, tc.maxExponent))
			assert.Equal(t, before, d.GetTimeoutDuration(5, 1))
		})
	}
}
