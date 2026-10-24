package countdown

import (
	"math"
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
	helper.SetParams(duration, base, max_exponent)
	result = helper.GetTimeoutDuration(currentRound, highestQCRound)
	assert.Equal(t, duration*time.Duration(base)*time.Duration(base), result)
	// round 14 = 9+5, already 4 rounds timeout, but max_exponent=3, should be base*exponent^3
	currentRound++
	currentRound++
	result = helper.GetTimeoutDuration(currentRound, highestQCRound)
	assert.Equal(t, duration*time.Duration(math.Pow(base, float64(3))), result)

	// extreme case
	helper.SetParams(duration, float64(0), uint8(0))
	result = helper.GetTimeoutDuration(currentRound, highestQCRound)
	assert.Equal(t, duration, result)
}

// TestExpDurationRoundDiff pins the exponent at literal round differences
// instead of re-deriving it from the implementation formula. 256 and 513
// straddle the uint8 wrap point, so an exponent truncated modulo 256 shows up
// as a timeout far below the one derived from the full difference.
func TestExpDurationRoundDiff(t *testing.T) {
	const duration = time.Second
	base := float64(2.0)
	tests := []struct {
		maxExponent uint8
		diff        uint64
		want        time.Duration
	}{
		{0, 1, duration},
		{0, 256, duration},
		{0, 513, duration},
		{3, 1, duration},
		{3, 2, 2 * duration},
		{3, 4, 8 * duration},
		{3, 5, 8 * duration},
		{3, 256, 8 * duration},
		{3, 257, 8 * duration},
		{3, 258, 8 * duration},
		{3, 259, 8 * duration},
		{3, 513, 8 * duration},
		{31, 1, duration},
		{31, 32, duration * (1 << 31)},
		{31, 256, duration * (1 << 31)},
		{31, 257, duration * (1 << 31)},
	}
	for _, test := range tests {
		helper, err := NewExpTimeoutDuration(duration, base, test.maxExponent)
		assert.NoError(t, err)
		got := helper.GetTimeoutDuration(types.Round(test.diff), types.Round(0))
		assert.Equal(t, test.want, got, "maxExponent=%d roundDiff=%d", test.maxExponent, test.diff)
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
}

func TestInvalidParameter(t *testing.T) {
	base := float64(2.0)
	max_exponent := uint8(32)
	duration := time.Second * 59
	_, err := NewExpTimeoutDuration(duration, base, max_exponent)
	assert.Error(t, err)

	base = float64(3.0)
	max_exponent = uint8(21)
	duration = time.Second * 59
	_, err = NewExpTimeoutDuration(duration, base, max_exponent)
	assert.Error(t, err)
}
