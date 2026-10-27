// A countdown timer that will mostly be used by XDPoS v2 consensus engine
package countdown

import (
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/XinFinOrg/XDPoSChain/core/types"
)

const maxExponentUpperbound uint8 = 32

// ExpTimeoutDuration holds the parameters of the exponential timeout formula.
// The countdown goroutine reads them via GetTimeoutDuration, the checkpoint
// loop replaces them via SetParams; mu keeps the three fields consistent.
type ExpTimeoutDuration struct {
	mu sync.RWMutex // Protects duration, base and maxExponent

	duration    time.Duration
	base        float64
	maxExponent uint8
}

func NewExpTimeoutDuration(duration time.Duration, base float64, maxExponent uint8) (*ExpTimeoutDuration, error) {
	if err := checkExpParams(base, maxExponent); err != nil {
		return nil, err
	}
	return &ExpTimeoutDuration{
		duration:    duration,
		base:        base,
		maxExponent: maxExponent,
	}, nil
}

// checkExpParams validates a parameter set before it becomes visible to readers.
func checkExpParams(base float64, maxExponent uint8) error {
	if maxExponent >= maxExponentUpperbound {
		return fmt.Errorf("max_exponent (%d) >= max_exponent_upperbound (%d)", maxExponent, maxExponentUpperbound)
	}
	if math.Pow(base, float64(maxExponent)) >= float64(math.MaxUint32) {
		return fmt.Errorf("base^max_exponent (%f^%d) should be less than 2^32", base, maxExponent)
	}
	return nil
}

// The inputs should be: currentRound, highestQuorumCert's round
func (d *ExpTimeoutDuration) GetTimeoutDuration(currentRound, highestRound types.Round) time.Duration {
	// Snapshot the three fields under one lock, so a concurrent SetParams
	// cannot produce a mixed parameter set.
	d.mu.RLock()
	duration, base, maxExponent := d.duration, d.base, d.maxExponent
	d.mu.RUnlock()

	power := float64(1)
	// below statement must be true, just to prevent negative result
	if highestRound < currentRound {
		// The difference is computed in uint64: converting it to uint8 first
		// truncates it modulo 256, so a round difference of 257 would collapse
		// the timeout to its minimum instead of saturating at maxExponent.
		exp := min(uint64(currentRound-highestRound)-1, uint64(maxExponent))
		power = math.Pow(base, float64(exp))
	}
	// duration*power can exceed the range of time.Duration for a long round
	// difference and a large base; saturate instead of wrapping around to a
	// negative timeout, which would retrigger the timer immediately. A chain
	// whose maximum exponential timeout is unrepresentable is rejected by the
	// chain config validation at startup, so this branch is a backstop for
	// configs that bypass that check.
	multiplier := int64(power)
	if multiplier > 0 && int64(duration) > math.MaxInt64/multiplier {
		return time.Duration(math.MaxInt64)
	}
	return time.Duration(int64(duration) * multiplier)
}

// SetParams replaces the whole parameter set; an invalid set is rejected
// before the current one is touched.
func (d *ExpTimeoutDuration) SetParams(duration time.Duration, base float64, maxExponent uint8) error {
	if err := checkExpParams(base, maxExponent); err != nil {
		return err
	}
	d.mu.Lock()
	d.duration, d.base, d.maxExponent = duration, base, maxExponent
	d.mu.Unlock()
	return nil
}
