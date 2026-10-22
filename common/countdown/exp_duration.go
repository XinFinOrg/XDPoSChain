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
		exp := min(uint8(currentRound-highestRound)-1, maxExponent)
		power = math.Pow(base, float64(exp))
	}
	return duration * time.Duration(power)
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
