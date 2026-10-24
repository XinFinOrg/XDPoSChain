// A countdown timer that will mostly be used by XDPoS v2 consensus engine
package countdown

import (
	"fmt"
	"math"
	"time"

	"github.com/XinFinOrg/XDPoSChain/core/types"
)

const maxExponentUpperbound uint8 = 32

type ExpTimeoutDuration struct {
	duration    time.Duration
	base        float64
	maxExponent uint8
}

func NewExpTimeoutDuration(duration time.Duration, base float64, maxExponent uint8) (*ExpTimeoutDuration, error) {
	d := &ExpTimeoutDuration{
		duration:    duration,
		base:        base,
		maxExponent: maxExponent,
	}
	err := d.sanityCheck()
	return d, err
}

func (d *ExpTimeoutDuration) sanityCheck() error {
	if d.maxExponent >= maxExponentUpperbound {
		return fmt.Errorf("max_exponent (%d)= >= max_exponent_upperbound (%d)", d.maxExponent, maxExponentUpperbound)
	}
	if math.Pow(d.base, float64(d.maxExponent)) >= float64(math.MaxUint32) {
		return fmt.Errorf("base^max_exponent (%f^%d) should be less than 2^32", d.base, d.maxExponent)
	}
	return nil
}

// The inputs should be: currentRound, highestQuorumCert's round
func (d *ExpTimeoutDuration) GetTimeoutDuration(currentRound, highestRound types.Round) time.Duration {
	power := float64(1)
	// below statement must be true, just to prevent negative result
	if highestRound < currentRound {
		// The difference is computed in uint64: converting it to uint8 first
		// truncates it modulo 256, so a round difference of 257 would collapse
		// the timeout to its minimum instead of saturating at maxExponent.
		exp := min(uint64(currentRound-highestRound)-1, uint64(d.maxExponent))
		power = math.Pow(d.base, float64(exp))
	}
	// duration*power can exceed the range of time.Duration for a long round
	// difference and a large base; saturate instead of wrapping around to a
	// negative (or arbitrarily small) timeout. The saturated value is the
	// largest representable duration (~292 years), so a timer armed with it
	// never fires in practice: reaching it requires duration*base^maxExponent
	// to exceed MaxInt64, i.e. a configuration whose own maximum timeout is
	// already out of range. Every network configured in this repository uses
	// base=1 and maxExponent=0, which never saturates; only a chain that
	// overrides the timeout config through genesis can reach this branch, and
	// the chain config validation rejects such an override at startup.
	multiplier := int64(power)
	if multiplier > 0 && int64(d.duration) > math.MaxInt64/multiplier {
		return time.Duration(math.MaxInt64)
	}
	return time.Duration(int64(d.duration) * multiplier)
}

func (d *ExpTimeoutDuration) SetParams(duration time.Duration, base float64, maxExponent uint8) error {
	prevDuration := d.duration
	prevBase := d.base
	prevME := d.maxExponent

	d.duration = duration
	d.base = base
	d.maxExponent = maxExponent
	// if parameters are wrong, should remain instead of change or panic
	if err := d.sanityCheck(); err != nil {
		d.duration = prevDuration
		d.base = prevBase
		d.maxExponent = prevME
		return err
	}
	return nil
}
