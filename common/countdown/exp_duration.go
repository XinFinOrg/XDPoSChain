// A countdown timer that will mostly be used by XDPoS v2 consensus engine
package countdown

import (
	"math"
	"time"

	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/log"
)

const max_exponent_upperbound uint8 = 32

type ExpTimeoutDuration struct {
	duration     time.Duration
	base         float64
	max_exponent uint8
}

func NewExpTimeoutDuration(duration time.Duration, base float64, max_exponent uint8) *ExpTimeoutDuration {
	d := &ExpTimeoutDuration{
		duration:     duration,
		base:         base,
		max_exponent: max_exponent,
	}
	d.sanityCheck()
	return d
}

func (d *ExpTimeoutDuration) sanityCheck() {
	if d.max_exponent >= max_exponent_upperbound {
		log.Error("max_exponent (e)= >= max_exponent_upperbound (e_upper)", "e", d.max_exponent, "e_upper", max_exponent_upperbound)
		panic("max_exponent (e)= >= max_exponent_upperbound (e_upper)")
	}
	if math.Pow(d.base, float64(d.max_exponent)) >= float64(math.MaxUint32) {
		log.Error("base^max_exponent (b^e) should be less than 2^32", "b", d.base, "e", d.max_exponent)
		panic("base^max_exponent (b^e) should be less than 2^32")
	}
}

// The inputs should be: [blockchain, currentRound, highestQuorumCert's round]
func (d *ExpTimeoutDuration) GetTimeoutDuration(inputs ...interface{}) time.Duration {
	power := float64(1)
	if len(inputs) >= 3 {
		if currentRound, ok := inputs[1].(types.Round); ok {
			if highestRound, ok := inputs[2].(types.Round); ok {
				// below statement must be true, just to prevent negative result
				if highestRound < currentRound {
					exp := uint8(currentRound-highestRound) - 1
					if exp > d.max_exponent {
						exp = d.max_exponent
					}
					power = math.Pow(d.base, float64(exp))
				}
			}
		}
	}
	return d.duration * time.Duration(power)
}

func (d *ExpTimeoutDuration) SetParams(inputs ...interface{}) {
	if len(inputs) >= 1 {
		if duration, ok := inputs[0].(time.Duration); ok {
			d.duration = duration
		}
	}
	if len(inputs) >= 2 {
		if base, ok := inputs[1].(float64); ok {
			d.base = base
		}
	}
	if len(inputs) >= 3 {
		if exponent, ok := inputs[2].(uint8); ok {
			d.max_exponent = exponent
		}
	}
	d.sanityCheck()
}
