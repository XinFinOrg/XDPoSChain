// A countdown timer that will mostly be used by XDPoS v2 consensus engine
package countdown

import "time"

type ConstTimeoutDuration struct {
	duration time.Duration
}

func NewConstTimeoutDuration(duration time.Duration) *ConstTimeoutDuration {
	return &ConstTimeoutDuration{
		duration: duration,
	}
}

func (d *ConstTimeoutDuration) GetTimeoutDuration(inputs ...interface{}) time.Duration {
	return d.duration
}

func (d *ConstTimeoutDuration) SetParams(inputs ...interface{}) {
	if len(inputs) > 0 {
		if duration, ok := inputs[0].(time.Duration); ok {
			d.duration = duration
		}
	}
}
