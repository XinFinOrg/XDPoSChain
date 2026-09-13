package engine_v2

import (
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// TestSendTimeoutUnusableGapSchedule pins the epoch-switch branch of sendTimeout.
// A head at the v2 switch block makes isEpochSwitchAtRound answer true without
// decoding any extra fields, which routes the call into its gap-number lookup and
// into the head+1 height that names the block the timeout is for.
//
// The unset-epoch and missing-config shapes are caught by isEpochSwitchAtRound
// ahead of that lookup, because it divides by Epoch: they report the defect under
// its name and with the head height, not the head+1 the lookup would name.
func TestSendTimeoutUnusableGapSchedule(t *testing.T) {
	tests := []struct {
		name   string
		config *params.XDPoSConfig
		want   []string
		// unsetEpoch marks the rows whose defect is the caller's, not the schedule's.
		unsetEpoch bool
	}{
		{"zero gap", gapScheduleConfig(900, 0), []string{"[sendTimeout]", "XDPoS.Gap 0 designates no gap block inside XDPoS.Epoch 900", "number: 901"}, false},
		{"gap equal to epoch", gapScheduleConfig(900, 900), []string{"[sendTimeout]", "XDPoS.Gap 900 designates no gap block of its own inside XDPoS.Epoch 900", "number: 901"}, false},
		{"gap above epoch", gapScheduleConfig(900, 1200), []string{"[sendTimeout]", "XDPoS.Gap 1200 designates no gap block inside XDPoS.Epoch 900", "number: 901"}, false},
		{"epoch one leaves no usable gap", gapScheduleConfig(1, 0), []string{"[sendTimeout]", "XDPoS.Epoch 1 designates no gap block", "number: 901"}, false},
		{"unset epoch", gapScheduleConfig(0, 0), []string{"[isEpochSwitchAtRound]", "XDPoS.Epoch is unset", "number: 900", "gap: 0"}, true},
		{"missing config", nil, []string{"[isEpochSwitchAtRound]", "nil config", "number: 900"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			x := gapScheduleEngine(tt.config)
			chain := NewMockChainReader()
			chain.SetCurrentHeader(&types.Header{Number: new(big.Int).SetUint64(gapScheduleSwitchBlock)})

			err := x.sendTimeout(chain)
			switch {
			case tt.unsetEpoch:
				assertUnsetEpochInGapPath(t, err, tt.want)
			case tt.config == nil:
				assertMissingXDPoSConfig(t, err, tt.want)
			default:
				assertUnusableGapSchedule(t, err, tt.want)
			}
		})
	}
}
