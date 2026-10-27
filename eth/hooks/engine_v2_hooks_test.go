package hooks

import (
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// TestResolvePreUpgradeLimitPenaltyEpochUsesHistoricalValue tests the
// pre-upgrade path stays pinned to the historical V2 constant.
func TestResolvePreUpgradeLimitPenaltyEpochUsesHistoricalValue(t *testing.T) {
	if got := resolvePreUpgradeLimitPenaltyEpoch(); got != common.LimitPenaltyEpochV2 {
		t.Fatalf("unexpected pre-upgrade limit penalty epoch: have %d want %d", got, common.LimitPenaltyEpochV2)
	}
}

// TestResolvePostUpgradeLimitPenaltyEpochDefaultsToOne tests the post-upgrade
// path preserves the legacy fallback of one epoch when config is unset.
func TestResolvePostUpgradeLimitPenaltyEpochDefaultsToOne(t *testing.T) {
	if got := resolvePostUpgradeLimitPenaltyEpoch(nil); got != 1 {
		t.Fatalf("unexpected nil-config post-upgrade limit penalty epoch: have %d want %d", got, 1)
	}

	if got := resolvePostUpgradeLimitPenaltyEpoch(&params.V2Config{}); got != 1 {
		t.Fatalf("unexpected zero-value post-upgrade limit penalty epoch: have %d want %d", got, 1)
	}
}

// TestResolvePostUpgradeLimitPenaltyEpochUsesConfiguredValue tests the
// post-upgrade path still honors an explicit configuration value.
func TestResolvePostUpgradeLimitPenaltyEpochUsesConfiguredValue(t *testing.T) {
	cfg := &params.V2Config{LimitPenaltyEpoch: 2}
	if got := resolvePostUpgradeLimitPenaltyEpoch(cfg); got != 2 {
		t.Fatalf("unexpected configured post-upgrade limit penalty epoch: have %d want %d", got, 2)
	}
}

// TestCalculateRewardForSignerProportional tests that each signer is paid
// chainReward * sign / signSlots, rounded down, and never more than chainReward.
func TestCalculateRewardForSignerProportional(t *testing.T) {
	chainReward := new(big.Int).Mul(big.NewInt(6342), big.NewInt(1e16)) // 63.42 XDC
	tests := []struct {
		name        string
		chainReward *big.Int
		sign        uint64
		signSlots   uint64
		want        *big.Int
	}{
		{name: "full", chainReward: chainReward, sign: 60, signSlots: 60, want: chainReward},
		{name: "half", chainReward: chainReward, sign: 30, signSlots: 60, want: new(big.Int).Div(chainReward, big.NewInt(2))},
		{name: "one slot", chainReward: chainReward, sign: 1, signSlots: 60, want: new(big.Int).Div(chainReward, big.NewInt(60))},
		{name: "rounds down", chainReward: big.NewInt(100), sign: 1, signSlots: 3, want: big.NewInt(33)},
		{name: "multiplies before dividing", chainReward: big.NewInt(100), sign: 2, signSlots: 3, want: big.NewInt(66)},
		{name: "sign above slots is capped", chainReward: chainReward, sign: 61, signSlots: 60, want: chainReward},
		{name: "no sign slots", chainReward: chainReward, sign: 1, signSlots: 0, want: big.NewInt(0)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			addr := common.HexToAddress("0x1")
			signers := map[common.Address]*RewardLog{addr: {Sign: test.sign, Reward: new(big.Int)}}
			got, err := CalculateRewardForSignerProportional(test.chainReward, signers, test.signSlots)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			reward, ok := got[addr]
			if !ok {
				t.Fatal("signer missing from result")
			}
			if reward.Cmp(test.want) != 0 {
				t.Fatalf("unexpected reward: have %v want %v", reward, test.want)
			}
			if signers[addr].Reward.Cmp(test.want) != 0 {
				t.Fatalf("unexpected RewardLog.Reward: have %v want %v", signers[addr].Reward, test.want)
			}
		})
	}
}
