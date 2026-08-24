package main

import (
	"flag"
	"fmt"
	"math"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
)

// Flags for TestCalcMasternodeRewardsManual, so the reward numbers for a
// candidate network can be eyeballed without editing the test. Note that
// -v is required: go test discards the output of a passing package without it.
//
//	go test ./cmd/puppeth -run TestCalcMasternodeRewardsManual -v \
//	    -period=2 -epoch=900 -threshold=10_000_000 -yield=10 -signers=3
var (
	flagPeriod    = flag.Uint64("period", 2, "block period in seconds (manual reward calc)")
	flagEpoch     = flag.Uint64("epoch", 900, "blocks per epoch (manual reward calc)")
	flagThreshold = flag.Uint64("threshold", 10_000_000, "per-masternode staking threshold in whole coins (manual reward calc)")
	flagYield     = flag.Uint64("yield", 10, "target masternode yield in APY% (manual reward calc)")
	flagSigners   = flag.Int("signers", 3, "number of initial masternodes (manual reward calc)")
)

// TestCalcMasternodeRewardsManual prints the reward figures puppeth would bake
// into the genesis config for the flag values above, as a manual check. It
// asserts nothing beyond the calculation being possible at all; the assertions
// live in TestCalcMasternodeRewards.
func TestCalcMasternodeRewardsManual(t *testing.T) {
	rewards, ok := calcMasternodeRewards(*flagPeriod, *flagEpoch, *flagThreshold, *flagYield, *flagSigners)
	if !ok {
		t.Fatalf("period=%d epoch=%d yields less than one epoch per year, no rewards calculated", *flagPeriod, *flagEpoch)
	}
	epochsPerYear := (31536000 / *flagPeriod) / *flagEpoch
	netOfFoundation := float64(100-common.RewardFoundationPercent) / 100

	fmt.Printf("period=%ds epoch=%d blocks threshold=%d yield=%d%% masternodes=%d (%d epochs/year)",
		*flagPeriod, *flagEpoch, *flagThreshold, *flagYield, *flagSigners, epochsPerYear)
	fmt.Printf("  reward (total per epoch) = %d\n", rewards.TotalPerEpoch)
	fmt.Printf("  masternodeReward         = %v\n", rewards.MasternodeReward)
	fmt.Printf("  protectorReward          = %v\n", rewards.ProtectorReward)
	fmt.Printf("  observerReward           = %v\n", rewards.ObserverReward)
	fmt.Printf("  effective yield per masternode = %.4f%% (net of the %d%% foundation cut)",
		rewards.MasternodeReward*netOfFoundation*float64(epochsPerYear)/float64(*flagThreshold)*100, common.RewardFoundationPercent)
}

// TestCalcMasternodeRewards asserts the reward numbers for a set of fixed
// period/epoch/threshold/yield combinations. Run with -v to see the figures.
func TestCalcMasternodeRewards(t *testing.T) {
	tests := []struct {
		name      string
		period    uint64
		epoch     uint64
		threshold uint64
		yield     uint64
		signers   int
		wantOK    bool
		wantTotal uint64
		wantMN    float64
		wantProt  float64
		wantObs   float64
	}{
		{
			name:   "mainnet-like defaults, 3 masternodes",
			period: 2, epoch: 900, threshold: 10000000, yield: 10, signers: 3,
			wantOK:    true,
			wantTotal: 190, wantMN: 63.4196, wantProt: 50.7357, wantObs: 25.3678,
		},
		{
			name:   "mainnet-like defaults, full 108 masternode set",
			period: 2, epoch: 900, threshold: 10000000, yield: 10, signers: 108,
			wantOK:    true,
			wantTotal: 6849, wantMN: 63.4196, wantProt: 50.7357, wantObs: 25.3678,
		},
		{
			name:   "double threshold at half yield pays the same per node",
			period: 2, epoch: 900, threshold: 20000000, yield: 5, signers: 5,
			wantOK:    true,
			wantTotal: 317, wantMN: 63.4196, wantProt: 50.7357, wantObs: 25.3678,
		},
		{
			name:   "15s period, fewer epochs per year, bigger per-epoch reward",
			period: 15, epoch: 900, threshold: 10000000, yield: 10, signers: 3,
			wantOK:    true,
			wantTotal: 1427, wantMN: 475.6469, wantProt: 380.5175, wantObs: 190.2588,
		},
		{
			name:   "zero yield pays nothing",
			period: 2, epoch: 900, threshold: 10000000, yield: 0, signers: 3,
			wantOK: true,
		},
		{
			name:   "zero period is rejected",
			period: 0, epoch: 900, threshold: 10000000, yield: 10, signers: 3,
		},
		{
			name:   "zero epoch is rejected",
			period: 2, epoch: 0, threshold: 10000000, yield: 10, signers: 3,
		},
		{
			name:   "epoch longer than a year is rejected",
			period: 2, epoch: 20000000, threshold: 10000000, yield: 10, signers: 3,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rewards, ok := calcMasternodeRewards(tt.period, tt.epoch, tt.threshold, tt.yield, tt.signers)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if !ok {
				fmt.Printf("period=%ds epoch=%d -> rejected, reward config left untouched", tt.period, tt.epoch)
				if rewards != (masternodeRewards{}) {
					t.Fatalf("rewards = %+v, want zero value when not ok", rewards)
				}
				return
			}
			fmt.Printf("period=%ds epoch=%d threshold=%d yield=%d%% masternodes=%d -> total=%d mn=%v prot=%v obs=%v",
				tt.period, tt.epoch, tt.threshold, tt.yield, tt.signers,
				rewards.TotalPerEpoch, rewards.MasternodeReward, rewards.ProtectorReward, rewards.ObserverReward)

			if rewards.TotalPerEpoch != tt.wantTotal {
				t.Errorf("TotalPerEpoch = %d, want %d", rewards.TotalPerEpoch, tt.wantTotal)
			}
			if rewards.MasternodeReward != tt.wantMN {
				t.Errorf("MasternodeReward = %v, want %v", rewards.MasternodeReward, tt.wantMN)
			}
			if rewards.ProtectorReward != tt.wantProt {
				t.Errorf("ProtectorReward = %v, want %v", rewards.ProtectorReward, tt.wantProt)
			}
			if rewards.ObserverReward != tt.wantObs {
				t.Errorf("ObserverReward = %v, want %v", rewards.ObserverReward, tt.wantObs)
			}
			if tt.yield == 0 {
				return
			}
			// The requested yield must survive the foundation cut: a masternode
			// earning MasternodeReward each epoch, minus the foundation share,
			// should end the year on `yield`% of its stake.
			epochsPerYear := float64((31536000 / tt.period) / tt.epoch)
			netOfFoundation := float64(100-common.RewardFoundationPercent) / 100
			gotYield := rewards.MasternodeReward * netOfFoundation * epochsPerYear / float64(tt.threshold) * 100
			if math.Abs(gotYield-float64(tt.yield)) > 0.001 {
				t.Errorf("effective yield = %.4f%%, want %d%%", gotYield, tt.yield)
			}
		})
	}
}
