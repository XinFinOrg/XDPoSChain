package params

import (
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
)

// scaled multiplies base by the schedule multiplier expected for a tier.
func scaled(base *big.Int, multiplier int64) *big.Int {
	return new(big.Int).Mul(base, big.NewInt(multiplier))
}

// TestGasPriceResultsAreIndependent guards that callers can mutate a returned
// price without corrupting the schedule for everyone else.
func TestGasPriceResultsAreIndependent(t *testing.T) {
	cfg := &ChainConfig{Gas50xBlock: big.NewInt(100), Gas2500xBlock: big.NewInt(200)}

	for _, block := range []*big.Int{big.NewInt(99), big.NewInt(100), big.NewInt(200)} {
		want := GetGasPrice(block, cfg)
		GetGasPrice(block, cfg).SetInt64(1)
		if got := GetGasPrice(block, cfg); got.Cmp(want) != 0 {
			t.Fatalf("gas price at block %v corrupted by caller: have %v want %v", block, got, want)
		}
	}
}

// TestGasTiersOrderedLatestFirst guards the table order tierGasPrice relies on:
// the first matching entry wins, so prices must strictly decrease from the
// latest fork to the earliest.
func TestGasTiersOrderedLatestFirst(t *testing.T) {
	for i := 1; i < len(gasTiers); i++ {
		if prev, cur := gasTiers[i-1].price, gasTiers[i].price; prev.Cmp(cur) <= 0 {
			t.Fatalf("gasTiers[%d] price %v must exceed gasTiers[%d] price %v", i-1, prev, i, cur)
		}
	}
}

// TestGasTierActivationsMatchTableOrder guards the other half of that order: a
// tier's fork must imply every later-listed tier's fork, otherwise scanning
// latest first would return a row whose predecessor has not fired yet.
func TestGasTierActivationsMatchTableOrder(t *testing.T) {
	// One activation height per gasTiers entry, in the same order.
	cfg := &ChainConfig{Gas2500xBlock: big.NewInt(200), Gas50xBlock: big.NewInt(100)}
	forkBlocks := []int64{200, 100}
	if len(forkBlocks) != len(gasTiers) {
		t.Fatalf("forkBlocks covers %d tiers, want %d: schedule the new tier here too", len(forkBlocks), len(gasTiers))
	}

	probes := []*big.Int{big.NewInt(0)}
	for _, block := range forkBlocks {
		probes = append(probes, big.NewInt(block-1), big.NewInt(block), big.NewInt(block+1))
	}
	for _, number := range probes {
		newerActive := false
		for i, tier := range gasTiers {
			switch active := tier.activated(cfg, number); {
			case active:
				newerActive = true
			case newerActive:
				t.Fatalf("block %v: gasTiers[%d] is inactive while a newer tier is active", number, i)
			}
		}
	}
}

// TestGasTierGapRejectedAtStartup pins the premise of the invariant above: it
// only holds for configs that schedule every tier, and a gapped schedule is
// rejected before it can reach tierGasPrice.
func TestGasTierGapRejectedAtStartup(t *testing.T) {
	cfg := &ChainConfig{
		ChainID:                big.NewInt(1234),
		TIPTRC21FeeBlock:       big.NewInt(0),
		Gas50xBlock:            nil,
		Gas2500xBlock:          big.NewInt(200),
		TRC21IssuerSMC:         TestnetChainConfig.TRC21IssuerSMC,
		XDCXListingSMC:         TestnetChainConfig.XDCXListingSMC,
		RelayerRegistrationSMC: TestnetChainConfig.RelayerRegistrationSMC,
		LendingRegistrationSMC: TestnetChainConfig.LendingRegistrationSMC,
		Ethash:                 new(EthashConfig),
	}

	err := cfg.CheckConfigForkOrder()
	if !errors.Is(err, ErrMissingForkSwitch) {
		t.Fatalf("gapped gas schedule accepted: have %v want %v", err, ErrMissingForkSwitch)
	}
	if !strings.Contains(err.Error(), "Gas50xBlock") {
		t.Fatalf("unexpected error string: %v", err)
	}
}

func TestGetGasPriceForTRC21(t *testing.T) {
	cfg := &ChainConfig{
		TIPTRC21FeeBlock: big.NewInt(10),
		Gas50xBlock:      big.NewInt(20),
		Gas2500xBlock:    big.NewInt(30),
	}

	tests := []struct {
		name  string
		block *big.Int
		want  *big.Int
	}{
		{name: "activation block uses pre-tip price", block: big.NewInt(10), want: common.TRC21GasPriceBefore},
		{name: "after tip block uses tip price", block: big.NewInt(11), want: common.TRC21GasPrice},
		{name: "gas50x block uses gas50x price", block: big.NewInt(20), want: scaled(new(big.Int).SetUint64(common.DefaultMinGasPrice), 50)},
		{name: "below gas2500x block stays on gas50x price", block: big.NewInt(29), want: scaled(new(big.Int).SetUint64(common.DefaultMinGasPrice), 50)},
		{name: "gas2500x block uses gas2500x price", block: big.NewInt(30), want: scaled(new(big.Int).SetUint64(common.DefaultMinGasPrice), 2500)},
		{name: "above gas2500x block stays on gas2500x price", block: big.NewInt(31), want: scaled(new(big.Int).SetUint64(common.DefaultMinGasPrice), 2500)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := GetGasPriceForTRC21(tc.block, cfg)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Cmp(tc.want) != 0 {
				t.Fatalf("unexpected trc21 gas price: have %v want %v", got, tc.want)
			}
		})
	}
}

func TestGetGasPriceForTRC21RejectsNilBlock(t *testing.T) {
	cfg := &ChainConfig{TIPTRC21FeeBlock: big.NewInt(10)}

	if _, err := GetGasPriceForTRC21(nil, cfg); err == nil {
		t.Fatal("expected error for nil block number")
	}
}

// TestGetGasFeeUsesGas50xBlock tests get gas fee uses gas 50 x block.
func TestGetGasFeeUsesGas50xBlock(t *testing.T) {
	cfg := &ChainConfig{
		TIPTRC21FeeBlock: big.NewInt(50),
		Gas50xBlock:      big.NewInt(100),
		Gas2500xBlock:    big.NewInt(200),
	}

	beforeFork := GetGasFee(99, 2, cfg)
	if want := new(big.Int).Mul(big.NewInt(2), common.TRC21GasPrice); beforeFork.Cmp(want) != 0 {
		t.Fatalf("unexpected fee before gas50x fork: have %v want %v", beforeFork, want)
	}

	afterFork := GetGasFee(100, 2, cfg)
	if want := new(big.Int).Mul(big.NewInt(2), scaled(new(big.Int).SetUint64(common.DefaultMinGasPrice), 50)); afterFork.Cmp(want) != 0 {
		t.Fatalf("unexpected fee after gas50x fork: have %v want %v", afterFork, want)
	}

	afterGas2500x := GetGasFee(200, 2, cfg)
	if want := new(big.Int).Mul(big.NewInt(2), scaled(new(big.Int).SetUint64(common.DefaultMinGasPrice), 2500)); afterGas2500x.Cmp(want) != 0 {
		t.Fatalf("unexpected fee after gas2500x fork: have %v want %v", afterGas2500x, want)
	}
}

// TestGetGasFeeIgnoresForkHeightsAboveUint64 tests oversized fork heights do not wrap.
func TestGetGasFeeIgnoresForkHeightsAboveUint64(t *testing.T) {
	tipTRC21FeeBlock, ok := new(big.Int).SetString("18446744073709551626", 10)
	if !ok {
		t.Fatal("failed to construct TIPTRC21 fee fork height")
	}
	gas50xBlock, ok := new(big.Int).SetString("18446744073709551636", 10)
	if !ok {
		t.Fatal("failed to construct gas50x fork height")
	}
	cfg := &ChainConfig{
		TIPTRC21FeeBlock: tipTRC21FeeBlock,
		Gas50xBlock:      gas50xBlock,
	}

	for _, tc := range []struct {
		name  string
		block uint64
	}{
		{name: "before oversized tiptrc21 fork", block: 15},
		{name: "before oversized gas50x fork", block: 25},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fee := GetGasFee(tc.block, 2, cfg)
			if want := new(big.Int).Mul(big.NewInt(2), common.TRC21GasPriceBefore); fee.Cmp(want) != 0 {
				t.Fatalf("unexpected fee at block %d: have %v want %v", tc.block, fee, want)
			}
		})
	}
}

// TestGetGasPriceAndMinGasPriceUseGas50xBlock tests get gas price and min gas price use gas 50 x block.
func TestGetGasPriceAndMinGasPriceUseGas50xBlock(t *testing.T) {
	cfg := &ChainConfig{Gas50xBlock: big.NewInt(100), Gas2500xBlock: big.NewInt(200)}

	for _, tc := range []struct {
		name       string
		block      *big.Int
		multiplier int64
	}{
		{name: "before gas50x fork", block: big.NewInt(99), multiplier: 1},
		{name: "at gas50x fork", block: big.NewInt(100), multiplier: 50},
		{name: "below gas2500x fork", block: big.NewInt(199), multiplier: 50},
		{name: "at gas2500x fork", block: big.NewInt(200), multiplier: 2500},
		{name: "above gas2500x fork", block: big.NewInt(201), multiplier: 2500},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, want := GetGasPrice(tc.block, cfg), scaled(new(big.Int).SetUint64(common.DefaultMinGasPrice), tc.multiplier); got.Cmp(want) != 0 {
				t.Fatalf("unexpected gas price: have %v want %v", got, want)
			}
			if got, want := GetMinGasPrice(tc.block, cfg), scaled(new(big.Int).SetUint64(common.DefaultMinGasPrice), tc.multiplier); got.Cmp(want) != 0 {
				t.Fatalf("unexpected min gas price: have %v want %v", got, want)
			}
		})
	}
}

// TestBaseFeeForBlockMatchesGasPriceSchedule guards the invariant that the
// EIP-1559 base fee equals the chain-default gas price of every scheduled tier,
// so adding a tier cannot silently desynchronise header validation from the fee
// schedule and the fork order of EIP1559Block stays irrelevant to pricing.
func TestBaseFeeForBlockMatchesGasPriceSchedule(t *testing.T) {
	cfg := &ChainConfig{Gas50xBlock: big.NewInt(100), Gas2500xBlock: big.NewInt(200)}

	for _, block := range []*big.Int{big.NewInt(100), big.NewInt(199), big.NewInt(200), big.NewInt(201)} {
		if got, want := BaseFeeForBlock(cfg, block), GetGasPrice(block, cfg); got.Cmp(want) != 0 {
			t.Fatalf("base fee at block %v: have %v want %v", block, got, want)
		}
	}
}

// TestBaseFeeForBlockKeepsLegacyConstantBeforeGas50x pins the baseline tier to
// InitialBaseFee instead of the chain-default gas price. It covers both the
// London-to-Gas50x window, where mainnet has already produced blocks whose
// BASEFEE reported InitialBaseFee, and any chain that enables EIP-1559 before
// scheduling Gas50x, whose headers would otherwise be priced 50x lower.
func TestBaseFeeForBlockKeepsLegacyConstantBeforeGas50x(t *testing.T) {
	cfg := &ChainConfig{Gas50xBlock: big.NewInt(100)}

	for _, block := range []*big.Int{nil, big.NewInt(0), big.NewInt(99)} {
		if got, want := BaseFeeForBlock(cfg, block), new(big.Int).SetUint64(InitialBaseFee); got.Cmp(want) != 0 {
			t.Fatalf("unexpected pre-gas50x base fee at block %v: have %v want %v", block, got, want)
		}
	}
}

// TestInitialBaseFeeMatchesGas50xTier pins InitialBaseFee to the Gas50x tier
// price. BaseFeeForBlock falls back to InitialBaseFee below the first tier; if
// the two ever diverged, the base fee would jump at Gas50xBlock and every block
// already produced in the London-to-Gas50x window would replay with a different
// state root.
func TestInitialBaseFeeMatchesGas50xTier(t *testing.T) {
	cfg := &ChainConfig{Gas50xBlock: big.NewInt(0)}

	if got, want := BaseFeeForBlock(cfg, big.NewInt(0)), new(big.Int).SetUint64(InitialBaseFee); got.Cmp(want) != 0 {
		t.Fatalf("gas50x base fee drifted from InitialBaseFee: have %v want %v", got, want)
	}
	if got, want := new(big.Int).SetUint64(InitialBaseFee), scaled(new(big.Int).SetUint64(common.DefaultMinGasPrice), 50); got.Cmp(want) != 0 {
		t.Fatalf("InitialBaseFee drifted from the gas50x tier price: have %v want %v", got, want)
	}
}

// TestGasScheduleUnaffectedByUnscheduledGas2500x is the regression guard for
// networks that have not scheduled Gas2500x yet.
func TestGasScheduleUnaffectedByUnscheduledGas2500x(t *testing.T) {
	far, ok := new(big.Int).SetString("1000000000000", 10)
	if !ok {
		t.Fatal("failed to construct far-future fork height")
	}
	scheduled := &ChainConfig{TIPTRC21FeeBlock: big.NewInt(10), Gas50xBlock: big.NewInt(20), Gas2500xBlock: far}
	unscheduled := &ChainConfig{TIPTRC21FeeBlock: big.NewInt(10), Gas50xBlock: big.NewInt(20)}

	for _, block := range []*big.Int{big.NewInt(5), big.NewInt(11), big.NewInt(20), big.NewInt(1_000_000)} {
		if got, want := GetGasPrice(block, scheduled), GetGasPrice(block, unscheduled); got.Cmp(want) != 0 {
			t.Fatalf("gas price drifted at block %v: have %v want %v", block, got, want)
		}
		if got, want := GetMinGasPrice(block, scheduled), GetMinGasPrice(block, unscheduled); got.Cmp(want) != 0 {
			t.Fatalf("min gas price drifted at block %v: have %v want %v", block, got, want)
		}
		got, err := GetGasPriceForTRC21(block, scheduled)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want, err := GetGasPriceForTRC21(block, unscheduled)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Cmp(want) != 0 {
			t.Fatalf("trc21 gas price drifted at block %v: have %v want %v", block, got, want)
		}
	}
}

// TestGetGasFeeAllowsNilGas50xBlock tests nil Gas50xBlock means gas50x is unscheduled.
func TestGetGasFeeAllowsNilGas50xBlock(t *testing.T) {
	cfg := &ChainConfig{TIPTRC21FeeBlock: big.NewInt(10)}

	fee := GetGasFee(11, 2, cfg)
	if want := new(big.Int).Mul(big.NewInt(2), common.TRC21GasPrice); fee.Cmp(want) != 0 {
		t.Fatalf("unexpected fee with nil gas50x block: have %v want %v", fee, want)
	}
}

// TestGetGasFeeAllowsNilTIPTRC21FeeBlock tests nil TIPTRC21FeeBlock means the
// TRC21 fee switch remains unscheduled.
func TestGetGasFeeAllowsNilTIPTRC21FeeBlock(t *testing.T) {
	cfg := &ChainConfig{}

	fee := GetGasFee(11, 2, cfg)
	if want := new(big.Int).Mul(big.NewInt(2), common.TRC21GasPriceBefore); fee.Cmp(want) != 0 {
		t.Fatalf("unexpected fee with nil TIPTRC21 fee block: have %v want %v", fee, want)
	}
}

func TestGetGasFeeUsesGetGasPriceForTRC21(t *testing.T) {
	cfg := &ChainConfig{
		TIPTRC21FeeBlock: big.NewInt(10),
		Gas50xBlock:      big.NewInt(20),
		Gas2500xBlock:    big.NewInt(30),
	}

	for _, block := range []uint64{9, 10, 11, 20, 29, 30, 31} {
		fee := GetGasFee(block, 2, cfg)
		price, err := GetGasPriceForTRC21(new(big.Int).SetUint64(block), cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := new(big.Int).Mul(big.NewInt(2), price)
		if fee.Cmp(want) != 0 {
			t.Fatalf("unexpected fee at block %d: have %v want %v", block, fee, want)
		}
	}
}

// TestGasFeeResultsAreIndependent guards that GetGasFee never hands back a
// value aliasing the schedule, so a caller mutating the fee cannot corrupt it.
func TestGasFeeResultsAreIndependent(t *testing.T) {
	cfg := &ChainConfig{TIPTRC21FeeBlock: big.NewInt(10), Gas50xBlock: big.NewInt(100), Gas2500xBlock: big.NewInt(200)}

	for _, block := range []uint64{9, 11, 100, 200} {
		want := GetGasFee(block, 2, cfg)
		GetGasFee(block, 2, cfg).SetInt64(1)
		if got := GetGasFee(block, 2, cfg); got.Cmp(want) != 0 {
			t.Fatalf("gas fee at block %d corrupted by caller: have %v want %v", block, got, want)
		}
	}
}
