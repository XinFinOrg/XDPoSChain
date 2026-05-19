package params

import (
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
)

func TestGetGasPriceForTRC21(t *testing.T) {
	cfg := &ChainConfig{
		TIPTRC21FeeBlock: big.NewInt(10),
		Gas50xBlock:      big.NewInt(20),
	}

	tests := []struct {
		name  string
		block *big.Int
		want  *big.Int
	}{
		// {name: "nil block uses pre-tip price", block: nil, want: common.TRC21GasPriceBefore}, // removed: number must not be nil
		{name: "activation block uses pre-tip price", block: big.NewInt(10), want: common.TRC21GasPriceBefore},
		{name: "after tip block uses tip price", block: big.NewInt(11), want: common.TRC21GasPrice},
		{name: "gas50x block uses gas50x price", block: big.NewInt(20), want: gasPrice50x},
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

// TestGetGasFeeUsesGas50xBlock tests get gas fee uses gas 50 x block.
func TestGetGasFeeUsesGas50xBlock(t *testing.T) {
	cfg := &ChainConfig{
		TIPTRC21FeeBlock: big.NewInt(50),
		Gas50xBlock:      big.NewInt(100),
	}

	beforeFork := GetGasFee(99, 2, cfg)
	if want := new(big.Int).Mul(big.NewInt(2), common.TRC21GasPrice); beforeFork.Cmp(want) != 0 {
		t.Fatalf("unexpected fee before gas50x fork: have %v want %v", beforeFork, want)
	}

	afterFork := GetGasFee(100, 2, cfg)
	if want := new(big.Int).Mul(big.NewInt(2), gasPrice50x); afterFork.Cmp(want) != 0 {
		t.Fatalf("unexpected fee after gas50x fork: have %v want %v", afterFork, want)
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
	cfg := &ChainConfig{Gas50xBlock: big.NewInt(100)}

	if got := GetGasPrice(big.NewInt(99), cfg); got.Cmp(common.TRC21GasPrice) != 0 {
		t.Fatalf("unexpected gas price before gas50x fork: have %v want %v", got, common.TRC21GasPrice)
	}
	if got := GetGasPrice(big.NewInt(100), cfg); got.Cmp(gasPrice50x) != 0 {
		t.Fatalf("unexpected gas price after gas50x fork: have %v want %v", got, gasPrice50x)
	}
	if got := GetMinGasPrice(big.NewInt(99), cfg); got.Cmp(common.MinGasPrice) != 0 {
		t.Fatalf("unexpected min gas price before gas50x fork: have %v want %v", got, common.MinGasPrice)
	}
	if got := GetMinGasPrice(big.NewInt(100), cfg); got.Cmp(minGasPrice50x) != 0 {
		t.Fatalf("unexpected min gas price after gas50x fork: have %v want %v", got, minGasPrice50x)
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
	}

	for _, block := range []uint64{9, 10, 11, 20} {
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
