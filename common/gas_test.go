package common

import (
	"math/big"
	"testing"
)

func TestGetGasFeeUsesGas50xBlock(t *testing.T) {
	gas50xBlock := big.NewInt(100)
	tipTRC21FeeBlock := big.NewInt(50)

	beforeFork := GetGasFee(99, 2, tipTRC21FeeBlock, gas50xBlock)
	if want := new(big.Int).Mul(big.NewInt(2), TRC21GasPrice); beforeFork.Cmp(want) != 0 {
		t.Fatalf("unexpected fee before gas50x fork: have %v want %v", beforeFork, want)
	}

	afterFork := GetGasFee(100, 2, tipTRC21FeeBlock, gas50xBlock)
	if want := new(big.Int).Mul(big.NewInt(2), GasPrice50x); afterFork.Cmp(want) != 0 {
		t.Fatalf("unexpected fee after gas50x fork: have %v want %v", afterFork, want)
	}
}

func TestGetGasPriceAndMinGasPriceUseGas50xBlock(t *testing.T) {
	gas50xBlock := big.NewInt(100)

	if got := GetGasPrice(big.NewInt(99), gas50xBlock); got.Cmp(TRC21GasPrice) != 0 {
		t.Fatalf("unexpected gas price before gas50x fork: have %v want %v", got, TRC21GasPrice)
	}
	if got := GetGasPrice(big.NewInt(100), gas50xBlock); got.Cmp(GasPrice50x) != 0 {
		t.Fatalf("unexpected gas price after gas50x fork: have %v want %v", got, GasPrice50x)
	}
	if got := GetMinGasPrice(big.NewInt(99), gas50xBlock); got.Cmp(MinGasPrice) != 0 {
		t.Fatalf("unexpected min gas price before gas50x fork: have %v want %v", got, MinGasPrice)
	}
	if got := GetMinGasPrice(big.NewInt(100), gas50xBlock); got.Cmp(MinGasPrice50x) != 0 {
		t.Fatalf("unexpected min gas price after gas50x fork: have %v want %v", got, MinGasPrice50x)
	}
}
