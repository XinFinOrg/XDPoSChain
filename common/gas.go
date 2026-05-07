package common

import "math/big"

var MinGasPrice50x = big.NewInt(12500000000)
var GasPrice50x = big.NewInt(12500000000)
var BaseFee = big.NewInt(12500000000)

// GetGasFee returns the effective fee for the given block and gas usage.
// Callers must ensure gas50xBlock >= tipTRC21FeeBlock when both values are configured.
func GetGasFee(blockNumber, gas uint64, tipTRC21FeeBlock, gas50xBlock *big.Int) *big.Int {
	fee := new(big.Int).SetUint64(gas)
	if gas50xBlock != nil && blockNumber >= gas50xBlock.Uint64() {
		return fee.Mul(fee, GasPrice50x)
	}
	if tipTRC21FeeBlock != nil && blockNumber > tipTRC21FeeBlock.Uint64() {
		return fee.Mul(fee, TRC21GasPrice)
	}
	return fee.Mul(fee, TRC21GasPriceBefore)
}

func GetGasPrice(number, gas50xBlock *big.Int) *big.Int {
	if number != nil && gas50xBlock != nil && number.Cmp(gas50xBlock) >= 0 {
		return new(big.Int).Set(GasPrice50x)
	}
	return new(big.Int).Set(TRC21GasPrice)
}

func GetMinGasPrice(number, gas50xBlock *big.Int) *big.Int {
	if number != nil && gas50xBlock != nil && number.Cmp(gas50xBlock) >= 0 {
		return new(big.Int).Set(MinGasPrice50x)
	}
	return new(big.Int).Set(MinGasPrice)
}
