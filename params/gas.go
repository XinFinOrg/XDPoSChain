package params

import (
	"errors"
	"math/big"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/log"
)

var gasPrice50x = big.NewInt(12500000000)
var minGasPrice50x = big.NewInt(12500000000)

// SetMinGasPrice50x updates minGasPrice50x based on min gas price. It is only
// called once during node startup.
func SetMinGasPrice50x(minPrice *big.Int) {
	if minPrice == nil {
		log.Crit("SetMinGasPrice50x can't handle nil gas price")
	}
	minGasPrice50x = new(big.Int).Mul(minPrice, big.NewInt(50))
}

// GetGasPriceForTRC21 returns the effective gas price for TRC21 transactions
// at the given block number using the provided chain configuration.
//
// NOTE: number is not nil when called from state transition
func GetGasPriceForTRC21(number *big.Int, cfg *ChainConfig) (*big.Int, error) {
	if cfg == nil {
		return nil, errors.New("missing chain config for GetGasPriceForTRC21")
	}
	if cfg.TIPTRC21FeeBlock == nil {
		return nil, errors.New("missing TIPTRC21FeeBlock for GetGasPriceForTRC21")
	}
	if cfg.Gas50xBlock != nil && number.Cmp(cfg.Gas50xBlock) >= 0 {
		return new(big.Int).Set(gasPrice50x), nil
	}
	if number.Cmp(cfg.TIPTRC21FeeBlock) > 0 {
		return new(big.Int).Set(common.TRC21GasPrice), nil
	}
	return new(big.Int).Set(common.TRC21GasPriceBefore), nil
}

// GetGasFee returns the effective fee for the given block height and gas usage
// using the active chain configuration schedule.
//
// NOTE: caller must ensure cfg is non-nil
func GetGasFee(blockNumber, gas uint64, cfg *ChainConfig) *big.Int {
	if cfg == nil {
		log.Crit("GetGasFee received nil chain config")
	}
	fee := new(big.Int).SetUint64(gas)
	block := new(big.Int).SetUint64(blockNumber)
	if cfg.Gas50xBlock != nil && block.Cmp(cfg.Gas50xBlock) >= 0 {
		return fee.Mul(fee, gasPrice50x)
	}
	if cfg.TIPTRC21FeeBlock != nil && block.Cmp(cfg.TIPTRC21FeeBlock) > 0 {
		return fee.Mul(fee, common.TRC21GasPrice)
	}
	return fee.Mul(fee, common.TRC21GasPriceBefore)
}

// GetGasPrice returns the chain-default gas price for the given block height.
func GetGasPrice(number *big.Int, cfg *ChainConfig) *big.Int {
	if cfg == nil {
		log.Crit("GetGasPrice received nil chain config")
	}
	if number != nil && cfg.Gas50xBlock != nil && number.Cmp(cfg.Gas50xBlock) >= 0 {
		return new(big.Int).Set(gasPrice50x)
	}
	return new(big.Int).Set(common.TRC21GasPrice)
}

// GetMinGasPrice returns the chain-default minimum gas price for the given
// block height.
func GetMinGasPrice(number *big.Int, cfg *ChainConfig) *big.Int {
	if cfg == nil {
		log.Crit("GetMinGasPrice received nil chain config")
	}
	if number != nil && cfg.Gas50xBlock != nil && number.Cmp(cfg.Gas50xBlock) >= 0 {
		return new(big.Int).Set(minGasPrice50x)
	}
	return new(big.Int).Set(common.MinGasPrice)
}
