package params

import (
	"errors"
	"math/big"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/log"
)

// gasTier describes one step of the XDC gas price schedule. price is the only
// value that defines a tier: the consensus baseline common.DefaultMinGasPrice
// scaled by the tier multiplier, shared by chain-default gas price, TRC21 gas
// price and EIP-1559 base fee. It is computed once at init and never mutated,
// so accessors handing it to a caller must return a copy.
type gasTier struct {
	price     *big.Int
	activated func(cfg *ChainConfig, number *big.Int) bool
}

// gasTiers is ordered from the latest fork to the earliest, so resolution
// returns the first active entry. Introducing a new tier means adding one row.
var gasTiers = []gasTier{
	{
		price:     scaledGasPrice(2500),
		activated: func(cfg *ChainConfig, number *big.Int) bool { return cfg.IsGas2500x(number) },
	},
	{
		price:     scaledGasPrice(50),
		activated: func(cfg *ChainConfig, number *big.Int) bool { return cfg.IsGas50x(number) },
	},
}

// scaledGasPrice returns the schedule baseline scaled by multiplier. Every
// price in the schedule is derived from the immutable common.DefaultMinGasPrice
// rather than a mutable package variable because it feeds consensus critical
// values such as the EIP-1559 base fee. The pre-Gas50x baseline is multiplier 1.
// The product is computed in big.Int so a future tier cannot silently overflow.
func scaledGasPrice(multiplier int64) *big.Int {
	return new(big.Int).Mul(big.NewInt(common.DefaultMinGasPrice), big.NewInt(multiplier))
}

// baselineGasPrice is the chain-default gas price of the pre-Gas50x baseline
// tier. Like the tier prices it is shared and must be copied before it escapes.
var baselineGasPrice = scaledGasPrice(1)

// tierGasPrice returns the gas price of the tier active at number, or false
// when no tier fork has fired yet and the caller must fall back to its own
// pre-Gas50x baseline. The returned value is shared, so copy it before handing
// it to a caller.
func tierGasPrice(cfg *ChainConfig, number *big.Int) (*big.Int, bool) {
	for _, tier := range gasTiers {
		if tier.activated(cfg, number) {
			return tier.price, true
		}
	}
	return nil, false
}

// baselineTRC21GasPrice returns the TRC21 gas price of the pre-Gas50x baseline
// tier, where an unscheduled TIPTRC21FeeBlock keeps the legacy price.
func baselineTRC21GasPrice(cfg *ChainConfig, number *big.Int) *big.Int {
	if number != nil && cfg.TIPTRC21FeeBlock != nil && number.Cmp(cfg.TIPTRC21FeeBlock) > 0 {
		return new(big.Int).Set(common.TRC21GasPrice)
	}
	return new(big.Int).Set(common.TRC21GasPriceBefore)
}

// BaseFeeForBlock returns the EIP-1559 base fee at number, which equals the
// chain-default gas price of the tier active there, so header validation and
// the fee schedule cannot drift apart. Before any tier has fired it falls back
// to InitialBaseFee, the value every EIP-1559 header carried before the
// schedule became fork aware. It does not check EIP1559Block, so callers
// filling a header must confirm EIP-1559 is active at number first.
func BaseFeeForBlock(cfg *ChainConfig, number *big.Int) *big.Int {
	if price, ok := tierGasPrice(cfg, number); ok {
		return new(big.Int).Set(price)
	}
	return new(big.Int).SetUint64(InitialBaseFee)
}

// BaseFeeForOpcode returns what the BASEFEE opcode reports for a block whose
// header carries no base fee, which is the London-to-EIP1559 window where XDC
// had the opcode but not the header field. It stays pinned to InitialBaseFee
// instead of resolving the gas schedule so a later tier fork cannot rewrite
// what those already executed blocks saw. CheckConfigForkOrder keeps that
// window on the Gas50x tier, whose price is InitialBaseFee, so no chain can
// schedule a higher tier while headers still lack the field.
func BaseFeeForOpcode() *big.Int {
	return new(big.Int).SetUint64(InitialBaseFee)
}

// GetGasPriceForTRC21 returns the effective gas price for TRC21 transactions
// at the given block number using the provided chain configuration.
func GetGasPriceForTRC21(number *big.Int, cfg *ChainConfig) (*big.Int, error) {
	if cfg == nil {
		return nil, errors.New("chain config is nil")
	}
	if number == nil {
		return nil, errors.New("block number is nil")
	}
	// Stricter than GetGasFee on purpose: state transition must run against a
	// fully scheduled fee config.
	if cfg.TIPTRC21FeeBlock == nil {
		return nil, errors.New("missing TIPTRC21FeeBlock in chain config")
	}
	if price, ok := tierGasPrice(cfg, number); ok {
		return new(big.Int).Set(price), nil
	}
	return baselineTRC21GasPrice(cfg, number), nil
}

// GetGasFee returns the effective fee for the given block height and gas usage
// using the active chain configuration schedule.
func GetGasFee(blockNumber, gas uint64, cfg *ChainConfig) *big.Int {
	if cfg == nil {
		log.Crit("GetGasFee received nil chain config")
	}
	block := new(big.Int).SetUint64(blockNumber)
	price, ok := tierGasPrice(cfg, block)
	if !ok {
		price = baselineTRC21GasPrice(cfg, block)
	}
	return new(big.Int).Mul(price, new(big.Int).SetUint64(gas))
}

// chainDefaultGasPrice resolves the chain-default gas price schedule at number.
func chainDefaultGasPrice(number *big.Int, cfg *ChainConfig) *big.Int {
	price, ok := tierGasPrice(cfg, number)
	if !ok {
		price = baselineGasPrice
	}
	return new(big.Int).Set(price)
}

// GetGasPrice returns the chain-default gas price for the given block height.
func GetGasPrice(number *big.Int, cfg *ChainConfig) *big.Int {
	if cfg == nil {
		log.Crit("GetGasPrice received nil chain config")
	}
	return chainDefaultGasPrice(number, cfg)
}

// GetMinGasPrice returns the chain-default minimum gas price for the given
// block height. It is pool-local and never consensus critical.
func GetMinGasPrice(number *big.Int, cfg *ChainConfig) *big.Int {
	if cfg == nil {
		log.Crit("GetMinGasPrice received nil chain config")
	}
	return chainDefaultGasPrice(number, cfg)
}
