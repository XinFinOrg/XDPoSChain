package common

import (
	"math/big"
)

// Shared default values for all networks.
const (
	RewardMasterPercent        = 90
	RewardVoterPercent         = 0
	RewardFoundationPercent    = 10
	EpocBlockSecret            = 800
	EpocBlockOpening           = 850
	EpocBlockRandomize         = 900
	MaxMasternodes             = 18
	LimitPenaltyEpoch          = 4
	LimitPenaltyEpochV2        = 0
	LimitThresholdNonceInQueue = 10
	DefaultMinGasPrice         = 250000000
	MergeSignRange             = 15
	RangeReturnSigner          = 150
	MinimunMinerBlockPerEpoch  = 1
	BlocksPerYearTest          = uint64(200000)
	BlocksPerYear              = uint64(15768000)
	OneYear                    = uint64(365 * 86400)
	LiquidateLendingTradeBlock = uint64(100)
	LimitTimeFinality          = uint64(30) // limit in 30 block

	HexSignMethod = "e341eaa4"
	HexSetSecret  = "34d38600"
	HexSetOpening = "e11f5ba2"
)

var (
	Enable0xPrefix = true

	RollbackNumber = uint64(0)

	StoreRewardFolder string

	TRC21GasPriceBefore = big.NewInt(2500)
	TRC21GasPrice       = big.NewInt(250000000)
	MinGasPrice         = big.NewInt(250000000)
	BaseFee             = big.NewInt(12500000000)

	// XDCx and XDCxlending
	BasePrice         = big.NewInt(1000000000000000000)               // 1
	RelayerLockedFund = big.NewInt(20000)                             // 20000 XDC
	XDCXBaseFee       = big.NewInt(10000)                             // 1 / XDCXBaseFee
	XDCXBaseCancelFee = new(big.Int).Mul(XDCXBaseFee, big.NewInt(10)) // 1/ (XDCXBaseFee *10)

	// XDCx
	RelayerFee       = big.NewInt(1000000000000000) // 0.001
	RelayerCancelFee = big.NewInt(100000000000000)  // 0.0001

	// XDCxlending
	RateTopUp               = big.NewInt(90) // 90%
	BaseTopUp               = big.NewInt(100)
	BaseRecall              = big.NewInt(100)
	BaseLendingInterest     = big.NewInt(100000000)         // 1e8
	RelayerLendingFee       = big.NewInt(10000000000000000) // 0.01
	RelayerLendingCancelFee = big.NewInt(1000000000000000)  // 0.001
)
