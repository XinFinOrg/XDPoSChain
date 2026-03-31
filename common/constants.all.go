package common

import (
	"fmt"
	"maps"
	"math/big"

	"github.com/XinFinOrg/XDPoSChain/log"
)

// non-const variables for all network.
var (
	IsTestnet      bool = false
	Enable0xPrefix bool = true

	RollbackNumber = uint64(0)

	StoreRewardFolder string

	TRC21GasPriceBefore = big.NewInt(2500)
	TRC21GasPrice       = big.NewInt(250000000)
	MinGasPrice         = big.NewInt(DefaultMinGasPrice)

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

type constant struct {
	chainID          uint64
	denylistHFNumber uint64
	maxMasternodesV2 int // Last v1 masternodes

	tip2019Block           *big.Int
	tipSigning             *big.Int
	tipRandomize           *big.Int
	tipNoHalvingMNReward   *big.Int // hard fork no halving masternodes reward
	tipXDCX                *big.Int
	tipXDCXLending         *big.Int
	tipXDCXCancellationFee *big.Int
	tipTRC21Fee            *big.Int
	tipIncreaseMasternodes *big.Int // Upgrade MN Count at Block.
	berlinBlock            *big.Int
	londonBlock            *big.Int
	mergeBlock             *big.Int
	shanghaiBlock          *big.Int
	blockNumberGas50x      *big.Int
	TIPV2SwitchBlock       *big.Int
	tipXDCXMinerDisable    *big.Int
	tipXDCXReceiverDisable *big.Int
	tipUpgradeReward       *big.Int
	tipUpgradePenalty      *big.Int
	tipEpochHalving        *big.Int
	eip1559Block           *big.Int
	cancunBlock            *big.Int
	pragueBlock            *big.Int
	osakaBlock             *big.Int
	dynamicGasLimitBlock   *big.Int

	trc21IssuerSMC         Address
	xdcxListingSMC         Address
	relayerRegistrationSMC Address
	lendingRegistrationSMC Address

	ignoreSignerCheckBlockArray map[uint64]struct{}

	denylist map[Address]struct{}
}

func (c *constant) print() {
	fmt.Println("chainID:", c.chainID)
	fmt.Println("denylistHFNumber:", c.denylistHFNumber)
	fmt.Println("maxMasternodesV2:", c.maxMasternodesV2)
	fmt.Println("tip2019Block:", c.tip2019Block)
	fmt.Println("tipSigning:", c.tipSigning)
	fmt.Println("tipRandomize:", c.tipRandomize)
	fmt.Println("tipNoHalvingMNReward:", c.tipNoHalvingMNReward)
	fmt.Println("tipXDCX:", c.tipXDCX)
	fmt.Println("tipXDCXLending:", c.tipXDCXLending)
	fmt.Println("tipXDCXCancellationFee:", c.tipXDCXCancellationFee)
	fmt.Println("tipTRC21Fee:", c.tipTRC21Fee)
	fmt.Println("tipIncreaseMasternodes:", c.tipIncreaseMasternodes)
	fmt.Println("berlinBlock:", c.berlinBlock)
	fmt.Println("londonBlock:", c.londonBlock)
	fmt.Println("mergeBlock:", c.mergeBlock)
	fmt.Println("shanghaiBlock:", c.shanghaiBlock)
	fmt.Println("blockNumberGas50x:", c.blockNumberGas50x)
	fmt.Println("TIPV2SwitchBlock:", c.TIPV2SwitchBlock)
	fmt.Println("tipXDCXMinerDisable:", c.tipXDCXMinerDisable)
	fmt.Println("tipXDCXReceiverDisable:", c.tipXDCXReceiverDisable)
	fmt.Println("tipUpgradeReward:", c.tipUpgradeReward)
	fmt.Println("tipUpgradePenalty:", c.tipUpgradePenalty)
	fmt.Println("tipEpochHalving:", c.tipEpochHalving)
	fmt.Println("eip1559Block:", c.eip1559Block)
	fmt.Println("cancunBlock:", c.cancunBlock)
	fmt.Println("pragueBlock:", c.pragueBlock)
	fmt.Println("osakaBlock:", c.osakaBlock)
	fmt.Println("dynamicGasLimitBlock:", c.dynamicGasLimitBlock)
	fmt.Println("trc21IssuerSMC:", c.trc21IssuerSMC)
	fmt.Println("xdcxListingSMC:", c.xdcxListingSMC)
	fmt.Println("relayerRegistrationSMC:", c.relayerRegistrationSMC)
	fmt.Println("lendingRegistrationSMC:", c.lendingRegistrationSMC)
	fmt.Println("ignoreSignerCheckBlockArray:", c.ignoreSignerCheckBlockArray)
	fmt.Println("denylist:", c.denylist)
}

// variables for specific networks, copy values from mainnet constant to pass tests
var (
	DenylistHFNumber = MainnetConstant.denylistHFNumber
	MaxMasternodesV2 = MainnetConstant.maxMasternodesV2 // Last v1 masternodes

	TIP2019Block           = MainnetConstant.tip2019Block
	TIPSigning             = MainnetConstant.tipSigning
	TIPRandomize           = MainnetConstant.tipRandomize
	TIPNoHalvingMNReward   = MainnetConstant.tipNoHalvingMNReward
	TIPXDCX                = MainnetConstant.tipXDCX
	TIPXDCXLending         = MainnetConstant.tipXDCXLending
	TIPXDCXCancellationFee = MainnetConstant.tipXDCXCancellationFee
	TIPTRC21Fee            = MainnetConstant.tipTRC21Fee
	TIPIncreaseMasternodes = MainnetConstant.tipIncreaseMasternodes
	BerlinBlock            = MainnetConstant.berlinBlock
	LondonBlock            = MainnetConstant.londonBlock
	MergeBlock             = MainnetConstant.mergeBlock
	ShanghaiBlock          = MainnetConstant.shanghaiBlock
	BlockNumberGas50x      = MainnetConstant.blockNumberGas50x
	TIPXDCXMinerDisable    = MainnetConstant.tipXDCXMinerDisable
	TIPXDCXReceiverDisable = MainnetConstant.tipXDCXReceiverDisable
	Eip1559Block           = MainnetConstant.eip1559Block
	CancunBlock            = MainnetConstant.cancunBlock
	PragueBlock            = MainnetConstant.pragueBlock
	OsakaBlock             = MainnetConstant.osakaBlock
	DynamicGasLimitBlock   = MainnetConstant.dynamicGasLimitBlock
	TIPUpgradeReward       = MainnetConstant.tipUpgradeReward
	TipUpgradePenalty      = MainnetConstant.tipUpgradePenalty
	TIPEpochHalving        = MainnetConstant.tipEpochHalving

	TRC21IssuerSMC         = MainnetConstant.trc21IssuerSMC
	XDCXListingSMC         = MainnetConstant.xdcxListingSMC
	RelayerRegistrationSMC = MainnetConstant.relayerRegistrationSMC
	LendingRegistrationSMC = MainnetConstant.lendingRegistrationSMC

	ignoreSignerCheckBlockArray = MainnetConstant.ignoreSignerCheckBlockArray
	denylist                    = MainnetConstant.denylist
)

func IsIgnoreSignerCheckBlock(blockNumber uint64) bool {
	_, ok := ignoreSignerCheckBlockArray[blockNumber]
	return ok
}

func IsInDenylist(address *Address) bool {
	if address == nil {
		return false
	}
	_, ok := denylist[*address]
	return ok
}

// CopyConstants only handles testnet, devnet, local network.
// It skips mainnet since the default value is from mainnet.
func CopyConstants(chainID uint64) {
	log.Info("[CopyConstants]", "chainID", chainID)
	var c *constant
	switch chainID {
	case MainnetConstant.chainID:
		log.Info("[CopyConstants] mainnet chainID matched, no need to copy constants")
		return
	case TestnetConstant.chainID:
		log.Info("[CopyConstants] testnet chainID matched, copying testnet constants")
		c = &TestnetConstant
		IsTestnet = true
	case DevnetConstant.chainID:
		log.Info("[CopyConstants] devnet chainID matched, copying devnet constants")
		c = &DevnetConstant
	default: // local custom chain, it can have any chainID
		log.Info("[CopyConstants] local chainID matched, copying local constants")
		c = &localConstant
	}
	c.print()

	MaxMasternodesV2 = c.maxMasternodesV2
	DenylistHFNumber = c.denylistHFNumber
	TIP2019Block = c.tip2019Block
	TIPSigning = c.tipSigning
	TIPRandomize = c.tipRandomize
	TIPNoHalvingMNReward = c.tipNoHalvingMNReward
	TIPXDCX = c.tipXDCX
	TIPXDCXLending = c.tipXDCXLending
	TIPXDCXCancellationFee = c.tipXDCXCancellationFee
	TIPTRC21Fee = c.tipTRC21Fee
	TIPIncreaseMasternodes = c.tipIncreaseMasternodes
	BerlinBlock = c.berlinBlock
	LondonBlock = c.londonBlock
	MergeBlock = c.mergeBlock
	ShanghaiBlock = c.shanghaiBlock
	BlockNumberGas50x = c.blockNumberGas50x
	TIPXDCXMinerDisable = c.tipXDCXMinerDisable
	TIPXDCXReceiverDisable = c.tipXDCXReceiverDisable
	Eip1559Block = c.eip1559Block
	CancunBlock = c.cancunBlock
	PragueBlock = c.pragueBlock
	OsakaBlock = c.osakaBlock
	DynamicGasLimitBlock = c.dynamicGasLimitBlock
	TIPUpgradeReward = c.tipUpgradeReward
	TipUpgradePenalty = c.tipUpgradePenalty
	TIPEpochHalving = c.tipEpochHalving

	TRC21IssuerSMC = c.trc21IssuerSMC
	XDCXListingSMC = c.xdcxListingSMC
	RelayerRegistrationSMC = c.relayerRegistrationSMC
	LendingRegistrationSMC = c.lendingRegistrationSMC

	clear(ignoreSignerCheckBlockArray)
	maps.Copy(ignoreSignerCheckBlockArray, c.ignoreSignerCheckBlockArray)

	clear(denylist)
	maps.Copy(denylist, c.denylist)
}
