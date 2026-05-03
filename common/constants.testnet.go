package common

import (
	"math"
	"math/big"
)

var TestnetConstant = constant{
	chainID:          51,
	denylistHFNumber: 23779191,
	maxMasternodesV2: 15,

	tip2019Block:           big.NewInt(1),
	tipSigning:             big.NewInt(3000000),
	tipRandomize:           big.NewInt(3464000),
	tipNoHalvingMNReward:   big.NewInt(23779191), // hardfork no halving masternodes reward
	tipXDCX:                big.NewInt(23779191),
	tipXDCXLending:         big.NewInt(23779191),
	tipXDCXCancellationFee: big.NewInt(23779191),
	tipTRC21Fee:            big.NewInt(23779191),
	tipIncreaseMasternodes: big.NewInt(5000000),
	blockNumberGas50x:      big.NewInt(56828700), // Target 13rd Nov 2023
	TIPV2SwitchBlock:       big.NewInt(56828700), // Target 13rd Nov 2023
	berlinBlock:            big.NewInt(61290000), // Target 31st March 2024
	londonBlock:            big.NewInt(61290000), // Target 31st March 2024
	mergeBlock:             big.NewInt(61290000), // Target 31st March 2024
	shanghaiBlock:          big.NewInt(61290000), // Target 31st March 2024
	tipXDCXMinerDisable:    big.NewInt(61290000), // Target 31st March 2024
	tipXDCXReceiverDisable: big.NewInt(66825000), // Target 26 Aug 2024
	eip1559Block:           big.NewInt(71550000), // Target 14th Feb 2025
	cancunBlock:            big.NewInt(71551800),
	pragueBlock:            big.NewInt(math.MaxInt64),
	osakaBlock:             big.NewInt(math.MaxInt64),
	dynamicGasLimitBlock:   big.NewInt(math.MaxInt64),
	tipUpgradeReward:       big.NewInt(math.MaxInt64),
	tipUpgradePenalty:      big.NewInt(math.MaxInt64),
	tipEpochHalving:        big.NewInt(math.MaxInt64),

	trc21IssuerSMC:         HexToAddress("0x0E2C88753131CE01c7551B726b28BFD04e44003F"),
	xdcxListingSMC:         HexToAddress("0x14B2Bf043b9c31827A472CE4F94294fE9a6277e0"),
	relayerRegistrationSMC: HexToAddress("0xA1996F69f47ba14Cb7f661010A7C31974277958c"),
	lendingRegistrationSMC: HexToAddress("0x28d7fC2Cf5c18203aaCD7459EFC6Af0643C97bE8"),
}
