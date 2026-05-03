package common

import (
	"math"
	"math/big"
)

var MainnetConstant = constant{
	chainID:          50,
	denylistHFNumber: 38383838,
	maxMasternodesV2: 108,

	tip2019Block:           big.NewInt(1),
	tipSigning:             big.NewInt(3000000),
	tipRandomize:           big.NewInt(3464000),
	tipNoHalvingMNReward:   big.NewInt(38383838),
	tipXDCX:                big.NewInt(38383838),
	tipXDCXLending:         big.NewInt(38383838),
	tipXDCXCancellationFee: big.NewInt(38383838),
	tipTRC21Fee:            big.NewInt(38383838),
	tipIncreaseMasternodes: big.NewInt(5000000),
	berlinBlock:            big.NewInt(76321000), // Target 19th June 2024
	londonBlock:            big.NewInt(76321000), // Target 19th June 2024
	mergeBlock:             big.NewInt(76321000), // Target 19th June 2024
	shanghaiBlock:          big.NewInt(76321000), // Target 19th June 2024
	blockNumberGas50x:      big.NewInt(80370000), // Target 2nd Oct 2024
	TIPV2SwitchBlock:       big.NewInt(80370000), // Target 2nd Oct 2024
	tipXDCXMinerDisable:    big.NewInt(80370000), // Target 2nd Oct 2024
	tipXDCXReceiverDisable: big.NewInt(80370900), // Target 2nd Oct 2024, safer to release after disable miner
	eip1559Block:           big.NewInt(98800200), // Target 28th Jan 2026
	cancunBlock:            big.NewInt(98802000), // Target 28th Jan 2026
	pragueBlock:            big.NewInt(math.MaxInt64),
	osakaBlock:             big.NewInt(math.MaxInt64),
	dynamicGasLimitBlock:   big.NewInt(math.MaxInt64),
	tipUpgradeReward:       big.NewInt(math.MaxInt64),
	tipUpgradePenalty:      big.NewInt(math.MaxInt64),
	tipEpochHalving:        big.NewInt(math.MaxInt64),

	trc21IssuerSMC:         HexToAddress("0x8c0faeb5C6bEd2129b8674F262Fd45c4e9468bee"),
	xdcxListingSMC:         HexToAddress("0xDE34dD0f536170993E8CFF639DdFfCF1A85D3E53"),
	relayerRegistrationSMC: HexToAddress("0x16c63b79f9C8784168103C0b74E6A59EC2de4a02"),
	lendingRegistrationSMC: HexToAddress("0x7d761afd7ff65a79e4173897594a194e3c506e57"),
}
