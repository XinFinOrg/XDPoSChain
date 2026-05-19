package lendingstate

import (
	"errors"
	"math/big"

	"github.com/XinFinOrg/XDPoSChain/XDCx/tradingstate"
	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/log"
)

var (
	LendingRelayerListSlot    = uint64(0)
	CollateralMapSlot         = uint64(1)
	DefaultCollateralSlot     = uint64(2)
	SupportedBaseSlot         = uint64(3)
	SupportedTermSlot         = uint64(4)
	ILOCollateralSlot         = uint64(5)
	LendingRelayerStructSlots = map[string]*big.Int{
		"fee":         big.NewInt(0),
		"bases":       big.NewInt(1),
		"terms":       big.NewInt(2),
		"collaterals": big.NewInt(3),
	}
	CollateralStructSlots = map[string]*big.Int{
		"depositRate":     big.NewInt(0),
		"liquidationRate": big.NewInt(1),
		"recallRate":      big.NewInt(2),
		"price":           big.NewInt(3),
	}
	PriceStructSlots = map[string]*big.Int{
		"price":       big.NewInt(0),
		"blockNumber": big.NewInt(1),
	}
)

// lendingRegistrationSMC returns the lending registration contract address
// configured on the StateDB's attached chain config.
func lendingRegistrationSMC(statedb *state.StateDB) (common.Address, bool) {
	addr, err := statedb.LendingRegistrationSMC()
	if err != nil {
		return common.Address{}, false
	}
	return addr, true
}

// @function IsValidRelayer : return whether the given address is the coinbase of a valid relayer or not
// @param statedb : current state
// @param coinbase: coinbase address of relayer
// @return: true if it's a valid coinbase address of lending protocol, otherwise return false
func IsValidRelayer(statedb *state.StateDB, coinbase common.Address) bool {
	contract, ok := lendingRegistrationSMC(statedb)
	if !ok {
		return false
	}
	relayerContract, ok := relayerRegistrationSMC(statedb)
	if !ok {
		return false
	}
	locRelayerState := GetLocMappingAtKey(coinbase.Hash(), LendingRelayerListSlot)

	// a valid relayer must have baseToken
	locBaseToken := state.GetLocOfStructElement(locRelayerState, LendingRelayerStructSlots["bases"])
	if v := statedb.GetState(contract, common.BytesToHash(locBaseToken.Bytes())); v != (common.Hash{}) {
		if tradingstate.IsResignedRelayer(coinbase, statedb) {
			return false
		}
		slot := tradingstate.RelayerMappingSlot["RELAYER_LIST"]
		locRelayerStateTrading := GetLocMappingAtKey(coinbase.Hash(), slot)

		locBigDeposit := new(big.Int).SetUint64(uint64(0)).Add(locRelayerStateTrading, tradingstate.RelayerStructMappingSlot["_deposit"])
		locHashDeposit := common.BigToHash(locBigDeposit)
		balance := statedb.GetState(relayerContract, locHashDeposit).Big()
		expectedFund := new(big.Int).Mul(common.BasePrice, common.RelayerLockedFund)
		if balance.Cmp(expectedFund) <= 0 {
			log.Debug("Relayer is not in relayer list", "relayer", coinbase, "balance", balance, "expected", expectedFund)
			return false
		}
		return true
	}
	return false
}

// @function GetFee
// @param statedb : current state
// @param coinbase: coinbase address of relayer
// @return: feeRate of lending
func GetFee(statedb *state.StateDB, coinbase common.Address) *big.Int {
	contract, ok := lendingRegistrationSMC(statedb)
	if !ok {
		return new(big.Int)
	}
	locRelayerState := state.GetLocMappingAtKey(coinbase.Hash(), LendingRelayerListSlot)
	locHash := common.BytesToHash(new(big.Int).Add(locRelayerState, LendingRelayerStructSlots["fee"]).Bytes())
	return statedb.GetState(contract, locHash).Big()
}

// getBaseListAt returns the base-token list configured for coinbase in contract.
func getBaseListAt(statedb *state.StateDB, contract common.Address, coinbase common.Address) []common.Address {
	baseList := []common.Address{}
	locRelayerState := state.GetLocMappingAtKey(coinbase.Hash(), LendingRelayerListSlot)
	locBaseHash := state.GetLocOfStructElement(locRelayerState, LendingRelayerStructSlots["bases"])
	length := statedb.GetState(contract, locBaseHash).Big().Uint64()
	for i := uint64(0); i < length; i++ {
		loc := state.GetLocDynamicArrAtElement(locBaseHash, i, 1)
		addr := common.BytesToAddress(statedb.GetState(contract, loc).Bytes())
		if addr != (common.Address{}) {
			baseList = append(baseList, addr)
		}
	}
	return baseList
}

// getTermsAt returns the supported lending terms configured for coinbase in contract.
func getTermsAt(statedb *state.StateDB, contract common.Address, coinbase common.Address) []uint64 {
	terms := []uint64{}
	locRelayerState := state.GetLocMappingAtKey(coinbase.Hash(), LendingRelayerListSlot)
	locTermHash := state.GetLocOfStructElement(locRelayerState, LendingRelayerStructSlots["terms"])
	length := statedb.GetState(contract, locTermHash).Big().Uint64()
	for i := uint64(0); i < length; i++ {
		loc := state.GetLocDynamicArrAtElement(locTermHash, i, 1)
		t := statedb.GetState(contract, loc).Big().Uint64()
		if t != uint64(0) {
			terms = append(terms, t)
		}
	}
	return terms
}

// @function IsValidPair
// @param statedb : current state
// @param coinbase: coinbase address of relayer
// @param baseToken: address of baseToken
// @param terms: term
// @return: TRUE if the given baseToken, term organize a valid pair
func IsValidPair(statedb *state.StateDB, coinbase common.Address, baseToken common.Address, term uint64) (valid bool, pairIndex uint64) {
	contract, ok := lendingRegistrationSMC(statedb)
	if !ok {
		return false, 0
	}
	baseTokenList := getBaseListAt(statedb, contract, coinbase)
	terms := getTermsAt(statedb, contract, coinbase)
	baseIndexes := []uint64{}
	for i := uint64(0); i < uint64(len(baseTokenList)); i++ {
		if baseTokenList[i] == baseToken {
			baseIndexes = append(baseIndexes, i)
		}
	}
	for _, index := range baseIndexes {
		if terms[index] == term {
			pairIndex = index
			return true, pairIndex
		}
	}
	return false, pairIndex
}

// @function GetCollaterals
// @param statedb : current state
// @param coinbase: coinbase address of relayer
// @param baseToken: address of baseToken
// @param terms: term
// @return:
//   - collaterals []common.Address  : list of addresses of collateral
func GetCollaterals(statedb *state.StateDB, coinbase common.Address, baseToken common.Address, term uint64) (collaterals []common.Address) {
	validPair, _ := IsValidPair(statedb, coinbase, baseToken, term)
	if !validPair {
		return []common.Address{}
	}
	contract, _ := lendingRegistrationSMC(statedb)

	//TODO: ILO Collateral is not supported in release 2.2.0
	//locRelayerState := state.GetLocMappingAtKey(coinbase.Hash(), LendingRelayerListSlot)
	//locCollateralHash := state.GetLocOfStructElement(locRelayerState, LendingRelayerStructSlots["collaterals"])
	//length := statedb.GetState(common.LendingRegistrationSMC, locCollateralHash).Big().Uint64()
	//
	//loc := state.GetLocDynamicArrAtElement(locCollateralHash, pairIndex, 1)
	//collateralAddr := common.BytesToAddress(statedb.GetState(common.LendingRegistrationSMC, loc).Bytes())
	//if collateralAddr != (common.Address{}) && collateralAddr != (common.HexToAddress("0x0")) {
	//	return []common.Address{collateralAddr}, true
	//}

	// if collaterals is not defined for the relayer, return default collaterals
	locDefaultCollateralHash := state.GetLocSimpleVariable(DefaultCollateralSlot)
	length := statedb.GetState(contract, locDefaultCollateralHash).Big().Uint64()
	for i := uint64(0); i < length; i++ {
		loc := state.GetLocDynamicArrAtElement(locDefaultCollateralHash, i, 1)
		addr := common.BytesToAddress(statedb.GetState(contract, loc).Bytes())
		if addr != (common.Address{}) {
			collaterals = append(collaterals, addr)
		}
	}
	return collaterals
}

// @function GetCollateralDetail
// @param statedb : current state
// @param token: address of collateral token
// @return: depositRate, liquidationRate, price of collateral
func GetCollateralDetail(statedb *state.StateDB, token common.Address) (depositRate, liquidationRate, recallRate *big.Int) {
	contract, _ := lendingRegistrationSMC(statedb)
	collateralState := GetLocMappingAtKey(token.Hash(), CollateralMapSlot)
	locDepositRate := state.GetLocOfStructElement(collateralState, CollateralStructSlots["depositRate"])
	locLiquidationRate := state.GetLocOfStructElement(collateralState, CollateralStructSlots["liquidationRate"])
	locRecallRate := state.GetLocOfStructElement(collateralState, CollateralStructSlots["recallRate"])
	depositRate = statedb.GetState(contract, locDepositRate).Big()
	liquidationRate = statedb.GetState(contract, locLiquidationRate).Big()
	recallRate = statedb.GetState(contract, locRecallRate).Big()
	return depositRate, liquidationRate, recallRate
}

func GetCollateralPrice(statedb *state.StateDB, collateralToken common.Address, lendingToken common.Address) (price, blockNumber *big.Int) {
	contract, _ := lendingRegistrationSMC(statedb)
	collateralState := GetLocMappingAtKey(collateralToken.Hash(), CollateralMapSlot)
	locMapPrices := collateralState.Add(collateralState, CollateralStructSlots["price"])
	locLendingTokenPriceByte := crypto.Keccak256(lendingToken.Hash().Bytes(), common.BigToHash(locMapPrices).Bytes())

	locCollateralPrice := common.BigToHash(new(big.Int).Add(new(big.Int).SetBytes(locLendingTokenPriceByte), PriceStructSlots["price"]))
	locBlockNumber := common.BigToHash(new(big.Int).Add(new(big.Int).SetBytes(locLendingTokenPriceByte), PriceStructSlots["blockNumber"]))

	price = statedb.GetState(contract, locCollateralPrice).Big()
	blockNumber = statedb.GetState(contract, locBlockNumber).Big()
	return price, blockNumber
}

// getSupportedTermsAt returns the globally supported lending terms in contract.
func getSupportedTermsAt(statedb *state.StateDB, contract common.Address) []uint64 {
	terms := []uint64{}
	locSupportedTerm := state.GetLocSimpleVariable(SupportedTermSlot)
	length := statedb.GetState(contract, locSupportedTerm).Big().Uint64()
	for i := uint64(0); i < length; i++ {
		loc := state.GetLocDynamicArrAtElement(locSupportedTerm, i, 1)
		t := statedb.GetState(contract, loc).Big().Uint64()
		if t != 0 {
			terms = append(terms, t)
		}
	}
	return terms
}

// getSupportedBaseTokenAt returns the globally supported lending base tokens in contract.
func getSupportedBaseTokenAt(statedb *state.StateDB, contract common.Address) []common.Address {
	baseTokens := []common.Address{}
	locSupportedBaseToken := state.GetLocSimpleVariable(SupportedBaseSlot)
	length := statedb.GetState(contract, locSupportedBaseToken).Big().Uint64()
	for i := uint64(0); i < length; i++ {
		loc := state.GetLocDynamicArrAtElement(locSupportedBaseToken, i, 1)
		addr := common.BytesToAddress(statedb.GetState(contract, loc).Bytes())
		if addr != (common.Address{}) {
			baseTokens = append(baseTokens, addr)
		}
	}
	return baseTokens
}

// getAllCollateralAt returns the default collateral token list stored in contract.
func getAllCollateralAt(statedb *state.StateDB, contract common.Address) []common.Address {
	collaterals := []common.Address{}

	//TODO: ILO Collateral is not supported in release 2.2.0
	//locILOCollateral := state.GetLocSimpleVariable(ILOCollateralSlot)
	//length := statedb.GetState(common.LendingRegistrationSMC, locILOCollateral).Big().Uint64()
	//for i := uint64(0); i < length; i++ {
	//	loc := state.GetLocDynamicArrAtElement(locILOCollateral, i, 1)
	//	addr := common.BytesToAddress(statedb.GetState(common.LendingRegistrationSMC, loc).Bytes())
	//	if addr != (common.Address{}) {
	//		collaterals = append(collaterals, addr)
	//	}
	//}

	locDefaultCollateralHash := state.GetLocSimpleVariable(DefaultCollateralSlot)
	length := statedb.GetState(contract, locDefaultCollateralHash).Big().Uint64()
	for i := uint64(0); i < length; i++ {
		loc := state.GetLocDynamicArrAtElement(locDefaultCollateralHash, i, 1)
		addr := common.BytesToAddress(statedb.GetState(contract, loc).Bytes())
		if addr != (common.Address{}) {
			collaterals = append(collaterals, addr)
		}
	}
	return collaterals
}

// @function GetAllLendingBooks
// @param statedb : current state
// @return: a map to specify whether lendingBook (combination of baseToken and term) is valid or not
func GetAllLendingBooks(statedb *state.StateDB) (mapLendingBook map[common.Hash]bool, err error) {
	contract, ok := lendingRegistrationSMC(statedb)
	if !ok {
		return nil, errors.New("GetAllLendingBooks: missing lending registration contract")
	}
	mapLendingBook = make(map[common.Hash]bool)
	baseTokens := getSupportedBaseTokenAt(statedb, contract)
	terms := getSupportedTermsAt(statedb, contract)
	if len(baseTokens) == 0 {
		return nil, errors.New("GetAllLendingBooks: empty baseToken list")
	}
	if len(terms) == 0 {
		return nil, errors.New("GetAllLendingPairs: empty term list")
	}
	for _, baseToken := range baseTokens {
		for _, term := range terms {
			if (baseToken != common.Address{}) && (term > 0) {
				mapLendingBook[GetLendingOrderBookHash(baseToken, term)] = true
			}
		}
	}
	return mapLendingBook, nil
}

// @function GetAllLendingPairs
// @param statedb : current state
// @return: list of lendingPair (combination of baseToken and collateralToken)
func GetAllLendingPairs(statedb *state.StateDB) (allPairs []LendingPair, err error) {
	contract, ok := lendingRegistrationSMC(statedb)
	if !ok {
		return allPairs, errors.New("GetAllLendingPairs: missing lending registration contract")
	}
	baseTokens := getSupportedBaseTokenAt(statedb, contract)
	collaterals := getAllCollateralAt(statedb, contract)
	if len(baseTokens) == 0 {
		return allPairs, errors.New("GetAllLendingPairs: empty baseToken list")
	}
	if len(collaterals) == 0 {
		return allPairs, errors.New("GetAllLendingPairs: empty collateral list")
	}
	for _, baseToken := range baseTokens {
		for _, collateral := range collaterals {
			if (baseToken != common.Address{}) && (collateral != common.Address{}) {
				allPairs = append(allPairs, LendingPair{
					LendingToken:    baseToken,
					CollateralToken: collateral,
				})
			}
		}
	}
	return allPairs, nil
}
