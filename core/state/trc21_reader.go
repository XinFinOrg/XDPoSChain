package state

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/common/lru"
	"github.com/XinFinOrg/XDPoSChain/core/tracing"
)

type trc21FeeCapacityCacheKey struct {
	trieRoot common.Hash
	issuer   common.Address
}

var (
	SlotTRC21Issuer = map[string]uint64{
		"minCap":      0,
		"tokens":      1,
		"tokensState": 2,
	}
	SlotTRC21Token = map[string]uint64{
		"balances": 0,
		"minFee":   1,
		"issuer":   2,
	}
	transferFuncHex     = common.Hex2Bytes("0xa9059cbb")
	transferFromFuncHex = common.Hex2Bytes("0x23b872dd")
	cache               = lru.NewCache[trc21FeeCapacityCacheKey, map[common.Address]*big.Int](128)
)

// TRC21IssuerSMC returns the configured TRC21 issuer contract address when it
// is available on the attached chain config.
func (s *StateDB) TRC21IssuerSMC() (common.Address, error) {
	if s == nil {
		return common.Address{}, fmt.Errorf("state: missing StateDB for TRC21 state access")
	}
	if s.chainConfig == nil {
		return common.Address{}, fmt.Errorf("state: missing chain config for TRC21 state access")
	}
	if s.chainConfig.TRC21IssuerSMC.IsZero() {
		return common.Address{}, fmt.Errorf("state: missing TRC21 issuer address in chain config")
	}
	return s.chainConfig.TRC21IssuerSMC, nil
}

func (s *StateDB) GetTRC21FeeCapacityFromStateWithCache(trieRoot common.Hash) map[common.Address]*big.Int {
	if s == nil {
		return map[common.Address]*big.Int{}
	}
	issuer, err := s.TRC21IssuerSMC()
	if err != nil {
		return map[common.Address]*big.Int{}
	}

	cacheKey := trc21FeeCapacityCacheKey{trieRoot: trieRoot, issuer: issuer}
	info, ok := cache.Get(cacheKey)
	if !ok || info == nil {
		info = s.GetTRC21FeeCapacityFromState()
		cache.Add(cacheKey, info)
	}
	tokensFee := map[common.Address]*big.Int{}
	for key, value := range info {
		tokensFee[key] = big.NewInt(0).SetBytes(value.Bytes())
	}

	return tokensFee
}

func (s *StateDB) GetTRC21FeeCapacityFromState() map[common.Address]*big.Int {
	if s == nil {
		return map[common.Address]*big.Int{}
	}

	tokensCapacity := map[common.Address]*big.Int{}
	issuer, err := s.TRC21IssuerSMC()
	if err != nil {
		return tokensCapacity
	}
	slotTokens := SlotTRC21Issuer["tokens"]
	slotTokensHash := common.BigToHash(new(big.Int).SetUint64(slotTokens))
	slotTokensState := SlotTRC21Issuer["tokensState"]
	tokenCount := s.GetState(issuer, slotTokensHash).Big().Uint64()
	for i := range tokenCount {
		key := GetLocDynamicArrAtElement(slotTokensHash, i, 1)
		value := s.GetState(issuer, key)
		if !value.IsZero() {
			token := common.BytesToAddress(value.Bytes())
			balanceKey := GetLocMappingAtKey(token.Hash(), slotTokensState)
			balanceHash := s.GetState(issuer, common.BigToHash(balanceKey))
			tokensCapacity[common.BytesToAddress(token.Bytes())] = balanceHash.Big()
		}
	}

	return tokensCapacity
}

func (s *StateDB) PayFeeWithTRC21TxFail(from common.Address, token common.Address) {
	if s == nil {
		return
	}
	if _, err := s.TRC21IssuerSMC(); err != nil {
		return
	}

	slotBalanceTrc21 := SlotTRC21Token["balances"]
	balanceKey := GetLocMappingAtKey(from.Hash(), slotBalanceTrc21)
	balanceHash := s.GetState(token, common.BigToHash(balanceKey))
	if !balanceHash.IsZero() {
		balance := balanceHash.Big()
		feeUsed := big.NewInt(0)
		if balance.Cmp(feeUsed) <= 0 {
			return
		}
		issuerTokenKey := GetLocSimpleVariable(SlotTRC21Token["issuer"])
		if issuerTokenKey.IsZero() {
			return
		}
		issuerAddr := common.BytesToAddress(s.GetState(token, issuerTokenKey).Bytes())
		feeTokenKey := GetLocSimpleVariable(SlotTRC21Token["minFee"])
		feeHash := s.GetState(token, feeTokenKey)
		fee := feeHash.Big()
		if balance.Cmp(fee) < 0 {
			feeUsed = balance
		} else {
			feeUsed = fee
		}
		balance = balance.Sub(balance, feeUsed)
		s.SetState(token, common.BigToHash(balanceKey), common.BigToHash(balance))

		issuerBalanceKey := GetLocMappingAtKey(issuerAddr.Hash(), slotBalanceTrc21)
		issuerBalanceHash := s.GetState(token, common.BigToHash(issuerBalanceKey))
		issuerBalance := issuerBalanceHash.Big()
		issuerBalance = issuerBalance.Add(issuerBalance, feeUsed)
		s.SetState(token, common.BigToHash(issuerBalanceKey), common.BigToHash(issuerBalance))
	}
}

func (s *StateDB) ValidateTRC21Tx(from common.Address, token common.Address, data []byte) bool {
	if s == nil || data == nil {
		return false
	}

	slotBalanceTrc21 := SlotTRC21Token["balances"]
	balanceKey := GetLocMappingAtKey(from.Hash(), slotBalanceTrc21)
	balanceHash := s.GetState(token, common.BigToHash(balanceKey))

	if !balanceHash.IsZero() {
		balance := balanceHash.Big()
		minFeeTokenKey := GetLocSimpleVariable(SlotTRC21Token["minFee"])
		minFeeHash := s.GetState(token, minFeeTokenKey)
		requiredMinBalance := minFeeHash.Big()
		funcHex := data[:4]
		value := big.NewInt(0)
		if bytes.Equal(funcHex, transferFuncHex) && len(data) == 68 {
			value = common.BytesToHash(data[36:]).Big()
		} else {
			if bytes.Equal(funcHex, transferFromFuncHex) && len(data) == 80 {
				value = common.BytesToHash(data[68:]).Big()
			}
		}
		requiredMinBalance = requiredMinBalance.Add(requiredMinBalance, value)
		if balance.Cmp(requiredMinBalance) < 0 {
			return false
		} else {
			return true
		}
	} else {
		// we both accept tx with balance = 0 and fee = 0
		minFeeTokenKey := GetLocSimpleVariable(SlotTRC21Token["minFee"])
		if !minFeeTokenKey.IsZero() {
			return true
		}
	}

	return false
}

func (s *StateDB) UpdateTRC21Fee(newBalance map[common.Address]*big.Int, totalFeeUsed *big.Int) {
	if s == nil || len(newBalance) == 0 {
		return
	}

	slotTokensState := SlotTRC21Issuer["tokensState"]
	issuer, err := s.TRC21IssuerSMC()
	if err != nil {
		return
	}
	for token, value := range newBalance {
		balanceKey := GetLocMappingAtKey(token.Hash(), slotTokensState)
		s.SetState(issuer, common.BigToHash(balanceKey), common.BigToHash(value))
	}
	s.SubBalance(issuer, totalFeeUsed, tracing.BalanceChangeUnspecified)
}
