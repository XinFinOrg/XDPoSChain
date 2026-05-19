package lendingstate

import (
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
)

func TestSubRelayerFeeReturnsErrorWithoutChainConfigBeforeZeroAddressMutation(t *testing.T) {
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabase(rawdb.NewMemoryDatabase()))
	relayer := common.HexToAddress("0x00000000000000000000000000000000000000aa")

	err := SubRelayerFee(relayer, big.NewInt(1), statedb)
	if err == nil {
		t.Fatal("expected error when chain config is missing")
	}
	if statedb.Exist(common.Address{}) {
		t.Fatal("expected zero address to remain unmodified")
	}
}

func TestCheckSubRelayerFeeReturnsErrorWithoutChainConfigEvenWithCachedBalance(t *testing.T) {
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabase(rawdb.NewMemoryDatabase()))
	relayer := common.HexToAddress("0x00000000000000000000000000000000000000aa")
	mapBalances := map[common.Address]*big.Int{
		relayer: big.NewInt(10),
	}

	_, err := CheckSubRelayerFee(relayer, big.NewInt(1), statedb, mapBalances)
	if err == nil {
		t.Fatal("expected error when chain config is missing")
	}
	if statedb.Exist(common.Address{}) {
		t.Fatal("expected zero address to remain unmodified")
	}
}

func TestSetSubRelayerFeeReturnsErrorWithoutChainConfigBeforeZeroAddressMutation(t *testing.T) {
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabase(rawdb.NewMemoryDatabase()))
	relayer := common.HexToAddress("0x00000000000000000000000000000000000000aa")

	err := SetSubRelayerFee(relayer, big.NewInt(9), big.NewInt(1), statedb)
	if err == nil {
		t.Fatal("expected error when chain config is missing")
	}
	if statedb.Exist(common.Address{}) {
		t.Fatal("expected zero address to remain unmodified")
	}
}

func TestGetExRelayerFeeReturnsZeroWithZeroRelayerRegistrationConfig(t *testing.T) {
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabase(rawdb.NewMemoryDatabase()))
	if err := statedb.EnsureChainConfig(&params.ChainConfig{}); err != nil {
		t.Fatalf("failed to attach chain config: %v", err)
	}
	relayer := common.HexToAddress("0x00000000000000000000000000000000000000aa")

	fee := GetExRelayerFee(relayer, statedb)
	if fee.Sign() != 0 {
		t.Fatalf("expected zero fee, got %v", fee)
	}
}
