package tradingstate

import (
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	corestate "github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// TestSubRelayerFeeReturnsErrorWithoutChainConfigBeforeZeroAddressMutation tests sub relayer fee returns an error without mutating the zero address when chain config is missing.
func TestSubRelayerFeeReturnsErrorWithoutChainConfigBeforeZeroAddressMutation(t *testing.T) {
	state, _ := corestate.New(types.EmptyRootHash, corestate.NewDatabase(rawdb.NewMemoryDatabase()))
	relayer := common.HexToAddress("0x00000000000000000000000000000000000000aa")

	err := SubRelayerFee(relayer, big.NewInt(1), state)
	if err == nil {
		t.Fatal("expected error when chain config is missing")
	}
	if state.Exist(common.Address{}) {
		t.Fatal("expected zero address to remain unmodified")
	}
}

// TestGetExRelayerFeeReturnsZeroWithZeroRelayerRegistrationConfig tests get ex relayer fee returns zero when relayer registration config is missing.
func TestGetExRelayerFeeReturnsZeroWithZeroRelayerRegistrationConfig(t *testing.T) {
	state, _ := corestate.New(types.EmptyRootHash, corestate.NewDatabase(rawdb.NewMemoryDatabase()))
	if err := state.EnsureChainConfig(&params.ChainConfig{}); err != nil {
		t.Fatalf("failed to attach chain config: %v", err)
	}
	relayer := common.HexToAddress("0x00000000000000000000000000000000000000aa")

	fee := GetExRelayerFee(relayer, state)
	if fee.Sign() != 0 {
		t.Fatalf("expected zero fee, got %v", fee)
	}
}

// TestCheckSubRelayerFeeReturnsErrorWithoutChainConfigEvenWithCachedBalance tests cached relayer balances do not bypass missing config guards.
func TestCheckSubRelayerFeeReturnsErrorWithoutChainConfigEvenWithCachedBalance(t *testing.T) {
	state, _ := corestate.New(types.EmptyRootHash, corestate.NewDatabase(rawdb.NewMemoryDatabase()))
	relayer := common.HexToAddress("0x00000000000000000000000000000000000000aa")
	mapBalances := map[common.Address]*big.Int{
		relayer: big.NewInt(10),
	}

	_, err := CheckSubRelayerFee(relayer, big.NewInt(1), state, mapBalances)
	if err == nil {
		t.Fatal("expected error when chain config is missing")
	}
	if state.Exist(common.Address{}) {
		t.Fatal("expected zero address to remain unmodified")
	}
}

// TestSetSubRelayerFeeReturnsErrorWithoutChainConfigBeforeZeroAddressMutation tests set sub relayer fee returns an error before mutating zero address state.
func TestSetSubRelayerFeeReturnsErrorWithoutChainConfigBeforeZeroAddressMutation(t *testing.T) {
	state, _ := corestate.New(types.EmptyRootHash, corestate.NewDatabase(rawdb.NewMemoryDatabase()))
	relayer := common.HexToAddress("0x00000000000000000000000000000000000000aa")

	err := SetSubRelayerFee(relayer, big.NewInt(9), big.NewInt(1), state)
	if err == nil {
		t.Fatal("expected error when chain config is missing")
	}
	if state.Exist(common.Address{}) {
		t.Fatal("expected zero address to remain unmodified")
	}
}
