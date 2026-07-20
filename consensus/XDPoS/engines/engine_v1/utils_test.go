package engine_v1

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/utils"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// TestShouldDisableFullVerifyForMainnetChain tests should disable full verify for mainnet chain.
func TestShouldDisableFullVerifyForMainnetChain(t *testing.T) {
	engine := New(params.XDCMainnetChainConfig, nil)
	if engine.shouldDisableFullVerify() {
		t.Fatal("expected mainnet chain config to keep full verification enabled")
	}
}

// TestGetM1M2FromCheckpointHeader tests get m 1 m 2 from checkpoint header.
func TestGetM1M2FromCheckpointHeader(t *testing.T) {
	masternodes := []common.Address{
		common.StringToAddress("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		common.StringToAddress("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
		common.StringToAddress("cccccccccccccccccccccccccccccccccccccccc"),
	}
	validators := []int64{
		2,
		1,
		0,
	}
	epoch := uint64(900)
	config := &params.ChainConfig{
		TIPRandomizeBlock: big.NewInt(3464000),
		XDPoS: &params.XDPoSConfig{
			Epoch: epoch,
		},
	}
	testMoveM2 := []uint64{0, 0, 0, 1, 1, 1, 2, 2, 2, 0, 0, 0, 1, 1, 1, 2, 2, 2}
	//try from block 3410001 to 3410018
	for i := uint64(3464001); i <= 3464018; i++ {
		currentNumber := int64(i)
		currentHeader := &types.Header{
			Number: big.NewInt(currentNumber),
		}
		m1m2, moveM2, err := getM1M2(masternodes, validators, currentHeader, config)
		if err != nil {
			t.Error("can't get m1m2", "err", err)
		}
		fmt.Printf("block: %v, moveM2: %v\n", currentHeader.Number.Int64(), moveM2)
		for _, k := range masternodes {
			fmt.Printf("m1: %v - m2: %v\n", k.Str(), m1m2[k].Str())
		}
		if moveM2 != testMoveM2[i-3464001] {
			t.Error("wrong moveM2", "currentNumber", currentNumber, "want", testMoveM2[i-3464001], "have", moveM2)
		}
	}
}

// TestDecodeMasternodesFromHeaderExtraShortExtra checks that a header whose
// Extra is shorter than the vanity+seal prefix does not cause a makeslice panic.
func TestDecodeMasternodesFromHeaderExtraShortExtra(t *testing.T) {
	for _, size := range []int{0, utils.ExtraSeal, utils.ExtraVanity + utils.ExtraSeal - 1} {
		header := &types.Header{Extra: make([]byte, size)}
		if got := decodeMasternodesFromHeaderExtra(header); got != nil {
			t.Fatalf("Extra len %d: expected nil, got %d masternodes", size, len(got))
		}
	}
}

// TestDecodeMasternodesFromHeaderExtraValid checks masternodes are decoded from a
// well-formed Extra of vanity + N addresses + seal.
func TestDecodeMasternodesFromHeaderExtraValid(t *testing.T) {
	want := []common.Address{
		common.StringToAddress("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		common.StringToAddress("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
	}
	extra := make([]byte, utils.ExtraVanity)
	for _, mn := range want {
		extra = append(extra, mn.Bytes()...)
	}
	extra = append(extra, make([]byte, utils.ExtraSeal)...)

	got := decodeMasternodesFromHeaderExtra(&types.Header{Extra: extra})
	if len(got) != len(want) {
		t.Fatalf("expected %d masternodes, got %d", len(want), len(got))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("masternode %d: expected %s, got %s", i, want[i].Hex(), got[i].Hex())
		}
	}
}
