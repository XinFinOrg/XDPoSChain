package engine_v1

import (
	"errors"
	"math/big"
	"reflect"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// penaltyTestChain answers the one read removePenaltiesFromBlock makes; the embedded
// interface keeps every other consensus.ChainReader method out of the test, and holding no
// block body pins that the penalty set is read from the header alone.
type penaltyTestChain struct {
	consensus.ChainReader
	config *params.ChainConfig
	header *types.Header
}

func (c *penaltyTestChain) Config() *params.ChainConfig { return c.config }

func (c *penaltyTestChain) GetHeaderByNumber(uint64) *types.Header { return c.header }

func TestRemovePenaltiesFromBlockMissingHeader(t *testing.T) {
	signers := []common.Address{{1}, {2}}
	got, err := removePenaltiesFromBlock(&penaltyTestChain{}, signers, 900)
	if !errors.Is(err, consensus.ErrMissingPenaltyBlock) {
		t.Fatalf("err = %v, want %v", err, consensus.ErrMissingPenaltyBlock)
	}
	if !reflect.DeepEqual(got, signers) {
		t.Fatalf("signers = %v, want them unchanged on a missing header", got)
	}
}

// A node that holds the epoch header but not its body (fast sync's pre-pivot range, a
// header-only chain) can still read the penalty set: it is a header field.
func TestRemovePenaltiesFromBlockReadsPenaltiesWithoutBody(t *testing.T) {
	penalized := common.Address{1}
	header := &types.Header{Number: big.NewInt(900), Penalties: penalized[:]}
	got, err := removePenaltiesFromBlock(&penaltyTestChain{header: header}, []common.Address{{1}, {2}}, 900)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if want := []common.Address{{2}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("signers = %v, want %v", got, want)
	}
}

func TestRemovePenaltiesFromBlockNoPenalties(t *testing.T) {
	signers := []common.Address{{1}, {2}}
	header := &types.Header{Number: big.NewInt(900)}
	chain := &penaltyTestChain{header: header}
	got, err := removePenaltiesFromBlock(chain, signers, 900)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if !reflect.DeepEqual(got, signers) {
		t.Fatalf("signers = %v, want %v", got, signers)
	}
}

// The checkpoint below sits under mainnet's TIPSigningBlock, so the penalty hook taken is
// HookPenalty; the missing epoch block is what the call has to report.
func TestCheckSignersOnCheckpointReportsMissingPenaltyBlock(t *testing.T) {
	engine := &XDPoS_v1{
		chainConfig: params.XDCMainnetChainConfig,
		config:      params.XDCMainnetChainConfig.XDPoS,
		HookPenalty: func(consensus.ChainReader, uint64) ([]common.Address, error) { return nil, nil },
	}
	chain := &penaltyTestChain{config: params.XDCMainnetChainConfig}
	header := &types.Header{Number: big.NewInt(1800)}
	err := engine.checkSignersOnCheckpoint(chain, &types.Header{Number: big.NewInt(1799)}, header, []common.Address{{1}})
	if !errors.Is(err, consensus.ErrMissingPenaltyBlock) {
		t.Fatalf("err = %v, want %v", err, consensus.ErrMissingPenaltyBlock)
	}
}
