package engine_v1

import (
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/utils"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// checkpointTestChain answers the parent lookup of verifyCascadingFields and, for every other
// height, a synthetic header so that getSignersFromContract can walk its whole gap window. The
// embedded interface keeps the rest of consensus.ChainReader out of the test.
type checkpointTestChain struct {
	consensus.ChainReader
	config *params.ChainConfig
	parent *types.Header
}

func (c *checkpointTestChain) Config() *params.ChainConfig { return c.config }

func (c *checkpointTestChain) GetHeader(hash common.Hash, number uint64) *types.Header {
	if c.parent != nil && c.parent.Number.Uint64() == number && c.parent.Hash() == hash {
		return c.parent
	}
	return &types.Header{Number: new(big.Int).SetUint64(number)}
}

// GetHeaderByNumber answers every height as missing: the fixture holds no history, which is
// what the penalty reads judge the checkpoint against.
func (c *checkpointTestChain) GetHeaderByNumber(uint64) *types.Header { return nil }

// newCheckpointVerifyFixture builds a checkpoint header that passes the fields checked before
// the signer check, with the parent's snapshot cached so the snapshot walk needs no chain. The
// mock config signs at TIPSigning, so the hook under test is HookPenaltyTIPSigning.
func newCheckpointVerifyFixture(t *testing.T, hook func(consensus.ChainReader, *types.Header, []common.Address) ([]common.Address, error)) (*XDPoS_v1, *checkpointTestChain, *types.Header) {
	t.Helper()
	cfg := params.TestXDPoSMockChainConfig.Clone()
	cfg.XDPoS.SkipV1Validation = false

	engine := New(cfg, nil)
	engine.HookPenaltyTIPSigning = hook

	parent := &types.Header{
		Number:     big.NewInt(1799),
		Difficulty: big.NewInt(1),
		GasLimit:   1200000000,
		UncleHash:  utils.UncleHash,
		Extra:      make([]byte, utils.ExtraVanity+utils.ExtraSeal),
		BaseFee:    params.BaseFeeForBlock(cfg, big.NewInt(1799)),
	}
	header := &types.Header{
		Number:     big.NewInt(1800),
		ParentHash: parent.Hash(),
		Difficulty: big.NewInt(1),
		GasLimit:   1200000000,
		Time:       parent.Time,
		UncleHash:  utils.UncleHash,
		Extra:      make([]byte, utils.ExtraVanity+utils.ExtraSeal),
		BaseFee:    params.BaseFeeForBlock(cfg, big.NewInt(1800)),
	}
	signers := []common.Address{{1}, {2}, {3}}
	engine.recents.Add(parent.Hash(), newSnapshot(engine.config, engine.signatures, 1799, parent.Hash(), signers))

	return engine, &checkpointTestChain{config: cfg, parent: parent}, header
}

// A missing penalty block is this node's own record: the checkpoint check must return it
// without asking the contract for another signer list, because the retry after that fallback
// runs the same check and hits the same missing block.
func TestCheckpointVerifyStopsOnMissingPenaltyBlock(t *testing.T) {
	fallbackCalls := 0
	engine, chain, header := newCheckpointVerifyFixture(t, func(consensus.ChainReader, *types.Header, []common.Address) ([]common.Address, error) {
		return nil, fmt.Errorf("%w: header 900", consensus.ErrMissingPenaltyBlock)
	})
	engine.HookGetSignersFromContract = func(*types.Header) ([]common.Address, error) {
		fallbackCalls++
		return nil, nil
	}
	err := engine.verifyCascadingFields(chain, header, nil, true)
	if !errors.Is(err, consensus.ErrMissingPenaltyBlock) {
		t.Fatalf("err = %v, want %v", err, consensus.ErrMissingPenaltyBlock)
	}
	if fallbackCalls != 0 {
		t.Fatalf("the contract fallback ran %d times on a missing penalty block, want 0", fallbackCalls)
	}
}

// Any other signer failure still takes the contract fallback: the early return is only for the
// missing block, not for every checkSignersOnCheckpoint error.
func TestCheckpointVerifyFallsBackToContractOnOtherSignerErrors(t *testing.T) {
	fallbackCalls := 0
	engine, chain, header := newCheckpointVerifyFixture(t, func(consensus.ChainReader, *types.Header, []common.Address) ([]common.Address, error) {
		return nil, utils.ErrInvalidCheckpointPenalties
	})
	engine.HookGetSignersFromContract = func(*types.Header) ([]common.Address, error) {
		fallbackCalls++
		return nil, nil
	}
	err := engine.verifyCascadingFields(chain, header, nil, true)
	if err == nil {
		t.Fatal("expected the signer mismatch to be reported")
	}
	if errors.Is(err, consensus.ErrMissingPenaltyBlock) {
		t.Fatalf("a signer mismatch must keep the contract fallback: %v", err)
	}
	if !errors.Is(err, utils.ErrInvalidCheckpointPenalties) {
		t.Fatalf("err = %v, want %v", err, utils.ErrInvalidCheckpointPenalties)
	}
	if fallbackCalls != 1 {
		t.Fatalf("the contract fallback ran %d times, want 1", fallbackCalls)
	}
}

// The miner's Prepare runs the same penalty read at a checkpoint: a node missing a past epoch
// checkpoint must surface it instead of building a header from an unpenalized set.
func TestPrepareReportsMissingPenaltyBlock(t *testing.T) {
	engine, chain, header := newCheckpointVerifyFixture(t, func(consensus.ChainReader, *types.Header, []common.Address) ([]common.Address, error) {
		return nil, nil
	})
	err := engine.Prepare(chain, header)
	if !errors.Is(err, consensus.ErrMissingPenaltyBlock) {
		t.Fatalf("err = %v, want %v", err, consensus.ErrMissingPenaltyBlock)
	}
}
