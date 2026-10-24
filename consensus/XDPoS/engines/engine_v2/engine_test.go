package engine_v2

import (
	"math/big"
	"os"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/common/lru"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/utils"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/stretchr/testify/assert"
)

func TestNewRequiresStartupValidatedV2Config(t *testing.T) {
	chainConfig := params.TestnetChainConfig.Clone()
	chainConfig.XDPoS = chainConfig.XDPoS.Clone()
	chainConfig.XDPoS.V2 = nil

	engine, err := New(chainConfig, rawdb.NewMemoryDatabase(), make(chan int), make(chan types.Round, 1))
	assert.Nil(t, engine)
	assert.EqualError(t, err, "engine_v2.New requires startup-validated XDPoS V2 config")
}

// After a head rewind the stored highestQuorumCert can still name a block the
// chain reader no longer holds. The lookup must then return nil, leaving the
// caller (XDPoS.FindParentBlockToAssign) to fall back to the current head, and
// must not panic or fabricate a parent.
func TestFindParentBlockToAssignStaleQC(t *testing.T) {
	x, chain, _ := newRepairFixture(t, 1350, []common.Address{{0x1}}, []*big.Int{big.NewInt(10)})
	x.highestQuorumCert = &types.QuorumCert{
		ProposedBlockInfo: &types.BlockInfo{
			Hash:   common.Hash{0x1},
			Round:  types.Round(1),
			Number: big.NewInt(1349),
		},
		Signatures: []types.Signature{},
	}

	assert.Nil(t, x.FindParentBlockToAssign(chain))
}

// finalizeTestChain answers the chain lookups Finalize makes, without a real
// chain behind it.
type finalizeTestChain struct {
	config *params.ChainConfig
	parent *types.Header
}

func (c *finalizeTestChain) Config() *params.ChainConfig                 { return c.config }
func (c *finalizeTestChain) CurrentHeader() *types.Header                { return c.parent }
func (c *finalizeTestChain) GetHeader(common.Hash, uint64) *types.Header { return c.parent }
func (c *finalizeTestChain) GetHeaderByNumber(uint64) *types.Header      { return c.parent }
func (c *finalizeTestChain) GetHeaderByHash(common.Hash) *types.Header   { return c.parent }
func (c *finalizeTestChain) GetBlock(common.Hash, uint64) *types.Block   { return nil }

// A miner that already sealed a block at this or a later round must still be
// able to finalize imported epoch-switch blocks: yourturn reports ErrAlreadyMined
// from local bookkeeping, and Finalize skips the reward-file step instead of
// failing the import.
func TestFinalizeToleratesAlreadyMinedRound(t *testing.T) {
	switchBlock := uint64(30000)
	db := rawdb.NewMemoryDatabase()
	x := &XDPoS_v2{
		config: &params.XDPoSConfig{
			Epoch: 900,
			Gap:   450,
			V2: &params.V2{
				SwitchBlock: new(big.Int).SetUint64(switchBlock),
			},
		},
		db:        db,
		snapshots: lru.NewCache[common.Hash, *SnapshotV2](utils.InMemorySnapshots),
	}
	x.HookReward = func(chain consensus.ChainReader, state vm.StateDB, parentState *state.StateDB, header *types.Header) (map[string]interface{}, error) {
		return map[string]interface{}{}, nil
	}

	// Numbering the block as V2.SwitchBlock makes IsEpochSwitch answer true
	// without decoding a quorum certificate; the empty extra field then leaves
	// the round at zero, which yourturn reports as already mined.
	parent := &types.Header{Number: new(big.Int).SetUint64(switchBlock - 1), GasLimit: 8_000_000}
	header := &types.Header{Number: new(big.Int).SetUint64(switchBlock), ParentHash: parent.Hash(), GasLimit: 8_000_000}
	chain := &finalizeTestChain{config: params.TestChainConfig, parent: parent}

	oldRewardFolder := common.StoreRewardFolder
	common.StoreRewardFolder = t.TempDir()
	defer func() { common.StoreRewardFolder = oldRewardFolder }()

	statedb, err := state.New(types.EmptyRootHash, state.NewDatabase(db))
	if err != nil {
		t.Fatalf("state: %v", err)
	}
	if _, err := x.Finalize(chain, header, statedb, statedb, nil, nil, nil); err != nil {
		t.Fatalf("Finalize rejected an already-mined round: %v", err)
	}
	if entries, err := os.ReadDir(common.StoreRewardFolder); err != nil {
		t.Fatalf("read reward folder: %v", err)
	} else if len(entries) != 0 {
		t.Fatalf("Finalize wrote %d reward file(s) for an already-mined round", len(entries))
	}
}

// A yourturn failure that is not ErrAlreadyMined is still this node's bookkeeping:
// the import path must not fail the block for it.
func TestFinalizeToleratesYourturnBookkeepingError(t *testing.T) {
	switchBlock := uint64(30000)
	db := rawdb.NewMemoryDatabase()
	x := &XDPoS_v2{
		config: &params.XDPoSConfig{
			Epoch: 900,
			Gap:   450,
			V2: &params.V2{
				SwitchBlock: new(big.Int).SetUint64(switchBlock),
			},
		},
		db:                   db,
		snapshots:            lru.NewCache[common.Hash, *SnapshotV2](utils.InMemorySnapshots),
		round2epochBlockInfo: lru.NewCache[types.Round, *types.BlockInfo](utils.InMemoryRound2Epochs),
	}
	x.HookReward = func(chain consensus.ChainReader, state vm.StateDB, parentState *state.StateDB, header *types.Header) (map[string]interface{}, error) {
		return map[string]interface{}{}, nil
	}

	// The header carries a decodable epoch-switch certificate, so IsEpochSwitch
	// answers true; the parent is not the switch block and has no decodable extra,
	// so yourturn fails inside isEpochSwitchAtRound instead of ErrAlreadyMined.
	extra, err := (&types.ExtraFields_v2{
		Round: 900,
		QuorumCert: &types.QuorumCert{ProposedBlockInfo: &types.BlockInfo{
			Number: new(big.Int).SetUint64(switchBlock + 9),
		}},
	}).EncodeToBytes()
	if err != nil {
		t.Fatalf("encode extra: %v", err)
	}
	parent := &types.Header{Number: new(big.Int).SetUint64(switchBlock + 9), GasLimit: 8_000_000}
	header := &types.Header{
		Number:     new(big.Int).SetUint64(switchBlock + 10),
		ParentHash: parent.Hash(),
		GasLimit:   8_000_000,
		Extra:      extra,
	}
	chain := &finalizeTestChain{config: params.TestChainConfig, parent: parent}

	statedb, err := state.New(types.EmptyRootHash, state.NewDatabase(db))
	if err != nil {
		t.Fatalf("state: %v", err)
	}
	if _, err := x.Finalize(chain, header, statedb, statedb, nil, nil, nil); err != nil {
		t.Fatalf("Finalize failed on a yourturn bookkeeping error: %v", err)
	}
}
