package hooks

import (
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/utils"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// newHooksTestChain builds a chain that holds only its genesis block: every historical block
// the v1 penalty hooks read is missing.
func newHooksTestChain(t *testing.T) (*XDPoS.XDPoS, *core.BlockChain, ethdb.Database) {
	t.Helper()
	return newHooksTestChainWithConfig(t, params.TestXDPoSMockChainConfig.Clone())
}

// newHooksTestChainWithConfig is newHooksTestChain with the config spelled out. The mainnet
// config keeps the heights these tests write on the v1 engine (its v2 switch is far above
// them), so the adaptor calls inside the hooks resolve the way they do on a v1 chain.
func newHooksTestChainWithConfig(t *testing.T, cfg *params.ChainConfig) (*XDPoS.XDPoS, *core.BlockChain, ethdb.Database) {
	t.Helper()
	return newHooksTestChainWithAlloc(t, cfg, nil)
}

// newHooksTestChainWithAlloc is newHooksTestChainWithConfig with genesis accounts installed.
// That is how a test gives the block signer contract a record for the hooks to read.
func newHooksTestChainWithAlloc(t *testing.T, cfg *params.ChainConfig, alloc types.GenesisAlloc) (*XDPoS.XDPoS, *core.BlockChain, ethdb.Database) {
	t.Helper()
	db := rawdb.NewMemoryDatabase()
	engine, err := XDPoS.New(cfg, db)
	if err != nil {
		t.Fatalf("failed to create the consensus engine: %v", err)
	}
	genesis := &core.Genesis{Config: cfg, ExtraData: make([]byte, 32+crypto.SignatureLength), Alloc: alloc}
	genesis.MustCommit(db)
	chain, err := core.NewBlockChain(db, nil, genesis, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create the chain: %v", err)
	}
	t.Cleanup(chain.Stop)
	AttachConsensusV1Hooks(engine, chain, cfg)
	return engine, chain, db
}

// v1CheckpointExtra lays a single masternode into a checkpoint header's extra data.
func v1CheckpointExtra(addr common.Address) []byte {
	extra := make([]byte, 0, utils.ExtraVanity+common.AddressLength+utils.ExtraSeal)
	extra = append(extra, make([]byte, utils.ExtraVanity)...)
	extra = append(extra, addr[:]...)
	extra = append(extra, make([]byte, utils.ExtraSeal)...)
	return extra
}

// v1HeaderExtra is the extra data a header needs to parse as a v1 header without masternodes.
func v1HeaderExtra() []byte {
	return make([]byte, utils.ExtraVanity+utils.ExtraSeal)
}

// writeCanonicalHeader stores the header as the canonical one at its number, which is how the
// hooks resolve a height they only know by number.
func writeCanonicalHeader(t *testing.T, db ethdb.Database, header *types.Header) {
	t.Helper()
	rawdb.WriteHeader(db, header)
	rawdb.WriteCanonicalHash(db, header.Hash(), header.Number.Uint64())
}

// writeHeaderChain stores headers first..last as a parent-linked chain and returns the hash of
// the last one, so a header above the range can point at it.
func writeHeaderChain(t *testing.T, db ethdb.Database, first, last uint64) common.Hash {
	t.Helper()
	prev := common.Hash{}
	for n := first; n <= last; n++ {
		header := &types.Header{
			Number:     new(big.Int).SetUint64(n),
			ParentHash: prev,
			Extra:      v1HeaderExtra(),
		}
		writeCanonicalHeader(t, db, header)
		prev = header.Hash()
	}
	return prev
}

// A node that does not hold the previous epoch header must report it, not dereference it.
func TestHookPenaltyReportsMissingPreviousEpochHeader(t *testing.T) {
	engine, chain, _ := newHooksTestChain(t)
	penalties, err := engine.EngineV1.HookPenalty(chain, 1800)
	if !errors.Is(err, consensus.ErrMissingPenaltyBlock) {
		t.Fatalf("err = %v, want %v", err, consensus.ErrMissingPenaltyBlock)
	}
	if penalties != nil {
		t.Fatalf("penalties = %v, want nil", penalties)
	}
}

// The TIPSigning variant walks the epoch's headers first; a node missing them must report the
// missing block instead of recovering a signer from a nil header.
func TestHookPenaltyTIPSigningReportsMissingParentHeader(t *testing.T) {
	engine, chain, _ := newHooksTestChain(t)
	penalties, err := engine.EngineV1.HookPenaltyTIPSigning(chain, &types.Header{Number: big.NewInt(1800)}, nil)
	if !errors.Is(err, consensus.ErrMissingPenaltyBlock) {
		t.Fatalf("err = %v, want %v", err, consensus.ErrMissingPenaltyBlock)
	}
	if penalties != nil {
		t.Fatalf("penalties = %v, want nil", penalties)
	}
}

// A node that holds the previous epoch header but not a block body inside that epoch must
// report the missing body: the signing scan needs the body, and a missing one cannot be read
// as "nobody signed".
func TestHookPenaltyReportsMissingBody(t *testing.T) {
	engine, chain, db := newHooksTestChainWithConfig(t, params.XDCMainnetChainConfig.Clone())
	writeCanonicalHeader(t, db, &types.Header{Number: big.NewInt(900), Extra: v1CheckpointExtra(common.Address{1})})

	penalties, err := engine.EngineV1.HookPenalty(chain, 1800)
	if !errors.Is(err, consensus.ErrMissingPenaltyBlock) {
		t.Fatalf("err = %v, want %v", err, consensus.ErrMissingPenaltyBlock)
	}
	if !strings.Contains(err.Error(), "block 900") {
		t.Fatalf("err = %v, want it to name the missing body at 900", err)
	}
	if penalties != nil {
		t.Fatalf("penalties = %v, want nil", penalties)
	}
}

// A header missing inside the previous epoch is reported as the header, not as the block its
// then-unresolvable hash would name. Mainnet has TIP2019 on, so the scan checks only every
// MergeSignRange-th height and 915 is the first one after the header at 900.
func TestHookPenaltyReportsMissingHeader(t *testing.T) {
	engine, chain, db := newHooksTestChainWithConfig(t, params.XDCMainnetChainConfig.Clone())
	header := &types.Header{Number: big.NewInt(900), Extra: v1CheckpointExtra(common.Address{1})}
	writeCanonicalHeader(t, db, header)
	rawdb.WriteBody(db, header.Hash(), 900, &types.Body{})

	penalties, err := engine.EngineV1.HookPenalty(chain, 1800)
	if !errors.Is(err, consensus.ErrMissingPenaltyBlock) {
		t.Fatalf("err = %v, want %v", err, consensus.ErrMissingPenaltyBlock)
	}
	if !strings.Contains(err.Error(), "header 915") {
		t.Fatalf("err = %v, want it to name the missing header at 915", err)
	}
	if penalties != nil {
		t.Fatalf("penalties = %v, want nil", penalties)
	}
}

// The TIPSigning variant reads the previous epoch header after walking the epoch; a node that
// holds the walk but not that header must report it.
func TestHookPenaltyTIPSigningReportsMissingPreviousEpochHeader(t *testing.T) {
	engine, chain, db := newHooksTestChainWithConfig(t, params.XDCMainnetChainConfig.Clone())
	parent := writeHeaderChain(t, db, 901, 1799)

	penalties, err := engine.EngineV1.HookPenaltyTIPSigning(chain, &types.Header{Number: big.NewInt(1800), ParentHash: parent}, nil)
	if !errors.Is(err, consensus.ErrMissingPenaltyBlock) {
		t.Fatalf("err = %v, want %v", err, consensus.ErrMissingPenaltyBlock)
	}
	if !strings.Contains(err.Error(), "previous epoch header 900") {
		t.Fatalf("err = %v, want it to name the previous epoch header at 900", err)
	}
	if penalties != nil {
		t.Fatalf("penalties = %v, want nil", penalties)
	}
}

// Past LimitPenaltyEpoch epochs the TIPSigning variant also reads the comeback epoch header; a
// node that does not hold it must report it.
func TestHookPenaltyTIPSigningReportsMissingComebackHeader(t *testing.T) {
	engine, chain, db := newHooksTestChainWithConfig(t, params.XDCMainnetChainConfig.Clone())
	parent := writeHeaderChain(t, db, 4501, 5399)
	writeCanonicalHeader(t, db, &types.Header{Number: big.NewInt(4500), Extra: v1HeaderExtra()})

	// 5400 is beyond (LimitPenaltyEpoch+1)*Epoch = 4500, so the comeback epoch is 900.
	penalties, err := engine.EngineV1.HookPenaltyTIPSigning(chain, &types.Header{Number: big.NewInt(5400), ParentHash: parent}, nil)
	if !errors.Is(err, consensus.ErrMissingPenaltyBlock) {
		t.Fatalf("err = %v, want %v", err, consensus.ErrMissingPenaltyBlock)
	}
	if !strings.Contains(err.Error(), "comeback epoch header 900") {
		t.Fatalf("err = %v, want it to name the comeback epoch header at 900", err)
	}
	if penalties != nil {
		t.Fatalf("penalties = %v, want nil", penalties)
	}
}

// A node that holds the comeback epoch header but none of the bodies the comeback scan reads
// must report the missing block; 5250 is the first height it needs a body for.
func TestHookPenaltyTIPSigningReportsMissingBlock(t *testing.T) {
	engine, chain, db := newHooksTestChainWithConfig(t, params.XDCMainnetChainConfig.Clone())
	parent := writeHeaderChain(t, db, 4501, 5399)
	writeCanonicalHeader(t, db, &types.Header{Number: big.NewInt(4500), Extra: v1HeaderExtra()})
	penalized := common.Address{2}
	writeCanonicalHeader(t, db, &types.Header{Number: big.NewInt(900), Penalties: penalized[:], Extra: v1HeaderExtra()})

	penalties, err := engine.EngineV1.HookPenaltyTIPSigning(chain, &types.Header{Number: big.NewInt(5400), ParentHash: parent}, []common.Address{penalized})
	if !errors.Is(err, consensus.ErrMissingPenaltyBlock) {
		t.Fatalf("err = %v, want %v", err, consensus.ErrMissingPenaltyBlock)
	}
	if !strings.Contains(err.Error(), "block 5250") {
		t.Fatalf("err = %v, want it to name the missing block at 5250", err)
	}
	if penalties != nil {
		t.Fatalf("penalties = %v, want nil", penalties)
	}
}

// blockSignerSlots lays a block signer contract record into genesis storage: the signers the
// contract holds for hash, at the slots StateDB.GetSigners reads them from.
func blockSignerSlots(hash common.Hash, signers []common.Address) map[common.Hash]common.Hash {
	// mapping(bytes32 => address[]) at slot 0 of the block signer contract.
	base := crypto.Keccak256Hash(hash.Bytes(), common.BigToHash(new(big.Int)).Bytes())
	storage := map[common.Hash]common.Hash{
		base: common.BigToHash(new(big.Int).SetUint64(uint64(len(signers)))),
	}
	elem := crypto.Keccak256Hash(base.Bytes()).Big()
	for i, signer := range signers {
		storage[common.BigToHash(new(big.Int).Add(elem, big.NewInt(int64(i))))] = signer.Hash()
	}
	return storage
}

// A node that has seen every masternode sign holds the final penalty set already: a record
// missing later in the epoch must not become ErrMissingPenaltyBlock, because the set cannot
// depend on it. 915 is the next height the scan reads after 900.
func TestHookPenaltyStopsWhenEverySignerHasSigned(t *testing.T) {
	miner := common.Address{1}
	header := &types.Header{Number: big.NewInt(900), Extra: v1CheckpointExtra(miner)}

	for _, tt := range []struct {
		name      string
		writeNext bool
	}{
		{name: "missing header"},
		{name: "missing body", writeNext: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			alloc := types.GenesisAlloc{
				common.BlockSignersBinary: {Balance: big.NewInt(1), Storage: blockSignerSlots(header.Hash(), []common.Address{miner})},
			}
			engine, chain, db := newHooksTestChainWithAlloc(t, params.XDCMainnetChainConfig.Clone(), alloc)
			if mns := engine.GetMasternodes(chain, header); len(mns) != 1 || mns[0] != miner {
				t.Fatalf("masternodes = %v, want [%v]", mns, miner)
			}
			writeCanonicalHeader(t, db, header)
			rawdb.WriteBody(db, header.Hash(), 900, &types.Body{})
			if tt.writeNext {
				writeCanonicalHeader(t, db, &types.Header{Number: big.NewInt(915), ParentHash: header.Hash(), Extra: v1HeaderExtra()})
			}

			penalties, err := engine.EngineV1.HookPenalty(chain, 1800)
			if err != nil {
				t.Fatalf("err = %v, want nil: the set was final once %v had signed", err, miner)
			}
			if len(penalties) != 0 {
				t.Fatalf("penalties = %v, want none", penalties)
			}
		})
	}
}
