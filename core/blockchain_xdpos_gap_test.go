// Copyright 2025 The XDPoSChain Authors
// This file is part of the XDPoSChain library.
//
// The XDPoSChain library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The XDPoSChain library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the XDPoSChain library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"bytes"
	"errors"
	"math/big"
	"strings"
	"sync"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/utils"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// Slot layout of the masternode voting smart contract, mirrored from
// core/state/statedb_utils.go.
const (
	votingSCCandidatesSlot      = 8
	votingSCValidatorsStateSlot = 1
)

// keyCapture records the key a rawdb writer emits, so tests can learn raw
// database keys without duplicating the private schema of core/rawdb.
type keyCapture struct {
	key []byte
}

func (c *keyCapture) Put(key []byte, value []byte) error {
	c.key = common.CopyBytes(key)
	return nil
}

func (c *keyCapture) Delete(key []byte) error { return nil }

func dbKey(write func(db ethdb.KeyValueWriter)) []byte {
	capture := new(keyCapture)
	write(capture)
	return capture.key
}

func xdposV1SnapshotKey(hash common.Hash) []byte {
	return dbKey(func(db ethdb.KeyValueWriter) {
		_ = rawdb.WriteXdposV1Snapshot(db, hash, nil)
	})
}

func xdposV2SnapshotKey(hash common.Hash) []byte {
	return dbKey(func(db ethdb.KeyValueWriter) {
		_ = rawdb.WriteXdposV2Snapshot(db, hash, nil)
	})
}

func headBlockMarkerKey() []byte {
	return dbKey(func(db ethdb.KeyValueWriter) {
		rawdb.WriteHeadBlockHash(db, common.Hash{})
	})
}

// writeRecorder wraps a database and records, in order, every key/value pair
// that reaches the disk, either directly or through a batch. It lets tests
// assert the relative ordering of writes issued by different components.
type writeRecorder struct {
	ethdb.Database

	lock   sync.Mutex
	writes []recordedWrite
}

type recordedWrite struct {
	key   []byte
	value []byte
}

func (r *writeRecorder) Put(key []byte, value []byte) error {
	if err := r.Database.Put(key, value); err != nil {
		return err
	}
	r.append(recordedWrite{key: common.CopyBytes(key), value: common.CopyBytes(value)})
	return nil
}

func (r *writeRecorder) NewBatch() ethdb.Batch {
	return &recordingBatch{Batch: r.Database.NewBatch(), recorder: r}
}

func (r *writeRecorder) NewBatchWithSize(size int) ethdb.Batch {
	return &recordingBatch{Batch: r.Database.NewBatchWithSize(size), recorder: r}
}

func (r *writeRecorder) append(writes ...recordedWrite) {
	r.lock.Lock()
	defer r.lock.Unlock()
	r.writes = append(r.writes, writes...)
}

func (r *writeRecorder) reset() {
	r.lock.Lock()
	defer r.lock.Unlock()
	r.writes = nil
}

// indexOf returns the position of the first recorded write of the given key,
// optionally restricted to a specific value, or -1 if there is none.
func (r *writeRecorder) indexOf(key []byte, value []byte) int {
	r.lock.Lock()
	defer r.lock.Unlock()
	for i, write := range r.writes {
		if !bytes.Equal(write.key, key) {
			continue
		}
		if value != nil && !bytes.Equal(write.value, value) {
			continue
		}
		return i
	}
	return -1
}

type recordingBatch struct {
	ethdb.Batch

	recorder *writeRecorder
	pending  []recordedWrite
}

func (b *recordingBatch) Put(key []byte, value []byte) error {
	if err := b.Batch.Put(key, value); err != nil {
		return err
	}
	b.pending = append(b.pending, recordedWrite{key: common.CopyBytes(key), value: common.CopyBytes(value)})
	return nil
}

func (b *recordingBatch) Write() error {
	if err := b.Batch.Write(); err != nil {
		return err
	}
	b.recorder.append(b.pending...)
	b.pending = nil
	return nil
}

func (b *recordingBatch) Reset() {
	b.Batch.Reset()
	b.pending = nil
}

var (
	gapTestSealKey, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	gapTestCandidates = []common.Address{
		common.HexToAddress("0x1000000000000000000000000000000000000001"),
		common.HexToAddress("0x1000000000000000000000000000000000000002"),
		common.HexToAddress("0x1000000000000000000000000000000000000003"),
	}
)

// gapTestChainConfig shrinks the epoch so that block 1 is a gap block, keeping
// the generated test chains short. Gap blocks satisfy number%epoch == epoch-gap.
func gapTestChainConfig() *params.ChainConfig {
	config := *params.TestXDPoSMockChainConfig
	xdpos := *config.XDPoS
	xdpos.Epoch = 4
	xdpos.Gap = 3
	xdpos.V2 = xdpos.V2.Clone()
	config.XDPoS = &xdpos
	return &config
}

// drainCheckpointCh consumes the unbuffered epoch-switch notifications that
// insertChain emits, which would otherwise deadlock chains crossing an epoch.
// CheckpointCh is a package global, so no other test may read from it while this
// drainer is running.
func drainCheckpointCh(t *testing.T) {
	t.Helper()

	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	go func() {
		for {
			select {
			case <-CheckpointCh:
			case <-done:
				return
			}
		}
	}()
}

// votingSCStorage builds the raw storage of the masternode voting contract so
// that StateDB.GetCandidates/GetCandidateCap resolve the given candidates.
func votingSCStorage(candidates []common.Address) map[common.Hash]common.Hash {
	storage := make(map[common.Hash]common.Hash)
	slotHash := common.BigToHash(new(big.Int).SetUint64(votingSCCandidatesSlot))
	storage[slotHash] = common.BigToHash(new(big.Int).SetUint64(uint64(len(candidates))))
	for i, candidate := range candidates {
		storage[state.GetLocDynamicArrAtElement(slotHash, uint64(i), 1)] = candidate.Hash()
		capLoc := state.GetLocMappingAtKey(candidate.Hash(), votingSCValidatorsStateSlot)
		capLoc.Add(capLoc, common.Big1)
		storage[common.BigToHash(capLoc)] = common.BigToHash(big.NewInt(int64(1000 + i)))
	}
	return storage
}

func gapTestGenesis(config *params.ChainConfig, candidates []common.Address) *Genesis {
	extra := make([]byte, 32)
	for _, candidate := range candidates {
		extra = append(extra, candidate.Bytes()...)
	}
	extra = append(extra, make([]byte, crypto.SignatureLength)...)

	return &Genesis{
		Config:    config,
		ExtraData: extra,
		GasLimit:  10000000,
		BaseFee:   big.NewInt(params.InitialBaseFee),
		Alloc: types.GenesisAlloc{
			common.MasternodeVotingSMCBinary: {
				Balance: big.NewInt(1),
				Storage: votingSCStorage(candidates),
			},
		},
	}
}

// gapTestExtra returns a header extra field carrying a well formed seal, which
// the V1 snapshot machinery needs to recover a signer from the header.
func gapTestExtra(vanity byte) []byte {
	extra := make([]byte, 32)
	extra[0] = vanity
	sig, err := crypto.Sign(common.Hash{}.Bytes(), gapTestSealKey)
	if err != nil {
		panic(err)
	}
	return append(extra, sig...)
}

// gapTestChain generates blocks on top of the given genesis, tagging them with
// the given vanity byte so that competing chains end up with distinct hashes.
func gapTestChain(t *testing.T, gspec *Genesis, blocks int, vanity byte, gen func(int, *BlockGen)) []*types.Block {
	t.Helper()

	engine := XDPoS.NewFaker(rawdb.NewMemoryDatabase(), gspec.Config)
	if engine == nil {
		t.Fatal("failed to create fake XDPoS engine")
	}
	_, chain, _ := GenerateChainWithGenesis(gspec, engine, blocks, func(i int, block *BlockGen) {
		block.SetExtra(gapTestExtra(vanity))
		if gen != nil {
			gen(i, block)
		}
	})
	return chain
}

func newGapTestBlockChain(t *testing.T, gspec *Genesis) (*BlockChain, *writeRecorder) {
	t.Helper()

	db := &writeRecorder{Database: rawdb.NewMemoryDatabase()}
	engine := XDPoS.NewFaker(db, gspec.Config)
	if engine == nil {
		t.Fatal("failed to create fake XDPoS engine")
	}
	chain, err := NewBlockChain(db, nil, gspec, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create blockchain: %v", err)
	}
	t.Cleanup(chain.Stop)
	return chain, db
}

// TestGapBlockSnapshotStoredBeforeHead asserts that importing a canonical gap
// block persists the masternode snapshot before the head markers, so a crash in
// between can never leave the head pointing at a gap block without a snapshot.
func TestGapBlockSnapshotStoredBeforeHead(t *testing.T) {
	gspec := gapTestGenesis(gapTestChainConfig(), gapTestCandidates)
	blocks := gapTestChain(t, gspec, 1, 0xaa, nil)
	gapBlock := blocks[0]

	chain, db := newGapTestBlockChain(t, gspec)
	db.reset()
	if _, err := chain.InsertChain(blocks); err != nil {
		t.Fatalf("failed to insert gap block: %v", err)
	}
	if head := chain.CurrentBlock().Hash(); head != gapBlock.Hash() {
		t.Fatalf("head mismatch: have %x, want %x", head, gapBlock.Hash())
	}

	snapIndex := db.indexOf(xdposV1SnapshotKey(gapBlock.Hash()), nil)
	if snapIndex < 0 {
		t.Fatal("no snapshot was stored for the canonical gap block")
	}
	headIndex := db.indexOf(headBlockMarkerKey(), gapBlock.Hash().Bytes())
	if headIndex < 0 {
		t.Fatal("head block marker was never written for the gap block")
	}
	if snapIndex > headIndex {
		t.Fatalf("gap snapshot stored after head marker: snapshot at %d, head at %d", snapIndex, headIndex)
	}
	if _, err := rawdb.ReadXdposV1Snapshot(db, gapBlock.Hash()); err != nil {
		t.Fatalf("gap snapshot is not readable after import: %v", err)
	}
}

// TestGapBlockSnapshotStoredBeforeHeadV2 pins the same ordering for the V2
// engine, whose snapshots live under a different database key and whose loss is
// what drops a node out of consensus. A V2 header carries a quorum certificate
// that cannot be produced here, so an empty block is handed to
// WriteBlockWithState directly instead of going through header verification.
func TestGapBlockSnapshotStoredBeforeHeadV2(t *testing.T) {
	config := gapTestChainConfig()
	config.XDPoS.V2.SwitchBlock = big.NewInt(0)

	gspec := gapTestGenesis(config, gapTestCandidates)
	chain, db := newGapTestBlockChain(t, gspec)

	parent := chain.Genesis().Header()
	gapBlock := types.NewBlockWithHeader(&types.Header{
		ParentHash: parent.Hash(),
		Number:     new(big.Int).Add(parent.Number, common.Big1),
		Root:       parent.Root,
		GasLimit:   parent.GasLimit,
		Time:       parent.Time + 1,
		Difficulty: big.NewInt(1),
		BaseFee:    new(big.Int).Set(parent.BaseFee),
	})
	statedb, err := chain.StateAt(parent.Root)
	if err != nil {
		t.Fatalf("failed to open genesis state: %v", err)
	}
	db.reset()
	status, err := chain.WriteBlockWithState(gapBlock, nil, statedb, nil, nil)
	if err != nil {
		t.Fatalf("failed to write gap block: %v", err)
	}
	if status != CanonStatTy {
		t.Fatalf("gap block did not become canonical: status %v", status)
	}

	snapIndex := db.indexOf(xdposV2SnapshotKey(gapBlock.Hash()), nil)
	if snapIndex < 0 {
		t.Fatal("no V2 snapshot was stored for the canonical gap block")
	}
	headIndex := db.indexOf(headBlockMarkerKey(), gapBlock.Hash().Bytes())
	if headIndex < 0 {
		t.Fatal("head block marker was never written for the gap block")
	}
	if snapIndex > headIndex {
		t.Fatalf("gap snapshot stored after head marker: snapshot at %d, head at %d", snapIndex, headIndex)
	}
}

// TestGapBlockSnapshotStoredBeforeHeadOnReorg asserts the same ordering for gap
// blocks that only become canonical through a reorg.
func TestGapBlockSnapshotStoredBeforeHeadOnReorg(t *testing.T) {
	gspec := gapTestGenesis(gapTestChainConfig(), gapTestCandidates)
	canonical := gapTestChain(t, gspec, 1, 0xaa, nil)
	side := gapTestChain(t, gspec, 2, 0xbb, nil)
	sideGapBlock := side[0]

	chain, db := newGapTestBlockChain(t, gspec)
	if _, err := chain.InsertChain(canonical); err != nil {
		t.Fatalf("failed to insert canonical gap block: %v", err)
	}
	db.reset()
	if _, err := chain.InsertChain(side); err != nil {
		t.Fatalf("failed to insert side chain: %v", err)
	}
	if head := chain.CurrentBlock().Hash(); head != side[len(side)-1].Hash() {
		t.Fatalf("reorg did not happen: head is %x", head)
	}

	snapIndex := db.indexOf(xdposV1SnapshotKey(sideGapBlock.Hash()), nil)
	if snapIndex < 0 {
		t.Fatal("no snapshot was stored for the reorged gap block")
	}
	headIndex := db.indexOf(headBlockMarkerKey(), sideGapBlock.Hash().Bytes())
	if headIndex < 0 {
		t.Fatal("head block marker was never written for the reorged gap block")
	}
	if snapIndex > headIndex {
		t.Fatalf("reorged gap snapshot stored after head marker: snapshot at %d, head at %d", snapIndex, headIndex)
	}
}

// TestGapBlockHeadNotAdvancedWithoutSnapshot asserts that a gap block whose
// masternode set cannot be derived is rejected instead of becoming the head
// with no snapshot behind it.
func TestGapBlockHeadNotAdvancedWithoutSnapshot(t *testing.T) {
	gspec := gapTestGenesis(gapTestChainConfig(), nil)
	blocks := gapTestChain(t, gspec, 1, 0xaa, nil)
	gapBlock := blocks[0]

	chain, db := newGapTestBlockChain(t, gspec)
	genesisHash := chain.Genesis().Hash()
	_, err := chain.InsertChain(blocks)
	if err == nil {
		t.Fatal("expected gap block import to fail without masternode candidates")
	}
	if !errors.Is(err, utils.ErrGapSnapshotUnavailable) {
		t.Fatalf("import error does not report a local snapshot failure: %v", err)
	}
	if head := chain.CurrentBlock().Hash(); head != genesisHash {
		t.Fatalf("head advanced to a gap block without snapshot: have %x, want %x", head, genesisHash)
	}
	if head := rawdb.ReadHeadBlockHash(db); head != genesisHash {
		t.Fatalf("persisted head marker advanced: have %x, want %x", head, genesisHash)
	}
	if _, err := rawdb.ReadXdposV1Snapshot(db, gapBlock.Hash()); err == nil {
		t.Fatal("snapshot unexpectedly stored for the rejected gap block")
	}
}

// gapTestWipeGenesis returns a genesis whose voting contract clears its
// candidate list when it receives a plain call, so a later gap block can no
// longer derive a masternode set.
func gapTestWipeGenesis() *Genesis {
	gspec := gapTestGenesis(gapTestChainConfig(), gapTestCandidates)
	gspec.Alloc[crypto.PubkeyToAddress(gapTestSealKey.PublicKey)] = types.Account{Balance: big.NewInt(1e18)}
	votingSC := gspec.Alloc[common.MasternodeVotingSMCBinary]
	// sstore(candidates slot, 0): wipes the candidate list when called.
	votingSC.Code = common.FromHex("600060085500")
	gspec.Alloc[common.MasternodeVotingSMCBinary] = votingSC
	return gspec
}

// gapTestWipeTx is the call that triggers the candidate wipe.
func gapTestWipeTx(config *params.ChainConfig) *types.Transaction {
	votingSCAddr := common.MasternodeVotingSMCBinary
	return types.MustSignNewTx(gapTestSealKey, types.LatestSigner(config), &types.LegacyTx{
		Nonce:    0,
		To:       &votingSCAddr,
		Gas:      100000,
		GasPrice: big.NewInt(params.InitialBaseFee),
	})
}

// TestGapBlockReorgAbortedWithoutSnapshot asserts that a reorg onto a gap block
// whose masternode set cannot be derived is aborted with an error instead of
// killing the node, leaving the head on a chain that still has a snapshot.
func TestGapBlockReorgAbortedWithoutSnapshot(t *testing.T) {
	gspec := gapTestWipeGenesis()
	canonical := gapTestChain(t, gspec, 1, 0xaa, nil)
	side := gapTestChain(t, gspec, 2, 0xbb, func(i int, block *BlockGen) {
		if i == 0 {
			block.AddTx(gapTestWipeTx(gspec.Config))
		}
	})

	chain, db := newGapTestBlockChain(t, gspec)
	if _, err := chain.InsertChain(canonical); err != nil {
		t.Fatalf("failed to insert canonical gap block: %v", err)
	}
	_, err := chain.InsertChain(side)
	if err == nil {
		t.Fatal("expected reorg onto a gap block without masternode candidates to fail")
	}
	if !strings.Contains(err.Error(), "during reorg") {
		t.Fatalf("import failed outside of the reorg gap handling: %v", err)
	}
	if !errors.Is(err, utils.ErrGapSnapshotUnavailable) {
		t.Fatalf("reorg error does not report a local snapshot failure: %v", err)
	}
	if head := chain.CurrentBlock().Hash(); head != canonical[0].Hash() {
		t.Fatalf("head moved to a gap block without snapshot: have %x, want %x", head, canonical[0].Hash())
	}
	if _, err := rawdb.ReadXdposV1Snapshot(db, canonical[0].Hash()); err != nil {
		t.Fatalf("snapshot of the retained head is missing: %v", err)
	}
	if _, err := rawdb.ReadXdposV1Snapshot(db, side[0].Hash()); err == nil {
		t.Fatal("snapshot unexpectedly stored for the rejected gap block")
	}
}

// TestGapBlockReorgAbortedLeavesChainUntouched asserts that a reorg aborted on a
// gap block applies no part of the new chain: the head and the canonical number
// markers of the old chain all survive, so no block number can resolve to an
// abandoned block.
func TestGapBlockReorgAbortedLeavesChainUntouched(t *testing.T) {
	drainCheckpointCh(t)

	gspec := gapTestWipeGenesis()
	canonical := gapTestChain(t, gspec, 5, 0xaa, nil)
	// Wiping the candidates in block 2 keeps gap block 1 of the new chain valid
	// while gap block 5 can no longer derive a masternode set, so the reorg is
	// aborted before it mutates anything.
	side := gapTestChain(t, gspec, 6, 0xbb, func(i int, block *BlockGen) {
		if i == 1 {
			block.AddTx(gapTestWipeTx(gspec.Config))
		}
	})

	chain, db := newGapTestBlockChain(t, gspec)
	if _, err := chain.InsertChain(canonical); err != nil {
		t.Fatalf("failed to insert canonical chain: %v", err)
	}
	if _, err := chain.InsertChain(side); err == nil {
		t.Fatal("expected the reorg onto the candidate-less gap block to fail")
	}
	head := chain.CurrentBlock()
	if want := canonical[len(canonical)-1]; head.Hash() != want.Hash() {
		t.Fatalf("head moved during the aborted reorg: have #%d %x, want #%d %x", head.Number, head.Hash(), want.NumberU64(), want.Hash())
	}
	for i, block := range canonical {
		if hash := rawdb.ReadCanonicalHash(db, uint64(i+1)); hash != block.Hash() {
			t.Fatalf("canonical marker at #%d changed: have %x, want %x", i+1, hash, block.Hash())
		}
	}
	if hash := rawdb.ReadCanonicalHash(db, uint64(len(canonical))+1); hash != (common.Hash{}) {
		t.Fatalf("orphan canonical marker left above the head: %x", hash)
	}
}

// TestUpdateM1WithoutContractClient asserts that UpdateM1 derives the masternode
// set from the head state and no longer needs an RPC client to call the voting
// contract.
func TestUpdateM1WithoutContractClient(t *testing.T) {
	gspec := gapTestGenesis(gapTestChainConfig(), gapTestCandidates)
	blocks := gapTestChain(t, gspec, 1, 0xaa, nil)
	gapBlock := blocks[0]

	chain, db := newGapTestBlockChain(t, gspec)
	if _, err := chain.InsertChain(blocks); err != nil {
		t.Fatalf("failed to insert gap block: %v", err)
	}
	if chain.Client != nil {
		t.Fatal("test expects a blockchain without contract client")
	}
	if err := chain.UpdateM1(); err != nil {
		t.Fatalf("UpdateM1 failed without contract client: %v", err)
	}
	if _, err := rawdb.ReadXdposV1Snapshot(db, gapBlock.Hash()); err != nil {
		t.Fatalf("UpdateM1 did not store a snapshot for the head gap block: %v", err)
	}
}
