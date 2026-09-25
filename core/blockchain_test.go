// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"errors"
	"math/big"
	"math/rand"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/common/hexutil"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/tracing"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/XinFinOrg/XDPoSChain/trie"
)

// newCanonical creates a chain database, and injects a deterministic canonical
// chain. Depending on the full flag, it creates either a full block chain or a
// header only chain. The database and genesis specification for block generation
// are also returned in case more test blocks are needed later.
func newCanonical(engine consensus.Engine, n int, full bool) (ethdb.Database, *Genesis, *BlockChain, error) {
	var (
		genesis = &Genesis{
			BaseFee: big.NewInt(params.InitialBaseFee),
			Config:  params.AllEthashProtocolChanges,
		}
	)
	// Initialize a fresh chain with only a genesis block
	blockchain, _ := NewBlockChain(rawdb.NewMemoryDatabase(), nil, genesis, engine, vm.Config{})

	// Create and inject the requested chain
	if n == 0 {
		return rawdb.NewMemoryDatabase(), genesis, blockchain, nil
	}
	if full {
		// Full block-chain requested
		genDb, blocks := makeBlockChainWithGenesis(genesis, n, engine, canonicalSeed)
		_, err := blockchain.InsertChain(blocks)
		return genDb, genesis, blockchain, err
	}
	// Header-only chain requested
	genDb, headers := makeHeaderChainWithGenesis(genesis, n, engine, canonicalSeed)
	_, err := blockchain.InsertHeaderChain(headers, 1)
	return genDb, genesis, blockchain, err
}

// Test fork of length N starting from block i
func testFork(t *testing.T, blockchain *BlockChain, i, n int, full bool, comparator func(td1, td2 *big.Int)) {
	// Copy old chain up to #i into a new genDb
	genDb, _, blockchain2, err := newCanonical(ethash.NewFaker(), i, full)
	if err != nil {
		t.Fatal("could not make new canonical in testFork", err)
	}
	defer blockchain2.Stop()

	// Assert the chains have the same header/block at #i
	var hash1, hash2 common.Hash
	if full {
		hash1 = blockchain.GetBlockByNumber(uint64(i)).Hash()
		hash2 = blockchain2.GetBlockByNumber(uint64(i)).Hash()
	} else {
		hash1 = blockchain.GetHeaderByNumber(uint64(i)).Hash()
		hash2 = blockchain2.GetHeaderByNumber(uint64(i)).Hash()
	}
	if hash1 != hash2 {
		t.Errorf("chain content mismatch at %d: have hash %v, want hash %v", i, hash2, hash1)
	}
	// Extend the newly created chain
	var (
		blockChainB  []*types.Block
		headerChainB []*types.Header
	)
	if full {
		blockChainB = makeBlockChain(blockchain2.chainConfig, blockchain2.GetBlockByHash(blockchain2.CurrentBlock().Hash()), n, ethash.NewFaker(), genDb, forkSeed)
		if _, err := blockchain2.InsertChain(blockChainB); err != nil {
			t.Fatalf("failed to insert forking chain: %v", err)
		}
	} else {
		headerChainB = makeHeaderChain(blockchain2.chainConfig, blockchain2.CurrentHeader(), n, ethash.NewFaker(), genDb, forkSeed)
		if _, err := blockchain2.InsertHeaderChain(headerChainB, 1); err != nil {
			t.Fatalf("failed to insert forking chain: %v", err)
		}
	}
	// Sanity check that the forked chain can be imported into the original
	var tdPre, tdPost *big.Int

	if full {
		tdPre = blockchain.GetTdByHash(blockchain.CurrentBlock().Hash())
		if err := testBlockChainImport(blockChainB, blockchain); err != nil {
			t.Fatalf("failed to import forked block chain: %v", err)
		}
		tdPost = blockchain.GetTdByHash(blockChainB[len(blockChainB)-1].Hash())
	} else {
		tdPre = blockchain.GetTdByHash(blockchain.CurrentHeader().Hash())
		if err := testHeaderChainImport(headerChainB, blockchain); err != nil {
			t.Fatalf("failed to import forked header chain: %v", err)
		}
		tdPost = blockchain.GetTdByHash(headerChainB[len(headerChainB)-1].Hash())
	}
	// Compare the total difficulties of the chains
	comparator(tdPre, tdPost)
}

// testBlockChainImport tries to process a chain of blocks, writing them into
// the database if successful.
func testBlockChainImport(chain types.Blocks, blockchain *BlockChain) error {
	for _, block := range chain {
		// Try and process the block
		err := blockchain.engine.VerifyHeader(blockchain, block.Header(), true)
		if err == nil {
			err = blockchain.validator.ValidateBody(block)
		}
		if err != nil {
			if err == ErrKnownBlock {
				continue
			}
			return err
		}
		statedb, err := state.New(blockchain.GetBlockByHash(block.ParentHash()).Root(), blockchain.stateCache)
		if err != nil {
			return err
		}
		receipts, _, usedGas, err := blockchain.Processor().Process(block, statedb, nil, vm.Config{}, map[common.Address]*big.Int{})
		if err != nil {
			blockchain.reportBlock(block, receipts, err)
			return err
		}
		err = blockchain.validator.ValidateState(block, statedb, receipts, usedGas)
		if err != nil {
			blockchain.reportBlock(block, receipts, err)
			return err
		}
		blockchain.chainmu.MustLock()
		rawdb.WriteTd(blockchain.db, block.Hash(), block.NumberU64(), new(big.Int).Add(block.Difficulty(), blockchain.GetTdByHash(block.ParentHash())))
		rawdb.WriteBlock(blockchain.db, block)
		statedb.Commit(block.NumberU64(), true)
		blockchain.chainmu.Unlock()
	}
	return nil
}

// testHeaderChainImport tries to process a chain of header, writing them into
// the database if successful.
func testHeaderChainImport(chain []*types.Header, blockchain *BlockChain) error {
	for _, header := range chain {
		// Try and validate the header
		if err := blockchain.engine.VerifyHeader(blockchain, header, false); err != nil {
			return err
		}
		// Manually insert the header into the database, but don't reorganise (allows subsequent testing)
		blockchain.chainmu.MustLock()
		rawdb.WriteTd(blockchain.db, header.Hash(), header.Number.Uint64(), new(big.Int).Add(header.Difficulty, blockchain.GetTdByHash(header.ParentHash)))
		rawdb.WriteHeader(blockchain.db, header)
		blockchain.chainmu.Unlock()
	}
	return nil
}

// TestLastBlock tests last block.
func TestLastBlock(t *testing.T) {
	genDb, _, blockchain, err := newCanonical(ethash.NewFaker(), 0, true)
	if err != nil {
		t.Fatalf("failed to create pristine chain: %v", err)
	}
	defer blockchain.Stop()

	blocks := makeBlockChain(blockchain.chainConfig, blockchain.GetBlockByHash(blockchain.CurrentBlock().Hash()), 1, ethash.NewFullFaker(), genDb, 0)
	if _, err := blockchain.InsertChain(blocks); err != nil {
		t.Fatalf("Failed to insert block: %v", err)
	}
	if blocks[len(blocks)-1].Hash() != rawdb.ReadHeadBlockHash(blockchain.db) {
		t.Fatalf("Write/Get HeadBlockHash failed")
	}
}

// TestNewBlockChainRecoversMissingGenesisState tests new block chain recovers missing genesis state.
func TestNewBlockChainRecoversMissingGenesisState(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := DefaultGenesisBlock()
	genesisBlock := genesis.MustCommit(db)

	rawdb.DeleteLegacyTrieNode(db, genesisBlock.Root())

	chain, err := NewBlockChain(db, nil, genesis, ethash.NewFaker(), vm.Config{})
	if err != nil {
		t.Fatalf("failed to recover missing genesis state: %v", err)
	}
	defer chain.Stop()

	if !chain.HasState(genesisBlock.Root()) {
		t.Fatal("expected genesis state to be restored")
	}
	if chain.CurrentBlock().Hash() != genesisBlock.Hash() {
		t.Fatalf("unexpected head block: have %s want %s", chain.CurrentBlock().Hash(), genesisBlock.Hash())
	}
}

// TestNewBlockChainReadOnlyFailsGenesisStateRecovery tests readonly options-based open fails when genesis state recovery would mutate the database.
func TestNewBlockChainReadOnlyFailsGenesisStateRecovery(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := DefaultGenesisBlock()
	genesisBlock := genesis.MustCommit(db)

	rawdb.DeleteLegacyTrieNode(db, genesisBlock.Root())

	chain, err := NewBlockChainReadOnlyResolved(db, nil, nil, ethash.NewFaker(), vm.Config{}, genesis.Config, genesisBlock.Hash(), nil, DefaultChainConfigMismatchPolicy)
	if err == nil {
		chain.Stop()
		t.Fatal("expected readonly open to fail when genesis state restoration would be required")
	}
	if !errors.Is(err, ErrReadOnlyGenesisStateRecovery) {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := state.New(genesisBlock.Root(), state.NewDatabase(db)); err == nil {
		t.Fatal("expected readonly open to leave genesis state missing")
	}
}

// TestNewBlockChainRecoversMissingCustomGenesisState tests
// writable startup can recover a custom genesis state when the matching genesis
// specification is available to the caller.
func TestNewBlockChainRecoversMissingCustomGenesisState(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := &Genesis{
		Config: &params.ChainConfig{
			ChainID:        big.NewInt(4444),
			HomesteadBlock: new(big.Int),
			Ethash:         new(params.EthashConfig),
		},
		Nonce:      66,
		ExtraData:  make([]byte, 32+crypto.SignatureLength),
		GasLimit:   4700000,
		Difficulty: big.NewInt(1),
		Timestamp:  12345,
		Alloc: types.GenesisAlloc{
			common.Address{1}: {Balance: big.NewInt(1)},
		},
	}

	config, ghash, compatErr, err := SetupGenesisBlock(db, genesis)
	if err != nil {
		t.Fatalf("failed to set up custom genesis: %v", err)
	}
	if compatErr != nil {
		t.Fatalf("unexpected compatibility error: %v", compatErr)
	}
	genesisBlock := rawdb.ReadBlock(db, ghash, 0)
	if genesisBlock == nil {
		t.Fatal("expected stored genesis block")
	}

	rawdb.DeleteLegacyTrieNode(db, genesisBlock.Root())
	if err := db.Delete(append([]byte("ethereum-genesis-"), ghash.Bytes()...)); err != nil {
		t.Fatalf("failed to delete persisted genesis alloc: %v", err)
	}
	if _, err := state.New(genesisBlock.Root(), state.NewDatabase(db)); err == nil {
		t.Fatal("expected genesis state to be missing before reopen")
	}

	chain, err := NewBlockChainResolved(db, nil, genesis, ethash.NewFaker(), vm.Config{}, config, ghash, compatErr, MismatchRewindAndUpdate)
	if err != nil {
		t.Fatalf("failed to recover missing custom genesis state: %v", err)
	}
	defer chain.Stop()

	if !chain.HasState(genesisBlock.Root()) {
		t.Fatal("expected custom genesis state to be restored")
	}
	if chain.CurrentBlock().Hash() != genesisBlock.Hash() {
		t.Fatalf("unexpected head block: have %s want %s", chain.CurrentBlock().Hash(), genesisBlock.Hash())
	}
}

// TestNewBlockChainRecoversMissingSparseGenesisState tests
// writable startup can recover a custom genesis state when the provided
// recovery genesis requires hydration before its hash matches the canonical
// stored genesis hash.
func TestNewBlockChainRecoversMissingSparseGenesisState(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := &Genesis{
		Config: &params.ChainConfig{
			ChainID:        new(big.Int).Set(params.LocalnetChainConfig.ChainID),
			HomesteadBlock: new(big.Int),
			Ethash:         new(params.EthashConfig),
		},
		Nonce:      68,
		ExtraData:  make([]byte, 32+crypto.SignatureLength),
		GasLimit:   4700000,
		Difficulty: big.NewInt(1),
		Timestamp:  12347,
		Alloc: types.GenesisAlloc{
			common.Address{3}: {Balance: big.NewInt(1)},
		},
	}

	config, ghash, compatErr, err := SetupGenesisBlock(db, genesis)
	if err != nil {
		t.Fatalf("failed to set up sparse genesis: %v", err)
	}
	if compatErr != nil {
		t.Fatalf("unexpected compatibility error: %v", compatErr)
	}
	genesisBlock := rawdb.ReadBlock(db, ghash, 0)
	if genesisBlock == nil {
		t.Fatal("expected stored genesis block")
	}
	if genesis.ToBlock().Hash() == ghash {
		t.Fatal("expected sparse genesis hash to differ before hydration")
	}

	rawdb.DeleteLegacyTrieNode(db, genesisBlock.Root())
	if err := db.Delete(append([]byte("ethereum-genesis-"), ghash.Bytes()...)); err != nil {
		t.Fatalf("failed to delete persisted genesis alloc: %v", err)
	}
	if _, err := state.New(genesisBlock.Root(), state.NewDatabase(db)); err == nil {
		t.Fatal("expected genesis state to be missing before reopen")
	}

	chain, err := NewBlockChainResolved(db, nil, genesis, ethash.NewFaker(), vm.Config{}, config, ghash, compatErr, DefaultChainConfigMismatchPolicy)
	if err != nil {
		t.Fatalf("failed to recover missing sparse genesis state: %v", err)
	}
	defer chain.Stop()

	if !chain.HasState(genesisBlock.Root()) {
		t.Fatal("expected sparse genesis state to be restored")
	}
	if chain.CurrentBlock().Hash() != genesisBlock.Hash() {
		t.Fatalf("unexpected head block: have %s want %s", chain.CurrentBlock().Hash(), genesisBlock.Hash())
	}
}

// TestNewBlockChainReadOnlyFailsCustomGenesisStateRecovery
// tests readonly startup still fails when custom genesis recovery would require
// mutation.
func TestNewBlockChainReadOnlyFailsCustomGenesisStateRecovery(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := &Genesis{
		Config: &params.ChainConfig{
			ChainID:        big.NewInt(4445),
			HomesteadBlock: new(big.Int),
			Ethash:         new(params.EthashConfig),
		},
		Nonce:      67,
		ExtraData:  make([]byte, 32+crypto.SignatureLength),
		GasLimit:   4700000,
		Difficulty: big.NewInt(1),
		Timestamp:  12346,
		Alloc: types.GenesisAlloc{
			common.Address{2}: {Balance: big.NewInt(1)},
		},
	}

	config, ghash, compatErr, err := SetupGenesisBlock(db, genesis)
	if err != nil {
		t.Fatalf("failed to set up custom genesis: %v", err)
	}
	if compatErr != nil {
		t.Fatalf("unexpected compatibility error: %v", compatErr)
	}
	genesisBlock := rawdb.ReadBlock(db, ghash, 0)
	if genesisBlock == nil {
		t.Fatal("expected stored genesis block")
	}

	rawdb.DeleteLegacyTrieNode(db, genesisBlock.Root())
	if err := db.Delete(append([]byte("ethereum-genesis-"), ghash.Bytes()...)); err != nil {
		t.Fatalf("failed to delete persisted genesis alloc: %v", err)
	}

	chain, err := NewBlockChainReadOnlyResolved(db, nil, genesis, ethash.NewFaker(), vm.Config{}, config, ghash, compatErr, DefaultChainConfigMismatchPolicy)
	if err == nil {
		chain.Stop()
		t.Fatal("expected readonly open to fail when custom genesis recovery would be required")
	}
	if !errors.Is(err, ErrReadOnlyGenesisStateRecovery) {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := state.New(genesisBlock.Root(), state.NewDatabase(db)); err == nil {
		t.Fatal("expected readonly open to leave custom genesis state missing")
	}
}

func TestNewBlockChainLiveTracerDoesNotRecoverCustomGenesisAlloc(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := &Genesis{
		Config: &params.ChainConfig{
			ChainID:        big.NewInt(4447),
			HomesteadBlock: new(big.Int),
			Ethash:         new(params.EthashConfig),
		},
		Nonce:      70,
		ExtraData:  make([]byte, 32+crypto.SignatureLength),
		GasLimit:   4700000,
		Difficulty: big.NewInt(1),
		Timestamp:  12349,
		Alloc: types.GenesisAlloc{
			common.Address{5}: {Balance: big.NewInt(1)},
		},
	}

	config, ghash, compatErr, err := SetupGenesisBlock(db, genesis)
	if err != nil {
		t.Fatalf("failed to set up custom genesis: %v", err)
	}
	if compatErr != nil {
		t.Fatalf("unexpected compatibility error: %v", compatErr)
	}
	genesisBlock := rawdb.ReadBlock(db, ghash, 0)
	if genesisBlock == nil {
		t.Fatal("expected stored genesis block")
	}
	if !rawdb.HasLegacyTrieNode(db, genesisBlock.Root()) {
		t.Fatal("expected genesis state trie to remain present")
	}
	if err := db.Delete(append([]byte("ethereum-genesis-"), ghash.Bytes()...)); err != nil {
		t.Fatalf("failed to delete persisted genesis alloc: %v", err)
	}

	called := false
	chain, err := NewBlockChainResolved(db, nil, genesis, ethash.NewFaker(), vm.Config{Tracer: &tracing.Hooks{
		OnGenesisBlock: func(block *types.Block, alloc types.GenesisAlloc) {
			called = true
		},
	}}, config, ghash, compatErr, DefaultChainConfigMismatchPolicy)
	if err == nil {
		chain.Stop()
		t.Fatal("expected live tracer open to fail when custom genesis alloc would require recovery")
	}
	if called {
		t.Fatal("expected live tracer genesis hook to remain uncalled")
	}
	if !errors.Is(err, ErrGenesisAllocUnavailable) {
		t.Fatalf("expected genesis alloc unavailable error, have %v", err)
	}
	if got := err.Error(); !strings.Contains(got, "live blockchain tracer requires genesis alloc to be set") {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := err.Error(); !strings.Contains(got, ghash.Hex()) {
		t.Fatalf("expected tracer error to include genesis hash, have %v", err)
	}
	if rawdb.ReadGenesisStateSpec(db, ghash) != nil {
		t.Fatal("expected live tracer path to avoid restoring the persisted genesis alloc")
	}
}

// TestInsertChainWithoutTRC21Issuer tests insert chain without trc 21 issuer.
func TestInsertChainWithoutTRC21Issuer(t *testing.T) {
	key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	if err != nil {
		t.Fatalf("failed to create test key: %v", err)
	}
	from := crypto.PubkeyToAddress(key.PublicKey)
	to := common.HexToAddress("0x00000000000000000000000000000000000000aa")

	gspec := &Genesis{
		Config: &params.ChainConfig{
			ChainID:        big.NewInt(1338),
			HomesteadBlock: new(big.Int),
			Ethash:         new(params.EthashConfig),
		},
		Alloc: types.GenesisAlloc{
			from: {Balance: big.NewInt(params.Ether)},
			to:   {Balance: big.NewInt(0)},
		},
		Difficulty: big.NewInt(1),
	}

	engine := ethash.NewFaker()
	_, blocks, _ := GenerateChainWithGenesis(gspec, engine, 1, func(i int, b *BlockGen) {
		tx, err := types.SignTx(types.NewTransaction(0, to, big.NewInt(1), params.TxGas, big.NewInt(1), nil), types.HomesteadSigner{}, key)
		if err != nil {
			t.Fatalf("failed to sign tx: %v", err)
		}
		b.AddTx(tx)
	})

	chain, err := NewBlockChain(rawdb.NewMemoryDatabase(), nil, gspec, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create tester chain: %v", err)
	}
	defer chain.Stop()

	if n, err := chain.InsertChain(blocks); err != nil {
		t.Fatalf("block %d: failed to insert into chain: %v", n, err)
	}
	if chain.CurrentBlock().Number.Uint64() != 1 {
		t.Fatalf("unexpected head number: have %d want 1", chain.CurrentBlock().Number.Uint64())
	}
	if got := chain.GetBlockByNumber(1); got == nil || len(got.Transactions()) != 1 {
		t.Fatalf("expected imported block with one transaction")
	}
}

// TestNewBlockChainRepairsMissingHeadStateConsistently tests new block chain repairs missing head state consistently.
func TestNewBlockChainRepairsMissingHeadStateConsistently(t *testing.T) {
	var (
		key, _  = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		address = crypto.PubkeyToAddress(key.PublicKey)
		funds   = big.NewInt(1000000000000000)
		gspec   = &Genesis{
			Alloc:   types.GenesisAlloc{address: {Balance: funds}},
			BaseFee: big.NewInt(params.InitialBaseFee),
			Config:  params.TestChainConfig,
		}
	)
	db := rawdb.NewMemoryDatabase()
	chain, err := NewBlockChain(db, nil, gspec, ethash.NewFaker(), vm.Config{})
	if err != nil {
		t.Fatalf("failed to create chain: %v", err)
	}

	_, blocks, _ := GenerateChainWithGenesis(gspec, ethash.NewFaker(), 3, nil)
	if n, err := chain.InsertChain(blocks); err != nil {
		chain.Stop()
		t.Fatalf("failed to insert block %d: %v", n, err)
	}
	head := blocks[len(blocks)-1]
	repaired := blocks[len(blocks)-2]
	chain.Stop()

	rawdb.DeleteLegacyTrieNode(db, head.Root())

	reopened, err := NewBlockChain(db, nil, gspec, ethash.NewFaker(), vm.Config{})
	if err != nil {
		t.Fatalf("failed to reopen repaired chain: %v", err)
	}
	defer reopened.Stop()

	if got := reopened.CurrentBlock().Hash(); got != repaired.Hash() {
		t.Fatalf("unexpected repaired current block: have %s want %s", got, repaired.Hash())
	}
	if got := reopened.CurrentSnapBlock().Hash(); got != repaired.Hash() {
		t.Fatalf("unexpected repaired current snap block: have %s want %s", got, repaired.Hash())
	}
	if got := reopened.CurrentHeader().Hash(); got != repaired.Hash() {
		t.Fatalf("unexpected repaired current header: have %s want %s", got, repaired.Hash())
	}
	if got := rawdb.ReadHeadHeaderHash(db); got != repaired.Hash() {
		t.Fatalf("unexpected repaired persisted head header: have %s want %s", got.Hex(), repaired.Hash().Hex())
	}
	if got := rawdb.ReadHeadFastBlockHash(db); got != repaired.Hash() {
		t.Fatalf("unexpected repaired persisted head fast block: have %s want %s", got.Hex(), repaired.Hash().Hex())
	}
	if got := rawdb.ReadHeadBlockHash(db); got != repaired.Hash() {
		t.Fatalf("unexpected repaired persisted head block: have %s want %s", got.Hex(), repaired.Hash().Hex())
	}
}

// TestNewBlockChainRepairsMissingHeadStateRespectsRollbackTarget ensures
// startup repair does not rewind below the user-requested rollback target.
func TestNewBlockChainRepairsMissingHeadStateRespectsRollbackTarget(t *testing.T) {
	var (
		key, _  = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		address = crypto.PubkeyToAddress(key.PublicKey)
		funds   = big.NewInt(1000000000000000)
		gspec   = &Genesis{
			Alloc:   types.GenesisAlloc{address: {Balance: funds}},
			BaseFee: big.NewInt(params.InitialBaseFee),
			Config:  params.TestChainConfig,
		}
	)
	db := rawdb.NewMemoryDatabase()
	chain, err := NewBlockChain(db, nil, gspec, ethash.NewFaker(), vm.Config{})
	if err != nil {
		t.Fatalf("failed to create chain: %v", err)
	}

	_, blocks, _ := GenerateChainWithGenesis(gspec, ethash.NewFaker(), 3, nil)
	if n, err := chain.InsertChain(blocks); err != nil {
		chain.Stop()
		t.Fatalf("failed to insert block %d: %v", n, err)
	}
	head := blocks[len(blocks)-1]
	target := blocks[len(blocks)-2]
	chain.Stop()

	rawdb.DeleteLegacyTrieNode(db, head.Root())

	prevRollback := common.RollbackNumber
	common.RollbackNumber = int64(target.NumberU64())
	t.Cleanup(func() {
		common.RollbackNumber = prevRollback
	})

	reopened, err := NewBlockChain(db, nil, gspec, ethash.NewFaker(), vm.Config{})
	if err != nil {
		t.Fatalf("failed to reopen repaired chain: %v", err)
	}
	defer reopened.Stop()

	if got := reopened.CurrentBlock().Hash(); got != target.Hash() {
		t.Fatalf("unexpected repaired current block: have %s want %s", got, target.Hash())
	}
	if got := reopened.CurrentSnapBlock().Hash(); got != target.Hash() {
		t.Fatalf("unexpected repaired current snap block: have %s want %s", got, target.Hash())
	}
	if got := reopened.CurrentHeader().Hash(); got != target.Hash() {
		t.Fatalf("unexpected repaired current header: have %s want %s", got, target.Hash())
	}
}

// TestNewBlockChainReadOnlyFailsHeadStateRepair tests readonly options-based open fails when head state repair would mutate the database.
func TestNewBlockChainReadOnlyFailsHeadStateRepair(t *testing.T) {
	var (
		key, _  = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		address = crypto.PubkeyToAddress(key.PublicKey)
		funds   = big.NewInt(1000000000000000)
		gspec   = &Genesis{
			Alloc:   types.GenesisAlloc{address: {Balance: funds}},
			BaseFee: big.NewInt(params.InitialBaseFee),
			Config:  params.TestChainConfig,
		}
	)
	db := rawdb.NewMemoryDatabase()
	chain, err := NewBlockChain(db, nil, gspec, ethash.NewFaker(), vm.Config{})
	if err != nil {
		t.Fatalf("failed to create chain: %v", err)
	}

	_, blocks, _ := GenerateChainWithGenesis(gspec, ethash.NewFaker(), 3, nil)
	if n, err := chain.InsertChain(blocks); err != nil {
		chain.Stop()
		t.Fatalf("failed to insert block %d: %v", n, err)
	}
	head := blocks[len(blocks)-1]
	chain.Stop()

	rawdb.DeleteLegacyTrieNode(db, head.Root())

	reopened, err := NewBlockChainReadOnlyResolved(db, nil, nil, ethash.NewFaker(), vm.Config{}, gspec.Config, gspec.ToBlock().Hash(), nil, DefaultChainConfigMismatchPolicy)
	if err == nil {
		reopened.Stop()
		t.Fatal("expected readonly open to fail when head state repair would be required")
	}
	if !errors.Is(err, ErrReadOnlyHeadStateRepair) {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := state.New(head.Root(), state.NewDatabase(db)); err == nil {
		t.Fatal("expected readonly open to leave head state missing")
	}
	if got := rawdb.ReadHeadBlockHash(db); got != head.Hash() {
		t.Fatalf("expected readonly open to leave head hash unchanged: have %s want %s", got.Hex(), head.Hash().Hex())
	}
}

// TestNewBlockChainExReadOnlyResolvedHonorsReadOnly tests the XDCx-aware wrapper
// forwards readonly startup options instead of silently defaulting to writable
// recovery.
func TestNewBlockChainExReadOnlyResolvedHonorsReadOnly(t *testing.T) {
	var (
		key, _  = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		address = crypto.PubkeyToAddress(key.PublicKey)
		funds   = big.NewInt(1000000000000000)
		gspec   = &Genesis{
			Alloc:   types.GenesisAlloc{address: {Balance: funds}},
			BaseFee: big.NewInt(params.InitialBaseFee),
			Config:  params.TestChainConfig,
		}
	)
	db := rawdb.NewMemoryDatabase()
	chain, err := NewBlockChain(db, nil, gspec, ethash.NewFaker(), vm.Config{})
	if err != nil {
		t.Fatalf("failed to create chain: %v", err)
	}

	_, blocks, _ := GenerateChainWithGenesis(gspec, ethash.NewFaker(), 3, nil)
	if n, err := chain.InsertChain(blocks); err != nil {
		chain.Stop()
		t.Fatalf("failed to insert block %d: %v", n, err)
	}
	head := blocks[len(blocks)-1]
	chain.Stop()

	rawdb.DeleteLegacyTrieNode(db, head.Root())

	reopened, err := NewBlockChainExReadOnlyResolved(db, nil, nil, nil, ethash.NewFaker(), vm.Config{}, gspec.Config, gspec.ToBlock().Hash(), nil, DefaultChainConfigMismatchPolicy)
	if err == nil {
		reopened.Stop()
		t.Fatal("expected readonly open to fail when head state repair would be required")
	}
	if !errors.Is(err, ErrReadOnlyHeadStateRepair) {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := rawdb.ReadHeadBlockHash(db); got != head.Hash() {
		t.Fatalf("expected readonly open to leave head hash unchanged: have %s want %s", got.Hex(), head.Hash().Hex())
	}
	if _, err := state.New(head.Root(), state.NewDatabase(db)); err == nil {
		t.Fatal("expected readonly open to leave head state missing")
	}
}

// TestNewBlockChainRewindsIncompatibleHead tests writable options-based open rewinds an incompatible head when compat metadata requires it.
func TestNewBlockChainRewindsIncompatibleHead(t *testing.T) {
	futureFork := big.NewInt(1_000_000)
	customg := Genesis{
		Config: &params.ChainConfig{
			ChainID:                big.NewInt(4444),
			HomesteadBlock:         big.NewInt(3),
			TIP2019Block:           new(big.Int).Set(futureFork),
			EIP150Block:            new(big.Int).Set(futureFork),
			EIP155Block:            new(big.Int).Set(futureFork),
			EIP158Block:            new(big.Int).Set(futureFork),
			ByzantiumBlock:         new(big.Int).Set(futureFork),
			ConstantinopleBlock:    new(big.Int).Set(futureFork),
			PetersburgBlock:        new(big.Int).Set(futureFork),
			IstanbulBlock:          new(big.Int).Set(futureFork),
			TIPTRC21FeeBlock:       big.NewInt(0),
			Gas50xBlock:            new(big.Int).Set(futureFork),
			TRC21IssuerSMC:         params.TestnetChainConfig.TRC21IssuerSMC,
			XDCXListingSMC:         params.TestnetChainConfig.XDCXListingSMC,
			RelayerRegistrationSMC: params.TestnetChainConfig.RelayerRegistrationSMC,
			LendingRegistrationSMC: params.TestnetChainConfig.LendingRegistrationSMC,
			Ethash:                 new(params.EthashConfig),
		},
		Alloc: types.GenesisAlloc{
			{1}: {Balance: big.NewInt(1), Storage: map[common.Hash]common.Hash{{1}: {1}}},
		},
	}
	oldcustomg := customg
	setXinFinForksToFuture(customg.Config, futureFork)
	setXinFinForksToFuture(oldcustomg.Config, futureFork)
	var err error
	customg.Config, err = resolveProvidedChainConfig(common.Hash{}, customg.Config, builtInChainConfigMustMatch)
	if err != nil {
		t.Fatalf("failed to hydrate custom config: %v", err)
	}
	oldcustomg.Config = &params.ChainConfig{
		ChainID:                big.NewInt(4444),
		HomesteadBlock:         big.NewInt(2),
		TIP2019Block:           new(big.Int).Set(futureFork),
		EIP150Block:            new(big.Int).Set(futureFork),
		EIP155Block:            new(big.Int).Set(futureFork),
		EIP158Block:            new(big.Int).Set(futureFork),
		ByzantiumBlock:         new(big.Int).Set(futureFork),
		ConstantinopleBlock:    new(big.Int).Set(futureFork),
		PetersburgBlock:        new(big.Int).Set(futureFork),
		IstanbulBlock:          new(big.Int).Set(futureFork),
		TIPTRC21FeeBlock:       big.NewInt(0),
		Gas50xBlock:            new(big.Int).Set(futureFork),
		TRC21IssuerSMC:         params.TestnetChainConfig.TRC21IssuerSMC,
		XDCXListingSMC:         params.TestnetChainConfig.XDCXListingSMC,
		RelayerRegistrationSMC: params.TestnetChainConfig.RelayerRegistrationSMC,
		LendingRegistrationSMC: params.TestnetChainConfig.LendingRegistrationSMC,
		Ethash:                 new(params.EthashConfig),
	}
	setXinFinForksToFuture(oldcustomg.Config, futureFork)
	oldcustomg.Config, err = resolveProvidedChainConfig(common.Hash{}, oldcustomg.Config, builtInChainConfigMustMatch)
	if err != nil {
		t.Fatalf("failed to hydrate old custom config: %v", err)
	}

	db := rawdb.NewMemoryDatabase()
	genesis := oldcustomg.MustCommit(db)

	chain, err := NewBlockChain(db, nil, &oldcustomg, ethash.NewFullFaker(), vm.Config{})
	if err != nil {
		t.Fatalf("failed to create chain: %v", err)
	}
	blocks, _ := GenerateChain(oldcustomg.Config, genesis, ethash.NewFaker(), db, 4, nil)
	if n, err := chain.InsertChain(blocks); err != nil {
		chain.Stop()
		t.Fatalf("failed to insert block %d: %v", n, err)
	}
	chain.Stop()

	config, ghash, compatErr, err := SetupGenesisBlock(db, &customg)
	if err != nil {
		t.Fatalf("unexpected setup error: %v", err)
	}
	if compatErr == nil {
		t.Fatal("expected compatibility error")
	}

	reopened, err := NewBlockChainResolved(db, nil, nil, ethash.NewFaker(), vm.Config{}, config, ghash, compatErr, MismatchRewindAndUpdate)
	if err != nil {
		t.Fatalf("failed to reopen rewound chain: %v", err)
	}
	defer reopened.Stop()

	if got := reopened.CurrentBlock().Number.Uint64(); got != compatErr.RewindTo {
		t.Fatalf("unexpected head number after rewind: have %d want %d", got, compatErr.RewindTo)
	}
	if got := reopened.CurrentBlock().Hash(); got != blocks[compatErr.RewindTo-1].Hash() {
		t.Fatalf("unexpected head hash after rewind: have %s want %s", got, blocks[compatErr.RewindTo-1].Hash())
	}
}

// TestNewBlockChainFailsReadonlyConfigRewind tests new block chain fails readonly config rewind.
func TestNewBlockChainFailsReadonlyConfigRewind(t *testing.T) {
	futureFork := big.NewInt(1_000_000)
	customg := Genesis{
		Config: &params.ChainConfig{
			ChainID:                big.NewInt(4444),
			HomesteadBlock:         big.NewInt(3),
			TIP2019Block:           new(big.Int).Set(futureFork),
			EIP150Block:            new(big.Int).Set(futureFork),
			EIP155Block:            new(big.Int).Set(futureFork),
			EIP158Block:            new(big.Int).Set(futureFork),
			ByzantiumBlock:         new(big.Int).Set(futureFork),
			ConstantinopleBlock:    new(big.Int).Set(futureFork),
			PetersburgBlock:        new(big.Int).Set(futureFork),
			IstanbulBlock:          new(big.Int).Set(futureFork),
			TIPTRC21FeeBlock:       big.NewInt(0),
			Gas50xBlock:            new(big.Int).Set(futureFork),
			TRC21IssuerSMC:         params.TestnetChainConfig.TRC21IssuerSMC,
			XDCXListingSMC:         params.TestnetChainConfig.XDCXListingSMC,
			RelayerRegistrationSMC: params.TestnetChainConfig.RelayerRegistrationSMC,
			LendingRegistrationSMC: params.TestnetChainConfig.LendingRegistrationSMC,
			Ethash:                 new(params.EthashConfig),
		},
		Alloc: types.GenesisAlloc{
			{1}: {Balance: big.NewInt(1), Storage: map[common.Hash]common.Hash{{1}: {1}}},
		},
	}
	oldcustomg := customg
	setXinFinForksToFuture(customg.Config, futureFork)
	setXinFinForksToFuture(oldcustomg.Config, futureFork)
	var err error
	customg.Config, err = resolveProvidedChainConfig(common.Hash{}, customg.Config, builtInChainConfigMustMatch)
	if err != nil {
		t.Fatalf("failed to hydrate custom config: %v", err)
	}
	oldcustomg.Config = &params.ChainConfig{
		ChainID:                big.NewInt(4444),
		HomesteadBlock:         big.NewInt(2),
		TIP2019Block:           new(big.Int).Set(futureFork),
		EIP150Block:            new(big.Int).Set(futureFork),
		EIP155Block:            new(big.Int).Set(futureFork),
		EIP158Block:            new(big.Int).Set(futureFork),
		ByzantiumBlock:         new(big.Int).Set(futureFork),
		ConstantinopleBlock:    new(big.Int).Set(futureFork),
		PetersburgBlock:        new(big.Int).Set(futureFork),
		IstanbulBlock:          new(big.Int).Set(futureFork),
		TIPTRC21FeeBlock:       big.NewInt(0),
		Gas50xBlock:            new(big.Int).Set(futureFork),
		TRC21IssuerSMC:         params.TestnetChainConfig.TRC21IssuerSMC,
		XDCXListingSMC:         params.TestnetChainConfig.XDCXListingSMC,
		RelayerRegistrationSMC: params.TestnetChainConfig.RelayerRegistrationSMC,
		LendingRegistrationSMC: params.TestnetChainConfig.LendingRegistrationSMC,
		Ethash:                 new(params.EthashConfig),
	}
	setXinFinForksToFuture(oldcustomg.Config, futureFork)
	oldcustomg.Config, err = resolveProvidedChainConfig(common.Hash{}, oldcustomg.Config, builtInChainConfigMustMatch)
	if err != nil {
		t.Fatalf("failed to hydrate old custom config: %v", err)
	}

	db := rawdb.NewMemoryDatabase()
	genesis := oldcustomg.MustCommit(db)

	chain, err := NewBlockChain(db, nil, &oldcustomg, ethash.NewFullFaker(), vm.Config{})
	if err != nil {
		t.Fatalf("failed to create chain: %v", err)
	}
	blocks, _ := GenerateChain(oldcustomg.Config, genesis, ethash.NewFaker(), db, 4, nil)
	if n, err := chain.InsertChain(blocks); err != nil {
		chain.Stop()
		t.Fatalf("failed to insert block %d: %v", n, err)
	}
	chain.Stop()

	config, ghash, compatErr, err := SetupGenesisBlock(db, &customg)
	if err != nil {
		t.Fatalf("unexpected setup error: %v", err)
	}
	if compatErr == nil {
		t.Fatal("expected compatibility error")
	}

	resolvedCfg, err := newResolvedBlockChainOpenConfig(true, nil, config, ghash, compatErr, MismatchRewindAndUpdate)
	if err != nil {
		t.Fatalf("failed to build readonly startup config: %v", err)
	}

	reopened, err := newBlockChain(db, nil, ethash.NewFaker(), vm.Config{}, resolvedCfg)
	if err == nil {
		reopened.Stop()
		t.Fatal("expected readonly open to fail when config rewind would be required")
	}
	if !errors.Is(err, ErrReadOnlyConfigRewind) {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := rawdb.ReadHeadBlockHash(db); got != blocks[len(blocks)-1].Hash() {
		t.Fatalf("expected readonly open to leave head hash unchanged: have %s want %s", got.Hex(), blocks[len(blocks)-1].Hash().Hex())
	}
}

// TestNewBlockChainReadOnlyFailsBadHashRewind tests readonly options-based open fails when startup would need a bad-hash rewind.
func TestNewBlockChainReadOnlyFailsBadHashRewind(t *testing.T) {
	genDb := rawdb.NewMemoryDatabase()
	gspec := &Genesis{BaseFee: big.NewInt(params.InitialBaseFee), Config: params.AllEthashProtocolChanges}
	blockchain, err := NewBlockChain(genDb, nil, gspec, ethash.NewFaker(), vm.Config{})
	if err != nil {
		t.Fatalf("failed to create pristine chain: %v", err)
	}
	blocks := makeBlockChain(blockchain.chainConfig, blockchain.GetBlockByHash(blockchain.CurrentBlock().Hash()), 4, ethash.NewFaker(), genDb, 10)
	if _, err = blockchain.InsertChain(blocks); err != nil {
		blockchain.Stop()
		t.Fatalf("failed to import blocks: %v", err)
	}
	BadHashes[blocks[3].Hash()] = true
	defer func() { delete(BadHashes, blocks[3].Hash()) }()
	blockchain.Stop()

	reopened, err := NewBlockChainReadOnlyResolved(genDb, nil, nil, ethash.NewFaker(), vm.Config{}, gspec.Config, gspec.ToBlock().Hash(), nil, DefaultChainConfigMismatchPolicy)
	if err == nil {
		reopened.Stop()
		t.Fatal("expected readonly open to fail when bad-hash rewind would be required")
	}
	if !errors.Is(err, ErrReadOnlyBadHashRewind) {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := rawdb.ReadHeadBlockHash(genDb); got != blocks[3].Hash() {
		t.Fatalf("expected readonly open to leave head hash unchanged: have %s want %s", got.Hex(), blocks[3].Hash().Hex())
	}
}

// TestNewBlockChainRewindsBadHashOnWritableOpen tests writable startup rewinds
// a denylisted canonical head during blockchain open.
func TestNewBlockChainRewindsBadHashOnWritableOpen(t *testing.T) {
	genDb := rawdb.NewMemoryDatabase()
	gspec := &Genesis{BaseFee: big.NewInt(params.InitialBaseFee), Config: params.AllEthashProtocolChanges}
	blockchain, err := NewBlockChain(genDb, nil, gspec, ethash.NewFaker(), vm.Config{})
	if err != nil {
		t.Fatalf("failed to create pristine chain: %v", err)
	}
	blocks := makeBlockChain(blockchain.chainConfig, blockchain.GetBlockByHash(blockchain.CurrentBlock().Hash()), 4, ethash.NewFaker(), genDb, 10)
	if _, err = blockchain.InsertChain(blocks); err != nil {
		blockchain.Stop()
		t.Fatalf("failed to import blocks: %v", err)
	}
	BadHashes[blocks[3].Hash()] = true
	defer func() { delete(BadHashes, blocks[3].Hash()) }()
	blockchain.Stop()

	reopened, err := NewBlockChainResolved(genDb, nil, nil, ethash.NewFaker(), vm.Config{}, gspec.Config, gspec.ToBlock().Hash(), nil, DefaultChainConfigMismatchPolicy)
	if err != nil {
		t.Fatalf("failed to reopen rewound chain: %v", err)
	}
	defer reopened.Stop()

	if got := reopened.CurrentBlock().Hash(); got != blocks[2].Hash() {
		t.Fatalf("unexpected head hash after bad-hash rewind: have %s want %s", got.Hex(), blocks[2].Hash().Hex())
	}
	if got := rawdb.ReadHeadBlockHash(genDb); got != blocks[2].Hash() {
		t.Fatalf("expected writable open to rewrite head hash: have %s want %s", got.Hex(), blocks[2].Hash().Hex())
	}
}

// TestNewBlockChainFailsOnUnrecoverableMissingGenesisState tests new block
// chain fails on unrecoverable missing genesis state when no matching genesis
// specification is available to recover from.
func TestNewBlockChainFailsOnUnrecoverableMissingGenesisState(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := &Genesis{
		Config: &params.ChainConfig{
			ChainID:                big.NewInt(4444),
			HomesteadBlock:         big.NewInt(0),
			TIPTRC21FeeBlock:       big.NewInt(0),
			Gas50xBlock:            big.NewInt(1),
			TRC21IssuerSMC:         params.TestnetChainConfig.TRC21IssuerSMC,
			XDCXListingSMC:         params.TestnetChainConfig.XDCXListingSMC,
			RelayerRegistrationSMC: params.TestnetChainConfig.RelayerRegistrationSMC,
			LendingRegistrationSMC: params.TestnetChainConfig.LendingRegistrationSMC,
			Ethash:                 new(params.EthashConfig),
		},
		Alloc: types.GenesisAlloc{
			{1}: {Balance: big.NewInt(1)},
		},
		Difficulty: big.NewInt(1),
		GasLimit:   4700000,
	}
	block := genesis.ToBlock()
	rawdb.WriteTd(db, block.Hash(), block.NumberU64(), genesis.Difficulty)
	rawdb.WriteBlock(db, block)
	rawdb.WriteReceipts(db, block.Hash(), block.NumberU64(), nil)
	rawdb.WriteCanonicalHash(db, block.Hash(), block.NumberU64())
	rawdb.WriteHeadBlockHash(db, block.Hash())
	rawdb.WriteHeadFastBlockHash(db, block.Hash())
	rawdb.WriteHeadHeaderHash(db, block.Hash())
	rawdb.WriteChainConfig(db, block.Hash(), genesis.Config)

	_, err := NewBlockChain(db, nil, nil, ethash.NewFaker(), vm.Config{})
	if err == nil {
		t.Fatal("expected unrecoverable missing genesis state error")
	}
	if got := err.Error(); !strings.Contains(got, "unrecoverable genesis alloc") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestNewBlockChainReadOnlyDoesNotRepairMissingChainConfig tests readonly
// options-based open resolves startup metadata via readonly loading and does
// not repair a missing chain-config blob.
func TestNewBlockChainReadOnlyDoesNotRepairMissingChainConfig(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := &Genesis{
		Config: &params.ChainConfig{
			ChainID:                big.NewInt(92929),
			TIPTRC21FeeBlock:       big.NewInt(0),
			Gas50xBlock:            big.NewInt(1),
			TRC21IssuerSMC:         params.TestnetChainConfig.TRC21IssuerSMC,
			XDCXListingSMC:         params.TestnetChainConfig.XDCXListingSMC,
			RelayerRegistrationSMC: params.TestnetChainConfig.RelayerRegistrationSMC,
			LendingRegistrationSMC: params.TestnetChainConfig.LendingRegistrationSMC,
			Ethash:                 new(params.EthashConfig),
		},
		Alloc: types.GenesisAlloc{
			{1}: {Balance: big.NewInt(1)},
		},
		GasLimit:   4700000,
		Difficulty: big.NewInt(1),
	}
	block := genesis.MustCommit(db)

	if err := db.Delete(append([]byte("ethereum-config-"), block.Hash().Bytes()...)); err != nil {
		t.Fatalf("failed to delete chain config blob: %v", err)
	}
	if _, err := rawdb.ReadChainConfigJSON(db, block.Hash()); !errors.Is(err, rawdb.ErrChainConfigNotFound) {
		t.Fatalf("expected missing chain config blob, got %v", err)
	}

	chain, err := NewBlockChainReadOnly(db, nil, genesis, ethash.NewFaker(), vm.Config{})
	if err != nil {
		t.Fatalf("expected readonly open to resolve config in memory without repairing metadata: %v", err)
	}
	defer chain.Stop()
	if _, err := rawdb.ReadChainConfigJSON(db, block.Hash()); !errors.Is(err, rawdb.ErrChainConfigNotFound) {
		t.Fatalf("expected readonly open to leave chain config blob missing, got %v", err)
	}
}

// TestNewBlockChainResolvedRejectsMissingGenesisHash tests the
// resolved-config constructor rejects an empty genesis hash.
func TestNewBlockChainResolvedRejectsMissingGenesisHash(t *testing.T) {
	_, err := NewBlockChainResolved(rawdb.NewMemoryDatabase(), nil, nil, ethash.NewFaker(), vm.Config{}, params.AllEthashProtocolChanges, common.Hash{}, nil, DefaultChainConfigMismatchPolicy)
	if !errors.Is(err, errBlockChainOpenMissingGenesisHash) {
		t.Fatalf("unexpected error for missing genesis hash: %v", err)
	}
}

func TestNewBlockChainResolvedRejectsInvalidCompatPolicy(t *testing.T) {
	t.Parallel()

	db := rawdb.NewMemoryDatabase()
	genesis := DefaultGenesisBlock()
	if _, _, _, err := SetupGenesisBlock(db, genesis); err != nil {
		t.Fatalf("failed to setup genesis: %v", err)
	}

	chain, err := NewBlockChainResolved(
		db,
		nil,
		genesis,
		ethash.NewFaker(),
		vm.Config{},
		genesis.Config,
		genesis.ToBlock().Hash(),
		nil,
		ChainConfigMismatchPolicy("not-a-policy"),
	)
	if chain != nil {
		chain.Stop()
		t.Fatal("expected blockchain open to fail for invalid compat policy")
	}
	if err == nil {
		t.Fatal("expected error for invalid compat policy")
	}
	if !strings.Contains(err.Error(), "invalid chain config mismatch policy") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestRecoveryGenesisConfigMismatch reports whether a caller-provided recovery
// genesis config would be ignored in favor of the resolved chain config.
func TestRecoveryGenesisConfigMismatch(t *testing.T) {
	resolved := params.TestnetChainConfig.Clone()
	mismatched := resolved.Clone()
	mismatched.ChainID = big.NewInt(9999)

	mismatch, err := recoveryGenesisConfigMismatch(&Genesis{Config: mismatched}, resolved)
	if err != nil {
		t.Fatalf("unexpected mismatch error: %v", err)
	}
	if !mismatch {
		t.Fatal("expected mismatched recovery genesis config to be detected")
	}
	mismatch, err = recoveryGenesisConfigMismatch(&Genesis{Config: resolved.Clone()}, resolved)
	if err != nil {
		t.Fatalf("unexpected equality error: %v", err)
	}
	if mismatch {
		t.Fatal("expected semantically equal recovery genesis config to be accepted")
	}
	mismatch, err = recoveryGenesisConfigMismatch(&Genesis{}, resolved)
	if err != nil {
		t.Fatalf("unexpected missing-config error: %v", err)
	}
	if mismatch {
		t.Fatal("expected missing recovery genesis config to skip mismatch detection")
	}
	mismatch, err = recoveryGenesisConfigMismatch(nil, resolved)
	if err != nil {
		t.Fatalf("unexpected nil-genesis error: %v", err)
	}
	if mismatch {
		t.Fatal("expected nil recovery genesis to skip mismatch detection")
	}
}

// TestNormalizedRecoveryGenesisRejectsCompareErrors tests recovery genesis
// config comparison errors fail closed during normalization.
func TestNormalizedRecoveryGenesisRejectsCompareErrors(t *testing.T) {
	compareErr := errors.New("compare failed")
	_, err := normalizedRecoveryGenesisWith(&Genesis{Config: params.TestnetChainConfig.Clone()}, params.TestnetChainConfig.Clone(), func(a, b *params.ChainConfig) (bool, error) {
		return false, compareErr
	})
	if err == nil {
		t.Fatal("expected recovery genesis config comparison failure")
	}
	if !strings.Contains(err.Error(), "failed to compare RecoveryGenesis config") {
		t.Fatalf("unexpected error: %v", err)
	}
	if !errors.Is(err, compareErr) {
		t.Fatalf("expected wrapped comparison error, got %v", err)
	}
}

// Tests that given a starting canonical chain of a given size, it can be extended
// with various length chains.
func TestExtendCanonicalHeaders(t *testing.T) { testExtendCanonical(t, false) }

// TestExtendCanonicalBlocks tests extend canonical blocks.
func TestExtendCanonicalBlocks(t *testing.T) { testExtendCanonical(t, true) }

func testExtendCanonical(t *testing.T, full bool) {
	length := 5

	// Make first chain starting from genesis
	_, _, processor, err := newCanonical(ethash.NewFaker(), length, full)
	if err != nil {
		t.Fatalf("failed to make new canonical chain: %v", err)
	}
	defer processor.Stop()

	// Define the difficulty comparator
	better := func(td1, td2 *big.Int) {
		if td2.Cmp(td1) <= 0 {
			t.Errorf("total difficulty mismatch: have %v, expected more than %v", td2, td1)
		}
	}
	// Start fork from current height
	testFork(t, processor, length, 1, full, better)
	testFork(t, processor, length, 2, full, better)
	testFork(t, processor, length, 5, full, better)
	testFork(t, processor, length, 10, full, better)
}

// Tests that given a starting canonical chain of a given size, creating shorter
// forks do not take canonical ownership.
func TestShorterForkHeaders(t *testing.T) { testShorterFork(t, false) }

// TestShorterForkBlocks tests shorter fork blocks.
func TestShorterForkBlocks(t *testing.T) { testShorterFork(t, true) }

func testShorterFork(t *testing.T, full bool) {
	length := 10

	// Make first chain starting from genesis
	_, _, processor, err := newCanonical(ethash.NewFaker(), length, full)
	if err != nil {
		t.Fatalf("failed to make new canonical chain: %v", err)
	}
	defer processor.Stop()

	// Define the difficulty comparator
	worse := func(td1, td2 *big.Int) {
		if td2.Cmp(td1) >= 0 {
			t.Errorf("total difficulty mismatch: have %v, expected less than %v", td2, td1)
		}
	}
	// Sum of numbers must be less than `length` for this to be a shorter fork
	testFork(t, processor, 0, 3, full, worse)
	testFork(t, processor, 0, 7, full, worse)
	testFork(t, processor, 1, 1, full, worse)
	testFork(t, processor, 1, 7, full, worse)
	testFork(t, processor, 5, 3, full, worse)
	testFork(t, processor, 5, 4, full, worse)
}

// Tests that given a starting canonical chain of a given size, creating longer
// forks do take canonical ownership.
func TestLongerForkHeaders(t *testing.T) { testLongerFork(t, false) }

// TestLongerForkBlocks tests longer fork blocks.
func TestLongerForkBlocks(t *testing.T) { testLongerFork(t, true) }

func testLongerFork(t *testing.T, full bool) {
	length := 10

	// Make first chain starting from genesis
	_, _, processor, err := newCanonical(ethash.NewFaker(), length, full)
	if err != nil {
		t.Fatalf("failed to make new canonical chain: %v", err)
	}
	defer processor.Stop()

	// Define the difficulty comparator
	better := func(td1, td2 *big.Int) {
		if td2.Cmp(td1) <= 0 {
			t.Errorf("total difficulty mismatch: have %v, expected more than %v", td2, td1)
		}
	}
	// Sum of numbers must be greater than `length` for this to be a longer fork
	testFork(t, processor, 0, 11, full, better)
	testFork(t, processor, 0, 15, full, better)
	testFork(t, processor, 1, 10, full, better)
	testFork(t, processor, 1, 12, full, better)
	testFork(t, processor, 5, 6, full, better)
	testFork(t, processor, 5, 8, full, better)
}

// Tests that given a starting canonical chain of a given size, creating equal
// forks do take canonical ownership.
func TestEqualForkHeaders(t *testing.T) { testEqualFork(t, false) }

// TestEqualForkBlocks tests equal fork blocks.
func TestEqualForkBlocks(t *testing.T) { testEqualFork(t, true) }

func testEqualFork(t *testing.T, full bool) {
	length := 10

	// Make first chain starting from genesis
	_, _, processor, err := newCanonical(ethash.NewFaker(), length, full)
	if err != nil {
		t.Fatalf("failed to make new canonical chain: %v", err)
	}
	defer processor.Stop()

	// Define the difficulty comparator
	equal := func(td1, td2 *big.Int) {
		if td2.Cmp(td1) != 0 {
			t.Errorf("total difficulty mismatch: have %v, want %v", td2, td1)
		}
	}
	// Sum of numbers must be equal to `length` for this to be an equal fork
	testFork(t, processor, 0, 10, full, equal)
	testFork(t, processor, 1, 9, full, equal)
	testFork(t, processor, 2, 8, full, equal)
	testFork(t, processor, 5, 5, full, equal)
	testFork(t, processor, 6, 4, full, equal)
	testFork(t, processor, 9, 1, full, equal)
}

// Tests that chains missing links do not get accepted by the processor.
func TestBrokenHeaderChain(t *testing.T) { testBrokenChain(t, false) }

// TestBrokenBlockChain tests broken block chain.
func TestBrokenBlockChain(t *testing.T) { testBrokenChain(t, true) }

func testBrokenChain(t *testing.T, full bool) {
	// Make chain starting from genesis
	genDb, _, blockchain, err := newCanonical(ethash.NewFaker(), 10, full)
	if err != nil {
		t.Fatalf("failed to make new canonical chain: %v", err)
	}
	defer blockchain.Stop()

	// Create a forked chain, and try to insert with a missing link
	if full {
		chain := makeBlockChain(blockchain.chainConfig, blockchain.GetBlockByHash(blockchain.CurrentBlock().Hash()), 5, ethash.NewFaker(), genDb, forkSeed)[1:]
		if err := testBlockChainImport(chain, blockchain); err == nil {
			t.Errorf("broken block chain not reported")
		}
	} else {
		chain := makeHeaderChain(blockchain.chainConfig, blockchain.CurrentHeader(), 5, ethash.NewFaker(), genDb, forkSeed)[1:]
		if err := testHeaderChainImport(chain, blockchain); err == nil {
			t.Errorf("broken header chain not reported")
		}
	}
}

// Tests that reorganising a long difficult chain after a short easy one
// overwrites the canonical numbers and links in the database.
func TestReorgLongHeaders(t *testing.T) { testReorgLong(t, false) }

// TestReorgLongBlocks tests reorg long blocks.
func TestReorgLongBlocks(t *testing.T) { testReorgLong(t, true) }

func testReorgLong(t *testing.T, full bool) {
	testReorg(t, []int64{0, 0, -9}, []int64{0, 0, 0, -9}, 393280, full)
}

// Tests that reorganising a short difficult chain after a long easy one
// overwrites the canonical numbers and links in the database.
func TestReorgShortHeaders(t *testing.T) { testReorgShort(t, false) }

// TestReorgShortBlocks tests reorg short blocks.
func TestReorgShortBlocks(t *testing.T) { testReorgShort(t, true) }

func testReorgShort(t *testing.T, full bool) {
	// Create a long easy chain vs. a short heavy one. Due to difficulty adjustment
	// we need a fairly long chain of blocks with different difficulties for a short
	// one to become heavyer than a long one. The 96 is an empirical value.
	easy := make([]int64, 96)
	for i := 0; i < len(easy); i++ {
		easy[i] = 60
	}
	diff := make([]int64, len(easy)-1)
	for i := 0; i < len(diff); i++ {
		diff[i] = -9
	}
	if full {
		testReorg(t, easy, diff, 12615120, full)
	} else {
		testReorg(t, easy, diff, 12615120, full)
	}
}

func testReorg(t *testing.T, first, second []int64, td int64, full bool) {
	// Create a pristine chain and database
	genDb, _, blockchain, err := newCanonical(ethash.NewFaker(), 0, full)
	if err != nil {
		t.Fatalf("failed to create pristine chain: %v", err)
	}
	defer blockchain.Stop()

	// Insert an easy and a difficult chain afterwards
	easyBlocks, _ := GenerateChain(blockchain.chainConfig, blockchain.GetBlockByHash(blockchain.CurrentBlock().Hash()), ethash.NewFaker(), genDb, len(first), func(i int, b *BlockGen) {
		b.OffsetTime(first[i])
	})
	diffBlocks, _ := GenerateChain(blockchain.chainConfig, blockchain.GetBlockByHash(blockchain.CurrentBlock().Hash()), ethash.NewFaker(), genDb, len(second), func(i int, b *BlockGen) {
		b.OffsetTime(second[i])
	})
	if full {
		if _, err := blockchain.InsertChain(easyBlocks); err != nil {
			t.Fatalf("failed to insert easy chain: %v", err)
		}
		if _, err := blockchain.InsertChain(diffBlocks); err != nil {
			t.Fatalf("failed to insert difficult chain: %v", err)
		}
	} else {
		easyHeaders := make([]*types.Header, len(easyBlocks))
		for i, block := range easyBlocks {
			easyHeaders[i] = block.Header()
		}
		diffHeaders := make([]*types.Header, len(diffBlocks))
		for i, block := range diffBlocks {
			diffHeaders[i] = block.Header()
		}
		if _, err := blockchain.InsertHeaderChain(easyHeaders, 1); err != nil {
			t.Fatalf("failed to insert easy chain: %v", err)
		}
		if _, err := blockchain.InsertHeaderChain(diffHeaders, 1); err != nil {
			t.Fatalf("failed to insert difficult chain: %v", err)
		}
	}
	// Check that the chain is valid number and link wise
	if full {
		prev := blockchain.CurrentBlock()
		for block := blockchain.GetBlockByNumber(blockchain.CurrentBlock().Number.Uint64() - 1); block.NumberU64() != 0; prev, block = block.Header(), blockchain.GetBlockByNumber(block.NumberU64()-1) {
			if prev.ParentHash != block.Hash() {
				t.Errorf("parent block hash mismatch: have %x, want %x", prev.ParentHash, block.Hash())
			}
		}
	} else {
		prev := blockchain.CurrentHeader()
		for header := blockchain.GetHeaderByNumber(blockchain.CurrentHeader().Number.Uint64() - 1); header.Number.Sign() != 0; prev, header = header, blockchain.GetHeaderByNumber(header.Number.Uint64()-1) {
			if prev.ParentHash != header.Hash() {
				t.Errorf("parent header hash mismatch: have %x, want %x", prev.ParentHash, header.Hash())
			}
		}
	}
	// Make sure the chain total difficulty is the correct one
	want := new(big.Int).Add(blockchain.genesisBlock.Difficulty(), big.NewInt(td))
	if full {
		cur := blockchain.CurrentBlock()
		if have := blockchain.GetTd(cur.Hash(), cur.Number.Uint64()); have.Cmp(want) != 0 {
			t.Errorf("total difficulty mismatch: have %v, want %v", have, want)
		}
	} else {
		cur := blockchain.CurrentHeader()
		if have := blockchain.GetTd(cur.Hash(), cur.Number.Uint64()); have.Cmp(want) != 0 {
			t.Errorf("total difficulty mismatch: have %v, want %v", have, want)
		}
	}
}

// TestReorgDeliversRemovedLogsSynchronously pins the delivery contract that the
// reborn logs already follow: a reorg hands the removed logs to every subscriber
// before it returns. Spawning that send let a subscriber observe the logs of the
// new chain before the removals of the blocks they revert, which is why geth
// dropped the goroutine in #19396.
func TestReorgDeliversRemovedLogsSynchronously(t *testing.T) {
	var (
		key, _  = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		address = crypto.PubkeyToAddress(key.PublicKey)
		// emitter is a genesis contract whose runtime code emits one anonymous log:
		// PUSH1 0x00, PUSH1 0x00, LOG0, STOP.
		emitter = common.HexToAddress("0x0000000000000000000000000000000000000010")
		gspec   = &Genesis{
			Config: &params.ChainConfig{
				ChainID:        big.NewInt(1338),
				HomesteadBlock: new(big.Int),
				Ethash:         new(params.EthashConfig),
			},
			Alloc: types.GenesisAlloc{
				address: {Balance: big.NewInt(params.Ether)},
				emitter: {Code: []byte{0x60, 0x00, 0x60, 0x00, 0xa0, 0x00}},
			},
			Difficulty: big.NewInt(1),
		}
	)
	engine := ethash.NewFaker()
	genDb := rawdb.NewMemoryDatabase()
	if _, err := gspec.Commit(genDb); err != nil {
		t.Fatalf("failed to commit genesis: %v", err)
	}
	blockchain, err := NewBlockChain(rawdb.NewMemoryDatabase(), nil, gspec, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create chain: %v", err)
	}
	defer blockchain.Stop()

	// Every block emits one log, so undoing the canonical chain produces removals
	// that the reorg has to deliver.
	emit := func(i int, b *BlockGen) {
		tx, err := types.SignTx(types.NewTransaction(uint64(i), emitter, big.NewInt(0), 100000, big.NewInt(1), nil), types.HomesteadSigner{}, key)
		if err != nil {
			t.Fatalf("failed to sign log transaction: %v", err)
		}
		b.AddTx(tx)
	}
	canonical, _ := GenerateChain(gspec.Config, blockchain.Genesis(), engine, genDb, 4, emit)
	fork, _ := GenerateChain(gspec.Config, blockchain.Genesis(), engine, genDb, 4, func(i int, b *BlockGen) {
		b.SetCoinbase(common.Address{0: 0x02})
		emit(i, b)
	})
	if _, err := blockchain.InsertChain(canonical); err != nil {
		t.Fatalf("failed to insert canonical chain: %v", err)
	}
	if _, err := blockchain.InsertChain(fork); err != nil {
		t.Fatalf("failed to insert the fork: %v", err)
	}
	if head, want := blockchain.CurrentBlock(), canonical[len(canonical)-1]; head.Hash() != want.Hash() {
		t.Fatalf("head moved onto the fork, want it kept as a side chain: have %x, want %x", head.Hash(), want.Hash())
	}

	// The subscriber stalls on purpose: a synchronous send has to wait for it,
	// an asynchronous one would let the reorg return first.
	removed := make(chan RemovedLogsEvent)
	sub := blockchain.SubscribeRemovedLogsEvent(removed)
	defer sub.Unsubscribe()

	const subscriberDelay = 250 * time.Millisecond
	var delivered atomic.Bool
	go func() {
		time.Sleep(subscriberDelay)
		select {
		case <-removed:
			delivered.Store(true)
		case <-time.After(5 * time.Second):
		}
	}()

	if err := blockchain.reorg(blockchain.CurrentBlock(), fork[len(fork)-1].Header()); err != nil {
		t.Fatalf("failed to reorg: %v", err)
	}
	if !delivered.Load() {
		t.Fatalf("reorg returned before the removed logs reached the subscriber, the send must be synchronous")
	}
}

// Tests that the insertion functions detect banned hashes.
func TestBadHeaderHashes(t *testing.T) { testBadHashes(t, false) }

// TestBadBlockHashes tests bad block hashes.
func TestBadBlockHashes(t *testing.T) { testBadHashes(t, true) }

func testBadHashes(t *testing.T, full bool) {
	// Create a pristine chain and database
	genDb, _, blockchain, err := newCanonical(ethash.NewFaker(), 0, full)
	if err != nil {
		t.Fatalf("failed to create pristine chain: %v", err)
	}
	defer blockchain.Stop()

	// Create a chain, ban a hash and try to import
	if full {
		blocks := makeBlockChain(blockchain.chainConfig, blockchain.GetBlockByHash(blockchain.CurrentBlock().Hash()), 3, ethash.NewFaker(), genDb, 10)

		BadHashes[blocks[2].Header().Hash()] = true
		defer func() { delete(BadHashes, blocks[2].Header().Hash()) }()

		_, err = blockchain.InsertChain(blocks)
	} else {
		headers := makeHeaderChain(blockchain.chainConfig, blockchain.CurrentHeader(), 3, ethash.NewFaker(), genDb, 10)

		BadHashes[headers[2].Hash()] = true
		defer func() { delete(BadHashes, headers[2].Hash()) }()

		_, err = blockchain.InsertHeaderChain(headers, 1)
	}
	if !errors.Is(err, ErrDenylistedHash) {
		t.Errorf("error mismatch: have: %v, want: %v", err, ErrDenylistedHash)
	}
}

// Tests that bad hashes are detected on boot, and the chain rolled back to a
// good state prior to the bad hash.
func TestReorgBadHeaderHashes(t *testing.T) { testReorgBadHashes(t, false) }

// TestReorgBadBlockHashes tests reorg bad block hashes.
func TestReorgBadBlockHashes(t *testing.T) { testReorgBadHashes(t, true) }

func testReorgBadHashes(t *testing.T, full bool) {
	// Create a pristine chain and database
	genDb, gspec, blockchain, err := newCanonical(ethash.NewFaker(), 0, full)
	if err != nil {
		t.Fatalf("failed to create pristine chain: %v", err)
	}
	// Create a chain, import and ban afterwards
	headers := makeHeaderChain(blockchain.chainConfig, blockchain.CurrentHeader(), 4, ethash.NewFaker(), genDb, 10)
	blocks := makeBlockChain(blockchain.chainConfig, blockchain.GetBlockByHash(blockchain.CurrentBlock().Hash()), 4, ethash.NewFaker(), genDb, 10)

	if full {
		if _, err = blockchain.InsertChain(blocks); err != nil {
			t.Errorf("failed to import blocks: %v", err)
		}
		if blockchain.CurrentBlock().Hash() != blocks[3].Hash() {
			t.Errorf("last block hash mismatch: have: %x, want %x", blockchain.CurrentBlock().Hash(), blocks[3].Header().Hash())
		}
		BadHashes[blocks[3].Header().Hash()] = true
		defer func() { delete(BadHashes, blocks[3].Header().Hash()) }()
	} else {
		if _, err = blockchain.InsertHeaderChain(headers, 1); err != nil {
			t.Errorf("failed to import headers: %v", err)
		}
		if blockchain.CurrentHeader().Hash() != headers[3].Hash() {
			t.Errorf("last header hash mismatch: have: %x, want %x", blockchain.CurrentHeader().Hash(), headers[3].Hash())
		}
		BadHashes[headers[3].Hash()] = true
		defer func() { delete(BadHashes, headers[3].Hash()) }()
	}
	blockchain.Stop()

	// Create a new BlockChain and check that it rolled back the state.
	ncm, err := NewBlockChain(blockchain.db, nil, gspec, ethash.NewFaker(), vm.Config{})
	if err != nil {
		t.Fatalf("failed to create new chain manager: %v", err)
	}
	if full {
		if ncm.CurrentBlock().Hash() != blocks[2].Header().Hash() {
			t.Errorf("last block hash mismatch: have: %x, want %x", ncm.CurrentBlock().Hash(), blocks[2].Header().Hash())
		}
		if blocks[2].Header().GasLimit != ncm.GasLimit() {
			t.Errorf("last  block gasLimit mismatch: have: %d, want %d", ncm.GasLimit(), blocks[2].Header().GasLimit)
		}
	} else {
		if ncm.CurrentHeader().Hash() != headers[2].Hash() {
			t.Errorf("last header hash mismatch: have: %x, want %x", ncm.CurrentHeader().Hash(), headers[2].Hash())
		}
	}
	ncm.Stop()
}

// Tests chain insertions in the face of one entity containing an invalid nonce.
func TestHeadersInsertNonceError(t *testing.T) { testInsertNonceError(t, false) }

// TestBlocksInsertNonceError tests blocks insert nonce error.
func TestBlocksInsertNonceError(t *testing.T) { testInsertNonceError(t, true) }

func testInsertNonceError(t *testing.T, full bool) {
	for i := 1; i < 25 && !t.Failed(); i++ {
		// Create a pristine chain and database
		genDb, _, blockchain, err := newCanonical(ethash.NewFaker(), 0, full)
		if err != nil {
			t.Fatalf("failed to create pristine chain: %v", err)
		}
		defer blockchain.Stop()

		// Create and insert a chain with a failing nonce
		var (
			failAt  int
			failRes int
			failNum uint64
		)
		headers := makeHeaderChain(blockchain.chainConfig, blockchain.CurrentHeader(), i, ethash.NewFaker(), genDb, 0)

		failAt = rand.Int() % len(headers)
		failNum = headers[failAt].Number.Uint64()

		blockchain.engine = ethash.NewFakeFailer(failNum)
		blockchain.hc.engine = blockchain.engine
		failRes, _ = blockchain.InsertHeaderChain(headers, 1)
		// Check that the returned error indicates the failure.
		if failRes != failAt {
			t.Errorf("test %d: failure index mismatch: have %d, want %d", i, failRes, failAt)
		}
		// Check that all no blocks after the failing block have been inserted.
		for j := 0; j < i-failAt; j++ {
			if full {
				if block := blockchain.GetBlockByNumber(failNum + uint64(j)); block != nil {
					t.Errorf("test %d: invalid block in chain: %v", i, block)
				}
			} else {
				if header := blockchain.GetHeaderByNumber(failNum + uint64(j)); header != nil {
					t.Errorf("test %d: invalid header in chain: %v", i, header)
				}
			}
		}
	}
}

// Tests that fast importing a block chain produces the same chain data as the
// classical full block processing.
func TestFastVsFullChains(t *testing.T) {
	// Configure and generate a sample block chain
	var (
		key, _  = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		address = crypto.PubkeyToAddress(key.PublicKey)
		funds   = big.NewInt(1000000000000000000)
		gspec   = &Genesis{
			Alloc:   types.GenesisAlloc{address: {Balance: funds}},
			BaseFee: big.NewInt(params.InitialBaseFee),
			Config:  params.TestChainConfig,
		}
		signer = types.LatestSigner(gspec.Config)
	)
	_, blocks, receipts := GenerateChainWithGenesis(gspec, ethash.NewFaker(), 1024, func(i int, block *BlockGen) {
		block.SetCoinbase(common.Address{0x00})

		// If the block number is multiple of 3, send a few bonus transactions to the miner
		if i%3 == 2 {
			for j := 0; j < i%4+1; j++ {
				tx, err := types.SignTx(types.NewTransaction(block.TxNonce(address), common.Address{0x00}, big.NewInt(1000), params.TxGas, block.header.BaseFee, nil), signer, key)
				if err != nil {
					panic(err)
				}
				block.AddTx(tx)
			}
		}
		// If the block number is a multiple of 5, add a few bonus uncles to the block
		if i%5 == 5 {
			block.AddUncle(&types.Header{ParentHash: block.PrevBlock(i - 1).Hash(), Number: big.NewInt(int64(i - 1))})
		}
	})
	// Import the chain as an archive node for the comparison baseline
	archiveDb := rawdb.NewMemoryDatabase()
	archive, _ := NewBlockChain(archiveDb, nil, gspec, ethash.NewFaker(), vm.Config{})
	defer archive.Stop()

	if n, err := archive.InsertChain(blocks); err != nil {
		t.Fatalf("failed to process block %d: %v", n, err)
	}
	// Fast import the chain as a non-archive node to test
	fastDb := rawdb.NewMemoryDatabase()
	fast, _ := NewBlockChain(fastDb, nil, gspec, ethash.NewFaker(), vm.Config{})
	defer fast.Stop()

	headers := make([]*types.Header, len(blocks))
	for i, block := range blocks {
		headers[i] = block.Header()
	}
	if n, err := fast.InsertHeaderChain(headers, 1); err != nil {
		t.Fatalf("failed to insert header %d: %v", n, err)
	}
	if n, err := fast.InsertReceiptChain(blocks, receipts); err != nil {
		t.Fatalf("failed to insert receipt %d: %v", n, err)
	}
	// Iterate over all chain data components, and cross reference
	for i := 0; i < len(blocks); i++ {
		num, hash := blocks[i].NumberU64(), blocks[i].Hash()

		if ftd, atd := fast.GetTdByHash(hash), archive.GetTdByHash(hash); ftd.Cmp(atd) != 0 {
			t.Errorf("block #%d [%x]: td mismatch: have %v, want %v", num, hash, ftd, atd)
		}
		if fheader, aheader := fast.GetHeaderByHash(hash), archive.GetHeaderByHash(hash); fheader.Hash() != aheader.Hash() {
			t.Errorf("block #%d [%x]: header mismatch: have %v, want %v", num, hash, fheader, aheader)
		}
		if fblock, ablock := fast.GetBlockByHash(hash), archive.GetBlockByHash(hash); fblock.Hash() != ablock.Hash() {
			t.Errorf("block #%d [%x]: block mismatch: have %v, want %v", num, hash, fblock, ablock)
		} else if types.DeriveSha(fblock.Transactions(), trie.NewStackTrie(nil)) != types.DeriveSha(ablock.Transactions(), trie.NewStackTrie(nil)) {
			t.Errorf("block #%d [%x]: transactions mismatch: have %v, want %v", num, hash, fblock.Transactions(), ablock.Transactions())
		} else if types.CalcUncleHash(fblock.Uncles()) != types.CalcUncleHash(ablock.Uncles()) {
			t.Errorf("block #%d [%x]: uncles mismatch: have %v, want %v", num, hash, fblock.Uncles(), ablock.Uncles())
		}
		if freceipts, areceipts := rawdb.ReadReceipts(fastDb, hash, *rawdb.ReadHeaderNumber(fastDb, hash), fast.Config()), rawdb.ReadReceipts(archiveDb, hash, *rawdb.ReadHeaderNumber(archiveDb, hash), fast.Config()); types.DeriveSha(freceipts, trie.NewStackTrie(nil)) != types.DeriveSha(areceipts, trie.NewStackTrie(nil)) {
			t.Errorf("block #%d [%x]: receipts mismatch: have %v, want %v", num, hash, freceipts, areceipts)
		}
	}
	// Check that the canonical chains are the same between the databases
	for i := 0; i < len(blocks)+1; i++ {
		if fhash, ahash := rawdb.ReadCanonicalHash(fastDb, uint64(i)), rawdb.ReadCanonicalHash(archiveDb, uint64(i)); fhash != ahash {
			t.Errorf("block #%d: canonical hash mismatch: have %v, want %v", i, fhash, ahash)
		}
	}
}

// Tests that various import methods move the chain head pointers to the correct
// positions.
func TestLightVsFastVsFullChainHeads(t *testing.T) {
	// Configure and generate a sample block chain
	var (
		key, _  = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		address = crypto.PubkeyToAddress(key.PublicKey)
		funds   = big.NewInt(1000000000000000)
		gspec   = &Genesis{
			Alloc:   types.GenesisAlloc{address: {Balance: funds}},
			BaseFee: big.NewInt(params.InitialBaseFee),
			Config:  params.TestChainConfig,
		}
	)
	height := uint64(1024)
	_, blocks, receipts := GenerateChainWithGenesis(gspec, ethash.NewFaker(), int(height), nil)

	// Configure a subchain to roll back
	remove := []common.Hash{}
	for _, block := range blocks[height/2:] {
		remove = append(remove, block.Hash())
	}
	// Create a small assertion method to check the three heads
	assert := func(t *testing.T, kind string, chain *BlockChain, header uint64, fast uint64, block uint64) {
		if num := chain.CurrentBlock().Number.Uint64(); num != block {
			t.Errorf("%s head block mismatch: have #%v, want #%v", kind, num, block)
		}
		if num := chain.CurrentSnapBlock().Number.Uint64(); num != fast {
			t.Errorf("%s head fast-block mismatch: have #%v, want #%v", kind, num, fast)
		}
		if num := chain.CurrentHeader().Number.Uint64(); num != header {
			t.Errorf("%s head header mismatch: have #%v, want #%v", kind, num, header)
		}
	}
	// Import the chain as an archive node and ensure all pointers are updated
	archiveDb := rawdb.NewMemoryDatabase()

	archive, _ := NewBlockChain(archiveDb, nil, gspec, ethash.NewFaker(), vm.Config{})
	if n, err := archive.InsertChain(blocks); err != nil {
		t.Fatalf("failed to process block %d: %v", n, err)
	}
	defer archive.Stop()

	assert(t, "archive", archive, height, height, height)
	archive.Rollback(remove)
	assert(t, "archive", archive, height/2, height/2, height/2)

	// Import the chain as a non-archive node and ensure all pointers are updated
	fastDb := rawdb.NewMemoryDatabase()
	fast, _ := NewBlockChain(fastDb, nil, gspec, ethash.NewFaker(), vm.Config{})
	defer fast.Stop()

	headers := make([]*types.Header, len(blocks))
	for i, block := range blocks {
		headers[i] = block.Header()
	}
	if n, err := fast.InsertHeaderChain(headers, 1); err != nil {
		t.Fatalf("failed to insert header %d: %v", n, err)
	}
	if n, err := fast.InsertReceiptChain(blocks, receipts); err != nil {
		t.Fatalf("failed to insert receipt %d: %v", n, err)
	}
	assert(t, "fast", fast, height, height, 0)
	fast.Rollback(remove)
	assert(t, "fast", fast, height/2, height/2, 0)

	// Import the chain as a light node and ensure all pointers are updated
	lightDb := rawdb.NewMemoryDatabase()
	gspec.MustCommit(lightDb)

	light, _ := NewBlockChain(lightDb, nil, gspec, ethash.NewFaker(), vm.Config{})
	if n, err := light.InsertHeaderChain(headers, 1); err != nil {
		t.Fatalf("failed to insert header %d: %v", n, err)
	}
	defer light.Stop()

	assert(t, "light", light, height, 0, 0)
	light.Rollback(remove)
	assert(t, "light", light, height/2, 0, 0)
}

// Tests that chain reorganisations handle transaction removals and reinsertions.
func TestChainTxReorgs(t *testing.T) {
	var (
		key1, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		key2, _ = crypto.HexToECDSA("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a")
		key3, _ = crypto.HexToECDSA("49a7b37aa6f6645917e7b807e9d1c00d4fa71f18343b0d4122a4d2df64dd6fee")
		addr1   = crypto.PubkeyToAddress(key1.PublicKey)
		addr2   = crypto.PubkeyToAddress(key2.PublicKey)
		addr3   = crypto.PubkeyToAddress(key3.PublicKey)
		gspec   = &Genesis{
			GasLimit: 3141592,
			Alloc: types.GenesisAlloc{
				addr1: {Balance: big.NewInt(1000000000000000)},
				addr2: {Balance: big.NewInt(1000000000000000)},
				addr3: {Balance: big.NewInt(1000000000000000)},
			},
			Config: params.TestChainConfig,
		}
		signer = types.LatestSigner(gspec.Config)
	)

	// Create two transactions shared between the chains:
	//  - postponed: transaction included at a later block in the forked chain
	//  - swapped: transaction included at the same block number in the forked chain
	postponed, _ := types.SignTx(types.NewTransaction(0, addr1, big.NewInt(1000), params.TxGas, big.NewInt(params.InitialBaseFee), nil), signer, key1)
	swapped, _ := types.SignTx(types.NewTransaction(1, addr1, big.NewInt(1000), params.TxGas, big.NewInt(params.InitialBaseFee), nil), signer, key1)

	// Create two transactions that will be dropped by the forked chain:
	//  - pastDrop: transaction dropped retroactively from a past block
	//  - freshDrop: transaction dropped exactly at the block where the reorg is detected
	var pastDrop, freshDrop *types.Transaction

	// Create three transactions that will be added in the forked chain:
	//  - pastAdd:   transaction added before the reorganization is detected
	//  - freshAdd:  transaction added at the exact block the reorg is detected
	//  - futureAdd: transaction added after the reorg has already finished
	var pastAdd, freshAdd, futureAdd *types.Transaction

	_, chain, _ := GenerateChainWithGenesis(gspec, ethash.NewFaker(), 3, func(i int, gen *BlockGen) {
		switch i {
		case 0:
			pastDrop, _ = types.SignTx(types.NewTransaction(gen.TxNonce(addr2), addr2, big.NewInt(1000), params.TxGas, gen.header.BaseFee, nil), signer, key2)

			gen.AddTx(pastDrop)  // This transaction will be dropped in the fork from below the split point
			gen.AddTx(postponed) // This transaction will be postponed till block #3 in the fork

		case 2:
			freshDrop, _ = types.SignTx(types.NewTransaction(gen.TxNonce(addr2), addr2, big.NewInt(1000), params.TxGas, gen.header.BaseFee, nil), signer, key2)

			gen.AddTx(freshDrop) // This transaction will be dropped in the fork from exactly at the split point
			gen.AddTx(swapped)   // This transaction will be swapped out at the exact height

			gen.OffsetTime(9) // Lower the block difficulty to simulate a weaker chain
		}
	})
	// Import the chain. This runs all block validation rules.
	db := rawdb.NewMemoryDatabase()
	blockchain, _ := NewBlockChain(db, nil, gspec, ethash.NewFaker(), vm.Config{})
	if i, err := blockchain.InsertChain(chain); err != nil {
		t.Fatalf("failed to insert original chain[%d]: %v", i, err)
	}
	defer blockchain.Stop()

	// overwrite the old chain
	_, chain, _ = GenerateChainWithGenesis(gspec, ethash.NewFaker(), 5, func(i int, gen *BlockGen) {
		switch i {
		case 0:
			pastAdd, _ = types.SignTx(types.NewTransaction(gen.TxNonce(addr3), addr3, big.NewInt(1000), params.TxGas, gen.header.BaseFee, nil), signer, key3)
			gen.AddTx(pastAdd) // This transaction needs to be injected during reorg

		case 2:
			gen.AddTx(postponed) // This transaction was postponed from block #1 in the original chain
			gen.AddTx(swapped)   // This transaction was swapped from the exact current spot in the original chain

			freshAdd, _ = types.SignTx(types.NewTransaction(gen.TxNonce(addr3), addr3, big.NewInt(1000), params.TxGas, gen.header.BaseFee, nil), signer, key3)
			gen.AddTx(freshAdd) // This transaction will be added exactly at reorg time

		case 3:
			futureAdd, _ = types.SignTx(types.NewTransaction(gen.TxNonce(addr3), addr3, big.NewInt(1000), params.TxGas, gen.header.BaseFee, nil), signer, key3)
			gen.AddTx(futureAdd) // This transaction will be added after a full reorg
		}
	})
	if _, err := blockchain.InsertChain(chain); err != nil {
		t.Fatalf("failed to insert forked chain: %v", err)
	}

	// removed tx
	for i, tx := range (types.Transactions{pastDrop, freshDrop}) {
		if txn, _, _, _ := rawdb.ReadTransaction(db, tx.Hash()); txn != nil {
			t.Errorf("drop %d: tx %v found while shouldn't have been", i, txn)
		}
		if rcpt, _, _, _ := rawdb.ReadReceipt(db, tx.Hash(), blockchain.Config()); rcpt != nil {
			t.Errorf("drop %d: receipt %v found while shouldn't have been", i, rcpt)
		}
	}
	// added tx
	for i, tx := range (types.Transactions{pastAdd, freshAdd, futureAdd}) {
		if txn, _, _, _ := rawdb.ReadTransaction(db, tx.Hash()); txn == nil {
			t.Errorf("add %d: expected tx to be found", i)
		}
		if rcpt, _, _, _ := rawdb.ReadReceipt(db, tx.Hash(), blockchain.Config()); rcpt == nil {
			t.Errorf("add %d: expected receipt to be found", i)
		}
	}
	// shared tx
	for i, tx := range (types.Transactions{postponed, swapped}) {
		if txn, _, _, _ := rawdb.ReadTransaction(db, tx.Hash()); txn == nil {
			t.Errorf("share %d: expected tx to be found", i)
		}
		if rcpt, _, _, _ := rawdb.ReadReceipt(db, tx.Hash(), blockchain.Config()); rcpt == nil {
			t.Errorf("share %d: expected receipt to be found", i)
		}
	}
}

// TestLogReorgs tests log reorgs.
func TestLogReorgs(t *testing.T) {
	var (
		key1, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		addr1   = crypto.PubkeyToAddress(key1.PublicKey)

		// this code generates a log
		code  = common.Hex2Bytes("60606040525b7f24ec1d3ff24c2f6ff210738839dbc339cd45a5294d85c79361016243157aae7b60405180905060405180910390a15b600a8060416000396000f360606040526008565b00")
		gspec = &Genesis{
			Alloc:  types.GenesisAlloc{addr1: {Balance: big.NewInt(100000000000000000)}},
			Config: params.TestChainConfig,
		}
		signer = types.LatestSigner(gspec.Config)
	)

	blockchain, _ := NewBlockChain(rawdb.NewMemoryDatabase(), nil, gspec, ethash.NewFaker(), vm.Config{})
	defer blockchain.Stop()

	rmLogsCh := make(chan RemovedLogsEvent)
	blockchain.SubscribeRemovedLogsEvent(rmLogsCh)
	_, chain, _ := GenerateChainWithGenesis(gspec, ethash.NewFaker(), 2, func(i int, gen *BlockGen) {
		if i == 1 {
			tx, err := types.SignTx(types.NewContractCreation(gen.TxNonce(addr1), new(big.Int), 1000000, gen.header.BaseFee, code), signer, key1)
			if err != nil {
				t.Fatalf("failed to create tx: %v", err)
			}
			gen.AddTx(tx)
		}
	})
	if _, err := blockchain.InsertChain(chain); err != nil {
		t.Fatalf("failed to insert chain: %v", err)
	}

	_, chain, _ = GenerateChainWithGenesis(gspec, ethash.NewFaker(), 3, func(i int, gen *BlockGen) {})
	// Removed logs are delivered synchronously, so the subscriber has to be ready
	// before the reorg runs instead of draining the channel afterwards.
	done := make(chan struct{})
	go func() {
		ev := <-rmLogsCh
		if len(ev.Logs) == 0 {
			t.Error("expected logs")
		}
		close(done)
	}()
	if _, err := blockchain.InsertChain(chain); err != nil {
		t.Fatalf("failed to insert forked chain: %v", err)
	}

	timeout := time.NewTimer(1 * time.Second)
	defer timeout.Stop()
	select {
	case <-done:
	case <-timeout.C:
		t.Fatal("Timeout. There is no RemovedLogsEvent has been sent.")
	}
}

// Tests if the canonical block can be fetched from the database during chain insertion.
func TestCanonicalBlockRetrieval(t *testing.T) {
	_, gspec, blockchain, err := newCanonical(ethash.NewFaker(), 0, true)
	if err != nil {
		t.Fatalf("failed to create pristine chain: %v", err)
	}
	defer blockchain.Stop()

	_, chain, _ := GenerateChainWithGenesis(gspec, ethash.NewFaker(), 10, func(i int, gen *BlockGen) {})

	var pend sync.WaitGroup
	pend.Add(len(chain))

	for i := range chain {
		go func(block *types.Block) {
			defer pend.Done()

			// try to retrieve a block by its canonical hash and see if the block data can be retrieved.
			for {
				ch := rawdb.ReadCanonicalHash(blockchain.db, block.NumberU64())
				if ch == (common.Hash{}) {
					continue // busy wait for canonical hash to be written
				}
				if ch != block.Hash() {
					t.Errorf("unknown canonical hash, want %s, got %s", block.Hash().Hex(), ch.Hex())
					return
				}
				fb := rawdb.ReadBlock(blockchain.db, ch, block.NumberU64())
				if fb == nil {
					t.Errorf("unable to retrieve block %d for canonical hash: %s", block.NumberU64(), ch.Hex())
					return
				}
				if fb.Hash() != block.Hash() {
					t.Errorf("invalid block hash for block %d, want %s, got %s", block.NumberU64(), block.Hash().Hex(), fb.Hash().Hex())
					return
				}
				return
			}
		}(chain[i])

		if _, err := blockchain.InsertChain(types.Blocks{chain[i]}); err != nil {
			t.Fatalf("failed to insert block %d: %v", i, err)
		}
	}
	pend.Wait()
}

// TestEIP155Transition tests eip 155 transition.
func TestEIP155Transition(t *testing.T) {
	// Configure and generate a sample block chain
	var (
		key, _     = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		address    = crypto.PubkeyToAddress(key.PublicKey)
		funds      = big.NewInt(1000000000)
		deleteAddr = common.Address{1}
		futureFork = big.NewInt(1_000_000_000)
		gspec      = &Genesis{
			Config: &params.ChainConfig{
				ChainID:          big.NewInt(1337),
				EIP150Block:      big.NewInt(0),
				EIP155Block:      big.NewInt(2),
				EIP158Block:      big.NewInt(2),
				ByzantiumBlock:   new(big.Int).Set(futureFork),
				HomesteadBlock:   new(big.Int),
				TIPTRC21FeeBlock: new(big.Int),
				BerlinBlock:      new(big.Int).Set(futureFork),
				LondonBlock:      new(big.Int).Set(futureFork),
				MergeBlock:       new(big.Int).Set(futureFork),
				ShanghaiBlock:    new(big.Int).Set(futureFork),
				EIP1559Block:     new(big.Int).Set(futureFork),
				CancunBlock:      new(big.Int).Set(futureFork),
				PragueBlock:      new(big.Int).Set(futureFork),
				OsakaBlock:       new(big.Int).Set(futureFork),
			},
			Alloc: types.GenesisAlloc{address: {Balance: funds}, deleteAddr: {Balance: new(big.Int)}},
		}
	)
	setXinFinForksToFuture(gspec.Config, futureFork)
	gspec.Config.TIP2019Block = new(big.Int)
	var err error
	gspec.Config, err = resolveProvidedChainConfig(common.Hash{}, gspec.Config, builtInChainConfigMustMatch)
	if err != nil {
		t.Fatal(err)
	}
	genDb, blocks, _ := GenerateChainWithGenesis(gspec, ethash.NewFaker(), 4, func(i int, block *BlockGen) {
		var (
			tx      *types.Transaction
			err     error
			basicTx = func(signer types.Signer) (*types.Transaction, error) {
				return types.SignTx(types.NewTransaction(block.TxNonce(address), common.Address{}, new(big.Int), 21000, new(big.Int), nil), signer, key)
			}
		)
		switch i {
		case 0:
			tx, err = basicTx(types.HomesteadSigner{})
			if err != nil {
				t.Fatal(err)
			}
			block.AddTx(tx)
		case 2:
			tx, err = basicTx(types.HomesteadSigner{})
			if err != nil {
				t.Fatal(err)
			}
			block.AddTx(tx)

			tx, err = basicTx(types.LatestSigner(gspec.Config))
			if err != nil {
				t.Fatal(err)
			}
			block.AddTx(tx)
		case 3:
			tx, err = basicTx(types.HomesteadSigner{})
			if err != nil {
				t.Fatal(err)
			}
			block.AddTx(tx)

			tx, err = basicTx(types.LatestSigner(gspec.Config))
			if err != nil {
				t.Fatal(err)
			}
			block.AddTx(tx)
		}
	})

	blockchain, _ := NewBlockChain(rawdb.NewMemoryDatabase(), nil, gspec, ethash.NewFaker(), vm.Config{})
	defer blockchain.Stop()

	if _, err := blockchain.InsertChain(blocks); err != nil {
		t.Fatal(err)
	}
	block := blockchain.GetBlockByNumber(1)
	if block.Transactions()[0].Protected() {
		t.Error("Expected block[0].txs[0] to not be replay protected")
	}

	block = blockchain.GetBlockByNumber(3)
	if block.Transactions()[0].Protected() {
		t.Error("Expected block[3].txs[0] to not be replay protected")
	}
	if !block.Transactions()[1].Protected() {
		t.Error("Expected block[3].txs[1] to be replay protected")
	}
	if _, err := blockchain.InsertChain(blocks[4:]); err != nil {
		t.Fatal(err)
	}

	// generate an invalid chain id transaction
	config := &params.ChainConfig{
		ChainID:          big.NewInt(1338),
		EIP150Block:      big.NewInt(0),
		EIP155Block:      big.NewInt(2),
		HomesteadBlock:   new(big.Int),
		TIPTRC21FeeBlock: new(big.Int),
	}
	setXinFinForksToFuture(config, futureFork)
	config, err = resolveProvidedChainConfig(common.Hash{}, config, builtInChainConfigMustMatch)
	if err != nil {
		t.Fatal(err)
	}
	blocks, _ = GenerateChain(config, blocks[len(blocks)-1], ethash.NewFaker(), genDb, 4, func(i int, block *BlockGen) {
		var (
			tx      *types.Transaction
			err     error
			basicTx = func(signer types.Signer) (*types.Transaction, error) {
				return types.SignTx(types.NewTransaction(block.TxNonce(address), common.Address{}, new(big.Int), 21000, new(big.Int), nil), signer, key)
			}
		)
		if i == 0 {
			tx, err = basicTx(types.LatestSigner(config))
			if err != nil {
				t.Fatal(err)
			}
			block.AddTx(tx)
		}
	})
	_, err = blockchain.InsertChain(blocks)
	if have, want := err, types.ErrInvalidChainId; !errors.Is(have, want) {
		t.Errorf("have %v, want %v", have, want)
	}
}

// TestEIP161AccountRemoval tests eip 161 account removal.
func TestEIP161AccountRemoval(t *testing.T) {
	// Configure and generate a sample block chain
	var (
		key, _     = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		address    = crypto.PubkeyToAddress(key.PublicKey)
		funds      = big.NewInt(1000000000)
		theAddr    = common.Address{1}
		futureFork = big.NewInt(1_000_000_000)
		gspec      = &Genesis{
			Config: &params.ChainConfig{
				ChainID:          big.NewInt(1337),
				HomesteadBlock:   new(big.Int),
				EIP155Block:      new(big.Int),
				EIP158Block:      big.NewInt(2),
				ByzantiumBlock:   new(big.Int).Set(futureFork),
				TIPTRC21FeeBlock: new(big.Int),
				BerlinBlock:      new(big.Int).Set(futureFork),
				LondonBlock:      new(big.Int).Set(futureFork),
				MergeBlock:       new(big.Int).Set(futureFork),
				ShanghaiBlock:    new(big.Int).Set(futureFork),
				EIP1559Block:     new(big.Int).Set(futureFork),
				CancunBlock:      new(big.Int).Set(futureFork),
				PragueBlock:      new(big.Int).Set(futureFork),
				OsakaBlock:       new(big.Int).Set(futureFork),
			},
			Alloc: types.GenesisAlloc{address: {Balance: funds}},
		}
	)
	setXinFinForksToFuture(gspec.Config, futureFork)
	var err error
	gspec.Config, err = resolveProvidedChainConfig(common.Hash{}, gspec.Config, builtInChainConfigMustMatch)
	if err != nil {
		t.Fatal(err)
	}
	_, blocks, _ := GenerateChainWithGenesis(gspec, ethash.NewFaker(), 3, func(i int, block *BlockGen) {
		var (
			tx     *types.Transaction
			err    error
			signer = types.LatestSigner(gspec.Config)
		)
		switch i {
		case 0:
			tx, err = types.SignTx(types.NewTransaction(block.TxNonce(address), theAddr, new(big.Int), 21000, new(big.Int), nil), signer, key)
		case 1:
			tx, err = types.SignTx(types.NewTransaction(block.TxNonce(address), theAddr, new(big.Int), 21000, new(big.Int), nil), signer, key)
		case 2:
			tx, err = types.SignTx(types.NewTransaction(block.TxNonce(address), theAddr, new(big.Int), 21000, new(big.Int), nil), signer, key)
		}
		if err != nil {
			t.Fatal(err)
		}
		block.AddTx(tx)
	})
	// As in upstream geth, zero-value sends retain empty recipients before the
	// EIP-161 transition point and prune them once EIP-158 becomes active.
	blockchain, _ := NewBlockChain(rawdb.NewMemoryDatabase(), nil, gspec, ethash.NewFaker(), vm.Config{})
	defer blockchain.Stop()

	if _, err := blockchain.InsertChain(types.Blocks{blocks[0]}); err != nil {
		t.Fatal(err)
	}
	if st, _ := blockchain.State(); !st.Exist(theAddr) {
		t.Error("expected account to exist")
	}

	// account needs to be deleted post eip 161
	if _, err := blockchain.InsertChain(types.Blocks{blocks[1]}); err != nil {
		t.Fatal(err)
	}
	if st, _ := blockchain.State(); st.Exist(theAddr) {
		t.Error("account should not exist")
	}

	// account mustn't be created post eip 161
	if _, err := blockchain.InsertChain(types.Blocks{blocks[2]}); err != nil {
		t.Fatal(err)
	}
	if st, _ := blockchain.State(); st.Exist(theAddr) {
		t.Error("account should not exist")
	}
}

// setXinFinForksToFuture moves XDC-specific forks behind a common future block
// for tests that need pre-fork execution rules.
func setXinFinForksToFuture(cfg *params.ChainConfig, future *big.Int) {
	set := func() *big.Int { return new(big.Int).Set(future) }
	cfg.TIPSigningBlock = set()
	cfg.TIPRandomizeBlock = set()
	cfg.TIPIncreaseMasternodesBlock = set()
	cfg.DenylistBlock = set()
	cfg.TIPNoHalvingMNRewardBlock = set()
	cfg.TIPXDCXBlock = set()
	cfg.TIPXDCXLendingBlock = set()
	cfg.TIPXDCXCancellationFeeBlock = set()
	cfg.TIPTRC21FeeBlock = set()
	cfg.Gas50xBlock = set()
	cfg.BerlinBlock = set()
	cfg.LondonBlock = set()
	cfg.MergeBlock = set()
	cfg.ShanghaiBlock = set()
	cfg.TIPXDCXMinerDisableBlock = set()
	cfg.TIPXDCXReceiverDisableBlock = set()
	cfg.EIP1559Block = set()
	cfg.CancunBlock = set()
	cfg.PragueBlock = set()
	cfg.OsakaBlock = set()
	cfg.DynamicGasLimitBlock = set()
	cfg.TIPUpgradeRewardBlock = set()
	cfg.TIPUpgradePenaltyBlock = set()
	cfg.TIPEpochHalvingBlock = set()
	cfg.TRC21IssuerSMC = params.TestnetChainConfig.TRC21IssuerSMC
	cfg.XDCXListingSMC = params.TestnetChainConfig.XDCXListingSMC
	cfg.RelayerRegistrationSMC = params.TestnetChainConfig.RelayerRegistrationSMC
	cfg.LendingRegistrationSMC = params.TestnetChainConfig.LendingRegistrationSMC
}

// This is a regression test (i.e. as weird as it is, don't delete it ever), which
// tests that under weird reorg conditions the blockchain and its internal header-
// chain return the same latest block/header.
//
// https://github.com/XinFinOrg/XDPoSChain/pull/15941how Source Control
func TestBlockchainHeaderchainReorgConsistency(t *testing.T) {
	// Generate a canonical chain to act as the main dataset
	engine := ethash.NewFaker()
	genesis := &Genesis{
		BaseFee: big.NewInt(params.InitialBaseFee),
		Config:  params.TestChainConfig,
	}
	genDb, blocks, _ := GenerateChainWithGenesis(genesis, engine, 64, func(i int, b *BlockGen) { b.SetCoinbase(common.Address{1}) })

	// Generate a bunch of fork blocks, each side forking from the canonical chain
	forks := make([]*types.Block, len(blocks))
	for i := 0; i < len(forks); i++ {
		parent := genesis.ToBlock()
		if i > 0 {
			parent = blocks[i-1]
		}
		fork, _ := GenerateChain(genesis.Config, parent, engine, genDb, 1, func(i int, b *BlockGen) { b.SetCoinbase(common.Address{2}) })
		forks[i] = fork[0]
	}
	// Import the canonical and fork chain side by side, verifying the current block
	// and current header consistency
	chain, err := NewBlockChain(rawdb.NewMemoryDatabase(), nil, genesis, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create tester chain: %v", err)
	}
	for i := 0; i < len(blocks); i++ {
		if _, err := chain.InsertChain(blocks[i : i+1]); err != nil {
			t.Fatalf("block %d: failed to insert into chain: %v", i, err)
		}
		if chain.CurrentBlock().Hash() != chain.CurrentHeader().Hash() {
			t.Errorf("block %d: current block/header mismatch: block #%d [%x..], header #%d [%x..]", i, chain.CurrentBlock().Number, chain.CurrentBlock().Hash().Bytes()[:4], chain.CurrentHeader().Number, chain.CurrentHeader().Hash().Bytes()[:4])
		}
		if _, err := chain.InsertChain(forks[i : i+1]); err != nil {
			t.Fatalf(" fork %d: failed to insert into chain: %v", i, err)
		}
		if chain.CurrentBlock().Hash() != chain.CurrentHeader().Hash() {
			t.Errorf(" fork %d: current block/header mismatch: block #%d [%x..], header #%d [%x..]", i, chain.CurrentBlock().Number, chain.CurrentBlock().Hash().Bytes()[:4], chain.CurrentHeader().Number, chain.CurrentHeader().Hash().Bytes()[:4])
		}
	}
}

// Tests that importing small side forks doesn't leave junk in the trie database
// cache (which would eventually cause memory issues).
func TestTrieForkGC(t *testing.T) {
	// Generate a canonical chain to act as the main dataset
	engine := ethash.NewFaker()
	genesis := &Genesis{
		BaseFee: big.NewInt(params.InitialBaseFee),
		Config:  params.TestChainConfig,
	}
	genDb, blocks, _ := GenerateChainWithGenesis(genesis, engine, 2*TriesInMemory, func(i int, b *BlockGen) { b.SetCoinbase(common.Address{1}) })

	// Generate a bunch of fork blocks, each side forking from the canonical chain
	forks := make([]*types.Block, len(blocks))
	for i := 0; i < len(forks); i++ {
		parent := genesis.ToBlock()
		if i > 0 {
			parent = blocks[i-1]
		}
		fork, _ := GenerateChain(genesis.Config, parent, engine, genDb, 1, func(i int, b *BlockGen) { b.SetCoinbase(common.Address{2}) })
		forks[i] = fork[0]
	}
	// Import the canonical and fork chain side by side, forcing the trie cache to cache both
	chain, err := NewBlockChain(rawdb.NewMemoryDatabase(), nil, genesis, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create tester chain: %v", err)
	}
	defer chain.Stop()

	for i := 0; i < len(blocks); i++ {
		if _, err := chain.InsertChain(blocks[i : i+1]); err != nil {
			t.Fatalf("block %d: failed to insert into chain: %v", i, err)
		}
		if _, err := chain.InsertChain(forks[i : i+1]); err != nil {
			t.Fatalf("fork %d: failed to insert into chain: %v", i, err)
		}
	}
	// Dereference all the recent tries and ensure no past trie is left in
	for i := 0; i < TriesInMemory; i++ {
		chain.stateCache.TrieDB().Dereference(blocks[len(blocks)-1-i].Root())
		chain.stateCache.TrieDB().Dereference(forks[len(blocks)-1-i].Root())
	}
	if nodes, _ := chain.TrieDB().Size(); nodes > 0 {
		t.Fatalf("stale tries still alive after garbase collection")
	}
}

// Tests that doing large reorgs works even if the state associated with the
// forking point is not available any more.
func TestLargeReorgTrieGC(t *testing.T) {
	// Generate the original common chain segment and the two competing forks
	engine := ethash.NewFaker()
	genesis := &Genesis{
		BaseFee: big.NewInt(params.InitialBaseFee),
		Config:  params.TestChainConfig,
	}
	genDb, shared, _ := GenerateChainWithGenesis(genesis, engine, 64, func(i int, b *BlockGen) { b.SetCoinbase(common.Address{1}) })
	original, _ := GenerateChain(genesis.Config, shared[len(shared)-1], engine, genDb, 2*TriesInMemory, func(i int, b *BlockGen) { b.SetCoinbase(common.Address{2}) })
	competitor, _ := GenerateChain(genesis.Config, shared[len(shared)-1], engine, genDb, 2*TriesInMemory+1, func(i int, b *BlockGen) { b.SetCoinbase(common.Address{3}) })

	// Import the shared chain and the original canonical one
	chain, err := NewBlockChain(rawdb.NewMemoryDatabase(), nil, genesis, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create tester chain: %v", err)
	}
	defer chain.Stop()

	if _, err := chain.InsertChain(shared); err != nil {
		t.Fatalf("failed to insert shared chain: %v", err)
	}
	if _, err := chain.InsertChain(original); err != nil {
		t.Fatalf("failed to insert shared chain: %v", err)
	}
	// Ensure that the state associated with the forking point is pruned away
	if node, _ := chain.stateCache.TrieDB().Node(shared[len(shared)-1].Root()); node != nil {
		t.Fatalf("common-but-old ancestor still cache")
	}
	// Import the competitor chain without exceeding the canonical's TD and ensure
	// we have not processed any of the blocks (protection against malicious blocks)
	if _, err := chain.InsertChain(competitor[:len(competitor)-2]); err != nil {
		t.Fatalf("failed to insert competitor chain: %v", err)
	}
	for i, block := range competitor[:len(competitor)-2] {
		if node, _ := chain.stateCache.TrieDB().Node(block.Root()); node != nil {
			t.Fatalf("competitor %d: low TD chain became processed", i)
		}
	}
	// Import the head of the competitor chain, triggering the reorg and ensure we
	// successfully reprocess all the stashed away blocks.
	if _, err := chain.InsertChain(competitor[len(competitor)-2:]); err != nil {
		t.Fatalf("failed to finalize competitor chain: %v", err)
	}
	for i, block := range competitor[:len(competitor)-TriesInMemory] {
		if node, _ := chain.stateCache.TrieDB().Node(block.Root()); node != nil {
			t.Fatalf("competitor %d: competing chain state missing", i)
		}
	}
}

// Benchmarks large blocks with value transfers to non-existing accounts
func benchmarkLargeNumberOfValueToNonexisting(b *testing.B, numTxs, numBlocks int, recipientFn func(uint64) common.Address, dataFn func(uint64) []byte) {
	var (
		signer          = types.HomesteadSigner{}
		testBankKey, _  = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		testBankAddress = crypto.PubkeyToAddress(testBankKey.PublicKey)
		bankFunds       = big.NewInt(100000000000000000)
		gspec           = &Genesis{
			Alloc: GenesisAlloc{
				testBankAddress: {Balance: bankFunds},
				common.HexToAddress("0xc0de"): {
					Code:    []byte{0x60, 0x01, 0x50},
					Balance: big.NewInt(0),
				}, // push 1, pop
			},
			Config:   params.TestChainConfig,
			GasLimit: 100e6, // 100 M
		}
	)
	// Generate the original common chain segment and the two competing forks
	engine := ethash.NewFaker()

	blockGenerator := func(i int, block *BlockGen) {
		block.SetCoinbase(common.Address{1})
		for txi := 0; txi < numTxs; txi++ {
			uniq := uint64(i*numTxs + txi)
			recipient := recipientFn(uniq)
			//recipient := common.BigToAddress(big.NewInt(0).SetUint64(1337 + uniq))
			tx, err := types.SignTx(types.NewTransaction(uniq, recipient, big.NewInt(1), params.TxGas, big.NewInt(1), nil), signer, testBankKey)
			if err != nil {
				b.Error(err)
			}
			block.AddTx(tx)
		}
	}

	_, shared, _ := GenerateChainWithGenesis(gspec, engine, numBlocks, blockGenerator)
	b.StopTimer()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Import the shared chain and the original canonical one
		chain, err := NewBlockChain(rawdb.NewMemoryDatabase(), nil, gspec, engine, vm.Config{})
		if err != nil {
			b.Fatalf("failed to create tester chain: %v", err)
		}
		b.StartTimer()
		if _, err := chain.InsertChain(shared); err != nil {
			b.Fatalf("failed to insert shared chain: %v", err)
		}
		b.StopTimer()
		block := chain.GetBlockByHash(chain.CurrentBlock().Hash())
		if got := block.Transactions().Len(); got != numTxs*numBlocks {
			b.Fatalf("Transactions were not included, expected %d, got %d", (numTxs * numBlocks), got)
		}
	}
}

// BenchmarkBlockChain_1x1000ValueTransferToNonexisting benchmarks block chain 1 x 1000 value transfer to nonexisting.
func BenchmarkBlockChain_1x1000ValueTransferToNonexisting(b *testing.B) {
	var (
		numTxs    = 1000
		numBlocks = 1
	)

	recipientFn := func(nonce uint64) common.Address {
		return common.BigToAddress(big.NewInt(0).SetUint64(1337 + nonce))
	}
	dataFn := func(nonce uint64) []byte {
		return nil
	}

	benchmarkLargeNumberOfValueToNonexisting(b, numTxs, numBlocks, recipientFn, dataFn)
}

// BenchmarkBlockChain_1x1000ValueTransferToExisting benchmarks block chain 1 x 1000 value transfer to existing.
func BenchmarkBlockChain_1x1000ValueTransferToExisting(b *testing.B) {
	var (
		numTxs    = 1000
		numBlocks = 1
	)
	b.StopTimer()
	b.ResetTimer()

	recipientFn := func(nonce uint64) common.Address {
		return common.BigToAddress(big.NewInt(0).SetUint64(1337))
	}
	dataFn := func(nonce uint64) []byte {
		return nil
	}

	benchmarkLargeNumberOfValueToNonexisting(b, numTxs, numBlocks, recipientFn, dataFn)
}

// BenchmarkBlockChain_1x1000Executions benchmarks block chain 1 x 1000 executions.
func BenchmarkBlockChain_1x1000Executions(b *testing.B) {
	var (
		numTxs    = 1000
		numBlocks = 1
	)
	b.StopTimer()
	b.ResetTimer()

	recipientFn := func(nonce uint64) common.Address {
		return common.BigToAddress(big.NewInt(0).SetUint64(0xc0de))
	}
	dataFn := func(nonce uint64) []byte {
		return nil
	}

	benchmarkLargeNumberOfValueToNonexisting(b, numTxs, numBlocks, recipientFn, dataFn)
}

/*
Collection test for BlocksHashCache
cases
 1. When init new chain
 2. when insertChain
 3. when insertFork
 4. When adding new block by mining
 5. When adding new block by syncing with other nodes
*/
// TestBlocksHashCacheUpdate tests blocks hash cache update.
func TestBlocksHashCacheUpdate(t *testing.T) {
	_, _, chain, err := newCanonical(ethash.NewFaker(), 0, true)
	if err != nil {
		t.Fatalf("failed to make new canonical chain: %v", err)
	}
	defer chain.Stop()

	t.Run("Expect BlocksHashCache blank after initialized", func(t *testing.T) {
		if len(chain.blocksHashCache.Keys()) != 0 {
			t.Error("BlocksHashCache is not initialized correctly ")
		}
	})

	t.Run("Expect BlocksHashCache has 4 cached keys after concat a 4-length-chain", func(t *testing.T) {
		concatedChain := makeBlockChain(chain.chainConfig, chain.GetBlockByHash(chain.CurrentBlock().Hash()), 4, ethash.NewFullFaker(), chain.db, 0)
		if _, err := chain.InsertChain(concatedChain); err != nil {
			t.Fatalf("failed to insert shared chain: %v", err)
		}

		if len(chain.blocksHashCache.Keys()) != 4 {
			t.Error("BlocksHashCache doesn't add new cache after concating new chain ")
		}
	})

	t.Run("Expect BlocksHashCache caches work for fork case", func(t *testing.T) {
		concatedChain := makeBlockChain(chain.chainConfig, chain.GetBlockByNumber(uint64(2)), 3, ethash.NewFullFaker(), chain.db, 3)
		if _, err := chain.InsertChain(concatedChain); err != nil {
			t.Fatalf("failed to insert forked chain: %v", err)
		}
		cachedAt, _ := chain.blocksHashCache.Get(uint64(3))

		if len(cachedAt) != 2 {
			t.Error("BlocksHashCache doesn't add new cache after concating new fork ")
		}
	})

	t.Run("Expect BlocksHashCache caches when inserting block on syncing", func(t *testing.T) {
		currentCachedLength := len(chain.blocksHashCache.Keys())
		singleBlockChain := makeBlockChain(chain.chainConfig, chain.GetBlockByHash(chain.CurrentBlock().Hash()), 1, ethash.NewFaker(), chain.db, 0)
		chain.insertBlock(singleBlockChain[0])

		if len(chain.blocksHashCache.Keys()) != currentCachedLength+1 {
			t.Error("BlocksHashCache doesn't work when inserting block solely")
		}
	})

	t.Run("Expect repeated cache update to keep one entry per hash", func(t *testing.T) {
		head := chain.CurrentBlock()
		chain.UpdateBlocksHashCache(types.NewBlockWithHeader(head))
		chain.UpdateBlocksHashCache(types.NewBlockWithHeader(head))
		cached, _ := chain.blocksHashCache.Get(head.Number.Uint64())
		count := 0
		for _, hash := range cached {
			if hash == head.Hash() {
				count++
			}
		}
		if count != 1 {
			t.Errorf("BlocksHashCache has %d entries for head hash, want 1: %v", count, cached)
		}
	})
}

// TestAreTwoBlocksSamePath tests are two blocks same path.
func TestAreTwoBlocksSamePath(t *testing.T) {
	genDb, _, chain, err := newCanonical(ethash.NewFaker(), 10, true)
	if err != nil {
		t.Fatalf("failed to make new canonical chain: %v", err)
	}
	defer chain.Stop()

	t.Run("Expect return true with two canonical blocks", func(t *testing.T) {
		if !chain.AreTwoBlockSamePath(chain.CurrentBlock().Hash(), chain.GetBlockByNumber(uint64(2)).Hash()) {
			t.Error("Failed")
		}
	})

	t.Run("Expect return fail with canonical-fork paths", func(t *testing.T) {
		concatedChain := makeBlockChain(chain.chainConfig, chain.GetBlockByNumber(uint64(2)), 3, ethash.NewFullFaker(), genDb, 3)
		if _, err := chain.InsertChain(concatedChain); err != nil {
			t.Fatalf("failed to insert forked chain: %v", err)
		}
		if chain.AreTwoBlockSamePath(concatedChain[len(concatedChain)-1].Hash(), chain.GetBlockByNumber(uint64(3)).Hash()) {
			t.Error("Failed")
		}
	})
}

// TestEIP2718Transition tests that an EIP-2718 transaction will be accepted
// after the fork block has passed. This is verified by sending an EIP-2930
// access list transaction, which specifies a single slot access, and then
// checking that the gas usage of a hot SLOAD and a cold SLOAD are calculated
// correctly.
func TestEIP2718Transition(t *testing.T) {
	var (
		aa     = common.HexToAddress("0x000000000000000000000000000000000000aaaa")
		engine = ethash.NewFaker()

		// A sender who makes transactions, has some funds
		key, _  = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		address = crypto.PubkeyToAddress(key.PublicKey)
		funds   = big.NewInt(1000000000000000)
		gspec   = &Genesis{
			Config: &params.ChainConfig{
				ChainID:                big.NewInt(1337),
				HomesteadBlock:         big.NewInt(0),
				DAOForkBlock:           nil,
				DAOForkSupport:         true,
				EIP150Block:            big.NewInt(0),
				EIP155Block:            big.NewInt(0),
				EIP158Block:            big.NewInt(0),
				ByzantiumBlock:         big.NewInt(0),
				ConstantinopleBlock:    big.NewInt(0),
				PetersburgBlock:        big.NewInt(0),
				IstanbulBlock:          big.NewInt(0),
				TIPTRC21FeeBlock:       big.NewInt(0),
				Gas50xBlock:            big.NewInt(0),
				TRC21IssuerSMC:         params.TestnetChainConfig.TRC21IssuerSMC,
				XDCXListingSMC:         params.TestnetChainConfig.XDCXListingSMC,
				RelayerRegistrationSMC: params.TestnetChainConfig.RelayerRegistrationSMC,
				LendingRegistrationSMC: params.TestnetChainConfig.LendingRegistrationSMC,
				EIP1559Block:           big.NewInt(0),
			},
			Alloc: types.GenesisAlloc{
				address: {Balance: funds},
				// The address 0xAAAA sloads 0x00 and 0x01
				aa: {
					Code: []byte{
						byte(vm.PC),
						byte(vm.PC),
						byte(vm.SLOAD),
						byte(vm.SLOAD),
					},
					Nonce:   0,
					Balance: big.NewInt(50000000000),
				},
			},
			ExtraData: hexutil.MustDecode("0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
		}
	)
	// Generate blocks
	_, blocks, _ := GenerateChainWithGenesis(gspec, engine, 1, func(i int, b *BlockGen) {
		b.SetCoinbase(common.Address{1})

		// One transaction to 0xAAAA
		signer := types.LatestSigner(gspec.Config)
		tx, _ := types.SignNewTx(key, signer, &types.AccessListTx{
			ChainID:  gspec.Config.ChainID,
			Nonce:    0,
			To:       &aa,
			Gas:      30000,
			GasPrice: b.header.BaseFee,
			AccessList: types.AccessList{{
				Address:     aa,
				StorageKeys: []common.Hash{{0}},
			}},
		})
		b.AddTx(tx)
	})

	// Import the canonical chain
	chain, err := NewBlockChain(rawdb.NewMemoryDatabase(), nil, gspec, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create tester chain: %v", err)
	}
	defer chain.Stop()

	if n, err := chain.InsertChain(blocks); err != nil {
		t.Fatalf("block %d: failed to insert into chain: %v", n, err)
	}

	block := chain.GetBlockByNumber(1)

	// Expected gas is intrinsic + 2 * pc + hot load + cold load, since only one load is in the access list
	expected := params.TxGas + params.TxAccessListAddressGas + params.TxAccessListStorageKeyGas +
		vm.GasQuickStep*2 + params.WarmStorageReadCostEIP2929 + params.ColdSloadCostEIP2929
	if block.GasUsed() != expected {
		t.Fatalf("incorrect amount of gas spent: expected %d, got %d", expected, block.GasUsed())
	}
}

// TestTransientStorageReset ensures the transient storage is wiped correctly
// between transactions.
func TestTransientStorageReset(t *testing.T) {
	var (
		engine      = ethash.NewFaker()
		key, _      = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		address     = crypto.PubkeyToAddress(key.PublicKey)
		destAddress = crypto.CreateAddress(address, 0)
		funds       = big.NewInt(100000000000000000)
		vmConfig    = vm.Config{
			ExtraEips: []int{1153}, // Enable transient storage EIP
		}
	)
	code := append([]byte{
		// TLoad value with location 1
		byte(vm.PUSH1), 0x1,
		byte(vm.TLOAD),

		// PUSH location
		byte(vm.PUSH1), 0x1,

		// SStore location:value
		byte(vm.SSTORE),
	}, make([]byte, 32-6)...)
	initCode := []byte{
		// TSTORE 1:1
		byte(vm.PUSH1), 0x1,
		byte(vm.PUSH1), 0x1,
		byte(vm.TSTORE),

		// Get the runtime-code on the stack
		byte(vm.PUSH32)}
	initCode = append(initCode, code...)
	initCode = append(initCode, []byte{
		byte(vm.PUSH1), 0x0, // offset
		byte(vm.MSTORE),
		byte(vm.PUSH1), 0x6, // size
		byte(vm.PUSH1), 0x0, // offset
		byte(vm.RETURN), // return 6 bytes of zero-code
	}...)
	gspec := &Genesis{
		Alloc: types.GenesisAlloc{
			address: {Balance: funds},
		},
		Config: params.TestChainConfig,
	}
	nonce := uint64(0)
	signer := types.HomesteadSigner{}
	_, blocks, _ := GenerateChainWithGenesis(gspec, engine, 1, func(i int, b *BlockGen) {
		fee := big.NewInt(1)
		if b.header.BaseFee != nil {
			fee = b.header.BaseFee
		}
		b.SetCoinbase(common.Address{1})
		tx, _ := types.SignNewTx(key, signer, &types.LegacyTx{
			Nonce:    nonce,
			GasPrice: new(big.Int).Set(fee),
			Gas:      100000,
			Data:     initCode,
		})
		nonce++
		b.AddTxWithVMConfig(tx, vmConfig)

		tx, _ = types.SignNewTx(key, signer, &types.LegacyTx{
			Nonce:    nonce,
			GasPrice: new(big.Int).Set(fee),
			Gas:      100000,
			To:       &destAddress,
		})
		b.AddTxWithVMConfig(tx, vmConfig)
		nonce++
	})

	// Initialize the blockchain with 1153 enabled.
	chain, err := NewBlockChain(rawdb.NewMemoryDatabase(), nil, gspec, engine, vmConfig)
	if err != nil {
		t.Fatalf("failed to create tester chain: %v", err)
	}
	// Import the blocks
	if _, err := chain.InsertChain(blocks); err != nil {
		t.Fatalf("failed to insert into chain: %v", err)
	}
	// Check the storage
	state, err := chain.StateAt(chain.CurrentHeader().Root)
	if err != nil {
		t.Fatalf("Failed to load state %v", err)
	}
	loc := common.BytesToHash([]byte{1})
	slot := state.GetState(destAddress, loc)
	if slot != (common.Hash{}) {
		t.Fatalf("Unexpected dirty storage slot")
	}
}

// TestEIP3651 tests eip 3651.
func TestEIP3651(t *testing.T) {
	var (
		ConstantinopleBlockReward = big.NewInt(3e+18) // Block reward in wei for successfully mining a block upward from Constantinople

		aa     = common.HexToAddress("0x000000000000000000000000000000000000aaaa")
		bb     = common.HexToAddress("0x000000000000000000000000000000000000bbbb")
		engine = ethash.NewFaker()

		// A sender who makes transactions, has some funds
		key1, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		key2, _ = crypto.HexToECDSA("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a")
		addr1   = crypto.PubkeyToAddress(key1.PublicKey)
		addr2   = crypto.PubkeyToAddress(key2.PublicKey)
		funds   = big.NewInt(8000000000000000)
		gspec   = &Genesis{
			Alloc: types.GenesisAlloc{
				addr1: {Balance: funds},
				addr2: {Balance: funds},
				// The address 0xAAAA sloads 0x00 and 0x01
				aa: {
					Code: []byte{
						byte(vm.PC),
						byte(vm.PC),
						byte(vm.SLOAD),
						byte(vm.SLOAD),
					},
					Nonce:   0,
					Balance: big.NewInt(0),
				},
				// The address 0xBBBB calls 0xAAAA
				bb: {
					Code: []byte{
						byte(vm.PUSH1), 0, // out size
						byte(vm.DUP1),  // out offset
						byte(vm.DUP1),  // out insize
						byte(vm.DUP1),  // in offset
						byte(vm.PUSH2), // address
						byte(0xaa),
						byte(0xaa),
						byte(vm.GAS), // gas
						byte(vm.DELEGATECALL),
					},
					Nonce:   0,
					Balance: big.NewInt(0),
				},
			},
			Config: params.TestChainConfig,
		}
	)

	signer := types.LatestSigner(gspec.Config)
	gspec.Config.EIP1559Block = common.Big0

	_, blocks, _ := GenerateChainWithGenesis(gspec, engine, 1, func(i int, b *BlockGen) {
		b.SetCoinbase(aa)
		// One transaction to Coinbase
		txdata := &types.DynamicFeeTx{
			ChainID:    gspec.Config.ChainID,
			Nonce:      0,
			To:         &bb,
			Gas:        500000,
			GasFeeCap:  big.NewInt(12500000000),
			GasTipCap:  big.NewInt(0),
			AccessList: nil,
			Data:       []byte{},
		}
		tx := types.NewTx(txdata)
		tx, _ = types.SignTx(tx, signer, key1)

		b.AddTx(tx)
	})

	chain, err := NewBlockChain(rawdb.NewMemoryDatabase(), nil, gspec, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create tester chain: %v", err)
	}
	if n, err := chain.InsertChain(blocks); err != nil {
		t.Fatalf("block %d: failed to insert into chain: %v", n, err)
	}

	block := chain.GetBlockByNumber(1)

	// 1+2: Ensure EIP-1559 access lists are accounted for via gas usage.
	innerGas := vm.GasQuickStep*2 + params.ColdSloadCostEIP2929*2
	expectedGas := params.TxGas + 5*vm.GasFastestStep + vm.GasQuickStep + 100 + innerGas // 100 because 0xaaaa is in access list
	if block.GasUsed() != expectedGas {
		t.Fatalf("incorrect amount of gas spent: expected %d, got %d", expectedGas, block.GasUsed())
	}

	state, _ := chain.State()

	// 3: Ensure that miner received only the tx's tip.
	actual := state.GetBalance(block.Coinbase())
	expected := new(big.Int).Add(
		new(big.Int).SetUint64(block.GasUsed()*block.Transactions()[0].GasTipCap().Uint64()),
		ConstantinopleBlockReward,
	)
	if actual.Cmp(expected) != 0 {
		t.Fatalf("miner balance incorrect: expected %d, got %d", expected, actual)
	}

	// 4: Ensure the tx sender paid for the gasUsed * (tip + block baseFee).
	actual = new(big.Int).Sub(funds, state.GetBalance(addr1))
	expected = new(big.Int).SetUint64(block.GasUsed() * (block.Transactions()[0].GasTipCap().Uint64() + block.BaseFee().Uint64()))
	if actual.Cmp(expected) != 0 {
		t.Fatalf("sender balance incorrect: expected %d, got %d", expected, actual)
	}
}

// TestDeleteCreateRevert tests a weird state transition corner case that we hit
// while changing the internals of statedb. The workflow is that a contract is
// self destructed, then in a followup transaction (but same block) it's created
// again and the transaction reverted.
//
// The original statedb implementation flushed dirty objects to the tries after
// each transaction, so this works ok. The rework accumulated writes in memory
// first, but the journal wiped the entire state object on create-revert.
func TestDeleteCreateRevert(t *testing.T) {
	var (
		aa = common.HexToAddress("0x000000000000000000000000000000000000aaaa")
		bb = common.HexToAddress("0x000000000000000000000000000000000000bbbb")
		// Generate a canonical chain to act as the main dataset
		engine = ethash.NewFaker()

		// A sender who makes transactions, has some funds
		key, _  = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		address = crypto.PubkeyToAddress(key.PublicKey)
		funds   = big.NewInt(10000000000000000)
		gspec   = &Genesis{
			Alloc: GenesisAlloc{
				address: {Balance: funds},
				// The address 0xAAAAA selfdestructs if called
				aa: {
					// Code needs to just selfdestruct
					Code:    []byte{byte(vm.PC), 0xFF},
					Nonce:   1,
					Balance: big.NewInt(0),
				},
				// The address 0xBBBB send 1 wei to 0xAAAA, then reverts
				bb: {
					Code: []byte{
						byte(vm.PC),          // [0]
						byte(vm.DUP1),        // [0,0]
						byte(vm.DUP1),        // [0,0,0]
						byte(vm.DUP1),        // [0,0,0,0]
						byte(vm.PUSH1), 0x01, // [0,0,0,0,1] (value)
						byte(vm.PUSH2), 0xaa, 0xaa, // [0,0,0,0,1, 0xaaaa]
						byte(vm.GAS),
						byte(vm.CALL),
						byte(vm.REVERT),
					},
					Balance: big.NewInt(1),
				},
			},
			Config: params.TestChainConfig,
		}
	)

	_, blocks, _ := GenerateChainWithGenesis(gspec, engine, 1, func(i int, b *BlockGen) {
		b.SetCoinbase(common.Address{1})
		// One transaction to AAAA
		tx, _ := types.SignTx(types.NewTransaction(0, aa,
			big.NewInt(0), 50000, b.header.BaseFee, nil), types.HomesteadSigner{}, key)
		b.AddTx(tx)
		// One transaction to BBBB
		tx, _ = types.SignTx(types.NewTransaction(1, bb,
			big.NewInt(0), 100000, b.header.BaseFee, nil), types.HomesteadSigner{}, key)
		b.AddTx(tx)
	})
	// Import the canonical chain
	chain, err := NewBlockChain(rawdb.NewMemoryDatabase(), nil, gspec, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create tester chain: %v", err)
	}
	defer chain.Stop()

	if n, err := chain.InsertChain(blocks); err != nil {
		t.Fatalf("block %d: failed to insert into chain: %v", n, err)
	}
}

// newMissingTdChain returns a memory chain over a fresh genesis together with a batch of
// total generated blocks, of which the first imported ones are already inserted. Keeping
// total larger than imported lets callers hand the chain blocks that its head never
// reached. The engine and the generation database are returned as well, since generating
// a competing block needs both.
func newMissingTdChain(t *testing.T, total, imported int) (*BlockChain, types.Blocks, consensus.Engine, ethdb.Database) {
	t.Helper()

	engine := ethash.NewFaker()
	gspec := &Genesis{
		Alloc:   types.GenesisAlloc{},
		BaseFee: big.NewInt(params.InitialBaseFee),
		Config:  params.TestChainConfig,
	}
	genDb := rawdb.NewMemoryDatabase()
	if _, err := gspec.Commit(genDb); err != nil {
		t.Fatalf("failed to commit genesis: %v", err)
	}
	blocks, _ := GenerateChain(gspec.Config, gspec.ToBlock(), engine, genDb, total, nil)

	chain, err := NewBlockChain(rawdb.NewMemoryDatabase(), nil, gspec, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create tester chain: %v", err)
	}
	t.Cleanup(chain.Stop)

	if n, err := chain.InsertChain(blocks[:imported]); err != nil {
		t.Fatalf("block %d: failed to insert into chain: %v", n, err)
	}
	return chain, blocks, engine, genDb
}

// dropTd deletes a block's total difficulty from both the database and the read cache, so
// that GetTd answers nil for it again.
func dropTd(t *testing.T, chain *BlockChain, block *types.Block) {
	t.Helper()

	rawdb.DeleteTd(chain.ChainDb(), block.Hash(), block.NumberU64())
	chain.hc.tdCache.Remove(block.Hash())
	if td := chain.GetTd(block.Hash(), block.NumberU64()); td != nil {
		t.Fatalf("precondition: the total difficulty of block #%d is still readable", block.NumberU64())
	}
}

// sidechainSegmentIterator hands insertSidechain a batch whose first block has already
// been pulled from the iterator, mirroring the call site in insertChain. Every block is
// reported as pruned, the shape that routes a batch into insertSidechain.
func sidechainSegmentIterator(t *testing.T, chain *BlockChain, batch types.Blocks) (*types.Block, *insertIterator) {
	t.Helper()

	results := make(chan error, len(batch))
	for range batch {
		results <- consensus.ErrPrunedAncestor
	}
	it := newInsertIterator(batch, results, chain.validator.(*BlockValidator))
	block, err := it.next()
	if !errors.Is(err, consensus.ErrPrunedAncestor) {
		t.Fatalf("unexpected verification result: have %v want %v", err, consensus.ErrPrunedAncestor)
	}
	return block, it
}

// TestInsertSidechainReportsMissingParentTd covers a segment whose parent has no total
// difficulty on disk: the scan falls back to it to weigh the segment against the head,
// and used to dereference the missing value. Nothing about the blocks makes them bad -
// this node simply has no number to compare - so it has to be reported rather than
// crashing the node.
func TestInsertSidechainReportsMissingParentTd(t *testing.T) {
	chain, blocks, _, _ := newMissingTdChain(t, 5, 3) // head at #3, #4 and #5 are unknown
	dropTd(t, chain, blocks[2])

	// The segment opens on a block whose parent's total difficulty this node no longer
	// has, so the scan has nothing to weigh it against.
	block, it := sidechainSegmentIterator(t, chain, blocks[3:5])

	n, _, _, err := chain.insertSidechain(block, it)
	if !errors.Is(err, errMissingTotalDifficulty) {
		t.Fatalf("unexpected error: have %v want %v", err, errMissingTotalDifficulty)
	}
	if want := 0; n != want {
		t.Fatalf("unexpected failing index: have %d want %d", n, want)
	}
	if want := uint64(3); chain.CurrentBlock().Number.Uint64() != want {
		t.Fatalf("unexpected head number: have %d want %d", chain.CurrentBlock().Number.Uint64(), want)
	}
}

// TestInsertSidechainReportsMissingLocalTd covers the other side of the comparison: the
// segment carries a total difficulty, but the head's cannot be read. The head has to stay
// where it is and the failure has to be reported.
func TestInsertSidechainReportsMissingLocalTd(t *testing.T) {
	chain, blocks, _, _ := newMissingTdChain(t, 6, 3) // head at #3

	// #4 is stored as a side block with its total difficulty, so the segment that opens
	// above it has a number to weigh itself against; only the head's is missing.
	parentTd := chain.GetTd(blocks[2].Hash(), blocks[2].NumberU64())
	if parentTd == nil {
		t.Fatal("precondition: the parent's total difficulty is not readable")
	}
	if err := chain.writeBlockWithoutState(blocks[3], new(big.Int).Add(parentTd, blocks[3].Difficulty())); err != nil {
		t.Fatalf("failed to store the side block: %v", err)
	}
	dropTd(t, chain, blocks[2])

	// The segment starts above #4, so no block of it is compared against a canonical one
	// and the scan runs until the batch is exhausted.
	block, it := sidechainSegmentIterator(t, chain, blocks[4:6])

	n, _, _, err := chain.insertSidechain(block, it)
	if !errors.Is(err, errMissingTotalDifficulty) {
		t.Fatalf("unexpected error: have %v want %v", err, errMissingTotalDifficulty)
	}
	// The scan ran off the end of the batch looking for a block to weigh.
	if want := 2; n != want {
		t.Fatalf("unexpected failing index: have %d want %d", n, want)
	}
	if want := uint64(3); chain.CurrentBlock().Number.Uint64() != want {
		t.Fatalf("unexpected head number: have %d want %d", chain.CurrentBlock().Number.Uint64(), want)
	}
}

// TestGetResultBlockReportsMissingTd covers the same guard on the competing-block path: a
// competitor whose parent total difficulty this node cannot read is not a bad block, it
// just cannot be weighed, and the arithmetic used to dereference the missing value.
func TestGetResultBlockReportsMissingTd(t *testing.T) {
	chain, blocks, engine, genDb := newMissingTdChain(t, 2*TriesInMemory, 2*TriesInMemory)

	// Forking on a block whose state is already pruned makes ValidateBody report the
	// pruned ancestor, the branch of getResultBlock that compares total difficulties.
	lastPruned := blocks[TriesInMemory-1]
	fork, _ := GenerateChain(params.TestChainConfig, lastPruned, engine, genDb, 1, func(i int, b *BlockGen) {
		// A different coinbase keeps the fork block from reproducing the canonical child
		// of lastPruned.
		b.SetCoinbase(common.Address{2})
	})
	// The chain read this block's difficulty when it imported its child, so the cached
	// copy has to go as well.
	dropTd(t, chain, lastPruned)

	if _, err := chain.getResultBlock(fork[0], false); !errors.Is(err, errMissingTotalDifficulty) {
		t.Fatalf("unexpected error: have %v want %v", err, errMissingTotalDifficulty)
	}
}

// TestGetResultBlockReportsMissingLocalTd covers the other half of the same guard: the
// competitor's parent is readable, while the canonical head's total difficulty is the one
// this node cannot read, and the comparison against it used to dereference the missing
// value.
func TestGetResultBlockReportsMissingLocalTd(t *testing.T) {
	chain, blocks, engine, genDb := newMissingTdChain(t, 2*TriesInMemory, 2*TriesInMemory)

	// Forking on a block whose state is already pruned makes ValidateBody report the
	// pruned ancestor, the branch of getResultBlock that compares total difficulties.
	lastPruned := blocks[TriesInMemory-1]
	fork, _ := GenerateChain(params.TestChainConfig, lastPruned, engine, genDb, 1, func(i int, b *BlockGen) {
		// A different coinbase keeps the fork block from reproducing the canonical child
		// of lastPruned.
		b.SetCoinbase(common.Address{2})
	})
	// The chain read this block's difficulty when it imported it, so the cached copy has
	// to go as well. The competitor's parent stays readable.
	dropTd(t, chain, blocks[2*TriesInMemory-1])

	if _, err := chain.getResultBlock(fork[0], false); !errors.Is(err, errMissingTotalDifficulty) {
		t.Fatalf("unexpected error: have %v want %v", err, errMissingTotalDifficulty)
	}
}

// TestWriteBlockWithStateReportsMissingLocalTd covers the same guard on the stateful
// insertion path: a child of a recently executed side block can still be weighed against
// that parent, while the canonical head's total difficulty is the one that cannot be read,
// and the arithmetic used to dereference the missing value.
func TestWriteBlockWithStateReportsMissingLocalTd(t *testing.T) {
	chain, blocks, engine, genDb := newMissingTdChain(t, 4, 4) // head at #4

	// A side block on #3 that competes with the canonical #4. Importing it executes it,
	// so a child of it can be built on its state, and its own total difficulty is stored.
	side, _ := GenerateChain(params.TestChainConfig, blocks[2], engine, genDb, 1, func(i int, b *BlockGen) {
		// A different coinbase keeps the side block from reproducing the canonical #4.
		b.SetCoinbase(common.Address{2})
	})
	if n, err := chain.InsertChain(side); err != nil {
		t.Fatalf("block %d: failed to insert the side block: %v", n, err)
	}
	if head := chain.CurrentBlock().Number.Uint64(); head != 4 {
		t.Fatalf("precondition: the side block took over the head, at #%d want #4", head)
	}
	child, _ := GenerateChain(params.TestChainConfig, side[0], engine, genDb, 1, nil)

	// The child can be executed on the state of the side block; only the head's total
	// difficulty is gone, which used to dereference the missing number.
	statedb, err := state.NewWithChainConfig(side[0].Root(), chain.stateCache, chain.chainConfig)
	if err != nil {
		t.Fatalf("failed to open the parent state: %v", err)
	}
	dropTd(t, chain, blocks[3])

	if _, err := chain.WriteBlockWithState(child[0], nil, statedb, nil, nil); !errors.Is(err, errMissingTotalDifficulty) {
		t.Fatalf("unexpected error: have %v want %v", err, errMissingTotalDifficulty)
	}
	if want := uint64(4); chain.CurrentBlock().Number.Uint64() != want {
		t.Fatalf("unexpected head number: have %d want %d", chain.CurrentBlock().Number.Uint64(), want)
	}
}

// newPreparedBlockChain returns a memory chain over a fresh genesis together with a batch
// of generated blocks, none of which is inserted: PrepareBlock is about to prepare the
// first of them, and the chain has not seen any of them yet.
func newPreparedBlockChain(t *testing.T, total int, gen func(int, *BlockGen)) (*BlockChain, types.Blocks) {
	t.Helper()

	key, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	gspec := &Genesis{
		Alloc:   types.GenesisAlloc{crypto.PubkeyToAddress(key.PublicKey): {Balance: big.NewInt(1000000000000000)}},
		BaseFee: big.NewInt(params.InitialBaseFee),
		Config:  params.TestChainConfig,
	}
	_, blocks, _ := GenerateChainWithGenesis(gspec, ethash.NewFaker(), total, gen)
	// XDPoS signs a header with a validator signature before it inserts the block, a
	// signature that is part of the hash a block is inserted under and of none of the
	// hashes the caches ask for. The block the tests work with is signed here so that the
	// two hashes differ in it: an unsigned one answers a look-up by Hash and one by
	// HashNoValidator alike, and a test over it passes whatever key the caches are
	// written with.
	header := types.CopyHeader(blocks[0].Header())
	header.Validator = []byte{0x01}
	blocks[0] = blocks[0].WithSeal(header)
	if blocks[0].Hash() == blocks[0].HashNoValidator() {
		t.Fatal("the prepared block must be inserted under another hash than the caches ask for")
	}
	chain, err := NewBlockChain(rawdb.NewMemoryDatabase(), nil, gspec, ethash.NewFaker(), vm.Config{})
	if err != nil {
		t.Fatalf("failed to create tester chain: %v", err)
	}
	t.Cleanup(chain.Stop)
	return chain, blocks
}

// TestPrepareBlockStoresItsResultUnderTheLookupKey pins the key a prepared result is stored
// under. XDPoS signs a header with a validator signature that takes no part in its execution,
// so a prepared result belongs to the header alone: getResultBlock looks it up by
// HashNoValidator when insertBlock imports the block, and the two probes PrepareBlock starts
// with ask the same way. Storing it under Hash leaves all three look-ups empty, and the
// precomputation this function exists for is never reused.
func TestPrepareBlockStoresItsResultUnderTheLookupKey(t *testing.T) {
	chain, blocks := newPreparedBlockChain(t, 6, nil)
	target := blocks[0]

	if err := chain.PrepareBlock(target); err != nil {
		t.Fatalf("failed to prepare the block: %v", err)
	}
	if !chain.resultProcess.Contains(target.HashNoValidator()) {
		t.Fatal("the prepared result is not stored under the key its look-ups use")
	}
	// getResultBlock is the look-up insertBlock performs: a reused result is returned
	// without being computed, so the block is not recorded as being calculated. The
	// preparation above did record it, hence the reset - nothing else purges that cache.
	chain.calculatingBlock.Purge()
	result, err := chain.getResultBlock(target, true)
	if err != nil {
		t.Fatalf("failed to look the prepared result up: %v", err)
	}
	if result == nil {
		t.Fatal("the prepared result was not returned")
	}
	if chain.calculatingBlock.Contains(target.HashNoValidator()) {
		t.Fatal("the prepared result was not reused: the block was calculated a second time")
	}
}

// TestPrepareBlockSkipsABlockBeingCalculated covers the second probe: a block getResultBlock
// has already recorded is not prepared again. That probe asks by HashNoValidator as well, so
// an entry stored under any other key is answered as a miss and the preparation runs anyway.
func TestPrepareBlockSkipsABlockBeingCalculated(t *testing.T) {
	chain, blocks := newPreparedBlockChain(t, 6, nil)
	target := blocks[0]

	// The preset entry is the marker itself, and a preparation that runs anyway replaces it
	// with one of its own - so comparing the pointer says whether the probe answered or the
	// preparation went ahead.
	preset := &CalculatedBlock{block: target}
	chain.calculatingBlock.Add(target.HashNoValidator(), preset)
	if err := chain.PrepareBlock(target); err != nil {
		t.Fatalf("failed to prepare the block: %v", err)
	}
	got, ok := chain.calculatingBlock.Peek(target.HashNoValidator())
	if !ok || got != preset {
		t.Fatal("a block that is already being calculated was prepared again")
	}
}

// TestAReusedResultIsStampedWithTheBlockItIsInsertedUnder covers the hash a prepared result
// carries into the block that reuses it. XDPoS signs a header with a validator signature
// after the block was prepared, that signature is part of the hash the block is inserted
// under, and it is the only thing that hash and the one the result was computed with differ
// in. Reusing the result as it stands would hence stamp the receipts and the logs the block
// is published with the pre-signature hash, the hash of a block that is written nowhere.
func TestAReusedResultIsStampedWithTheBlockItIsInsertedUnder(t *testing.T) {
	key, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	address := crypto.PubkeyToAddress(key.PublicKey)
	// A transaction is what makes the result carry a receipt, the thing that is stamped
	// with the hash of the block it was computed from.
	chain, blocks := newPreparedBlockChain(t, 2, func(i int, b *BlockGen) {
		tx, _ := types.SignTx(types.NewTransaction(uint64(i), address, big.NewInt(1), params.TxGas, b.header.BaseFee, nil), types.HomesteadSigner{}, key)
		b.AddTx(tx)
	})
	target := blocks[0]

	// The fetcher prepares the block as it was propagated and imports the one XDPoS signed,
	// so the unsigned twin of the target is what is prepared here: the signature takes no
	// part in the execution, hence the prepared result answering the look-up the target
	// makes as well.
	header := types.CopyHeader(target.Header())
	header.Validator = nil
	unsigned := types.NewBlockWithHeader(header).WithBody(*target.Body())
	if unsigned.HashNoValidator() != target.HashNoValidator() {
		t.Fatal("the signature is not expected to take part in the key the caches use")
	}
	if unsigned.Hash() == target.Hash() {
		t.Fatal("the signature is expected to take part in the hash the block is inserted under")
	}
	if err := chain.PrepareBlock(unsigned); err != nil {
		t.Fatalf("failed to prepare the block: %v", err)
	}
	// A transaction that emits no log leaves nothing to cover the stamping of the logs,
	// so one is attached to the prepared result, where a log of its own would sit.
	prepared, ok := chain.resultProcess.Get(unsigned.HashNoValidator())
	if !ok {
		t.Fatal("the prepared result is not stored under the key its look-ups use")
	}
	if len(prepared.receipts) == 0 {
		t.Fatal("the prepared result has no receipt to stamp")
	}
	preparedLog := &types.Log{BlockHash: unsigned.Hash(), Address: address}
	prepared.receipts[0].Logs = append(prepared.receipts[0].Logs, preparedLog)
	prepared.logs = append(prepared.logs, preparedLog)

	// getResultBlock is the look-up insertBlock performs: a reused result is returned
	// without being computed, so the block is not recorded as being calculated. The
	// preparation above did record it, hence the reset - nothing else purges that cache.
	chain.calculatingBlock.Purge()
	result, err := chain.getResultBlock(target, true)
	if err != nil {
		t.Fatalf("failed to look the prepared result up: %v", err)
	}
	if chain.calculatingBlock.Contains(target.HashNoValidator()) {
		t.Fatal("the prepared result was not reused: the block was calculated a second time")
	}
	for _, receipt := range result.receipts {
		if receipt.BlockHash != target.Hash() {
			t.Fatalf("receipt stamped with a foreign block hash: have %v, want %v", receipt.BlockHash, target.Hash())
		}
	}
	for _, l := range result.logs {
		if l.BlockHash != target.Hash() {
			t.Fatalf("log stamped with a foreign block hash: have %v, want %v", l.BlockHash, target.Hash())
		}
	}
}

// TestConcurrentReusesOfAPreparedResultCarryTheirOwnHash covers the hash a prepared result
// carries into each of the blocks that reuse it at the same time. A block that was signed
// twice - by two nodes sharing the validator key, say - yields two blocks that ask the
// caches by the same hash and are inserted under a hash each, so both of them look the same
// prepared result up. Each insertion has to be stamped with its own hash: stamping the
// cached result in place would let one insertion overwrite the hash the other one persists
// and publishes, and restamp the logs a subscriber is already holding.
func TestConcurrentReusesOfAPreparedResultCarryTheirOwnHash(t *testing.T) {
	key, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	address := crypto.PubkeyToAddress(key.PublicKey)
	// A transaction is what makes the result carry a receipt, the thing that is stamped
	// with the hash of the block it was computed from.
	chain, blocks := newPreparedBlockChain(t, 2, func(i int, b *BlockGen) {
		tx, _ := types.SignTx(types.NewTransaction(uint64(i), address, big.NewInt(1), params.TxGas, b.header.BaseFee, nil), types.HomesteadSigner{}, key)
		b.AddTx(tx)
	})
	target := blocks[0]

	// The fetcher prepares the block as it was propagated and imports the one XDPoS signed,
	// so the unsigned twin of the target is what is prepared here: the signature takes no
	// part in the execution, hence the prepared result answering the look-up every signed
	// twin of it makes.
	header := types.CopyHeader(target.Header())
	header.Validator = nil
	unsigned := types.NewBlockWithHeader(header).WithBody(*target.Body())
	if err := chain.PrepareBlock(unsigned); err != nil {
		t.Fatalf("failed to prepare the block: %v", err)
	}
	// A transaction that emits no log leaves nothing to cover the stamping of the logs, so
	// one is attached to the prepared result, where a log of its own would sit.
	prepared, ok := chain.resultProcess.Get(unsigned.HashNoValidator())
	if !ok {
		t.Fatal("the prepared result is not stored under the key its look-ups use")
	}
	if len(prepared.receipts) == 0 {
		t.Fatal("the prepared result has no receipt to stamp")
	}
	preparedLog := &types.Log{BlockHash: unsigned.Hash(), Address: address}
	prepared.receipts[0].Logs = append(prepared.receipts[0].Logs, preparedLog)
	prepared.logs = append(prepared.logs, preparedLog)

	// Two blocks sharing the key of the prepared result, under a hash each.
	twins := make([]*types.Block, 0, 2)
	for _, validator := range [][]byte{{0x01}, {0x02}} {
		signed := types.CopyHeader(target.Header())
		signed.Validator = validator
		twins = append(twins, types.NewBlockWithHeader(signed).WithBody(*target.Body()))
	}
	if twins[0].HashNoValidator() != twins[1].HashNoValidator() {
		t.Fatal("the twins do not share the key the caches ask for")
	}
	if twins[0].Hash() == twins[1].Hash() {
		t.Fatal("the twins are expected to be inserted under a hash each")
	}

	// Reuse the prepared result from both twins at once, the way two insertions of them
	// running concurrently do.
	results := make([]*ResultProcessBlock, len(twins))
	var wg sync.WaitGroup
	for i, twin := range twins {
		wg.Add(1)
		go func(i int, twin *types.Block) {
			defer wg.Done()

			result, err := chain.getResultBlock(twin, true)
			if err != nil {
				t.Errorf("failed to look the prepared result up: %v", err)
				return
			}
			results[i] = result
		}(i, twin)
	}
	wg.Wait()

	for i, twin := range twins {
		if results[i] == nil {
			t.Fatalf("the look-up performed by the block under %v returned nothing", twin.Hash())
		}
		for _, receipt := range results[i].receipts {
			if receipt.BlockHash != twin.Hash() {
				t.Errorf("receipt of the block under %v stamped with %v", twin.Hash(), receipt.BlockHash)
			}
		}
		for _, l := range results[i].logs {
			if l.BlockHash != twin.Hash() {
				t.Errorf("log of the block under %v stamped with %v", twin.Hash(), l.BlockHash)
			}
		}
	}
	// The cache outlives its reuses and answers every look-up, so neither of them may have
	// stamped the result it was handed.
	for _, receipt := range prepared.receipts {
		if receipt.BlockHash != unsigned.Hash() {
			t.Errorf("the cached result was stamped in place: receipt has %v, want %v", receipt.BlockHash, unsigned.Hash())
		}
	}
	for _, l := range prepared.logs {
		if l.BlockHash != unsigned.Hash() {
			t.Errorf("the cached result was stamped in place: log has %v, want %v", l.BlockHash, unsigned.Hash())
		}
	}
}
