package core

import (
	"errors"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/XinFinOrg/XDPoSChain/trie"
)

var errParentNotCanonical = errors.New("parent of batch is not canonical")

// sharedStateEngine is an ethash faker without block rewards, so a block without
// transactions keeps the state root of its parent like an XDPoS block does. Like
// the XDPoS epoch switch reading its gap block, its header verification looks up
// the parent of a batch by canonical number.
type sharedStateEngine struct {
	*ethash.Ethash
}

func (e sharedStateEngine) VerifyHeaders(chain consensus.ChainReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	abort := make(chan struct{})
	results := make(chan error, len(headers))
	for i, header := range headers {
		if i == 0 {
			parent := chain.GetHeaderByNumber(header.Number.Uint64() - 1)
			if parent == nil || parent.Hash() != header.ParentHash {
				results <- errParentNotCanonical
				continue
			}
		}
		results <- nil
	}
	return abort, results
}

func (e sharedStateEngine) Finalize(chain consensus.ChainReader, header *types.Header, state vm.StateDB, parentState *state.StateDB, txs []*types.Transaction, uncles []*types.Header, receipts []*types.Receipt) (*types.Block, error) {
	header.Root = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))
	return types.NewBlock(header, &types.Body{Transactions: txs, Uncles: uncles}, receipts, trie.NewStackTrie(nil)), nil
}

// makeSharedStateChain generates six blocks, where block 3 has no transactions
// and therefore the same state root as block 2.
func makeSharedStateChain(t *testing.T) (*Genesis, sharedStateEngine, []*types.Block) {
	var (
		key, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		addr   = crypto.PubkeyToAddress(key.PublicKey)
		config = *params.TestChainConfig
		gspec  = &Genesis{
			Alloc:   types.GenesisAlloc{addr: {Balance: big.NewInt(params.Ether)}},
			BaseFee: big.NewInt(params.InitialBaseFee),
			Config:  &config,
		}
		engine = sharedStateEngine{ethash.NewFaker()}
	)
	// EIP-2935 stores the parent hash in the state of every block, and EIP-7934
	// is scheduled together with it, so stay before Prague.
	config.PragueBlock, config.OsakaBlock = nil, nil
	signer := types.LatestSigner(gspec.Config)
	_, blocks, _ := GenerateChainWithGenesis(gspec, engine, 6, func(i int, b *BlockGen) {
		if i == 2 {
			return
		}
		tx, err := types.SignTx(types.NewTransaction(b.TxNonce(addr), common.Address{0xaa}, big.NewInt(1), params.TxGas, b.BaseFee(), nil), signer, key)
		if err != nil {
			t.Fatalf("failed to sign tx: %v", err)
		}
		b.AddTx(tx)
	})
	if blocks[2].Root() != blocks[1].Root() {
		t.Fatalf("block 3 does not share the state of block 2")
	}
	return gspec, engine, blocks
}

// writeStateless stores blocks the way insertSidechain does: body, header and
// total difficulty, but no state, no receipts and no canonical marker.
func writeStateless(t *testing.T, chain *BlockChain, blocks []*types.Block) {
	for _, block := range blocks {
		ptd := chain.GetTd(block.ParentHash(), block.NumberU64()-1)
		if ptd == nil {
			t.Fatalf("missing total difficulty of the parent of block %d", block.NumberU64())
		}
		if err := chain.writeBlockWithoutState(block, new(big.Int).Add(ptd, block.Difficulty())); err != nil {
			t.Fatalf("failed to write block %d: %v", block.NumberU64(), err)
		}
	}
}

func assertCanonical(t *testing.T, chain *BlockChain, blocks []*types.Block) {
	if head := chain.CurrentBlock().Number.Uint64(); head != blocks[len(blocks)-1].NumberU64() {
		t.Fatalf("chain head mismatch: have %d, want %d", head, blocks[len(blocks)-1].NumberU64())
	}
	for _, block := range blocks {
		if hash := rawdb.ReadCanonicalHash(chain.db, block.NumberU64()); hash != block.Hash() {
			t.Fatalf("block %d is not canonical", block.NumberU64())
		}
	}
}

// TestInsertKnownBlockInTheMiddle tests that a batch carrying a known block
// above the head, whose state an earlier block already produced, is imported
// in full instead of stopping at that block.
func TestInsertKnownBlockInTheMiddle(t *testing.T) {
	gspec, engine, blocks := makeSharedStateChain(t)

	chain, err := NewBlockChain(rawdb.NewMemoryDatabase(), nil, gspec, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create chain: %v", err)
	}
	defer chain.Stop()

	if _, err := chain.InsertChain(blocks[:2]); err != nil {
		t.Fatalf("failed to insert initial blocks: %v", err)
	}
	// Block 3 is stored without state, but its state is the one of block 2.
	writeStateless(t, chain, blocks[2:3])

	if _, err := chain.InsertChain(blocks[2:]); err != nil {
		t.Fatalf("failed to insert remaining blocks: %v", err)
	}
	assertCanonical(t, chain, blocks)
	if receipts := chain.GetReceiptsByHash(blocks[2].Hash()); receipts == nil || len(receipts) != 0 {
		t.Fatalf("known block receipts mismatch: have %v, want empty", receipts)
	}
}

// TestInsertAfterStatelessAncestors reproduces a node restarting after an
// unclean shutdown: the downloader resumes after the highest stored block, which
// was written without state, and the header verification of the next batch
// requires its parent to be canonical.
func TestInsertAfterStatelessAncestors(t *testing.T) {
	gspec, engine, blocks := makeSharedStateChain(t)

	chain, err := NewBlockChain(rawdb.NewMemoryDatabase(), nil, gspec, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create chain: %v", err)
	}
	defer chain.Stop()

	writeStateless(t, chain, blocks[:5])

	if _, err := chain.InsertChain(blocks[5:]); err != nil {
		t.Fatalf("failed to insert block after stateless ancestors: %v", err)
	}
	assertCanonical(t, chain, blocks)
}

// TestInsertAfterLighterStatelessAncestors tests that stored ancestors without
// state are left alone when they do not outweigh the canonical chain.
func TestInsertAfterLighterStatelessAncestors(t *testing.T) {
	gspec, engine, blocks := makeSharedStateChain(t)

	chain, err := NewBlockChain(rawdb.NewMemoryDatabase(), nil, gspec, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create chain: %v", err)
	}
	defer chain.Stop()

	// A heavier canonical chain of six blocks on a different branch.
	_, canon, _ := GenerateChainWithGenesis(gspec, engine, 6, func(i int, b *BlockGen) {
		b.SetCoinbase(common.Address{0xbb})
	})
	if _, err := chain.InsertChain(canon); err != nil {
		t.Fatalf("failed to insert canonical chain: %v", err)
	}
	writeStateless(t, chain, blocks[:4])

	if _, err := chain.InsertChain(blocks[4:5]); !errors.Is(err, errParentNotCanonical) {
		t.Fatalf("insert error mismatch: have %v, want %v", err, errParentNotCanonical)
	}
	assertCanonical(t, chain, canon)
}
