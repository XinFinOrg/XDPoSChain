// Copyright 2026 The XDPoSChain Authors
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

package ethapi

import (
	"crypto/ecdsa"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/XinFinOrg/XDPoSChain/rpc"
	"github.com/XinFinOrg/XDPoSChain/trie"
)

// signersBackend serves blocks by number, with an explicit current head.
type signersBackend struct {
	*blockLookupBackendMock
	head *types.Header
}

func (b *signersBackend) CurrentBlock() *types.Header { return b.head }

// signingTxFor signs a BlockSigners sign transaction for target.
func signingTxFor(t *testing.T, config *params.ChainConfig, key *ecdsa.PrivateKey, target *types.Header) *types.Transaction {
	t.Helper()
	data := append(common.FromHex(common.SignMethod), common.LeftPadBytes(target.Number.Bytes(), 32)...)
	data = append(data, target.Hash().Bytes()...)
	tx, err := types.SignTx(types.NewTransaction(0, common.BlockSignersBinary, new(big.Int), 200_000, new(big.Int), data), types.MakeSigner(config, big.NewInt(2)), key)
	if err != nil {
		t.Fatalf("failed to sign tx: %v", err)
	}
	return tx
}

// TestGetSignersFromBlocksCachesUnderBlockHash checks that the signing
// transactions read for the finality RPC are cached under the hash of the block
// they were read from. The cache is shared with the reward and penalty hooks, so
// an entry keyed by another block's hash would feed them the wrong signers. The
// backend answers the header lookup with a block that was since replaced at the
// same height, the way two separate reads do when the chain reorganises between
// them.
func TestGetSignersFromBlocksCachesUnderBlockHash(t *testing.T) {
	config := params.TestXDPoSMockChainConfig
	engine := XDPoS.NewFaker(rawdb.NewMemoryDatabase(), config)

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	signer := crypto.PubkeyToAddress(key.PublicKey)
	target := &types.Header{Number: big.NewInt(1), Extra: []byte("target")}
	signTx := signingTxFor(t, config, key, target)

	stale := &types.Header{Number: big.NewInt(2), ParentHash: target.Hash(), Extra: []byte("stale")}
	replaced := types.NewBlock(&types.Header{Number: big.NewInt(2), ParentHash: target.Hash(), Extra: []byte("replacement")},
		&types.Body{Transactions: types.Transactions{signTx}}, nil, trie.NewStackTrie(nil))

	backend := &signersBackend{
		blockLookupBackendMock: &blockLookupBackendMock{
			backendMock:     &backendMock{config: config, engine: engine},
			headersByNumber: map[rpc.BlockNumber]*types.Header{2: stale},
			blocksByNumber:  map[rpc.BlockNumber]*types.Block{2: replaced},
		},
		head: replaced.Header(),
	}

	signers, err := GetSignersFromBlocks(backend, target.Number.Uint64(), target.Hash(), []common.Address{signer})
	if err != nil {
		t.Fatalf("GetSignersFromBlocks failed: %v", err)
	}
	if len(signers) != 1 || signers[0] != signer {
		t.Fatalf("signers %v, want [%v]", signers, signer)
	}
	if txs, ok := engine.GetCachedSigningTxs(stale.Hash()); ok {
		t.Fatalf("cached %d signing txs under the hash of a block that does not carry them", len(txs))
	}
	txs, ok := engine.GetCachedSigningTxs(replaced.Hash())
	if !ok || len(txs) != 1 || txs[0].Hash() != signTx.Hash() {
		t.Fatalf("signing txs of the block read are not cached under its own hash: ok %v, %d txs", ok, len(txs))
	}
}

// TestGetSignersFromBlocksRejectsMismatchedBody checks that a block whose body
// does not match its header's transaction root is reported, and that none of its
// transactions reach the signing-transaction cache.
func TestGetSignersFromBlocksRejectsMismatchedBody(t *testing.T) {
	config := params.TestXDPoSMockChainConfig
	engine := XDPoS.NewFaker(rawdb.NewMemoryDatabase(), config)

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	signer := crypto.PubkeyToAddress(key.PublicKey)
	target := &types.Header{Number: big.NewInt(1), Extra: []byte("target")}

	// The header commits to an empty body, the block carries a signing tx.
	header := &types.Header{Number: big.NewInt(2), ParentHash: target.Hash(), TxHash: types.EmptyTxsHash}
	block := types.NewBlockWithHeader(header).WithBody(types.Body{Transactions: types.Transactions{signingTxFor(t, config, key, target)}})

	backend := &signersBackend{
		blockLookupBackendMock: &blockLookupBackendMock{
			backendMock:    &backendMock{config: config, engine: engine},
			blocksByNumber: map[rpc.BlockNumber]*types.Block{2: block},
		},
		head: header,
	}
	if _, err := GetSignersFromBlocks(backend, target.Number.Uint64(), target.Hash(), []common.Address{signer}); err == nil {
		t.Fatal("GetSignersFromBlocks accepted a block whose body does not match its transaction root")
	}
	if txs, ok := engine.GetCachedSigningTxs(block.Hash()); ok {
		t.Fatalf("cached %d signing txs from a block whose body does not match its transaction root", len(txs))
	}
}
