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

package miner

import (
	"crypto/ecdsa"
	"math/big"
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/txpool"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/event"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/XinFinOrg/XDPoSChain/trie"
	"github.com/holiman/uint256"
)

// signerSourceFaker is the ethash faker with a fixed candidate list.
type signerSourceFaker struct {
	consensus.Engine
	signers []common.Address
}

func (e *signerSourceFaker) GetAuthorisedSignersFromSnapshot(consensus.ChainReader, *types.Header) ([]common.Address, error) {
	return e.signers, nil
}

// signRulesFixture is a worker on top of a genesis-only chain whose engine
// reports two candidates, A and B. C is not a candidate and D only pays.
type signRulesFixture struct {
	t      *testing.T
	config *params.ChainConfig
	engine *signerSourceFaker
	chain  *core.BlockChain
	worker *worker
	parent *types.Block

	keyA, keyB, keyC, keyD *ecdsa.PrivateKey
	candidateA, candidateB common.Address
	outsider, payer        common.Address
}

// newSignRulesFixture builds the fixture with TIPSigning and TIP2019 active
// and TIPSignTxRules at forkBlock, nil for not scheduled.
func newSignRulesFixture(t *testing.T, forkBlock *big.Int) *signRulesFixture {
	t.Helper()
	newKey := func() (*ecdsa.PrivateKey, common.Address) {
		key, err := crypto.GenerateKey()
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		return key, crypto.PubkeyToAddress(key.PublicKey)
	}
	f := &signRulesFixture{t: t}
	f.keyA, f.candidateA = newKey()
	f.keyB, f.candidateB = newKey()
	f.keyC, f.outsider = newKey()
	f.keyD, f.payer = newKey()

	f.config = &params.ChainConfig{
		ChainID:                big.NewInt(1338),
		HomesteadBlock:         new(big.Int),
		TIP2019Block:           new(big.Int),
		TIPSigningBlock:        new(big.Int),
		TIPXDCXBlock:           big.NewInt(0),
		TIPTRC21FeeBlock:       big.NewInt(0),
		Gas50xBlock:            big.NewInt(0),
		TIPSignTxRulesBlock:    forkBlock,
		TRC21IssuerSMC:         params.TestnetChainConfig.TRC21IssuerSMC,
		XDCXListingSMC:         params.TestnetChainConfig.XDCXListingSMC,
		RelayerRegistrationSMC: params.TestnetChainConfig.RelayerRegistrationSMC,
		LendingRegistrationSMC: params.TestnetChainConfig.LendingRegistrationSMC,
		Ethash:                 new(params.EthashConfig),
	}
	genesis := &core.Genesis{
		Config:     f.config,
		Alloc:      types.GenesisAlloc{f.payer: {Balance: big.NewInt(params.Ether)}},
		Difficulty: big.NewInt(1),
		GasLimit:   params.XDCGenesisGasLimit,
	}
	f.engine = &signerSourceFaker{Engine: ethash.NewFaker(), signers: []common.Address{f.candidateA, f.candidateB}}
	chain, err := core.NewBlockChain(rawdb.NewMemoryDatabase(), nil, genesis, f.engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create blockchain: %v", err)
	}
	t.Cleanup(chain.Stop)
	f.chain = chain

	f.parent = chain.GetBlockByNumber(0)
	header := &types.Header{
		ParentHash: f.parent.Hash(),
		Difficulty: big.NewInt(1),
		Number:     big.NewInt(1),
		Time:       f.parent.Time() + 1,
		GasLimit:   params.XDCGenesisGasLimit,
	}
	f.worker = &worker{
		config:      &Config{GasCeil: params.XDCGenesisGasLimit, GasPrice: big.NewInt(1)},
		chainConfig: f.config,
		engine:      f.engine,
		chain:       chain,
	}
	if err := f.worker.makeCurrent(f.parent, header); err != nil {
		t.Fatalf("failed to create current work: %v", err)
	}
	return f
}

// sign signs tx with key.
func (f *signRulesFixture) sign(key *ecdsa.PrivateKey, tx *types.Transaction) *types.Transaction {
	signed, err := types.SignTx(tx, types.HomesteadSigner{}, key)
	if err != nil {
		f.t.Fatalf("sign tx: %v", err)
	}
	return signed
}

// signTx is a sign transaction from key at nonce with the given call data.
func (f *signRulesFixture) signTx(key *ecdsa.PrivateKey, nonce uint64, data []byte) *types.Transaction {
	return f.sign(key, types.NewTransaction(nonce, common.BlockSignersBinary, new(big.Int), 200000, new(big.Int), data))
}

// commit offers txs, keyed by sender, to the current work in one
// commitTransactions call.
func (f *signRulesFixture) commit(txs map[common.Address][]*types.Transaction) {
	lazy := make(map[common.Address][]*txpool.LazyTransaction, len(txs))
	for from, list := range txs {
		for _, tx := range list {
			fee := uint256.MustFromBig(tx.GasPrice())
			lazy[from] = append(lazy[from], &txpool.LazyTransaction{Hash: tx.Hash(), Tx: tx, Time: time.Now(), GasFeeCap: fee, GasTipCap: fee, Gas: tx.Gas()})
		}
	}
	set, specialTxs := newTransactionsByPriceAndNonce(f.worker.current.signer, lazy, nil, nil)
	f.worker.current.commitTransactions(new(event.TypeMux), map[common.Address]*big.Int{}, set, specialTxs, f.chain, &event.Feed{})
}

// committed reports which transactions the current work holds.
func (f *signRulesFixture) committed() map[common.Hash]bool {
	committed := make(map[common.Hash]bool)
	for _, tx := range f.worker.current.txs {
		committed[tx.Hash()] = true
	}
	return committed
}

// TestWorkerCommitTransactionsAppliesSignTxRules checks that the miner packs
// only sign transactions that pass the sign transaction rules, at most one per
// signer, before TIPSignTxRules is scheduled, while other transactions are
// packed as usual.
func TestWorkerCommitTransactionsAppliesSignTxRules(t *testing.T) {
	f := newSignRulesFixture(t, nil)

	// Block 1 can only sign block 0.
	honestA := f.signTx(f.keyA, 0, signTxData(0))
	secondA := f.signTx(f.keyA, 1, signTxData(0))
	malformedB := f.signTx(f.keyB, 0, make([]byte, 100))
	outsiderC := f.signTx(f.keyC, 0, signTxData(0))
	transfer := f.sign(f.keyD, types.NewTransaction(0, common.HexToAddress("0xaa"), big.NewInt(1), params.TxGas, big.NewInt(1), nil))

	f.commit(map[common.Address][]*types.Transaction{
		f.candidateA: {honestA, secondA},
		f.candidateB: {malformedB},
		f.outsider:   {outsiderC},
		f.payer:      {transfer},
	})

	committed := f.committed()
	for _, want := range []struct {
		name string
		tx   *types.Transaction
		in   bool
	}{
		{"honest sign tx", honestA, true},
		{"second sign tx from the same signer", secondA, false},
		{"malformed sign tx", malformedB, false},
		{"sign tx from a non-candidate", outsiderC, false},
		{"regular transfer", transfer, true},
	} {
		if committed[want.tx.Hash()] != want.in {
			t.Errorf("%s: committed = %v, want %v", want.name, committed[want.tx.Hash()], want.in)
		}
	}
	if len(f.worker.current.txs) != 2 {
		t.Fatalf("committed %d transactions, want 2", len(f.worker.current.txs))
	}
}

// TestWorkerSignTxRulesSpanCommitCalls checks that the one sign transaction
// per sender rule holds across commitTransactions calls on the same work, as
// in the non-mining path that adds new pool transactions to the pending block.
func TestWorkerSignTxRulesSpanCommitCalls(t *testing.T) {
	f := newSignRulesFixture(t, nil)

	first := f.signTx(f.keyA, 0, signTxData(0))
	second := f.signTx(f.keyA, 1, signTxData(0))
	f.commit(map[common.Address][]*types.Transaction{f.candidateA: {first}})
	f.commit(map[common.Address][]*types.Transaction{f.candidateA: {second}})

	committed := f.committed()
	if !committed[first.Hash()] {
		t.Fatalf("first sign tx not committed")
	}
	if committed[second.Hash()] {
		t.Fatalf("second sign tx from the same sender committed in a later call")
	}
}

// TestWorkerBlockPassesProcessAfterFork builds a block with the worker while
// TIPSignTxRules is active and runs it through block processing: a block the
// miner builds must pass the rules consensus applies.
func TestWorkerBlockPassesProcessAfterFork(t *testing.T) {
	f := newSignRulesFixture(t, big.NewInt(1))

	honestA := f.signTx(f.keyA, 0, signTxData(0))
	f.commit(map[common.Address][]*types.Transaction{
		f.candidateA: {honestA, f.signTx(f.keyA, 1, signTxData(0))},
		f.candidateB: {f.signTx(f.keyB, 0, make([]byte, 100))},
		f.outsider:   {f.signTx(f.keyC, 0, signTxData(0))},
		f.payer:      {f.sign(f.keyD, types.NewTransaction(0, common.HexToAddress("0xaa"), big.NewInt(1), params.TxGas, big.NewInt(1), nil))},
	})
	work := f.worker.current
	if len(work.txs) != 2 || !f.committed()[honestA.Hash()] {
		t.Fatalf("committed %d transactions, want the honest sign tx and the transfer", len(work.txs))
	}

	block := types.NewBlock(work.header, &types.Body{Transactions: work.txs}, work.receipts, trie.NewStackTrie(nil))
	statedb, err := f.chain.StateAt(f.parent.Root())
	if err != nil {
		t.Fatalf("parent state: %v", err)
	}
	processor := core.NewStateProcessor(f.config, f.chain, f.engine)
	if _, _, _, err := processor.Process(block, statedb, nil, vm.Config{}, map[common.Address]*big.Int{}); err != nil {
		t.Fatalf("Process rejected the block the miner built: %v", err)
	}
}

// signTxData is a sign(number, hash) call.
func signTxData(number uint64) []byte {
	data := common.Hex2Bytes(common.HexSignMethod)
	data = append(data, common.LeftPadBytes(new(big.Int).SetUint64(number).Bytes(), 32)...)
	return append(data, common.Hash{1}.Bytes()...)
}
