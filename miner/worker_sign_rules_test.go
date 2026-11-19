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

// TestWorkerCommitTransactionsAppliesSignTxRules checks that the miner packs
// only sign transactions that pass the sign transaction rules, at most one per
// signer, before TIPSignTxRules is scheduled, while other transactions are
// packed as usual.
func TestWorkerCommitTransactionsAppliesSignTxRules(t *testing.T) {
	newKey := func() (*ecdsa.PrivateKey, common.Address) {
		key, err := crypto.GenerateKey()
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		return key, crypto.PubkeyToAddress(key.PublicKey)
	}
	keyA, candidateA := newKey()
	keyB, candidateB := newKey()
	keyC, outsider := newKey()
	keyD, payer := newKey()

	// TIPSigning and TIP2019 are active, TIPSignTxRules is not scheduled.
	chainConfig := &params.ChainConfig{
		ChainID:                big.NewInt(1338),
		HomesteadBlock:         new(big.Int),
		TIP2019Block:           new(big.Int),
		TIPSigningBlock:        new(big.Int),
		TIPXDCXBlock:           big.NewInt(0),
		TIPTRC21FeeBlock:       big.NewInt(0),
		Gas50xBlock:            big.NewInt(0),
		TRC21IssuerSMC:         params.TestnetChainConfig.TRC21IssuerSMC,
		XDCXListingSMC:         params.TestnetChainConfig.XDCXListingSMC,
		RelayerRegistrationSMC: params.TestnetChainConfig.RelayerRegistrationSMC,
		LendingRegistrationSMC: params.TestnetChainConfig.LendingRegistrationSMC,
		Ethash:                 new(params.EthashConfig),
	}
	genesis := &core.Genesis{
		Config:     chainConfig,
		Alloc:      types.GenesisAlloc{payer: {Balance: big.NewInt(params.Ether)}},
		Difficulty: big.NewInt(1),
		GasLimit:   params.XDCGenesisGasLimit,
	}
	engine := &signerSourceFaker{Engine: ethash.NewFaker(), signers: []common.Address{candidateA, candidateB}}
	chain, err := core.NewBlockChain(rawdb.NewMemoryDatabase(), nil, genesis, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create blockchain: %v", err)
	}
	defer chain.Stop()

	parent := chain.GetBlockByNumber(0)
	header := &types.Header{
		ParentHash: parent.Hash(),
		Difficulty: big.NewInt(1),
		Number:     big.NewInt(1),
		Time:       parent.Time() + 1,
		GasLimit:   params.XDCGenesisGasLimit,
	}
	worker := &worker{
		config:      &Config{GasCeil: params.XDCGenesisGasLimit, GasPrice: big.NewInt(1)},
		chainConfig: chainConfig,
		engine:      engine,
		chain:       chain,
	}
	if err := worker.makeCurrent(parent, header); err != nil {
		t.Fatalf("failed to create current work: %v", err)
	}

	sign := func(key *ecdsa.PrivateKey, tx *types.Transaction) *types.Transaction {
		signed, err := types.SignTx(tx, types.HomesteadSigner{}, key)
		if err != nil {
			t.Fatalf("sign tx: %v", err)
		}
		return signed
	}
	// Block 1 can only sign block 0.
	honestA := sign(keyA, types.NewTransaction(0, common.BlockSignersBinary, new(big.Int), 200000, new(big.Int), signTxData(0)))
	secondA := sign(keyA, types.NewTransaction(1, common.BlockSignersBinary, new(big.Int), 200000, new(big.Int), signTxData(0)))
	malformedB := sign(keyB, types.NewTransaction(0, common.BlockSignersBinary, new(big.Int), 200000, new(big.Int), make([]byte, 100)))
	outsiderC := sign(keyC, types.NewTransaction(0, common.BlockSignersBinary, new(big.Int), 200000, new(big.Int), signTxData(0)))
	transfer := sign(keyD, types.NewTransaction(0, common.HexToAddress("0xaa"), big.NewInt(1), params.TxGas, big.NewInt(1), nil))

	lazy := func(tx *types.Transaction) *txpool.LazyTransaction {
		fee := uint256.MustFromBig(tx.GasPrice())
		return &txpool.LazyTransaction{Hash: tx.Hash(), Tx: tx, Time: time.Now(), GasFeeCap: fee, GasTipCap: fee, Gas: tx.Gas()}
	}
	txs, specialTxs := newTransactionsByPriceAndNonce(worker.current.signer, map[common.Address][]*txpool.LazyTransaction{
		candidateA: {lazy(honestA), lazy(secondA)},
		candidateB: {lazy(malformedB)},
		outsider:   {lazy(outsiderC)},
		payer:      {lazy(transfer)},
	}, nil, nil)

	worker.current.commitTransactions(new(event.TypeMux), map[common.Address]*big.Int{}, txs, specialTxs, chain, &event.Feed{})

	committed := make(map[common.Hash]bool)
	for _, tx := range worker.current.txs {
		committed[tx.Hash()] = true
	}
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
	if len(worker.current.txs) != 2 {
		t.Fatalf("committed %d transactions, want 2", len(worker.current.txs))
	}
}

// signTxData is a sign(number, hash) call.
func signTxData(number uint64) []byte {
	data := common.Hex2Bytes(common.HexSignMethod)
	data = append(data, common.LeftPadBytes(new(big.Int).SetUint64(number).Bytes(), 32)...)
	return append(data, common.Hash{1}.Bytes()...)
}
