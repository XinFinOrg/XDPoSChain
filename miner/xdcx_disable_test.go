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
	"math/big"
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
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

// TestRejectsXDCXSystemTxAfterDisableFork pins the miner half: a transaction
// admitted before the fork crossed must not be sealed into a block past it.
func TestRejectsXDCXSystemTxAfterDisableFork(t *testing.T) {
	work := &Work{
		config: &params.ChainConfig{
			TIPXDCXBlock:                big.NewInt(0),
			TIPXDCXReceiverDisableBlock: big.NewInt(100),
		},
		header: &types.Header{Number: big.NewInt(100)},
	}
	systemTx := types.NewTransaction(0, common.XDCXAddrBinary, common.Big0, params.TxGas, common.Big1, nil)
	if !work.rejectsXDCXSystemTx(systemTx) {
		t.Fatal("expected a system transaction to be rejected after the disable fork")
	}
	regularTx := types.NewTransaction(0, common.Address{0x01}, common.Big0, params.TxGas, common.Big1, nil)
	if work.rejectsXDCXSystemTx(regularTx) {
		t.Fatal("expected a regular transaction to be kept after the disable fork")
	}
	work.header.Number = big.NewInt(99)
	if work.rejectsXDCXSystemTx(systemTx) {
		t.Fatal("expected a system transaction to be kept before the disable fork")
	}
}

// TestRejectsXDCXSystemTxInMinerDisableWindow pins the window between the two
// disable forks: the miner already stopped writing the XDCx roots while
// importers still read them, so a system transaction must not be sealed.
func TestRejectsXDCXSystemTxInMinerDisableWindow(t *testing.T) {
	work := &Work{
		config: &params.ChainConfig{
			ChainID:                     big.NewInt(1339),
			TIPXDCXBlock:                big.NewInt(0),
			TIPXDCXMinerDisableBlock:    big.NewInt(50),
			TIPXDCXReceiverDisableBlock: big.NewInt(100),
		},
		header: &types.Header{Number: big.NewInt(49)},
	}
	systemTx := types.NewTransaction(0, common.XDCXAddrBinary, common.Big0, params.TxGas, common.Big1, nil)
	if work.rejectsXDCXSystemTx(systemTx) {
		t.Fatal("expected a system transaction to be kept before the miner disable fork")
	}
	for _, number := range []int64{50, 99, 100} {
		work.header.Number = big.NewInt(number)
		if !work.rejectsXDCXSystemTx(systemTx) {
			t.Fatalf("expected a system transaction to be rejected at block %d", number)
		}
	}
	work.header.Number = big.NewInt(50)
	regularTx := types.NewTransaction(0, common.Address{0x01}, common.Big0, params.TxGas, common.Big1, nil)
	if work.rejectsXDCXSystemTx(regularTx) {
		t.Fatal("expected a regular transaction to be kept in the miner disable window")
	}
}

// TestCommitTransactionsSkipsXDCXSystemTxAfterDisableFork pins the loop half: a
// transaction admitted before the fork crossed is popped, not sealed. A regular
// transaction sealed in the same round is the control that keeps the loop honest.
func TestCommitTransactionsSkipsXDCXSystemTxAfterDisableFork(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to create test key: %v", err)
	}
	from := crypto.PubkeyToAddress(key.PublicKey)
	key2, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to create second test key: %v", err)
	}
	from2 := crypto.PubkeyToAddress(key2.PublicKey)
	chainConfig := &params.ChainConfig{
		ChainID:                     big.NewInt(1339),
		HomesteadBlock:              new(big.Int),
		EIP150Block:                 new(big.Int),
		EIP155Block:                 new(big.Int),
		EIP158Block:                 new(big.Int),
		ByzantiumBlock:              new(big.Int),
		TIPTRC21FeeBlock:            new(big.Int),
		Gas50xBlock:                 new(big.Int),
		TRC21IssuerSMC:              params.TestnetChainConfig.TRC21IssuerSMC,
		XDCXListingSMC:              params.TestnetChainConfig.XDCXListingSMC,
		RelayerRegistrationSMC:      params.TestnetChainConfig.RelayerRegistrationSMC,
		LendingRegistrationSMC:      params.TestnetChainConfig.LendingRegistrationSMC,
		TIPXDCXBlock:                new(big.Int),
		TIPXDCXReceiverDisableBlock: big.NewInt(1),
		Ethash:                      new(params.EthashConfig),
	}
	genesis := &core.Genesis{
		Config:     chainConfig,
		Alloc:      types.GenesisAlloc{from: {Balance: big.NewInt(params.Ether)}, from2: {Balance: big.NewInt(params.Ether)}},
		Difficulty: big.NewInt(1),
		GasLimit:   params.XDCGenesisGasLimit,
	}
	engine := ethash.NewFaker()
	chain, err := core.NewBlockChain(rawdb.NewMemoryDatabase(), nil, genesis, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create blockchain: %v", err)
	}
	defer chain.Stop()

	parent := chain.GetBlockByNumber(0)
	if parent == nil {
		t.Fatal("expected genesis block")
	}
	// Block 0 keeps the receiver fork on, block 1 is the first one past it.
	header := &types.Header{
		ParentHash: parent.Hash(),
		Difficulty: big.NewInt(1),
		Number:     big.NewInt(1),
		Time:       parent.Time() + 1,
		GasLimit:   params.XDCGenesisGasLimit,
		BaseFee:    new(big.Int),
	}
	w := &worker{
		config:      &Config{GasCeil: params.XDCGenesisGasLimit, GasPrice: big.NewInt(1)},
		chainConfig: chainConfig,
		engine:      engine,
		chain:       chain,
	}
	if err := w.makeCurrent(parent, header); err != nil {
		t.Fatalf("failed to create current work: %v", err)
	}
	tx, err := types.SignTx(types.NewTransaction(0, common.XDCXAddrBinary, common.Big0, params.TxGas, big.NewInt(1), nil), types.LatestSigner(chainConfig), key)
	if err != nil {
		t.Fatalf("failed to sign transaction: %v", err)
	}
	regTx, err := types.SignTx(types.NewTransaction(0, common.Address{0x02}, common.Big0, params.TxGas, big.NewInt(1), nil), types.LatestSigner(chainConfig), key2)
	if err != nil {
		t.Fatalf("failed to sign regular transaction: %v", err)
	}
	fee := uint256.NewInt(1)
	lazy := &txpool.LazyTransaction{Hash: tx.Hash(), Tx: tx, Time: time.Now(), GasFeeCap: fee, GasTipCap: fee, Gas: tx.Gas()}
	lazyReg := &txpool.LazyTransaction{Hash: regTx.Hash(), Tx: regTx, Time: time.Now(), GasFeeCap: fee, GasTipCap: fee, Gas: regTx.Gas()}
	txs, specialTxs := newTransactionsByPriceAndNonce(w.current.signer, map[common.Address][]*txpool.LazyTransaction{
		from:  {lazy},
		from2: {lazyReg},
	}, nil, header.BaseFee)

	w.current.commitTransactions(new(event.TypeMux), map[common.Address]*big.Int{}, txs, specialTxs, chain, &event.Feed{})
	if w.current.tcount != 1 || len(w.current.txs) != 1 || w.current.txs[0].Hash() != regTx.Hash() {
		t.Fatalf("sealed %d transactions (tcount %d), want only the regular transaction sealed and the post-fork system transaction skipped", len(w.current.txs), w.current.tcount)
	}
}
