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

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/event"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// TestWorkerSpecialTxsAfterBlockGasBurnt checks that a randomize transaction
// that uses up the block gas pool does not stop the miner from packing the sign
// transactions after it, which take no block gas, and that a later randomize
// transaction that no longer fits is skipped on its own.
func TestWorkerSpecialTxsAfterBlockGasBurnt(t *testing.T) {
	newKey := func() (*ecdsa.PrivateKey, common.Address) {
		key, err := crypto.GenerateKey()
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		return key, crypto.PubkeyToAddress(key.PublicKey)
	}
	keyA, signerA := newKey()
	keyB, signerB := newKey()
	keyC, signerC := newKey()

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
	// The randomize contract is replaced by an endless loop, so a call to it
	// runs out of gas and uses its whole gas limit.
	genesis := &core.Genesis{
		Config:     chainConfig,
		Alloc:      types.GenesisAlloc{common.RandomizeSMCBinary: {Balance: new(big.Int), Code: []byte{0x5b, 0x60, 0x00, 0x56}}},
		Difficulty: big.NewInt(1),
		GasLimit:   params.XDCGenesisGasLimit,
	}
	engine := &signerSourceFaker{Engine: ethash.NewFaker(), signers: []common.Address{signerA, signerB, signerC}}
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
	secret := append(common.Hex2Bytes(common.HexSetSecret), common.Hash{1}.Bytes()...)
	burner := sign(keyA, types.NewTransaction(0, common.RandomizeSMCBinary, new(big.Int), header.GasLimit-10000, new(big.Int), secret))
	tooBig := sign(keyB, types.NewTransaction(0, common.RandomizeSMCBinary, new(big.Int), 200000, new(big.Int), secret))
	signA := sign(keyA, types.NewTransaction(1, common.BlockSignersBinary, new(big.Int), 200000, new(big.Int), signTxData(0)))
	signC := sign(keyC, types.NewTransaction(0, common.BlockSignersBinary, new(big.Int), 200000, new(big.Int), signTxData(0)))

	// The special transactions in a fixed order: the burner first.
	worker.current.commitTransactions(new(event.TypeMux), map[common.Address]*big.Int{}, nil, types.Transactions{burner, tooBig, signA, signC}, chain, &event.Feed{})

	committed := make(map[common.Hash]bool)
	for _, tx := range worker.current.txs {
		committed[tx.Hash()] = true
	}
	for _, want := range []struct {
		name string
		tx   *types.Transaction
		in   bool
	}{
		{"randomize tx burning the block gas", burner, true},
		{"randomize tx that no longer fits", tooBig, false},
		{"sign tx after the burner, same sender", signA, true},
		{"sign tx after the burner, another signer", signC, true},
	} {
		if committed[want.tx.Hash()] != want.in {
			t.Errorf("%s: committed = %v, want %v", want.name, committed[want.tx.Hash()], want.in)
		}
	}
}
