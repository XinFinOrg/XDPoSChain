// Copyright 2026 The go-ethereum Authors
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
	"crypto/ecdsa"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// eip8246CreateTx returns a transaction that deploys the EIP-8246 probe
// contract: the initcode stores a value in slot 5, then self-destructs with
// itself as the beneficiary, all within the creation transaction.
func eip8246CreateTx(t *testing.T, key *ecdsa.PrivateKey, config *params.ChainConfig, value *big.Int) *types.Transaction {
	t.Helper()

	// PUSH1 0x2a; PUSH1 0x05; SSTORE; ADDRESS; SELFDESTRUCT
	initcode := []byte{0x60, 0x2a, 0x60, 0x05, 0x55, 0x30, 0xff}
	gasPrice := new(big.Int).Mul(big.NewInt(20), big.NewInt(params.GWei))
	tx, err := types.SignTx(types.NewContractCreation(0, value, 1_000_000, gasPrice, initcode), types.LatestSigner(config), key)
	if err != nil {
		t.Fatalf("failed to sign the creation transaction: %v", err)
	}
	return tx
}

// TestEIP8246SelfdestructNoBurn drives the Amsterdam rule through block
// processing: a contract created and self-destructed to itself within the
// creation transaction keeps its balance, while nonce, code and storage are
// cleared at finalisation.
func TestEIP8246SelfdestructNoBurn(t *testing.T) {
	var (
		key, _  = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		sender  = crypto.PubkeyToAddress(key.PublicKey)
		value   = big.NewInt(1_000_000)
		slot    = common.BigToHash(big.NewInt(0x05))
		config  = *params.AllEthashProtocolChanges // Amsterdam active from block 0
		created = crypto.CreateAddress(sender, 0)
	)
	db := rawdb.NewMemoryDatabase()
	gspec := &Genesis{
		Config: &config,
		Alloc:  types.GenesisAlloc{sender: {Balance: big.NewInt(params.Ether)}},
	}
	genesis := gspec.MustCommit(db)

	blocks, receipts := GenerateChain(&config, genesis, ethash.NewFaker(), db, 1, func(i int, b *BlockGen) {
		b.AddTx(eip8246CreateTx(t, key, &config, value))
	})
	if status := receipts[0][0].Status; status != types.ReceiptStatusSuccessful {
		t.Fatalf("creation transaction failed with status %d", status)
	}
	statedb, err := state.New(blocks[0].Root(), state.NewDatabase(db))
	if err != nil {
		t.Fatalf("failed to open the post-state: %v", err)
	}
	if !statedb.Exist(created) {
		t.Fatalf("created contract was deleted instead of preserved")
	}
	if got := statedb.GetBalance(created); got.Cmp(value) != 0 {
		t.Errorf("created contract balance = %v, want %v", got, value)
	}
	if got := statedb.GetNonce(created); got != 0 {
		t.Errorf("created contract nonce = %d, want 0", got)
	}
	if code := statedb.GetCode(created); len(code) != 0 {
		t.Errorf("created contract code = %x, want empty", code)
	}
	if got := statedb.GetState(created, slot); got != (common.Hash{}) {
		t.Errorf("created contract storage = %x, want empty", got)
	}
}

// TestEIP8246SelfdestructRefunded verifies that ETH sent back to a
// same-transaction selfdestructed account is retained at finalisation instead
// of being dropped with the deleted account. The factory funds the account
// twice after SELFDESTRUCT.
func TestEIP8246SelfdestructRefunded(t *testing.T) {
	var (
		key, _      = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		sender      = crypto.PubkeyToAddress(key.PublicKey)
		factory     = common.HexToAddress("0xfac8246")
		beneficiary = common.HexToAddress("0xbeef")
		config      = *params.AllEthashProtocolChanges // Amsterdam active from block 0
		gasPrice    = new(big.Int).Mul(big.NewInt(20), big.NewInt(params.GWei))
	)
	// The child initcode selfdestructs to another account. The factory then
	// sends it 7 and 8 wei after it is marked for selfdestruction.
	childInit := append([]byte{0x73}, beneficiary.Bytes()...)
	childInit = append(childInit, 0xff)
	var word [32]byte
	copy(word[32-len(childInit):], childInit)
	factoryCode := append([]byte{0x7f}, word[:]...)
	factoryCode = append(factoryCode, 0x5f, 0x52) // PUSH0; MSTORE
	// CREATE(value=0, offset=10, length=22), then store the returned address.
	factoryCode = append(factoryCode, 0x60, byte(len(childInit)), 0x60, byte(32-len(childInit)), 0x5f, 0xf0, 0x5f, 0x52)
	for _, amount := range []byte{7, 8} {
		// CALL(child, value=amount) with empty input/output.
		factoryCode = append(factoryCode, 0x5f, 0x5f, 0x5f, 0x5f, 0x60, amount, 0x5f, 0x51, 0x5a, 0xf1, 0x50)
	}
	factoryCode = append(factoryCode, 0x00)

	db := rawdb.NewMemoryDatabase()
	gspec := &Genesis{
		Config: &config,
		Alloc: types.GenesisAlloc{
			sender:  {Balance: big.NewInt(params.Ether)},
			factory: {Nonce: 1, Code: factoryCode, Balance: big.NewInt(15)},
		},
	}
	genesis := gspec.MustCommit(db)

	tx, err := types.SignTx(types.NewTransaction(0, factory, big.NewInt(0), 1_000_000, gasPrice, nil), types.LatestSigner(&config), key)
	if err != nil {
		t.Fatalf("failed to sign the factory transaction: %v", err)
	}
	blocks, receipts := GenerateChain(&config, genesis, ethash.NewFaker(), db, 1, func(i int, b *BlockGen) {
		b.AddTx(tx)
	})
	if status := receipts[0][0].Status; status != types.ReceiptStatusSuccessful {
		t.Fatalf("factory transaction failed with status %d", status)
	}
	child := crypto.CreateAddress(factory, 1)
	statedb, err := state.New(blocks[0].Root(), state.NewDatabase(db))
	if err != nil {
		t.Fatalf("failed to open the post-state: %v", err)
	}
	if !statedb.Exist(child) {
		t.Fatalf("refunded child was deleted instead of preserved")
	}
	if got := statedb.GetBalance(child); got.Cmp(big.NewInt(15)) != 0 {
		t.Errorf("refunded child balance = %v, want 15", got)
	}
	if got := statedb.GetNonce(child); got != 0 {
		t.Errorf("refunded child nonce = %d, want 0", got)
	}
	if code := statedb.GetCode(child); len(code) != 0 {
		t.Errorf("refunded child code = %x, want empty", code)
	}
}

// TestSelfdestructBurnWithoutEIP8246 pins the pre-Amsterdam block processing:
// the same creation transaction burns the balance and removes the account.
func TestSelfdestructBurnWithoutEIP8246(t *testing.T) {
	var (
		key, _  = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		sender  = crypto.PubkeyToAddress(key.PublicKey)
		value   = big.NewInt(1_000_000)
		config  = *params.AllEthashProtocolChanges
		created = crypto.CreateAddress(sender, 0)
	)
	config.AmsterdamBlock = nil

	db := rawdb.NewMemoryDatabase()
	gspec := &Genesis{
		Config: &config,
		Alloc:  types.GenesisAlloc{sender: {Balance: big.NewInt(params.Ether)}},
	}
	genesis := gspec.MustCommit(db)

	blocks, receipts := GenerateChain(&config, genesis, ethash.NewFaker(), db, 1, func(i int, b *BlockGen) {
		b.AddTx(eip8246CreateTx(t, key, &config, value))
	})
	if status := receipts[0][0].Status; status != types.ReceiptStatusSuccessful {
		t.Fatalf("creation transaction failed with status %d", status)
	}
	statedb, err := state.New(blocks[0].Root(), state.NewDatabase(db))
	if err != nil {
		t.Fatalf("failed to open the post-state: %v", err)
	}
	if statedb.Exist(created) {
		t.Errorf("self-destructed contract survived without EIP-8246")
	}
	if got := statedb.GetBalance(created); got.Sign() != 0 {
		t.Errorf("self-destructed contract balance = %v, want 0", got)
	}
}

// TestEIP8246Create2RecreatesBalanceOnly verifies that an EIP-8246
// balance-only account does not block recreating the same CREATE2 address in a
// later transaction. The second creation contributes another wei to the
// preserved balance, proving that it executed rather than collided.
func TestEIP8246Create2RecreatesBalanceOnly(t *testing.T) {
	var (
		key, _   = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		sender   = crypto.PubkeyToAddress(key.PublicKey)
		factory  = common.HexToAddress("0xfac8246")
		config   = *params.AllEthashProtocolChanges // Amsterdam active from block 0
		init     = []byte{0x30, 0xff}               // ADDRESS; SELFDESTRUCT
		gasPrice = new(big.Int).Mul(big.NewInt(20), big.NewInt(params.GWei))
	)
	// Factory code: PUSH32 <init>; PUSH0; MSTORE; PUSH1 1 (salt); PUSH1 2 (len);
	// PUSH1 30 (offset); CALLVALUE; CREATE2; POP; STOP.
	var word [32]byte
	copy(word[32-len(init):], init)
	factoryCode := append([]byte{0x7f}, word[:]...)
	factoryCode = append(factoryCode,
		0x5f, 0x52, // PUSH0; MSTORE
		0x60, 0x01, // salt
		0x60, byte(len(init)),
		0x60, byte(32-len(init)),
		0x34, // CALLVALUE
		0xf5, // CREATE2
		0x50, // POP
		0x00,
	)
	gspec := &Genesis{
		Config: &config,
		Alloc: types.GenesisAlloc{
			sender:  {Balance: big.NewInt(params.Ether)},
			factory: {Nonce: 1, Code: factoryCode},
		},
	}
	db := rawdb.NewMemoryDatabase()
	genesis := gspec.MustCommit(db)

	var salt [32]byte
	salt[31] = 1
	child := crypto.CreateAddress2(factory, salt, crypto.Keccak256(init))

	blocks, receipts := GenerateChain(&config, genesis, ethash.NewFaker(), db, 2, func(i int, b *BlockGen) {
		value := big.NewInt(5)
		if i == 1 {
			value = big.NewInt(1)
		}
		tx, err := types.SignTx(types.NewTransaction(uint64(i), factory, value, 1_000_000, gasPrice, nil), types.LatestSigner(&config), key)
		if err != nil {
			t.Fatalf("failed to sign transaction %d: %v", i, err)
		}
		b.AddTx(tx)
	})
	for i, rs := range receipts {
		for _, receipt := range rs {
			if receipt.Status != types.ReceiptStatusSuccessful {
				t.Fatalf("transaction in block %d failed with status %d", i, receipt.Status)
			}
		}
	}
	statedb, err := state.New(blocks[1].Root(), state.NewDatabase(db))
	if err != nil {
		t.Fatalf("failed to open the post-state: %v", err)
	}
	// The preserved account keeps 5 from the first block and gains the 1 wei of
	// the second creation, so a collision would have left it at 5.
	if !statedb.Exist(child) {
		t.Fatalf("CREATE2 child does not exist after the second creation")
	}
	if got := statedb.GetBalance(child); got.Cmp(big.NewInt(6)) != 0 {
		t.Errorf("CREATE2 child balance = %v, want 6", got)
	}
	if got := statedb.GetNonce(child); got != 0 {
		t.Errorf("CREATE2 child nonce = %d, want 0", got)
	}
	if code := statedb.GetCode(child); len(code) != 0 {
		t.Errorf("CREATE2 child code = %x, want empty", code)
	}
}
