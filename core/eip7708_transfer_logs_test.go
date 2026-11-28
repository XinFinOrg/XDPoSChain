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
	"bytes"
	"crypto/ecdsa"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/tracing"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/holiman/uint256"
)

// eip7708TestCode is the Solidity test contract from go-ethereum's EIP-7708
// test (core/eth_transfer_logs_test.go). test() forwards half of the value it
// received to 0xDeaDBeef, whose test2() emits an event and self-destructs to
// 0x12345678:
//
//	pragma solidity >=0.4.22 <0.6.0;
//
//	contract TestLogs {
//	  address public constant target_contract = 0x00000000000000000000000000000000DeaDBeef;
//	  address payable constant selfdestruct_addr = 0x0000000000000000000000000000000012345678;
//
//	  event Response(bool success, bytes data);
//	  event TestEvent();
//	  event TestEvent2();
//
//	  function test() public payable {
//	    emit TestEvent();
//	    target_contract.call.value(msg.value/2)(abi.encodeWithSignature("test2()"));
//	  }
//	  function test2() public payable {
//	    emit TestEvent2();
//	    selfdestruct(selfdestruct_addr);
//	  }
//	}
//
// The bytecode-level cases below mirror go-ethereum's core/eip7708_test.go
// boundary matrix (DELEGATECALL, CREATE2, failed CREATE, special recipients,
// fee exclusion and the fork gate), adapted to this tree's big.Int balances
// and GenerateChain harness.
var eip7708TestCode = common.FromHex("6080604052600436106100345760003560e01c8063574ffc311461003957806366e41cb714610090578063f8a8fd6d1461009a575b600080fd5b34801561004557600080fd5b5061004e6100a4565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b6100986100ac565b005b6100a26100f5565b005b63deadbeef81565b7f38e80b5c85ba49b7280ccc8f22548faa62ae30d5a008a1b168fba5f47f5d1ee560405160405180910390a1631234567873ffffffffffffffffffffffffffffffffffffffff16ff5b7f24ec1d3ff24c2f6ff210738839dbc339cd45a5294d85c79361016243157aae7b60405160405180910390a163deadbeef73ffffffffffffffffffffffffffffffffffffffff166002348161014657fe5b046040516024016040516020818303038152906040527f66e41cb7000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff83818316178352505050506040518082805190602001908083835b602083106101fd57805182526020820191506020810190506020830392506101da565b6001836020036101000a03801982511681845116808217855250505050505090500191505060006040518083038185875af1925050503d806000811461025f576040519150601f19603f3d011682016040523d82523d6000602084013e610264565b606091505b50505056fea265627a7a723158202cce817a434785d8560c200762f972d453ccd30694481be7545f9035a512826364736f6c63430005100032")

var (
	eip7708Key    = "b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291"
	eip7708Callee = common.HexToAddress("cafebabe")
	eip7708Target = common.HexToAddress("0x00000000000000000000000000000000DeaDBeef")
	eip7708Benef  = common.HexToAddress("0x0000000000000000000000000000000012345678")
)

// eip7708TransferLog builds the EIP-7708 transfer log expected for a value
// move from -> to. The system log uses params.SystemAddress as emitter and the
// ERC-20 Transfer ABI with a 32-byte amount.
func eip7708TransferLog(from, to common.Address, amount uint64) *types.Log {
	data := make([]byte, 32)
	binary.BigEndian.PutUint64(data[24:], amount)
	return &types.Log{
		Address: params.SystemAddress,
		Topics: []common.Hash{
			params.EthTransferLogEvent,
			common.BytesToHash(from.Bytes()),
			common.BytesToHash(to.Bytes()),
		},
		Data: data,
	}
}

// runEIP7708Transfer executes the CALL/SELFDESTRUCT scenario of the upstream
// EIP-7708 test against the given chain config and returns the receipt logs.
func runEIP7708Transfer(t *testing.T, config *params.ChainConfig, value int64) (*types.Block, *types.Receipt, *types.Transaction, common.Address) {
	t.Helper()

	key, sender := eip7708KeyPair(t)
	gspec := &Genesis{
		Config: config,
		Alloc: types.GenesisAlloc{
			sender:        {Balance: big.NewInt(params.Ether)},
			eip7708Callee: {Code: eip7708TestCode},
			eip7708Target: {Code: eip7708TestCode},
		},
	}
	db := rawdb.NewMemoryDatabase()
	genesis := gspec.MustCommit(db)

	signer := types.LatestSigner(config)
	tx, err := types.SignTx(types.NewTransaction(
		0, eip7708Callee, big.NewInt(value), 500_000, eip7708GasPrice(), common.FromHex("f8a8fd6d"),
	), signer, key)
	if err != nil {
		t.Fatalf("failed to sign the transfer transaction: %v", err)
	}
	blocks, receipts := GenerateChain(config, genesis, ethash.NewFaker(), db, 1, func(i int, b *BlockGen) {
		b.AddTx(tx)
	})
	if status := receipts[0][0].Status; status != types.ReceiptStatusSuccessful {
		t.Fatalf("transfer transaction failed with status %d", status)
	}
	return blocks[0], receipts[0][0], tx, sender
}

// TestEIP7708TransferLogs drives the Amsterdam transfer logs through block
// processing: the transaction value, the CALL value and the SELFDESTRUCT value
// each produce one system log, interleaved with the contract's own events.
func TestEIP7708TransferLogs(t *testing.T) {
	config := *params.AllEthashProtocolChanges // Amsterdam active from block 0
	block, receipt, tx, sender := runEIP7708Transfer(t, &config, 1_000_000_000)

	var (
		testEvent  = crypto.Keccak256Hash([]byte("TestEvent()"))
		testEvent2 = crypto.Keccak256Hash([]byte("TestEvent2()"))
		want       = []*types.Log{
			eip7708TransferLog(sender, eip7708Callee, 1_000_000_000),
			{Address: eip7708Callee, Topics: []common.Hash{testEvent}},
			eip7708TransferLog(eip7708Callee, eip7708Target, 500_000_000),
			{Address: eip7708Target, Topics: []common.Hash{testEvent2}},
			eip7708TransferLog(eip7708Target, eip7708Benef, 500_000_000),
		}
	)
	if len(receipt.Logs) != len(want) {
		t.Fatalf("log count = %d, want %d", len(receipt.Logs), len(want))
	}
	for i, log := range receipt.Logs {
		eip7708CheckRawLog(t, log, want[i])
		if log.BlockNumber != block.NumberU64() {
			t.Errorf("log %d block number = %d, want %d", i, log.BlockNumber, block.NumberU64())
		}
		if log.TxHash != tx.Hash() || log.TxIndex != 0 || log.Index != uint(i) {
			t.Errorf("log %d metadata = (%v, %d, %d), want (%v, 0, %d)", i, log.TxHash, log.TxIndex, log.Index, tx.Hash(), i)
		}
	}
}

// TestEIP7708ZeroValue pins that a transaction moving no value produces no
// transfer logs, only the contract's own events.
func TestEIP7708ZeroValue(t *testing.T) {
	config := *params.AllEthashProtocolChanges
	_, receipt, _, _ := runEIP7708Transfer(t, &config, 0)

	eip7708NoTransferLog(t, receipt.Logs, 2)
}

// TestEIP7708PreAmsterdam pins the fork gate: the same scenario before
// Amsterdam emits the contract events only.
func TestEIP7708PreAmsterdam(t *testing.T) {
	config := *params.AllEthashProtocolChanges
	config.AmsterdamBlock = nil

	_, receipt, _, _ := runEIP7708Transfer(t, &config, 1_000_000_000)

	eip7708NoTransferLog(t, receipt.Logs, 2)
}

// TestEIP7708SelfTransfer pins that a transfer to self moves no value and
// therefore emits no transfer log.
func TestEIP7708SelfTransfer(t *testing.T) {
	config := *params.AllEthashProtocolChanges
	key, sender := eip7708KeyPair(t)
	gspec := &Genesis{Config: &config, Alloc: types.GenesisAlloc{sender: {Balance: big.NewInt(params.Ether)}}}
	db := rawdb.NewMemoryDatabase()
	genesis := gspec.MustCommit(db)
	tx, err := types.SignTx(types.NewTransaction(
		0, sender, big.NewInt(params.Ether/2), params.TxGas, eip7708GasPrice(), nil,
	), types.LatestSigner(&config), key)
	if err != nil {
		t.Fatalf("failed to sign the self transfer: %v", err)
	}
	_, receipts := GenerateChain(&config, genesis, ethash.NewFaker(), db, 1, func(i int, b *BlockGen) {
		b.AddTx(tx)
	})
	if status := receipts[0][0].Status; status != types.ReceiptStatusSuccessful {
		t.Fatalf("self transfer failed with status %d", status)
	}
	if logs := receipts[0][0].Logs; len(logs) != 0 {
		t.Fatalf("self transfer emitted %d log(s), want none", len(logs))
	}
}

// eip7708CallCode returns runtime code that CALLs target with one wei and then
// either reverts (revert=true) or stops. The caller must be funded with one wei.
func eip7708CallCode(target common.Address, revert bool) []byte {
	code := []byte{0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x01, 0x73}
	code = append(code, target.Bytes()...)
	code = append(code, 0x5a, 0xf1, 0x50, 0x60, 0x00, 0x60, 0x00)
	if revert {
		code = append(code, 0xfd)
	} else {
		code = append(code, 0x00)
	}
	return code
}

// TestEIP7708RevertedTransferLog pins that the transfer log of a reverted call
// frame is discarded with the rest of the frame's state changes.
func TestEIP7708RevertedTransferLog(t *testing.T) {
	var (
		config   = *params.AllEthashProtocolChanges
		contract = common.HexToAddress("0x00000000000000000000000000000000000000aa")
		target   = common.HexToAddress("0x00000000000000000000000000000000000000bb")
	)
	key, sender := eip7708KeyPair(t)
	tests := []struct {
		name    string
		revert  bool
		wantLog int
	}{
		{name: "reverted frame", revert: true, wantLog: 0},
		{name: "committed frame", revert: false, wantLog: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gspec := &Genesis{
				Config: &config,
				Alloc: types.GenesisAlloc{
					sender:   {Balance: big.NewInt(params.Ether)},
					contract: {Balance: big.NewInt(1), Code: eip7708CallCode(target, tt.revert)},
				},
			}
			db := rawdb.NewMemoryDatabase()
			genesis := gspec.MustCommit(db)
			tx, err := types.SignTx(types.NewTransaction(
				0, contract, nil, 100_000, eip7708GasPrice(), nil,
			), types.LatestSigner(&config), key)
			if err != nil {
				t.Fatalf("failed to sign the call transaction: %v", err)
			}
			_, receipts := GenerateChain(&config, genesis, ethash.NewFaker(), db, 1, func(i int, b *BlockGen) {
				b.AddTx(tx)
			})
			logs := receipts[0][0].Logs
			if len(logs) != tt.wantLog {
				t.Fatalf("log count = %d, want %d", len(logs), tt.wantLog)
			}
			if tt.wantLog == 1 {
				want := eip7708TransferLog(contract, target, 1)
				if logs[0].Address != want.Address || !bytes.Equal(logs[0].Data, want.Data) {
					t.Fatalf("unexpected transfer log: %+v", logs[0])
				}
			}
		})
	}
}

// eip7708CallLogged returns runtime code that emits a LOG0 and then CALLs target
// with one wei, either reverting (revert=true) or stopping. The caller must be
// funded with one wei. The LOG0 pins that a reverted inner frame only drops its
// own logs, not the caller's.
func eip7708CallLogged(target common.Address, revert bool) []byte {
	code := []byte{0x60, 0x00, 0x60, 0x00, 0xa0, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x01, 0x73}
	code = append(code, target.Bytes()...)
	code = append(code, 0x5a, 0xf1, 0x50, 0x60, 0x00, 0x60, 0x00)
	if revert {
		code = append(code, 0xfd)
	} else {
		code = append(code, 0x00)
	}
	return code
}

// TestEIP7708OuterRevertDiscardsAllLogs pins that a reverted top-level call
// frame takes every log with it, including the transaction's own transfer log.
func TestEIP7708OuterRevertDiscardsAllLogs(t *testing.T) {
	var (
		config = *params.AllEthashProtocolChanges
		caller = common.HexToAddress("0x00000000000000000000000000000000000000d1")
		callee = common.HexToAddress("0x00000000000000000000000000000000000000d2")
	)
	receipt, _ := eip7708RunTx(t, &config, types.GenesisAlloc{
		caller: {Balance: big.NewInt(1), Code: eip7708CallCode(callee, true)},
		callee: {Code: []byte{0x00}},
	}, &caller, big.NewInt(1), 200_000, nil, common.Address{})
	if receipt.Status != types.ReceiptStatusFailed {
		t.Fatalf("reverting call status = %d, want failed", receipt.Status)
	}
	if len(receipt.Logs) != 0 {
		t.Fatalf("reverted transaction kept %d log(s), want none", len(receipt.Logs))
	}
}

// TestEIP7708InnerRevertKeepsOuterLog pins that a reverted inner call frame only
// drops its own transfer log: the transaction transfer and the caller's LOG0
// survive.
func TestEIP7708InnerRevertKeepsOuterLog(t *testing.T) {
	var (
		config   = *params.AllEthashProtocolChanges
		caller   = common.HexToAddress("0x00000000000000000000000000000000000000d3")
		reverter = common.HexToAddress("0x00000000000000000000000000000000000000d4")
	)
	receipt, sender := eip7708RunTx(t, &config, types.GenesisAlloc{
		caller:   {Balance: big.NewInt(1), Code: eip7708CallLogged(reverter, false)},
		reverter: {Code: []byte{0x60, 0x00, 0x60, 0x00, 0xfd}},
	}, &caller, big.NewInt(1), 200_000, nil, common.Address{})
	if receipt.Status != types.ReceiptStatusSuccessful {
		t.Fatalf("call transaction failed with status %d", receipt.Status)
	}
	if len(receipt.Logs) != 2 {
		t.Fatalf("log count = %d, want the transaction transfer and the caller LOG0", len(receipt.Logs))
	}
	eip7708CheckLog(t, receipt.Logs[0], eip7708TransferLog(sender, caller, 1))
	if receipt.Logs[1].Address != caller || len(receipt.Logs[1].Topics) != 0 || len(receipt.Logs[1].Data) != 0 {
		t.Fatalf("second log = %+v, want the caller LOG0", receipt.Logs[1])
	}
}

// TestEIP7708DelegateCallAttribution pins that a transfer made by code running
// under DELEGATECALL is attributed to the executing context, not to the
// implementation the code was taken from.
func TestEIP7708DelegateCallAttribution(t *testing.T) {
	var (
		config = *params.AllEthashProtocolChanges
		caller = common.HexToAddress("0x00000000000000000000000000000000000000d5")
		impl   = common.HexToAddress("0x00000000000000000000000000000000000000d6")
		callee = common.HexToAddress("0x00000000000000000000000000000000000000d7")
	)
	receipt, sender := eip7708RunTx(t, &config, types.GenesisAlloc{
		caller: {Balance: big.NewInt(10), Code: eip7708DelegateCallCode(impl)},
		impl:   {Code: eip7708CallLogged(callee, false)},
		callee: {Code: []byte{0x00}},
	}, &caller, big.NewInt(10), 300_000, nil, common.Address{})
	if receipt.Status != types.ReceiptStatusSuccessful {
		t.Fatalf("delegate call transaction failed with status %d", receipt.Status)
	}
	if len(receipt.Logs) != 3 {
		t.Fatalf("log count = %d, want the transaction transfer, the delegated LOG0 and the inner transfer", len(receipt.Logs))
	}
	eip7708CheckLog(t, receipt.Logs[0], eip7708TransferLog(sender, caller, 10))
	if receipt.Logs[1].Address != caller || len(receipt.Logs[1].Topics) != 0 || len(receipt.Logs[1].Data) != 0 {
		t.Fatalf("delegated LOG0 = %+v, want the executing context %v as emitter", receipt.Logs[1], caller)
	}
	eip7708CheckLog(t, receipt.Logs[2], eip7708TransferLog(caller, callee, 1))
}

// eip7708GasPrice returns the gas price used by the cases below.
func eip7708GasPrice() *big.Int {
	return new(big.Int).Mul(big.NewInt(20), big.NewInt(params.GWei))
}

// eip7708KeyPair loads the sender key shared by the cases below.
func eip7708KeyPair(t *testing.T) (*ecdsa.PrivateKey, common.Address) {
	t.Helper()

	key, err := crypto.HexToECDSA(eip7708Key)
	if err != nil {
		t.Fatalf("failed to load the sender key: %v", err)
	}
	return key, crypto.PubkeyToAddress(key.PublicKey)
}

// eip7708RunTx runs a single transaction in its own block against a genesis
// that funds the sender with one ether, and returns the receipt together with
// the sender. A nil to creates a contract from data; a zero coinbase keeps the
// genesis default.
func eip7708RunTx(t *testing.T, config *params.ChainConfig, alloc types.GenesisAlloc, to *common.Address, value *big.Int, gas uint64, data []byte, coinbase common.Address) (*types.Receipt, common.Address) {
	t.Helper()

	key, sender := eip7708KeyPair(t)
	funded := types.GenesisAlloc{sender: {Balance: big.NewInt(params.Ether)}}
	for addr, account := range alloc {
		funded[addr] = account
	}
	db := rawdb.NewMemoryDatabase()
	genesis := (&Genesis{Config: config, Alloc: funded}).MustCommit(db)

	var (
		tx  *types.Transaction
		err error
	)
	if to == nil {
		tx, err = types.SignTx(types.NewContractCreation(0, value, gas, eip7708GasPrice(), data), types.LatestSigner(config), key)
	} else {
		tx, err = types.SignTx(types.NewTransaction(0, *to, value, gas, eip7708GasPrice(), data), types.LatestSigner(config), key)
	}
	if err != nil {
		t.Fatalf("failed to sign the transaction: %v", err)
	}
	_, receipts := GenerateChain(config, genesis, ethash.NewFaker(), db, 1, func(i int, b *BlockGen) {
		if coinbase != (common.Address{}) {
			b.SetCoinbase(coinbase)
		}
		b.AddTx(tx)
	})
	return receipts[0][0], sender
}

// eip7708CheckRawLog compares an emitted log against the expected one: emitter,
// topics and data.
func eip7708CheckRawLog(t *testing.T, got, want *types.Log) {
	t.Helper()

	if got.Address != want.Address {
		t.Errorf("log address = %v, want %v", got.Address, want.Address)
	}
	if len(got.Topics) != len(want.Topics) {
		t.Fatalf("topic count = %d, want %d", len(got.Topics), len(want.Topics))
	}
	for i := range want.Topics {
		if got.Topics[i] != want.Topics[i] {
			t.Errorf("topic %d = %v, want %v", i, got.Topics[i], want.Topics[i])
		}
	}
	if !bytes.Equal(got.Data, want.Data) {
		t.Errorf("data = %x, want %x", got.Data, want.Data)
	}
}

// eip7708CheckLog compares an emitted log against the expected transfer log and
// pins the 32-byte amount encoding on its own.
func eip7708CheckLog(t *testing.T, got, want *types.Log) {
	t.Helper()

	eip7708CheckRawLog(t, got, want)
	if len(got.Data) != 32 {
		t.Errorf("data length = %d, want 32", len(got.Data))
	}
}

// eip7708NoTransferLog pins that a receipt carries exactly want logs and that
// none of them is an EIP-7708 system transfer log.
func eip7708NoTransferLog(t *testing.T, logs []*types.Log, want int) {
	t.Helper()

	if len(logs) != want {
		t.Fatalf("log count = %d, want %d contract events only", len(logs), want)
	}
	for i, log := range logs {
		if log.Address == params.SystemAddress {
			t.Errorf("log %d is an ETH transfer log, want contract events only", i)
		}
	}
}

// eip7708DelegateCallCode returns code that DELEGATECALLs target and stops.
// DELEGATECALL runs the callee's code in the caller's context and moves no
// value, so it must not produce a transfer log.
func eip7708DelegateCallCode(target common.Address) []byte {
	code := []byte{0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x73}
	code = append(code, target.Bytes()...)
	return append(code, 0x5a, 0xf4, 0x50, 0x00)
}

// eip7708Create2Code returns code that writes the one-byte init code 0x00 to
// memory and CREATE2s a contract endowed with value.
func eip7708Create2Code(value byte) []byte {
	return []byte{
		0x60, 0x00, 0x60, 0x00, 0x53, // MSTORE8(0, 0x00): init code is STOP
		0x60, 0x00, // salt
		0x60, 0x01, // size
		0x60, 0x00, // offset
		0x60, value, // endowment
		0xf5, // CREATE2
		0x50, // POP
		0x00, // STOP
	}
}

// TestEIP7708DelegateCallDoesNotLog pins that a DELEGATECALL frame moves no
// value and therefore adds no transfer log.
func TestEIP7708DelegateCallDoesNotLog(t *testing.T) {
	var (
		config = *params.AllEthashProtocolChanges
		caller = common.HexToAddress("0x00000000000000000000000000000000000000c1")
		target = common.HexToAddress("0x00000000000000000000000000000000000000c2")
	)
	receipt, sender := eip7708RunTx(t, &config, types.GenesisAlloc{
		caller: {Code: eip7708DelegateCallCode(target)},
		target: {Code: []byte{0x00}},
	}, &caller, big.NewInt(1), 200_000, nil, common.Address{})
	if receipt.Status != types.ReceiptStatusSuccessful {
		t.Fatalf("delegate call transaction failed with status %d", receipt.Status)
	}
	if len(receipt.Logs) != 1 {
		t.Fatalf("log count = %d, want the transaction transfer only", len(receipt.Logs))
	}
	eip7708CheckLog(t, receipt.Logs[0], eip7708TransferLog(sender, caller, 1))
}

// TestEIP7708Create2Endowment pins that a CREATE2 endowment is logged with the
// created address as recipient.
func TestEIP7708Create2Endowment(t *testing.T) {
	var (
		config  = *params.AllEthashProtocolChanges
		factory = common.HexToAddress("0x00000000000000000000000000000000000000c3")
	)
	receipt, _ := eip7708RunTx(t, &config, types.GenesisAlloc{
		factory: {Balance: big.NewInt(5), Code: eip7708Create2Code(5)},
	}, &factory, big.NewInt(0), 300_000, nil, common.Address{})
	if receipt.Status != types.ReceiptStatusSuccessful {
		t.Fatalf("create2 transaction failed with status %d", receipt.Status)
	}
	if len(receipt.Logs) != 1 {
		t.Fatalf("log count = %d, want the create2 endowment only", len(receipt.Logs))
	}
	created := crypto.CreateAddress2(factory, [32]byte{}, crypto.Keccak256([]byte{0x00}))
	eip7708CheckLog(t, receipt.Logs[0], eip7708TransferLog(factory, created, 5))
}

// TestEIP7708FailedCreateRollsBackLog pins that the endowment log of a failed
// contract creation is rolled back with the rest of the frame.
func TestEIP7708FailedCreateRollsBackLog(t *testing.T) {
	config := *params.AllEthashProtocolChanges
	// PUSH1 0x00; PUSH1 0x00; REVERT
	receipt, _ := eip7708RunTx(t, &config, nil, nil, big.NewInt(5), 500_000, []byte{0x60, 0x00, 0x60, 0x00, 0xfd}, common.Address{})
	if receipt.Status != types.ReceiptStatusFailed {
		t.Fatalf("reverting create status = %d, want failed", receipt.Status)
	}
	if len(receipt.Logs) != 0 {
		t.Fatalf("failed create kept %d log(s), want none", len(receipt.Logs))
	}
}

// TestEIP7708SpecialRecipients pins that value sent to a precompile, to the
// system address or to the coinbase address is logged like any other transfer.
func TestEIP7708SpecialRecipients(t *testing.T) {
	coinbase := common.HexToAddress("0x00000000000000000000000000000000000000c9")
	for _, tc := range []struct {
		name     string
		to       common.Address
		coinbase common.Address
	}{
		{name: "precompile", to: common.BytesToAddress([]byte{4})},
		{name: "system", to: params.SystemAddress},
		{name: "coinbase", to: coinbase, coinbase: coinbase},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := *params.AllEthashProtocolChanges
			to := tc.to
			receipt, sender := eip7708RunTx(t, &config, nil, &to, big.NewInt(1), 100_000, nil, tc.coinbase)
			if receipt.Status != types.ReceiptStatusSuccessful {
				t.Fatalf("transfer failed with status %d", receipt.Status)
			}
			if len(receipt.Logs) != 1 {
				t.Fatalf("log count = %d, want 1", len(receipt.Logs))
			}
			eip7708CheckLog(t, receipt.Logs[0], eip7708TransferLog(sender, to, 1))
		})
	}
}

// TestEIP7708FeesNotLogged pins that the priority-fee credit to the coinbase
// stays outside EIP-7708: the transaction value is the receipt's only log.
func TestEIP7708FeesNotLogged(t *testing.T) {
	var (
		config    = *params.AllEthashProtocolChanges
		recipient = common.HexToAddress("0x00000000000000000000000000000000000000c4")
		coinbase  = common.HexToAddress("0x00000000000000000000000000000000000000c5")
	)
	receipt, sender := eip7708RunTx(t, &config, nil, &recipient, big.NewInt(1), params.TxGas, nil, coinbase)
	if receipt.Status != types.ReceiptStatusSuccessful {
		t.Fatalf("transfer failed with status %d", receipt.Status)
	}
	if len(receipt.Logs) != 1 {
		t.Fatalf("log count = %d, want the transaction transfer only", len(receipt.Logs))
	}
	eip7708CheckLog(t, receipt.Logs[0], eip7708TransferLog(sender, recipient, 1))
}

// TestEIP7708TransferForkGate drives core.Transfer directly to pin both the
// fork gate and the 32-byte log data.
func TestEIP7708TransferForkGate(t *testing.T) {
	var (
		from   = common.HexToAddress("0x00000000000000000000000000000000000000c6")
		to     = common.HexToAddress("0x00000000000000000000000000000000000000c7")
		txHash = common.HexToHash("0x01")
	)
	sdb, err := state.New(types.EmptyRootHash, state.NewDatabase(rawdb.NewMemoryDatabase()))
	if err != nil {
		t.Fatalf("failed to create the state: %v", err)
	}
	sdb.SetTxContext(txHash, 0)
	sdb.SetBalance(from, big.NewInt(4), tracing.BalanceChangeUnspecified)

	Transfer(sdb, from, to, uint256.NewInt(1), &params.Rules{})
	if logs := sdb.GetLogs(txHash, 1, common.Hash{}); len(logs) != 0 {
		t.Fatalf("pre-Amsterdam transfer logged %d entry, want none", len(logs))
	}
	Transfer(sdb, from, to, uint256.NewInt(1), &params.Rules{IsAmsterdam: true})
	logs := sdb.GetLogs(txHash, 1, common.Hash{})
	if len(logs) != 1 {
		t.Fatalf("Amsterdam transfer logged %d entry, want 1", len(logs))
	}
	eip7708CheckLog(t, logs[0], eip7708TransferLog(from, to, 1))
}

// eip7708RunRawTx runs a pre-built transaction in its own block against a
// genesis that funds the sender with one ether, and returns the receipt. A
// zero coinbase keeps the genesis default.
func eip7708RunRawTx(t *testing.T, config *params.ChainConfig, alloc types.GenesisAlloc, tx *types.Transaction, coinbase common.Address) *types.Receipt {
	t.Helper()

	_, sender := eip7708KeyPair(t)
	funded := types.GenesisAlloc{sender: {Balance: big.NewInt(params.Ether)}}
	for addr, account := range alloc {
		funded[addr] = account
	}
	db := rawdb.NewMemoryDatabase()
	genesis := (&Genesis{Config: config, Alloc: funded}).MustCommit(db)

	_, receipts := GenerateChain(config, genesis, ethash.NewFaker(), db, 1, func(i int, b *BlockGen) {
		if coinbase != (common.Address{}) {
			b.SetCoinbase(coinbase)
		}
		b.AddTx(tx)
	})
	return receipts[0][0]
}

// TestEIP7708SelfdestructToSelf pins that a SELFDESTRUCT to the executing
// account moves no value and therefore emits no transfer log; only the
// transaction value is logged.
func TestEIP7708SelfdestructToSelf(t *testing.T) {
	var (
		config   = *params.AllEthashProtocolChanges
		contract = common.HexToAddress("0x00000000000000000000000000000000000000ca")
	)
	code := append([]byte{0x73}, contract.Bytes()...)
	code = append(code, 0xff) // PUSH20 self; SELFDESTRUCT
	receipt, sender := eip7708RunTx(t, &config, types.GenesisAlloc{
		contract: {Code: code},
	}, &contract, big.NewInt(1), 200_000, nil, common.Address{})
	if receipt.Status != types.ReceiptStatusSuccessful {
		t.Fatalf("selfdestruct transaction failed with status %d", receipt.Status)
	}
	if len(receipt.Logs) != 1 {
		t.Fatalf("log count = %d, want the transaction transfer only", len(receipt.Logs))
	}
	eip7708CheckLog(t, receipt.Logs[0], eip7708TransferLog(sender, contract, 1))
}

// TestEIP7708TransactionTypes pins that the transaction value is logged for
// every transaction type, including a delegated EOA that receives the value
// (the log names the delegated account, never its implementation).
func TestEIP7708TransactionTypes(t *testing.T) {
	var (
		config      = *params.AllEthashProtocolChanges
		key, sender = eip7708KeyPair(t)
		recipient   = common.HexToAddress("0x00000000000000000000000000000000000000cb")
		signer      = types.LatestSigner(&config)
		gasPrice    = eip7708GasPrice()
	)
	authKey, _ := crypto.HexToECDSA("0202020202020202020202020202020202020202020202020202002020202020")
	auth, err := types.SignSetCode(authKey, types.SetCodeAuthorization{
		ChainID: *uint256.MustFromBig(config.ChainID),
		Address: common.HexToAddress("0x00000000000000000000000000000000000000cc"),
	})
	if err != nil {
		t.Fatalf("failed to sign the set-code authorization: %v", err)
	}
	build := func(inner types.TxData) *types.Transaction {
		t.Helper()

		tx, err := types.SignTx(types.NewTx(inner), signer, key)
		if err != nil {
			t.Fatalf("failed to sign the transaction: %v", err)
		}
		return tx
	}
	cases := []struct {
		name string
		tx   *types.Transaction
	}{
		{"legacy", build(&types.LegacyTx{
			Nonce: 0, To: &recipient, Value: big.NewInt(1), Gas: 100_000, GasPrice: gasPrice,
		})},
		{"access-list", build(&types.AccessListTx{
			ChainID: config.ChainID, Nonce: 0, GasPrice: gasPrice, Gas: 100_000,
			To: &recipient, Value: big.NewInt(1),
		})},
		{"dynamic", build(&types.DynamicFeeTx{
			ChainID: config.ChainID, Nonce: 0, GasTipCap: gasPrice, GasFeeCap: gasPrice,
			Gas: 100_000, To: &recipient, Value: big.NewInt(1),
		})},
		{"set-code", build(&types.SetCodeTx{
			ChainID: uint256.MustFromBig(config.ChainID), Nonce: 0,
			GasTipCap: uint256.MustFromBig(gasPrice), GasFeeCap: uint256.MustFromBig(gasPrice),
			Gas: 300_000, To: recipient, Value: uint256.NewInt(1),
			AuthList: []types.SetCodeAuthorization{auth},
		})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			receipt := eip7708RunRawTx(t, &config, nil, tc.tx, common.Address{})
			if receipt.Status != types.ReceiptStatusSuccessful {
				t.Fatalf("transfer failed with status %d", receipt.Status)
			}
			if len(receipt.Logs) != 1 {
				t.Fatalf("log count = %d, want the transaction transfer only", len(receipt.Logs))
			}
			eip7708CheckLog(t, receipt.Logs[0], eip7708TransferLog(sender, recipient, 1))
		})
	}

	t.Run("delegated", func(t *testing.T) {
		var (
			delegated = common.HexToAddress("0x00000000000000000000000000000000000000cd")
			impl      = common.HexToAddress("0x00000000000000000000000000000000000000ce")
		)
		tx := build(&types.LegacyTx{
			Nonce: 0, To: &delegated, Value: big.NewInt(1), Gas: 100_000, GasPrice: gasPrice,
		})
		receipt := eip7708RunRawTx(t, &config, types.GenesisAlloc{
			delegated: {Code: types.AddressToDelegation(impl)},
			impl:      {Code: []byte{0x00}},
		}, tx, common.Address{})
		if receipt.Status != types.ReceiptStatusSuccessful {
			t.Fatalf("delegated transfer failed with status %d", receipt.Status)
		}
		if len(receipt.Logs) != 1 {
			t.Fatalf("log count = %d, want the transaction transfer only", len(receipt.Logs))
		}
		eip7708CheckLog(t, receipt.Logs[0], eip7708TransferLog(sender, delegated, 1))
	})
}

// eip7708CallCodeOpcode returns runtime code that CALLCODEs target with the
// given value. CALLCODE runs the callee's code in the caller's context and
// moves no value, so it must not produce a transfer log.
func eip7708CallCodeOpcode(target common.Address, value byte) []byte {
	code := []byte{0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, value, 0x73}
	code = append(code, target.Bytes()...)
	return append(code, 0x5a, 0xf2, 0x50, 0x00)
}

// TestEIP7708CallCodeDoesNotLog pins that a CALLCODE frame moves no value and
// therefore adds no transfer log.
func TestEIP7708CallCodeDoesNotLog(t *testing.T) {
	var (
		config = *params.AllEthashProtocolChanges
		caller = common.HexToAddress("0x00000000000000000000000000000000000000cf")
		target = common.HexToAddress("0x00000000000000000000000000000000000000d0")
	)
	receipt, sender := eip7708RunTx(t, &config, types.GenesisAlloc{
		caller: {Balance: big.NewInt(1), Code: eip7708CallCodeOpcode(target, 1)},
		target: {Code: []byte{0x00}},
	}, &caller, big.NewInt(1), 200_000, nil, common.Address{})
	if receipt.Status != types.ReceiptStatusSuccessful {
		t.Fatalf("callcode transaction failed with status %d", receipt.Status)
	}
	if len(receipt.Logs) != 1 {
		t.Fatalf("log count = %d, want the transaction transfer only", len(receipt.Logs))
	}
	eip7708CheckLog(t, receipt.Logs[0], eip7708TransferLog(sender, caller, 1))
}

// TestEIP7708CreateEndowment pins that the endowment of a successful
// top-level CREATE is logged with the created address as recipient.
func TestEIP7708CreateEndowment(t *testing.T) {
	config := *params.AllEthashProtocolChanges
	// Init code 0x00 is STOP: the creation succeeds without deploying code.
	receipt, sender := eip7708RunTx(t, &config, nil, nil, big.NewInt(5), 500_000, []byte{0x00}, common.Address{})
	if receipt.Status != types.ReceiptStatusSuccessful {
		t.Fatalf("create transaction failed with status %d", receipt.Status)
	}
	if len(receipt.Logs) != 1 {
		t.Fatalf("log count = %d, want the create endowment only", len(receipt.Logs))
	}
	eip7708CheckLog(t, receipt.Logs[0], eip7708TransferLog(sender, crypto.CreateAddress(sender, 0), 5))
}
