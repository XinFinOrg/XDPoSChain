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

package tracetest

// End-to-end tests for the supply live tracer, ported from go-ethereum's
// eth/tracers/internal/tracetest/supply_test.go (introduced by #29347). The
// port is not verbatim, because this tree differs from upstream in ways the
// tests have to account for:
//
//   - There is no beacon merge: no BlockGen.SetPoS, no TerminalTotalDifficulty
//     and no core.SystemContractAllocs. Blocks are generated and imported with
//     the ethash faker engine instead.
//   - The chain is opened with core.NewBlockChain(db, cacheConfig, genesis,
//     engine, vmConfig) and the tracer is attached through vm.Config.Tracer.
//   - Only the EIP-6780 flavour of SELFDESTRUCT exists: the jump table is built
//     with enable6780 unconditionally, so the legacy opcode never runs. The
//     upstream pre-Cancun expectations cannot be reproduced, and a pre-existing
//     contract that self-destructs to itself neither dies nor burns anything.
//   - There are no beacon withdrawals (core/types has no Withdrawal), so
//     upstream's TestSupplyWithdrawals is not ported.
//   - The block reward is ethash.ByzantiumBlockReward (3 ETH here, 2 ETH
//     upstream) and the genesis base fee is params.InitialBaseFee (12.5 gwei
//     here, 1 gwei upstream), so every expected value is derived from the
//     generated chain instead of being copied as a literal.
//   - core.BlockChain.Stop closes the state database, so the chain outlives the
//     assertions through t.Cleanup instead of being stopped by the helper.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/common/hexutil"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/eth/tracers"
	"github.com/XinFinOrg/XDPoSChain/params"

	// Force-load live packages, to trigger registration
	_ "github.com/XinFinOrg/XDPoSChain/eth/tracers/live"
)

type supplyInfoIssuance struct {
	GenesisAlloc *hexutil.Big `json:"genesisAlloc,omitempty"`
	Reward       *hexutil.Big `json:"reward,omitempty"`
	Withdrawals  *hexutil.Big `json:"withdrawals,omitempty"`
}

type supplyInfoBurn struct {
	EIP1559 *hexutil.Big `json:"1559,omitempty"`
	Blob    *hexutil.Big `json:"blob,omitempty"`
	Misc    *hexutil.Big `json:"misc,omitempty"`
}

type supplyInfo struct {
	Issuance *supplyInfoIssuance `json:"issuance,omitempty"`
	Burn     *supplyInfoBurn     `json:"burn,omitempty"`

	// Block info
	Number     uint64      `json:"blockNumber"`
	Hash       common.Hash `json:"hash"`
	ParentHash common.Hash `json:"parentHash"`
}

func emptyBlockGenerationFunc(b *core.BlockGen) {}

// TestSupplyOmittedFields checks that the genesis entry of a chain with an empty
// allocation carries no supply fields at all.
func TestSupplyOmittedFields(t *testing.T) {
	config := *params.TestChainConfig
	gspec := &core.Genesis{
		Config:  &config,
		BaseFee: big.NewInt(params.InitialBaseFee),
	}

	out, chain, err := testSupplyTracer(t, gspec, emptyBlockGenerationFunc, 1)
	if err != nil {
		t.Fatalf("failed to test supply tracer: %v", err)
	}

	expected := supplyInfo{
		Number:     0,
		Hash:       chain.Genesis().Hash(),
		ParentHash: common.Hash{},
	}

	compareAsJSON(t, expected, out[expected.Number])
}

// TestSupplyGenesisAlloc checks that the genesis allocation is reported as
// issuance on the genesis entry.
func TestSupplyGenesisAlloc(t *testing.T) {
	var (
		key1, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		key2, _ = crypto.HexToECDSA("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a")
		addr1   = crypto.PubkeyToAddress(key1.PublicKey)
		addr2   = crypto.PubkeyToAddress(key2.PublicKey)
		eth1    = new(big.Int).Mul(common.Big1, big.NewInt(params.Ether))

		config = *params.AllEthashProtocolChanges

		gspec = &core.Genesis{
			Config: &config,
			Alloc: types.GenesisAlloc{
				addr1: {Balance: eth1},
				addr2: {Balance: eth1},
			},
		}
	)

	out, chain, err := testSupplyTracer(t, gspec, emptyBlockGenerationFunc, 1)
	if err != nil {
		t.Fatalf("failed to test supply tracer: %v", err)
	}

	expected := supplyInfo{
		Issuance: &supplyInfoIssuance{
			GenesisAlloc: (*hexutil.Big)(new(big.Int).Mul(common.Big2, big.NewInt(params.Ether))),
		},
		Number:     0,
		Hash:       chain.Genesis().Hash(),
		ParentHash: common.Hash{},
	}

	compareAsJSON(t, expected, out[expected.Number])
}

// TestSupplyRewards checks that the block reward of an ethash chain is reported
// as issuance. Upstream pins 2 ETH, this tree pays ethash.ByzantiumBlockReward
// (3 ETH) because it has no Constantinople reward step.
func TestSupplyRewards(t *testing.T) {
	config := *params.AllEthashProtocolChanges
	gspec := &core.Genesis{
		Config: &config,
	}

	out, chain, err := testSupplyTracer(t, gspec, emptyBlockGenerationFunc, 1)
	if err != nil {
		t.Fatalf("failed to test supply tracer: %v", err)
	}

	head := chain.CurrentBlock()
	expected := supplyInfo{
		Issuance: &supplyInfoIssuance{
			Reward: (*hexutil.Big)(new(big.Int).Set(ethash.ByzantiumBlockReward)),
		},
		Number:     1,
		Hash:       head.Hash(),
		ParentHash: head.ParentHash,
	}

	compareAsJSON(t, expected, out[expected.Number])
}

// TestSupplyEip1559Burn checks that the base fee of a block with a dynamic fee
// transaction is reported as burnt.
func TestSupplyEip1559Burn(t *testing.T) {
	var (
		config = *params.AllEthashProtocolChanges

		aa = common.HexToAddress("0x000000000000000000000000000000000000aaaa")
		// A sender who makes transactions, has some eth1
		key1, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		addr1   = crypto.PubkeyToAddress(key1.PublicKey)
		eth1    = new(big.Int).Mul(common.Big1, big.NewInt(params.Ether))
		// The genesis base fee here is params.InitialBaseFee (12.5 gwei), so the
		// fee cap has to stay above it. Upstream can use 5 gwei because its
		// initial base fee is 1 gwei.
		gasFeeCap = new(big.Int).Mul(big.NewInt(20), big.NewInt(params.GWei))
		gasTipCap = new(big.Int).Mul(big.NewInt(2), big.NewInt(params.GWei))

		gspec = &core.Genesis{
			Config:  &config,
			BaseFee: big.NewInt(params.InitialBaseFee),
			Alloc: types.GenesisAlloc{
				addr1: {Balance: eth1},
			},
		}
	)

	signer := types.LatestSigner(gspec.Config)

	eip1559BlockGenerationFunc := func(b *core.BlockGen) {
		tx, err := types.SignTx(types.NewTx(&types.DynamicFeeTx{
			ChainID:   gspec.Config.ChainID,
			Nonce:     0,
			To:        &aa,
			Gas:       21000,
			GasFeeCap: gasFeeCap,
			GasTipCap: gasTipCap,
		}), signer, key1)
		if err != nil {
			t.Fatalf("failed to sign transaction: %v", err)
		}
		b.AddTx(tx)
	}

	out, chain, err := testSupplyTracer(t, gspec, eip1559BlockGenerationFunc, 1)
	if err != nil {
		t.Fatalf("failed to test supply tracer: %v", err)
	}

	var (
		head     = chain.CurrentBlock()
		burn     = new(big.Int).Mul(new(big.Int).SetUint64(head.GasUsed), head.BaseFee)
		expected = supplyInfo{
			Issuance: &supplyInfoIssuance{
				Reward: (*hexutil.Big)(new(big.Int).Set(ethash.ByzantiumBlockReward)),
			},
			Burn: &supplyInfoBurn{
				EIP1559: (*hexutil.Big)(burn),
			},
			Number:     1,
			Hash:       head.Hash(),
			ParentHash: head.ParentHash,
		}
	)

	compareAsJSON(t, expected, out[expected.Number])
}

// TestSupplySelfdestruct is upstream's self-destruct scenario running under
// EIP-6780 only. Contract A calls contract B, B self-destructs to 0x0dad and
// hands it its 1 ETH, and A then sends 5 gwei to the address of B.
//
// The legacy semantics (B deleted, the 5 gwei paid into the dead account burnt)
// are unreachable here: this tree's jump table always routes SELFDESTRUCT
// through opSelfdestruct6780, and B is deployed in the genesis block, so the
// destruct neither deletes nor burns anything. What the tracer must report is
// therefore just the EIP-1559 fee burn, with no misc burn at all.
func TestSupplySelfdestruct(t *testing.T) {
	var (
		config = *params.TestChainConfig

		aa       = common.HexToAddress("0x1111111111111111111111111111111111111111")
		bb       = common.HexToAddress("0x2222222222222222222222222222222222222222")
		dad      = common.HexToAddress("0x0000000000000000000000000000000000000dad")
		key1, _  = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		addr1    = crypto.PubkeyToAddress(key1.PublicKey)
		gwei5    = new(big.Int).Mul(big.NewInt(5), big.NewInt(params.GWei))
		eth1     = new(big.Int).Mul(common.Big1, big.NewInt(params.Ether))
		gasPrice = new(big.Int).Mul(big.NewInt(20), big.NewInt(params.GWei))

		gspec = &core.Genesis{
			Config:  &config,
			BaseFee: big.NewInt(params.InitialBaseFee),
			Alloc: types.GenesisAlloc{
				addr1: {Balance: eth1},
				aa: {
					Code:    common.FromHex("0x61face60f01b6000527322222222222222222222222222222222222222226000806002600080855af160008103603457600080fd5b60008060008034865af1905060008103604c57600080fd5b5050"),
					Balance: big.NewInt(0),
				},
				bb: {
					Code:    common.FromHex("0x6000357fface000000000000000000000000000000000000000000000000000000000000808203602f57610dad80ff5b5050"),
					Nonce:   0,
					Balance: eth1,
				},
			},
		}
	)

	signer := types.LatestSigner(gspec.Config)

	testBlockGenerationFunc := func(b *core.BlockGen) {
		tx, err := types.SignTx(types.NewTx(&types.LegacyTx{
			Nonce:    0,
			To:       &aa,
			Value:    gwei5,
			Gas:      150000,
			GasPrice: gasPrice,
		}), signer, key1)
		if err != nil {
			t.Fatalf("failed to sign transaction: %v", err)
		}
		b.AddTx(tx)
	}

	out, chain, err := testSupplyTracer(t, gspec, testBlockGenerationFunc, 1)
	if err != nil {
		t.Fatalf("failed to test supply tracer: %v", err)
	}

	statedb, err := chain.State()
	if err != nil {
		t.Fatalf("failed to open head state: %v", err)
	}
	if got, exp := statedb.GetBalance(dad), eth1; got.Cmp(exp) != 0 {
		t.Fatalf("address %q balance, got %v exp %v", dad, got, exp)
	}
	if got, exp := statedb.GetBalance(aa), common.Big0; got.Cmp(exp) != 0 {
		t.Fatalf("address %q balance, got %v exp %v", aa, got, exp)
	}
	if got, exp := statedb.GetBalance(bb), gwei5; got.Cmp(exp) != 0 {
		t.Fatalf("address %q balance, got %v exp %v", bb, got, exp)
	}

	head := chain.CurrentBlock()
	expected := supplyInfo{
		// There is no beacon merge here, so the ethash engine pays the block
		// reward into the coinbase of every block, while upstream's post-merge
		// runs carry no issuance at all.
		Issuance: &supplyInfoIssuance{
			Reward: (*hexutil.Big)(new(big.Int).Set(ethash.ByzantiumBlockReward)),
		},
		Burn: &supplyInfoBurn{
			EIP1559: (*hexutil.Big)(new(big.Int).Mul(new(big.Int).SetUint64(head.GasUsed), head.BaseFee)),
		},
		Number:     1,
		Hash:       head.Hash(),
		ParentHash: head.ParentHash,
	}

	compareAsJSON(t, expected, out[expected.Number])
}

// TestSupplySelfdestructItselfAndRevert is upstream's second self-destruct
// scenario running under EIP-6780 only.
//
// Contract A calls B and D. B self-destructs to itself, D calls C which
// self-destructs to itself and then reverts. With EIP-6780 a pre-existing
// contract that self-destructs to itself is not destroyed at all, so no balance
// is burnt: upstream's pre-Cancun expectation (B at zero with 5 ETH reported as
// misc burn) cannot be recreated, and the misc burn has to be absent. Contracts
// created inside a transaction are covered by the two tests below.
func TestSupplySelfdestructItselfAndRevert(t *testing.T) {
	var (
		config = *params.TestChainConfig

		aa       = common.HexToAddress("0x1111111111111111111111111111111111111111")
		bb       = common.HexToAddress("0x2222222222222222222222222222222222222222")
		cc       = common.HexToAddress("0x3333333333333333333333333333333333333333")
		dd       = common.HexToAddress("0x4444444444444444444444444444444444444444")
		key1, _  = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		addr1    = crypto.PubkeyToAddress(key1.PublicKey)
		eth1     = new(big.Int).Mul(common.Big1, big.NewInt(params.Ether))
		eth2     = new(big.Int).Mul(common.Big2, big.NewInt(params.Ether))
		eth5     = new(big.Int).Mul(big.NewInt(5), big.NewInt(params.Ether))
		gasPrice = new(big.Int).Mul(big.NewInt(20), big.NewInt(params.GWei))

		gspec = &core.Genesis{
			Config:  &config,
			BaseFee: big.NewInt(params.InitialBaseFee),
			Alloc: types.GenesisAlloc{
				addr1: {Balance: eth1},
				aa: {
					Code:    common.FromHex("0x73222222222222222222222222222222222222222273444444444444444444444444444444444444444460006000600060006000865af160006000600060006000865af150505050"),
					Balance: common.Big0,
				},
				bb: {
					Code:    common.FromHex("0x3080ff50"),
					Balance: eth5,
				},
				cc: {
					Code:    common.FromHex("0x3080ff50"),
					Balance: eth1,
				},
				dd: {
					Code:    common.FromHex("0x73333333333333333333333333333333333333333360006000600060006000855af160006000fd5050"),
					Balance: eth2,
				},
			},
		}
	)

	signer := types.LatestSigner(gspec.Config)

	testBlockGenerationFunc := func(b *core.BlockGen) {
		tx, err := types.SignTx(types.NewTx(&types.LegacyTx{
			Nonce:    0,
			To:       &aa,
			Value:    common.Big0,
			Gas:      150000,
			GasPrice: gasPrice,
		}), signer, key1)
		if err != nil {
			t.Fatalf("failed to sign transaction: %v", err)
		}
		b.AddTx(tx)
	}

	out, chain, err := testSupplyTracer(t, gspec, testBlockGenerationFunc, 1)
	if err != nil {
		t.Fatalf("failed to test supply tracer: %v", err)
	}

	statedb, err := chain.State()
	if err != nil {
		t.Fatalf("failed to open head state: %v", err)
	}
	if got, exp := statedb.GetBalance(aa), common.Big0; got.Cmp(exp) != 0 {
		t.Fatalf("address %q balance, got %v exp %v", aa, got, exp)
	}
	if got, exp := statedb.GetBalance(bb), eth5; got.Cmp(exp) != 0 {
		t.Fatalf("address %q balance, got %v exp %v", bb, got, exp)
	}
	if got, exp := statedb.GetBalance(cc), eth1; got.Cmp(exp) != 0 {
		t.Fatalf("address %q balance, got %v exp %v", cc, got, exp)
	}
	if got, exp := statedb.GetBalance(dd), eth2; got.Cmp(exp) != 0 {
		t.Fatalf("address %q balance, got %v exp %v", dd, got, exp)
	}

	head := chain.CurrentBlock()
	expected := supplyInfo{
		Issuance: &supplyInfoIssuance{
			Reward: (*hexutil.Big)(new(big.Int).Set(ethash.ByzantiumBlockReward)),
		},
		Burn: &supplyInfoBurn{
			EIP1559: (*hexutil.Big)(new(big.Int).Mul(new(big.Int).SetUint64(head.GasUsed), head.BaseFee)),
		},
		Number:     1,
		Hash:       head.Hash(),
		ParentHash: head.ParentHash,
	}

	compareAsJSON(t, expected, out[expected.Number])
}

// The two tests below cover the only self-destruct that still burns under
// EIP-6780: a contract created and destroyed inside one transaction. They need
// a chain where EIP-8246 (Amsterdam) is not active yet, because Amsterdam keeps
// the balance of such a destruct instead of reporting it as burnt. The default
// test configurations enable Amsterdam from the genesis block, so the config is
// copied and Amsterdam is left unscheduled; a required fork at the end of the
// fork order may be skipped without breaking the fork order check.

// factoryBurnCode creates a child contract with 1 ETH whose init code
// self-destructs to itself, then sends another 0.5 ETH to the address of the
// destroyed child. The destruction clears 1 ETH and the transfer afterwards is
// burnt as well, so the misc burn has to be 1.5 ETH.
//
//	61 30ff            PUSH2 0x30ff
//	60 00 52           MSTORE          ; mem[30:32] = 30 ff
//	60 02 60 1e        PUSH1 2, 30     ; size and offset of the init code
//	67 0de0b6b3a7640000 PUSH8 1e18     ; value: 1 ETH
//	f0                 CREATE          ; stack: [child]
//	60 00 60 00 60 00 60 00             ; retSize, retOffset, inSize, inOffset
//	67 06f05b59d3b20000 PUSH8 5e17     ; value: 0.5 ETH
//	85                 DUP6            ; child address
//	5a f1              GAS, CALL
//	00                 STOP
const factoryBurnCode = "0x6130ff6000526002601e670de0b6b3a7640000f060006000600060006706f05b59d3b20000855af100"

// factoryRevertCode creates the same child and then reverts the transaction, so
// neither the creation nor the destruct survives and no burn may be reported.
const factoryRevertCode = "0x6130ff6000526002601e670de0b6b3a7640000f060006000fd"

// TestSupplySelfdestructCreatedInTx checks the positive case: a self-destruct of
// a contract created in the same transaction still burns, and the tracer has to
// report both halves of it (the cleared balance and the ether paid into the
// destroyed account afterwards).
func TestSupplySelfdestructCreatedInTx(t *testing.T) {
	var (
		factory  = common.HexToAddress("0x1111111111111111111111111111111111111111")
		key1, _  = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		addr1    = crypto.PubkeyToAddress(key1.PublicKey)
		eth1     = new(big.Int).Mul(common.Big1, big.NewInt(params.Ether))
		eth2     = new(big.Int).Mul(common.Big2, big.NewInt(params.Ether))
		gasPrice = new(big.Int).Mul(big.NewInt(20), big.NewInt(params.GWei))

		config = *params.TestChainConfig
	)
	config.AmsterdamBlock = nil

	gspec := &core.Genesis{
		Config:  &config,
		BaseFee: big.NewInt(params.InitialBaseFee),
		Alloc: types.GenesisAlloc{
			addr1:   {Balance: eth1},
			factory: {Code: common.FromHex(factoryBurnCode), Balance: eth2},
		},
	}

	signer := types.LatestSigner(gspec.Config)

	testBlockGenerationFunc := func(b *core.BlockGen) {
		tx, err := types.SignTx(types.NewTx(&types.LegacyTx{
			Nonce:    0,
			To:       &factory,
			Value:    common.Big0,
			Gas:      200000,
			GasPrice: gasPrice,
		}), signer, key1)
		if err != nil {
			t.Fatalf("failed to sign transaction: %v", err)
		}
		b.AddTx(tx)
	}

	out, chain, err := testSupplyTracer(t, gspec, testBlockGenerationFunc, 1)
	if err != nil {
		t.Fatalf("failed to test supply tracer: %v", err)
	}

	statedb, err := chain.State()
	if err != nil {
		t.Fatalf("failed to open head state: %v", err)
	}
	child := crypto.CreateAddress(factory, 0)
	if statedb.Exist(child) {
		t.Fatalf("destroyed child %q still exists", child)
	}
	// 2 ETH funded, 1 ETH into the child, 0.5 ETH sent to it afterwards.
	if got, exp := statedb.GetBalance(factory), new(big.Int).Rsh(eth1, 1); got.Cmp(exp) != 0 {
		t.Fatalf("factory %q balance, got %v exp %v", factory, got, exp)
	}
	// A transaction that failed before creating the child would report no burn
	// either, so pin that the factory call went through.
	block := chain.GetBlockByNumber(1)
	if receipts := chain.GetReceiptsByHash(block.Hash()); len(receipts) != 1 || receipts[0].Status != types.ReceiptStatusSuccessful {
		t.Fatalf("factory transaction did not succeed: %v", receipts)
	}

	head := chain.CurrentBlock()
	expected := supplyInfo{
		Issuance: &supplyInfoIssuance{
			Reward: (*hexutil.Big)(new(big.Int).Set(ethash.ByzantiumBlockReward)),
		},
		Burn: &supplyInfoBurn{
			EIP1559: (*hexutil.Big)(new(big.Int).Mul(new(big.Int).SetUint64(head.GasUsed), head.BaseFee)),
			// The destruct cleared 1 ETH and the transfer afterwards added 0.5 ETH.
			Misc: (*hexutil.Big)(new(big.Int).Add(eth1, new(big.Int).Rsh(eth1, 1))),
		},
		Number:     1,
		Hash:       head.Hash(),
		ParentHash: head.ParentHash,
	}

	compareAsJSON(t, expected, out[expected.Number])
}

// TestSupplySelfdestructCreatedInTxReverted checks the negative case: a
// self-destruct of a contract created and reverted in the same transaction is
// rolled back, so the tracer must not report any misc burn.
func TestSupplySelfdestructCreatedInTxReverted(t *testing.T) {
	var (
		factory  = common.HexToAddress("0x1111111111111111111111111111111111111111")
		key1, _  = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		addr1    = crypto.PubkeyToAddress(key1.PublicKey)
		eth1     = new(big.Int).Mul(common.Big1, big.NewInt(params.Ether))
		eth2     = new(big.Int).Mul(common.Big2, big.NewInt(params.Ether))
		gasPrice = new(big.Int).Mul(big.NewInt(20), big.NewInt(params.GWei))

		config = *params.TestChainConfig
	)
	config.AmsterdamBlock = nil

	gspec := &core.Genesis{
		Config:  &config,
		BaseFee: big.NewInt(params.InitialBaseFee),
		Alloc: types.GenesisAlloc{
			addr1:   {Balance: eth1},
			factory: {Code: common.FromHex(factoryRevertCode), Balance: eth2},
		},
	}

	signer := types.LatestSigner(gspec.Config)

	testBlockGenerationFunc := func(b *core.BlockGen) {
		tx, err := types.SignTx(types.NewTx(&types.LegacyTx{
			Nonce:    0,
			To:       &factory,
			Value:    common.Big0,
			Gas:      200000,
			GasPrice: gasPrice,
		}), signer, key1)
		if err != nil {
			t.Fatalf("failed to sign transaction: %v", err)
		}
		b.AddTx(tx)
	}

	out, chain, err := testSupplyTracer(t, gspec, testBlockGenerationFunc, 1)
	if err != nil {
		t.Fatalf("failed to test supply tracer: %v", err)
	}

	statedb, err := chain.State()
	if err != nil {
		t.Fatalf("failed to open head state: %v", err)
	}
	if statedb.Exist(crypto.CreateAddress(factory, 0)) {
		t.Fatalf("reverted child of %q exists", factory)
	}
	if got, exp := statedb.GetBalance(factory), eth2; got.Cmp(exp) != 0 {
		t.Fatalf("factory %q balance, got %v exp %v", factory, got, exp)
	}
	// A transaction that never reached the creation would report no burn either,
	// so pin that the factory ran and reverted after creating the child.
	block := chain.GetBlockByNumber(1)
	if receipts := chain.GetReceiptsByHash(block.Hash()); len(receipts) != 1 || receipts[0].Status != types.ReceiptStatusFailed {
		t.Fatalf("factory transaction did not revert: %v", receipts)
	}

	head := chain.CurrentBlock()
	expected := supplyInfo{
		Issuance: &supplyInfoIssuance{
			Reward: (*hexutil.Big)(new(big.Int).Set(ethash.ByzantiumBlockReward)),
		},
		Burn: &supplyInfoBurn{
			EIP1559: (*hexutil.Big)(new(big.Int).Mul(new(big.Int).SetUint64(head.GasUsed), head.BaseFee)),
		},
		Number:     1,
		Hash:       head.Hash(),
		ParentHash: head.ParentHash,
	}

	compareAsJSON(t, expected, out[expected.Number])
}

// testSupplyTracer generates numBlocks blocks, imports them into a fresh chain
// with the supply tracer attached, and returns the JSON lines the tracer wrote
// along with the chain. The returned chain is stopped when the test finishes,
// not when this helper returns: stopping it closes the state database, and the
// callers still read the head state afterwards.
func testSupplyTracer(t *testing.T, genesis *core.Genesis, gen func(b *core.BlockGen), numBlocks int) ([]supplyInfo, *core.BlockChain, error) {
	t.Helper()

	var (
		engine = ethash.NewFaker()
		dir    = t.TempDir()
	)
	tracer, err := tracers.LiveDirectory.New("supply", json.RawMessage(fmt.Sprintf(`{"path":%q}`, filepath.ToSlash(dir))))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create supply tracer: %v", err)
	}
	chain, err := core.NewBlockChain(rawdb.NewMemoryDatabase(), &core.CacheConfig{TrieDirtyDisabled: true}, genesis, engine, vm.Config{Tracer: tracer})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create tester chain: %v", err)
	}
	t.Cleanup(chain.Stop)

	_, blocks, _ := core.GenerateChainWithGenesis(genesis, engine, numBlocks, func(_ int, b *core.BlockGen) {
		b.SetCoinbase(common.Address{1})
		gen(b)
	})
	if n, err := chain.InsertChain(blocks); err != nil {
		return nil, chain, fmt.Errorf("block %d: failed to insert into chain: %v", n, err)
	}

	// The tracer writes one line for the genesis block and one for every
	// imported block, so a complete run leaves numBlocks+1 lines.
	file, err := os.Open(filepath.Join(dir, "supply.jsonl"))
	if err != nil {
		return nil, chain, fmt.Errorf("failed to open output file: %v", err)
	}
	defer file.Close()

	var output []supplyInfo
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var info supplyInfo
		if err := json.Unmarshal(scanner.Bytes(), &info); err != nil {
			return nil, chain, fmt.Errorf("failed to unmarshal result: %v", err)
		}
		output = append(output, info)
	}
	if err := scanner.Err(); err != nil {
		return nil, chain, fmt.Errorf("failed to read output file: %v", err)
	}
	if len(output) != numBlocks+1 {
		return nil, chain, fmt.Errorf("got %d supply entries, want %d", len(output), numBlocks+1)
	}
	return output, chain, nil
}

func compareAsJSON(t *testing.T, expected interface{}, actual interface{}) {
	t.Helper()
	want, err := json.Marshal(expected)
	if err != nil {
		t.Fatalf("failed to marshal expected value to JSON: %v", err)
	}
	have, err := json.Marshal(actual)
	if err != nil {
		t.Fatalf("failed to marshal actual value to JSON: %v", err)
	}
	if !bytes.Equal(want, have) {
		t.Fatalf("incorrect supply info:\nwant %s\nhave %s", string(want), string(have))
	}
}
