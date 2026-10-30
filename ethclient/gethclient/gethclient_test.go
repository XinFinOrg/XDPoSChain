// Copyright 2021 The go-ethereum Authors
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

package gethclient

import (
	"bytes"
	"context"
	"encoding/json"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	ethereum "github.com/XinFinOrg/XDPoSChain"
	"github.com/XinFinOrg/XDPoSChain/XDCx"
	"github.com/XinFinOrg/XDPoSChain/XDCxlending"
	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/eth"
	"github.com/XinFinOrg/XDPoSChain/eth/ethconfig"
	"github.com/XinFinOrg/XDPoSChain/eth/filters"
	"github.com/XinFinOrg/XDPoSChain/eth/tracers"
	_ "github.com/XinFinOrg/XDPoSChain/eth/tracers/native"
	"github.com/XinFinOrg/XDPoSChain/ethclient"
	"github.com/XinFinOrg/XDPoSChain/node"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/XinFinOrg/XDPoSChain/rpc"
)

var (
	testKey, _   = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	testAddr     = crypto.PubkeyToAddress(testKey.PublicKey)
	testContract = common.HexToAddress("0xbeef")
	testEmpty    = common.HexToAddress("0xeeee")
	testSlot     = common.HexToHash("0xdeadbeef")
	testValue    = crypto.Keccak256Hash(testSlot[:])
	testBalance  = big.NewInt(2e15)
)

// pendingTxTimeout bounds the wait for a subscription notification. The node
// delivers them asynchronously, and without a bound a lost one blocks the test
// forever.
const pendingTxTimeout = 10 * time.Second

// callTimeout bounds a single RPC round trip: the node runs in this process,
// and a handler that wedges would otherwise block the test until the package
// timeout.
const callTimeout = 30 * time.Second

// rpcCtx returns a context for one test, bounded by callTimeout.
func rpcCtx(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	return context.WithTimeout(context.Background(), callTimeout)
}

func newTestBackend(t *testing.T) (*node.Node, []*types.Block, []common.Hash) {
	// Generate test chain.
	genesis, blocks, txHashes := generateTestChain(t)
	// Create node
	n, err := node.New(&node.Config{
		DataDir:     t.TempDir(),
		HTTPModules: []string{"debug", "eth", "admin"},
	})
	if err != nil {
		t.Fatalf("can't create new node: %v", err)
	}
	// XDCx opens its database and never closes it - XDCX has no lifecycle hook,
	// so the file stays open for the lifetime of the node - and a directory
	// t.TempDir owns fails its own cleanup when that happens. Make one here and
	// remove it best-effort instead: a leftover temp dir is a better trade than
	// a package that does not run on Windows at all.
	xdcxDir, err := os.MkdirTemp("", "xdposchain-xdcx-") //nolint:usetesting // t.TempDir cleans up after itself and fails the test when it cannot
	if err != nil {
		t.Fatalf("can't create XDCx data dir: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(xdcxDir); err != nil {
			t.Logf("leaving %s behind: %v", xdcxDir, err)
		}
	})
	xdcx := XDCx.New(n, &XDCx.Config{DataDir: xdcxDir})
	lending := XDCxlending.New(n, xdcx)
	// Create Ethereum Service
	config := &ethconfig.Config{Genesis: genesis, RPCGasCap: 1000000}
	ethservice, err := eth.New(n, config, xdcx, lending)
	if err != nil {
		t.Fatalf("can't create new ethereum service: %v", err)
	}
	n.RegisterAPIs(tracers.APIs(ethservice.APIBackend))

	filterSystem := filters.NewFilterSystem(ethservice.APIBackend, filters.Config{})
	n.RegisterAPIs([]rpc.API{{
		Namespace: "eth",
		Service:   filters.NewFilterAPI(filterSystem, false),
	}})

	// Import the test chain.
	if err := n.Start(); err != nil {
		t.Fatalf("can't start test node: %v", err)
	}
	if _, err := ethservice.BlockChain().InsertChain(blocks[1:]); err != nil {
		t.Fatalf("can't import test blocks: %v", err)
	}
	return n, blocks, txHashes
}

func generateTestChain(t *testing.T) (*core.Genesis, []*types.Block, []common.Hash) {
	t.Helper()
	chainConfig := *params.AllEthashProtocolChanges
	genesis := &core.Genesis{
		Config: &chainConfig,
		Alloc: types.GenesisAlloc{
			testAddr:     {Balance: testBalance, Storage: map[common.Hash]common.Hash{testSlot: testValue}},
			testContract: {Nonce: 1, Code: []byte{0x13, 0x37}},
			testEmpty:    {Balance: big.NewInt(1)},
		},
		ExtraData: []byte("test genesis"),
		Timestamp: 9000,
	}
	txHashes := make([]common.Hash, 0)
	generate := func(i int, g *core.BlockGen) {
		g.OffsetTime(5)
		g.SetExtra([]byte("test"))

		// Address 0x01 is the ecrecover precompile, so this "transfer" runs it
		// and costs EcrecoverGas on top of the intrinsic gas. With exactly
		// params.TxGas the message ran out of gas and every generated
		// transaction landed as a failure - which the trace tests then traced.
		to := common.BytesToAddress([]byte{byte(i + 1)})
		tx := types.NewTx(&types.LegacyTx{
			Nonce:    uint64(i),
			To:       &to,
			Value:    big.NewInt(int64(2*i + 1)),
			Gas:      3 * params.TxGas,
			GasPrice: big.NewInt(params.InitialBaseFee),
			Data:     nil,
		})
		tx, err := types.SignTx(tx, types.LatestSignerForChainID(chainConfig.ChainID), testKey)
		if err != nil {
			t.Fatalf("can't sign test transaction: %v", err)
		}
		g.AddTx(tx)
		txHashes = append(txHashes, tx.Hash())
	}
	_, blocks, _ := core.GenerateChainWithGenesis(genesis, ethash.NewFaker(), 1, generate)
	blocks = append([]*types.Block{genesis.ToBlock()}, blocks...)
	return genesis, blocks, txHashes
}

// TestGethClient tests geth client.
func TestGethClient(t *testing.T) {
	backend, _, txHashes := newTestBackend(t)
	client := backend.Attach()
	defer backend.Close()
	defer client.Close()

	tests := []struct {
		name string
		test func(t *testing.T)
	}{
		{
			"TestGCStats",
			func(t *testing.T) { testGCStats(t, client) },
		}, {
			"TestMemStats",
			func(t *testing.T) { testMemStats(t, client) },
		}, {
			"TestGetNodeInfo",
			func(t *testing.T) { testGetNodeInfo(t, client) },
		}, {
			"TestSubscribePendingTxHashes",
			func(t *testing.T) { testSubscribePendingTransactions(t, client) },
		}, {
			"TestCallContract",
			func(t *testing.T) { testCallContract(t, client) },
		}, {
			"TestCallContractWithBlockOverrides",
			func(t *testing.T) { testCallContractWithBlockOverrides(t, client) },
		}, {
			"TestTraceTransactionWithCallTracer",
			func(t *testing.T) { testTraceTransactionWithCallTracer(t, client, txHashes) },
		}, {
			"TestTraceCallWithCallTracer",
			func(t *testing.T) { testTraceCallWithCallTracer(t, client) },
		},
		{
			"TestAccessList",
			func(t *testing.T) { testAccessList(t, client) },
		},
		{
			"TestTraceTransaction",
			func(t *testing.T) { testTraceTransactions(t, client, txHashes) },
		},
		// TestSetHead rewinds the chain to genesis, so everything that reads the
		// imported block has to run before it: keep this case last.
		{
			"TestSetHead",
			func(t *testing.T) { testSetHead(t, client) },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, tt.test)
	}
}

func testAccessList(t *testing.T, client *rpc.Client) {
	ec := New(client)
	ctx, cancel := rpcCtx(t)
	defer cancel()
	baseFee := new(big.Int).SetUint64(params.InitialBaseFee)

	for i, tc := range []struct {
		msg       ethereum.CallMsg
		wantGas   uint64
		wantErr   string
		wantVMErr string
		wantAL    string
	}{
		{ // Test transfer
			msg: ethereum.CallMsg{
				From:     testAddr,
				To:       &common.Address{},
				Gas:      21000,
				GasPrice: baseFee,
				Value:    big.NewInt(1),
			},
			wantGas: 21000,
			wantAL:  `[]`,
		},
		{ // Test reverting transaction
			msg: ethereum.CallMsg{
				From:     testAddr,
				To:       nil,
				Gas:      100000,
				GasPrice: baseFee,
				Value:    big.NewInt(1),
				Data:     common.FromHex("0x608060806080608155fd"),
			},
			wantGas:   77498,
			wantVMErr: "execution reverted",
			wantAL: `[
  {
    "address": "0xdb7d6ab1f17c6b31909ae466702703daef9269cf",
    "storageKeys": [
      "0x0000000000000000000000000000000000000000000000000000000000000081"
    ]
  }
]`,
		},
		{ // error when gasPrice is less than baseFee
			msg: ethereum.CallMsg{
				From:     testAddr,
				To:       &common.Address{},
				Gas:      21000,
				GasPrice: big.NewInt(1), // less than baseFee
				Value:    big.NewInt(1),
			},
			wantErr: "max fee per gas less than block base fee",
		},
		{ // when gasPrice is not specified
			msg: ethereum.CallMsg{
				From:  testAddr,
				To:    &common.Address{},
				Gas:   21000,
				Value: big.NewInt(1),
			},
			wantGas: 21000,
			wantAL:  `[]`,
		},
	} {
		al, gas, vmErr, err := ec.CreateAccessList(ctx, tc.msg)
		if tc.wantErr != "" {
			// A nil error is the regression this case exists to catch, so it
			// has to be reported: err.Error() below would dereference it and
			// turn a wrong result into a panic.
			if err == nil {
				t.Fatalf("test %d: expected error %q, got none", i, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("test %d: wrong error: %v", i, err)
			}
			continue
		} else if err != nil {
			t.Fatalf("test %d: wrong error: %v", i, err)
		}
		if have, want := vmErr, tc.wantVMErr; have != want {
			t.Fatalf("test %d: vmErr wrong, have %v want %v", i, have, want)
		}
		if have, want := gas, tc.wantGas; have != want {
			t.Fatalf("test %d: gas wrong, have %v want %v", i, have, want)
		}
		haveList, _ := json.MarshalIndent(al, "", "  ")
		if have, want := string(haveList), tc.wantAL; have != want {
			t.Fatalf("test %d: access list wrong, have:\n%v\nwant:\n%v", i, have, want)
		}
	}
}

func testGCStats(t *testing.T, client *rpc.Client) {
	ec := New(client)
	ctx, cancel := rpcCtx(t)
	defer cancel()
	_, err := ec.GCStats(ctx)
	if err != nil {
		t.Fatal(err)
	}
}

func testMemStats(t *testing.T, client *rpc.Client) {
	ec := New(client)
	ctx, cancel := rpcCtx(t)
	defer cancel()
	stats, err := ec.MemStats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Alloc == 0 {
		t.Fatal("Invalid mem stats retrieved")
	}
}

func testGetNodeInfo(t *testing.T, client *rpc.Client) {
	ec := New(client)
	ctx, cancel := rpcCtx(t)
	defer cancel()
	info, err := ec.GetNodeInfo(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if info.Name == "" {
		t.Fatal("Invalid node info retrieved")
	}
}

func testSetHead(t *testing.T, client *rpc.Client) {
	ec := New(client)
	ctx, cancel := rpcCtx(t)
	defer cancel()
	err := ec.SetHead(ctx, big.NewInt(0))
	if err != nil {
		t.Fatal(err)
	}
}

func testSubscribePendingTransactions(t *testing.T, client *rpc.Client) {
	ec := New(client)
	ctx, cancel := rpcCtx(t)
	defer cancel()
	ethcl := ethclient.NewClient(client)
	baseFee := new(big.Int).SetUint64(params.InitialBaseFee)

	// Subscribe to Transactions
	ch1 := make(chan common.Hash)
	sub1, err := ec.SubscribePendingTransactions(ctx, ch1)
	if err != nil {
		t.Fatalf("can't subscribe to pending transaction hashes: %v", err)
	}
	defer sub1.Unsubscribe()

	// Subscribe to Transactions
	ch2 := make(chan *types.Transaction)
	sub2, err := ec.SubscribeFullPendingTransactions(ctx, ch2)
	if err != nil {
		t.Fatalf("can't subscribe to full pending transactions: %v", err)
	}
	defer sub2.Unsubscribe()

	// Send a transaction
	chainID, err := ethcl.ChainID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := ethcl.NonceAt(ctx, testAddr, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Create transaction
	tx := types.NewTransaction(nonce, common.Address{1}, big.NewInt(1), 22000, baseFee, nil)
	signer := types.LatestSignerForChainID(chainID)
	signature, err := crypto.Sign(signer.Hash(tx).Bytes(), testKey)
	if err != nil {
		t.Fatal(err)
	}
	signedTx, err := tx.WithSignature(signer, signature)
	if err != nil {
		t.Fatal(err)
	}
	// Send transaction
	err = ethcl.SendTransaction(ctx, signedTx)
	if err != nil {
		t.Fatal(err)
	}
	// Check that the transaction was sent over the channel. The notification
	// arrives asynchronously and a lost one used to block here forever: the
	// package then hung until the CI job was killed, leaving no stack (#2942).
	select {
	case hash := <-ch1:
		if hash != signedTx.Hash() {
			t.Fatalf("Invalid tx hash received, got %v, want %v", hash, signedTx.Hash())
		}
	case <-time.After(pendingTxTimeout):
		t.Fatalf("no pending transaction hash arrived within %v", pendingTxTimeout)
	}
	// Check that the transaction was sent over the channel
	select {
	case got := <-ch2:
		if got.Hash() != signedTx.Hash() {
			t.Fatalf("Invalid tx hash received, got %v, want %v", got.Hash(), signedTx.Hash())
		}
	case <-time.After(pendingTxTimeout):
		t.Fatalf("no full pending transaction arrived within %v", pendingTxTimeout)
	}
}

func testCallContract(t *testing.T, client *rpc.Client) {
	ec := New(client)
	ctx, cancel := rpcCtx(t)
	defer cancel()
	baseFee := new(big.Int).SetUint64(params.InitialBaseFee)
	msg := ethereum.CallMsg{
		From:     testAddr,
		To:       &common.Address{},
		Gas:      100000,
		GasPrice: baseFee,
		Value:    big.NewInt(1),
	}
	// CallContract without override: the target account is empty, so the call
	// returns nothing.
	res, err := ec.CallContract(ctx, msg, big.NewInt(0), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("unexpected return data from an empty account: %x", res)
	}
	// CallContract with override. The override has to change what the call
	// returns: asserting only that it does not error would pass whether or not
	// it reached the EVM.
	override := OverrideAccount{
		Code: common.FromHex("0x602a60005260206000f3"), // returns 32 bytes holding 0x2a
	}
	mapAcc := make(map[common.Address]OverrideAccount)
	mapAcc[common.Address{}] = override
	res, err = ec.CallContract(ctx, msg, big.NewInt(0), &mapAcc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := common.LeftPadBytes([]byte{0x2a}, 32); !bytes.Equal(res, want) {
		t.Fatalf("override did not reach the EVM: have %x, want %x", res, want)
	}
}

func testTraceTransactions(t *testing.T, client *rpc.Client, txHashes []common.Hash) {
	ec := New(client)
	ctx, cancel := rpcCtx(t)
	defer cancel()
	for _, txHash := range txHashes {
		// The struct logger, default config and an explicit empty one: both
		// must produce the same trace of a transfer that succeeded.
		for _, config := range []*tracers.TraceConfig{nil, {}} {
			trace, err := ec.TraceTransaction(ctx, txHash, config)
			if err != nil {
				t.Fatalf("trace of %s failed: %v", txHash, err)
			}
			result, ok := trace.(map[string]any)
			if !ok {
				t.Fatalf("trace of %s is a %T, want an object", txHash, trace)
			}
			if failed, _ := result["failed"].(bool); failed {
				t.Fatalf("trace of %s reports a failed transaction", txHash)
			}
			// Intrinsic gas plus the ecrecover call the fixture makes.
			gas, ok := result["gas"].(float64)
			if want := params.TxGas + params.EcrecoverGas; !ok || uint64(gas) != want {
				t.Fatalf("trace of %s reports gas %v, want %d", txHash, result["gas"], want)
			}
			// A plain transfer executes no opcode.
			if logs, ok := result["structLogs"].([]any); !ok || len(logs) != 0 {
				t.Fatalf("trace of %s has struct logs for a plain transfer: %v", txHash, result["structLogs"])
			}
		}
	}
}

// TestOverrideAccountMarshal tests override account marshal.
func TestOverrideAccountMarshal(t *testing.T) {
	om := map[common.Address]OverrideAccount{
		{0x11}: {
			// Zero-valued nonce is not overridden, but simply dropped by the encoder.
			Nonce: 0,
		},
		{0xaa}: {
			Nonce: 5,
		},
		{0xbb}: {
			Code: []byte{1},
		},
		{0xcc}: {
			// 'code', 'balance', 'state' should be set when input is
			// a non-nil but empty value.
			Code:    []byte{},
			Balance: big.NewInt(0),
			State:   map[common.Hash]common.Hash{},
			// For 'stateDiff' the behavior is different, empty map
			// is ignored because it makes no difference.
			StateDiff: map[common.Hash]common.Hash{},
		},
	}

	marshalled, err := json.MarshalIndent(&om, "", "  ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := `{
  "0x1100000000000000000000000000000000000000": {},
  "0xaa00000000000000000000000000000000000000": {
    "nonce": "0x5"
  },
  "0xbb00000000000000000000000000000000000000": {
    "code": "0x01"
  },
  "0xcc00000000000000000000000000000000000000": {
    "code": "0x",
    "balance": "0x0",
    "state": {}
  }
}`

	if string(marshalled) != expected {
		t.Error("wrong output:", string(marshalled))
		t.Error("want:", expected)
	}
}

// TestBlockOverridesMarshal tests block overrides marshal.
func TestBlockOverridesMarshal(t *testing.T) {
	for i, tt := range []struct {
		bo   BlockOverrides
		want string
	}{
		{
			bo:   BlockOverrides{},
			want: `{}`,
		},
		{
			bo: BlockOverrides{
				Coinbase: common.HexToAddress("0x1111111111111111111111111111111111111111"),
			},
			want: `{"feeRecipient":"0x1111111111111111111111111111111111111111"}`,
		},
		{
			bo: BlockOverrides{
				Number:     big.NewInt(1),
				Difficulty: big.NewInt(2),
				Time:       3,
				GasLimit:   4,
				BaseFee:    big.NewInt(5),
			},
			want: `{"number":"0x1","difficulty":"0x2","time":"0x3","gasLimit":"0x4","baseFeePerGas":"0x5"}`,
		},
	} {
		marshalled, err := json.Marshal(&tt.bo)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(marshalled) != tt.want {
			t.Errorf("Testcase #%d failed. expected\n%s\ngot\n%s", i, tt.want, string(marshalled))
		}
	}
}

func testCallContractWithBlockOverrides(t *testing.T, client *rpc.Client) {
	ec := New(client)
	ctx, cancel := rpcCtx(t)
	defer cancel()
	baseFee := new(big.Int).SetUint64(params.InitialBaseFee)
	msg := ethereum.CallMsg{
		From:     testAddr,
		To:       &common.Address{},
		Gas:      50000,
		GasPrice: baseFee,
		Value:    big.NewInt(1),
	}
	override := OverrideAccount{
		// Returns coinbase address.
		Code: common.FromHex("0x41806000526014600cf3"),
	}
	mapAcc := make(map[common.Address]OverrideAccount)
	mapAcc[common.Address{}] = override
	res, err := ec.CallContract(ctx, msg, big.NewInt(0), &mapAcc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(res, common.FromHex("0x0000000000000000000000000000000000000000")) {
		t.Fatalf("unexpected result: %x", res)
	}

	// Now test with block overrides
	bo := BlockOverrides{
		Coinbase: common.HexToAddress("0x1111111111111111111111111111111111111111"),
	}
	res, err = ec.CallContractWithBlockOverrides(ctx, msg, big.NewInt(0), &mapAcc, bo)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(res, common.FromHex("0x1111111111111111111111111111111111111111")) {
		t.Fatalf("unexpected result: %x", res)
	}
}

func testTraceTransactionWithCallTracer(t *testing.T, client *rpc.Client, txHashes []common.Hash) {
	ec := New(client)
	ctx, cancel := rpcCtx(t)
	defer cancel()
	for _, txHash := range txHashes {
		// With nil config (defaults).
		result, err := ec.TraceTransactionWithCallTracer(ctx, txHash, nil)
		if err != nil {
			t.Fatalf("nil config: %v", err)
		}
		if result.Type != "CALL" {
			t.Fatalf("unexpected type: %s", result.Type)
		}
		if result.From == (common.Address{}) {
			t.Fatal("from is zero")
		}
		if result.Gas == 0 {
			t.Fatal("gas is zero")
		}

		// With explicit config.
		result, err = ec.TraceTransactionWithCallTracer(ctx, txHash,
			&CallTracerConfig{},
		)
		if err != nil {
			t.Fatalf("explicit config: %v", err)
		}
		if result.Type != "CALL" {
			t.Fatalf("unexpected type: %s", result.Type)
		}
	}
}

func testTraceCallWithCallTracer(t *testing.T, client *rpc.Client) {
	ec := New(client)
	ctx, cancel := rpcCtx(t)
	defer cancel()
	baseFee := new(big.Int).SetUint64(params.InitialBaseFee)
	msg := ethereum.CallMsg{
		From:     testAddr,
		To:       &common.Address{},
		Gas:      21000,
		GasPrice: baseFee,
		Value:    big.NewInt(1),
	}
	result, err := ec.TraceCallWithCallTracer(ctx, msg,
		rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber), nil, nil, nil,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Type != "CALL" {
		t.Fatalf("unexpected type: %s", result.Type)
	}
	if result.From == (common.Address{}) {
		t.Fatal("from is zero")
	}
	if result.Gas == 0 {
		t.Fatal("gas is zero")
	}
}
