package tracetest

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/common/hexutil"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/eth/tracers"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/XinFinOrg/XDPoSChain/tests"
)

// nonEVMRouteCase is one routing configuration of the trace below. While the XDCX
// receiver fork is active, a transaction to a system address is handled by
// ApplyEmptyTransaction and never enters the EVM; without it the EVM executes the
// transaction and pushes a real top-level frame.
type nonEVMRouteCase struct {
	name         string
	tipXDCXBlock *big.Int
	evmRan       bool
}

var nonEVMRouteCases = []nonEVMRouteCase{
	{name: "receiver fork active", tipXDCXBlock: common.Big0, evmRan: false},
	{name: "receiver fork inactive", tipXDCXBlock: big.NewInt(2), evmRan: true},
}

// nonEVMFlatFrame is the subset of the flat tracer output the test compares.
type nonEVMFlatFrame struct {
	Type      string `json:"type"`
	Subtraces int    `json:"subtraces"`
	Action    struct {
		To *common.Address `json:"to"`
	} `json:"action"`
	Result struct {
		GasUsed *hexutil.Uint64 `json:"gasUsed"`
	} `json:"result"`
}

// nonEVMCallFrame is the subset of the nested call tracer output the test compares.
type nonEVMCallFrame struct {
	Type    string            `json:"type"`
	To      *common.Address   `json:"to"`
	GasUsed *hexutil.Uint64   `json:"gasUsed"`
	Calls   []json.RawMessage `json:"calls"`
}

// traceNonEVMTxOnce runs a transaction to an XDCX system address through the block
// processing entry point, routing included, and returns its tracer result together with
// the gas the receipt reports.
//
// It goes through core.ApplyTransactionWithEVM instead of driving the tracer hooks by
// hand, because that function owns the routing: it is what decides whether the EVM ever
// sees the transaction, and therefore whether the tracer is asked for a result with an
// empty callstack.
func traceNonEVMTxOnce(t *testing.T, tc nonEVMRouteCase, tracerName string) (json.RawMessage, uint64) {
	t.Helper()

	config := *params.TestChainConfig
	config.TIPXDCXBlock = tc.tipXDCXBlock
	config.TIPXDCXReceiverDisableBlock = nil

	key, _ := crypto.GenerateKey()
	from := crypto.PubkeyToAddress(key.PublicKey)
	to := common.TradingStateAddrBinary
	blockNumber := common.Big1

	genesis := &core.Genesis{
		Config: &config,
		Alloc: types.GenesisAlloc{
			from: {Balance: new(big.Int).Mul(big.NewInt(10), big.NewInt(params.Ether))},
		},
	}
	statedb := tests.MakePreState(rawdb.NewMemoryDatabase(), genesis.Alloc)
	// The entry point reads validator and fee state through the state itself, so the state
	// needs the chain config the production paths attach to it as well.
	if err := statedb.EnsureChainConfig(&config); err != nil {
		t.Fatalf("failed to attach the chain config: %v", err)
	}

	signer := types.MakeSigner(&config, blockNumber)
	tx, err := types.SignTx(types.NewTx(&types.LegacyTx{
		Nonce:    0,
		To:       &to,
		Value:    big.NewInt(1000),
		Gas:      params.TxGas,
		GasPrice: big.NewInt(1),
	}), signer, key)
	if err != nil {
		t.Fatalf("failed to sign the transaction: %v", err)
	}
	if !tx.IsNonEVMTx() {
		t.Fatal("premise: the trading state address must flag the transaction as non-EVM")
	}

	blockCtx := vm.BlockContext{
		CanTransfer: core.CanTransfer,
		Transfer:    core.Transfer,
		Coinbase:    common.HexToAddress("0x000000000000000000000000000000000000c01b"),
		BlockNumber: blockNumber,
		Difficulty:  big.NewInt(1),
		GasLimit:    30_000_000,
		BaseFee:     common.Big0,
	}
	msg, err := core.TransactionToMessage(tx, signer, nil, blockNumber, blockCtx.BaseFee, &config)
	if err != nil {
		t.Fatalf("failed to build the message: %v", err)
	}
	tracer, err := tracers.DefaultDirectory.New(tracerName, new(tracers.Context), nil, &config)
	if err != nil {
		t.Fatalf("failed to create the %s: %v", tracerName, err)
	}

	statedb.SetTxContext(tx.Hash(), 0)
	// Hand the EVM a hooked state, the way the production trace path does: the tracer
	// hooks see the state changes, and the entry point below finalises that same state,
	// not the plain one behind it.
	hookedState := state.NewHookedState(statedb, tracer.Hooks)
	evm := vm.NewEVM(blockCtx, hookedState, nil, &config, vm.Config{Tracer: tracer.Hooks, NoBaseFee: true})
	var usedGas uint64
	receipt, _, _, err := core.ApplyTransactionWithEVM(msg, new(core.GasPool).AddGas(msg.GasLimit), statedb, blockNumber, common.Hash{}, tx, &usedGas, evm, nil)
	if err != nil {
		t.Fatalf("%s: ApplyTransactionWithEVM failed: %v", tracerName, err)
	}
	// With an empty callstack GetResult used to fail with "invalid number of calls" and
	// abort the whole block trace instead of reporting the transaction.
	res, err := tracer.GetResult()
	if err != nil {
		t.Fatalf("%s: GetResult failed: %v", tracerName, err)
	}
	return res, receipt.GasUsed
}

// checkNonEVMFrame asserts what both tracers must report for the single top-level frame
// of the transaction: the system address it was sent to, and the gas of the receipt,
// which is 0 exactly when the EVM did not execute it.
func checkNonEVMFrame(t *testing.T, tc nonEVMRouteCase, to *common.Address, gasUsed *hexutil.Uint64, receiptGas uint64) {
	t.Helper()

	if to == nil {
		t.Fatal("the frame is missing its to address")
	}
	if *to != common.TradingStateAddrBinary {
		t.Fatalf("frame to = %s, want the trading state address %s", *to, common.TradingStateAddrBinary)
	}
	if gasUsed == nil {
		t.Fatal("the frame is missing its gasUsed")
	}
	if uint64(*gasUsed) != receiptGas {
		t.Fatalf("frame gasUsed = %d, want the receipt gas %d", uint64(*gasUsed), receiptGas)
	}
	if tc.evmRan != (receiptGas > 0) {
		t.Fatalf("evmRan = %v but the receipt gas is %d (0 only when the EVM did not run)", tc.evmRan, receiptGas)
	}
}

// TestNonEVMTxThroughBlockProcessingRouting traces a transaction to an XDCX system
// address through core.ApplyTransactionWithEVM, the entry point block processing and the
// block tracers share, with the native tracers linked in. The routing decides whether the
// EVM ever runs the transaction, so both the synthetic frame (EVM stayed out) and the real
// top-level frame (EVM ran, even though the to address flags the transaction as non-EVM)
// must come out of GetResult without an error.
//
// The block level assembly of these per transaction results is covered by
// TestTraceBlockSkipNonceTransactions in the tracers package, which cannot import the
// native tracers: the two tests cover the two halves of the same path.
func TestNonEVMTxThroughBlockProcessingRouting(t *testing.T) {
	for _, tc := range nonEVMRouteCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("flatCallTracer", func(t *testing.T) {
				res, receiptGas := traceNonEVMTxOnce(t, tc, "flatCallTracer")

				var frames []nonEVMFlatFrame
				if err := json.Unmarshal(res, &frames); err != nil {
					t.Fatalf("failed to unmarshal the flat trace: %v", err)
				}
				if len(frames) != 1 {
					t.Fatalf("flat trace frames = %d, want 1", len(frames))
				}
				if frames[0].Type != "call" {
					t.Fatalf("frame type = %q, want %q", frames[0].Type, "call")
				}
				if frames[0].Subtraces != 0 {
					t.Fatalf("frame subtraces = %d, want 0", frames[0].Subtraces)
				}
				checkNonEVMFrame(t, tc, frames[0].Action.To, frames[0].Result.GasUsed, receiptGas)
			})
			t.Run("callTracer", func(t *testing.T) {
				res, receiptGas := traceNonEVMTxOnce(t, tc, "callTracer")

				var frame nonEVMCallFrame
				if err := json.Unmarshal(res, &frame); err != nil {
					t.Fatalf("failed to unmarshal the call trace: %v", err)
				}
				if frame.Type != "CALL" {
					t.Fatalf("frame type = %q, want %q", frame.Type, "CALL")
				}
				if len(frame.Calls) != 0 {
					t.Fatalf("frame calls = %d, want 0", len(frame.Calls))
				}
				checkNonEVMFrame(t, tc, frame.To, frame.GasUsed, receiptGas)
			})
		})
	}
}
