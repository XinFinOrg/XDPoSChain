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
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/holiman/uint256"
)

// The EIP-7708 transfer log (emitted by core.Transfer under the Amsterdam
// rules) is only produced when rules.IsAmsterdam is active. The shared
// frameChainConfig() deliberately leaves AmsterdamTime nil, so these tests
// run under a private clone with AmsterdamTime = 0 (test-only; no preset
// network configuration is touched).
var cfgFrameAmsterdam = func() *params.ChainConfig {
	cfg := *params.MergedTestChainConfig
	cfg.FrameTxTime = new(uint64)
	cfg.AmsterdamTime = new(uint64)
	return &cfg
}()

// amsterdamFrameEVM mirrors frameCoreEVM but over cfgFrameAmsterdam.
func amsterdamFrameEVM(sdb *state.StateDB) *vm.EVM {
	ctx := vm.BlockContext{
		CanTransfer:      CanTransfer,
		Transfer:         Transfer,
		GetHash:          func(uint64) common.Hash { return common.Hash{} },
		BlockNumber:      big.NewInt(0),
		Time:             0,
		Random:           &common.Hash{},
		Difficulty:       big.NewInt(0),
		BaseFee:          big.NewInt(0),
		BlobBaseFee:      big.NewInt(0),
		GasLimit:         60_000_000,
		CostPerStateByte: params.CostPerStateByte,
	}
	return vm.NewEVM(ctx, sdb, cfgFrameAmsterdam, vm.Config{NoBaseFee: true})
}

func applyAmsterdamFrameTx(t *testing.T, sdb *state.StateDB, ftx *types.FrameTx) (*ExecutionResult, *GasPool, error) {
	t.Helper()
	evm := amsterdamFrameEVM(sdb)
	msg, err := TransactionToMessage(types.NewTx(ftx), frameSgn, evm.Context.BaseFee)
	if err != nil {
		t.Fatalf("to message: %v", err)
	}
	gp := NewGasPool(evm.Context.GasLimit)
	evm.SetTxContext(NewEVMTxContext(msg))
	st := newStateTransition(evm, msg, gp, common.Address{})
	res, err := st.execute()
	return res, gp, err
}

// transferLogs filters the system-address EIP-7708 transfer logs.
func transferLogs(logs []*types.Log) []*types.Log {
	var out []*types.Log
	for _, l := range logs {
		if l.Address == params.SystemAddress {
			out = append(out, l)
		}
	}
	return out
}

// assertTransferLog checks the exact EIP-7708 format: address SystemAddress,
// topics [TransferEvent, from, to], 32-byte big-endian amount.
func assertTransferLog(t *testing.T, l *types.Log, from, to common.Address, amount uint64) {
	t.Helper()
	if l.Address != params.SystemAddress {
		t.Fatalf("log address = %x, want SystemAddress %x", l.Address, params.SystemAddress)
	}
	if len(l.Topics) != 3 {
		t.Fatalf("log topics = %d, want 3", len(l.Topics))
	}
	if l.Topics[0] != params.EthTransferLogEvent {
		t.Fatalf("topic0 = %x, want EthTransferLogEvent %x", l.Topics[0], params.EthTransferLogEvent)
	}
	if l.Topics[1] != common.BytesToHash(from.Bytes()) {
		t.Fatalf("topic1 = %x, want from %x", l.Topics[1], from)
	}
	if l.Topics[2] != common.BytesToHash(to.Bytes()) {
		t.Fatalf("topic2 = %x, want to %x", l.Topics[2], to)
	}
	if len(l.Data) != 32 {
		t.Fatalf("log data = %d bytes, want 32", len(l.Data))
	}
	if got := new(big.Int).SetBytes(l.Data); got.Uint64() != amount {
		t.Fatalf("log amount = %v, want %d", got, amount)
	}
}

// approvePrefixFrames returns the canonical two-frame approve prefix used by
// the frame execution tests: default-code execution approve, then a payment
// approve via the APPROVE opcode contract.
func approvePrefixFrames() []types.Frame {
	return []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 0x2, Limits: mkFrameLimits(100_000, 300_000)},
		{Mode: types.FrameModeVerify, Target: &frameContractPayer, Flags: 0x1, Limits: mkFrameLimits(100_000, 300_000)},
	}
}

// TestFrameTransferLogSuccess: a successful SENDER value transfer emits
// exactly one correctly formatted EIP-7708 log, present in the frame
// receipt and in the concatenated state log list in execution order.
func TestFrameTransferLogSuccess(t *testing.T) {
	contractT := common.BytesToAddress([]byte("frame-transfer-target"))
	sdb := mkState(types.GenesisAlloc{
		senderAddr:         {Balance: big.NewInt(1_000)},
		frameContractPayer: {Code: frameApproveCode(0x1)},
		contractT:          {Code: frameCodeSStoreLog(0, 4)}, // emits a normal LOG after SSTORE
	})
	frames := append(approvePrefixFrames(),
		types.Frame{Mode: types.FrameModeSender, Target: &contractT, Flags: 0x0, Limits: mkFrameLimits(100_000, 300_000), Value: uint256.NewInt(100)})
	ftx := frameTx(0, frames, []types.FrameSignature{{Scheme: types.FrameSigSchemeSecp256k1}})
	ftx.Signatures = defaultApproveSigs(t, senderKey, ftx)

	res, _, err := applyAmsterdamFrameTx(t, sdb, ftx)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(res.FrameReceipts) != 3 {
		t.Fatalf("receipts: %d, want 3", len(res.FrameReceipts))
	}
	// Exactly one transfer log overall.
	all := sdb.Logs()
	tl := transferLogs(all)
	if len(tl) != 1 {
		t.Fatalf("transfer logs = %d, want 1 (all logs %d)", len(tl), len(all))
	}
	assertTransferLog(t, tl[0], senderAddr, contractT, 100)
	// The frame receipt carries the transfer log first (the transfer is
	// recorded by core.Transfer before the target contract's own LOG op).
	fr := res.FrameReceipts[2]
	if len(fr.Logs) != len(all) {
		t.Fatalf("frame receipt logs = %d, want %d (all block logs)", len(fr.Logs), len(all))
	}
	assertTransferLog(t, fr.Logs[0], senderAddr, contractT, 100)
	// Concatenated order: the transfer log precedes the contract LOG.
	if fr.Logs[1] != all[1] {
		t.Fatal("frame receipt log order diverges from state log order")
	}
	if fr.Status != 1 {
		t.Fatalf("frame status = %d, want 1", fr.Status)
	}
}

// TestFrameTransferLogRevertDiscarded: a frame that reverts discards the
// transfer log it produced.
func TestFrameTransferLogRevertDiscarded(t *testing.T) {
	reverter := common.BytesToAddress([]byte("frame-revert-target"))
	sdb := mkState(types.GenesisAlloc{
		senderAddr:         {Balance: big.NewInt(1_000)},
		frameContractPayer: {Code: frameApproveCode(0x1)},
		reverter:           {Code: []byte{0x60, 0x00, 0x60, 0x00, 0xfd}}, // PUSH1 0 PUSH1 0 REVERT
	})
	frames := append(approvePrefixFrames(),
		types.Frame{Mode: types.FrameModeSender, Target: &reverter, Flags: 0x0, Limits: mkFrameLimits(100_000, 300_000), Value: uint256.NewInt(100)})
	ftx := frameTx(0, frames, []types.FrameSignature{{Scheme: types.FrameSigSchemeSecp256k1}})
	ftx.Signatures = defaultApproveSigs(t, senderKey, ftx)

	res, _, err := applyAmsterdamFrameTx(t, sdb, ftx)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if got := sdb.GetBalance(reverter).Uint64(); got != 0 {
		t.Fatalf("reverted target balance = %d, want 0", got)
	}
	if got := sdb.GetBalance(senderAddr).Uint64(); got != 1_000 {
		t.Fatalf("sender balance = %d, want 1000 (transfer rolled back)", got)
	}
	if n := len(sdb.Logs()); n != 0 {
		t.Fatalf("state logs = %d, want 0 after revert", n)
	}
	fr := res.FrameReceipts[2]
	if fr.Status != 0 {
		t.Fatalf("frame status = %d, want 0", fr.Status)
	}
	if len(fr.Logs) != 0 {
		t.Fatalf("frame receipt logs = %d, want 0", len(fr.Logs))
	}
}

// TestFrameTransferLogAtomicBatchRollback: an atomic batch rollback
// discards transfer logs produced by earlier frames of the batch while
// preserving their success status (with zeroed state gas) and gas
// accounting.
func TestFrameTransferLogAtomicBatchRollback(t *testing.T) {
	contractA := common.BytesToAddress([]byte("frame-batch-A"))
	reverter := common.BytesToAddress([]byte("frame-batch-B"))
	sdb := mkState(types.GenesisAlloc{
		senderAddr:         {Balance: big.NewInt(1_000)},
		frameContractPayer: {Code: frameApproveCode(0x1)},
		contractA:          {Code: frameCodeSStore(0, 1)},
		reverter:           {Code: []byte{0x60, 0x00, 0x60, 0x00, 0xfd}},
	})
	frames := append(approvePrefixFrames(),
		types.Frame{Mode: types.FrameModeSender, Target: &contractA, Flags: types.FrameAtomicBatchFlag, Limits: mkFrameLimits(100_000, 300_000), Value: uint256.NewInt(50)},
		types.Frame{Mode: types.FrameModeSender, Target: &reverter, Flags: types.FrameAtomicBatchFlag, Limits: mkFrameLimits(100_000, 300_000), Value: uint256.NewInt(70)},
	)
	ftx := frameTx(0, frames, []types.FrameSignature{{Scheme: types.FrameSigSchemeSecp256k1}})
	ftx.Signatures = defaultApproveSigs(t, senderKey, ftx)

	res, _, err := applyAmsterdamFrameTx(t, sdb, ftx)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	// Both transfers rolled back.
	if got := sdb.GetBalance(contractA).Uint64(); got != 0 {
		t.Fatalf("batch frame A balance = %d, want 0", got)
	}
	if got := sdb.GetBalance(senderAddr).Uint64(); got != 1_000 {
		t.Fatalf("sender balance = %d, want 1000", got)
	}
	// No logs survive the rollback.
	if n := len(sdb.Logs()); n != 0 {
		t.Fatalf("state logs = %d, want 0 after batch rollback", n)
	}
	ra, rb := res.FrameReceipts[2], res.FrameReceipts[3]
	if ra.Status != 1 {
		t.Fatalf("frame A status = %d, want 1 (status preserved)", ra.Status)
	}
	if ra.GasUsedState != 0 {
		t.Fatalf("frame A state gas = %d, want 0 (zeroed by rollback)", ra.GasUsedState)
	}
	if len(ra.Logs) != 0 {
		t.Fatalf("frame A logs = %d, want 0 (discarded by rollback)", len(ra.Logs))
	}
	if rb.Status != 0 {
		t.Fatalf("frame B status = %d, want 0", rb.Status)
	}
	if len(rb.Logs) != 0 {
		t.Fatalf("frame B logs = %d, want 0", len(rb.Logs))
	}
}

// TestFrameTransferLogSkippedFrame: a frame skipped by an atomic batch
// rollback emits no transfer logs and its budget is untouched.
func TestFrameTransferLogSkippedFrame(t *testing.T) {
	contractA := common.BytesToAddress([]byte("frame-skip-A"))
	reverter := common.BytesToAddress([]byte("frame-skip-B"))
	contractC := common.BytesToAddress([]byte("frame-skip-C"))
	sdb := mkState(types.GenesisAlloc{
		senderAddr:         {Balance: big.NewInt(1_000)},
		frameContractPayer: {Code: frameApproveCode(0x1)},
		contractA:          {Code: frameCodeSStore(0, 1)},
		reverter:           {Code: []byte{0x60, 0x00, 0x60, 0x00, 0xfd}},
		contractC:          {Code: frameCodeSStore(0, 9)},
	})
	frames := append(approvePrefixFrames(),
		types.Frame{Mode: types.FrameModeSender, Target: &contractA, Flags: types.FrameAtomicBatchFlag, Limits: mkFrameLimits(100_000, 300_000), Value: uint256.NewInt(50)},
		types.Frame{Mode: types.FrameModeSender, Target: &reverter, Flags: types.FrameAtomicBatchFlag, Limits: mkFrameLimits(100_000, 300_000), Value: uint256.NewInt(70)},
		types.Frame{Mode: types.FrameModeSender, Target: &contractC, Flags: 0x0, Limits: mkFrameLimits(100_000, 300_000), Value: uint256.NewInt(90)},
	)
	ftx := frameTx(0, frames, []types.FrameSignature{{Scheme: types.FrameSigSchemeSecp256k1}})
	ftx.Signatures = defaultApproveSigs(t, senderKey, ftx)

	res, _, err := applyAmsterdamFrameTx(t, sdb, ftx)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if got := sdb.GetBalance(contractA).Uint64(); got != 0 {
		t.Fatalf("batch frame A balance = %d, want 0 (rolled back)", got)
	}
	if got := sdb.GetBalance(contractC).Uint64(); got != 0 {
		t.Fatalf("skipped frame C balance = %d, want 0 (never executed)", got)
	}
	if got := sdb.GetState(contractC, common.Hash{}); got != (common.Hash{}) {
		t.Fatalf("skipped frame C storage = %x, want empty", got)
	}
	if n := len(sdb.Logs()); n != 0 {
		t.Fatalf("state logs = %d, want 0", n)
	}
	rc := res.FrameReceipts[4]
	if rc.Status != frameStatusSkipped {
		t.Fatalf("frame C status = %d, want skipped (%d)", rc.Status, frameStatusSkipped)
	}
	if rc.GasUsedExecution != 0 || rc.GasUsedState != 0 {
		t.Fatalf("skipped frame C gas = %d/%d, want 0/0", rc.GasUsedExecution, rc.GasUsedState)
	}
	if len(rc.Logs) != 0 {
		t.Fatalf("skipped frame C logs = %d, want 0", len(rc.Logs))
	}
}

// TestFrameTransferLogBloom: the block-level logs bloom includes the
// transfer log's address and topics.
func TestFrameTransferLogBloom(t *testing.T) {
	contractT := common.BytesToAddress([]byte("frame-bloom-target"))
	sdb := mkState(types.GenesisAlloc{
		senderAddr:         {Balance: big.NewInt(1_000)},
		frameContractPayer: {Code: frameApproveCode(0x1)},
		contractT:          {Code: frameCodeSStore(0, 4)},
	})
	frames := append(approvePrefixFrames(),
		types.Frame{Mode: types.FrameModeSender, Target: &contractT, Flags: 0x0, Limits: mkFrameLimits(100_000, 300_000), Value: uint256.NewInt(100)})
	ftx := frameTx(0, frames, []types.FrameSignature{{Scheme: types.FrameSigSchemeSecp256k1}})
	ftx.Signatures = defaultApproveSigs(t, senderKey, ftx)

	if _, _, err := applyAmsterdamFrameTx(t, sdb, ftx); err != nil {
		t.Fatalf("execute: %v", err)
	}
	tl := transferLogs(sdb.Logs())
	if len(tl) != 1 {
		t.Fatalf("transfer logs = %d, want 1", len(tl))
	}
	receipt := &types.Receipt{Logs: sdb.Logs()}
	bloom := types.CreateBloom(receipt)
	for _, topic := range tl[0].Topics {
		if !types.BloomLookup(bloom, topic) {
			t.Fatalf("bloom missing topic %x", topic)
		}
	}
	if !types.BloomLookup(bloom, tl[0].Address) {
		t.Fatal("bloom missing SystemAddress")
	}
}

// TestFrameTransferLogChildCallRollback: a value transfer performed by a
// child call inside a contract is rolled back when the enclosing frame
// reverts.
func TestFrameTransferLogChildCallRollback(t *testing.T) {
	child := common.BytesToAddress([]byte("frame-child"))
	caller := common.BytesToAddress([]byte("frame-child-caller"))
	// CALL(child, value=1) with empty input, then REVERT.
	code := append([]byte{
		0x60, 0x00, // retSize
		0x60, 0x00, // retOffset
		0x60, 0x00, // argSize
		0x60, 0x00, // argOffset
		0x60, 0x01, // value = 1
		0x73, // PUSH20 child
	}, child.Bytes()...)
	code = append(code,
		0x61, 0xff, 0xff, // gas
		0xf1,                         // CALL
		0x60, 0x00, 0x60, 0x00, 0xfd, // PUSH1 0 PUSH1 0 REVERT
	)
	sdb := mkState(types.GenesisAlloc{
		senderAddr:         {Balance: big.NewInt(1_000)},
		frameContractPayer: {Code: frameApproveCode(0x1)},
		caller:             {Code: code, Balance: big.NewInt(10)},
		child:              {},
	})
	frames := append(approvePrefixFrames(),
		types.Frame{Mode: types.FrameModeSender, Target: &caller, Flags: 0x0, Limits: mkFrameLimits(200_000, 300_000), Value: uint256.NewInt(100)})
	ftx := frameTx(0, frames, []types.FrameSignature{{Scheme: types.FrameSigSchemeSecp256k1}})
	ftx.Signatures = defaultApproveSigs(t, senderKey, ftx)

	res, _, err := applyAmsterdamFrameTx(t, sdb, ftx)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	// Everything rolled back with the frame.
	if got := sdb.GetBalance(child).Uint64(); got != 0 {
		t.Fatalf("child balance = %d, want 0 (rolled back)", got)
	}
	if got := sdb.GetBalance(caller).Uint64(); got != 10 {
		t.Fatalf("caller balance = %d, want 10 (frame transfer rolled back)", got)
	}
	if n := len(transferLogs(sdb.Logs())); n != 0 {
		t.Fatalf("transfer logs = %d, want 0 (child call rolled back)", n)
	}
	fr := res.FrameReceipts[2]
	if fr.Status != 0 {
		t.Fatalf("frame status = %d, want 0", fr.Status)
	}
	if len(fr.Logs) != 0 {
		t.Fatalf("frame receipt logs = %d, want 0", len(fr.Logs))
	}
}
