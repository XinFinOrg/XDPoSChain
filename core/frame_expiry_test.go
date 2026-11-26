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
	"encoding/binary"
	"math/big"
	"strings"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// frameEVMWithTime mirrors frameCoreEVM with a configurable block timestamp
// (the expiry verifier compares against evm.Context.Time).
func frameEVMWithTime(sdb *state.StateDB, blockTime uint64) *vm.EVM {
	ctx := vm.BlockContext{
		CanTransfer:      CanTransfer,
		Transfer:         Transfer,
		GetHash:          func(uint64) common.Hash { return common.Hash{} },
		BlockNumber:      big.NewInt(0),
		Time:             blockTime,
		Random:           &common.Hash{},
		Difficulty:       big.NewInt(0),
		BaseFee:          big.NewInt(0),
		BlobBaseFee:      big.NewInt(0),
		GasLimit:         60_000_000,
		CostPerStateByte: params.CostPerStateByte,
	}
	return vm.NewEVM(ctx, sdb, cfgFrame, vm.Config{NoBaseFee: true})
}

func applyFrameTxAtTime(t *testing.T, sdb *state.StateDB, ftx *types.FrameTx, blockTime uint64) (*ExecutionResult, error) {
	t.Helper()
	evm := frameEVMWithTime(sdb, blockTime)
	msg, err := TransactionToMessage(types.NewTx(ftx), frameSgn, evm.Context.BaseFee)
	if err != nil {
		t.Fatalf("to message: %v", err)
	}
	gp := NewGasPool(evm.Context.GasLimit)
	evm.SetTxContext(NewEVMTxContext(msg))
	st := newStateTransition(evm, msg, gp, common.Address{})
	return st.execute()
}

// expiryFrameData encodes an 8-byte big-endian deadline (EXPIRY_DATA_LENGTH).
func expiryFrameData(deadline uint64) []byte {
	data := make([]byte, types.FrameExpiryDataLength)
	binary.BigEndian.PutUint64(data, deadline)
	return data
}

// expiryFrame builds a well-formed expiry verifier frame.
func expiryFrame(deadline uint64) types.Frame {
	target := types.FrameExpiryVerifier
	return types.Frame{
		Mode:   types.FrameModeVerify,
		Target: &target,
		Flags:  0x0,
		Limits: types.FrameLimits{Execution: 100_000, State: 0},
		Data:   expiryFrameData(deadline),
	}
}

// expiryApprovePrefix builds [expiry, self_verify]: the expiry verifier frame
// followed by a self-relay execution+payment approve, matching the mempool
// prefix shape [expiry_verify, self_verify].
func expiryApprovePrefix(deadline uint64) []types.Frame {
	return []types.Frame{
		expiryFrame(deadline),
		{Mode: types.FrameModeVerify, Flags: 0x3, Limits: mkFrameLimits(100_000, 300_000)},
	}
}

// expected expiry verifier gas: cold access (2600) + canonical runtime cost.
const (
	expiryGasSuccess = 2600 + 51 // access + successful canonical execution
)

// TestFrameExpirySuccess: a future deadline passes; the expiry frame succeeds
// consuming exactly the cold access charge plus the canonical runtime gas.
func TestFrameExpirySuccess(t *testing.T) {
	sdb := mkState(types.GenesisAlloc{senderAddr: {Balance: big.NewInt(1_000_000)}})
	emptyTarget := common.BytesToAddress([]byte("frame-expiry-success-target"))
	frames := append(expiryApprovePrefix(10_000),
		types.Frame{Mode: types.FrameModeSender, Target: &emptyTarget, Flags: 0x0, Limits: mkFrameLimits(100_000, 300_000)})
	ftx := frameTx(0, frames, []types.FrameSignature{{Scheme: types.FrameSigSchemeSecp256k1}})
	ftx.Signatures = defaultApproveSigs(t, senderKey, ftx)

	res, err := applyFrameTxAtTime(t, sdb, ftx, 5_000)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(res.FrameReceipts) != 3 {
		t.Fatalf("receipts: %d, want 3", len(res.FrameReceipts))
	}
	fr := res.FrameReceipts[0]
	if fr.Status != 1 {
		t.Fatalf("expiry frame status = %d, want 1", fr.Status)
	}
	if fr.GasUsedExecution != expiryGasSuccess {
		t.Fatalf("expiry frame execution gas = %d, want %d (2600 cold access + 51 canonical)", fr.GasUsedExecution, expiryGasSuccess)
	}
	if fr.GasUsedState != 0 {
		t.Fatalf("expiry frame state gas = %d, want 0", fr.GasUsedState)
	}
	for i, want := range []uint8{1, 1, 1} {
		if res.FrameReceipts[i].Status != want {
			t.Fatalf("frame %d status = %d, want %d", i, res.FrameReceipts[i].Status, want)
		}
	}
}

// TestFrameExpiryEquality: verification succeeds when the timestamp equals
// the deadline (the call reverts only when block.timestamp > expiry).
func TestFrameExpiryEquality(t *testing.T) {
	sdb := mkState(types.GenesisAlloc{senderAddr: {Balance: big.NewInt(1_000_000)}})
	frames := expiryApprovePrefix(5_000)
	ftx := frameTx(0, frames, []types.FrameSignature{{Scheme: types.FrameSigSchemeSecp256k1}})
	ftx.Signatures = defaultApproveSigs(t, senderKey, ftx)

	res, err := applyFrameTxAtTime(t, sdb, ftx, 5_000)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if res.FrameReceipts[0].Status != 1 {
		t.Fatalf("expiry frame status = %d, want 1 at deadline equality", res.FrameReceipts[0].Status)
	}
}

// TestFrameExpiryExpired: a past deadline fails the VERIFY frame and
// invalidates the transaction with all effects rolled back.
func TestFrameExpiryExpired(t *testing.T) {
	sdb := mkState(types.GenesisAlloc{senderAddr: {Balance: big.NewInt(1_000_000)}})
	frames := expiryApprovePrefix(4_999)
	ftx := frameTx(0, frames, []types.FrameSignature{{Scheme: types.FrameSigSchemeSecp256k1}})
	ftx.Signatures = defaultApproveSigs(t, senderKey, ftx)

	_, err := applyFrameTxAtTime(t, sdb, ftx, 5_000)
	if err == nil {
		t.Fatal("execute: want VERIFY failure for expired deadline, got success")
	}
	if !strings.Contains(err.Error(), "VERIFY frame failed") {
		t.Fatalf("error = %v, want VERIFY frame failure", err)
	}
	// The transaction-invalid outcome rolls back all effects: the
	// self_verify approve (frame 1) never ran, so the nonce is untouched.
	if nonce := sdb.GetNonce(senderAddr); nonce != 0 {
		t.Fatalf("sender nonce = %d, want 0 (tx rolled back)", nonce)
	}
}

// TestFrameExpiryMalformedData: calldata that is not exactly 8 bytes fails
// verification (canonical runtime size check), invalidating the transaction.
func TestFrameExpiryMalformedData(t *testing.T) {
	malformed := expiryFrame(10_000)
	malformed.Data = malformed.Data[:4]
	sdb := mkState(types.GenesisAlloc{senderAddr: {Balance: big.NewInt(1_000_000)}})
	frames := append([]types.Frame{malformed},
		types.Frame{Mode: types.FrameModeVerify, Flags: 0x3, Limits: mkFrameLimits(100_000, 300_000)})
	ftx := frameTx(0, frames, []types.FrameSignature{{Scheme: types.FrameSigSchemeSecp256k1}})
	ftx.Signatures = defaultApproveSigs(t, senderKey, ftx)

	_, err := applyFrameTxAtTime(t, sdb, ftx, 5_000)
	if err == nil {
		t.Fatal("execute: want VERIFY failure for malformed calldata, got success")
	}
	if !strings.Contains(err.Error(), "VERIFY frame failed") {
		t.Fatalf("error = %v, want VERIFY frame failure", err)
	}
	if nonce := sdb.GetNonce(senderAddr); nonce != 0 {
		t.Fatalf("sender nonce = %d, want 0 (tx rolled back)", nonce)
	}
}

// TestFrameExpiryAtomicBatchInteraction: an atomic batch that rolls back
// after the expiry verifier frame does not affect the already-successful
// expiry frame; the batch's earlier frames keep their status with zeroed
// state gas, and the frame batched after the failing one is skipped.
func TestFrameExpiryAtomicBatchInteraction(t *testing.T) {
	contractA := common.BytesToAddress([]byte("frame-expiry-batch-A"))
	reverter := common.BytesToAddress([]byte("frame-expiry-batch-B"))
	contractC := common.BytesToAddress([]byte("frame-expiry-batch-C"))
	sdb := mkState(types.GenesisAlloc{
		senderAddr: {Balance: big.NewInt(1_000_000)},
		contractA:  {Code: frameCodeSStore(0, 1)},
		reverter:   {Code: []byte{0x60, 0x00, 0x60, 0x00, 0xfd}},
		contractC:  {Code: frameCodeSStore(0, 9)},
	})
	frames := append(expiryApprovePrefix(10_000),
		types.Frame{Mode: types.FrameModeSender, Target: &contractA, Flags: types.FrameAtomicBatchFlag, Limits: mkFrameLimits(100_000, 300_000)},
		types.Frame{Mode: types.FrameModeSender, Target: &reverter, Flags: types.FrameAtomicBatchFlag, Limits: mkFrameLimits(100_000, 300_000)},
		types.Frame{Mode: types.FrameModeSender, Target: &contractC, Flags: 0x0, Limits: mkFrameLimits(100_000, 300_000)},
	)
	ftx := frameTx(0, frames, []types.FrameSignature{{Scheme: types.FrameSigSchemeSecp256k1}})
	ftx.Signatures = defaultApproveSigs(t, senderKey, ftx)

	res, err := applyFrameTxAtTime(t, sdb, ftx, 5_000)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(res.FrameReceipts) != 5 {
		t.Fatalf("receipts: %d, want 5", len(res.FrameReceipts))
	}
	// Expiry frame ran before the batch and stays successful.
	if res.FrameReceipts[0].Status != 1 {
		t.Fatalf("expiry frame status = %d, want 1", res.FrameReceipts[0].Status)
	}
	// Batch rolled back: A keeps its status with zeroed state gas and its
	// effects reverted.
	if got := sdb.GetState(contractA, common.Hash{}); got != (common.Hash{}) {
		t.Fatalf("batch frame A storage = %x, want empty (rolled back)", got)
	}
	if res.FrameReceipts[2].Status != 1 || res.FrameReceipts[2].GasUsedState != 0 {
		t.Fatalf("frame A status/state gas = %d/%d, want 1/0", res.FrameReceipts[2].Status, res.FrameReceipts[2].GasUsedState)
	}
	if res.FrameReceipts[3].Status != 0 {
		t.Fatalf("frame B status = %d, want 0", res.FrameReceipts[3].Status)
	}
	// C is batched after the failing flagged frame: skipped, never executed.
	if res.FrameReceipts[4].Status != frameStatusSkipped {
		t.Fatalf("frame C status = %d, want skipped (%d)", res.FrameReceipts[4].Status, frameStatusSkipped)
	}
	if res.FrameReceipts[4].GasUsedExecution != 0 || res.FrameReceipts[4].GasUsedState != 0 {
		t.Fatalf("frame C gas = %d/%d, want 0/0", res.FrameReceipts[4].GasUsedExecution, res.FrameReceipts[4].GasUsedState)
	}
	if got := sdb.GetState(contractC, common.Hash{}); got != (common.Hash{}) {
		t.Fatalf("frame C storage = %x, want empty (never executed)", got)
	}
}

// TestFrameExpirySkippedFrameShape: a VERIFY frame can never be part of an
// atomic batch or be skipped by one — the payload rules reject a VERIFY
// frame following an atomic-flagged frame outright.
func TestFrameExpirySkippedFrameShape(t *testing.T) {
	contractA := common.BytesToAddress([]byte("frame-expiry-skip-A"))
	frames := []types.Frame{
		{Mode: types.FrameModeSender, Target: &contractA, Flags: types.FrameAtomicBatchFlag, Limits: mkFrameLimits(100_000, 300_000)},
		expiryFrame(10_000),
	}
	ftx := frameTx(0, frames, []types.FrameSignature{{Scheme: types.FrameSigSchemeSecp256k1}})
	if err := ftx.ValidateStatic(); err == nil {
		t.Fatal("ValidateStatic: want rejection of VERIFY frame after atomic-flagged frame")
	} else if !strings.Contains(err.Error(), "atomic") {
		t.Fatalf("error = %v, want atomic placement rule", err)
	}
}

// TestFrameExpiryDeployedCode: when code IS deployed at EXPIRY_VERIFIER the
// frame executes that code through the ordinary dispatch (EIP-8141: the
// verifier is an ordinary contract; direct evaluation applies only when no
// code is present). The canonical runtime is used here, so the observable
// result matches the direct evaluation.
func TestFrameExpiryDeployedCode(t *testing.T) {
	canonical := common.FromHex("0x60083614600a575f5ffd5b5f3560c01c4211601657005b5f5ffd")
	sdb := mkState(types.GenesisAlloc{
		senderAddr:                {Balance: big.NewInt(1_000_000)},
		types.FrameExpiryVerifier: {Code: canonical},
	})
	frames := expiryApprovePrefix(10_000)
	ftx := frameTx(0, frames, []types.FrameSignature{{Scheme: types.FrameSigSchemeSecp256k1}})
	ftx.Signatures = defaultApproveSigs(t, senderKey, ftx)

	res, err := applyFrameTxAtTime(t, sdb, ftx, 5_000)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if res.FrameReceipts[0].Status != 1 {
		t.Fatalf("expiry frame status = %d, want 1 with deployed canonical code", res.FrameReceipts[0].Status)
	}

	// Expired deadline with deployed code reverts through ordinary execution.
	sdb2 := mkState(types.GenesisAlloc{
		senderAddr:                {Balance: big.NewInt(1_000_000)},
		types.FrameExpiryVerifier: {Code: canonical},
	})
	ftx2 := frameTx(0, expiryApprovePrefix(4_999), []types.FrameSignature{{Scheme: types.FrameSigSchemeSecp256k1}})
	ftx2.Signatures = defaultApproveSigs(t, senderKey, ftx2)
	if _, err := applyFrameTxAtTime(t, sdb2, ftx2, 5_000); err == nil {
		t.Fatal("execute: want VERIFY failure for expired deadline with deployed code")
	} else if !strings.Contains(err.Error(), "VERIFY frame failed") {
		t.Fatalf("error = %v, want VERIFY frame failure", err)
	}
}
