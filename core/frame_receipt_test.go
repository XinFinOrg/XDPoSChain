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

// Receipt / block-processing integration tests for EIP-8141. These execute
// frame transactions through ApplyTransactionWithEVM — the same entry point
// StateProcessor uses per transaction — and verify the canonical receipt.

package core

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/rlp"
)

// frameReceiptScenario executes a frame transaction with two successful
// frames (approval flow plus a logging contract) and one reverting frame,
// returning the state, the transaction, the receipt and the block gas pool.
func frameReceiptScenario(t *testing.T) (*state.StateDB, *types.Transaction, *types.Receipt, *GasPool) {
	t.Helper()
	revertTarget := common.BytesToAddress([]byte("frame-revert-target"))
	sdb := mkState(types.GenesisAlloc{
		senderAddr:         {Nonce: 0, Balance: big.NewInt(0)},
		frameContractD:     {Code: frameCodeSStoreLog(0, 7)},
		frameContractPayer: {Code: frameApproveCode(0x1)},
		revertTarget:       {Code: frameCodeRevert},
	})

	ftx := frameTx(0, []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 0x2, Limits: mkFrameLimits(100_000, 300_000)},                              // default code, EXECUTION scope
		{Mode: types.FrameModeVerify, Target: &frameContractPayer, Flags: 0x1, Limits: mkFrameLimits(100_000, 300_000)}, // payment approval via APPROVE
		{Mode: types.FrameModeDefault, Target: &frameContractD, Limits: mkFrameLimits(100_000, 300_000)},                // success + 1 log
		{Mode: types.FrameModeDefault, Target: &revertTarget, Limits: mkFrameLimits(100_000, 300_000)},                  // revert (status 0)
	}, []types.FrameSignature{{Scheme: types.FrameSigSchemeSecp256k1}})
	ftx.Signatures = defaultApproveSigs(t, senderKey, ftx)

	tx := types.NewTx(ftx)
	evm := frameCoreEVM(sdb)
	msg, err := TransactionToMessage(tx, frameSgn, evm.Context.BaseFee)
	if err != nil {
		t.Fatalf("to message: %v", err)
	}
	sdb.SetTxContext(tx.Hash(), 0, 0)
	gp := NewGasPool(evm.Context.GasLimit)
	receipt, _, err := ApplyTransactionWithEVM(msg, gp, sdb, big.NewInt(0), common.HexToHash("0xabc123"), 0, tx, evm)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	return sdb, tx, receipt, gp
}

// TestFrameTxBlockProcessingReceipt verifies the canonical receipt produced by
// the block-processing path for a multi-frame transaction with successful and
// reverted frames.
func TestFrameTxBlockProcessingReceipt(t *testing.T) {
	_, _, receipt, gp := frameReceiptScenario(t)

	if receipt.Type != types.FrameTxType {
		t.Fatalf("receipt type: %d", receipt.Type)
	}
	if receipt.Payer == nil || *receipt.Payer != frameContractPayer {
		t.Fatalf("receipt payer: %v", receipt.Payer)
	}
	if len(receipt.FrameReceipts) != 4 {
		t.Fatalf("frame receipts: %d", len(receipt.FrameReceipts))
	}
	wantStatus := []uint8{1, 1, 1, 0}
	for i, fr := range receipt.FrameReceipts {
		if fr.Status != wantStatus[i] {
			t.Fatalf("frame %d status: %d", i, fr.Status)
		}
		if fr.GasUsedExecution == 0 {
			t.Fatalf("frame %d has zero execution gas", i)
		}
	}
	// Frame 2 (logging contract) owns the single log; the reverted frame's
	// logs were rolled back.
	if len(receipt.FrameReceipts[2].Logs) != 1 {
		t.Fatalf("frame 2 logs: %d", len(receipt.FrameReceipts[2].Logs))
	}
	if len(receipt.FrameReceipts[3].Logs) != 0 {
		t.Fatalf("frame 3 logs: %d", len(receipt.FrameReceipts[3].Logs))
	}
	if len(receipt.Logs) != 1 || receipt.Logs[0].Address != frameContractD {
		t.Fatalf("tx logs: %+v", receipt.Logs)
	}
	// Bloom over the concatenated logs.
	if receipt.Bloom != types.CreateBloom(receipt) {
		t.Fatalf("bloom mismatch")
	}
	if receipt.Bloom == (types.Bloom{}) {
		t.Fatalf("bloom is empty despite a log")
	}
	// Transaction status is derived: one failed frame -> failed.
	if receipt.Status != types.ReceiptStatusFailed {
		t.Fatalf("derived status: %d", receipt.Status)
	}
	// Cumulative gas equals the block gas pool's cumulative usage.
	if receipt.CumulativeGasUsed != gp.CumulativeUsed() {
		t.Fatalf("cumulative gas: %d != %d", receipt.CumulativeGasUsed, gp.CumulativeUsed())
	}
	if receipt.GasUsed == 0 || receipt.GasUsed > receipt.CumulativeGasUsed {
		t.Fatalf("gas used: %d, cumulative: %d", receipt.GasUsed, receipt.CumulativeGasUsed)
	}

}

// TestFrameTxReceiptWireRoundTrip verifies the canonical receipt survives the
// consensus encoding, the receipt-root (DeriveSha) encoding and storage
// encoding with per-frame data intact.
func TestFrameTxReceiptWireRoundTrip(t *testing.T) {
	_, _, receipt, _ := frameReceiptScenario(t)

	bin, err := receipt.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var dec types.Receipt
	if err := dec.UnmarshalBinary(bin); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if dec.Payer == nil || *dec.Payer != *receipt.Payer {
		t.Fatalf("payer roundtrip: %v", dec.Payer)
	}
	if len(dec.FrameReceipts) != len(receipt.FrameReceipts) {
		t.Fatalf("frame count roundtrip: %d", len(dec.FrameReceipts))
	}
	for i := range dec.FrameReceipts {
		a, b := dec.FrameReceipts[i], receipt.FrameReceipts[i]
		if a.Status != b.Status || a.GasUsedExecution != b.GasUsedExecution ||
			a.GasUsedState != b.GasUsedState || len(a.Logs) != len(b.Logs) {
			t.Fatalf("frame %d roundtrip mismatch: %+v vs %+v", i, a, b)
		}
	}
	if dec.Status != receipt.Status || dec.CumulativeGasUsed != receipt.CumulativeGasUsed {
		t.Fatalf("header fields mismatch: %+v", dec)
	}
	if dec.Bloom != receipt.Bloom {
		t.Fatalf("bloom mismatch after decode")
	}

	// Receipt-root encoding must match the canonical typed encoding.
	rs := types.Receipts{receipt}
	var buf bytes.Buffer
	rs.EncodeIndex(0, &buf)
	if !bytes.Equal(buf.Bytes(), bin) {
		t.Fatalf("EncodeIndex mismatch")
	}

	// Storage encoding must preserve the frame payload.
	stored := types.ReceiptForStorage(*receipt)
	blob, err := rlp.EncodeToBytes(&stored)
	if err != nil {
		t.Fatalf("encode stored: %v", err)
	}
	var back types.ReceiptForStorage
	if err := rlp.DecodeBytes(blob, &back); err != nil {
		t.Fatalf("decode stored: %v", err)
	}
	br := (*types.Receipt)(&back)
	if br.Payer == nil || *br.Payer != *receipt.Payer || len(br.FrameReceipts) != 4 {
		t.Fatalf("stored roundtrip: payer %v frames %d", br.Payer, len(br.FrameReceipts))
	}
}

// TestFrameTxReceiptDeriveFields verifies the derived log metadata, including
// the per-frame log indexes continuing the transaction's log sequence.
func TestFrameTxReceiptDeriveFields(t *testing.T) {
	_, tx, receipt, _ := frameReceiptScenario(t)

	signer := types.NewFrameTxSigner(cfgFrame.ChainID)
	receipt.DeriveFields(signer, types.DeriveReceiptContext{
		BlockHash:   common.HexToHash("0xabc123"),
		BlockNumber: 0,
		GasUsed:     receipt.GasUsed,
		Tx:          tx,
		TxIndex:     0,
	})
	if len(receipt.Logs) != 1 {
		t.Fatalf("logs: %d", len(receipt.Logs))
	}
	if receipt.Logs[0].Index != 0 || receipt.Logs[0].TxHash == (common.Hash{}) {
		t.Fatalf("derived log metadata: %+v", receipt.Logs[0])
	}
	frLogs := receipt.FrameReceipts[2].Logs
	if len(frLogs) != 1 || frLogs[0].Index != 0 || frLogs[0].BlockHash != receipt.Logs[0].BlockHash {
		t.Fatalf("derived frame log metadata: %+v", frLogs[0])
	}
}

// TestFrameTxAtomicBatchReceipt verifies the canonical receipt of a frame
// transaction with a failed atomic batch: the rolled-back frame keeps its
// status and execution gas with state gas and logs zeroed, the skipped frame
// carries status 0x2, and the wire encoding preserves all of it. It executes
// through ApplyTransactionWithEVM so MakeReceipt builds the receipt.
func TestFrameTxAtomicBatchReceipt(t *testing.T) {
	contractC := common.BytesToAddress([]byte("frame-contract-C"))
	contractR := common.BytesToAddress([]byte("frame-contract-R"))
	sdb := mkState(types.GenesisAlloc{
		senderAddr:         {Balance: big.NewInt(0)},
		frameContractPayer: {Code: frameApproveCode(0x1)},
		contractC:          {Code: frameCodeSStoreLog(1, 1)},
		contractR:          {Code: frameCodeRevert},
	})
	ftx := frameTx(0, []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 0x2, Limits: mkFrameLimits(100_000, 300_000)},
		{Mode: types.FrameModeVerify, Target: &frameContractPayer, Flags: 0x1, Limits: mkFrameLimits(100_000, 300_000)},
		{Mode: types.FrameModeDefault, Target: &contractC, Flags: 0x4, Limits: mkFrameLimits(100_000, 300_000)},
		{Mode: types.FrameModeDefault, Target: &contractR, Flags: 0x4, Limits: mkFrameLimits(100_000, 300_000)},
		{Mode: types.FrameModeDefault, Target: &contractC, Flags: 0x0, Limits: mkFrameLimits(100_000, 300_000)},
	}, []types.FrameSignature{{Scheme: types.FrameSigSchemeSecp256k1}})
	ftx.Signatures = defaultApproveSigs(t, senderKey, ftx)

	tx := types.NewTx(ftx)
	evm := frameCoreEVM(sdb)
	msg, err := TransactionToMessage(tx, frameSgn, evm.Context.BaseFee)
	if err != nil {
		t.Fatalf("to message: %v", err)
	}
	sdb.SetTxContext(tx.Hash(), 0, 0)
	receipt, _, err := ApplyTransactionWithEVM(msg, NewGasPool(evm.Context.GasLimit), sdb,
		big.NewInt(0), common.HexToHash("0xabc123"), 0, tx, evm)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	rs := receipt.FrameReceipts
	if len(rs) != 5 {
		t.Fatalf("frame receipts: %d, want 5", len(rs))
	}
	// Rolled-back frame: success status and execution gas retained, state
	// gas and logs zeroed.
	if rs[2].Status != 1 || rs[2].GasUsedExecution == 0 || rs[2].GasUsedState != 0 || len(rs[2].Logs) != 0 {
		t.Fatalf("frame 2 receipt wrong: %+v", rs[2])
	}
	if rs[3].Status != 0 {
		t.Fatalf("frame 3 status = %d, want 0", rs[3].Status)
	}
	if rs[4].Status != 2 || rs[4].GasUsedExecution != 0 || rs[4].GasUsedState != 0 {
		t.Fatalf("frame 4 receipt wrong: %+v", rs[4])
	}
	// No log survives the batch rollback anywhere in the canonical receipt.
	if len(receipt.Logs) != 0 {
		t.Fatalf("tx logs: %d, want 0 (batch rolled back)", len(receipt.Logs))
	}
	if receipt.Bloom != (types.Bloom{}) {
		t.Fatalf("bloom must be empty without logs")
	}
	// The skipped frame's status 0x2 survives the wire encoding.
	bin, err := receipt.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var dec types.Receipt
	if err := dec.UnmarshalBinary(bin); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(dec.FrameReceipts) != 5 || dec.FrameReceipts[4].Status != 2 ||
		dec.FrameReceipts[2].GasUsedState != 0 || dec.FrameReceipts[2].GasUsedExecution == 0 {
		t.Fatalf("wire roundtrip mismatch: %+v", dec.FrameReceipts)
	}
	if dec.Status != types.ReceiptStatusFailed {
		t.Fatalf("derived status: %d", dec.Status)
	}
}
