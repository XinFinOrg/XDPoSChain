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

// Frame-execution driver tests for EIP-8141 (core/state_transition_frame.go).
// The environment mirrors core/eip8037_test.go: Amsterdam-era two-dimensional
// gas with the FrameTx fork activated, fees zeroed.

package core

import (
	"crypto/ecdsa"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/holiman/uint256"
)

var (
	cfgFrame   = frameChainConfig()
	frameRules = cfgFrame.Rules(big.NewInt(0), true, 0)
	frameSgn   = types.NewFrameTxSigner(cfgFrame.ChainID)

	// frameKey2/frameSender2: a second deterministic identity used by the
	// SENDER-mode test (its account carries executable code).
	frameKey2, _ = crypto.HexToECDSA("a11ce4a97e97b24b2b9ee17ae16c6668d313eac2f96dbcda3f291b71c71a67e1")
	frameSender2 = crypto.PubkeyToAddress(frameKey2.PublicKey)
)

// frameChainConfig clones MergedTestChainConfig with the FrameTx fork active
// at genesis time. Test-only; no preset sets FrameTxTime.
func frameChainConfig() *params.ChainConfig {
	cfg := *params.MergedTestChainConfig
	cfg.FrameTxTime = new(uint64)
	return &cfg
}

// frameCoreEVM builds the frame-fork EVM over sdb with zero base fees.
func frameCoreEVM(sdb *state.StateDB) *vm.EVM {
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
	return vm.NewEVM(ctx, sdb, cfgFrame, vm.Config{NoBaseFee: true})
}

// applyFrameTx executes one frame transaction and returns the result, the
// block gas pool and any consensus error.
func applyFrameTx(t *testing.T, sdb *state.StateDB, ftx *types.FrameTx) (*ExecutionResult, *GasPool, error) {
	t.Helper()
	evm := frameCoreEVM(sdb)
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

// frameTx builds a zero-fee frame transaction payload from tx.sender.
func frameTx(nonce uint64, frames []types.Frame, sigs []types.FrameSignature) *types.FrameTx {
	return frameTxFrom(senderAddr, nonce, frames, sigs)
}

// frameTxFrom builds a zero-fee frame transaction payload from a given sender.
func frameTxFrom(sender common.Address, nonce uint64, frames []types.Frame, sigs []types.FrameSignature) *types.FrameTx {
	return &types.FrameTx{
		ChainID:    uint256.MustFromBig(cfgFrame.ChainID),
		Nonce:      nonce,
		Sender:     sender,
		Frames:     frames,
		Signatures: sigs,
		Fees: types.FrameFees{
			GasTipCap:  uint256.NewInt(0),
			GasFeeCap:  uint256.NewInt(0),
			BlobFeeCap: uint256.NewInt(0),
		},
	}
}

// mkFrameLimits is a compact frame-gas constructor.
func mkFrameLimits(exec, stateGas uint64) types.FrameLimits {
	return types.FrameLimits{Execution: exec, State: stateGas}
}

// defaultApproveSigs returns the secp256k1 signature entries the default code
// requires: sig[0] by tx.sender over the transaction's signature hash with an
// empty msg.
func defaultApproveSigs(t *testing.T, key *ecdsa.PrivateKey, ftx *types.FrameTx) []types.FrameSignature {
	t.Helper()
	digest := ftx.SigHash()
	sig, err := crypto.Sign(digest.Bytes(), key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	// secp256k1 signature bytes are v (1B) || r (32B) || s (32B) (EIP-8141
	// wire form).
	return []types.FrameSignature{{
		Scheme:    types.FrameSigSchemeSecp256k1,
		Signature: append(append([]byte{}, sig[64]), sig[0:64]...),
	}}
}

// Bytecode fixtures.
var (
	frameCodeSStore = func(slot, val byte) []byte { return []byte{0x60, val, 0x60, slot, 0x55, 0x00} }
	// frameCodeSStoreLog: SSTORE then LOG0 in a single flow (no STOP between).
	frameCodeSStoreLog = func(slot, val byte) []byte {
		return []byte{0x60, val, 0x60, slot, 0x55, 0x60, 0x00, 0x60, 0x00, 0xa0, 0x00}
	}
	frameCodeRevert  = []byte{0x60, 0x00, 0x60, 0x00, 0xfd}
	frameCodeLoop    = []byte{0x5b, 0x60, 0x00, 0x56} // JUMPDEST; PUSH1 0; JUMP
	frameCodeLog0    = []byte{0x60, 0x00, 0x60, 0x00, 0xa0, 0x00}
	frameApproveCode = func(scope byte) []byte { return []byte{0x60, scope, 0x60, 0x00, 0x60, 0x00, 0xaa, 0x00} }
)

var (
	frameContractD     = common.BytesToAddress([]byte("frame-contract-D"))
	frameContractPayer = common.BytesToAddress([]byte("frame-payer-contract"))
	frameEmptyTarget   = common.BytesToAddress([]byte("frame-empty-target"))
)

// TestFrameApproveAndDefaultExecution covers: VERIFY default-code EXECUTION
// approval (frame 0), payment approval via the APPROVE opcode (frame 1), and
// a subsequent DEFAULT frame with a log (frame 2). Asserts approval effects
// (nonce, payer), per-frame receipts and per-frame log attribution.
func TestFrameApproveAndDefaultExecution(t *testing.T) {
	sdb := mkState(types.GenesisAlloc{
		senderAddr:         {Nonce: 0, Balance: big.NewInt(0)},
		frameContractD:     {Code: frameCodeSStoreLog(0, 7)},
		frameContractPayer: {Code: frameApproveCode(0x1)},
	})

	// Assemble with a placeholder signature so the digest is stable (empty-msg
	// signature bytes are elided from the hash).
	ftx := frameTx(0, []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 0x2, Limits: mkFrameLimits(100_000, 300_000)}, // default code, EXECUTION scope
		{Mode: types.FrameModeVerify, Target: &frameContractPayer, Flags: 0x1, Limits: mkFrameLimits(100_000, 300_000)},
		{Mode: types.FrameModeDefault, Target: &frameContractD, Flags: 0x0, Limits: mkFrameLimits(100_000, 300_000)},
	}, []types.FrameSignature{{Scheme: types.FrameSigSchemeSecp256k1}})
	ftx.Signatures = defaultApproveSigs(t, senderKey, ftx)

	res, _, err := applyFrameTx(t, sdb, ftx)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(res.FrameReceipts) != 3 {
		t.Fatalf("frame receipts: %d, want 3", len(res.FrameReceipts))
	}
	for i, r := range res.FrameReceipts {
		if r.Status != 1 {
			t.Fatalf("frame %d status = %d, want 1 (success)", i, r.Status)
		}
	}
	// Approval effects: sender nonce incremented once (by the payment
	// approval); execution approval alone does not touch the nonce.
	if nonce := sdb.GetNonce(senderAddr); nonce != 1 {
		t.Fatalf("sender nonce = %d, want 1", nonce)
	}
	// DEFAULT frame wrote storage and emitted one log attributed to frame 2.
	if got := sdb.GetState(frameContractD, common.Hash{}); got != common.BigToHash(big.NewInt(7)) {
		t.Fatalf("slot 0 = %x, want 7", got)
	}
	if n := len(res.FrameReceipts[2].Logs); n != 1 {
		t.Fatalf("frame 2 logs = %d, want 1", n)
	}
	if len(res.FrameReceipts[0].Logs) != 0 || len(res.FrameReceipts[1].Logs) != 0 {
		t.Fatal("frames 0/1 must not carry frame 2's log")
	}
	// Frame 0 (default code, resolved target == tx.sender) burns only the
	// warm target access: tx.sender is pre-warmed by the EIP-2929/EIP-3651
	// transaction-context initialization.
	if used := res.FrameReceipts[0].GasUsedExecution; used != params.WarmStorageReadCostEIP2929 {
		t.Fatalf("frame 0 execution gas = %d, want warm access %d", used, params.WarmStorageReadCostEIP2929)
	}
	// Settlement: used gas covers the intrinsic cost; the frame pools account
	// for the remainder.
	intrinsic := ftx.IntrinsicGas()
	if res.UsedGas <= intrinsic {
		t.Fatalf("used gas %d must exceed intrinsic %d", res.UsedGas, intrinsic)
	}
	if res.MaxUsedGas < res.UsedGas {
		t.Fatalf("max used gas %d < used gas %d", res.MaxUsedGas, res.UsedGas)
	}
}

// TestFrameSenderExecution covers the full SENDER path: execution approval
// (default code), payment approval (APPROVE opcode), then a SENDER frame with
// a value transfer to a contract.
func TestFrameSenderExecution(t *testing.T) {
	frameContractS := common.BytesToAddress([]byte("frame-contract-SENDER"))
	sdb := mkState(types.GenesisAlloc{
		frameSender2:       {Balance: big.NewInt(1_000)},
		frameContractPayer: {Code: frameApproveCode(0x1)},
		frameContractS:     {Code: frameCodeSStore(0, 4)},
	})

	ftx := frameTxFrom(frameSender2, 0, []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 0x2, Limits: mkFrameLimits(100_000, 300_000)},
		{Mode: types.FrameModeVerify, Target: &frameContractPayer, Flags: 0x1, Limits: mkFrameLimits(100_000, 300_000)},
		{Mode: types.FrameModeSender, Target: &frameContractS, Flags: 0x0, Limits: mkFrameLimits(100_000, 300_000), Value: uint256.NewInt(100)},
	}, []types.FrameSignature{{Scheme: types.FrameSigSchemeSecp256k1}})
	ftx.Signatures = defaultApproveSigs(t, frameKey2, ftx)

	res, _, err := applyFrameTx(t, sdb, ftx)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(res.FrameReceipts) != 3 {
		t.Fatalf("receipts: %d, want 3", len(res.FrameReceipts))
	}
	// The SENDER frame ran the target contract's code with the sender as
	// caller and transferred value sender -> target.
	if got := sdb.GetState(frameContractS, common.Hash{}); got != common.BigToHash(big.NewInt(4)) {
		t.Fatalf("target slot 0 = %x, want 4", got)
	}
	if bal := sdb.GetBalance(frameContractS); bal.Uint64() != 100 {
		t.Fatalf("target balance = %d, want 100", bal.Uint64())
	}
	if bal := sdb.GetBalance(frameSender2); bal.Uint64() != 900 {
		t.Fatalf("sender2 balance = %d, want 900", bal.Uint64())
	}
	if nonce := sdb.GetNonce(frameSender2); nonce != 1 {
		t.Fatalf("sender2 nonce = %d, want 1", nonce)
	}
}

// TestFrameSenderWithoutApproval: a SENDER frame before any execution
// approval invalidates the transaction (EIP-8141 Behavior).
func TestFrameSenderWithoutApproval(t *testing.T) {
	sdb := mkState(types.GenesisAlloc{senderAddr: {}})
	ftx := frameTx(0, []types.Frame{
		{Mode: types.FrameModeSender, Flags: 0x0, Limits: mkFrameLimits(100_000, 300_000)},
	}, nil)
	if _, _, err := applyFrameTx(t, sdb, ftx); err == nil {
		t.Fatal("expected invalid transaction for unapproved SENDER frame")
	}
	if nonce := sdb.GetNonce(senderAddr); nonce != 0 {
		t.Fatalf("nonce = %d, want 0 (tx invalid, no approval effects)", nonce)
	}
}

// TestFrameVerifyFailureInvalidatesTx: a failed VERIFY frame invalidates the
// whole transaction, unrolling all effects (approvals, nonce).
func TestFrameVerifyFailureInvalidatesTx(t *testing.T) {
	ftx := frameTx(0, []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 0x2, Limits: mkFrameLimits(100_000, 300_000)},
		{Mode: types.FrameModeVerify, Target: &frameContractPayer, Flags: 0x1, Limits: mkFrameLimits(100_000, 300_000)},
		{Mode: types.FrameModeVerify, Target: &frameContractD, Flags: 0x0, Limits: mkFrameLimits(100_000, 300_000)}, // reverts
	}, []types.FrameSignature{{Scheme: types.FrameSigSchemeSecp256k1}})
	ftx.Signatures = defaultApproveSigs(t, senderKey, ftx)

	sdb := mkState(types.GenesisAlloc{
		senderAddr:         {},
		frameContractPayer: {Code: frameApproveCode(0x1)},
		frameContractD:     {Code: frameCodeRevert},
	})
	if _, _, err := applyFrameTx(t, sdb, ftx); err == nil {
		t.Fatal("expected invalid transaction for failed VERIFY frame")
	}
	// All effects (approvals, nonce) must be unrolled.
	if nonce := sdb.GetNonce(senderAddr); nonce != 0 {
		t.Fatalf("nonce = %d, want 0 after VERIFY failure", nonce)
	}
}

// TestFrameAtomicBatchRollback: frames 1 and 2 carry ATOMIC_BATCH_FLAG; frame
// 2 reverts. State rolls back to before frame 1; frame 1 keeps its execution
// status/gas with zero state gas and no logs; frame 3 (unflagged terminator
// of the batch) is skipped with status 0x2.
func TestFrameAtomicBatchRollback(t *testing.T) {
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

	res, _, err := applyFrameTx(t, sdb, ftx)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	rs := res.FrameReceipts
	if len(rs) != 5 {
		t.Fatalf("receipts: %d, want 5", len(rs))
	}
	if rs[0].Status != 1 || rs[1].Status != 1 {
		t.Fatalf("frames 0/1 status = %d/%d, want 1/1", rs[0].Status, rs[1].Status)
	}
	// Frame 2 executed successfully before the batch failure: retains status
	// and execution gas, but state gas and logs are zeroed by the rollback.
	if rs[2].Status != 1 {
		t.Fatalf("frame 2 status = %d, want 1", rs[2].Status)
	}
	if rs[2].GasUsedExecution == 0 {
		t.Fatal("frame 2 execution gas must be retained")
	}
	if rs[2].GasUsedState != 0 || len(rs[2].Logs) != 0 {
		t.Fatalf("frame 2 state gas = %d logs = %d, want 0/0", rs[2].GasUsedState, len(rs[2].Logs))
	}
	// Frame 3 failed.
	if rs[3].Status != 0 {
		t.Fatalf("frame 3 status = %d, want 0", rs[3].Status)
	}
	// Frame 4 was skipped.
	if rs[4].Status != 2 {
		t.Fatalf("frame 4 status = %d, want 2 (skipped)", rs[4].Status)
	}
	if rs[4].GasUsedExecution != 0 || rs[4].GasUsedState != 0 {
		t.Fatal("skipped frame must have zero gas")
	}
	// The batch state changes are rolled back: storage unset, log gone, and
	// frame 4 never ran either.
	if got := sdb.GetState(contractC, common.BytesToHash([]byte{1})); got != (common.Hash{}) {
		t.Fatalf("slot 1 = %x, want 0 (batch rolled back)", got)
	}
}

// TestFrameExecutionGasExhaustion: a frame whose code runs out of execution
// gas halts exceptionally (full execution pool consumed); the failure is
// isolated and the next frame still executes.
func TestFrameExecutionGasExhaustion(t *testing.T) {
	contractL := common.BytesToAddress([]byte("frame-contract-L"))
	sdb := mkState(types.GenesisAlloc{
		senderAddr:         {},
		frameContractPayer: {Code: frameApproveCode(0x1)},
		contractL:          {Code: frameCodeLoop},
		frameContractD:     {Code: frameCodeSStore(0, 3)},
	})
	ftx := frameTx(0, []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 0x2, Limits: mkFrameLimits(100_000, 300_000)},
		{Mode: types.FrameModeVerify, Target: &frameContractPayer, Flags: 0x1, Limits: mkFrameLimits(100_000, 300_000)},
		{Mode: types.FrameModeDefault, Target: &contractL, Flags: 0x0, Limits: mkFrameLimits(20_000, 300_000)},
		{Mode: types.FrameModeDefault, Target: &frameContractD, Flags: 0x0, Limits: mkFrameLimits(100_000, 300_000)},
	}, []types.FrameSignature{{Scheme: types.FrameSigSchemeSecp256k1}})
	ftx.Signatures = defaultApproveSigs(t, senderKey, ftx)

	res, _, err := applyFrameTx(t, sdb, ftx)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	rs := res.FrameReceipts
	if rs[2].Status != 0 {
		t.Fatalf("frame 2 status = %d, want 0", rs[2].Status)
	}
	if rs[2].GasUsedExecution != 20_000 {
		t.Fatalf("frame 2 execution gas = %d, want full pool 20000", rs[2].GasUsedExecution)
	}
	if rs[2].GasUsedState != 0 {
		t.Fatalf("frame 2 state gas = %d, want 0", rs[2].GasUsedState)
	}
	if rs[3].Status != 1 {
		t.Fatalf("frame 3 status = %d, want 1 (isolated failure)", rs[3].Status)
	}
}

// TestFrameStateGasExhaustion: SSTORE state-gas demand exceeding the frame's
// state pool halts the frame without touching the execution pool beyond the
// halt itself (StrictState: no spill).
func TestFrameStateGasExhaustion(t *testing.T) {
	contractS := common.BytesToAddress([]byte("frame-contract-S"))
	sdb := mkState(types.GenesisAlloc{
		senderAddr:         {},
		frameContractPayer: {Code: frameApproveCode(0x1)},
		contractS:          {Code: frameCodeSStore(0, 1)},
		frameContractD:     {Code: frameCodeSStore(0, 3)},
	})
	newSlotState := uint64(params.StorageCreationSize * params.CostPerStateByte)
	ftx := frameTx(0, []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 0x2, Limits: mkFrameLimits(100_000, 300_000)},
		{Mode: types.FrameModeVerify, Target: &frameContractPayer, Flags: 0x1, Limits: mkFrameLimits(100_000, 300_000)},
		{Mode: types.FrameModeDefault, Target: &contractS, Flags: 0x0, Limits: mkFrameLimits(100_000, newSlotState-1)},
		{Mode: types.FrameModeDefault, Target: &frameContractD, Flags: 0x0, Limits: mkFrameLimits(100_000, 300_000)},
	}, []types.FrameSignature{{Scheme: types.FrameSigSchemeSecp256k1}})
	ftx.Signatures = defaultApproveSigs(t, senderKey, ftx)

	res, _, err := applyFrameTx(t, sdb, ftx)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	rs := res.FrameReceipts
	if rs[2].Status != 0 {
		t.Fatalf("frame 2 status = %d, want 0", rs[2].Status)
	}
	if rs[2].GasUsedState != 0 {
		t.Fatalf("frame 2 state gas = %d, want 0 (state charge never spilled)", rs[2].GasUsedState)
	}
	if got := sdb.GetState(contractS, common.Hash{}); got != (common.Hash{}) {
		t.Fatalf("slot = %x, want 0 (halted before SSTORE)", got)
	}
	if rs[3].Status != 1 {
		t.Fatalf("frame 3 status = %d, want 1", rs[3].Status)
	}
}

// TestFrameValueInsufficientBalance: a SENDER frame whose value exceeds the
// sender's balance reverts (not halts), consuming only the gas charged so
// far; the transaction remains valid once a payer exists.
func TestFrameValueInsufficientBalance(t *testing.T) {
	contractV := common.BytesToAddress([]byte("frame-contract-V"))
	sdb := mkState(types.GenesisAlloc{
		senderAddr:         {}, // no balance
		frameContractPayer: {Code: frameApproveCode(0x1)},
		contractV:          {Code: frameCodeSStore(0, 1)},
	})
	ftx := frameTx(0, []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 0x2, Limits: mkFrameLimits(100_000, 300_000)},
		{Mode: types.FrameModeVerify, Target: &frameContractPayer, Flags: 0x1, Limits: mkFrameLimits(100_000, 300_000)},
		{Mode: types.FrameModeSender, Target: &contractV, Flags: 0x0, Limits: mkFrameLimits(100_000, 300_000), Value: uint256.NewInt(100)},
	}, []types.FrameSignature{{Scheme: types.FrameSigSchemeSecp256k1}})
	ftx.Signatures = defaultApproveSigs(t, senderKey, ftx)

	res, _, err := applyFrameTx(t, sdb, ftx)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	rs := res.FrameReceipts
	if rs[2].Status != 0 {
		t.Fatalf("frame 2 status = %d, want 0", rs[2].Status)
	}
	// Revert semantics: not the full execution pool.
	if rs[2].GasUsedExecution >= 100_000 {
		t.Fatalf("frame 2 execution gas = %d, want < 100000 (revert)", rs[2].GasUsedExecution)
	}
	if got := sdb.GetState(contractV, common.Hash{}); got != (common.Hash{}) {
		t.Fatalf("slot = %x, want 0 (reverted)", got)
	}
}

// TestFrameEmptyCodeDefault: a DEFAULT-mode frame targeting an account
// without code succeeds with only the target-access charge (default code);
// a VERIFY-mode frame with no approval scopes reverts, invalidating the tx.
func TestFrameEmptyCodeDefault(t *testing.T) {
	sdb := mkState(types.GenesisAlloc{
		senderAddr:         {},
		frameContractPayer: {Code: frameApproveCode(0x1)},
		frameEmptyTarget:   {},
	})
	ftx := frameTx(0, []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 0x2, Limits: mkFrameLimits(100_000, 300_000)},
		{Mode: types.FrameModeVerify, Target: &frameContractPayer, Flags: 0x1, Limits: mkFrameLimits(100_000, 300_000)},
		{Mode: types.FrameModeDefault, Target: &frameEmptyTarget, Flags: 0x0, Limits: mkFrameLimits(100_000, 300_000)},
	}, []types.FrameSignature{{Scheme: types.FrameSigSchemeSecp256k1}})
	ftx.Signatures = defaultApproveSigs(t, senderKey, ftx)

	res, _, err := applyFrameTx(t, sdb, ftx)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if res.FrameReceipts[2].Status != 1 {
		t.Fatalf("frame 2 status = %d, want 1", res.FrameReceipts[2].Status)
	}
	if used := res.FrameReceipts[2].GasUsedExecution; used != params.ColdAccountAccessCostEIP2929 {
		t.Fatalf("empty-code frame execution gas = %d, want %d", used, params.ColdAccountAccessCostEIP2929)
	}

	// VERIFY default code without any approval scope reverts.
	sdb2 := mkState(types.GenesisAlloc{
		senderAddr:       {},
		frameEmptyTarget: {},
	})
	ftx2 := frameTx(0, []types.Frame{
		{Mode: types.FrameModeVerify, Target: &frameEmptyTarget, Flags: 0x0, Limits: mkFrameLimits(100_000, 300_000)},
	}, nil)
	if _, _, err := applyFrameTx(t, sdb2, ftx2); err == nil {
		t.Fatal("expected invalid transaction for scope-less VERIFY default code")
	}
}

// TestFrameAtomicBatchApprovalRollback: an EXECUTION approval gained inside a
// failed atomic batch must roll back with the batch. The SENDER frame after
// the batch then invalidates the transaction (EIP-8141 Behavior: atomic batch
// rollback restores the state before the batch began).
func TestFrameAtomicBatchApprovalRollback(t *testing.T) {
	contractR := common.BytesToAddress([]byte("frame-batch-rollback-R"))
	sdb := mkState(types.GenesisAlloc{
		frameContractPayer: {Code: frameApproveCode(0x1)},
		contractR:          {Code: frameCodeRevert},
	})
	// Frames 1 and 2 form an atomic batch (frame 2 reverts). Frame 1 is a
	// VERIFY default-code EXECUTION approval. No payment approval anywhere:
	// if the execution approval rolled back correctly, the SENDER frame 3
	// invalidates the transaction.
	ftx := frameTx(0, []types.Frame{
		{Mode: types.FrameModeDefault, Target: &frameContractPayer, Flags: 0x4, Limits: mkFrameLimits(100_000, 300_000)},
		{Mode: types.FrameModeVerify, Flags: 0x2 | 0x4, Limits: mkFrameLimits(100_000, 300_000)}, // approves execution, then batch fails
		{Mode: types.FrameModeDefault, Target: &contractR, Flags: 0x4, Limits: mkFrameLimits(100_000, 300_000)},
		{Mode: types.FrameModeSender, Flags: 0x0, Limits: mkFrameLimits(100_000, 300_000)},
	}, []types.FrameSignature{{Scheme: types.FrameSigSchemeSecp256k1}})
	ftx.Signatures = defaultApproveSigs(t, senderKey, ftx)

	if _, _, err := applyFrameTx(t, sdb, ftx); err == nil {
		t.Fatal("expected invalid transaction: SENDER frame after batch rollback without approval")
	}
	if nonce := sdb.GetNonce(senderAddr); nonce != 0 {
		t.Fatalf("nonce = %d, want 0 (no payment approval survived)", nonce)
	}
}

// TestFramePaymentApprovalInsufficientBalance: per EIP-8141 "APPROVE
// Instruction", APPROVE_PAYMENT and APPROVE_EXECUTION_AND_PAYMENT revert the
// current call frame when the resolved payer's balance is below the
// transaction's max_cost (instead of underflowing through SubBalance). A
// revert inside a VERIFY frame invalidates the whole transaction and all
// approval/nonce effects are unrolled.
func TestFramePaymentApprovalInsufficientBalance(t *testing.T) {
	mkTx := func(t *testing.T, frames []types.Frame, tipCap uint64) *types.FrameTx {
		t.Helper()
		ftx := frameTx(0, frames, []types.FrameSignature{{Scheme: types.FrameSigSchemeSecp256k1}})
		// Non-zero max_cost: with baseFee == 0, MaxCost == maxGas * tipCap.
		ftx.Fees.GasFeeCap = uint256.NewInt(1_000_000)
		ftx.Fees.GasTipCap = uint256.NewInt(tipCap)
		ftx.Signatures = defaultApproveSigs(t, senderKey, ftx)
		return ftx
	}
	approveFrames := func(paymentFlags byte, paymentTarget *common.Address) []types.Frame {
		return []types.Frame{
			{Mode: types.FrameModeVerify, Flags: 0x2, Limits: mkFrameLimits(100_000, 300_000)}, // self EXECUTION approval
			{Mode: types.FrameModeVerify, Target: paymentTarget, Flags: paymentFlags, Limits: mkFrameLimits(100_000, 300_000)},
		}
	}

	t.Run("PaymentByContractPayer", func(t *testing.T) {
		ftx := mkTx(t, approveFrames(0x1, &frameContractPayer), 1)
		sdb := mkState(types.GenesisAlloc{
			senderAddr:         {Balance: big.NewInt(1_000_000_000)}, // covers max_cost
			frameContractPayer: {Code: frameApproveCode(0x1)},        // payer balance: 0 < max_cost
		})
		if _, _, err := applyFrameTx(t, sdb, ftx); err == nil {
			t.Fatal("expected invalid transaction for payment approval revert in VERIFY frame")
		}
		if nonce := sdb.GetNonce(senderAddr); nonce != 0 {
			t.Fatalf("nonce = %d, want 0 (approval effects unrolled)", nonce)
		}
		if bal := sdb.GetBalance(senderAddr); bal.CmpUint64(1_000_000_000) != 0 {
			t.Fatalf("sender balance = %v, want unchanged 1000000000", bal)
		}
	})

	t.Run("ExecutionAndPaymentBySender", func(t *testing.T) {
		// Target nil resolves to tx.sender: the sender approves EXECUTION
		// and PAYMENT but cannot cover max_cost.
		ftx := mkTx(t, approveFrames(0x3, nil), 1)
		sdb := mkState(types.GenesisAlloc{
			senderAddr: {}, // balance 0 < max_cost
		})
		if _, _, err := applyFrameTx(t, sdb, ftx); err == nil {
			t.Fatal("expected invalid transaction for insolvent EXECUTION_AND_PAYMENT")
		}
		if nonce := sdb.GetNonce(senderAddr); nonce != 0 {
			t.Fatalf("nonce = %d, want 0 (approval effects unrolled)", nonce)
		}
	})
}

// TestFrameValueRevertPrecedesAccountCreation: EIP-8141 "Behavior" orders
// the frame call as (1) access charge, (2) caller balance check, (3)
// account-creation state-gas charge, (4) dispatch. With caller balance below
// frame.value AND state gas below the account-creation cost, the result must
// be the specified revert (consuming only the gas charged so far), not an
// exceptional halt that burns the entire execution pool.
func TestFrameValueRevertPrecedesAccountCreation(t *testing.T) {
	freshTarget := common.BytesToAddress([]byte("frame-fresh-target"))
	sdb := mkState(types.GenesisAlloc{
		senderAddr:         {Code: nil},
		frameContractPayer: {Code: frameApproveCode(0x1)},
	})
	ftx := frameTx(0, []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 0x2, Limits: mkFrameLimits(100_000, 300_000)},
		{Mode: types.FrameModeVerify, Target: &frameContractPayer, Flags: 0x1, Limits: mkFrameLimits(100_000, 300_000)},
		{Mode: types.FrameModeSender, Target: &freshTarget, Flags: 0x0, Limits: mkFrameLimits(100_000, 1_000), Value: uint256.NewInt(100)},
	}, []types.FrameSignature{{Scheme: types.FrameSigSchemeSecp256k1}})
	ftx.Signatures = defaultApproveSigs(t, senderKey, ftx)

	res, _, err := applyFrameTx(t, sdb, ftx)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	rs := res.FrameReceipts
	if rs[2].Status != 0 {
		t.Fatalf("frame 2 status = %d, want 0", rs[2].Status)
	}
	// Revert classification: only the access charge (2600) was consumed,
	// not the whole 100_000 execution pool. Under the pre-fix ordering the
	// account-creation charge would have failed first and burned the pool.
	if rs[2].GasUsedExecution >= 100_000 {
		t.Fatalf("frame 2 execution gas = %d, want < 100000 (revert, not exceptional halt)", rs[2].GasUsedExecution)
	}
	if rs[2].GasUsedExecution == 0 {
		t.Fatal("frame 2 execution gas = 0, want access charge consumed")
	}
	if rs[2].GasUsedState != 0 {
		t.Fatalf("frame 2 state gas = %d, want 0 (no state charge on revert path)", rs[2].GasUsedState)
	}
	if sdb.Exist(freshTarget) {
		t.Fatal("fresh target must not be created on revert")
	}
}
