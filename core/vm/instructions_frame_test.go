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

// Opcode-level tests for EIP-8141 frame instructions (TXPARAM, FRAMEDATA*,
// FRAMEPARAM, SIGPARAM, SIGDATACOPY) and the APPROVE instruction.

package vm

import (
	"errors"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/tracing"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/holiman/uint256"
)

// frameTestChainID is the chain id used by the frame opcode tests.
const frameTestChainID = 0x97

// frameTestSigHash is a stand-in transaction signature hash.
var frameTestSigHash = common.HexToHash("0xdeadbeef00000000000000000000000000000000000000000000000000000001")

// frame8141Config clones MergedTestChainConfig with the FrameTx fork live.
func frame8141Config() *params.ChainConfig {
	cfg := *params.MergedTestChainConfig
	cfg.FrameTxTime = new(uint64)
	return &cfg
}

// frame8141EVM builds an EVM with the FrameTx instruction set and a frame
// context installed.
func frame8141EVM(statedb StateDB, fc *FrameContext) *EVM {
	ctx := BlockContext{
		CanTransfer: func(db StateDB, addr common.Address, amount *uint256.Int) bool {
			return db.GetBalance(addr).Cmp(amount) >= 0
		},
		Transfer: func(db StateDB, sender, recipient common.Address, amount *uint256.Int, _ *params.Rules) {
			db.SubBalance(sender, amount, tracing.BalanceChangeTransfer)
			db.AddBalance(recipient, amount, tracing.BalanceChangeTransfer)
		},
		BlockNumber:      big.NewInt(1),
		Time:             1,
		Random:           &common.Hash{},
		CostPerStateByte: params.CostPerStateByte,
	}
	evm := NewEVM(ctx, statedb, frame8141Config(), Config{})
	evm.TxContext.GasPrice = uint256.NewInt(0)
	if fc != nil {
		evm.SetFrameContext(fc)
	}
	return evm
}

// frameTestSigner / frameTestSender are deterministic test identities.
var (
	frameTestSigner = common.BytesToAddress([]byte("frame-signer-00001"))
	frameTestSender = common.BytesToAddress([]byte("frame-test-sender"))
	frameTestTarget = common.BytesToAddress([]byte("frame-test-target"))
)

// makeFrameTestContext builds a two-frame FrameContext for the opcode tests:
// frame 0 targets frameTestTarget with data 0x010203..., frame 1 is a SENDER
// frame with no data.
func makeFrameTestContext(t *testing.T) *FrameContext {
	t.Helper()
	signer1 := frameTestSigner
	ftx := &types.FrameTx{
		ChainID: uint256.NewInt(frameTestChainID),
		Nonce:   7,
		Sender:  frameTestSender,
		Frames: []types.Frame{
			{
				Target: &frameTestTarget,
				Data:   []byte{1, 2, 3, 4, 5, 6, 7, 8},
				Limits: types.FrameLimits{Execution: 100000, State: 100000},
				Mode:   types.FrameModeDefault,
				Flags:  types.FrameApproveScopeMask,
			},
			{
				Data:   nil,
				Limits: types.FrameLimits{Execution: 100000, State: 100000},
				Mode:   types.FrameModeSender,
			},
		},
		Signatures: []types.FrameSignature{
			{Scheme: types.FrameSigSchemeSecp256k1, Signer: signer1.Bytes()},
			{Scheme: types.FrameSigSchemeP256, Msg: frameTestSigHash.Bytes()},
		},
		Fees:       types.FrameFees{GasTipCap: uint256.NewInt(0), GasFeeCap: uint256.NewInt(0), BlobFeeCap: uint256.NewInt(0)},
		BlobHashes: []common.Hash{{0x01}},
	}
	return &FrameContext{
		Tx:       ftx,
		SigHash:  frameTestSigHash,
		FrameIdx: 0,
		Receipts: make([]FrameReceipt, len(ftx.Frames)),
	}
}

// runFrameCode executes code at addr with the given frame context and returns
// the resulting budget and error.
func runFrameCode(t *testing.T, evm *EVM, addr common.Address, code []byte, gas GasBudget) (GasBudget, error) {
	t.Helper()
	statedb := evm.StateDB
	statedb.CreateAccount(addr)
	statedb.SetCode(addr, code, tracing.CodeChangeUnspecified)
	statedb.Finalise(true)
	_, result, err := evm.Call(common.Address{}, addr, nil, gas, new(uint256.Int))
	return result, err
}

// sstoreTop stores the top-of-stack value into storage slot 0.
// "TXPARAM <p>; SSTORE(0)": PUSH p, TXPARAM, PUSH 0, SSTORE.
func paramSstore(p byte) []byte {
	return []byte{0x60, p, 0xb0, 0x60, 0x00, 0x55, 0x00}
}

func TestFrameTxParam(t *testing.T) {
	fc := makeFrameTestContext(t)
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	evm := frame8141EVM(statedb, fc)
	addr := common.BytesToAddress([]byte("txparam-contract"))

	cases := []struct {
		param byte
		want  common.Hash
	}{
		{0x00, common.BigToHash(big.NewInt(6))},             // TXPARAM_TYPE
		{0x01, common.BigToHash(big.NewInt(7))},             // TXPARAM_NONCE
		{0x02, common.BytesToHash(frameTestSender.Bytes())}, // TXPARAM_SENDER
		{0x03, common.BigToHash(big.NewInt(0))},             // TXPARAM_MAX_PRIORITY_FEE_PER_GAS
		{0x04, common.BigToHash(big.NewInt(0))},             // TXPARAM_MAX_FEE
		{0x07, common.BigToHash(big.NewInt(1))},             // TXPARAM_BLOB_COUNT
		{0x08, frameTestSigHash},                            // TXPARAM_SIG_HASH
		{0x09, common.BigToHash(big.NewInt(2))},             // TXPARAM_FRAME_COUNT
		{0x0a, common.BigToHash(big.NewInt(0))},             // TXPARAM_CURRENT_FRAME_INDEX
		{0x0b, common.BigToHash(big.NewInt(2))},             // TXPARAM_SIGNATURE_COUNT
	}
	for _, c := range cases {
		res, err := runFrameCode(t, evm, addr, paramSstore(c.param), hugeBudget())
		if err != nil {
			t.Fatalf("TXPARAM 0x%02x: %v", c.param, err)
		}
		got := statedb.GetState(addr, common.Hash{})
		if got != c.want {
			t.Fatalf("TXPARAM 0x%02x: slot 0 = %x, want %x", c.param, got, c.want)
		}
		_ = res
		statedb.SetState(addr, common.Hash{}, common.Hash{})
	}
	// TXPARAM_STATE_GAS_LEFT (0x0c) reports the frame's remaining state reservoir.
	res, err := runFrameCode(t, evm, addr, paramSstore(0x0c), hugeBudget())
	if err != nil {
		t.Fatal(err)
	}
	_ = res
	if got := statedb.GetState(addr, common.Hash{}); got.Big().Sign() == 0 {
		t.Fatal("TXPARAM_STATE_GAS_LEFT: expected non-zero remaining state gas")
	}
	statedb.SetState(addr, common.Hash{}, common.Hash{})

	// Undefined parameters (0x05, 0x06, and anything above 0x0c) must halt.
	for _, p := range []byte{0x05, 0x06, 0x0d, 0xff} {
		if _, err := runFrameCode(t, evm, addr, paramSstore(p), hugeBudget()); err == nil {
			t.Fatalf("TXPARAM 0x%02x: expected exceptional halt", p)
		} else if !errors.Is(err, ErrInvalidFrameParam) {
			t.Fatalf("TXPARAM 0x%02x: err = %v, want ErrInvalidFrameParam", p, err)
		}
	}
}

func TestFrameDataLoadCopy(t *testing.T) {
	fc := makeFrameTestContext(t)
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	evm := frame8141EVM(statedb, fc)
	addr := common.BytesToAddress([]byte("framedata-contract"))

	// FRAMEDATALOAD: offset 0 of frame 0 data -> word 0x0807060504030201...
	loadCode := []byte{0x60, 0x00, 0x60, 0x00, 0xb1, 0x60, 0x00, 0x55, 0x00}
	if _, err := runFrameCode(t, evm, addr, loadCode, hugeBudget()); err != nil {
		t.Fatal(err)
	}
	// FRAMEDATALOAD left-aligns like CALLDATALOAD: the first calldata byte is
	// the most significant byte of the word.
	want := common.HexToHash("0x0102030405060708000000000000000000000000000000000000000000000000")
	if got := statedb.GetState(addr, common.Hash{}); got != want {
		t.Fatalf("FRAMEDATALOAD: slot 0 = %x, want %x", got, want)
	}
	statedb.SetState(addr, common.Hash{}, common.Hash{})

	// Out-of-bounds frame index must halt. Per the EIP-8141 stack order
	// (top-0 offset, top-1 frameIndex) the frame index is pushed first.
	badCode := []byte{0x60, 0x05, 0x60, 0x00, 0xb1, 0x60, 0x00, 0x55, 0x00}
	if _, err := runFrameCode(t, evm, addr, badCode, hugeBudget()); err == nil {
		t.Fatal("FRAMEDATALOAD oob frame: expected exceptional halt")
	}

	// FRAMEDATACOPY: copy 4 bytes at offset 2 of frame 0 into memory 0,
	// MSTORE to slot 0 -> word 0x0304050600... Stack order per the spec is
	// top-0 memOffset, top-1 dataOffset, top-2 length, top-3 frameIndex, so
	// the frame index is pushed first and memOffset last.
	copyCode := []byte{
		0x60, 0x00, // PUSH1 frameIndex=0
		0x60, 0x04, // PUSH1 length=4
		0x60, 0x02, // PUSH1 dataOffset=2
		0x60, 0x00, // PUSH1 memOffset=0
		0xb2,       // FRAMEDATACOPY
		0x60, 0x00, // PUSH1 0
		0x51,       // MLOAD
		0x60, 0x00, // PUSH1 slot 0
		0x55, 0x00, // SSTORE STOP
	}
	if _, err := runFrameCode(t, evm, addr, copyCode, hugeBudget()); err != nil {
		t.Fatal(err)
	}
	if got := statedb.GetState(addr, common.Hash{}); got[0] != 0x03 || got[1] != 0x04 || got[2] != 0x05 || got[3] != 0x06 {
		t.Fatalf("FRAMEDATACOPY: slot 0 = %x, want 03040506...", got)
	}
}

// TestFrameParam exercises FRAMEPARAM resolution rules (current/future frames
// must halt) and SIGPARAM/SIGDATACOPY over the fixture signatures.
func TestFrameParam(t *testing.T) {
	fc := makeFrameTestContext(t)
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	evm := frame8141EVM(statedb, fc)
	addr := common.BytesToAddress([]byte("frameparam-contract"))

	// FRAMEPARAM resolved_target of frame 0: PUSH param, PUSH idx, FRAMEPARAM, SSTORE.
	resTargetCode := []byte{0x60, 0x00, 0x60, 0x00, 0xb3, 0x60, 0x00, 0x55, 0x00}
	if _, err := runFrameCode(t, evm, addr, resTargetCode, hugeBudget()); err != nil {
		t.Fatal(err)
	}
	if got := statedb.GetState(addr, common.Hash{}); got != common.BytesToHash(frameTestTarget.Bytes()) {
		t.Fatalf("FRAMEPARAM RESOLVED_TARGET: %x", got)
	}
	statedb.SetState(addr, common.Hash{}, common.Hash{})

	// Flags of frame 0 must equal the approve-scope mask.
	flagsCode := []byte{0x60, 0x06, 0x60, 0x00, 0xb3, 0x60, 0x00, 0x55, 0x00}
	if _, err := runFrameCode(t, evm, addr, flagsCode, hugeBudget()); err != nil {
		t.Fatal(err)
	}
	if got := statedb.GetState(addr, common.Hash{}); got != common.BigToHash(big.NewInt(int64(types.FrameApproveScopeMask))) {
		t.Fatalf("FRAMEPARAM FLAGS: %x", got)
	}
	statedb.SetState(addr, common.Hash{}, common.Hash{})

	// Data length of frame 0 = 8.
	lenCode := []byte{0x60, 0x04, 0x60, 0x00, 0xb3, 0x60, 0x00, 0x55, 0x00}
	if _, err := runFrameCode(t, evm, addr, lenCode, hugeBudget()); err != nil {
		t.Fatal(err)
	}
	if got := statedb.GetState(addr, common.Hash{}); got != common.BigToHash(big.NewInt(8)) {
		t.Fatalf("FRAMEPARAM DATA_LENGTH: %x", got)
	}
	statedb.SetState(addr, common.Hash{}, common.Hash{})

	// Future frame (index 1): only STATUS, EXECUTION_GAS_USED and
	// STATE_GAS_USED halt (per the EIP-8141 FRAMEPARAM table); RESOLVED_TARGET
	// is explicitly valid for future frames and the remaining params are
	// frame-declaration data.
	for _, p := range []byte{0x05, 0x0a, 0x0b} {
		code := []byte{0x60, p, 0x60, 0x01, 0xb3, 0x60, 0x00, 0x55, 0x00}
		if _, err := runFrameCode(t, evm, addr, code, hugeBudget()); err == nil {
			t.Fatalf("FRAMEPARAM param 0x%02x on future frame: expected exceptional halt", p)
		}
	}
	// Undefined param must halt.
	bad := []byte{0x60, 0xff, 0x60, 0x00, 0xb3, 0x60, 0x00, 0x55, 0x00}
	if _, err := runFrameCode(t, evm, addr, bad, hugeBudget()); err == nil {
		t.Fatal("FRAMEPARAM undefined param: expected exceptional halt")
	} else if !errors.Is(err, ErrInvalidFrameParam) {
		t.Fatalf("FRAMEPARAM undefined param: err = %v", err)
	}
}

func TestSigParamAndCopy(t *testing.T) {
	fc := makeFrameTestContext(t)
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	evm := frame8141EVM(statedb, fc)
	addr := common.BytesToAddress([]byte("sigparam-contract"))

	// SIGPARAM scheme of signature 0: PUSH param, PUSH idx, SIGPARAM, SSTORE.
	schemeCode := []byte{0x60, 0x01, 0x60, 0x00, 0xb4, 0x60, 0x00, 0x55, 0x00}
	if _, err := runFrameCode(t, evm, addr, schemeCode, hugeBudget()); err != nil {
		t.Fatal(err)
	}
	if got := statedb.GetState(addr, common.Hash{}); got != common.BigToHash(big.NewInt(int64(types.FrameSigSchemeSecp256k1))) {
		t.Fatalf("SIGPARAM SCHEME: %x", got)
	}
	statedb.SetState(addr, common.Hash{}, common.Hash{})

	// Empty signer resolves to tx.sender.
	signerCode := []byte{0x60, 0x00, 0x60, 0x01, 0xb4, 0x60, 0x00, 0x55, 0x00}
	if _, err := runFrameCode(t, evm, addr, signerCode, hugeBudget()); err != nil {
		t.Fatal(err)
	}
	if got := statedb.GetState(addr, common.Hash{}); got != common.BytesToHash(frameTestSender.Bytes()) {
		t.Fatalf("SIGPARAM RESOLVED_SIGNER (empty): %x", got)
	}
	statedb.SetState(addr, common.Hash{}, common.Hash{})

	// Signature 1 msg -> sig hash.
	msgCode := []byte{0x60, 0x02, 0x60, 0x01, 0xb4, 0x60, 0x00, 0x55, 0x00}
	if _, err := runFrameCode(t, evm, addr, msgCode, hugeBudget()); err != nil {
		t.Fatal(err)
	}
	if got := statedb.GetState(addr, common.Hash{}); got != frameTestSigHash {
		t.Fatalf("SIGPARAM MSG: %x", got)
	}
	statedb.SetState(addr, common.Hash{}, common.Hash{})

	// SIGPARAM_LENGTH is only defined for ARBITRARY signatures.
	arbitrary := types.FrameSignature{Scheme: types.FrameSigSchemeArbitrary, Signature: []byte{0xaa}}
	fc.Tx.Signatures = append(fc.Tx.Signatures, arbitrary)
	lenCode := []byte{0x60, 0x03, 0x60, 0x02, 0xb4, 0x60, 0x00, 0x55, 0x00}
	if _, err := runFrameCode(t, evm, addr, lenCode, hugeBudget()); err != nil {
		t.Fatal(err)
	}
	if got := statedb.GetState(addr, common.Hash{}); got != common.BigToHash(big.NewInt(1)) {
		t.Fatalf("SIGPARAM LENGTH: %x", got)
	}
	statedb.SetState(addr, common.Hash{}, common.Hash{})
	// LENGTH on a protocol-validated signature must halt.
	if _, err := runFrameCode(t, evm, addr, []byte{0x60, 0x03, 0x60, 0x00, 0xb4, 0x60, 0x00, 0x55, 0x00}, hugeBudget()); err == nil {
		t.Fatal("SIGPARAM_LENGTH on secp256k1: expected exceptional halt")
	}

	// SIGDATACOPY on a protocol-validated signature must halt.
	if _, err := runFrameCode(t, evm, addr, []byte{0x60, 0x01, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0xb5, 0x00}, hugeBudget()); err == nil {
		t.Fatal("SIGDATACOPY on secp256k1: expected exceptional halt")
	}
	// SIGDATACOPY out-of-bounds signature index must halt.
	if _, err := runFrameCode(t, evm, addr, []byte{0x60, 0x01, 0x60, 0x00, 0x60, 0x00, 0x60, 0x09, 0xb5, 0x00}, hugeBudget()); err == nil {
		t.Fatal("SIGDATACOPY oob: expected exceptional halt")
	}
}

// TestApproveOpcodeInNonFrameTx verifies that the frame instructions halt
// exceptionally when executed outside of a frame transaction.
func TestApproveOpcodeInNonFrameTx(t *testing.T) {
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	evm := frame8141EVM(statedb, nil) // no frame context
	addr := common.BytesToAddress([]byte("approve-nonframe"))
	codes := map[string][]byte{
		"APPROVE":       {0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0xaa, 0x00},
		"TXPARAM":       paramSstore(0x00),
		"FRAMEDATALOAD": {0x60, 0x00, 0x60, 0x00, 0xb1, 0x00},
		"FRAMEDATACOPY": {0x60, 0x01, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0xb2, 0x00},
		"FRAMEPARAM":    {0x60, 0x00, 0x60, 0x00, 0xb3, 0x00},
		"SIGPARAM":      {0x60, 0x00, 0x60, 0x00, 0xb4, 0x00},
		"SIGDATACOPY":   {0x60, 0x01, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0xb5, 0x00},
	}
	for name, code := range codes {
		if _, err := runFrameCode(t, evm, addr, code, hugeBudget()); err == nil {
			t.Fatalf("%s in non-frame tx: expected exceptional halt", name)
		} else if !errors.Is(err, errFrameOpcodeNonFrameTx) {
			t.Fatalf("%s in non-frame tx: err = %v, want errFrameOpcodeNonFrameTx", name, err)
		}
	}
}

// TestFrameInstructionSet verifies the fork wiring: frame instructions exist
// in the FrameTx instruction set and are undefined before the fork.
func TestFrameInstructionSet(t *testing.T) {
	frame := newFrameTxInstructionSet()
	for _, op := range []OpCode{APPROVE, TXPARAM, FRAMEDATALOAD, FRAMEDATACOPY, FRAMEPARAM, SIGPARAM, SIGDATACOPY} {
		if frame[op].execute == nil {
			t.Fatalf("frame instruction set missing %v", op)
		}
	}
	prague := newPragueInstructionSet()
	for _, op := range []OpCode{APPROVE, TXPARAM, FRAMEDATALOAD, FRAMEDATACOPY, FRAMEPARAM, SIGPARAM, SIGDATACOPY} {
		if !prague[op].undefined {
			t.Fatalf("prague instruction set unexpectedly defines %v", op)
		}
	}
}
