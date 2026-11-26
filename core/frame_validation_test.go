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
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
)

func simHeader(t uint64) *types.Header {
	return &types.Header{
		Number:     big.NewInt(0),
		Time:       t,
		Difficulty: big.NewInt(0),
		GasLimit:   60_000_000,
	}
}

// simulate runs public-mempool validation simulation on a fresh copy of sdb.
func simulate(t *testing.T, sdbAlloc types.GenesisAlloc, ftx *types.FrameTx, signsender bool) error {
	t.Helper()
	sdb := mkState(sdbAlloc)
	if signsender {
		ftx.Signatures = defaultApproveSigs(t, senderKey, ftx)
	}
	return SimulateFrameValidation(sdb, cfgFrame, simHeader(5000), types.NewTx(ftx))
}

var (
	valExisting   = common.BytesToAddress([]byte("val-existing-contract")) // code STOP
	valEOA        = common.BytesToAddress([]byte("val-existing-eoa"))      // exists, no code
	valMissing    = common.BytesToAddress([]byte("val-missing-account"))   // not in genesis
	valDelegated  = common.BytesToAddress([]byte("val-delegated-account")) // 7702 designator
	valHelper     = common.BytesToAddress([]byte("val-helper-contract"))
	valFactory    = common.BytesToAddress([]byte("val-factory-contract"))
	valTarget2    = common.BytesToAddress([]byte("val-delegation-target"))
	precompileECR = common.BytesToAddress([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01})
)

// callArgs pushes retSize, retOffset, inSize, inOffset, value, to (gas is
// pushed by the caller) for CALL, or without value for DELEGATECALL.
func pushCall(to common.Address, delegate bool) []byte {
	code := []byte{0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00} // retSize retOffset inSize inOffset
	if !delegate {
		code = append(code, 0x60, 0x00) // value
	}
	return append(append(code, 0x73), to.Bytes()...)
}

func approveCode(scope byte) []byte { return frameApproveCode(scope) }

// selfVerifyApproveCode notes: opFrameApprove ends frame execution (it
// returns errStopToken), so contract code can perform exactly one APPROVE.
// The two approval flags are therefore produced by separate frames: the
// only_verify frame's contract approves EXECUTION, and the pay frame's
// contract approves PAYMENT. APPROVE(EXECUTION_AND_PAYMENT) is applied only
// by the protocol-defined default-code path.

// TestFrameValidationSelfVerifyDefault: the all-default-code self-relay
// prefix simulates cleanly, and frames after the payer-setting frame are not
// simulated (structural rule 7).
func TestFrameValidationSelfVerifyDefault(t *testing.T) {
	banned := common.BytesToAddress([]byte("val-post-op-banned"))
	alloc := types.GenesisAlloc{
		senderAddr: {Balance: big.NewInt(1_000_000)},
		banned:     {Code: []byte{0x42, 0x00}}, // TIMESTAMP, STOP
	}
	frames := []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 0x3, Limits: mkFrameLimits(30_000, 150_000)},
		{Mode: types.FrameModeSender, Target: &banned, Flags: 0x0, Limits: mkFrameLimits(30_000, 150_000)},
	}
	ftx := frameTx(0, frames, []types.FrameSignature{{Scheme: types.FrameSigSchemeSecp256k1}})
	if err := simulate(t, alloc, ftx, true); err != nil {
		t.Fatalf("simulation: %v", err)
	}
}

// TestFrameValidationOnlyVerifyPay: the canonical-paymaster-shape prefix with
// a default-code pay (default-code sponsor) simulates cleanly.
func TestFrameValidationOnlyVerifyPay(t *testing.T) {
	alloc := types.GenesisAlloc{senderAddr: {Balance: big.NewInt(1_000_000)}}
	frames := []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 0x2, Limits: mkFrameLimits(30_000, 150_000)},
		{Mode: types.FrameModeVerify, Target: &frameContractPayer, Flags: 0x1, Limits: mkFrameLimits(30_000, 150_000)},
	}
	ftx := frameTx(0, frames, []types.FrameSignature{{Scheme: types.FrameSigSchemeSecp256k1}})
	alloc[frameContractPayer] = types.Account{Code: frameApproveCode(0x1)}
	if err := simulate(t, alloc, ftx, true); err != nil {
		t.Fatalf("simulation: %v", err)
	}
}

// TestFrameValidationBannedOpcodes: each banned opcode in deployed validation
// code rejects the transaction.
func TestFrameValidationBannedOpcodes(t *testing.T) {
	banned := map[string][]byte{
		"TIMESTAMP":    {0x42, 0x00},
		"NUMBER":       {0x43, 0x00},
		"BASEFEE":      {0x48, 0x00},
		"BALANCE":      {0x60, 0x00, 0x31, 0x50, 0x00},
		"SELFBALANCE":  {0x47, 0x00},
		"INVALID":      {0xfe},
		"BLOCKHASH":    {0x60, 0x00, 0x40, 0x50, 0x00},
		"COINBASE":     {0x41, 0x50, 0x00},
		"GASLIMIT":     {0x45, 0x50, 0x00},
		"SELFDESTRUCT": {0x60, 0x00, 0xff},
		"CREATE":       {0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0xf0, 0x50, 0x00},
	}
	for name, code := range banned {
		t.Run(name, func(t *testing.T) {
			helper := valHelper
			alloc := types.GenesisAlloc{
				senderAddr: {Balance: big.NewInt(1_000_000)},
				helper:     {Code: code},
			}
			frames := []types.Frame{
				{Mode: types.FrameModeVerify, Flags: 0x2, Limits: mkFrameLimits(30_000, 150_000)},
				{Mode: types.FrameModeVerify, Target: &helper, Flags: 0x1, Limits: mkFrameLimits(30_000, 150_000)},
			}
			ftx := frameTx(0, frames, []types.FrameSignature{{Scheme: types.FrameSigSchemeSecp256k1}})
			err := simulate(t, alloc, ftx, true)
			if err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("simulation error = %v, want banned opcode %s", err, name)
			}
		})
	}
}

// TestFrameValidationGasBeforeCall: GAS is permitted immediately before a
// *CALL and banned otherwise.
func TestFrameValidationGasBeforeCall(t *testing.T) {
	helper := valHelper
	// GAS immediately before CALL: accepted.
	gasThenCall := append(append(pushCall(valExisting, false), 0x5a), // gas = GAS (top)
		0xf1, 0x50) // CALL, POP
	gasThenCall = append(gasThenCall, approveCode(0x1)...)
	// GAS followed by POP: banned.
	gasThenPop := append([]byte{0x5a, 0x50}, approveCode(0x1)...)

	alloc := types.GenesisAlloc{
		senderAddr:  {Balance: big.NewInt(1_000_000)},
		helper:      {Code: gasThenCall},
		valExisting: {Code: []byte{0x00}},
	}
	frames := []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 0x2, Limits: mkFrameLimits(40_000, 200_000)},
		{Mode: types.FrameModeVerify, Target: &helper, Flags: 0x1, Limits: mkFrameLimits(40_000, 200_000)},
	}
	ftx := frameTx(0, frames, []types.FrameSignature{{Scheme: types.FrameSigSchemeSecp256k1}})
	if err := simulate(t, alloc, ftx, true); err != nil {
		t.Fatalf("GAS-before-CALL: %v", err)
	}

	alloc[helper] = types.Account{Code: gasThenPop}
	ftx = frameTx(0, frames, []types.FrameSignature{{Scheme: types.FrameSigSchemeSecp256k1}})
	if err := simulate(t, alloc, ftx, true); err == nil || !strings.Contains(err.Error(), "GAS") {
		t.Fatalf("GAS-then-POP error = %v, want GAS ban", err)
	}
}

// TestFrameValidationStorageWrites: SSTORE is permitted only to tx.sender's
// storage and only inside the first deploy frame.
func TestFrameValidationStorageWrites(t *testing.T) {
	// Sender code branches on calldata: the deploy frame (empty data) takes
	// the SSTORE path (write to sender storage, allowed inside the deploy
	// frame); the only_verify frame (data = 1) takes the approve path. A
	// pay frame approves payment.
	helper := valHelper
	var senderCode []byte
	senderCode = append(senderCode, 0x60, 0x00, 0x35, 0x60, 0x01, 0x14, 0x60, 0x0f, 0x57) // if data==1 goto 0x0f
	senderCode = append(senderCode, 0x60, 0x01, 0x60, 0x00, 0x55, 0x00)                   // deploy: SSTORE slot0=1, STOP
	senderCode = append(senderCode, 0x5b)                                                 // JUMPDEST 0x0f
	senderCode = append(senderCode, approveCode(0x2)...)
	senderCode = append(senderCode, approveCode(0x1)...)
	senderCode = append(senderCode, 0x00)
	verifyData := make([]byte, 32)
	verifyData[31] = 1

	alloc := types.GenesisAlloc{
		senderAddr: {Balance: big.NewInt(1_000_000), Code: senderCode},
		helper:     {Code: approveCode(0x1)},
	}
	frames := []types.Frame{
		{Mode: types.FrameModeDefault, Target: &senderAddr, Flags: 0x0, Limits: mkFrameLimits(30_000, 150_000)},
		{Mode: types.FrameModeVerify, Flags: 0x2, Data: verifyData, Limits: mkFrameLimits(30_000, 150_000)},
		{Mode: types.FrameModeVerify, Target: &helper, Flags: 0x1, Limits: mkFrameLimits(30_000, 150_000)},
	}
	ftx := frameTx(0, frames, []types.FrameSignature{{Scheme: types.FrameSigSchemeSecp256k1}})
	if err := simulate(t, alloc, ftx, true); err != nil {
		t.Fatalf("SSTORE to sender in deploy frame: %v", err)
	}

	// The same SSTORE performed by the only_verify frame (outside the deploy
	// frame): rejected. Calldata 0 selects the SSTORE path for both frames.
	frames[1].Data = nil
	ftx = frameTx(0, frames, []types.FrameSignature{{Scheme: types.FrameSigSchemeSecp256k1}})
	if err := simulate(t, alloc, ftx, true); err == nil || !strings.Contains(err.Error(), "SSTORE") {
		t.Fatalf("SSTORE outside deploy error = %v, want SSTORE ban", err)
	}

	// Deploy frame whose factory CALLs a helper that SSTOREs (helper's own
	// storage): rejected.
	factoryCode := append(append(pushCall(helper, false), 0x61, 0xff, 0xff), 0xf1, 0x50, 0x00)
	alloc = types.GenesisAlloc{
		senderAddr: {Balance: big.NewInt(1_000_000)},
		valFactory: {Code: factoryCode},
		helper:     {Code: []byte{0x60, 0x01, 0x60, 0x00, 0x55, 0x00}},
	}
	frames = []types.Frame{
		{Mode: types.FrameModeDefault, Target: &valFactory, Flags: 0x0, Limits: mkFrameLimits(30_000, 150_000)},
		{Mode: types.FrameModeVerify, Flags: 0x3, Limits: mkFrameLimits(30_000, 150_000)},
	}
	ftx = frameTx(0, frames, []types.FrameSignature{{Scheme: types.FrameSigSchemeSecp256k1}})
	if err := simulate(t, alloc, ftx, true); err == nil || !strings.Contains(err.Error(), "SSTORE") {
		t.Fatalf("factory CALL helper SSTORE error = %v, want SSTORE ban", err)
	}
}

// TestFrameValidationStorageReads: SLOAD may access only tx.sender's
// storage, including transitively through helper contracts.
func TestFrameValidationStorageReads(t *testing.T) {
	// Helper reading its own storage as a pay frame: rejected.
	helper := valHelper
	alloc := types.GenesisAlloc{
		senderAddr: {Balance: big.NewInt(1_000_000)},
		helper:     {Code: []byte{0x60, 0x00, 0x54, 0x50, 0x00}},
	}
	frames := []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 0x2, Limits: mkFrameLimits(30_000, 150_000)},
		{Mode: types.FrameModeVerify, Target: &helper, Flags: 0x1, Limits: mkFrameLimits(30_000, 150_000)},
	}
	ftx := frameTx(0, frames, []types.FrameSignature{{Scheme: types.FrameSigSchemeSecp256k1}})
	if err := simulate(t, alloc, ftx, true); err == nil || !strings.Contains(err.Error(), "storage read") {
		t.Fatalf("helper SLOAD error = %v, want storage-read ban", err)
	}

	// Sender's own validation code reading sender storage: accepted. The
	// only_verify frame executes tx.sender's code; the pay frame approves
	// payment.
	sloadSender := append([]byte{0x60, 0x00, 0x54, 0x50}, approveCode(0x2)...)
	alloc = types.GenesisAlloc{
		senderAddr: {Balance: big.NewInt(1_000_000), Code: sloadSender},
		helper:     {Code: approveCode(0x1)},
	}
	frames = []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 0x2, Limits: mkFrameLimits(40_000, 200_000)},
		{Mode: types.FrameModeVerify, Target: &helper, Flags: 0x1, Limits: mkFrameLimits(40_000, 200_000)},
	}
	ftx = frameTx(0, frames, []types.FrameSignature{{Scheme: types.FrameSigSchemeSecp256k1}})
	if err := simulate(t, alloc, ftx, true); err != nil {
		t.Fatalf("sender SLOAD: %v", err)
	}
}

// TestFrameValidationCallTargets: CALL*/EXTCODE* targets must be existing
// contracts or precompiles (or tx.sender); EIP-7702 delegated addresses are
// banned. Covers the zero-value CALL to a nonexistent account, which the EVM
// would otherwise short-circuit without executing.
func TestFrameValidationCallTargets(t *testing.T) {
	helper := valHelper
	base := func(helperCode []byte) (types.GenesisAlloc, []types.Frame) {
		alloc := types.GenesisAlloc{
			senderAddr:   {Balance: big.NewInt(1_000_000)},
			helper:       {Code: helperCode},
			valExisting:  {Code: []byte{0x00}},
			valEOA:       {},
			valDelegated: {Code: types.AddressToDelegation(valTarget2)},
			valTarget2:   {Code: []byte{0x00}},
		}
		frames := []types.Frame{
			{Mode: types.FrameModeVerify, Flags: 0x2, Limits: mkFrameLimits(30_000, 150_000)},
			{Mode: types.FrameModeVerify, Target: &helper, Flags: 0x1, Limits: mkFrameLimits(30_000, 150_000)},
		}
		return alloc, frames
	}
	run := func(t *testing.T, helperCode []byte, wantErr string) {
		t.Helper()
		alloc, frames := base(helperCode)
		ftx := frameTx(0, frames, []types.FrameSignature{{Scheme: types.FrameSigSchemeSecp256k1}})
		err := simulate(t, alloc, ftx, true)
		if wantErr == "" {
			if err != nil {
				t.Fatalf("simulation: %v", err)
			}
			return
		}
		if err == nil || !strings.Contains(err.Error(), wantErr) {
			t.Fatalf("simulation error = %v, want %q", err, wantErr)
		}
	}

	callThenApprove := func(to common.Address) []byte {
		code := append(pushCall(to, false), 0x61, 0xff, 0xff, 0xf1, 0x50)
		return append(code, approveCode(0x1)...)
	}
	t.Run("CallNonexistent", func(t *testing.T) { run(t, callThenApprove(valMissing), "nonexistent") })
	t.Run("CallExistingEOA", func(t *testing.T) { run(t, callThenApprove(valEOA), "nonexistent") })
	t.Run("CallPrecompile", func(t *testing.T) { run(t, callThenApprove(precompileECR), "") })
	t.Run("CallSender", func(t *testing.T) { run(t, callThenApprove(senderAddr), "") })
	t.Run("CallExistingContract", func(t *testing.T) { run(t, callThenApprove(valExisting), "") })
	t.Run("CallDelegated", func(t *testing.T) { run(t, callThenApprove(valDelegated), "delegated") })

	extcodeThenApprove := func(to common.Address) []byte {
		code := append([]byte{0x73}, to.Bytes()...)
		code = append(code, 0x3b, 0x50) // EXTCODESIZE, POP
		return append(code, approveCode(0x1)...)
	}
	t.Run("ExtcodeSizeNonexistent", func(t *testing.T) { run(t, extcodeThenApprove(valMissing), "nonexistent") })
	t.Run("ExtcodeSizeExisting", func(t *testing.T) { run(t, extcodeThenApprove(valExisting), "") })
}

// TestFrameValidationRevertAndApprove: a reverting validation frame rejects
// the transaction, as does a validation frame that exits without its
// required APPROVE.
func TestFrameValidationRevertAndApprove(t *testing.T) {
	helper := valHelper
	alloc := types.GenesisAlloc{
		senderAddr: {Balance: big.NewInt(1_000_000)},
		helper:     {Code: []byte{0x60, 0x00, 0x60, 0x00, 0xfd}}, // REVERT
	}
	frames := []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 0x2, Limits: mkFrameLimits(30_000, 150_000)},
		{Mode: types.FrameModeVerify, Target: &helper, Flags: 0x1, Limits: mkFrameLimits(30_000, 150_000)},
	}
	ftx := frameTx(0, frames, []types.FrameSignature{{Scheme: types.FrameSigSchemeSecp256k1}})
	if err := simulate(t, alloc, ftx, true); err == nil || !errors.Is(err, ErrFrameValidation) {
		t.Fatalf("reverting frame error = %v, want %v", err, ErrFrameValidation)
	}

	// Helper that succeeds but never APPROVEs.
	alloc[helper] = types.Account{Code: []byte{0x00}}
	ftx = frameTx(0, frames, []types.FrameSignature{{Scheme: types.FrameSigSchemeSecp256k1}})
	if err := simulate(t, alloc, ftx, true); err == nil || !strings.Contains(err.Error(), "APPROVE(PAYMENT)") {
		t.Fatalf("missing-approve error = %v, want APPROVE(PAYMENT)", err)
	}

	// self_verify code approving only execution: rejected for missing payment.
	execOnly := append([]byte{}, approveCode(0x2)...)
	alloc = types.GenesisAlloc{senderAddr: {Balance: big.NewInt(1_000_000), Code: execOnly}}
	frames = []types.Frame{{Mode: types.FrameModeVerify, Flags: 0x3, Limits: mkFrameLimits(30_000, 150_000)}}
	ftx = frameTx(0, frames, []types.FrameSignature{{Scheme: types.FrameSigSchemeSecp256k1}})
	if err := simulate(t, alloc, ftx, true); err == nil || !strings.Contains(err.Error(), "EXECUTION_AND_PAYMENT") {
		t.Fatalf("wrong-scope error = %v, want EXECUTION_AND_PAYMENT", err)
	}
}

// TestFrameValidationDeployInstall: a deploy frame must result in non-empty
// code at tx.sender (conventional code or an EIP-7702 delegation indicator).
func TestFrameValidationDeployInstall(t *testing.T) {
	// Fresh sender, no-op factory: rejected.
	alloc := types.GenesisAlloc{
		senderAddr: {Balance: big.NewInt(1_000_000)},
		valFactory: {Code: []byte{0x00}},
	}
	frames := []types.Frame{
		{Mode: types.FrameModeDefault, Target: &valFactory, Flags: 0x0, Limits: mkFrameLimits(30_000, 150_000)},
		{Mode: types.FrameModeVerify, Flags: 0x3, Limits: mkFrameLimits(30_000, 150_000)},
	}
	ftx := frameTx(0, frames, []types.FrameSignature{{Scheme: types.FrameSigSchemeSecp256k1}})
	if err := simulate(t, alloc, ftx, true); err == nil || !strings.Contains(err.Error(), "install") {
		t.Fatalf("no-install error = %v, want install rule", err)
	}

	// Sender carrying a delegation designator: accepted. Requires an
	// EIP-7702 (Prague) active config so the EVM resolves the designator.
	// Shape: deploy + only_verify (through the designator) + pay.
	cfgPrague := *cfgFrame
	pragueTime := uint64(0)
	cfgPrague.PragueTime = &pragueTime
	alloc = types.GenesisAlloc{
		senderAddr: {Balance: big.NewInt(1_000_000), Code: types.AddressToDelegation(valTarget2)},
		valFactory: {Code: []byte{0x00}},
		valTarget2: {Code: approveCode(0x2)},
		valHelper:  {Code: approveCode(0x1)},
	}
	frames = []types.Frame{
		{Mode: types.FrameModeDefault, Target: &valFactory, Flags: 0x0, Limits: mkFrameLimits(22_000, 100_000)},
		{Mode: types.FrameModeVerify, Flags: 0x2, Limits: mkFrameLimits(22_000, 100_000)},
		{Mode: types.FrameModeVerify, Target: &valHelper, Flags: 0x1, Limits: mkFrameLimits(22_000, 100_000)},
	}
	ftx = frameTx(0, frames, []types.FrameSignature{{Scheme: types.FrameSigSchemeSecp256k1}})
	sdb := mkState(alloc)
	ftx.Signatures = defaultApproveSigs(t, senderKey, ftx)
	if err := SimulateFrameValidation(sdb, &cfgPrague, simHeader(5000), types.NewTx(ftx)); err != nil {
		t.Fatalf("delegation-designator deploy: %v", err)
	}
}

// TestFrameValidationStateIsolation: simulation mutates only the state copy;
// the caller's canonical state is untouched even when the validation prefix
// performs writes (SSTORE to sender inside the deploy frame).
func TestFrameValidationStateIsolation(t *testing.T) {
	var senderCode []byte
	senderCode = append(senderCode, 0x60, 0x00, 0x35, 0x60, 0x01, 0x14, 0x60, 0x0f, 0x57) // if data==1 goto 0x0f
	senderCode = append(senderCode, 0x60, 0x01, 0x60, 0x00, 0x55, 0x00)                   // deploy: SSTORE slot0=1, STOP
	senderCode = append(senderCode, 0x5b)                                                 // JUMPDEST 0x0f
	senderCode = append(senderCode, approveCode(0x2)...)
	senderCode = append(senderCode, 0x00)
	verifyData := make([]byte, 32)
	verifyData[31] = 1

	sdb := mkState(types.GenesisAlloc{
		senderAddr: {Balance: big.NewInt(1_000_000), Code: senderCode},
		valHelper:  {Code: approveCode(0x1)},
	})
	frames := []types.Frame{
		{Mode: types.FrameModeDefault, Target: &senderAddr, Flags: 0x0, Limits: mkFrameLimits(30_000, 150_000)},
		{Mode: types.FrameModeVerify, Flags: 0x2, Data: verifyData, Limits: mkFrameLimits(30_000, 150_000)},
		{Mode: types.FrameModeVerify, Target: &valHelper, Flags: 0x1, Limits: mkFrameLimits(30_000, 150_000)},
	}
	ftx := frameTx(0, frames, []types.FrameSignature{{Scheme: types.FrameSigSchemeSecp256k1}})
	ftx.Signatures = defaultApproveSigs(t, senderKey, ftx)
	if err := SimulateFrameValidation(sdb, cfgFrame, simHeader(5000), types.NewTx(ftx)); err != nil {
		t.Fatalf("simulation: %v", err)
	}
	if got := sdb.GetState(senderAddr, common.Hash{}); got != (common.Hash{}) {
		t.Fatalf("canonical storage mutated: slot 0 = %x, want empty", got)
	}
	if nonce := sdb.GetNonce(senderAddr); nonce != 0 {
		t.Fatalf("canonical nonce mutated: %d, want 0", nonce)
	}
	if bal := sdb.GetBalance(senderAddr).Uint64(); bal != 1_000_000 {
		t.Fatalf("canonical balance mutated: %d, want 1000000", bal)
	}
}

// TestFrameValidationExpiryIntegration: the expiry verifier frame is
// evaluated inside simulation (direct evaluation), and an expired deadline is
// rejected by the structural freshness rule before execution.
func TestFrameValidationExpiryIntegration(t *testing.T) {
	alloc := types.GenesisAlloc{senderAddr: {Balance: big.NewInt(1_000_000)}}
	expiry := expiryFrame(10_000)
	expiry.Limits = types.FrameLimits{Execution: 50_000, State: 0} // keep the prefix within MAX_VERIFY_GAS
	frames := append([]types.Frame{expiry},
		types.Frame{Mode: types.FrameModeVerify, Flags: 0x3, Limits: mkFrameLimits(40_000, 300_000)})
	ftx := frameTx(0, frames, []types.FrameSignature{{Scheme: types.FrameSigSchemeSecp256k1}})
	if err := simulate(t, alloc, ftx, true); err != nil {
		t.Fatalf("future expiry: %v", err)
	}

	frames[0] = expiryFrame(4_999)
	ftx = frameTx(0, frames, []types.FrameSignature{{Scheme: types.FrameSigSchemeSecp256k1}})
	if err := simulate(t, alloc, ftx, true); err == nil {
		t.Fatal("expired expiry-verifier frame: want rejection")
	}
}

// --- Canonical paymaster validation (ethereum/EIPs PR #12041) ---------------

// canonicalPaymasterRuntime is the assembled EIP-8141 canonical paymaster
// runtime published in ethereum/EIPs PR #12041; its keccak256 equals
// CanonicalPaymasterCodeHash (verified locally during implementation).
var canonicalPaymasterRuntime = common.FromHex("0x3461002e57366100355760016001b41561005a575f6001b45f54141561005a5760026001b461005a5760015f5faa5b3661005a57005b5f3560f81c8060011461005e57806002146100a557806003146100ec57600414610123575b5f5ffd5b50335f54146100875760016001b41561005a575f6001b45f54141561005a5760026001b461005a575b60025461005a57600135801561005a57600155426201518001600255005b50335f54146100ce5760016001b41561005a575f6001b45f54141561005a5760026001b461005a575b60025461005a57600135801561005a57600355426201518001600255005b50335f54146101155760016001b41561005a575f6001b45f54141561005a5760026001b461005a575b5f6001555f6002555f600355005b600254801561005a57421061005a576001548015610153575f6001555f6002555f5f5f5f845f545af11561005a57005b506003545f555f6003555f60025500")

// signFrameEntry signs the transaction's canonical signature hash with key
// and returns the secp256k1 entry naming addr (v || r || s wire form).
func signFrameEntry(t *testing.T, ftx *types.FrameTx, key *ecdsa.PrivateKey, addr common.Address) types.FrameSignature {
	t.Helper()
	sig, err := crypto.Sign(ftx.SigHash().Bytes(), key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return types.FrameSignature{
		Scheme:    types.FrameSigSchemeSecp256k1,
		Signer:    addr.Bytes(),
		Signature: append(append([]byte{}, sig[64]), sig[0:64]...),
	}
}

// TestFrameValidationCanonicalPaymaster: a pay frame targeting an instance of
// the canonical paymaster runtime is admitted by code-hash match and a
// successful APPROVE(APPROVE_PAYMENT) even though it reads its own storage
// slot 0 (the generic trace rules do not apply to the canonical pay frame).
func TestFrameValidationCanonicalPaymaster(t *testing.T) {
	sponsorKey, _ := crypto.GenerateKey()
	sponsor := crypto.PubkeyToAddress(sponsorKey.PublicKey)
	paymaster := common.BytesToAddress([]byte("val-canonical-paymaster"))
	alloc := types.GenesisAlloc{
		senderAddr: {Balance: big.NewInt(1_000_000)},
		paymaster: {
			Balance: big.NewInt(1_000_000),
			Code:    canonicalPaymasterRuntime,
			Storage: map[common.Hash]common.Hash{
				CanonicalPaymasterSlotSigner: common.BytesToHash(sponsor.Bytes()),
			},
		},
	}
	frames := []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 0x2, Limits: mkFrameLimits(30_000, 150_000)},
		{Mode: types.FrameModeVerify, Flags: 0x1, Limits: mkFrameLimits(30_000, 150_000), Target: &paymaster},
	}
	ftx := frameTx(0, frames, make([]types.FrameSignature, 2))
	ftx.Signatures[0] = signFrameEntry(t, ftx, senderKey, senderAddr)
	ftx.Signatures[1] = signFrameEntry(t, ftx, sponsorKey, sponsor)
	if err := SimulateFrameValidation(mkState(alloc), cfgFrame, simHeader(5000), types.NewTx(ftx)); err != nil {
		t.Fatalf("canonical paymaster simulation: %v", err)
	}
}

// TestFrameValidationCanonicalPaymasterHashSpecific: a pay frame whose target
// reads its own storage but does NOT match the pinned canonical code hash is
// still rejected by the generic storage-read rule.
func TestFrameValidationCanonicalPaymasterHashSpecific(t *testing.T) {
	sponsorKey, _ := crypto.GenerateKey()
	sponsor := crypto.PubkeyToAddress(sponsorKey.PublicKey)
	paymaster := common.BytesToAddress([]byte("val-near-canonical-paymaster"))
	// PUSH1 0 SLOAD POP; then approve PAYMENT. Same storage access as the
	// canonical validation path, different (non-canonical) code hash.
	sloadApprove := []byte{0x60, 0x00, 0x54, 0x50, 0x60, 0x01, 0x60, 0x00, 0x60, 0x00, 0xaa, 0x00}
	alloc := types.GenesisAlloc{
		senderAddr: {Balance: big.NewInt(1_000_000)},
		paymaster: {
			Balance: big.NewInt(1_000_000),
			Code:    sloadApprove,
			Storage: map[common.Hash]common.Hash{
				CanonicalPaymasterSlotSigner: common.BytesToHash(sponsor.Bytes()),
			},
		},
	}
	frames := []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 0x2, Limits: mkFrameLimits(30_000, 150_000)},
		{Mode: types.FrameModeVerify, Flags: 0x1, Limits: mkFrameLimits(30_000, 150_000), Target: &paymaster},
	}
	ftx := frameTx(0, frames, make([]types.FrameSignature, 2))
	ftx.Signatures[0] = signFrameEntry(t, ftx, senderKey, senderAddr)
	ftx.Signatures[1] = signFrameEntry(t, ftx, sponsorKey, sponsor)
	err := SimulateFrameValidation(mkState(alloc), cfgFrame, simHeader(5000), types.NewTx(ftx))
	if err == nil || !strings.Contains(err.Error(), "storage read") {
		t.Fatalf("non-canonical pay frame storage read not rejected: %v", err)
	}
}
