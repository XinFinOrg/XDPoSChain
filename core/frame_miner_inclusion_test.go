// Copyright 2026 The go-ethereum Authors
// Reproduction/regression test for the live chain-81411 observation that the
// miner never includes the submitted Scenario A frame transaction: the tx is
// executable in the pool, yet every assembled block comes back empty.
//
// This test replays the miner's exact application path for the scenario-a2
// fixture bytes (R1-P synthetic re-encode, see scenarioA2RawHex) against a
// state and chain config matching the disposable run2 network:
//
//	signer := types.MakeSigner(config, number, time)      // as miner/worker.go commitTransaction
//	msg, err := core.TransactionToMessage(tx, signer, baseFee)
//	core.ApplyTransactionWithEVM(msg, gp, statedb, ...)   // as miner applyTransaction
//
// Before the fix that made this test pass, TransactionToMessage failed with
// ErrTxTypeNotSupported under the miner's block-context MakeSigner (see
// TestFrameTxMakeSignerXDPoSDifficulty), and the worker silently skipped the
// transaction at debug log level, producing empty blocks forever.

package core

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/holiman/uint256"
)

// scenarioA2RawHex is the R1-P repair fixture (approved 2026-11-11): a
// synthetic re-encode of the scenario-a2 frame transaction, byte-identical
// in structure to the original live-captured tx (self-verify-flags (0x3)
// frame + SENDER frame targeting account-b with 0.001 XDC, MaxGas 472,790,
// chainId 81411, GasTipCap 6 Gwei) but with the EIP-8141 AGGREGATE fee
// budget GasFeeCap = 8,746,615,000,000,000 wei (MaxGas×(baseFee+tip) at
// 12.5 Gwei) and signed by the harness key — the original signing key is
// unrecoverable (rehearsal materials deleted 2026-11-07) and the frame
// sighash covers the fee fields.
// (176 bytes, sha256 14119ae3810c11e4349fbc68657c9d339300788f034118c5b031665c4392b007,
// hash 0xaec7dd16d48e21750918e686b4c56c8608bac36ff49dc110e384194b9ebd6ea5).
const scenarioA2RawHex = "06f8ad83013e03809471562b71999873db5b286df957af199ec94617f7f7cc010380c68261a88261a88080e9028094c67c1da5fd98d573182ca4b0da2686ba7cc1f0ccc8830186a0830493e087038d7ea4c6800080f848f846018080b8410013c296671e2cb76d0d153d88cfd3098bd422e03eac7bad710d7d7e1a0272b70943784b2800d8102b541e26431a71daef19b3a13bfd2bfc8c27f6b0bc11b16002cf850165a0bc00871f1300000fe60080c0"

// run2ChainConfigJSON mirrors the config block of the run2-20261030 genesis
// (chainId 81411, all forks at genesis except cancun at 3150, frameTxTime 0,
// XDPoS epoch 900 period 1, v2 switchBlock 1800).
const run2ChainConfigJSON = `{
  "chainId": 81411,
  "homesteadBlock": 0, "eip150Block": 0, "eip155Block": 0, "eip158Block": 0,
  "byzantiumBlock": 0, "constantinopleBlock": 0, "petersburgBlock": 0,
  "istanbulBlock": 0, "berlinBlock": 0, "londonBlock": 0,
  "cancunBlock": 3150,
  "frameTxTime": 0,
  "xdpos": {"epoch": 900, "period": 1, "reward": 5000, "gap": 450,
    "v2": {"switchBlock": 1800,
      "config": {"maxMasternodes": 108, "certificateThreshold": 0.667,
                 "timeoutPeriod": 10, "timeoutSyncThreshold": 3, "minePeriod": 1}}}
}`

func run2TestConfig(t *testing.T) *params.ChainConfig {
	t.Helper()
	cfg := new(params.ChainConfig)
	if err := json.Unmarshal([]byte(run2ChainConfigJSON), cfg); err != nil {
		t.Fatalf("unmarshal run2 config: %v", err)
	}
	if !cfg.IsFrameTx(big.NewInt(1758), 0) {
		t.Fatal("run2 config: IsFrameTx(1758) = false, want true")
	}
	if cfg.IsCancun(big.NewInt(1758), 0) {
		t.Fatal("run2 config: IsCancun(1758) = true, want false (cancun at 3150)")
	}
	return cfg
}

func decodeScenarioA2(t *testing.T) *types.Transaction {
	t.Helper()
	raw, err := hex.DecodeString(scenarioA2RawHex)
	if err != nil {
		t.Fatalf("decode raw hex: %v", err)
	}
	tx := new(types.Transaction)
	if err := tx.UnmarshalBinary(raw); err != nil {
		t.Fatalf("unmarshal scenario-a2: %v", err)
	}
	return tx
}

// TestScenarioA2MinerApplyPath replays the exact miner application sequence
// against the live-equivalent environment. This is the regression test for
// the empty-block inclusion failure.
func TestScenarioA2MinerApplyPath(t *testing.T) {
	cfg := run2TestConfig(t)
	tx := decodeScenarioA2(t)

	const (
		blockNum  = 1758 // live head region: > epoch 900, < cancun 3150
		blockTime = 1_760_000_000
		gasLimit  = 14_270_061 // live block gasLimit (0xd9bc6d)
	)
	baseFee := big.NewInt(12_500_000_000) // 12.5 Gwei, live base fee

	// Sender is the DECLARED payload field for frame txs (no recovery).
	signer := types.MakeSigner(cfg, big.NewInt(blockNum), blockTime)
	from, err := types.Sender(signer, tx)
	if err != nil {
		t.Fatalf("miner-path Sender: %v", err)
	}
	t.Logf("sender=%s nonce=%d gas=%d", from.Hex(), tx.Nonce(), tx.Gas())

	// State matching the live network at submission time.
	sdb, err := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	if err != nil {
		t.Fatalf("state: %v", err)
	}
	senderBalance, _ := new(big.Int).SetString("5000000000000000000", 10) // 5 XDC
	sdb.SetBalance(from, uint256.MustFromBig(senderBalance), 0)
	sdb.SetNonce(from, 0, 0)
	target := common.HexToAddress("0xC67C1Da5fD98D573182Ca4B0Da2686ba7cc1f0cc")
	sdb.SetBalance(target, uint256.NewInt(2_000_000_000_000_000_000), 0)

	blockCtx := vm.BlockContext{
		CanTransfer: CanTransfer,
		Transfer:    Transfer,
		GetHash:     func(uint64) common.Hash { return common.Hash{} },
		Coinbase:    common.HexToAddress("0x5039d5B570eB7B982E5f64690020Ef760CCF5CdD"),
		BlockNumber: big.NewInt(blockNum),
		Time:        blockTime,
		Difficulty:  big.NewInt(2), // XDPoS live headers carry difficulty 2
		BaseFee:     baseFee,
		GasLimit:    gasLimit,
	}
	evm := vm.NewEVM(blockCtx, sdb, cfg, vm.Config{})
	gp := NewGasPool(gasLimit)

	// --- the miner's exact calls (miner/worker.go commitTransaction) ---
	msg, err := TransactionToMessage(tx, signer, baseFee)
	if err != nil {
		t.Fatalf("TransactionToMessage: %v", err)
	}
	evm.SetTxContext(NewEVMTxContext(msg))
	receipt, _, err := ApplyTransactionWithEVM(msg, gp, sdb, big.NewInt(blockNum), common.Hash{}, blockTime, tx, evm)
	if err != nil {
		t.Fatalf("ApplyTransactionWithEVM: %v", err)
	}
	if receipt.Status != types.ReceiptStatusSuccessful {
		t.Fatalf("receipt status = %d, want success", receipt.Status)
	}
	if nonce := sdb.GetNonce(from); nonce != 1 {
		t.Fatalf("sender nonce = %d, want 1", nonce)
	}
	want, _ := new(big.Int).SetString("2001000000000000000", 10)
	if bal := sdb.GetBalance(target); bal.ToBig().Cmp(want) != 0 {
		t.Fatalf("target balance = %v, want %v (2 XDC + 0.001 XDC)", bal, want)
	}
	// The sender must have been charged a real fee bounded by the EIP-1559
	// total: gasUsed <= MaxGas, price <= min(feeCap, baseFee+tipCap).
	ftx := tx.FramePayload()
	maxCost := new(big.Int).Mul(new(big.Int).SetUint64(ftx.MaxGas()),
		new(big.Int).Add(baseFee, ftx.Fees.GasTipCap.ToBig()))
	spent := new(big.Int).Sub(senderBalance, sdb.GetBalance(from).ToBig())
	if spent.Sign() <= 0 || spent.Cmp(maxCost) > 0 {
		t.Fatalf("sender spent %v, want in (0, %v]", spent, maxCost)
	}
}

// TestFrameFeeCapBelowBaseFeeRejected pins the fee-unit semantics of
// FrameFees: GasFeeCap is the AGGREGATE EIP-8141 max-fee budget (wei for the
// whole transaction, compared against MaxGas×baseFee), while GasTipCap is
// per-gas. A frame tx whose aggregate fee budget cannot cover MaxGas×baseFee
// can never execute and must be rejected VISIBLY at pool-simulation time (not
// admitted and then silently skipped by the miner, which is what produced
// the empty-block incident on chain 81411).
func TestFrameFeeCapBelowBaseFeeRejected(t *testing.T) {
	sdb := mkState(types.GenesisAlloc{senderAddr: {Balance: big.NewInt(5_000_000_000_000_000_000)}})
	target := senderAddr
	ftx := frameTx(0, []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 0x3, Limits: mkFrameLimits(25_000, 25_000)},
		{Mode: types.FrameModeSender, Target: &target, Limits: mkFrameLimits(100_000, 100_000)},
	}, nil)
	// Aggregate fee budget of 5 Gwei wei for the whole tx — far below the
	// required MaxGas×12.5 Gwei block base fee.
	ftx.Fees.GasFeeCap = uint256.NewInt(5_000_000_000)
	ftx.Fees.GasTipCap = uint256.NewInt(1_000_000_000)
	// Attach the signature ENTRY before signing so SigHash covers it
	// (signature bytes are elided for empty-msg entries; the harness'
	// defaultApproveSigs signs too early and never passes ValidateSignatures).
	ftx.Signatures = []types.FrameSignature{{Scheme: types.FrameSigSchemeSecp256k1}}
	digest := ftx.SigHash()
	sig, err := crypto.Sign(digest.Bytes(), senderKey)
	if err != nil {
		t.Fatal(err)
	}
	ftx.Signatures[0].Signature = append(append([]byte{}, sig[64]), sig[0:64]...)
	tx := types.NewTx(ftx)

	header := &types.Header{
		Number:     big.NewInt(1),
		GasLimit:   30_000_000,
		Difficulty: big.NewInt(2),
		BaseFee:    big.NewInt(12_500_000_000),
	}
	if err := SimulateFrameValidation(sdb, cfgFrame, header, tx); !errors.Is(err, ErrFeeCapTooLow) {
		t.Fatalf("pool simulation error = %v, want ErrFeeCapTooLow", err)
	}

	signer := types.MakeSigner(cfgFrame, header.Number, header.Time)
	msg, err := TransactionToMessage(tx, signer, header.BaseFee)
	if err != nil {
		t.Fatalf("TransactionToMessage: %v", err)
	}
	evm := vm.NewEVM(vm.BlockContext{
		CanTransfer: CanTransfer,
		Transfer:    Transfer,
		GetHash:     func(uint64) common.Hash { return common.Hash{} },
		Coinbase:    common.Address{},
		BlockNumber: header.Number,
		Time:        header.Time,
		Difficulty:  header.Difficulty,
		BaseFee:     header.BaseFee,
		GasLimit:    header.GasLimit,
	}, sdb, cfgFrame, vm.Config{})
	_, _, err = ApplyTransactionWithEVM(msg, NewGasPool(header.GasLimit), sdb, header.Number, common.Hash{}, header.Time, tx, evm)
	if !errors.Is(err, ErrFeeCapTooLow) {
		t.Fatalf("block apply error = %v, want ErrFeeCapTooLow", err)
	}
}

// TestScenarioA2PendingFilterSemantics mirrors the pool-side filter the miner
// applies (txpool.PendingFilter{MinTip, BaseFee}) for the run2 fee market, to
// pin that the live fee values do not exclude the transaction.
func TestScenarioA2PendingFilterSemantics(t *testing.T) {
	tx := decodeScenarioA2(t)
	baseFee := big.NewInt(12_500_000_000)
	minTip := big.NewInt(params.GWei / 1000) // miner.DefaultConfig.GasPrice
	tip, err := tx.EffectiveGasTip(baseFee)
	if err != nil {
		t.Fatalf("EffectiveGasTip: %v", err)
	}
	if tip.Cmp(minTip) < 0 {
		t.Fatalf("effective tip %v below miner MinTip %v", tip, minTip)
	}
	t.Logf("effective tip = %v wei (min %v)", tip, minTip)
}

var _ = strings.TrimSpace // keep strings import if assertions grow
