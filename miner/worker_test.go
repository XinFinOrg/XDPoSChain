// Copyright 2026 The XDPoSChain Authors
// This file is part of the XDPoSChain library.
//
// The XDPoSChain library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The XDPoSChain library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the XDPoSChain library. If not, see <http://www.gnu.org/licenses/>.

package miner

import (
	"crypto/ecdsa"
	"math/big"
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/utils"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/txpool"
	"github.com/XinFinOrg/XDPoSChain/core/txpool/legacypool"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/event"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/holiman/uint256"
)

func newBlockingSubscription() event.Subscription {
	return event.NewSubscription(func(unsub <-chan struct{}) error {
		<-unsub
		return nil
	})
}

func TestWorkerUpdateNonXDPoSStaysRunning(t *testing.T) {
	worker := &worker{
		engine:       ethash.NewFaker(),
		chainHeadSub: newBlockingSubscription(),
		chainSideSub: newBlockingSubscription(),
		resetCh:      make(chan time.Duration, 1),
	}

	done := make(chan struct{})
	started := make(chan struct{})
	go func() {
		close(started)
		worker.update()
		close(done)
	}()
	select {
	case <-started:
		// worker.update has started; proceed with timing checks.
	case <-time.After(time.Second):
		t.Fatal("worker.update did not start in time")
	}

	select {
	case <-done:
		t.Fatal("worker.update returned before unsubscribe")
	default:
		// Expected: update is still running until subscription error.
	}
	worker.chainHeadSub.Unsubscribe()

	select {
	case <-done:
		// Expected: update exits after subscription error.
	case <-time.After(time.Second):
		t.Fatal("worker.update did not return after unsubscribe")
	}
}

func TestWorkerCheckPreCommitXDPoSMismatch(t *testing.T) {
	config := &params.ChainConfig{
		ChainID: big.NewInt(1),
		XDPoS: &params.XDPoSConfig{
			V2: &params.V2{
				SwitchBlock: big.NewInt(0),
				AllConfigs: map[uint64]*params.V2Config{
					0: {MinePeriod: 2},
				},
			},
		},
	}
	signer := common.HexToAddress("0x0000000000000000000000000000000000000001")
	extraData := make([]byte, 0, utils.ExtraVanity+common.AddressLength+utils.ExtraSeal)
	extraData = append(extraData, make([]byte, utils.ExtraVanity)...)
	extraData = append(extraData, signer.Bytes()...)
	extraData = append(extraData, make([]byte, utils.ExtraSeal)...)
	genesis := &core.Genesis{
		Config:     config,
		GasLimit:   params.XDCGenesisGasLimit,
		Difficulty: big.NewInt(1),
		Alloc:      types.GenesisAlloc{},
		ExtraData:  extraData,
	}
	db := rawdb.NewMemoryDatabase()
	if _, err := genesis.Commit(db); err != nil {
		t.Fatalf("failed to commit genesis: %v", err)
	}
	engine := ethash.NewFaker()
	chain, err := core.NewBlockChain(db, nil, genesis, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create blockchain: %v", err)
	}
	defer chain.Stop()

	worker := &worker{
		chainConfig: config,
		engine:      engine,
		chain:       chain,
		announceTxs: true,
	}

	parent, shouldReturn := worker.checkPreCommitWithLock()
	if parent == nil {
		t.Fatal("expected parent block, got nil")
	}
	if !shouldReturn {
		t.Fatal("expected checkPreCommitWithLock to skip when XDPoS config is enabled but engine is not XDPoS")
	}
	if parent.Number().Sign() != 0 {
		t.Fatalf("expected genesis parent, got number %v", parent.Number())
	}
}

func TestWorkerSetGasTipValidation(t *testing.T) {
	w := &worker{tip: uint256.NewInt(1)}
	old := new(uint256.Int).Set(w.tip)

	tests := []struct {
		name string
		tip  *big.Int
	}{
		{name: "nil", tip: nil},
		{name: "negative", tip: big.NewInt(-1)},
		{name: "too high", tip: new(big.Int).Add(maxGasTip, big.NewInt(1))},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := w.setGasTip(tc.tip); err == nil {
				t.Fatalf("expected error for %s tip", tc.name)
			}
			if w.tip.Cmp(old) != 0 {
				t.Fatalf("tip changed on invalid input: have %v want %v", w.tip, old)
			}
		})
	}
}

func TestWorkerSetGasTipCopiesValue(t *testing.T) {
	w := &worker{}
	input := big.NewInt(2 * params.GWei)

	if err := w.setGasTip(input); err != nil {
		t.Fatalf("setGasTip failed: %v", err)
	}
	if w.tip == nil {
		t.Fatal("worker tip was not set")
	}

	input.Add(input, big.NewInt(1))
	if w.tip.Cmp(uint256.NewInt(2*params.GWei)) != 0 {
		t.Fatalf("worker tip mutated via input pointer: have %v", w.tip)
	}
}

func TestPendingMinTipForHeaderWithoutBaseFee(t *testing.T) {
	minGasPrice := uint256.NewInt(12_500_000_000)
	got := pendingMinTipForHeader(minGasPrice, nil)

	if got.Cmp(minGasPrice) != 0 {
		t.Fatalf("unexpected min tip without baseFee: have %v want %v", got, minGasPrice)
	}
}

func TestPendingMinTipForHeaderBaseFeeEqualsMinGasPrice(t *testing.T) {
	minGasPrice := uint256.NewInt(12_500_000_000)
	baseFee := uint256.NewInt(12_500_000_000)

	got := pendingMinTipForHeader(minGasPrice, baseFee)
	want := uint256.NewInt(0)

	if got.Cmp(want) != 0 {
		t.Fatalf("unexpected min tip when baseFee equals min gas price: have %v want %v", got, want)
	}
}

func TestPendingMinTipForHeaderSubtractsBaseFee(t *testing.T) {
	minGasPrice := uint256.NewInt(12_500_000_001)
	baseFee := uint256.NewInt(12_500_000_000)

	got := pendingMinTipForHeader(minGasPrice, baseFee)
	want := uint256.NewInt(1)

	if got.Cmp(want) != 0 {
		t.Fatalf("unexpected min tip after baseFee subtraction: have %v want %v", got, want)
	}
}

func TestPendingFilterForHeaderBaseFeeBoundary(t *testing.T) {
	header := &types.Header{
		Number:  big.NewInt(1),
		BaseFee: big.NewInt(12_500_000_000),
	}
	minGasPrice := uint256.NewInt(12_500_000_000)

	filter := pendingFilterForHeader(minGasPrice, header, &params.ChainConfig{})

	if filter.MinTip == nil || filter.MinTip.Cmp(uint256.NewInt(0)) != 0 {
		t.Fatalf("unexpected min tip at boundary: have %v want 0", filter.MinTip)
	}
	if filter.BaseFee == nil || filter.BaseFee.Cmp(uint256.MustFromBig(header.BaseFee)) != 0 {
		t.Fatalf("unexpected base fee in filter: have %v want %v", filter.BaseFee, header.BaseFee)
	}
}

func TestPendingFilterForHeaderWithoutBaseFee(t *testing.T) {
	header := &types.Header{
		Number: big.NewInt(1),
	}
	minGasPrice := uint256.NewInt(12_500_000_000)

	filter := pendingFilterForHeader(minGasPrice, header, &params.ChainConfig{})

	if filter.MinTip == nil || filter.MinTip.Cmp(minGasPrice) != 0 {
		t.Fatalf("unexpected min tip without baseFee: have %v want %v", filter.MinTip, minGasPrice)
	}
	if filter.BaseFee != nil {
		t.Fatalf("expected nil base fee in filter, have %v", filter.BaseFee)
	}
}

func TestPendingFilterForHeaderGasLimitCapPreOsaka(t *testing.T) {
	header := &types.Header{
		Number:  big.NewInt(1),
		BaseFee: big.NewInt(12_500_000_000),
	}
	minGasPrice := uint256.NewInt(12_500_000_000)
	// With default chain config (Osaka not activated), GasLimitCap should remain zero.
	filter := pendingFilterForHeader(minGasPrice, header, &params.ChainConfig{})
	if filter.GasLimitCap != 0 {
		t.Fatalf("unexpected gas limit cap before Osaka activation: have %v want %v", filter.GasLimitCap, 0)
	}
}

func TestPendingFilterForHeaderGasLimitCapOsaka(t *testing.T) {
	header := &types.Header{
		Number:  big.NewInt(1),
		BaseFee: big.NewInt(12_500_000_000),
	}
	minGasPrice := uint256.NewInt(12_500_000_000)
	// Activate Osaka at block 1 so that this header is considered Osaka.
	cfg := &params.ChainConfig{
		OsakaBlock: big.NewInt(1),
	}
	filter := pendingFilterForHeader(minGasPrice, header, cfg)
	if filter.GasLimitCap != params.MaxTxGas {
		t.Fatalf("unexpected gas limit cap after Osaka activation: have %v want %v", filter.GasLimitCap, params.MaxTxGas)
	}
}

func TestPendingFilterForHeaderTxPoolBoundarySelection(t *testing.T) {
	key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	if err != nil {
		t.Fatalf("failed to create test key: %v", err)
	}
	from := crypto.PubkeyToAddress(key.PublicKey)
	to := common.HexToAddress("0x0000000000000000000000000000000000000001")

	chainConfig := params.MergedTestChainConfig
	baseFee := big.NewInt(params.InitialBaseFee)
	genesis := &core.Genesis{
		Config: chainConfig,
		Alloc: types.GenesisAlloc{
			from: {Balance: big.NewInt(1_000_000_000_000_000_000)},
		},
		Difficulty: common.Big0,
		BaseFee:    new(big.Int).Set(baseFee),
	}

	db := rawdb.NewMemoryDatabase()
	engine := ethash.NewFaker()
	chain, err := core.NewBlockChain(db, nil, genesis, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create blockchain: %v", err)
	}
	defer chain.Stop()

	legacyCfg := legacypool.DefaultConfig
	legacyCfg.Journal = ""
	legacyPool := legacypool.New(legacyCfg, chain)
	txPool, err := txpool.New(legacyCfg.PriceLimit, chain, []txpool.SubPool{legacyPool})
	if err != nil {
		t.Fatalf("failed to create txpool: %v", err)
	}
	defer func() {
		if err := txPool.Close(); err != nil {
			t.Errorf("failed to close txpool: %v", err)
		}
	}()

	signer := types.LatestSignerForChainID(chainConfig.ChainID)
	legacyTx := mustSignLegacyTx(t, key, signer, 0, new(big.Int).Set(baseFee), to)
	dynamicTx := mustSignDynamicBoundaryTx(t, key, signer, chainConfig.ChainID, 1, new(big.Int).Set(baseFee), to)

	errs := txPool.Add([]*types.Transaction{legacyTx, dynamicTx}, true)
	for i, addErr := range errs {
		if addErr != nil {
			t.Fatalf("failed to add tx %d: %v", i, addErr)
		}
	}

	pendingAll, _ := txPool.ContentFrom(from)
	if len(pendingAll) != 2 {
		t.Fatalf("unexpected pending tx count after add: have %d want 2", len(pendingAll))
	}

	header := &types.Header{Number: big.NewInt(1), BaseFee: new(big.Int).Set(baseFee)}
	minGasPrice := uint256.MustFromBig(baseFee)

	filter := pendingFilterForHeader(minGasPrice, header, chainConfig)
	selected := txPool.Pending(filter)
	if got := len(selected[from]); got != 2 {
		t.Fatalf("boundary txs should be selected with derived min tip: have %d want 2", got)
	}

	// This mirrors the pre-fix behavior (MinTip=minGasPrice with baseFee present),
	// which over-filters boundary-valid transactions.
	legacyBehaviorFilter := txpool.PendingFilter{MinTip: minGasPrice, BaseFee: uint256.MustFromBig(baseFee)}
	legacySelected := txPool.Pending(legacyBehaviorFilter)
	if got := len(legacySelected[from]); got != 0 {
		t.Fatalf("pre-fix filter unexpectedly selected boundary txs: have %d want 0", got)
	}
}

func mustSignLegacyTx(t *testing.T, key *ecdsa.PrivateKey, signer types.Signer, nonce uint64, gasPrice *big.Int, to common.Address) *types.Transaction {
	t.Helper()
	tx := types.NewTransaction(nonce, to, big.NewInt(1), params.TxGas, gasPrice, nil)
	signed, err := types.SignTx(tx, signer, key)
	if err != nil {
		t.Fatalf("failed to sign legacy tx: %v", err)
	}
	return signed
}

func mustSignDynamicBoundaryTx(t *testing.T, key *ecdsa.PrivateKey, signer types.Signer, chainID *big.Int, nonce uint64, baseFee *big.Int, to common.Address) *types.Transaction {
	t.Helper()
	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   new(big.Int).Set(chainID),
		Nonce:     nonce,
		GasTipCap: big.NewInt(params.GWei),
		GasFeeCap: new(big.Int).Set(baseFee),
		Gas:       params.TxGas,
		To:        &to,
		Value:     big.NewInt(1),
	})
	signed, err := types.SignTx(tx, signer, key)
	if err != nil {
		t.Fatalf("failed to sign dynamic fee tx: %v", err)
	}
	return signed
}
