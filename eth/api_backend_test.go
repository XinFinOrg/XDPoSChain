// Copyright 2025 The go-ethereum Authors
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

package eth

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"math/big"
	"reflect"
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/txpool"
	"github.com/XinFinOrg/XDPoSChain/core/txpool/legacypool"
	"github.com/XinFinOrg/XDPoSChain/core/txpool/locals"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	internalethapi "github.com/XinFinOrg/XDPoSChain/internal/ethapi"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/XinFinOrg/XDPoSChain/rpc"
	"github.com/holiman/uint256"
)

var (
	key, _          = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	address         = crypto.PubkeyToAddress(key.PublicKey)
	funds           = big.NewInt(1000_000_000_000_000)
	testChainConfig = func() *params.ChainConfig {
		cfg := params.MergedTestChainConfig.Clone()
		cfg.Gas50xBlock = big.NewInt(1_000_000_000)
		return cfg
	}()
	gspec = &core.Genesis{
		Config: testChainConfig,
		Alloc: types.GenesisAlloc{
			address: {Balance: funds},
		},
		Difficulty: common.Big0,
		BaseFee:    big.NewInt(params.InitialBaseFee),
	}
	signer = types.LatestSignerForChainID(gspec.Config.ChainID)
)

func initBackend(t *testing.T, withLocal bool) *EthAPIBackend {
	t.Helper()

	var (
		// Create a database pre-initialize with a genesis block
		db     = rawdb.NewMemoryDatabase()
		engine = ethash.NewFaker()
	)
	chain, err := core.NewBlockChain(db, nil, gspec, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create blockchain: %v", err)
	}

	txconfig := legacypool.DefaultConfig
	txconfig.Journal = "" // Don't litter the disk with test journals

	legacyPool := legacypool.New(txconfig, chain)
	txpool, err := txpool.New(txconfig.PriceLimit, chain, []txpool.SubPool{legacyPool})
	if err != nil {
		// Ensure we don't leak the blockchain goroutines if txpool creation fails.
		chain.Stop()
		t.Fatalf("failed to create txpool: %v", err)
	}

	eth := &Ethereum{
		blockchain: chain,
		txPool:     txpool,
	}
	if withLocal {
		eth.localTxTracker = locals.New("", time.Minute, gspec.Config, txpool)
	}
	t.Cleanup(func() {
		if eth.localTxTracker != nil {
			if err := eth.localTxTracker.Stop(); err != nil {
				t.Errorf("failed to stop local tx tracker: %v", err)
			}
		}
		if err := txpool.Close(); err != nil {
			t.Errorf("failed to close txpool: %v", err)
		}
		chain.Stop()
	})

	return &EthAPIBackend{
		eth: eth,
	}
}

func TestAttachStateChainConfig(t *testing.T) {
	t.Parallel()

	backend := initBackend(t, false)
	statedb, err := state.New(types.EmptyRootHash, state.NewDatabase(rawdb.NewMemoryDatabase()))
	if err != nil {
		t.Fatalf("failed to create state db: %v", err)
	}
	if statedb.ChainConfig() != nil {
		t.Fatal("expected fresh state db to start without chain config")
	}

	statedb, err = internalethapi.AttachStateChainConfig(statedb, backend.ChainConfig())
	if err != nil {
		t.Fatalf("expected attach to succeed: %v", err)
	}

	if statedb.ChainConfig() != backend.ChainConfig() {
		t.Fatal("expected backend helper to attach chain config to state db")
	}
}

func TestFinalizedBlockNumberWithoutCommittedBlock(t *testing.T) {
	// The mock config switches to v2 after block 900. Below the genesis block the
	// engine is v2 from block 0, so the v2 branch needs no generated chain.
	cfg := params.TestXDPoSMockChainConfig.Clone()
	cfg.XDPoS.Epoch = 1
	cfg.XDPoS.V2.SwitchBlock = big.NewInt(-1)

	v2Gspec := &core.Genesis{
		Config:     cfg,
		Alloc:      types.GenesisAlloc{address: {Balance: funds}},
		Difficulty: common.Big0,
		BaseFee:    big.NewInt(params.InitialBaseFee),
		ExtraData:  append(make([]byte, 32), make([]byte, crypto.SignatureLength)...),
	}
	db := rawdb.NewMemoryDatabase()
	engine := XDPoS.NewFaker(db, cfg)
	chain, err := core.NewBlockChain(db, nil, v2Gspec, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create blockchain: %v", err)
	}
	t.Cleanup(chain.Stop)

	if got := chain.Config().XDPoS.BlockConsensusVersion(chain.CurrentBlock().Number); got != params.ConsensusEngineVersion2 {
		t.Fatalf("test setup needs an active v2 engine, have consensus version %q", got)
	}
	if info := engine.EngineV2.GetLatestCommittedBlockInfo(); info != nil {
		t.Fatalf("test setup needs an engine without committed block info, have %v", info)
	}

	backend := &EthAPIBackend{eth: &Ethereum{blockchain: chain}, XDPoS: engine}
	const wantErr = "no committed block info available yet"

	header, err := backend.HeaderByNumber(context.Background(), rpc.FinalizedBlockNumber)
	if header != nil || err == nil || err.Error() != wantErr {
		t.Fatalf("HeaderByNumber on the finalized tag: have (%v, %v), want (nil, %q)", header, err, wantErr)
	}
	block, err := backend.BlockByNumber(context.Background(), rpc.FinalizedBlockNumber)
	if block != nil || err == nil || err.Error() != wantErr {
		t.Fatalf("BlockByNumber on the finalized tag: have (%v, %v), want (nil, %q)", block, err, wantErr)
	}
}

func makeTx(nonce uint64, gasPrice *big.Int, amount *big.Int, key *ecdsa.PrivateKey) *types.Transaction {
	if gasPrice == nil {
		gasPrice = big.NewInt(params.GWei)
	}
	if amount == nil {
		amount = big.NewInt(1000)
	}
	tx, _ := types.SignTx(types.NewTransaction(nonce, common.Address{0x00}, amount, params.TxGas, gasPrice, nil), signer, key)
	return tx
}

type unsignedAuth struct {
	nonce uint64
	key   *ecdsa.PrivateKey
}

func pricedSetCodeTx(nonce uint64, gaslimit uint64, gasFee, tip *uint256.Int, key *ecdsa.PrivateKey, unsigned []unsignedAuth) *types.Transaction {
	var authList []types.SetCodeAuthorization
	for _, u := range unsigned {
		auth, _ := types.SignSetCode(u.key, types.SetCodeAuthorization{
			ChainID: *uint256.MustFromBig(gspec.Config.ChainID),
			Address: common.Address{0x42},
			Nonce:   u.nonce,
		})
		authList = append(authList, auth)
	}
	return pricedSetCodeTxWithAuth(nonce, gaslimit, gasFee, tip, key, authList)
}

func pricedSetCodeTxWithAuth(nonce uint64, gaslimit uint64, gasFee, tip *uint256.Int, key *ecdsa.PrivateKey, authList []types.SetCodeAuthorization) *types.Transaction {
	return types.MustSignNewTx(key, signer, &types.SetCodeTx{
		ChainID:    uint256.MustFromBig(gspec.Config.ChainID),
		Nonce:      nonce,
		GasTipCap:  tip,
		GasFeeCap:  gasFee,
		Gas:        gaslimit,
		To:         common.Address{},
		Value:      uint256.NewInt(100),
		Data:       nil,
		AccessList: nil,
		AuthList:   authList,
	})
}

func TestSendTx(t *testing.T) {
	testSendTx(t, false)
	testSendTx(t, true)
}

func testSendTx(t *testing.T, withLocal bool) {
	b := initBackend(t, withLocal)

	txA := pricedSetCodeTx(0, 250000, uint256.NewInt(params.GWei), uint256.NewInt(params.GWei), key, []unsignedAuth{{nonce: 0, key: key}})
	if err := b.SendTx(context.Background(), txA); err != nil {
		t.Fatalf("Failed to submit tx: %v", err)
	}
	for {
		pending, _ := b.TxPool().ContentFrom(address)
		if len(pending) == 1 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	txB := makeTx(1, nil, nil, key)
	err := b.SendTx(context.Background(), txB)

	if withLocal {
		if err != nil {
			t.Fatalf("Unexpected error sending tx: %v", err)
		}
	} else {
		if !errors.Is(err, txpool.ErrInflightTxLimitReached) {
			t.Fatalf("Unexpected error, want: %v, got: %v", txpool.ErrInflightTxLimitReached, err)
		}
	}
}

func TestSendTxWithLocalPermanentErrorNotTracked(t *testing.T) {
	b := initBackend(t, true)
	if b.eth.localTxTracker == nil {
		t.Fatal("expected local tx tracker to be configured")
	}
	// Force txpool min tip above tx gas price so submission fails permanently.
	if err := b.TxPool().SetGasTip(big.NewInt(params.GWei + 1)); err != nil {
		t.Fatalf("failed to set gas tip: %v", err)
	}

	tx := makeTx(0, big.NewInt(params.GWei), nil, key)
	err := b.SendTx(context.Background(), tx)
	if !errors.Is(err, txpool.ErrTxGasPriceTooLow) {
		t.Fatalf("unexpected error, want: %v, got: %v", txpool.ErrTxGasPriceTooLow, err)
	}

	tracked := reflect.ValueOf(b.eth.localTxTracker).Elem().FieldByName("all").Len()
	if tracked != 0 {
		t.Fatalf("unexpected tracked tx count: have %d, want 0", tracked)
	}
}

func TestSendTxTracksAlreadyKnown(t *testing.T) {
	b := initBackend(t, true)
	if b.eth.localTxTracker == nil {
		t.Fatal("expected local tx tracker to be configured")
	}
	tx := makeTx(0, nil, nil, key)
	// Simulate the transaction reaching the pool via gossip: a plain pool add
	// does not involve the local tracker.
	if err := b.eth.txPool.Add([]*types.Transaction{tx}, true)[0]; err != nil {
		t.Fatalf("failed to seed the pool with the transaction: %v", err)
	}
	if tracked := reflect.ValueOf(b.eth.localTxTracker).Elem().FieldByName("all").Len(); tracked != 0 {
		t.Fatalf("unexpected tracked tx count before resubmission: have %d, want 0", tracked)
	}
	// Submitting the same transaction locally must report ErrAlreadyKnown to
	// the submitter while still tracking it for the local resubmit flow.
	err := b.SendTx(context.Background(), tx)
	if !errors.Is(err, txpool.ErrAlreadyKnown) {
		t.Fatalf("unexpected error, want: %v, got: %v", txpool.ErrAlreadyKnown, err)
	}
	if tracked := reflect.ValueOf(b.eth.localTxTracker).Elem().FieldByName("all").Len(); tracked != 1 {
		t.Fatalf("unexpected tracked tx count: have %d, want 1", tracked)
	}
}
