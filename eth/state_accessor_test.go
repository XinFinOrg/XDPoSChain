package eth

import (
	"context"
	"math/big"
	"strings"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// TestStateAtBlockPropagatesChainConfigToReconstructedState tests state at block propagates chain config to reconstructed state.
func TestStateAtBlockPropagatesChainConfigToReconstructedState(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	engine := ethash.NewFaker()
	genesis := &core.Genesis{
		Config: params.TestChainConfig,
		Alloc: types.GenesisAlloc{
			testBank: {Balance: big.NewInt(1)},
		},
		Difficulty: big.NewInt(1),
	}
	chain, err := core.NewBlockChain(db, nil, genesis, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create blockchain: %v", err)
	}
	defer chain.Stop()

	eth := &Ethereum{blockchain: chain, chainDb: db}
	block := chain.GetBlockByNumber(chain.CurrentBlock().Number.Uint64())
	if block == nil {
		t.Fatal("expected current block")
	}
	statedb, release, err := eth.StateAtBlock(context.Background(), block, 0, nil, false, false)
	if release != nil {
		defer release()
	}
	if err != nil {
		t.Fatalf("StateAtBlock failed: %v", err)
	}
	if statedb == nil {
		t.Fatal("expected reconstructed state")
	}
	if statedb.ChainConfig() != chain.Config() {
		t.Fatalf("unexpected chain config on reconstructed state: have %p want %p", statedb.ChainConfig(), chain.Config())
	}
}

// TestStateAtTransactionReturnsTransactionToMessageError tests state at transaction returns transaction to message error.
func TestStateAtTransactionReturnsTransactionToMessageError(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	engine := ethash.NewFaker()
	token := common.HexToAddress("0x00000000000000000000000000000000000000aa")
	issuer := common.HexToAddress("0x00000000000000000000000000000000000000bb")
	config := params.TestChainConfig.Clone()
	config.Gas50xBlock = big.NewInt(1_000_000_000)
	config.TRC21IssuerSMC = issuer
	feeCapacity := new(big.Int).Mul(new(big.Int).SetUint64(params.TxGas), common.TRC21GasPrice)
	slotTokensHash := common.BigToHash(new(big.Int).SetUint64(state.SlotTRC21Issuer["tokens"]))
	tokenSlot := state.GetLocDynamicArrAtElement(slotTokensHash, 0, 1)
	tokenStateSlot := common.BigToHash(state.GetLocMappingAtKey(token.Hash(), state.SlotTRC21Issuer["tokensState"]))

	genesis := &core.Genesis{
		Config: config,
		Alloc: types.GenesisAlloc{
			testBank: {Balance: new(big.Int).Mul(big.NewInt(params.Ether), big.NewInt(2))},
			issuer: {
				Balance: new(big.Int).Set(feeCapacity),
				Storage: map[common.Hash]common.Hash{
					slotTokensHash: common.BigToHash(big.NewInt(1)),
					tokenSlot:      common.BytesToHash(token.Bytes()),
					tokenStateSlot: common.BigToHash(feeCapacity),
				},
			},
			token: {Balance: big.NewInt(0)},
		},
		Difficulty: big.NewInt(1),
	}

	chain, err := core.NewBlockChain(db, nil, genesis, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create blockchain: %v", err)
	}
	defer chain.Stop()

	_, blocks, _ := core.GenerateChainWithGenesis(genesis, engine, 1, func(i int, b *core.BlockGen) {
		tx0, err := types.SignTx(types.NewTx(&types.LegacyTx{
			Nonce:    0,
			To:       &token,
			Value:    big.NewInt(0),
			Gas:      params.TxGas,
			GasPrice: b.BaseFee(),
		}), types.HomesteadSigner{}, testBankKey)
		if err != nil {
			t.Fatalf("failed to sign first tx: %v", err)
		}
		b.AddTx(tx0)

		tx1, err := types.SignTx(types.NewTx(&types.LegacyTx{
			Nonce:    1,
			To:       &testBank,
			Value:    big.NewInt(0),
			Gas:      params.TxGas,
			GasPrice: b.BaseFee(),
		}), types.HomesteadSigner{}, testBankKey)
		if err != nil {
			t.Fatalf("failed to sign second tx: %v", err)
		}
		b.AddTx(tx1)
	})
	if _, err := chain.InsertChain(blocks); err != nil {
		t.Fatalf("failed to insert chain: %v", err)
	}

	eth := &Ethereum{blockchain: chain, chainDb: db}
	chain.Config().TIPTRC21FeeBlock = nil

	block := chain.GetBlockByNumber(1)
	if block == nil {
		t.Fatal("expected block #1")
	}
	_, _, _, _, err = eth.stateAtTransaction(context.Background(), block, 1, 0)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "missing TIPTRC21FeeBlock") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestStateAtTransactionWithoutTRC21Issuer tests state at transaction without trc 21 issuer.
func TestStateAtTransactionWithoutTRC21Issuer(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	engine := ethash.NewFaker()
	recipient := common.HexToAddress("0x00000000000000000000000000000000000000aa")
	config := &params.ChainConfig{
		ChainID:        big.NewInt(1338),
		HomesteadBlock: new(big.Int),
		Ethash:         new(params.EthashConfig),
	}
	genesis := &core.Genesis{
		Config: config,
		Alloc: types.GenesisAlloc{
			testBank:  {Balance: new(big.Int).Mul(big.NewInt(params.Ether), big.NewInt(2))},
			recipient: {Balance: big.NewInt(0)},
		},
		Difficulty: big.NewInt(1),
	}

	chain, err := core.NewBlockChain(db, nil, genesis, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create blockchain: %v", err)
	}
	defer chain.Stop()

	var wantTxHash common.Hash
	_, blocks, _ := core.GenerateChainWithGenesis(genesis, engine, 1, func(i int, b *core.BlockGen) {
		for nonce := uint64(0); nonce < 2; nonce++ {
			tx, err := types.SignTx(types.NewTransaction(nonce, recipient, big.NewInt(1), params.TxGas, b.BaseFee(), nil), types.HomesteadSigner{}, testBankKey)
			if err != nil {
				t.Fatalf("failed to sign tx %d: %v", nonce, err)
			}
			b.AddTx(tx)
			if nonce == 1 {
				wantTxHash = tx.Hash()
			}
		}
	})
	if _, err := chain.InsertChain(blocks); err != nil {
		t.Fatalf("failed to insert chain: %v", err)
	}

	eth := &Ethereum{blockchain: chain, chainDb: db}
	block := chain.GetBlockByNumber(1)
	if block == nil {
		t.Fatal("expected block #1")
	}

	tx, _, statedb, release, err := eth.stateAtTransaction(context.Background(), block, 1, 0)
	if release != nil {
		defer release()
	}
	if err != nil {
		t.Fatalf("stateAtTransaction failed: %v", err)
	}
	if tx == nil {
		t.Fatal("expected transaction")
	}
	if tx.Hash() != wantTxHash {
		t.Fatalf("unexpected transaction hash: have %s want %s", tx.Hash(), wantTxHash)
	}
	if statedb == nil {
		t.Fatal("expected statedb")
	}
	if statedb.ChainConfig() != chain.Config() {
		t.Fatalf("unexpected chain config on state: have %p want %p", statedb.ChainConfig(), chain.Config())
	}
}

// TestStateAtTransactionGiveUpReturnsNoState pins the return contract of the give-up
// paths of stateAtTransaction: once the parent state has been obtained, a path that gives
// up must not hand the state or the release function back to the caller. Every caller
// returns on the error before reaching its deferred release, so a release function handed
// back on a give-up path would simply be dropped.
//
// The requested index is out of range, so the replay of the block's transactions runs to
// the end and the function gives up afterwards, with the parent state already in hand:
// nothing half-initialised may be handed back to the caller.
//
// Note: whether the release function is actually invoked is not observable from here. The
// reference is taken inside StateAtBlock (its readOnly path) and neither the live trie
// database nor the ephemeral one exposes its reference count, so this test cannot tell a
// released state from a leaked one: the release is guaranteed by the deferred guard in
// stateAtTransaction, not by the assertions below.
func TestStateAtTransactionGiveUpReturnsNoState(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	engine := ethash.NewFaker()
	// TIPXDCXBlock is 0 and TIPXDCXReceiverDisableBlock is nil: the receiver fork is
	// active from genesis.
	config := params.TestChainConfig.Clone()
	recipient := common.HexToAddress("0x00000000000000000000000000000000deadbeef")
	genesis := &core.Genesis{
		Config: config,
		Alloc: types.GenesisAlloc{
			testBank: {Balance: new(big.Int).Mul(big.NewInt(params.Ether), big.NewInt(2))},
		},
		Difficulty: big.NewInt(1),
	}

	chain, err := core.NewBlockChain(db, nil, genesis, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create blockchain: %v", err)
	}
	defer chain.Stop()

	signer := types.MakeSigner(config, common.Big1)
	_, blocks, _ := core.GenerateChainWithGenesis(genesis, engine, 1, func(i int, b *core.BlockGen) {
		tx, err := types.SignTx(types.NewTx(&types.LegacyTx{
			Nonce:    0,
			To:       &recipient,
			Value:    big.NewInt(1),
			Gas:      params.TxGas,
			GasPrice: b.BaseFee(),
		}), signer, testBankKey)
		if err != nil {
			t.Fatalf("failed to sign the transaction: %v", err)
		}
		b.AddTx(tx)
	})
	if _, err := chain.InsertChain(blocks); err != nil {
		t.Fatalf("failed to insert chain: %v", err)
	}

	eth := &Ethereum{blockchain: chain, chainDb: db}
	block := chain.GetBlockByNumber(1)
	if block == nil {
		t.Fatal("expected block #1")
	}
	outOfRange := len(block.Transactions()) + 1
	tx, _, statedb, release, err := eth.stateAtTransaction(context.Background(), block, outOfRange, 0)
	if err == nil {
		t.Fatalf("expected an error for the out of range transaction index %d", outOfRange)
	}
	if tx != nil || statedb != nil || release != nil {
		t.Fatalf("expected no transaction, state or release on the error path, got tx=%v state=%v release=%v", tx, statedb, release)
	}
}

// TestStateAtTransactionReplayKeepsNonceLessSenderNonce verifies that replaying a
// transaction sent to an XDCX system address goes through ApplyTransactionForReplay:
// while the receiver fork is active it is handled by ApplyEmptyTransaction and must
// not increment the sender nonce, so that a following transaction reusing the same
// nonce still replays (Apothem block 0x2e69c13, issue gzliudan/XDPoSChain#256).
func TestStateAtTransactionReplayKeepsNonceLessSenderNonce(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	engine := ethash.NewFaker()
	config := *params.TestChainConfig // TIPXDCXBlock is 0: the receiver fork is active from genesis
	config.TIPXDCXReceiverDisableBlock = nil
	tradingState := common.TradingStateAddrBinary
	recipient := common.HexToAddress("0x00000000000000000000000000000000deadbeef")
	genesis := &core.Genesis{
		Config: &config,
		Alloc: types.GenesisAlloc{
			testBank: {Balance: new(big.Int).Mul(big.NewInt(params.Ether), big.NewInt(2))},
		},
		Difficulty: big.NewInt(1),
	}

	chain, err := core.NewBlockChain(db, nil, genesis, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create blockchain: %v", err)
	}
	defer chain.Stop()

	signer := types.MakeSigner(&config, common.Big1)
	var wantTxHash common.Hash
	_, blocks, _ := core.GenerateChainWithGenesis(genesis, engine, 1, func(i int, b *core.BlockGen) {
		// While the XDCX receiver fork is active this transaction is handled by
		// ApplyEmptyTransaction and leaves the sender nonce at 0.
		tx0, err := types.SignTx(types.NewTx(&types.LegacyTx{
			Nonce:    0,
			To:       &tradingState,
			Value:    big.NewInt(0),
			Gas:      params.TxGas,
			GasPrice: b.BaseFee(),
		}), signer, testBankKey)
		if err != nil {
			t.Fatalf("failed to sign first tx: %v", err)
		}
		b.AddTx(tx0)

		// The sender reuses nonce 0.
		tx1, err := types.SignTx(types.NewTx(&types.LegacyTx{
			Nonce:    0,
			To:       &recipient,
			Value:    big.NewInt(0),
			Gas:      params.TxGas,
			GasPrice: b.BaseFee(),
		}), signer, testBankKey)
		if err != nil {
			t.Fatalf("failed to sign second tx: %v", err)
		}
		b.AddTx(tx1)
		wantTxHash = tx1.Hash()
	})
	if _, err := chain.InsertChain(blocks); err != nil {
		t.Fatalf("failed to insert chain: %v", err)
	}

	eth := &Ethereum{blockchain: chain, chainDb: db}
	block := chain.GetBlockByNumber(1)
	if block == nil {
		t.Fatal("expected block #1")
	}
	tx, _, statedb, release, err := eth.stateAtTransaction(context.Background(), block, 1, 0)
	if release != nil {
		defer release()
	}
	if err != nil {
		t.Fatalf("stateAtTransaction failed: %v", err)
	}
	if tx == nil || tx.Hash() != wantTxHash {
		t.Fatalf("unexpected transaction: %v", tx)
	}
	if statedb == nil {
		t.Fatal("expected statedb")
	}
	// Replaying the first transaction must leave the nonce untouched: bumping it
	// makes the second transaction fail with "nonce too low" downstream.
	if got := statedb.GetNonce(testBank); got != 0 {
		t.Fatalf("sender nonce after replay = %d, want 0", got)
	}
}
