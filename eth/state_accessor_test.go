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
