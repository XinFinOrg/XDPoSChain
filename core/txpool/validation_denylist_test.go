package txpool

import (
	"math/big"
	"strings"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/tracing"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/params"
)

func newValidationStateOpts(t *testing.T, cfg *params.ChainConfig, number *big.Int) (*types.Transaction, types.Signer, *ValidationOptionsWithState) {
	t.Helper()

	statedb, err := state.New(types.EmptyRootHash, state.NewDatabase(rawdb.NewMemoryDatabase()))
	if err != nil {
		t.Fatalf("failed to create state: %v", err)
	}

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	from := crypto.PubkeyToAddress(key.PublicKey)
	statedb.AddBalance(from, new(big.Int).Mul(big.NewInt(1_000_000), big.NewInt(params.Ether)), tracing.BalanceChangeUnspecified)

	denylistedReceiver := common.HexToAddress("0x5248bfb72fd4f234e062d3e9bb76f08643004fcd")
	gasPrice := new(big.Int).Mul(new(big.Int).Set(common.MinGasPrice), big.NewInt(10))
	tx, err := types.SignTx(
		types.NewTransaction(0, denylistedReceiver, big.NewInt(1), params.TxGas, gasPrice, nil),
		types.HomesteadSigner{},
		key,
	)
	if err != nil {
		t.Fatalf("failed to sign tx: %v", err)
	}

	opts := &ValidationOptionsWithState{
		Config: cfg,
		State:  statedb,
		ExistingExpenditure: func(common.Address) *big.Int {
			return new(big.Int)
		},
		ExistingCost: func(common.Address, uint64) *big.Int {
			return nil
		},
		PendingNonce: func(common.Address) uint64 {
			return 0
		},
		CurrentNumber: func() *big.Int {
			return number
		},
	}

	return tx, types.HomesteadSigner{}, opts
}

func TestValidateTransactionWithStateDenylistHardForkBoundaries(t *testing.T) {
	cfg := &params.ChainConfig{DenylistBlock: big.NewInt(100), Gas50xBlock: big.NewInt(1000)}

	t.Run("missing chain config returns explicit error", func(t *testing.T) {
		tx, signer, opts := newValidationStateOpts(t, nil, big.NewInt(100))
		opts.Config = nil
		err := ValidateTransactionWithState(tx, signer, opts)
		if err == nil {
			t.Fatal("expected missing chain config error")
		}
		if err != ErrMissingChainConfig {
			t.Fatalf("unexpected error: have %v want %v", err, ErrMissingChainConfig)
		}
	})

	t.Run("below hard fork allows denylisted receiver", func(t *testing.T) {
		tx, signer, opts := newValidationStateOpts(t, cfg, big.NewInt(99))
		if err := ValidateTransactionWithState(tx, signer, opts); err != nil {
			t.Fatalf("unexpected error below hard fork: %v", err)
		}
	})

	t.Run("at hard fork rejects denylisted receiver", func(t *testing.T) {
		tx, signer, opts := newValidationStateOpts(t, cfg, big.NewInt(100))
		err := ValidateTransactionWithState(tx, signer, opts)
		if err == nil {
			t.Fatal("expected denylist error at hard fork")
		}
		if !strings.Contains(err.Error(), "receiver in denylist") {
			t.Fatalf("unexpected error at hard fork: %v", err)
		}
	})

	t.Run("above hard fork rejects denylisted receiver", func(t *testing.T) {
		tx, signer, opts := newValidationStateOpts(t, cfg, big.NewInt(101))
		err := ValidateTransactionWithState(tx, signer, opts)
		if err == nil {
			t.Fatal("expected denylist error above hard fork")
		}
		if !strings.Contains(err.Error(), "receiver in denylist") {
			t.Fatalf("unexpected error above hard fork: %v", err)
		}
	})
}
