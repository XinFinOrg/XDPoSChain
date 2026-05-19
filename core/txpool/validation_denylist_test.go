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

// newValidationStateOpts builds a signed transaction and state-backed
// validation options for denylist tests.
func newValidationStateOpts(t *testing.T, cfg *params.ChainConfig, number *big.Int) (*types.Transaction, types.Signer, *ValidationOptionsWithState) {
	t.Helper()

	var (
		statedb *state.StateDB
		err     error
	)
	if cfg != nil {
		statedb, err = state.NewWithChainConfig(types.EmptyRootHash, state.NewDatabase(rawdb.NewMemoryDatabase()), cfg)
	} else {
		statedb, err = state.New(types.EmptyRootHash, state.NewDatabase(rawdb.NewMemoryDatabase()))
	}
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

// TestValidateTransactionWithStateDenylistHardForkBoundaries tests validate transaction with state denylist hard fork boundaries.
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

	t.Run("missing state returns explicit error", func(t *testing.T) {
		tx, signer, opts := newValidationStateOpts(t, cfg, big.NewInt(100))
		opts.State = nil
		err := ValidateTransactionWithState(tx, signer, opts)
		if err == nil || err.Error() != "state: missing StateDB for chain config attachment" {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("state without attached chain config is rejected", func(t *testing.T) {
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

		gasPrice := new(big.Int).Mul(new(big.Int).Set(common.MinGasPrice), big.NewInt(10))
		tx, err := types.SignTx(
			types.NewTransaction(0, common.HexToAddress("0x00000000000000000000000000000000000000b1"), big.NewInt(1), params.TxGas, gasPrice, nil),
			types.HomesteadSigner{},
			key,
		)
		if err != nil {
			t.Fatalf("failed to sign tx: %v", err)
		}

		err = ValidateTransactionWithState(tx, types.HomesteadSigner{}, &ValidationOptionsWithState{
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
				return big.NewInt(99)
			},
		})
		if err == nil || err.Error() != "state: missing chain config for state access" {
			t.Fatalf("unexpected error: %v", err)
		}
		if statedb.ChainConfig() != nil {
			t.Fatal("expected validation to leave state chain config untouched")
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

// TestValidateTransactionRejectsMissingChainConfig tests validate transaction rejects missing chain config.
func TestValidateTransactionRejectsMissingChainConfig(t *testing.T) {
	tx, signer, _ := newValidationStateOpts(t, &params.ChainConfig{DenylistBlock: big.NewInt(100)}, big.NewInt(100))
	head := &types.Header{Number: big.NewInt(100), GasLimit: params.GenesisGasLimit}

	err := ValidateTransaction(tx, head, signer, &ValidationOptions{
		Config:  nil,
		Accept:  1 << types.LegacyTxType,
		MaxSize: tx.Size(),
		MinTip:  big.NewInt(0),
		NotSigner: func(common.Address) bool {
			return false
		},
	})
	if err == nil {
		t.Fatal("expected missing chain config error")
	}
	if err != ErrMissingChainConfig {
		t.Fatalf("unexpected error: have %v want %v", err, ErrMissingChainConfig)
	}
}
