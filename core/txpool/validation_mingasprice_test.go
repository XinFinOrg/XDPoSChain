package txpool

import (
	"errors"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/tracing"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// TestValidateTransactionWithStateTRC21CostSchedule checks that the TRC21 fee
// capacity check prices a pending tx with the next block's gas schedule.
func TestValidateTransactionWithStateTRC21CostSchedule(t *testing.T) {
	cfg := &params.ChainConfig{Gas50xBlock: big.NewInt(100), Gas2500xBlock: big.NewInt(200)}

	token := common.HexToAddress("0x00000000000000000000000000000000000000cc")
	// Fee capacity that exactly covers the transaction at the Gas50x tier.
	gas50xCapacity := new(big.Int).Mul(
		new(big.Int).Mul(common.TRC21GasPrice, big.NewInt(50)),
		new(big.Int).SetUint64(params.TxGas),
	)

	for _, tc := range []struct {
		name    string
		number  *big.Int
		wantErr error
	}{
		{name: "gas50x capacity accepted before gas2500x boundary", number: big.NewInt(198)},
		{name: "gas50x capacity rejected when next block reaches gas2500x", number: big.NewInt(199), wantErr: core.ErrInsufficientFunds},
	} {
		t.Run(tc.name, func(t *testing.T) {
			statedb, err := state.NewWithChainConfig(types.EmptyRootHash, state.NewDatabase(rawdb.NewMemoryDatabase()), cfg)
			if err != nil {
				t.Fatalf("failed to create state: %v", err)
			}
			key, err := crypto.GenerateKey()
			if err != nil {
				t.Fatalf("failed to generate key: %v", err)
			}

			// The sender is left without native balance so that the TRC21 fee
			// capacity alone decides the outcome.
			tx, err := types.SignTx(
				types.NewTransaction(0, token, big.NewInt(0), params.TxGas, big.NewInt(common.DefaultMinGasPrice*1000), []byte{0x01, 0x02, 0x03, 0x04}),
				types.HomesteadSigner{},
				key,
			)
			if err != nil {
				t.Fatalf("failed to sign tx: %v", err)
			}

			opts := &ValidationOptionsWithState{
				Config:              cfg,
				State:               statedb,
				Trc21FeeCapacity:    map[common.Address]*big.Int{token: gas50xCapacity},
				ExistingExpenditure: func(common.Address) *big.Int { return new(big.Int) },
				ExistingCost:        func(common.Address, uint64) *big.Int { return nil },
				PendingNonce:        func(common.Address) uint64 { return 0 },
				CurrentNumber:       func() *big.Int { return tc.number },
			}

			err = ValidateTransactionWithState(tx, types.HomesteadSigner{}, opts)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("unexpected error: have %v want %v", err, tc.wantErr)
			}
		})
	}
}

// TestValidateTransactionWithStateMinGasPriceSchedule checks that the pool
// admission floor for pending txs follows the next block's gas schedule.
func TestValidateTransactionWithStateMinGasPriceSchedule(t *testing.T) {
	cfg := &params.ChainConfig{Gas50xBlock: big.NewInt(100), Gas2500xBlock: big.NewInt(200)}

	gas50xPrice := big.NewInt(common.DefaultMinGasPrice * 50)
	gas2500xPrice := big.NewInt(common.DefaultMinGasPrice * 2500)

	for _, tc := range []struct {
		name     string
		number   *big.Int
		gasPrice *big.Int
		wantErr  error
	}{
		{name: "gas50x floor accepted before gas2500x boundary", number: big.NewInt(198), gasPrice: gas50xPrice},
		{name: "gas50x floor rejected when next block reaches gas2500x", number: big.NewInt(199), gasPrice: gas50xPrice, wantErr: ErrUnderMinGasPrice},
		{name: "gas2500x floor accepted at gas2500x", number: big.NewInt(200), gasPrice: gas2500xPrice},
	} {
		t.Run(tc.name, func(t *testing.T) {
			statedb, err := state.NewWithChainConfig(types.EmptyRootHash, state.NewDatabase(rawdb.NewMemoryDatabase()), cfg)
			if err != nil {
				t.Fatalf("failed to create state: %v", err)
			}
			key, err := crypto.GenerateKey()
			if err != nil {
				t.Fatalf("failed to generate key: %v", err)
			}
			from := crypto.PubkeyToAddress(key.PublicKey)
			statedb.AddBalance(from, new(big.Int).Mul(big.NewInt(1_000_000), big.NewInt(params.Ether)), tracing.BalanceChangeUnspecified)

			tx, err := types.SignTx(
				types.NewTransaction(0, common.HexToAddress("0x1234"), big.NewInt(1), params.TxGas, tc.gasPrice, nil),
				types.HomesteadSigner{},
				key,
			)
			if err != nil {
				t.Fatalf("failed to sign tx: %v", err)
			}

			opts := &ValidationOptionsWithState{
				Config:              cfg,
				State:               statedb,
				ExistingExpenditure: func(common.Address) *big.Int { return new(big.Int) },
				ExistingCost:        func(common.Address, uint64) *big.Int { return nil },
				PendingNonce:        func(common.Address) uint64 { return 0 },
				CurrentNumber:       func() *big.Int { return tc.number },
			}

			err = ValidateTransactionWithState(tx, types.HomesteadSigner{}, opts)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err != tc.wantErr {
				t.Fatalf("unexpected error: have %v want %v", err, tc.wantErr)
			}
		})
	}
}
