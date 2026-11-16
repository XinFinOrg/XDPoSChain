package legacypool

import (
	"crypto/ecdsa"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// The admission gate and the state check only need the head lookup. The
// embedded interfaces keep every other chain method out of the test.
type stubXDCxChain struct {
	blockChainXDCx
	head *types.Header
}

func (s *stubXDCxChain) CurrentBlock() *types.Header { return s.head }

type stubLendingChain struct {
	blockChainLending
	head *types.Header
}

func (s *stubLendingChain) CurrentBlock() *types.Header { return s.head }

func receiverDisabledConfig() *params.ChainConfig {
	return &params.ChainConfig{
		TIPXDCXBlock:                big.NewInt(0),
		TIPXDCXReceiverDisableBlock: big.NewInt(100),
	}
}

func receiverActiveConfig() *params.ChainConfig {
	return &params.ChainConfig{TIPXDCXBlock: big.NewInt(0)}
}

func newOrderPoolForAdmission(cfg *params.ChainConfig, number int64) *OrderPool {
	return &OrderPool{
		chainconfig: cfg,
		chain:       &stubXDCxChain{head: &types.Header{Number: big.NewInt(number)}},
		signer:      types.OrderTxSigner{},
		all:         make(map[common.Hash]*types.OrderTransaction),
	}
}

func newLendingPoolForAdmission(cfg *params.ChainConfig, number int64) *LendingPool {
	return &LendingPool{
		chainconfig: cfg,
		chain:       &stubLendingChain{head: &types.Header{Number: big.NewInt(number)}},
		signer:      types.LendingTxSigner{},
		all:         make(map[common.Hash]*types.LendingTransaction),
	}
}

func signedOrderTx(t *testing.T, key *ecdsa.PrivateKey) *types.OrderTransaction {
	t.Helper()
	from := crypto.PubkeyToAddress(key.PublicKey)
	tx := types.NewOrderTransaction(0, big.NewInt(1), big.NewInt(1), common.Address{}, from, common.Address{}, common.Address{}, OrderStatusNew, OrderSideBid, OrderTypeLimit, common.Hash{}, 0)
	sig, err := crypto.Sign(types.OrderTxSigner{}.Hash(tx).Bytes(), key)
	if err != nil {
		t.Fatalf("failed to sign order transaction: %v", err)
	}
	signed, err := tx.WithSignature(types.OrderTxSigner{}, sig)
	if err != nil {
		t.Fatalf("failed to attach order signature: %v", err)
	}
	return signed
}

func signedLendingTx(t *testing.T, key *ecdsa.PrivateKey) *types.LendingTransaction {
	t.Helper()
	from := crypto.PubkeyToAddress(key.PublicKey)
	tx := types.NewLendingTransaction(0, big.NewInt(1), 1, 1, common.Address{}, from, common.Address{}, common.Address{}, false, types.LendingStatusNew, types.LendingSideInvest, types.LendingTypeLo, common.Hash{}, 0, 0, "")
	sig, err := crypto.Sign(types.LendingTxSigner{}.Hash(tx).Bytes(), key)
	if err != nil {
		t.Fatalf("failed to sign lending transaction: %v", err)
	}
	signed, err := tx.WithSignature(types.LendingTxSigner{}, sig)
	if err != nil {
		t.Fatalf("failed to attach lending signature: %v", err)
	}
	return signed
}

func TestOrderPoolAddRemotesDropsWhenReceiverDisabled(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	pool := newOrderPoolForAdmission(receiverDisabledConfig(), 200)

	errs := pool.AddRemotes([]*types.OrderTransaction{signedOrderTx(t, key)})
	if len(errs) != 1 || errs[0] != nil {
		t.Fatalf("want one silently dropped transaction, got %v", errs)
	}
	if len(pool.all) != 0 {
		t.Fatalf("pool accepted %d transactions while the receiver fork is off", len(pool.all))
	}
}

func TestLendingPoolAddRemotesDropsWhenReceiverDisabled(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	pool := newLendingPoolForAdmission(receiverDisabledConfig(), 200)

	errs := pool.AddRemotes([]*types.LendingTransaction{signedLendingTx(t, key)})
	if len(errs) != 1 || errs[0] != nil {
		t.Fatalf("want one silently dropped transaction, got %v", errs)
	}
	if len(pool.all) != 0 {
		t.Fatalf("pool accepted %d transactions while the receiver fork is off", len(pool.all))
	}
}

func TestOrderPoolRejectsTransactionWithoutState(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	pool := newOrderPoolForAdmission(receiverActiveConfig(), 200)

	if err := pool.AddRemote(signedOrderTx(t, key)); err != ErrOrderPoolStateNotInitialised {
		t.Fatalf("want %v, got %v", ErrOrderPoolStateNotInitialised, err)
	}
}

func TestLendingPoolRejectsTransactionWithoutState(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	pool := newLendingPoolForAdmission(receiverActiveConfig(), 200)

	if err := pool.AddRemote(signedLendingTx(t, key)); err != ErrLendingPoolStateNotInitialised {
		t.Fatalf("want %v, got %v", ErrLendingPoolStateNotInitialised, err)
	}
}

func TestOrderPoolAddRemotesRejectsWithoutState(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	pool := newOrderPoolForAdmission(receiverActiveConfig(), 200)

	errs := pool.AddRemotes([]*types.OrderTransaction{signedOrderTx(t, key)})
	if len(errs) != 1 || errs[0] != ErrOrderPoolStateNotInitialised {
		t.Fatalf("want %v, got %v", ErrOrderPoolStateNotInitialised, errs)
	}
	if len(pool.all) != 0 {
		t.Fatalf("pool accepted %d transactions without state", len(pool.all))
	}
}

func TestLendingPoolAddRemotesRejectsWithoutState(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	pool := newLendingPoolForAdmission(receiverActiveConfig(), 200)

	errs := pool.AddRemotes([]*types.LendingTransaction{signedLendingTx(t, key)})
	if len(errs) != 1 || errs[0] != ErrLendingPoolStateNotInitialised {
		t.Fatalf("want %v, got %v", ErrLendingPoolStateNotInitialised, errs)
	}
	if len(pool.all) != 0 {
		t.Fatalf("pool accepted %d transactions without state", len(pool.all))
	}
}
