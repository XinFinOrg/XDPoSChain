package ethtest

import (
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
)

// TestCompareReceivedTxs verifies the announcement comparison splits received
// hashes into present and missing transactions.
func TestCompareReceivedTxs(t *testing.T) {
	s := loadTestSuite(t)
	if len(s.chain.senders) == 0 {
		t.Skip("fixture has no sender accounts")
	}
	txs, _, err := s.signedFixtureTxs(2)
	if err != nil {
		t.Fatalf("signedFixtureTxs failed: %v", err)
	}
	received := []common.Hash{txs[0].Hash()}

	present, missing := compareReceivedTxs(received, txs)
	if len(present) != 1 || present[0].Hash() != txs[0].Hash() {
		t.Fatalf("wrong present set: have %v", present)
	}
	if len(missing) != 1 || missing[0].Hash() != txs[1].Hash() {
		t.Fatalf("wrong missing set: have %v", missing)
	}
}

// TestInvalidTxGeneratorsBuild verifies the oversized-transaction generators
// produce signed transactions, and that the stale-nonce generator reports the
// consumed-nonce prerequisite faithfully.
func TestInvalidTxGeneratorsBuild(t *testing.T) {
	s := loadTestSuite(t)
	if len(s.chain.senders) == 0 {
		t.Skip("fixture has no sender accounts")
	}
	for name, build := range map[string]func() (*types.Transaction, bool){
		"hugeAmount":   s.hugeAmountTx,
		"hugeGasPrice": s.hugeGasPriceTx,
		"hugeData":     s.hugeDataTx,
	} {
		tx, ok := build()
		if !ok {
			t.Fatalf("%s: expected generator to build a signed transaction", name)
		}
		if tx == nil || tx.Hash() == (common.Hash{}) {
			t.Fatalf("%s: built transaction is empty", name)
		}
	}
	_, nonce := s.chain.GetSender(0)
	if _, ok := s.invalidNonceTx(); ok != (nonce >= 2) {
		t.Fatalf("stale nonce generator ok=%v, want %v for tracked nonce %d", ok, nonce >= 2, nonce)
	}
}

// TestOldChainTxFindsIncludedTx verifies the already-included transaction
// search only returns transactions from blocks below the fixture head.
func TestOldChainTxFindsIncludedTx(t *testing.T) {
	s := loadTestSuite(t)
	tx, ok := s.oldChainTx()
	if !ok {
		t.Log("fixture blocks below head carry no transactions")
		return
	}
	for _, block := range s.chain.blocks[:s.chain.Len()-1] {
		for _, included := range block.Transactions() {
			if included.Hash() == tx.Hash() {
				return
			}
		}
	}
	t.Fatalf("returned tx %v is not included below head", tx.Hash())
}
