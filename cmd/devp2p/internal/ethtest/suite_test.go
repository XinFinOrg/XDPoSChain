package ethtest

import (
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
)

func loadTestSuite(t *testing.T) *Suite {
	t.Helper()
	s, err := NewSuite(nil, "testdata", "", "")
	if err != nil {
		t.Fatalf("expected testdata to load, got error: %v", err)
	}
	return s
}

func TestNewSuiteRequiresChainDir(t *testing.T) {
	_, err := NewSuite(nil, "", "", "")
	if err == nil {
		t.Fatal("expected error when chain directory is empty")
	}
}

func TestNewSuiteLoadsFixtures(t *testing.T) {
	s := loadTestSuite(t)
	if s.chain == nil {
		t.Fatal("expected initialized chain")
	}
	if s.chain.Len() == 0 {
		t.Fatal("expected chain fixtures to include at least genesis block")
	}
}

func TestSignedFixtureTxsBuildsSequentialTransactions(t *testing.T) {
	s := loadTestSuite(t)
	if len(s.chain.senders) == 0 {
		t.Skip("fixture has no sender accounts")
	}

	txs, from, err := s.signedFixtureTxs(2)
	if err != nil {
		t.Fatalf("signedFixtureTxs failed: %v", err)
	}
	if len(txs) != 2 {
		t.Fatalf("wrong tx count: have %d want 2", len(txs))
	}
	if _, ok := s.chain.senders[from]; !ok {
		t.Fatalf("returned sender is not tracked: %s", from)
	}
	_, nonce := s.chain.GetSender(0)
	if txs[0].Nonce() != nonce {
		t.Fatalf("wrong first tx nonce: have %d want %d", txs[0].Nonce(), nonce)
	}
	if txs[1].Nonce() != nonce+1 {
		t.Fatalf("wrong second tx nonce: have %d want %d", txs[1].Nonce(), nonce+1)
	}
	if txs[0].Hash() == txs[1].Hash() {
		t.Fatal("expected distinct signed transactions")
	}
}

func TestSignedFixtureTxsRequiresSenders(t *testing.T) {
	s := loadTestSuite(t)
	s.chain.senders = map[common.Address]*senderInfo{}

	_, _, err := s.signedFixtureTxs(1)
	if err == nil {
		t.Fatal("expected error when no sender accounts are available")
	}
}
