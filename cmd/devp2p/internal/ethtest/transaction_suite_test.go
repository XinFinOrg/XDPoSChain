package ethtest

import (
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
)

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

func TestGenerateTxsClearsChainGasFloor(t *testing.T) {
	for _, tc := range []struct {
		name       string
		dir        string
		multiplier int64
	}{
		{"baseline", "testdata", 1},
		{"gas2500x", xdcFixtureDir, 2500},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := NewSuite(nil, tc.dir, "", "")
			if err != nil {
				t.Fatalf("failed to load suite: %v", err)
			}
			pending := new(big.Int).Add(s.chain.Head().Number(), common.Big1)
			floor := params.GetMinGasPrice(pending, s.chain.config)
			want := new(big.Int).Mul(big.NewInt(common.DefaultMinGasPrice), big.NewInt(tc.multiplier))
			if floor.Cmp(want) != 0 {
				t.Fatalf("chain floor: have %v want %v", floor, want)
			}
			numTxs := 4
			hashMap, txs, err := s.generateTxs(numTxs)
			if err != nil {
				t.Fatalf("generateTxs failed: %v", err)
			}
			if len(txs) != numTxs || len(hashMap) != numTxs {
				t.Fatalf("unexpected batch size: %d txs, %d hashes", len(txs), len(hashMap))
			}
			_, nonce := s.chain.GetSender(0)
			for i, tx := range txs {
				if tx.GasPriceIntCmp(floor) != 0 {
					t.Fatalf("tx %d gas price %v, want chain floor %v", i, tx.GasPrice(), floor)
				}
				if tx.Nonce() != nonce+uint64(i) {
					t.Fatalf("tx %d nonce %d, want %d", i, tx.Nonce(), nonce+uint64(i))
				}
				if hashMap[tx.Hash()] != tx.Hash() {
					t.Fatalf("tx %d hash missing from map", i)
				}
			}
		})
	}
}

func TestChainGasPriceFloorUsesPendingNumber(t *testing.T) {
	for _, tc := range []struct {
		name       string
		fork       int64
		multiplier int64
	}{
		{"fork at pending", 601, 2500},
		{"fork after pending", 602, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Suite{chain: &Chain{
				config: &params.ChainConfig{Gas2500xBlock: big.NewInt(tc.fork)},
				blocks: []*types.Block{types.NewBlockWithHeader(&types.Header{Number: big.NewInt(600)})},
			}}
			want := new(big.Int).Mul(big.NewInt(common.DefaultMinGasPrice), big.NewInt(tc.multiplier))
			if floor := s.chainGasPriceFloor(); floor.Cmp(want) != 0 {
				t.Fatalf("chain floor: have %v want %v", floor, want)
			}
		})
	}
}

// Only blocks below the head count as already included
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
