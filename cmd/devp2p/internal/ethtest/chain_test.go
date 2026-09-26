package ethtest

import (
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
)

func TestChainGetSenderAndNonce(t *testing.T) {
	chain, err := NewChain("testdata")
	if err != nil {
		t.Fatalf("failed to load chain fixtures: %v", err)
	}
	if len(chain.senders) == 0 {
		t.Skip("fixture has no sender accounts")
	}

	addr, nonce := chain.GetSender(0)
	if _, ok := chain.senders[addr]; !ok {
		t.Fatalf("returned address is not a known sender: %s", addr)
	}
	if nonce != chain.senders[addr].Nonce {
		t.Fatalf("wrong sender nonce: have %d want %d", nonce, chain.senders[addr].Nonce)
	}
}

func TestChainIncNonce(t *testing.T) {
	chain, err := NewChain("testdata")
	if err != nil {
		t.Fatalf("failed to load chain fixtures: %v", err)
	}
	if len(chain.senders) == 0 {
		t.Skip("fixture has no sender accounts")
	}

	addr, nonce := chain.GetSender(0)
	chain.IncNonce(addr, 2)
	if got := chain.senders[addr].Nonce; got != nonce+2 {
		t.Fatalf("nonce not incremented correctly: have %d want %d", got, nonce+2)
	}
}

func TestChainBalanceKnownAndUnknown(t *testing.T) {
	chain, err := NewChain("testdata")
	if err != nil {
		t.Fatalf("failed to load chain fixtures: %v", err)
	}

	if len(chain.senders) > 0 {
		addr, _ := chain.GetSender(0)
		bal := chain.Balance(addr)
		if bal.Sign() < 0 {
			t.Fatalf("unexpected negative balance: %s", bal)
		}
	}
	unknown := common.HexToAddress("0x00000000000000000000000000000000000000aa")
	if got := chain.Balance(unknown); got.Sign() != 0 {
		t.Fatalf("unknown account balance should be zero, have %s", got)
	}
}

func TestChainSignTx(t *testing.T) {
	chain, err := NewChain("testdata")
	if err != nil {
		t.Fatalf("failed to load chain fixtures: %v", err)
	}
	if len(chain.senders) == 0 {
		t.Skip("fixture has no sender accounts")
	}

	from, nonce := chain.GetSender(0)
	to := common.HexToAddress("0x00000000000000000000000000000000000000aa")
	unsigned := types.NewTransaction(nonce, to, big.NewInt(1), 21000, big.NewInt(1), nil)
	signed, err := chain.SignTx(from, unsigned)
	if err != nil {
		t.Fatalf("failed to sign transaction: %v", err)
	}
	if signed.Hash() == (common.Hash{}) {
		t.Fatal("signed transaction hash must not be empty")
	}
}

func TestChainSignTxUnknownSender(t *testing.T) {
	chain, err := NewChain("testdata")
	if err != nil {
		t.Fatalf("failed to load chain fixtures: %v", err)
	}
	unknown := common.HexToAddress("0x00000000000000000000000000000000000000bb")
	to := common.HexToAddress("0x00000000000000000000000000000000000000aa")
	unsigned := types.NewTransaction(0, to, big.NewInt(1), 21000, big.NewInt(1), nil)
	_, err = chain.SignTx(unknown, unsigned)
	if err == nil {
		t.Fatal("expected signing error for unknown sender")
	}
}

func TestChainGetHeadersRejectsZeroAmount(t *testing.T) {
	chain, err := NewChain("testdata")
	if err != nil {
		t.Fatalf("failed to load chain fixtures: %v", err)
	}
	_, err = chain.GetHeaders(&getBlockHeadersData{Amount: 0})
	if err == nil {
		t.Fatal("expected error for zero header amount")
	}
}

func TestChainGetHeadersByNumber(t *testing.T) {
	chain, err := NewChain("testdata")
	if err != nil {
		t.Fatalf("failed to load chain fixtures: %v", err)
	}
	headers, err := chain.GetHeaders(&getBlockHeadersData{Origin: hashOrNumber{Number: 0}, Amount: 1})
	if err != nil {
		t.Fatalf("unexpected get headers error: %v", err)
	}
	if len(headers) != 1 {
		t.Fatalf("wrong header count: have %d want 1", len(headers))
	}
	if headers[0].Number.Uint64() != 0 {
		t.Fatalf("wrong header number: have %d want 0", headers[0].Number.Uint64())
	}
}

func TestChainGetHeadersByHash(t *testing.T) {
	chain, err := NewChain("testdata")
	if err != nil {
		t.Fatalf("failed to load chain fixtures: %v", err)
	}
	headers, err := chain.GetHeaders(&getBlockHeadersData{Origin: hashOrNumber{Hash: chain.blocks[0].Hash()}, Amount: 1})
	if err != nil {
		t.Fatalf("unexpected get headers by hash error: %v", err)
	}
	if len(headers) != 1 {
		t.Fatalf("wrong header count by hash: have %d want 1", len(headers))
	}
	if headers[0].Hash() != chain.blocks[0].Header().Hash() {
		t.Fatalf("wrong header hash by origin: have %x want %x", headers[0].Hash(), chain.blocks[0].Header().Hash())
	}
}

func TestChainGetHeadersNonexistentOrigin(t *testing.T) {
	chain, err := NewChain("testdata")
	if err != nil {
		t.Fatalf("failed to load chain fixtures: %v", err)
	}
	_, err = chain.GetHeaders(&getBlockHeadersData{
		Origin: hashOrNumber{Number: ^uint64(0)},
		Amount: 1,
	})
	if err == nil {
		t.Fatal("expected error for nonexistent header origin")
	}
}

func TestChainGetHeadersNonexistentHashOrigin(t *testing.T) {
	chain, err := NewChain("testdata")
	if err != nil {
		t.Fatalf("failed to load chain fixtures: %v", err)
	}
	_, err = chain.GetHeaders(&getBlockHeadersData{
		Origin: hashOrNumber{Hash: common.HexToHash("0x01")},
		Amount: 1,
	})
	if err == nil {
		t.Fatal("expected error for nonexistent hash header origin")
	}
}

func TestChainGetHeadersWithSkip(t *testing.T) {
	chain, err := NewChain("testdata")
	if err != nil {
		t.Fatalf("failed to load chain fixtures: %v", err)
	}
	if chain.Len() < 5 {
		t.Skipf("fixture chain too short for skip test: len=%d", chain.Len())
	}
	headers, err := chain.GetHeaders(&getBlockHeadersData{
		Origin: hashOrNumber{Number: 0},
		Amount: 3,
		Skip:   1,
	})
	if err != nil {
		t.Fatalf("unexpected get headers error: %v", err)
	}
	if len(headers) != 3 {
		t.Fatalf("wrong skipped headers count: have %d want 3", len(headers))
	}
	if headers[0].Number.Uint64() != 0 || headers[1].Number.Uint64() != 2 || headers[2].Number.Uint64() != 4 {
		t.Fatalf("unexpected skipped header numbers: have [%d %d %d] want [0 2 4]",
			headers[0].Number.Uint64(), headers[1].Number.Uint64(), headers[2].Number.Uint64())
	}
}

func TestChainGetHeadersReverseWithSkip(t *testing.T) {
	chain, err := NewChain("testdata")
	if err != nil {
		t.Fatalf("failed to load chain fixtures: %v", err)
	}
	if chain.Len() < 5 {
		t.Skipf("fixture chain too short for reverse skip test: len=%d", chain.Len())
	}
	headers, err := chain.GetHeaders(&getBlockHeadersData{
		Origin:  hashOrNumber{Number: 4},
		Amount:  3,
		Skip:    1,
		Reverse: true,
	})
	if err != nil {
		t.Fatalf("unexpected get headers error: %v", err)
	}
	if len(headers) != 3 {
		t.Fatalf("wrong reverse skipped headers count: have %d want 3", len(headers))
	}
	if headers[0].Number.Uint64() != 4 || headers[1].Number.Uint64() != 2 || headers[2].Number.Uint64() != 0 {
		t.Fatalf("unexpected reverse skipped header numbers: have [%d %d %d] want [4 2 0]",
			headers[0].Number.Uint64(), headers[1].Number.Uint64(), headers[2].Number.Uint64())
	}
}

func TestChainGetHeadersReverseFromGenesisStopsSafely(t *testing.T) {
	chain, err := NewChain("testdata")
	if err != nil {
		t.Fatalf("failed to load chain fixtures: %v", err)
	}
	headers, err := chain.GetHeaders(&getBlockHeadersData{
		Origin:  hashOrNumber{Number: 0},
		Amount:  3,
		Skip:    0,
		Reverse: true,
	})
	if err != nil {
		t.Fatalf("unexpected get headers error: %v", err)
	}
	if len(headers) != 1 {
		t.Fatalf("wrong reverse headers count: have %d want 1", len(headers))
	}
	if headers[0].Number.Uint64() != 0 {
		t.Fatalf("wrong reverse header number: have %d want 0", headers[0].Number.Uint64())
	}
}

func TestChainGetBlockBodiesByHash(t *testing.T) {
	chain, err := NewChain("testdata")
	if err != nil {
		t.Fatalf("failed to load chain fixtures: %v", err)
	}
	req := getBlockBodiesData{chain.blocks[0].Hash()}
	bodies, err := chain.GetBlockBodies(&req)
	if err != nil {
		t.Fatalf("unexpected get block bodies error: %v", err)
	}
	if len(bodies) != 1 {
		t.Fatalf("wrong block bodies count: have %d want 1", len(bodies))
	}
}

func TestChainGetBlockBodiesRejectsNil(t *testing.T) {
	chain, err := NewChain("testdata")
	if err != nil {
		t.Fatalf("failed to load chain fixtures: %v", err)
	}
	_, err = chain.GetBlockBodies(nil)
	if err == nil {
		t.Fatal("expected error for nil block bodies request")
	}
}

func TestChainGetBlockBodiesSkipsUnknownHash(t *testing.T) {
	chain, err := NewChain("testdata")
	if err != nil {
		t.Fatalf("failed to load chain fixtures: %v", err)
	}
	req := getBlockBodiesData{chain.blocks[0].Hash(), common.HexToHash("0x01")}
	bodies, err := chain.GetBlockBodies(&req)
	if err != nil {
		t.Fatalf("unexpected get block bodies error: %v", err)
	}
	if len(bodies) != 1 {
		t.Fatalf("wrong block bodies count with unknown hash: have %d want 1", len(bodies))
	}
}

func TestChainGetBlockBodiesUnknownOnly(t *testing.T) {
	chain, err := NewChain("testdata")
	if err != nil {
		t.Fatalf("failed to load chain fixtures: %v", err)
	}
	req := getBlockBodiesData{common.HexToHash("0x01")}
	bodies, err := chain.GetBlockBodies(&req)
	if err != nil {
		t.Fatalf("unexpected get block bodies error: %v", err)
	}
	if len(bodies) != 0 {
		t.Fatalf("wrong block bodies count for unknown-only request: have %d want 0", len(bodies))
	}
}

func TestChainGetReceiptsByHash(t *testing.T) {
	chain, err := NewChain("testdata")
	if err != nil {
		t.Fatalf("failed to load chain fixtures: %v", err)
	}
	req := getReceiptsData{chain.blocks[0].Hash(), common.HexToHash("0x01")}
	receipts, err := chain.GetReceipts(&req)
	if err != nil {
		t.Fatalf("unexpected get receipts error: %v", err)
	}
	if len(receipts) != 1 {
		t.Fatalf("wrong receipts count: have %d want 1", len(receipts))
	}
}

func TestChainGetReceiptsUnknownOnly(t *testing.T) {
	chain, err := NewChain("testdata")
	if err != nil {
		t.Fatalf("failed to load chain fixtures: %v", err)
	}
	req := getReceiptsData{common.HexToHash("0x01")}
	receipts, err := chain.GetReceipts(&req)
	if err != nil {
		t.Fatalf("unexpected get receipts error: %v", err)
	}
	if len(receipts) != 0 {
		t.Fatalf("wrong receipts count for unknown-only request: have %d want 0", len(receipts))
	}
}

func TestChainGetReceiptsRejectsNil(t *testing.T) {
	chain, err := NewChain("testdata")
	if err != nil {
		t.Fatalf("failed to load chain fixtures: %v", err)
	}
	_, err = chain.GetReceipts(nil)
	if err == nil {
		t.Fatal("expected error for nil receipts request")
	}
}
