package simulated

import (
	"context"
	"crypto/ecdsa"
	"math/big"
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
)

// TestTransactionRollbackBehavior tests that calling Rollback on the simulated backend doesn't prevent subsequent
// addition of new transactions
func TestTransactionRollbackBehavior(t *testing.T) {
	sim := New(
		types.GenesisAlloc{
			testAddr:  {Balance: big.NewInt(10000000000000000)},
			testAddr2: {Balance: big.NewInt(10000000000000000)},
		},
		10000000,
	)
	defer sim.Close()
	client := sim.Client()

	btx0 := testSendSignedTx(t, testKey, sim)
	tx0 := testSendSignedTx(t, testKey2, sim)
	tx1 := testSendSignedTx(t, testKey2, sim)

	if err := sim.Rollback(); err != nil {
		t.Fatalf("rollback failed: %v", err)
	}

	if pendingStateHasTx(client, btx0) || pendingStateHasTx(client, tx0) || pendingStateHasTx(client, tx1) {
		t.Fatalf("all transactions were not rolled back")
	}

	btx2 := testSendSignedTx(t, testKey, sim)
	tx2 := testSendSignedTx(t, testKey2, sim)
	tx3 := testSendSignedTx(t, testKey2, sim)

	sim.Commit()

	if !pendingStateHasTx(client, btx2) || !pendingStateHasTx(client, tx2) || !pendingStateHasTx(client, tx3) {
		t.Fatalf("all post-rollback transactions were not included")
	}
}

func TestSetPendingBlockReturnsErrorOnMissingState(t *testing.T) {
	sim := New(types.GenesisAlloc{}, 10_000_000)
	defer sim.Close()

	stateDB, err := sim.blockchain.State()
	if err != nil {
		t.Fatalf("failed to load blockchain state: %v", err)
	}
	originalBlock := sim.pendingBlock
	originalState := sim.pendingState
	badBlock := types.NewBlockWithHeader(&types.Header{Root: common.HexToHash("0x1")})

	err = sim.setPendingBlock(badBlock, stateDB.Database())
	if err == nil {
		t.Fatal("expected missing state error")
	}
	if sim.pendingBlock != originalBlock {
		t.Fatal("pending block changed on rebuild failure")
	}
	if sim.pendingState != originalState {
		t.Fatal("pending state changed on rebuild failure")
	}
}

func TestSetPendingBlockAndReceiptsKeepsReceiptsOnFailure(t *testing.T) {
	sim := New(types.GenesisAlloc{}, 10_000_000)
	defer sim.Close()

	stateDB, err := sim.blockchain.State()
	if err != nil {
		t.Fatalf("failed to load blockchain state: %v", err)
	}
	originalBlock := sim.pendingBlock
	originalState := sim.pendingState
	originalReceipts := types.Receipts{{TxHash: common.HexToHash("0x1")}}
	sim.pendingReceipts = originalReceipts

	badBlock := types.NewBlockWithHeader(&types.Header{Root: common.HexToHash("0x1")})
	newReceipts := types.Receipts{{TxHash: common.HexToHash("0x2")}}

	err = sim.setPendingBlockAndReceipts(badBlock, newReceipts, stateDB.Database())
	if err == nil {
		t.Fatal("expected missing state error")
	}
	if sim.pendingBlock != originalBlock {
		t.Fatal("pending block changed on rebuild failure")
	}
	if sim.pendingState != originalState {
		t.Fatal("pending state changed on rebuild failure")
	}
	if len(sim.pendingReceipts) != len(originalReceipts) || sim.pendingReceipts[0].TxHash != originalReceipts[0].TxHash {
		t.Fatalf("pending receipts changed on rebuild failure: have %v want %v", sim.pendingReceipts, originalReceipts)
	}
}

// testSendSignedTx sends a signed transaction to the simulated backend.
// It does not commit the block.
func testSendSignedTx(t *testing.T, key *ecdsa.PrivateKey, sim *Backend) *types.Transaction {
	t.Helper()
	client := sim.Client()
	ctx := context.Background()

	var (
		err      error
		signedTx *types.Transaction
	)
	signedTx, err = newTx(sim, key)
	if err != nil {
		t.Fatalf("failed to create transaction: %v", err)
	}

	if err = client.SendTransaction(ctx, signedTx); err != nil {
		t.Fatalf("failed to send transaction: %v", err)
	}

	return signedTx
}

// pendingStateHasTx returns true if a given transaction was successfully included as of the latest pending state.
func pendingStateHasTx(client Client, tx *types.Transaction) bool {
	ctx := context.Background()

	var (
		receipt *types.Receipt
		err     error
	)

	// Poll for receipt with timeout
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		receipt, err = client.TransactionReceipt(ctx, tx.Hash())
		if err == nil && receipt != nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if err != nil {
		return false
	}
	if receipt == nil {
		return false
	}
	if receipt.Status != types.ReceiptStatusSuccessful {
		return false
	}
	return true
}
