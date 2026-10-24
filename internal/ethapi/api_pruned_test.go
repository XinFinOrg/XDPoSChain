// Copyright 2026 The XDPoSChain Authors
// This file is part of the XDPoSChain library.
//
// The XDPoSChain library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The XDPoSChain library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the XDPoSChain library. If not, see <http://www.gnu.org/licenses/>.

package ethapi

import (
	"errors"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/ethdb/memorydb"
)

// TestPrunedTransactionError checks that a transaction indexed in a block whose
// body was pruned by minimal history mode is reported as pruned, rather than as
// unknown.
func TestPrunedTransactionError(t *testing.T) {
	db, err := rawdb.Open(memorydb.New(), rawdb.OpenOptions{Ancient: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	_, err = db.ModifyAncients(func(op ethdb.AncientWriteOp) error {
		for i := uint64(0); i < 10; i++ {
			for _, table := range []string{rawdb.ChainFreezerHeaderTable, rawdb.ChainFreezerHashTable, rawdb.ChainFreezerBodiesTable, rawdb.ChainFreezerReceiptTable} {
				if err := op.AppendRaw(table, i, []byte{byte(i)}); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.TruncateTail(rawdb.ChainFreezerBlockDataGroup, 5); err != nil {
		t.Fatal(err)
	}
	indexTx := func(number uint64) common.Hash {
		tx := types.NewTransaction(number, common.Address{}, big.NewInt(0), 21000, big.NewInt(1), nil)
		block := types.NewBlockWithHeader(&types.Header{Number: new(big.Int).SetUint64(number)}).WithBody(types.Body{Transactions: types.Transactions{tx}})
		rawdb.WriteTxLookupEntriesByBlock(db, block)
		return tx.Hash()
	}
	pruned, kept := indexTx(3), indexTx(7)

	if err := prunedTransactionError(db, pruned); !errors.Is(err, rawdb.ErrPrunedHistory) {
		t.Fatalf("transaction in a pruned block: got %v, want %v", err, rawdb.ErrPrunedHistory)
	}
	if err := prunedTransactionError(db, kept); err != nil {
		t.Fatalf("transaction in a retained block: %v", err)
	}
	if err := prunedTransactionError(db, common.Hash{1}); err != nil {
		t.Fatalf("unknown transaction: %v", err)
	}
	var rpcErr interface{ ErrorCode() int }
	if !errors.As(rawdb.ErrPrunedHistory, &rpcErr) || rpcErr.ErrorCode() != 4444 {
		t.Fatal("pruned history error carries no RPC error code 4444")
	}
}
