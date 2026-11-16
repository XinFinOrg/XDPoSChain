// Copyright 2018 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package rawdb

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"math/rand/v2"
	"os"
	"strings"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/crypto/keccak"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/XinFinOrg/XDPoSChain/rlp"
)

type errorReader struct {
	hasResult bool
	hasErr    error
	getErr    error
	value     []byte
}

// Has returns the configured Has result for metadata read tests.
func (r *errorReader) Has(key []byte) (bool, error) {
	return r.hasResult, r.hasErr
}

// Get returns the configured Get result for metadata read tests.
func (r *errorReader) Get(key []byte) ([]byte, error) {
	if r.getErr != nil {
		return nil, r.getErr
	}
	return r.value, nil
}

// TestReadChainConfigGetError tests read chain config get error.
func TestReadChainConfigGetError(t *testing.T) {
	hash := common.HexToHash("0x1")
	wantErr := errors.New("boom")
	_, err := ReadChainConfig(&errorReader{getErr: wantErr, hasResult: true}, hash)
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected wrapped get error, got %v", err)
	}
}

// TestReadChainConfigNotFound tests read chain config not found.
func TestReadChainConfigNotFound(t *testing.T) {
	hash := common.HexToHash("0x2")
	_, err := ReadChainConfig(&errorReader{getErr: errors.New("missing"), hasResult: false}, hash)
	if !errors.Is(err, ErrChainConfigNotFound) {
		t.Fatalf("expected ErrChainConfigNotFound, got %v", err)
	}
}

// TestReadOptionalBlobNotFound tests metadata reads use the generic metadata sentinel.
func TestReadOptionalBlobNotFound(t *testing.T) {
	_, err := readOptionalBlob(&errorReader{getErr: errors.New("missing"), hasResult: false}, []byte("key"))
	if !errors.Is(err, ErrMetadataNotFound) {
		t.Fatalf("expected ErrMetadataNotFound, got %v", err)
	}
}

// TestReadChainConfigJSONGetError tests read chain config json get error.
func TestReadChainConfigJSONGetError(t *testing.T) {
	hash := common.HexToHash("0x3")
	wantErr := errors.New("boom")
	_, err := ReadChainConfigJSON(&errorReader{getErr: wantErr, hasResult: true}, hash)
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected wrapped get error, got %v", err)
	}
}

// TestReadChainConfigJSONNotFound tests missing chain config json uses the chain config sentinel.
func TestReadChainConfigJSONNotFound(t *testing.T) {
	hash := common.HexToHash("0x31")
	_, err := ReadChainConfigJSON(&errorReader{getErr: errors.New("missing"), hasResult: false}, hash)
	if !errors.Is(err, ErrChainConfigNotFound) {
		t.Fatalf("expected ErrChainConfigNotFound, got %v", err)
	}
}

// TestReadChainConfigOverrideGetError tests override marker read error propagation.
func TestReadChainConfigOverrideGetError(t *testing.T) {
	hash := common.HexToHash("0x4")
	wantErr := errors.New("boom")
	marker, err := ReadChainConfigOverride(&errorReader{getErr: wantErr, hasResult: true}, hash)
	if marker {
		t.Fatal("expected override marker to be false on read error")
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected wrapped get error, got %v", err)
	}
}

// TestReadChainConfigOverrideNotFound tests missing override marker handling.
func TestReadChainConfigOverrideNotFound(t *testing.T) {
	hash := common.HexToHash("0x5")
	marker, err := ReadChainConfigOverride(&errorReader{getErr: errors.New("missing"), hasResult: false}, hash)
	if err != nil {
		t.Fatalf("expected nil error for missing marker, got %v", err)
	}
	if marker {
		t.Fatal("expected missing marker to read as false")
	}
}

// TestReadChainConfigOverrideVersionedPayload tests the current override marker payload.
func TestReadChainConfigOverrideVersionedPayload(t *testing.T) {
	hash := common.HexToHash("0x6")
	marker, err := ReadChainConfigOverride(&errorReader{hasResult: true, value: []byte{1, 1}}, hash)
	if err != nil {
		t.Fatalf("expected nil error for valid marker payload, got %v", err)
	}
	if !marker {
		t.Fatal("expected valid marker payload to read as true")
	}
}

// TestReadChainConfigOverrideRejectsMalformedPayload tests malformed marker payload handling.
func TestReadChainConfigOverrideRejectsMalformedPayload(t *testing.T) {
	tests := []struct {
		name    string
		value   []byte
		wantErr string
	}{
		{name: "short payload", value: []byte{1}, wantErr: "invalid chain config override marker payload"},
		{name: "disabled flag", value: []byte{1, 0}, wantErr: "invalid chain config override marker payload"},
		{name: "unknown version", value: []byte{2, 1}, wantErr: "unsupported chain config override marker version"},
	}

	hash := common.HexToHash("0x7")
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			marker, err := ReadChainConfigOverride(&errorReader{hasResult: true, value: test.value}, hash)
			if marker {
				t.Fatal("expected malformed marker payload to read as false")
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("expected error containing %q, got %v", test.wantErr, err)
			}
		})
	}
}

// TestReadChainConfigOverrideIgnoresLegacyMarker tests legacy marker keys are no longer read.
func TestReadChainConfigOverrideIgnoresLegacyMarker(t *testing.T) {
	db := NewMemoryDatabase()
	hash := common.HexToHash("0x8")
	legacyKey := append([]byte("ethereum-config-override-"), hash.Bytes()...)
	if err := db.Put(legacyKey, []byte{1}); err != nil {
		t.Fatalf("failed to write legacy marker: %v", err)
	}

	marker, err := ReadChainConfigOverride(db, hash)
	if err != nil {
		t.Fatalf("expected nil error for ignored legacy marker, got %v", err)
	}
	if marker {
		t.Fatal("expected legacy marker to be ignored")
	}
}

func TestWriteChainConfigOmitsInferredZeroValueFields(t *testing.T) {
	db := NewMemoryDatabase()
	hash := common.HexToHash("0x9")
	cfg := (&params.ChainConfig{
		ChainID:        big.NewInt(51),
		DAOForkBlock:   big.NewInt(0),
		DAOForkSupport: false,
		Ethash:         new(params.EthashConfig),
	}).CloneForBackfill()

	WriteChainConfig(db, hash, cfg)

	rawCfg, err := ReadChainConfigJSON(db, hash)
	if err != nil {
		t.Fatalf("failed to read stored chain config JSON: %v", err)
	}
	var storedKeys map[string]json.RawMessage
	if err := json.Unmarshal(rawCfg, &storedKeys); err != nil {
		t.Fatalf("failed to inspect stored chain config JSON: %v", err)
	}
	if _, ok := storedKeys["daoForkSupport"]; ok {
		t.Fatalf("expected inferred false daoForkSupport to remain omitted, have %s", rawCfg)
	}
	if _, ok := storedKeys["daoForkBlock"]; !ok {
		t.Fatalf("expected explicit daoForkBlock to remain present, have %s", rawCfg)
	}
	if _, ok := storedKeys["ethash"]; !ok {
		t.Fatalf("expected ethash config to be persisted, have %s", rawCfg)
	}
}

type fullLogRLP struct {
	Address     common.Address
	Topics      []common.Hash
	Data        []byte
	BlockNumber uint64
	TxHash      common.Hash
	TxIndex     uint
	BlockHash   common.Hash
	Index       uint
}

func newFullLogRLP(l *types.Log) *fullLogRLP {
	return &fullLogRLP{
		Address:     l.Address,
		Topics:      l.Topics,
		Data:        l.Data,
		BlockNumber: l.BlockNumber,
		TxHash:      l.TxHash,
		TxIndex:     l.TxIndex,
		BlockHash:   l.BlockHash,
		Index:       l.Index,
	}
}

// Tests block header storage and retrieval operations.
func TestHeaderStorage(t *testing.T) {
	db := NewMemoryDatabase()

	// Create a test header to move around the database and make sure it's really new
	header := &types.Header{Number: big.NewInt(42), Extra: []byte("test header")}
	if entry := ReadHeader(db, header.Hash(), header.Number.Uint64()); entry != nil {
		t.Fatalf("Non existent header returned: %v", entry)
	}
	// Write and verify the header in the database
	WriteHeader(db, header)
	if entry := ReadHeader(db, header.Hash(), header.Number.Uint64()); entry == nil {
		t.Fatalf("Stored header not found")
	} else if entry.Hash() != header.Hash() {
		t.Fatalf("Retrieved header mismatch: have %v, want %v", entry, header)
	}
	if entry := ReadHeaderRLP(db, header.Hash(), header.Number.Uint64()); entry == nil {
		t.Fatalf("Stored header RLP not found")
	} else {
		if hash := crypto.Keccak256Hash(entry); hash != header.Hash() {
			t.Fatalf("Retrieved RLP header mismatch: have %v, want %v", entry, header)
		}
	}
	// Delete the header and verify the execution
	DeleteHeader(db, header.Hash(), header.Number.Uint64())
	if entry := ReadHeader(db, header.Hash(), header.Number.Uint64()); entry != nil {
		t.Fatalf("Deleted header returned: %v", entry)
	}
}

// Tests block body storage and retrieval operations.
func TestBodyStorage(t *testing.T) {
	db := NewMemoryDatabase()

	// Create a test body to move around the database and make sure it's really new
	body := &types.Body{Uncles: []*types.Header{{Extra: []byte("test header")}}}

	hasher := keccak.NewLegacyKeccak256()
	if err := rlp.Encode(hasher, body); err != nil {
		t.Fatalf("rlp.Encode fail: %v", err)
	}
	hash := common.BytesToHash(hasher.Sum(nil))

	if entry := ReadBody(db, hash, 0); entry != nil {
		t.Fatalf("Non existent body returned: %v", entry)
	}
	// Write and verify the body in the database
	WriteBody(db, hash, 0, body)
	if entry := ReadBody(db, hash, 0); entry == nil {
		t.Fatalf("Stored body not found")
	} else if types.DeriveSha(types.Transactions(entry.Transactions), newTestHasher()) != types.DeriveSha(types.Transactions(body.Transactions), newTestHasher()) || types.CalcUncleHash(entry.Uncles) != types.CalcUncleHash(body.Uncles) {
		t.Fatalf("Retrieved body mismatch: have %v, want %v", entry, body)
	}
	if entry := ReadBodyRLP(db, hash, 0); entry == nil {
		t.Fatalf("Stored body RLP not found")
	} else {
		if calc := crypto.Keccak256Hash(entry); calc != hash {
			t.Fatalf("Retrieved RLP body mismatch: have %v, want %v", entry, body)
		}
	}
	// Delete the body and verify the execution
	DeleteBody(db, hash, 0)
	if entry := ReadBody(db, hash, 0); entry != nil {
		t.Fatalf("Deleted body returned: %v", entry)
	}
}

// Tests block storage and retrieval operations.
func TestBlockStorage(t *testing.T) {
	db := NewMemoryDatabase()

	// Create a test block to move around the database and make sure it's really new
	block := types.NewBlockWithHeader(&types.Header{
		Extra:       []byte("test block"),
		UncleHash:   types.EmptyUncleHash,
		TxHash:      types.EmptyRootHash,
		ReceiptHash: types.EmptyRootHash,
	})
	if entry := ReadBlock(db, block.Hash(), block.NumberU64()); entry != nil {
		t.Fatalf("Non existent block returned: %v", entry)
	}
	if entry := ReadHeader(db, block.Hash(), block.NumberU64()); entry != nil {
		t.Fatalf("Non existent header returned: %v", entry)
	}
	if entry := ReadBody(db, block.Hash(), block.NumberU64()); entry != nil {
		t.Fatalf("Non existent body returned: %v", entry)
	}
	// Write and verify the block in the database
	WriteBlock(db, block)
	if entry := ReadBlock(db, block.Hash(), block.NumberU64()); entry == nil {
		t.Fatalf("Stored block not found")
	} else if entry.Hash() != block.Hash() {
		t.Fatalf("Retrieved block mismatch: have %v, want %v", entry, block)
	}
	if entry := ReadHeader(db, block.Hash(), block.NumberU64()); entry == nil {
		t.Fatalf("Stored header not found")
	} else if entry.Hash() != block.Header().Hash() {
		t.Fatalf("Retrieved header mismatch: have %v, want %v", entry, block.Header())
	}
	if entry := ReadBody(db, block.Hash(), block.NumberU64()); entry == nil {
		t.Fatalf("Stored body not found")
	} else if types.DeriveSha(types.Transactions(entry.Transactions), newTestHasher()) != types.DeriveSha(block.Transactions(), newTestHasher()) || types.CalcUncleHash(entry.Uncles) != types.CalcUncleHash(block.Uncles()) {
		t.Fatalf("Retrieved body mismatch: have %v, want %v", entry, block.Body())
	}
	// Delete the block and verify the execution
	DeleteBlock(db, block.Hash(), block.NumberU64())
	if entry := ReadBlock(db, block.Hash(), block.NumberU64()); entry != nil {
		t.Fatalf("Deleted block returned: %v", entry)
	}
	if entry := ReadHeader(db, block.Hash(), block.NumberU64()); entry != nil {
		t.Fatalf("Deleted header returned: %v", entry)
	}
	if entry := ReadBody(db, block.Hash(), block.NumberU64()); entry != nil {
		t.Fatalf("Deleted body returned: %v", entry)
	}
}

// Tests that partial block contents don't get reassembled into full blocks.
func TestPartialBlockStorage(t *testing.T) {
	db := NewMemoryDatabase()
	block := types.NewBlockWithHeader(&types.Header{
		Extra:       []byte("test block"),
		UncleHash:   types.EmptyUncleHash,
		TxHash:      types.EmptyRootHash,
		ReceiptHash: types.EmptyRootHash,
	})
	// Store a header and check that it's not recognized as a block
	WriteHeader(db, block.Header())
	if entry := ReadBlock(db, block.Hash(), block.NumberU64()); entry != nil {
		t.Fatalf("Non existent block returned: %v", entry)
	}
	DeleteHeader(db, block.Hash(), block.NumberU64())

	// Store a body and check that it's not recognized as a block
	WriteBody(db, block.Hash(), block.NumberU64(), block.Body())
	if entry := ReadBlock(db, block.Hash(), block.NumberU64()); entry != nil {
		t.Fatalf("Non existent block returned: %v", entry)
	}
	DeleteBody(db, block.Hash(), block.NumberU64())

	// Store a header and a body separately and check reassembly
	WriteHeader(db, block.Header())
	WriteBody(db, block.Hash(), block.NumberU64(), block.Body())
	if entry := ReadBlock(db, block.Hash(), block.NumberU64()); entry == nil {
		t.Fatalf("Stored block not found")
	} else if entry.Hash() != block.Hash() {
		t.Fatalf("Retrieved block mismatch: have %v, want %v", entry, block)
	}
}

// Tests block storage and retrieval operations.
func TestBadBlockStorage(t *testing.T) {
	db := NewMemoryDatabase()

	// Create a test block to move around the database and make sure it's really new
	block := types.NewBlockWithHeader(&types.Header{
		Number:      big.NewInt(1),
		Extra:       []byte("bad block"),
		UncleHash:   types.EmptyUncleHash,
		TxHash:      types.EmptyTxsHash,
		ReceiptHash: types.EmptyReceiptsHash,
	})
	if entry := ReadBadBlock(db, block.Hash()); entry != nil {
		t.Fatalf("Non existent block returned: %v", entry)
	}
	// Write and verify the block in the database
	WriteBadBlock(db, block)
	if entry := ReadBadBlock(db, block.Hash()); entry == nil {
		t.Fatalf("Stored block not found")
	} else if entry.Hash() != block.Hash() {
		t.Fatalf("Retrieved block mismatch: have %v, want %v", entry, block)
	}
	// Write one more bad block
	blockTwo := types.NewBlockWithHeader(&types.Header{
		Number:      big.NewInt(2),
		Extra:       []byte("bad block two"),
		UncleHash:   types.EmptyUncleHash,
		TxHash:      types.EmptyTxsHash,
		ReceiptHash: types.EmptyReceiptsHash,
	})
	WriteBadBlock(db, blockTwo)

	// Write the block one again, should be filtered out.
	WriteBadBlock(db, block)
	badBlocks := ReadAllBadBlocks(db)
	if len(badBlocks) != 2 {
		t.Fatalf("Failed to load all bad blocks")
	}

	// Write a bunch of bad blocks, all the blocks are should sorted
	// in reverse order. The extra blocks should be truncated.
	for _, n := range rand.Perm(100) {
		block := types.NewBlockWithHeader(&types.Header{
			Number:      big.NewInt(int64(n)),
			Extra:       []byte("bad block"),
			UncleHash:   types.EmptyUncleHash,
			TxHash:      types.EmptyTxsHash,
			ReceiptHash: types.EmptyReceiptsHash,
		})
		WriteBadBlock(db, block)
	}
	badBlocks = ReadAllBadBlocks(db)
	if len(badBlocks) != badBlockToKeep {
		t.Fatalf("The number of persised bad blocks in incorrect %d", len(badBlocks))
	}
	for i := 0; i < len(badBlocks)-1; i++ {
		if badBlocks[i].NumberU64() < badBlocks[i+1].NumberU64() {
			t.Fatalf("The bad blocks are not sorted #[%d](%d) < #[%d](%d)", i, badBlocks[i].NumberU64(), i+1, badBlocks[i+1].NumberU64())
		}
	}

	// Delete all bad blocks
	DeleteBadBlocks(db)
	badBlocks = ReadAllBadBlocks(db)
	if len(badBlocks) != 0 {
		t.Fatalf("Failed to delete bad blocks")
	}
}

// Tests block total difficulty storage and retrieval operations.
func TestTdStorage(t *testing.T) {
	db := NewMemoryDatabase()

	// Create a test TD to move around the database and make sure it's really new
	hash, td := common.Hash{}, big.NewInt(314)
	if entry := ReadTd(db, hash, 0); entry != nil {
		t.Fatalf("Non existent TD returned: %v", entry)
	}
	// Write and verify the TD in the database
	WriteTd(db, hash, 0, td)
	if entry := ReadTd(db, hash, 0); entry == nil {
		t.Fatalf("Stored TD not found")
	} else if entry.Cmp(td) != 0 {
		t.Fatalf("Retrieved TD mismatch: have %v, want %v", entry, td)
	}
	// Delete the TD and verify the execution
	DeleteTd(db, hash, 0)
	if entry := ReadTd(db, hash, 0); entry != nil {
		t.Fatalf("Deleted TD returned: %v", entry)
	}
}

// Tests that canonical numbers can be mapped to hashes and retrieved.
func TestCanonicalMappingStorage(t *testing.T) {
	db := NewMemoryDatabase()

	// Create a test canonical number and assinged hash to move around
	hash, number := common.Hash{0: 0xff}, uint64(314)
	if entry := ReadCanonicalHash(db, number); entry != (common.Hash{}) {
		t.Fatalf("Non existent canonical mapping returned: %v", entry)
	}
	// Write and verify the TD in the database
	WriteCanonicalHash(db, hash, number)
	if entry := ReadCanonicalHash(db, number); entry == (common.Hash{}) {
		t.Fatalf("Stored canonical mapping not found")
	} else if entry != hash {
		t.Fatalf("Retrieved canonical mapping mismatch: have %v, want %v", entry, hash)
	}
	// Delete the TD and verify the execution
	DeleteCanonicalHash(db, number)
	if entry := ReadCanonicalHash(db, number); entry != (common.Hash{}) {
		t.Fatalf("Deleted canonical mapping returned: %v", entry)
	}
}

// Tests that head headers and head blocks can be assigned, individually.
func TestHeadStorage(t *testing.T) {
	db := NewMemoryDatabase()

	blockHead := types.NewBlockWithHeader(&types.Header{Extra: []byte("test block header")})
	blockFull := types.NewBlockWithHeader(&types.Header{Extra: []byte("test block full")})
	blockFast := types.NewBlockWithHeader(&types.Header{Extra: []byte("test block fast")})

	// Check that no head entries are in a pristine database
	if entry := ReadHeadHeaderHash(db); entry != (common.Hash{}) {
		t.Fatalf("Non head header entry returned: %v", entry)
	}
	if entry := ReadHeadBlockHash(db); entry != (common.Hash{}) {
		t.Fatalf("Non head block entry returned: %v", entry)
	}
	if entry := ReadHeadFastBlockHash(db); entry != (common.Hash{}) {
		t.Fatalf("Non fast head block entry returned: %v", entry)
	}
	// Assign separate entries for the head header and block
	WriteHeadHeaderHash(db, blockHead.Hash())
	WriteHeadBlockHash(db, blockFull.Hash())
	WriteHeadFastBlockHash(db, blockFast.Hash())
	// Check that both heads are present, and different (i.e. two heads maintained)
	if entry := ReadHeadHeaderHash(db); entry != blockHead.Hash() {
		t.Fatalf("Head header hash mismatch: have %v, want %v", entry, blockHead.Hash())
	}
	if entry := ReadHeadBlockHash(db); entry != blockFull.Hash() {
		t.Fatalf("Head block hash mismatch: have %v, want %v", entry, blockFull.Hash())
	}
	if entry := ReadHeadFastBlockHash(db); entry != blockFast.Hash() {
		t.Fatalf("Fast head block hash mismatch: have %v, want %v", entry, blockFast.Hash())
	}
}

// Tests that receipts associated with a single block can be stored and retrieved.
func TestBlockReceiptStorage(t *testing.T) {
	db := NewMemoryDatabase()

	// Create a live block since we need metadata to reconstruct the receipt
	tx1 := types.NewTransaction(1, common.HexToAddress("0x1"), big.NewInt(1), 1, big.NewInt(1), nil)
	tx2 := types.NewTransaction(2, common.HexToAddress("0x2"), big.NewInt(2), 2, big.NewInt(2), nil)

	body := &types.Body{Transactions: types.Transactions{tx1, tx2}}

	receipt1 := &types.Receipt{
		Status:            types.ReceiptStatusFailed,
		CumulativeGasUsed: 1,
		Logs: []*types.Log{
			{Address: common.BytesToAddress([]byte{0x11})},
			{Address: common.BytesToAddress([]byte{0x01, 0x11})},
		},
		TxHash:          tx1.Hash(),
		ContractAddress: common.BytesToAddress([]byte{0x01, 0x11, 0x11}),
		GasUsed:         111111,
	}
	receipt1.Bloom = types.CreateBloom(types.Receipts{receipt1})

	receipt2 := &types.Receipt{
		PostState:         common.Hash{2}.Bytes(),
		CumulativeGasUsed: 2,
		Logs: []*types.Log{
			{Address: common.BytesToAddress([]byte{0x22})},
			{Address: common.BytesToAddress([]byte{0x02, 0x22})},
		},
		TxHash:          tx2.Hash(),
		ContractAddress: common.BytesToAddress([]byte{0x02, 0x22, 0x22}),
		GasUsed:         222222,
	}
	receipt2.Bloom = types.CreateBloom(types.Receipts{receipt2})

	receipts := []*types.Receipt{receipt1, receipt2}

	// Check that no receipt entries are in a pristine database
	hash := common.BytesToHash([]byte{0x03, 0x14})
	if rs := ReadReceipts(db, hash, 0, params.TestChainConfig); len(rs) != 0 {
		t.Fatalf("non existent receipts returned: %v", rs)
	}
	// Insert the body that corresponds to the receipts
	WriteBody(db, hash, 0, body)

	// Insert the receipt slice into the database and check presence
	WriteReceipts(db, hash, 0, receipts)
	if rs := ReadReceipts(db, hash, 0, params.TestChainConfig); len(rs) == 0 {
		t.Fatal("no receipts returned")
	} else {
		if err := checkReceiptsRLP(rs, receipts); err != nil {
			t.Fatal(err)
		}
	}
	// Delete the body and ensure that the receipts are no longer returned (metadata can't be recomputed)
	DeleteBody(db, hash, 0)
	if rs := ReadReceipts(db, hash, 0, params.TestChainConfig); rs != nil {
		t.Fatalf("receipts returned when body was deleted: %v", rs)
	}
	// Ensure that receipts without metadata can be returned without the block body too
	if err := checkReceiptsRLP(ReadRawReceipts(db, hash, 0), receipts); err != nil {
		t.Fatal(err)
	}
	// Sanity check that body alone without the receipt is a full purge
	WriteBody(db, hash, 0, body)

	DeleteReceipts(db, hash, 0)
	if rs := ReadReceipts(db, hash, 0, params.TestChainConfig); len(rs) != 0 {
		t.Fatalf("deleted receipts returned: %v", rs)
	}
}

func checkReceiptsRLP(have, want types.Receipts) error {
	if len(have) != len(want) {
		return fmt.Errorf("receipts sizes mismatch: have %d, want %d", len(have), len(want))
	}
	for i := 0; i < len(want); i++ {
		rlpHave, err := rlp.EncodeToBytes(have[i])
		if err != nil {
			return err
		}
		rlpWant, err := rlp.EncodeToBytes(want[i])
		if err != nil {
			return err
		}
		if !bytes.Equal(rlpHave, rlpWant) {
			return fmt.Errorf("receipt #%d: receipt mismatch: have %s, want %s", i, hex.EncodeToString(rlpHave), hex.EncodeToString(rlpWant))
		}
	}
	return nil
}

// Tests that logs associated with a single block can be retrieved.
func TestReadLogs(t *testing.T) {
	db := NewMemoryDatabase()

	// Create a live block since we need metadata to reconstruct the receipt
	tx1 := types.NewTransaction(1, common.HexToAddress("0x1"), big.NewInt(1), 1, big.NewInt(1), nil)
	tx2 := types.NewTransaction(2, common.HexToAddress("0x2"), big.NewInt(2), 2, big.NewInt(2), nil)

	body := &types.Body{Transactions: types.Transactions{tx1, tx2}}

	// Create the two receipts to manage afterwards
	receipt1 := &types.Receipt{
		Status:            types.ReceiptStatusFailed,
		CumulativeGasUsed: 1,
		Logs: []*types.Log{
			{Address: common.BytesToAddress([]byte{0x11})},
			{Address: common.BytesToAddress([]byte{0x01, 0x11})},
		},
		TxHash:          tx1.Hash(),
		ContractAddress: common.BytesToAddress([]byte{0x01, 0x11, 0x11}),
		GasUsed:         111111,
	}
	receipt1.Bloom = types.CreateBloom(types.Receipts{receipt1})

	receipt2 := &types.Receipt{
		PostState:         common.Hash{2}.Bytes(),
		CumulativeGasUsed: 2,
		Logs: []*types.Log{
			{Address: common.BytesToAddress([]byte{0x22})},
			{Address: common.BytesToAddress([]byte{0x02, 0x22})},
		},
		TxHash:          tx2.Hash(),
		ContractAddress: common.BytesToAddress([]byte{0x02, 0x22, 0x22}),
		GasUsed:         222222,
	}
	receipt2.Bloom = types.CreateBloom(types.Receipts{receipt2})
	receipts := []*types.Receipt{receipt1, receipt2}

	hash := common.BytesToHash([]byte{0x03, 0x14})
	// Check that no receipt entries are in a pristine database
	if rs := ReadReceipts(db, hash, 0, params.TestChainConfig); len(rs) != 0 {
		t.Fatalf("non existent receipts returned: %v", rs)
	}
	// Insert the body that corresponds to the receipts
	WriteBody(db, hash, 0, body)

	// Insert the receipt slice into the database and check presence
	WriteReceipts(db, hash, 0, receipts)

	logs := ReadLogs(db, hash, 0)
	if len(logs) == 0 {
		t.Fatalf("no logs returned")
	}
	if have, want := len(logs), 2; have != want {
		t.Fatalf("unexpected number of logs returned, have %d want %d", have, want)
	}
	if have, want := len(logs[0]), 2; have != want {
		t.Fatalf("unexpected number of logs[0] returned, have %d want %d", have, want)
	}
	if have, want := len(logs[1]), 2; have != want {
		t.Fatalf("unexpected number of logs[1] returned, have %d want %d", have, want)
	}

	for i, pr := range receipts {
		for j, pl := range pr.Logs {
			rlpHave, err := rlp.EncodeToBytes(newFullLogRLP(logs[i][j]))
			if err != nil {
				t.Fatal(err)
			}
			rlpWant, err := rlp.EncodeToBytes(newFullLogRLP(pl))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(rlpHave, rlpWant) {
				t.Fatalf("receipt #%d: receipt mismatch: have %s, want %s", i, hex.EncodeToString(rlpHave), hex.EncodeToString(rlpWant))
			}
		}
	}
}

// TestDeriveLogFields tests derive log fields.
func TestDeriveLogFields(t *testing.T) {
	// Create a few transactions to have receipts for
	to2 := common.HexToAddress("0x2")
	to3 := common.HexToAddress("0x3")
	txs := types.Transactions{
		types.NewTx(&types.LegacyTx{
			Nonce:    1,
			Value:    big.NewInt(1),
			Gas:      1,
			GasPrice: big.NewInt(1),
		}),
		types.NewTx(&types.LegacyTx{
			To:       &to2,
			Nonce:    2,
			Value:    big.NewInt(2),
			Gas:      2,
			GasPrice: big.NewInt(2),
		}),
		types.NewTx(&types.AccessListTx{
			To:       &to3,
			Nonce:    3,
			Value:    big.NewInt(3),
			Gas:      3,
			GasPrice: big.NewInt(3),
		}),
	}
	// Create the corresponding receipts
	receipts := []*receiptLogs{
		{
			Logs: []*types.Log{
				{Address: common.BytesToAddress([]byte{0x11})},
				{Address: common.BytesToAddress([]byte{0x01, 0x11})},
			},
		},
		{
			Logs: []*types.Log{
				{Address: common.BytesToAddress([]byte{0x22})},
				{Address: common.BytesToAddress([]byte{0x02, 0x22})},
			},
		},
		{
			Logs: []*types.Log{
				{Address: common.BytesToAddress([]byte{0x33})},
				{Address: common.BytesToAddress([]byte{0x03, 0x33})},
			},
		},
	}

	// Derive log metadata fields
	number := big.NewInt(1)
	hash := common.BytesToHash([]byte{0x03, 0x14})
	if err := deriveLogFields(receipts, hash, number.Uint64(), txs); err != nil {
		t.Fatal(err)
	}

	// Iterate over all the computed fields and check that they're correct
	logIndex := uint(0)
	for i := range receipts {
		for j := range receipts[i].Logs {
			if receipts[i].Logs[j].BlockNumber != number.Uint64() {
				t.Errorf("receipts[%d].Logs[%d].BlockNumber = %d, want %d", i, j, receipts[i].Logs[j].BlockNumber, number.Uint64())
			}
			if receipts[i].Logs[j].BlockHash != hash {
				t.Errorf("receipts[%d].Logs[%d].BlockHash = %s, want %s", i, j, receipts[i].Logs[j].BlockHash.String(), hash.String())
			}
			if receipts[i].Logs[j].TxHash != txs[i].Hash() {
				t.Errorf("receipts[%d].Logs[%d].TxHash = %s, want %s", i, j, receipts[i].Logs[j].TxHash.String(), txs[i].Hash().String())
			}
			if receipts[i].Logs[j].TxIndex != uint(i) {
				t.Errorf("receipts[%d].Logs[%d].TransactionIndex = %d, want %d", i, j, receipts[i].Logs[j].TxIndex, i)
			}
			if receipts[i].Logs[j].Index != logIndex {
				t.Errorf("receipts[%d].Logs[%d].Index = %d, want %d", i, j, receipts[i].Logs[j].Index, logIndex)
			}
			logIndex++
		}
	}
}

// failingIterator wraps an iterator so that it stops feeding keys after limit
// items and then reports err, imitating a database that aborts the walk halfway.
type failingIterator struct {
	inner ethdb.Iterator
	limit int
	err   error
}

func (it *failingIterator) Next() bool {
	if it.limit <= 0 {
		return false
	}
	if !it.inner.Next() {
		return false
	}
	it.limit--
	return true
}

func (it *failingIterator) Error() error {
	if it.limit <= 0 {
		return it.err
	}
	return it.inner.Error()
}

func (it *failingIterator) Key() []byte   { return it.inner.Key() }
func (it *failingIterator) Value() []byte { return it.inner.Value() }
func (it *failingIterator) Release()      { it.inner.Release() }

// failingIterStore hands out failingIterator instances over a backing database.
type failingIterStore struct {
	ethdb.Database
	limit int
	err   error
}

func (db *failingIterStore) NewIterator(prefix, start []byte) ethdb.Iterator {
	return &failingIterator{inner: db.Database.NewIterator(prefix, start), limit: db.limit, err: db.err}
}

// writeOrphanHeaders writes count headers at the heights immediately above head.
// Each header comes with the total-difficulty entry and the canonical marker that
// a real import would have left next to it, so a sweep that drops the header but
// keeps either of the two is observable.
func writeOrphanHeaders(db ethdb.KeyValueWriter, head uint64, count int) []*types.Header {
	headers := make([]*types.Header, 0, count)
	for i := 1; i <= count; i++ {
		number := head + uint64(i)
		header := &types.Header{Number: new(big.Int).SetUint64(number)}
		WriteHeader(db, header)
		WriteTd(db, header.Hash(), number, big.NewInt(int64(i+1)))
		WriteCanonicalHash(db, header.Hash(), number)
		headers = append(headers, header)
	}
	return headers
}

// TestDeleteDanglingHashesIteratorError checks that a keyspace walk the database
// aborts halfway is reported, instead of being mistaken for a completed sweep,
// and that the heights the aborted walk never reached keep their entries.
func TestDeleteDanglingHashesIteratorError(t *testing.T) {
	db := NewMemoryDatabase()
	defer db.Close()
	headers := writeOrphanHeaders(db, 10, 5)

	walkErr := errors.New("iterator failed")
	store := &failingIterStore{Database: db, limit: 1, err: walkErr}
	if err := DeleteDanglingHashes(store, 10, nil); !errors.Is(err, walkErr) {
		t.Fatalf("expected the iterator error to be returned, got %v", err)
	}
	// The walk stopped after the first key, so every height it never reached
	// still holds all three entries the fixture wrote: reporting the error only
	// after sweeping the keyspace to the end and committing the batch - which
	// looks like a completed sweep that happens to fail - would have removed
	// them, and this loop catches that.
	for _, header := range headers[1:] {
		number := header.Number.Uint64()
		if entry := ReadHeader(db, header.Hash(), number); entry == nil {
			t.Fatalf("header %d was removed by an aborted sweep", header.Number)
		}
		if td := ReadTd(db, header.Hash(), number); td == nil {
			t.Fatalf("total difficulty of block %d was removed by an aborted sweep", header.Number)
		}
		if marker := ReadCanonicalHash(db, number); marker == (common.Hash{}) {
			t.Fatalf("canonical marker of height %d was removed by an aborted sweep", header.Number)
		}
	}
}

// TestDeleteDanglingHashesCleanWalk covers the other half of the boundary: a walk
// that runs to the end returns no error and still removes every orphaned header,
// along with the total-difficulty entry and the canonical marker beside it.
func TestDeleteDanglingHashesCleanWalk(t *testing.T) {
	db := NewMemoryDatabase()
	defer db.Close()
	headers := writeOrphanHeaders(db, 10, 5)

	if err := DeleteDanglingHashes(db, 10, nil); err != nil {
		t.Fatalf("clean walk returned an error: %v", err)
	}
	for _, header := range headers {
		number := header.Number.Uint64()
		if entry := ReadHeader(db, header.Hash(), number); entry != nil {
			t.Fatalf("header %d survived the sweep", header.Number)
		}
		if td := ReadTd(db, header.Hash(), number); td != nil {
			t.Fatalf("total difficulty of block %d survived the sweep", header.Number)
		}
		if marker := ReadCanonicalHash(db, number); marker != (common.Hash{}) {
			t.Fatalf("canonical marker of height %d survived the sweep: %s", header.Number, marker)
		}
	}
}

// TestDeleteCanonicalHashesAbove checks that the purge removes every assignment
// above head, including one at a height whose header key is already gone, while
// leaving lower assignments and the neighbouring header, TD and transaction
// lookup entries alone. A lookup is resolved through the assignment at its
// height, so one above the head is inert once the assignment is gone; deleting
// it as well would take the lookup of a transaction that a canonical block below
// the head still indexes.
func TestDeleteCanonicalHashesAbove(t *testing.T) {
	db := NewMemoryDatabase()
	defer db.Close()

	// A hole at 2: a contiguous walk would stop there and leave 4 behind
	for _, number := range []uint64{0, 1, 4} {
		WriteCanonicalHash(db, common.Hash{0: byte(number + 1)}, number)
	}
	// Header, TD, body and transaction lookup at height 3 must survive: the purge
	// only touches assignments, and a lookup whose block is still canonical below
	// the head has to stay.
	header := &types.Header{Number: new(big.Int).SetUint64(3)}
	block := types.NewBlockWithHeader(header).WithBody(types.Body{
		Transactions: []*types.Transaction{types.NewTransaction(0, common.Address{0xaa}, big.NewInt(0), params.TxGas, big.NewInt(1), nil)},
	})
	WriteBlock(db, block)
	WriteTd(db, block.Hash(), 3, big.NewInt(3))
	WriteCanonicalHash(db, block.Hash(), 3)
	WriteTxLookupEntriesByBlock(db, block)
	// A header above the head must not end the walk: its leading number byte is
	// zero, and the assignment at 7 sorts after it, so a walk that stops at the
	// first non-assignment key would leave 7 behind.
	WriteHeader(db, &types.Header{Number: new(big.Int).SetUint64(6)})
	WriteCanonicalHash(db, common.Hash{0: 0x07}, 7)

	removed, bound, err := DeleteCanonicalHashesAbove(db, 1, 0)
	if err != nil {
		t.Fatalf("purge returned an error: %v", err)
	}
	if want := uint64(3); removed != want {
		t.Fatalf("unexpected removed count: have %d want %d", removed, want)
	}
	if want := uint64(7); bound != want {
		t.Fatalf("unexpected highest removed assignment: have #%d want #%d", bound, want)
	}
	// The sweep commits the bound with the deletion batches.
	if persisted, err := ReadSweptCanonicalBound(db); err != nil || persisted != bound {
		t.Fatalf("bound after the sweep: have #%d err %v, want #%d", persisted, err, bound)
	}
	// Every dropped assignment is recorded at its own height, with the hash the
	// assignment named, so a replay can match the header exactly.
	for _, want := range []struct {
		number uint64
		hash   common.Hash
	}{
		{3, block.Hash()}, {4, common.Hash{0: 5}}, {7, common.Hash{0: 0x07}},
	} {
		hash, ok, err := ReadSweptCanonicalHash(db, want.number)
		if err != nil || !ok || hash != want.hash {
			t.Fatalf("record at #%d: have %s ok=%t err %v, want %s", want.number, hash, ok, err, want.hash)
		}
	}
	for _, number := range []uint64{0, 1, 5} {
		if _, ok, err := ReadSweptCanonicalHash(db, number); err != nil || ok {
			t.Fatalf("record at #%d: have ok=%t err %v, want absent", number, ok, err)
		}
	}
	for _, number := range []uint64{0, 1} {
		if marker := ReadCanonicalHash(db, number); marker == (common.Hash{}) {
			t.Fatalf("canonical marker of height %d was removed: it is at or below head", number)
		}
	}
	for _, number := range []uint64{3, 4, 7} {
		if marker := ReadCanonicalHash(db, number); marker != (common.Hash{}) {
			t.Fatalf("canonical marker of height %d survived the purge: %s", number, marker)
		}
	}
	if entry := ReadHeader(db, header.Hash(), 3); entry == nil {
		t.Fatalf("the purge removed the header at height 3")
	}
	if entry := ReadHeader(db, (&types.Header{Number: big.NewInt(6)}).Hash(), 6); entry == nil {
		t.Fatalf("the purge removed the header at height 6")
	}
	if td := ReadTd(db, header.Hash(), 3); td == nil {
		t.Fatalf("the purge removed the total difficulty at height 3")
	}
	if entry := ReadTxLookupEntry(db, block.Transactions()[0].Hash()); entry == nil || *entry != 3 {
		t.Fatalf("the purge removed the transaction lookup of height 3: %v", entry)
	}
	// A second run over an empty range removes nothing and keeps the bound.
	if removed, again, err := DeleteCanonicalHashesAbove(db, 1, bound); err != nil || removed != 0 || again != bound {
		t.Fatalf("second run: removed %d bound #%d err %v, want 0 #%d nil", removed, again, err, bound)
	}
	// head == max must not wrap into a walk from the start of the keyspace
	WriteCanonicalHash(db, common.Hash{0: 0xff}, 5)
	if removed, again, err := DeleteCanonicalHashesAbove(db, ^uint64(0), bound); err != nil || removed != 0 || again != bound {
		t.Fatalf("head=max: removed %d bound #%d err %v, want 0 #%d nil", removed, again, err, bound)
	}
	if marker := ReadCanonicalHash(db, 5); marker == (common.Hash{}) {
		t.Fatalf("head=max removed the canonical marker of height 5")
	}
}

// TestSweptCanonicalBoundRoundTrip checks the recovery bound the startup sweep
// persists for the next start.
func TestSweptCanonicalBoundRoundTrip(t *testing.T) {
	db := NewMemoryDatabase()
	defer db.Close()

	if got, err := ReadSweptCanonicalBound(db); err != nil || got != 0 {
		t.Fatalf("empty database: have #%d err %v, want zero", got, err)
	}
	if err := WriteSweptCanonicalBound(db, 13); err != nil {
		t.Fatalf("failed to write the bound: %v", err)
	}
	if got, err := ReadSweptCanonicalBound(db); err != nil || got != 13 {
		t.Fatalf("bound after write: have #%d err %v, want #13", got, err)
	}
	if err := DeleteSweptCanonicalHashes(db); err != nil {
		t.Fatalf("failed to delete the bound: %v", err)
	}
	if got, err := ReadSweptCanonicalBound(db); err != nil || got != 0 {
		t.Fatalf("bound after delete: have #%d err %v, want zero", got, err)
	}
	// A malformed record has to be reported, not read as a height.
	for _, data := range [][]byte{{1, 2, 3}, make([]byte, 8+common.HashLength)} {
		if err := db.Put(sweptCanonicalBoundKey, data); err != nil {
			t.Fatalf("failed to write the malformed bound: %v", err)
		}
		if _, err := ReadSweptCanonicalBound(db); err == nil {
			t.Fatalf("malformed bound of %d bytes read without an error", len(data))
		}
	}
	// A read failure is not an absent record: the restore point would be retired
	// silently if it were read as one.
	wantErr := errors.New("boom")
	if _, err := ReadSweptCanonicalBound(&errorReader{hasResult: true, getErr: wantErr}); !errors.Is(err, wantErr) {
		t.Fatalf("read error not propagated: %v", err)
	}
	if got, err := ReadSweptCanonicalBound(&errorReader{hasResult: false, getErr: wantErr}); err != nil || got != 0 {
		t.Fatalf("absent bound: have #%d err %v, want zero nil", got, err)
	}
}

// TestSweptCanonicalHashRoundTrip checks the per-height records the startup sweep
// writes for the replay to match against.
func TestSweptCanonicalHashRoundTrip(t *testing.T) {
	db := NewMemoryDatabase()
	defer db.Close()

	if _, ok, err := ReadSweptCanonicalHash(db, 7); err != nil || ok {
		t.Fatalf("empty database: have ok=%t err %v, want absent", ok, err)
	}
	want := common.Hash{0: 0x07}
	if err := WriteSweptCanonicalHash(db, 7, want); err != nil {
		t.Fatalf("failed to write the record: %v", err)
	}
	if got, ok, err := ReadSweptCanonicalHash(db, 7); err != nil || !ok || got != want {
		t.Fatalf("record after write: have %s ok=%t err %v, want %s", got, ok, err, want)
	}
	// A malformed record has to be reported, not read as a hash.
	if err := db.Put(sweptCanonicalKey(8), []byte{1, 2, 3}); err != nil {
		t.Fatalf("failed to write the malformed record: %v", err)
	}
	if _, ok, err := ReadSweptCanonicalHash(db, 8); err == nil || ok {
		t.Fatalf("malformed record read without an error: ok=%t err %v", ok, err)
	}
	// A read failure is not an absent record.
	wantErr := errors.New("boom")
	if _, ok, err := ReadSweptCanonicalHash(&errorReader{hasResult: true, getErr: wantErr}, 7); !errors.Is(err, wantErr) || ok {
		t.Fatalf("read error not propagated: ok=%t err %v", ok, err)
	}
	if _, ok, err := ReadSweptCanonicalHash(&errorReader{hasResult: false, getErr: wantErr}, 7); err != nil || ok {
		t.Fatalf("absent record: have ok=%t err %v, want absent nil", ok, err)
	}
}

// TestDeleteCanonicalHashesAboveKeepsHigherBound covers a sweep that drops less
// than the pending bound: the records below it are still pending, so the higher
// bound survives.
func TestDeleteCanonicalHashesAboveKeepsHigherBound(t *testing.T) {
	db := NewMemoryDatabase()
	defer db.Close()

	for number := uint64(1); number <= 6; number++ {
		WriteCanonicalHash(db, common.Hash{0: byte(number)}, number)
	}
	removed, bound, err := DeleteCanonicalHashesAbove(db, 3, 10)
	if err != nil {
		t.Fatalf("purge returned an error: %v", err)
	}
	if removed != 3 {
		t.Fatalf("unexpected removed count: have %d want 3", removed)
	}
	if bound != 10 {
		t.Fatalf("the sweep shrank the pending bound: have #%d want #10", bound)
	}
	if persisted, err := ReadSweptCanonicalBound(db); err != nil || persisted != 10 {
		t.Fatalf("bound after the sweep: have #%d err %v, want #10", persisted, err)
	}
	// The records of the heights this sweep dropped are written regardless of the
	// higher pending bound: the replay matches them by height and hash.
	for _, number := range []uint64{4, 5, 6} {
		if hash, ok, err := ReadSweptCanonicalHash(db, number); err != nil || !ok || hash != (common.Hash{0: byte(number)}) {
			t.Fatalf("record at #%d: have %s ok=%t err %v, want %s", number, hash, ok, err, common.Hash{0: byte(number)})
		}
	}
}

// TestPruneSweptCanonicalHashes checks that a head advance spends the records it
// passed and keeps the ones still pending.
func TestPruneSweptCanonicalHashes(t *testing.T) {
	db := NewMemoryDatabase()
	defer db.Close()

	for number := uint64(4); number <= 6; number++ {
		if err := WriteSweptCanonicalHash(db, number, common.Hash{0: byte(number)}); err != nil {
			t.Fatalf("failed to write the record at #%d: %v", number, err)
		}
	}
	if err := WriteSweptCanonicalBound(db, 6); err != nil {
		t.Fatalf("failed to write the bound: %v", err)
	}
	if err := PruneSweptCanonicalHashes(db, 5); err != nil {
		t.Fatalf("failed to prune the records: %v", err)
	}
	for _, number := range []uint64{4, 5} {
		if _, ok, err := ReadSweptCanonicalHash(db, number); err != nil || ok {
			t.Fatalf("record at #%d survived the prune: ok=%t err %v", number, ok, err)
		}
	}
	if _, ok, err := ReadSweptCanonicalHash(db, 6); err != nil || !ok {
		t.Fatalf("record at #6 dropped by the prune: ok=%t err %v", ok, err)
	}
	if bound, err := ReadSweptCanonicalBound(db); err != nil || bound != 6 {
		t.Fatalf("bound changed by a partial prune: have #%d err %v, want #6", bound, err)
	}
	if err := DeleteSweptCanonicalHashes(db); err != nil {
		t.Fatalf("failed to clear the records: %v", err)
	}
	if _, ok, err := ReadSweptCanonicalHash(db, 6); err != nil || ok {
		t.Fatalf("record at #6 survived the clear: ok=%t err %v", ok, err)
	}
	if bound, err := ReadSweptCanonicalBound(db); err != nil || bound != 0 {
		t.Fatalf("bound survived the clear: have #%d err %v, want zero", bound, err)
	}
}

// TestPurgeCanonicalHashesAboveDoesNotRecord checks the Reset variant: it drops
// every assignment without writing records the caller would delete right away.
func TestPurgeCanonicalHashesAboveDoesNotRecord(t *testing.T) {
	db := NewMemoryDatabase()
	defer db.Close()

	for number := uint64(1); number <= 3; number++ {
		WriteCanonicalHash(db, common.Hash{0: byte(number)}, number)
	}
	if err := PurgeCanonicalHashesAbove(db, 1); err != nil {
		t.Fatalf("purge returned an error: %v", err)
	}
	for _, number := range []uint64{2, 3} {
		if marker := ReadCanonicalHash(db, number); marker != (common.Hash{}) {
			t.Fatalf("assignment at #%d survived the purge: %s", number, marker)
		}
		if _, ok, err := ReadSweptCanonicalHash(db, number); err != nil || ok {
			t.Fatalf("purge recorded #%d: ok=%t err %v", number, ok, err)
		}
	}
	if bound, err := ReadSweptCanonicalBound(db); err != nil || bound != 0 {
		t.Fatalf("purge wrote a bound: have #%d err %v, want zero", bound, err)
	}
}

// failingBatchDB shapes the batches the sweep writes: the batch reports itself
// full after a few deletions, so the intermediate flush path runs on a small
// database, and the configured write fails, so the crash window between two
// deletion batches can be replayed without a real crash.
type failingBatchDB struct {
	ethdb.KeyValueStore
	failAt int
	writes int
}

func (db *failingBatchDB) NewBatch() ethdb.Batch {
	return &failingBatch{Batch: db.KeyValueStore.NewBatch(), db: db}
}

type failingBatch struct {
	ethdb.Batch
	db      *failingBatchDB
	deletes int
}

func (b *failingBatch) Delete(key []byte) error {
	err := b.Batch.Delete(key)
	b.deletes++
	return err
}

func (b *failingBatch) ValueSize() int {
	if b.deletes >= 4 {
		return ethdb.IdealBatchSize
	}
	return b.Batch.ValueSize()
}

func (b *failingBatch) Reset() {
	b.Batch.Reset()
	b.deletes = 0
}

func (b *failingBatch) Write() error {
	b.db.writes++
	if b.db.writes == b.db.failAt {
		return errors.New("simulated crash between deletion batches")
	}
	return b.Batch.Write()
}

// TestDeleteCanonicalHashesAboveRecordsBoundPerBatch pins the records to every
// deletion batch: a crash after an intermediate flush still leaves the bound and
// the per-height records of the assignments committed with it, and the next
// sweep covers the rest.
func TestDeleteCanonicalHashesAboveRecordsBoundPerBatch(t *testing.T) {
	db := NewMemoryDatabase()
	defer db.Close()

	total := uint64(10)
	for number := uint64(1); number <= total; number++ {
		WriteCanonicalHash(db, common.Hash{0: byte(number)}, number)
	}
	wrapped := &failingBatchDB{KeyValueStore: db, failAt: 2}
	if _, _, err := DeleteCanonicalHashesAbove(wrapped, 3, 0); err == nil {
		t.Fatal("the interrupted sweep returned no error")
	}
	bound, err := ReadSweptCanonicalBound(db)
	if err != nil {
		t.Fatalf("failed to read the bound of the interrupted sweep: %v", err)
	}
	if bound <= 3 || bound >= total {
		t.Fatalf("bound after the interrupted sweep: have #%d, want an intermediate height in (%d, %d)", bound, 3, total)
	}
	// The assignment the bound names was committed with its record; the ones of
	// the failed batch are still on disk, without a record.
	if marker := ReadCanonicalHash(db, bound); marker != (common.Hash{}) {
		t.Fatalf("assignment at #%d survived the flush that recorded it: %s", bound, marker)
	}
	if hash, ok, err := ReadSweptCanonicalHash(db, bound); err != nil || !ok || hash != (common.Hash{0: byte(bound)}) {
		t.Fatalf("record at #%d: have %s ok=%t err %v", bound, hash, ok, err)
	}
	if marker := ReadCanonicalHash(db, total); marker == (common.Hash{}) {
		t.Fatalf("assignment at #%d was committed without its record", total)
	}
	if _, ok, err := ReadSweptCanonicalHash(db, total); err != nil || ok {
		t.Fatalf("record at #%d exists before its deletion was committed: ok=%t err %v", total, ok, err)
	}
	// The next startup sweeps the rest and raises the bound to the true top.
	removed, rest, err := DeleteCanonicalHashesAbove(db, 3, bound)
	if err != nil {
		t.Fatalf("second sweep returned an error: %v", err)
	}
	if removed == 0 || rest != total {
		t.Fatalf("second sweep: removed %d bound #%d, want the rest and #%d", removed, rest, total)
	}
	if hash, ok, err := ReadSweptCanonicalHash(db, total); err != nil || !ok || hash != (common.Hash{0: byte(total)}) {
		t.Fatalf("record at #%d after the second sweep: have %s ok=%t err %v", total, hash, ok, err)
	}
}

// countingIteratorDB counts the keys iterated on a database, so a regression
// that drops the early stop of a keyspace walk shows up as a proportional step
// count.
type countingIteratorDB struct {
	ethdb.KeyValueStore
	steps *int
}

func (db *countingIteratorDB) NewIterator(prefix []byte, start []byte) ethdb.Iterator {
	return &countingIterator{Iterator: db.KeyValueStore.NewIterator(prefix, start), steps: db.steps}
}

type countingIterator struct {
	ethdb.Iterator
	steps *int
}

func (it *countingIterator) Next() bool {
	*it.steps = *it.steps + 1
	return it.Iterator.Next()
}

// TestDeleteCanonicalHashesAboveStopsScanning checks that the purge stops at the
// end of the canonical-hash range instead of reading the legacy trie nodes that
// share the "h" prefix, while still removing every assignment above the head.
func TestDeleteCanonicalHashesAboveStopsScanning(t *testing.T) {
	db := NewMemoryDatabase()
	defer db.Close()

	// Legacy hash-scheme trie nodes are stored under their bare 32-byte hash.
	// Plant the slice of them that shares the "h" prefix and sorts after the
	// canonical assignments, plus one whose leading number bytes are all zero
	// and whose remaining bytes spell a number between the assignments at 9 and
	// 300: its length alone must not end the walk, and the assignment behind it
	// still has to be removed.
	const planted = 100000
	for i := 0; i < planted; i++ {
		var key common.Hash
		key[0] = 'h'
		key[1] = byte(i>>16) + 1 // non-zero leading number byte
		key[2] = byte(i >> 8)
		key[3] = byte(i)
		if err := db.Put(key[:], []byte{1}); err != nil {
			t.Fatalf("failed to plant trie node %d: %v", i, err)
		}
	}
	var inside common.Hash
	inside[0] = 'h'
	inside[7] = 0x01 // number field reads 265, between the assignments at 9 and 300
	inside[8] = 0x09
	inside[9] = 0xff // sorts after the assignment at 9, whose key ends in "n"
	if err := db.Put(inside[:], []byte{1}); err != nil {
		t.Fatalf("failed to plant trie node inside the number range: %v", err)
	}
	for _, number := range []uint64{1, 2, 9, 300} {
		WriteCanonicalHash(db, common.Hash{0: byte(number)}, number)
	}
	steps := 0
	removed, bound, err := DeleteCanonicalHashesAbove(&countingIteratorDB{KeyValueStore: db, steps: &steps}, 3, 0)
	if err != nil {
		t.Fatalf("purge returned an error: %v", err)
	}
	if want := uint64(2); removed != want {
		t.Fatalf("unexpected removed count: have %d want %d", removed, want)
	}
	if want := uint64(300); bound != want {
		t.Fatalf("unexpected highest removed assignment: have #%d want #%d", bound, want)
	}
	for _, number := range []uint64{9, 300} {
		if marker := ReadCanonicalHash(db, number); marker != (common.Hash{}) {
			t.Fatalf("canonical marker of height %d survived the purge: %s", number, marker)
		}
	}
	// A walk that runs through the planted slice reads all of it.
	if steps > 100 {
		t.Fatalf("purge walked %d keys, want a scan bounded by the canonical range", steps)
	}
}

// BenchmarkDecodeRLPLogs benchmarks decode rlp logs.
func BenchmarkDecodeRLPLogs(b *testing.B) {
	// Encoded receipts from block 0x14ee094309fbe8f70b65f45ebcc08fb33f126942d97464aad5eb91cfd1e2d269
	buf, err := os.ReadFile("testdata/stored_receipts.bin")
	if err != nil {
		b.Fatal(err)
	}
	b.Run("ReceiptForStorage", func(b *testing.B) {
		b.ReportAllocs()
		var r []*types.ReceiptForStorage
		for i := 0; i < b.N; i++ {
			if err := rlp.DecodeBytes(buf, &r); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("rlpLogs", func(b *testing.B) {
		b.ReportAllocs()
		var r []*receiptLogs
		for i := 0; i < b.N; i++ {
			if err := rlp.DecodeBytes(buf, &r); err != nil {
				b.Fatal(err)
			}
		}
	})
}
