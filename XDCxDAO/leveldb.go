package XDCxDAO

import (
	"bytes"
	"errors"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/log"
)

type BatchItem struct {
	Value interface{}
}

type BatchDatabase struct {
	db         ethdb.Database
	emptyKey   []byte
	cacheLimit int
	Debug      bool
}

// NewBatchDatabase use rlp as encoding
func NewBatchDatabase(datadir string, cacheLimit int) *BatchDatabase {
	return NewBatchDatabaseWithEncode(datadir, cacheLimit)
}

// batchdatabase is a fast cache db to retrieve in-mem object
func NewBatchDatabaseWithEncode(datadir string, cacheLimit int) *BatchDatabase {
	db, err := rawdb.NewLevelDBDatabase(datadir, 128, 1024, "", false)
	if err != nil {
		log.Error("Can't create new DB", "error", err)
		return nil
	}
	itemCacheLimit := defaultCacheLimit
	if cacheLimit > 0 {
		itemCacheLimit = cacheLimit
	}

	batchDB := &BatchDatabase{
		db:         db,
		emptyKey:   EmptyKey(), // pre alloc for comparison
		cacheLimit: itemCacheLimit,
	}

	return batchDB
}

func (db *BatchDatabase) IsEmptyKey(key []byte) bool {
	return len(key) == 0 || bytes.Equal(key, db.emptyKey)
}

func (db *BatchDatabase) GetObject(hash common.Hash, val interface{}) (interface{}, error) {
	return nil, nil
}

func (db *BatchDatabase) Put(key []byte, val []byte) error {
	return db.db.Put(key, val)
}

func (db *BatchDatabase) Delete(key []byte) error {
	return db.db.Delete(key)
}

func (db *BatchDatabase) Has(key []byte) (bool, error) {
	return db.db.Has(key)
}

func (db *BatchDatabase) Get(key []byte) ([]byte, error) {
	return db.db.Get(key)
}

func (db *BatchDatabase) Close() error {
	return db.db.Close()
}

func (db *BatchDatabase) NewBatch() ethdb.Batch {
	return db.db.NewBatch()
}

func (db *BatchDatabase) NewBatchWithSize(size int) ethdb.Batch {
	return db.db.NewBatch()
}

func (db *BatchDatabase) DeleteItemByTxHash(txhash common.Hash, val interface{}) {
}

func (db *BatchDatabase) GetListItemByTxHash(txhash common.Hash, val interface{}) interface{} {
	return []interface{}{}
}

func (db *BatchDatabase) GetListItemByHashes(hashes []string, val interface{}) interface{} {
	return []interface{}{}
}

func (db *BatchDatabase) InitBulk() {
}

func (db *BatchDatabase) CommitBulk() error {
	return nil
}

func (db *BatchDatabase) InitLendingBulk() {
}

func (db *BatchDatabase) CommitLendingBulk() error {
	return nil
}

var errNotSupported = errors.New("this operation is not supported")

// The XDCx order/lending store has no chain freezer; every ancient operation is
// unsupported. The methods exist only to satisfy ethdb.Database.

// Ancient returns an error as we don't have a backing chain freezer.
func (db *BatchDatabase) Ancient(kind string, number uint64) ([]byte, error) {
	return nil, errNotSupported
}

// AncientRange returns an error as we don't have a backing chain freezer.
func (db *BatchDatabase) AncientRange(kind string, start, count, maxBytes uint64) ([][]byte, error) {
	return nil, errNotSupported
}

// AncientBytes returns an error as we don't have a backing chain freezer.
func (db *BatchDatabase) AncientBytes(kind string, id, offset, length uint64) ([]byte, error) {
	return nil, errNotSupported
}

// Ancients returns an error as we don't have a backing chain freezer.
func (db *BatchDatabase) Ancients() (uint64, error) {
	return 0, errNotSupported
}

// Tail returns an error as we don't have a backing chain freezer.
func (db *BatchDatabase) Tail(group string) (uint64, error) {
	return 0, errNotSupported
}

// AncientSize returns an error as we don't have a backing chain freezer.
func (db *BatchDatabase) AncientSize(kind string) (uint64, error) {
	return 0, errNotSupported
}

// ReadAncients runs the given function against this store. It deliberately does
// not return errNotSupported so that callers can probe the ancient store and
// fall back to the key-value store within a single closure.
func (db *BatchDatabase) ReadAncients(fn func(ethdb.AncientReaderOp) error) error {
	return fn(db)
}

// ModifyAncients returns an error as we don't have a backing chain freezer.
func (db *BatchDatabase) ModifyAncients(func(ethdb.AncientWriteOp) error) (int64, error) {
	return 0, errNotSupported
}

// TruncateHead returns an error as we don't have a backing chain freezer.
func (db *BatchDatabase) TruncateHead(items uint64) (uint64, error) {
	return 0, errNotSupported
}

// TruncateTail returns an error as we don't have a backing chain freezer.
func (db *BatchDatabase) TruncateTail(group string, items uint64) (uint64, error) {
	return 0, errNotSupported
}

// SyncAncient returns an error as we don't have a backing chain freezer.
func (db *BatchDatabase) SyncAncient() error {
	return errNotSupported
}

// AncientDatadir returns an error as we don't have a backing chain freezer.
func (db *BatchDatabase) AncientDatadir() (string, error) {
	return "", errNotSupported
}

func (db *BatchDatabase) NewIterator(prefix []byte, start []byte) ethdb.Iterator {
	panic("NewIterator from XDCxDAO leveldb is not supported")
}

func (db *BatchDatabase) Stat(property string) (string, error) {
	return "", errNotSupported
}

func (db *BatchDatabase) Compact(start []byte, limit []byte) error {
	return errNotSupported
}
