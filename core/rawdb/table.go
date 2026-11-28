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
	"errors"

	"github.com/XinFinOrg/XDPoSChain/ethdb"
)

// table is a wrapper around a database that prefixes each key access with a pre-
// configured string.
type table struct {
	db     ethdb.Database
	prefix string
}

// NewTable returns a database object that prefixes all keys with a given string.
func NewTable(db ethdb.Database, prefix string) ethdb.Database {
	return &table{
		db:     db,
		prefix: prefix,
	}
}

// Close is a noop to implement the Database interface.
func (t *table) Close() error {
	return nil
}

// Has retrieves if a prefixed version of a key is present in the database.
func (t *table) Has(key []byte) (bool, error) {
	return t.db.Has(append([]byte(t.prefix), key...))
}

// Get retrieves the given prefixed key if it's present in the database.
func (t *table) Get(key []byte) ([]byte, error) {
	return t.db.Get(append([]byte(t.prefix), key...))
}

// HasAncient is a noop passthrough that just forwards the request to the underlying
// database.
func (t *table) HasAncient(kind string, number uint64) (bool, error) {
	return t.db.HasAncient(kind, number)
}

// Ancient is a noop passthrough that just forwards the request to the underlying
// database.
func (t *table) Ancient(kind string, number uint64) ([]byte, error) {
	return t.db.Ancient(kind, number)
}

// Ancients is a noop passthrough that just forwards the request to the underlying
// database.
func (t *table) Ancients() (uint64, error) {
	return t.db.Ancients()
}

// AncientSize is a noop passthrough that just forwards the request to the underlying
// database.
func (t *table) AncientSize(kind string) (uint64, error) {
	return t.db.AncientSize(kind)
}

// AppendAncient is a noop passthrough that just forwards the request to the underlying
// database.
func (t *table) AppendAncient(number uint64, hash, header, body, receipts, td []byte) error {
	return t.db.AppendAncient(number, hash, header, body, receipts, td)
}

// TruncateAncients is a noop passthrough that just forwards the request to the underlying
// database.
func (t *table) TruncateAncients(items uint64) error {
	return t.db.TruncateAncients(items)
}

// Sync is a noop passthrough that just forwards the request to the underlying
// database.
func (t *table) Sync() error {
	return t.db.Sync()
}

// Put inserts the given value into the database at a prefixed version of the
// provided key.
func (t *table) Put(key []byte, value []byte) error {
	return t.db.Put(append([]byte(t.prefix), key...), value)
}

// Delete removes the given prefixed key from the database.
func (t *table) Delete(key []byte) error {
	return t.db.Delete(append([]byte(t.prefix), key...))
}

// DeleteRange deletes all of the keys (and values) in the range [start,end)
// (inclusive on start, exclusive on end).
//
// A nil end is rewritten to ethdb.MaximumKey so that adding the prefix does
// not turn an unbounded range into an empty one. The marker has to stay
// relative because tableBatch.Replay strips the source prefix and re-adds the
// destination one, and a computed next-prefix bound would not survive that
// round trip. A table-relative key at or beyond 32 0xFF bytes is therefore
// outside the range and survives.
func (t *table) DeleteRange(start, end []byte) error {
	if end == nil {
		end = ethdb.MaximumKey
	}
	return t.db.DeleteRange(append([]byte(t.prefix), start...), append([]byte(t.prefix), end...))
}

// NewIterator creates a binary-alphabetical iterator over a subset
// of database content with a particular key prefix, starting at a particular
// initial key (or after, if it does not exist).
func (t *table) NewIterator(prefix []byte, start []byte) ethdb.Iterator {
	innerPrefix := append([]byte(t.prefix), prefix...)
	iter := t.db.NewIterator(innerPrefix, start)
	return &tableIterator{
		iter:   iter,
		prefix: t.prefix,
	}
}

// Stat returns a particular internal stat of the database.
func (t *table) Stat(property string) (string, error) {
	return t.db.Stat(property)
}

// Compact flattens the underlying data store for the given key range. In essence,
// deleted and overwritten versions are discarded, and the data is rearranged to
// reduce the cost of operations needed to access them.
//
// A nil start is treated as a key before all keys in the data store; a nil limit
// is treated as a key after all keys in the data store. If both is nil then it
// will compact entire data store.
func (t *table) Compact(start []byte, limit []byte) error {
	// If no start was specified, use the table prefix as the first value
	if start == nil {
		start = []byte(t.prefix)
	}
	// If no limit was specified, use the first element not matching the prefix
	// as the limit
	if limit == nil {
		limit = []byte(t.prefix)
		for i := len(limit) - 1; i >= 0; i-- {
			// Bump the current character, stopping if it doesn't overflow
			limit[i]++
			if limit[i] > 0 {
				break
			}
			// Character overflown, proceed to the next or nil if the last
			if i == 0 {
				limit = nil
			}
		}
	}
	// Range correctly calculated based on table prefix, delegate down
	return t.db.Compact(start, limit)
}

// NewBatch creates a write-only database that buffers changes to its host db
// until a final write is called, each operation prefixing all keys with the
// pre-configured string.
func (t *table) NewBatch() ethdb.Batch {
	return &tableBatch{t.db.NewBatch(), t.prefix}
}

// NewBatchWithSize creates a write-only database batch with pre-allocated buffer.
func (t *table) NewBatchWithSize(size int) ethdb.Batch {
	return &tableBatch{t.db.NewBatchWithSize(size), t.prefix}
}

// tableBatch is a wrapper around a database batch that prefixes each key access
// with a pre-configured string.
type tableBatch struct {
	batch  ethdb.Batch
	prefix string
}

// Put inserts the given value into the batch for later committing.
func (b *tableBatch) Put(key, value []byte) error {
	return b.batch.Put(append([]byte(b.prefix), key...), value)
}

// Delete inserts the a key removal into the batch for later committing.
func (b *tableBatch) Delete(key []byte) error {
	return b.batch.Delete(append([]byte(b.prefix), key...))
}

// DeleteRange removes all keys in the range [start, end) from the batch for later committing.
//
// A nil end becomes ethdb.MaximumKey before the prefix is added so the bounds
// stay relative for replay, which leaves table-relative keys at or beyond
// 32 0xFF bytes outside the range.
func (b *tableBatch) DeleteRange(start, end []byte) error {
	if end == nil {
		end = ethdb.MaximumKey
	}
	return b.batch.DeleteRange(append([]byte(b.prefix), start...), append([]byte(b.prefix), end...))
}

// ValueSize retrieves the amount of data queued up for writing.
func (b *tableBatch) ValueSize() int {
	return b.batch.ValueSize()
}

// Write flushes any accumulated data to disk.
func (b *tableBatch) Write() error {
	return b.batch.Write()
}

// Reset resets the batch for reuse.
func (b *tableBatch) Reset() {
	b.batch.Reset()
}

// tableReplayer is a wrapper around a batch replayer which truncates
// the added prefix.
type tableReplayer struct {
	w      ethdb.KeyValueWriter
	prefix string
}

// Put implements the interface KeyValueWriter.
func (r *tableReplayer) Put(key []byte, value []byte) error {
	trimmed := key[len(r.prefix):]
	return r.w.Put(trimmed, value)
}

// Delete implements the interface KeyValueWriter.
func (r *tableReplayer) Delete(key []byte) error {
	trimmed := key[len(r.prefix):]
	return r.w.Delete(trimmed)
}

// DeleteRange implements the interface KeyValueRangeDeleter.
func (r *tableReplayer) DeleteRange(start, end []byte) error {
	w, ok := r.w.(ethdb.KeyValueRangeDeleter)
	if !ok {
		return errors.New("ethdb.KeyValueWriter does not implement DeleteRange")
	}
	if start != nil {
		start = start[len(r.prefix):]
	}
	if end != nil {
		end = end[len(r.prefix):]
	}
	return w.DeleteRange(start, end)
}

// Replay replays the batch contents into w, stripping the table prefix from
// keys and range bounds, so w must resolve them in its own namespace, as a
// table does. Replaying into the underlying database instead spreads the batch
// over that database's key space: an unbounded table range becomes
// DeleteRange([], MaximumKey) there.
//
// A range deletion only reaches w when the backing batch still holds it. A
// memorydb batch keeps the range, so it is stripped and forwarded, and w
// deletes whatever it holds in it. A leveldb batch has already expanded the
// range into the keys committed when DeleteRange was called, so only those
// point deletions are replayed: a range that matched nothing replays nothing.
func (b *tableBatch) Replay(w ethdb.KeyValueWriter) error {
	return b.batch.Replay(&tableReplayer{w: w, prefix: b.prefix})
}

// tableIterator is a wrapper around a database iterator that prefixes each key access
// with a pre-configured string.
type tableIterator struct {
	iter   ethdb.Iterator
	prefix string
}

// Next moves the iterator to the next key/value pair. It returns whether the
// iterator is exhausted.
func (iter *tableIterator) Next() bool {
	return iter.iter.Next()
}

// Error returns any accumulated error. Exhausting all the key/value pairs
// is not considered to be an error.
func (iter *tableIterator) Error() error {
	return iter.iter.Error()
}

// Key returns the key of the current key/value pair, or nil if done. The caller
// should not modify the contents of the returned slice, and its contents may
// change on the next call to Next.
func (iter *tableIterator) Key() []byte {
	key := iter.iter.Key()
	if key == nil {
		return nil
	}
	return key[len(iter.prefix):]
}

// Value returns the value of the current key/value pair, or nil if done. The
// caller should not modify the contents of the returned slice, and its contents
// may change on the next call to Next.
func (iter *tableIterator) Value() []byte {
	return iter.iter.Value()
}

// Release releases associated resources. Release should always succeed and can
// be called multiple times without causing error.
func (iter *tableIterator) Release() {
	iter.iter.Release()
}
