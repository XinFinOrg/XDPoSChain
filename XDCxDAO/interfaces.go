// Copyright 2019 The XDPoSChain Authors
// This file is part of the Core XDPoSChain infrastructure
// https://XDPoSChain.com
// Package XDCxDAO provides an interface to work with XDCx database, including leveldb for masternode and mongodb for SDK node

package XDCxDAO

import (
	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
)

const defaultCacheLimit = 1024

type XDCXDAO interface {
	// for both leveldb and mongodb
	IsEmptyKey(key []byte) bool
	Close() error
	GetObject(hash common.Hash, val interface{}) (interface{}, error)

	// basic XDCx
	InitBulk()
	CommitBulk() error

	// XDCx lending
	InitLendingBulk()
	CommitLendingBulk() error

	// leveldb methods
	Put(key []byte, value []byte) error
	Get(key []byte) ([]byte, error)
	Has(key []byte) (bool, error)
	Delete(key []byte) error
	NewBatch() ethdb.Batch
	NewBatchWithSize(size int) ethdb.Batch
	Ancient(kind string, number uint64) ([]byte, error)
	AncientRange(kind string, start, count, maxBytes uint64) ([][]byte, error)
	AncientBytes(kind string, id, offset, length uint64) ([]byte, error)
	Ancients() (uint64, error)
	Tail(group string) (uint64, error)
	AncientSize(kind string) (uint64, error)
	ReadAncients(fn func(ethdb.AncientReaderOp) error) error
	ModifyAncients(func(ethdb.AncientWriteOp) error) (int64, error)
	TruncateHead(n uint64) (uint64, error)
	TruncateTail(group string, n uint64) (uint64, error)
	SyncAncient() error
	AncientDatadir() (string, error)
	NewIterator(prefix []byte, start []byte) ethdb.Iterator

	Stat(property string) (string, error)
	Compact(start []byte, limit []byte) error
}

// use alloc to prevent reference manipulation
func EmptyKey() []byte {
	key := make([]byte, common.HashLength)
	return key
}
