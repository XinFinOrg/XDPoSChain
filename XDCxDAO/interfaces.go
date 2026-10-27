// Copyright 2019 The XDPoSChain Authors
// This file is part of the Core XDPoSChain infrastructure
// https://XDPoSChain.com
// Package XDCxDAO provides an interface to work with XDCx database backed by leveldb

package XDCxDAO

import (
	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
)

const defaultCacheLimit = 1024

type XDCXDAO interface {
	IsEmptyKey(key []byte) bool
	Close() error

	// leveldb methods
	Put(key []byte, value []byte) error
	Get(key []byte) ([]byte, error)
	Has(key []byte) (bool, error)
	Delete(key []byte) error
	NewBatch() ethdb.Batch
	NewBatchWithSize(size int) ethdb.Batch
	HasAncient(kind string, number uint64) (bool, error)
	Ancient(kind string, number uint64) ([]byte, error)
	Ancients() (uint64, error)
	AncientSize(kind string) (uint64, error)
	AppendAncient(number uint64, hash, header, body, receipt, td []byte) error
	TruncateAncients(n uint64) error
	Sync() error
	NewIterator(prefix []byte, start []byte) ethdb.Iterator

	Stat(property string) (string, error)
	Compact(start []byte, limit []byte) error
}

// use alloc to prevent reference manipulation
func EmptyKey() []byte {
	key := make([]byte, common.HashLength)
	return key
}
