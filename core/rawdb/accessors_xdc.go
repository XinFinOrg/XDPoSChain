// Copyright 2025 The XDPoSChain Authors
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

package rawdb

import (
	"encoding/binary"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/log"
)

// ReadXdposV1Snapshot retrieves an existing snapshot from the database.
func ReadXdposV1Snapshot(db ethdb.KeyValueReader, hash common.Hash) ([]byte, error) {
	data, err := db.Get(xdposV1Key(hash))
	if err != nil {
		return nil, err
	}
	return data, nil
}

// WriteXdposV1Snapshot writes the SnapshotV2 into the database.
func WriteXdposV1Snapshot(db ethdb.KeyValueWriter, hash common.Hash, blob []byte) error {
	if err := db.Put(xdposV1Key(hash), blob); err != nil {
		log.Crit("Failed to store SnapshotV2", "err", err)
	}
	return nil
}

// ReadXdposV2Snapshot retrieves an existing snapshot from the database.
func ReadXdposV2Snapshot(db ethdb.KeyValueReader, hash common.Hash) ([]byte, error) {
	data, err := db.Get(xdposV2Key(hash))
	if err != nil {
		return nil, err
	}
	return data, nil
}

// WriteXdposV2Snapshot writes the SnapshotV2 into the database.
func WriteXdposV2Snapshot(db ethdb.KeyValueWriter, hash common.Hash, blob []byte) error {
	if err := db.Put(xdposV2Key(hash), blob); err != nil {
		log.Crit("Failed to store SnapshotV2", "err", err)
	}
	return nil
}

// ReadSectionHead retrieves the last block hash of a processed section
// from the database.
func ReadSectionHead(db ethdb.KeyValueReader, section uint64) common.Hash {
	hash, err := db.Get(sectionHeadKey(section))
	if err != nil || len(hash) != len(common.Hash{}) {
		return common.Hash{}
	}
	return common.BytesToHash(hash)
}

// WriteSectionHead writes the last block hash of a processed section into database.
func WriteSectionHead(db ethdb.KeyValueWriter, section uint64, hash common.Hash) {
	if err := db.Put(sectionHeadKey(section), hash.Bytes()); err != nil {
		log.Crit("Failed to write section head", "err", err)
	}
}

// DeleteectionHead removes the reference to a processed section from the database.
func DeleteectionHead(db ethdb.KeyValueWriter, section uint64) {
	if err := db.Delete(sectionHeadKey(section)); err != nil {
		log.Crit("Failed to delete section head", "err", err)
	}
}

// HasRandomize verifies the existence of randomize.
func HasRandomize(db ethdb.KeyValueReader) bool {
	if has, err := db.Has(randomizeKey); !has || err != nil {
		return false
	}
	return true
}

// ReadRandomize retrieves the randomiz from database.
func ReadRandomize(db ethdb.KeyValueReader) ([]byte, error) {
	data, err := db.Get(randomizeKey)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// WriteRandomize writes the randomize into database.
func WriteRandomize(db ethdb.KeyValueWriter, data []byte) {
	if err := db.Put(randomizeKey, data); err != nil {
		log.Crit("Failed to store randomizeKey", "err", err)
	}
}

// DeleteRandomize deletes the randomize from database.
func DeleteRandomize(db ethdb.KeyValueWriter) {
	if err := db.Delete(randomizeKey); err != nil {
		log.Crit("Failed to delete randomizeKey", "err", err)
	}
}

// ReadValidSections retrieves the number of valid sections from database.
func ReadValidSections(db ethdb.KeyValueReader) *uint64 {
	data, err := db.Get(validSectionsKey)
	if err != nil || len(data) != 8 {
		return nil
	}
	storedSections := binary.BigEndian.Uint64(data[:])
	return &storedSections
}

// WriteValidSections writes the number of valid sections into database
func WriteValidSections(db ethdb.KeyValueWriter, sections uint64) {
	// Set the current number of valid sections in the database
	var data [8]byte
	binary.BigEndian.PutUint64(data[:], sections)
	if err := db.Put(validSectionsKey, data[:]); err != nil {
		log.Crit("Failed to store valid sections", "err", err)
	}
}
