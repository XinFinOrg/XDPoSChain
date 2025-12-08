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
	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/log"
)

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
