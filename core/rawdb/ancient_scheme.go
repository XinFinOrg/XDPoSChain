// Copyright 2022 The go-ethereum Authors
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

// ported from go-ethereum v1.17.5 core/rawdb/ancient_scheme.go
//
// Deviations from upstream:
//   - The state and trienode freezers are omitted; this fork has no path-based
//     state scheme, so there is no state history to freeze.
//   - The BAL (EIP-7928 block access list) table is omitted.
//   - The total difficulty table ("diffs") is deliberately NOT reintroduced.
//     XDPoS still uses total difficulty, but ReadTdRLP reads it exclusively from
//     the key-value store, so TD is never frozen. See claude/plan §3.4.

package rawdb

// The list of table names of chain freezer.
const (
	// ChainFreezerHeaderTable indicates the name of the freezer header table.
	ChainFreezerHeaderTable = "headers"

	// ChainFreezerHashTable indicates the name of the freezer canonical hash table.
	ChainFreezerHashTable = "hashes"

	// ChainFreezerBodiesTable indicates the name of the freezer block body table.
	ChainFreezerBodiesTable = "bodies"

	// ChainFreezerReceiptTable indicates the name of the freezer receipts table.
	ChainFreezerReceiptTable = "receipts"
)

// Identifiers of tail groups used by the chain freezer.
const (
	// ChainFreezerBlockDataGroup is the tail group shared by the body and
	// receipt tables. The two tables are pruned together and therefore have
	// the same tail position.
	//
	// This group is what "minimal history mode" prunes; see claude/plan §4.
	ChainFreezerBlockDataGroup = "blockdata"
)

// chainFreezerTableConfigs configures the settings for tables in the chain freezer.
// Compression is disabled for hashes as they don't compress well. Additionally,
// tail truncation is disabled for the header and hash tables, as these are intended
// to be retained long-term.
var chainFreezerTableConfigs = map[string]freezerTableConfig{
	ChainFreezerHeaderTable:  {noSnappy: false},
	ChainFreezerHashTable:    {noSnappy: true},
	ChainFreezerBodiesTable:  {noSnappy: false, tailGroup: ChainFreezerBlockDataGroup},
	ChainFreezerReceiptTable: {noSnappy: false, tailGroup: ChainFreezerBlockDataGroup},
}

// freezerTableConfig contains the settings for a freezer table.
type freezerTableConfig struct {
	// noSnappy disables item compression when true.
	noSnappy bool

	// tailGroup names a logical group of tables that share the same tail
	// position. Tables in the same group are pruned together and must agree
	// on their tail. An empty value means the table is not prunable; its
	// tail is always 0.
	tailGroup string
}

// The list of identifiers of ancient stores.
var (
	ChainFreezerName = "chain" // the folder name of chain segment ancient store.
)

// freezers the collections of all builtin freezers.
var freezers = []string{ChainFreezerName}
