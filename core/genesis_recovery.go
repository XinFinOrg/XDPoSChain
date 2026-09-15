// Copyright 2015 The go-ethereum Authors
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

package core

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/tracing"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/params"
)

type recoveryMode uint8

const (
	recoveryDisabled recoveryMode = iota
	recoveryWritable
)

const GenesisAllocUnavailableRecoveryMessage = "genesis state is missing and cannot be reconstructed from the available genesis alloc data. Reopen the database in writable mode with the correct genesis file or restore the persisted genesis alloc, then retry."

var ErrGenesisAllocUnavailable = errors.New("genesis alloc unavailable")

func wrapGenesisAllocUnavailable(context string, blockhash common.Hash) error {
	return fmt.Errorf("%s for hash %s: %w", context, blockhash.Hex(), ErrGenesisAllocUnavailable)
}

// getGenesisState returns the persisted genesis allocation for blockhash.
//
// If the explicit allocation blob is missing, bundled networks fall back to
// their built-in allocation so startup recovery can reconstruct genesis state.
// Custom networks only use fallbackGenesis when the caller explicitly enables
// writable recovery. Read-only startup must not auto-recover custom genesis
// state from an external genesis file. Missing or unrecoverable alloc data
// returns ErrGenesisAllocUnavailable so callers don't have to infer absence
// from a nil alloc map.
func getGenesisState(db ethdb.Database, blockhash common.Hash, fallbackGenesis *Genesis, mode recoveryMode) (alloc types.GenesisAlloc, err error) {
	blob := rawdb.ReadGenesisStateSpec(db, blockhash)
	if len(blob) != 0 {
		if err := alloc.UnmarshalJSON(blob); err != nil {
			return nil, err
		}

		return alloc, nil
	}

	// Genesis allocation is missing and there are several possibilities:
	// the node is legacy which doesn't persist the genesis allocation or
	// the persisted allocation is just lost.
	// - supported networks(mainnet, testnets), recover with defined allocations
	// - private network, can't recover
	var genesis *Genesis
	switch blockhash {
	case params.MainnetGenesisHash:
		genesis = DefaultGenesisBlock()
	case params.TestnetGenesisHash:
		genesis = DefaultTestnetGenesisBlock()
	case params.DevnetGenesisHash:
		genesis = DefaultDevnetGenesisBlock()
	}
	if genesis != nil {
		return genesis.Alloc, nil
	}
	if mode == recoveryWritable && fallbackGenesis != nil {
		fallbackHash, err := fallbackGenesis.Hash()
		if err != nil {
			return nil, err
		}
		// SECURITY: Do not relax this hash check or hydrate the config before it.
		// Genesis.Hash can depend on config-derived header fields (for example
		// EIP-1559 activation sets the initial BaseFee), so mutating Config prior
		// to hashing could make a mismatched fallback genesis appear canonical.
		if fallbackHash == blockhash {
			return fallbackGenesis.Alloc, nil
		}
	}

	return nil, wrapGenesisAllocUnavailable("genesis alloc unavailable", blockhash)
}

// hashAlloc computes the state root according to the genesis specification.
func hashAlloc(ga *types.GenesisAlloc) (common.Hash, error) {
	// Create an ephemeral in-memory database for computing hash,
	// all the derived states will be discarded to not pollute disk.
	db := state.NewDatabaseWithConfig(rawdb.NewMemoryDatabase(), nil)
	statedb, err := state.New(types.EmptyRootHash, db)
	if err != nil {
		return common.Hash{}, err
	}
	for addr, account := range *ga {
		if account.Balance != nil {
			statedb.AddBalance(addr, account.Balance, tracing.BalanceIncreaseGenesisBalance)
		}
		statedb.SetCode(addr, account.Code)
		statedb.SetNonce(addr, account.Nonce, tracing.NonceChangeGenesis)
		for key, value := range account.Storage {
			statedb.SetState(addr, key, value)
		}
	}
	return statedb.Commit(0, false)
}

// flushAlloc is very similar to hashAlloc, but the main difference is
// all the generated states will be persisted into the given database.
// Also, the genesis state specification will be flushed as well.
func flushAlloc(ga *types.GenesisAlloc, db ethdb.Database, blockhash common.Hash) error {
	statedb, err := state.New(types.EmptyRootHash, state.NewDatabase(db))
	if err != nil {
		return err
	}
	for addr, account := range *ga {
		if account.Balance != nil {
			statedb.AddBalance(addr, account.Balance, tracing.BalanceIncreaseGenesisBalance)
		}
		statedb.SetCode(addr, account.Code)
		statedb.SetNonce(addr, account.Nonce, tracing.NonceChangeGenesis)
		for key, value := range account.Storage {
			statedb.SetState(addr, key, value)
		}
	}
	root, err := statedb.Commit(0, false)
	if err != nil {
		return err
	}
	err = statedb.Database().TrieDB().Commit(root, true)
	if err != nil {
		return err
	}
	// Marshal the genesis state specification and persist.
	blob, err := json.Marshal(ga)
	if err != nil {
		return err
	}
	rawdb.WriteGenesisStateSpec(db, blockhash, blob)
	return nil
}

// restoreGenesisState restores the persisted genesis allocation for block when
// the allocation blob is missing. It recomputes the genesis root, verifies it
// against the canonical block header, and flushes the recovered state back to
// disk. Writable callers may provide the matching genesis spec as a custom
// recovery fallback when the stored allocation blob is missing. Read-only
// callers must surface ErrReadOnlyGenesisStateRecovery instead of auto-
// recovering custom genesis state.
func restoreGenesisState(db ethdb.Database, block *types.Block, fallbackGenesis *Genesis) error {
	alloc, err := getGenesisState(db, block.Hash(), fallbackGenesis, recoveryWritable)
	if err != nil {
		if errors.Is(err, ErrGenesisAllocUnavailable) {
			return wrapGenesisAllocUnavailable("missing genesis state and unrecoverable genesis alloc", block.Hash())
		}
		return fmt.Errorf("failed to load genesis alloc for %s: %w", block.Hash().Hex(), err)
	}
	root, err := hashAlloc(&alloc)
	if err != nil {
		return fmt.Errorf("failed to hash genesis alloc for %s: %w", block.Hash().Hex(), err)
	}
	if root != block.Root() {
		return fmt.Errorf("genesis alloc root mismatch for %s: have %s want %s", block.Hash().Hex(), root.Hex(), block.Root().Hex())
	}
	if err := flushAlloc(&alloc, db, block.Hash()); err != nil {
		return fmt.Errorf("failed to restore genesis state for %s: %w", block.Hash().Hex(), err)
	}
	return nil
}
func requireBuiltInCustomRecovery(hash common.Hash, allow bool) error {
	if allow || builtInChainConfigByHash(hash) == nil {
		return nil
	}
	return builtInGenesisConfigConflictError(hash)
}
