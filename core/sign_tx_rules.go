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

package core

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// Errors returned by the sign transaction rules. A sign transaction is a
// transaction routed to ApplySignTransaction, see IsSignTransactionRoute.
var (
	// ErrSignTxType is returned for a sign transaction that is not a legacy
	// transaction.
	ErrSignTxType = errors.New("sign transaction must be a legacy transaction")
	// ErrSignTxData is returned for a sign transaction whose data is not
	// exactly a sign(uint256,bytes32) call.
	ErrSignTxData = errors.New("sign transaction data must be a sign(uint256,bytes32) call")
	// ErrSignTxValue is returned for a sign transaction with a non-zero value.
	ErrSignTxValue = errors.New("sign transaction must not carry value")
	// ErrSignTxFutureBlock is returned for a sign transaction that signs a block
	// at or above the block it is included in.
	ErrSignTxFutureBlock = errors.New("sign transaction signs a block that is not below the including block")
	// ErrSignTxNotMergeBlock is returned for a sign transaction that signs a
	// block whose number is not a multiple of common.MergeSignRange.
	ErrSignTxNotMergeBlock = errors.New("sign transaction signs a block outside the merge sign range")
	// ErrSignTxOutOfWindow is returned for a sign transaction that signs a block
	// more than two epochs below the block it is included in.
	ErrSignTxOutOfWindow = errors.New("sign transaction signs a block older than two epochs")
	// ErrSignTxNotCandidate is returned for a sign transaction whose sender is
	// not a candidate in the parent block's snapshot.
	ErrSignTxNotCandidate = errors.New("sign transaction sender is not a candidate")
	// ErrSignTxDuplicateSender is returned for a second sign transaction from
	// the same sender in one block.
	ErrSignTxDuplicateSender = errors.New("more than one sign transaction from the same sender in a block")
)

// signTxWindowEpochs is how many epochs back a sign transaction may sign. It
// matches the window the reward hook counts signing transactions over.
const signTxWindowEpochs = 2

// SignerSource is implemented by a consensus engine that keeps the candidate
// list sign transactions are checked against. XDPoS implements it; the list is
// the same one the transaction pool's signer check reads.
type SignerSource interface {
	GetAuthorisedSignersFromSnapshot(chain consensus.ChainReader, header *types.Header) ([]common.Address, error)
}

// CheckSignTxFields applies the per-transaction sign transaction rules that
// need no chain context: transaction type, call data, value, and that the
// signed block is a merge block no more than two epochs below block number,
// the block the transaction goes into. It returns nil for a transaction that is
// not a sign transaction at that block.
//
// It does not require the signed block to be below number: the pool judges a
// transaction against the block after its own head, which can lag behind the
// block a node has just imported and signs. SignTxRules adds that rule for the
// block actually being built or processed.
func CheckSignTxFields(config *params.ChainConfig, number *big.Int, tx *types.Transaction) error {
	if !IsSignTransactionRoute(config, number, tx) {
		return nil
	}
	if tx.Type() != types.LegacyTxType {
		return fmt.Errorf("%w: type %d", ErrSignTxType, tx.Type())
	}
	if !tx.IsSigningTransaction() {
		return fmt.Errorf("%w: %d bytes", ErrSignTxData, len(tx.Data()))
	}
	if tx.Value().Sign() != 0 {
		return fmt.Errorf("%w: %v", ErrSignTxValue, tx.Value())
	}
	signed := signedBlockNumber(tx)
	// No block number reaches 2^64; rejecting such a number here also keeps
	// the merge check below from reading a truncated value.
	if !signed.IsUint64() {
		return fmt.Errorf("%w: signed %v", ErrSignTxFutureBlock, signed)
	}
	// Before TIP2019 every block was signed, after it only merge blocks are.
	if config.IsTIP2019(number) && signed.Uint64()%common.MergeSignRange != 0 {
		return fmt.Errorf("%w: signed %v", ErrSignTxNotMergeBlock, signed)
	}
	if config.XDPoS != nil && config.XDPoS.Epoch > 0 {
		window := new(big.Int).SetUint64(signTxWindowEpochs * config.XDPoS.Epoch)
		if signed.Cmp(number) < 0 && new(big.Int).Sub(number, signed).Cmp(window) > 0 {
			return fmt.Errorf("%w: signed %v, block %v", ErrSignTxOutOfWindow, signed, number)
		}
	}
	return nil
}

// signedBlockNumber returns the block number a sign transaction signs. The
// call data must already have passed tx.IsSigningTransaction.
func signedBlockNumber(tx *types.Transaction) *big.Int {
	return new(big.Int).SetBytes(tx.Data()[4:36])
}

// SignTxRules checks the sign transactions of one block: the per-transaction
// rules of CheckSignTxFields, that the signed block is below this block, that
// the sender is a candidate in the parent block's snapshot, and that each
// sender has at most one sign transaction in the block. Block processing
// applies it from TIPSignTxRules on, and the miner applies it to the block it
// builds, so a miner never seals a block the rules reject. A SignTxRules is
// used for one block only.
type SignTxRules struct {
	config *params.ChainConfig
	number *big.Int

	// candidates loads the candidate set the first time a sign transaction is
	// checked, so a block without sign transactions never reads a snapshot.
	candidates func() (map[common.Address]struct{}, error)
	loaded     map[common.Address]struct{}

	seen map[common.Address]struct{}
}

// SignerSourceOf returns engine as a SignerSource, or nil when engine keeps no
// candidate list.
func SignerSourceOf(engine consensus.Engine) SignerSource {
	source, _ := engine.(SignerSource)
	return source
}

// NewSignTxRules returns the rules for the block numbered number whose parent
// is parent. The candidate set comes from source; when source is nil the
// sender rule is not applied.
func NewSignTxRules(config *params.ChainConfig, number *big.Int, source SignerSource, chain consensus.ChainReader, parent *types.Header) *SignTxRules {
	r := &SignTxRules{
		config: config,
		number: new(big.Int).Set(number),
		seen:   make(map[common.Address]struct{}),
	}
	if source != nil {
		r.candidates = func() (map[common.Address]struct{}, error) {
			if parent == nil {
				return nil, fmt.Errorf("%w: parent of block %v unknown", ErrSignTxNotCandidate, number)
			}
			signers, err := source.GetAuthorisedSignersFromSnapshot(chain, parent)
			if err != nil {
				return nil, fmt.Errorf("cannot load the candidates for sign transactions at block %v: %w", number, err)
			}
			set := make(map[common.Address]struct{}, len(signers))
			for _, signer := range signers {
				set[signer] = struct{}{}
			}
			return set, nil
		}
	}
	return r
}

// Check applies the rules to tx, sent by from, as the next transaction of the
// block. A transaction that is not a sign transaction passes, and so does every
// transaction for a nil SignTxRules (before TIPSignTxRules). Check does not
// count the transaction against its sender; call Record once it is part of
// the block.
func (r *SignTxRules) Check(tx *types.Transaction, from common.Address) error {
	if r == nil || !IsSignTransactionRoute(r.config, r.number, tx) {
		return nil
	}
	if err := CheckSignTxFields(r.config, r.number, tx); err != nil {
		return err
	}
	if signed := signedBlockNumber(tx); signed.Cmp(r.number) >= 0 {
		return fmt.Errorf("%w: signed %v, block %v", ErrSignTxFutureBlock, signed, r.number)
	}
	if r.candidates != nil {
		if r.loaded == nil {
			set, err := r.candidates()
			if err != nil {
				return err
			}
			r.loaded = set
		}
		if _, ok := r.loaded[from]; !ok {
			return fmt.Errorf("%w: %s", ErrSignTxNotCandidate, from.Hex())
		}
	}
	if _, ok := r.seen[from]; ok {
		return fmt.Errorf("%w: %s", ErrSignTxDuplicateSender, from.Hex())
	}
	return nil
}

// Record counts tx, sent by from, against its sender once it is part of the
// block, so a later sign transaction from the same sender fails Check. It does
// nothing for a transaction that is not a sign transaction.
func (r *SignTxRules) Record(tx *types.Transaction, from common.Address) {
	if r != nil && IsSignTransactionRoute(r.config, r.number, tx) {
		r.seen[from] = struct{}{}
	}
}
