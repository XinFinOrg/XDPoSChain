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
	"errors"
	"fmt"

	"github.com/XinFinOrg/XDPoSChain/XDCx/tradingstate"
	"github.com/XinFinOrg/XDPoSChain/XDCxlending/lendingstate"
	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/log"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/XinFinOrg/XDPoSChain/trie"
)

// BlockValidator is responsible for validating block headers, uncles and
// processed state.
//
// BlockValidator implements Validator.
type BlockValidator struct {
	config *params.ChainConfig // Chain configuration options
	bc     *BlockChain         // Canonical block chain
	engine consensus.Engine    // Consensus engine used for validating
}

// NewBlockValidator returns a new block validator which is safe for re-use
func NewBlockValidator(config *params.ChainConfig, blockchain *BlockChain, engine consensus.Engine) *BlockValidator {
	validator := &BlockValidator{
		config: config,
		engine: engine,
		bc:     blockchain,
	}
	return validator
}

// ValidateBody validates the given block's uncles and verifies the block
// header's transaction and uncle roots. The headers are assumed to be already
// validated at this point.
func (v *BlockValidator) ValidateBody(block *types.Block) error {
	// check EIP-7934 RLP-encoded block size cap
	if v.config.IsOsaka(block.Number()) && block.Size() > params.MaxBlockSize {
		return ErrBlockOversized
	}
	// Check whether the block's known, and if not, that it's linkable. Known means this node
	// executed it, which HasExecutedBlock answers from the marker an execution leaves behind:
	// a block that is on disk with a state root that resolves, but without that marker, is not
	// one this node ran, so it has to go through execution like any other - where ValidateState
	// rejects a block whose state root its own execution does not reproduce.
	//
	// The genesis block is the one block the marker never applies to: it is not executed, and
	// core/genesis.go writes its state and its block without one. A database this node has been
	// running on holds none for block 0 either, because SetupGenesisBlock does not rewrite the
	// genesis of a database that already has it, and nothing else writes that key. Answered by
	// the marker, block 0 falls through to the parent lookup below and asks for the parent of
	// block 0 - number 0-1 - so it is reported as consensus.ErrUnknownAncestor, which the import
	// records as a bad block: importing a chain this node exported itself would fail on block 0,
	// the header it was started from, because BlockChain.Export starts there (ExportN(0, head)).
	//
	// Block 0 is answered by the question these paths asked before the marker existed instead:
	// its own hash, on disk together with its state. A block 0 of another chain does not pass it
	// - its hash is not the one on disk - and still reaches ErrUnknownAncestor.
	if block.NumberU64() == 0 {
		if v.bc.HasBlockAndFullState(block.Hash(), 0) {
			return ErrKnownBlock
		}
	} else if v.bc.HasExecutedBlock(block.Hash(), block.NumberU64()) {
		return ErrKnownBlock
	}
	// Header validity is known at this point, check the uncles and transactions
	header := block.Header()
	if err := v.engine.VerifyUncles(v.bc, block); err != nil {
		return err
	}
	if hash := types.CalcUncleHash(block.Uncles()); hash != header.UncleHash {
		return fmt.Errorf("uncle root hash mismatch: have %x, want %x", hash, header.UncleHash)
	}
	if hash := types.DeriveSha(block.Transactions(), trie.NewStackTrie(nil)); hash != header.TxHash {
		return fmt.Errorf("transaction root hash mismatch: have %x, want %x", hash, header.TxHash)
	}
	// The parent is asked a weaker question than the block above: all its execution needs is a
	// state to run against, not a proof that this node ran it. A side entry written by
	// writeBlockWithoutState has no state and no receipts, so it lands in the pruned-ancestor
	// branch, which is what sends the segment to insertSideChain - using HasExecutedBlock here
	// would answer the same today and only obscure why.
	if !v.bc.HasBlockAndFullState(block.ParentHash(), block.NumberU64()-1) {
		if !v.bc.HasBlock(block.ParentHash(), block.NumberU64()-1) {
			return consensus.ErrUnknownAncestor
		}
		return consensus.ErrPrunedAncestor
	}
	return nil
}

// ValidateState validates the various changes that happen after a state
// transition, such as amount of used gas, the receipt roots and the state root
// itself. ValidateState returns a database batch if the validation was a success
// otherwise nil and an error is returned.
func (v *BlockValidator) ValidateState(block *types.Block, statedb *state.StateDB, receipts types.Receipts, usedGas uint64) error {
	header := block.Header()
	if block.GasUsed() != usedGas {
		return fmt.Errorf("invalid gas used (remote: %d local: %d)", block.GasUsed(), usedGas)
	}
	// Validate the received block's bloom with the one derived from the generated receipts.
	// For valid blocks this should always validate to true.
	rbloom := types.CreateBloom(receipts)
	if rbloom != header.Bloom {
		return fmt.Errorf("invalid bloom (remote: %x  local: %x)", header.Bloom, rbloom)
	}
	// Tre receipt Trie's root (R = (Tr [[H1, R1], ... [Hn, R1]]))
	receiptSha := types.DeriveSha(receipts, trie.NewStackTrie(nil))
	if receiptSha != header.ReceiptHash {
		return fmt.Errorf("invalid receipt root hash (remote: %x local: %x)", header.ReceiptHash, receiptSha)
	}
	// Validate the state root against the received state root and throw
	// an error if they don't match.
	if root := statedb.IntermediateRoot(v.config.IsEIP158(header.Number)); header.Root != root {
		return fmt.Errorf("invalid merkle root (remote: %x local: %x) dberr: %w", header.Root, root, statedb.Error())
	}
	return nil
}

func (v *BlockValidator) ValidateTradingOrder(statedb *state.StateDB, XDCxStatedb *tradingstate.TradingStateDB, txMatchBatch tradingstate.TxMatchBatch, coinbase common.Address, header *types.Header) error {
	XDPoSEngine, ok := v.bc.Engine().(*XDPoS.XDPoS)
	if XDPoSEngine == nil || !ok {
		return ErrNotXDPoS
	}
	XDCXService := XDPoSEngine.GetXDCXService()
	if XDCXService == nil {
		return errors.New("XDCx not found")
	}
	log.Debug("verify matching transaction found a TxMatches Batch", "numTxMatches", len(txMatchBatch.Data))
	tradingResult := map[common.Hash]tradingstate.MatchingResult{}
	for _, txMatch := range txMatchBatch.Data {
		// verify orderItem
		order, err := txMatch.DecodeOrder()
		if err != nil {
			log.Error("transaction match is corrupted. Failed decode order", "err", err)
			continue
		}

		log.Debug("process tx match", "order", order)
		// process Matching Engine
		newTrades, newRejectedOrders, err := XDCXService.ApplyOrder(header, coinbase, v.bc, statedb, XDCxStatedb, tradingstate.GetTradingOrderBookHash(order.BaseToken, order.QuoteToken), order)
		if err != nil {
			return err
		}
		tradingResult[tradingstate.GetMatchingResultCacheKey(order)] = tradingstate.MatchingResult{
			Trades:  newTrades,
			Rejects: newRejectedOrders,
		}
	}
	return nil
}

func (v *BlockValidator) ValidateLendingOrder(statedb *state.StateDB, lendingStateDb *lendingstate.LendingStateDB, XDCxStatedb *tradingstate.TradingStateDB, batch lendingstate.TxLendingBatch, coinbase common.Address, header *types.Header) error {
	XDPoSEngine, ok := v.bc.Engine().(*XDPoS.XDPoS)
	if XDPoSEngine == nil || !ok {
		return ErrNotXDPoS
	}
	XDCXService := XDPoSEngine.GetXDCXService()
	if XDCXService == nil {
		return errors.New("XDCx not found")
	}
	lendingService := XDPoSEngine.GetLendingService()
	if lendingService == nil {
		return errors.New("lendingService not found")
	}
	log.Debug("verify lendingItem ", "numItems", len(batch.Data))
	lendingResult := map[common.Hash]lendingstate.MatchingResult{}
	for _, l := range batch.Data {
		// verify lendingItem

		log.Debug("process lending tx", "lendingItem", lendingstate.ToJSON(l))
		// process Matching Engine
		newTrades, newRejectedOrders, err := lendingService.ApplyOrder(header, coinbase, v.bc, statedb, lendingStateDb, XDCxStatedb, lendingstate.GetLendingOrderBookHash(l.LendingToken, l.Term), l)
		if err != nil {
			return err
		}
		lendingResult[lendingstate.GetLendingCacheKey(l)] = lendingstate.MatchingResult{
			Trades:  newTrades,
			Rejects: newRejectedOrders,
		}
	}
	return nil
}

// CalcGasLimit computes the gas limit of the next block after parent. It aims
// to keep the baseline gas close to the provided target, and increase it towards
// the target if the baseline gas is lower.
func CalcGasLimit(parentGasLimit, desiredLimit uint64) uint64 {
	delta := parentGasLimit/params.GasLimitBoundDivisor - 1
	if desiredLimit < params.MinGasLimit {
		desiredLimit = params.MinGasLimit
	}
	// If we're outside our allowed gas range, we try to hone towards them
	if parentGasLimit < desiredLimit {
		return min(parentGasLimit+delta, desiredLimit)
	}
	if parentGasLimit > desiredLimit {
		return max(parentGasLimit-delta, desiredLimit)
	}
	return parentGasLimit
}

func ExtractTradingTransactions(transactions types.Transactions) ([]tradingstate.TxMatchBatch, error) {
	txMatchBatchData := []tradingstate.TxMatchBatch{}
	for _, tx := range transactions {
		if tx.IsTradingTransaction() {
			txMatchBatch, err := tradingstate.DecodeTxMatchesBatch(tx.Data())
			if err != nil {
				log.Error("transaction match is corrupted. Failed to decode txMatchBatch", "err", err, "txHash", tx.Hash().Hex())
				continue
			}
			txMatchBatch.TxHash = tx.Hash()
			txMatchBatchData = append(txMatchBatchData, txMatchBatch)
		}
	}
	return txMatchBatchData, nil
}

func ExtractLendingTransactions(transactions types.Transactions) ([]lendingstate.TxLendingBatch, error) {
	batchData := []lendingstate.TxLendingBatch{}
	for _, tx := range transactions {
		if tx.IsLendingTransaction() {
			txMatchBatch, err := lendingstate.DecodeTxLendingBatch(tx.Data())
			if err != nil {
				log.Error("transaction match is corrupted. Failed to decode lendingTransaction", "err", err, "txHash", tx.Hash().Hex())
				continue
			}
			txMatchBatch.TxHash = tx.Hash()
			batchData = append(batchData, txMatchBatch)
		}
	}
	return batchData, nil
}

func ExtractLendingFinalizedTradeTransactions(transactions types.Transactions) (lendingstate.FinalizedResult, error) {
	for _, tx := range transactions {
		if tx.IsLendingFinalizedTradeTransaction() {
			finalizedTrades, err := lendingstate.DecodeFinalizedResult(tx.Data())
			if err != nil {
				log.Error("transaction is corrupted. Failed to decode LendingClosedTradeTransaction", "err", err, "txHash", tx.Hash().Hex())
				continue
			}
			finalizedTrades.TxHash = tx.Hash()
			// each block has only one tx of this type
			return finalizedTrades, nil
		}
	}
	return lendingstate.FinalizedResult{}, nil
}
