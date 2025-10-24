package XDCxlending

import (
	"encoding/json"
	"errors"
	"math/big"
	"strconv"

	"github.com/XinFinOrg/XDPoSChain/XDCx"
	"github.com/XinFinOrg/XDPoSChain/XDCx/tradingstate"
	"github.com/XinFinOrg/XDPoSChain/XDCxDAO"
	"github.com/XinFinOrg/XDPoSChain/XDCxlending/lendingstate"
	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/common/lru"
	"github.com/XinFinOrg/XDPoSChain/common/prque"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/log"
	"github.com/XinFinOrg/XDPoSChain/node"
)

const (
	defaultCacheLimit = 1024
)

var (
	ErrNonceTooHigh = errors.New("nonce too high")
	ErrNonceTooLow  = errors.New("nonce too low")
)

type Lending struct {
	Triegc     *prque.Prque[int64, common.Hash] // Priority queue mapping block numbers to tries to gc
	StateCache lendingstate.Database            // State database to reuse between imports (contains state cache)    *lendingstate.TradingStateDB

	XDCx                *XDCx.XDCX
	lendingItemHistory  *lru.Cache[common.Hash, map[common.Hash]lendingstate.LendingItemHistoryItem]
	lendingTradeHistory *lru.Cache[common.Hash, map[common.Hash]lendingstate.LendingTradeHistoryItem]
}

func New(stack *node.Node, XDCx *XDCx.XDCX) *Lending {
	lending := &Lending{
		Triegc:              prque.New[int64, common.Hash](nil),
		lendingItemHistory:  lru.NewCache[common.Hash, map[common.Hash]lendingstate.LendingItemHistoryItem](defaultCacheLimit),
		lendingTradeHistory: lru.NewCache[common.Hash, map[common.Hash]lendingstate.LendingTradeHistoryItem](defaultCacheLimit),
	}
	lending.StateCache = lendingstate.NewDatabase(XDCx.GetLevelDB())
	lending.XDCx = XDCx

	return lending
}

func (l *Lending) GetLevelDB() XDCxDAO.XDCXDAO {
	return l.XDCx.GetLevelDB()
}

func (l *Lending) ProcessOrderPending(header *types.Header, coinbase common.Address, chain consensus.ChainContext, pending map[common.Address]types.LendingTransactions, statedb *state.StateDB, lendingStatedb *lendingstate.LendingStateDB, tradingStateDb *tradingstate.TradingStateDB) ([]*lendingstate.LendingItem, map[common.Hash]lendingstate.MatchingResult) {
	lendingItems := []*lendingstate.LendingItem{}
	matchingResults := map[common.Hash]lendingstate.MatchingResult{}

	txs := types.NewLendingTransactionByNonce(types.LendingTxSigner{}, pending)
	for {
		tx := txs.Peek()
		if tx == nil {
			break
		}
		log.Debug("ProcessOrderPending start", "len", len(pending))
		log.Debug("Get pending orders to process", "address", tx.UserAddress(), "nonce", tx.Nonce())
		V, R, S := tx.Signature()

		bigstr := V.String()
		n, e := strconv.ParseInt(bigstr, 10, 8)
		if e != nil {
			continue
		}

		order := &lendingstate.LendingItem{
			Nonce:           big.NewInt(int64(tx.Nonce())),
			Quantity:        tx.Quantity(),
			Interest:        new(big.Int).SetUint64(tx.Interest()),
			Relayer:         tx.RelayerAddress(),
			Term:            tx.Term(),
			UserAddress:     tx.UserAddress(),
			LendingToken:    tx.LendingToken(),
			CollateralToken: tx.CollateralToken(),
			AutoTopUp:       tx.AutoTopUp(),
			Status:          tx.Status(),
			Side:            tx.Side(),
			Type:            tx.Type(),
			Hash:            tx.LendingHash(),
			LendingId:       tx.LendingId(),
			LendingTradeId:  tx.LendingTradeId(),
			ExtraData:       tx.ExtraData(),
			Signature: &lendingstate.Signature{
				V: byte(n),
				R: common.BigToHash(R),
				S: common.BigToHash(S),
			},
		}

		log.Info("Process order pending", "orderPending", order, "LendingToken", order.LendingToken.Hex(), "CollateralToken", order.CollateralToken)
		originalOrder := &lendingstate.LendingItem{}
		*originalOrder = *order
		originalOrder.Quantity = lendingstate.CloneBigInt(order.Quantity)

		newTrades, newRejectedOrders, err := l.CommitOrder(header, coinbase, chain, statedb, lendingStatedb, tradingStateDb, lendingstate.GetLendingOrderBookHash(order.LendingToken, order.Term), order)
		for _, reject := range newRejectedOrders {
			log.Debug("Reject order", "reject", *reject)
		}

		switch err {
		case ErrNonceTooLow:
			// New head notification data race between the transaction pool and miner, shift
			log.Debug("Skipping order with low nonce", "sender", tx.UserAddress(), "nonce", tx.Nonce())
			txs.Shift()
			continue

		case ErrNonceTooHigh:
			// Reorg notification data race between the transaction pool and miner, skip account =
			log.Debug("Skipping order account with high nonce", "sender", tx.UserAddress(), "nonce", tx.Nonce())
			txs.Pop()
			continue

		case nil:
			// everything ok
			txs.Shift()

		default:
			// Strange error, discard the transaction and get the next in line (note, the
			// nonce-too-high clause will prevent us from executing in vain).
			log.Debug("Transaction failed, account skipped", "hash", tx.Hash(), "err", err)
			txs.Shift()
			continue
		}

		// orderID has been updated
		originalOrder.LendingId = order.LendingId
		originalOrder.ExtraData = order.ExtraData
		lendingItems = append(lendingItems, originalOrder)
		matchingResults[lendingstate.GetLendingCacheKey(order)] = lendingstate.MatchingResult{
			Trades:  newTrades,
			Rejects: newRejectedOrders,
		}
	}
	return lendingItems, matchingResults
}

func (l *Lending) GetLendingState(block *types.Block, author common.Address) (*lendingstate.LendingStateDB, error) {
	root, err := l.GetLendingStateRoot(block, author)
	if err != nil {
		return nil, err
	}
	if l.StateCache == nil {
		return nil, errors.New("not initialized XDCx")
	}
	state, err := lendingstate.New(root, l.StateCache)
	if err != nil {
		log.Info("Not found lending state when GetLendingState", "block", block.Number(), "lendingRoot", root.Hex())
	}
	return state, err
}

func (l *Lending) GetStateCache() lendingstate.Database {
	return l.StateCache
}

func (l *Lending) HasLendingState(block *types.Block, author common.Address) bool {
	root, err := l.GetLendingStateRoot(block, author)
	if err != nil {
		return false
	}
	_, err = l.StateCache.OpenTrie(root)
	return err == nil
}

func (l *Lending) GetTriegc() *prque.Prque[int64, common.Hash] {
	return l.Triegc
}

func (l *Lending) GetLendingStateRoot(block *types.Block, author common.Address) (common.Hash, error) {
	for _, tx := range block.Transactions() {
		to := tx.To()
		if to != nil && *to == common.TradingStateAddrBinary && *tx.From() == author {
			data := tx.Data()
			if len(data) >= 64 {
				return common.BytesToHash(data[32:]), nil
			}
		}
	}
	return lendingstate.EmptyRoot, nil
}

func (l *Lending) UpdateLendingItemCache(LendingToken, CollateralToken common.Address, hash common.Hash, txhash common.Hash, lastState lendingstate.LendingItemHistoryItem) {
	lendingCacheAtTxHash, ok := l.lendingItemHistory.Get(txhash)
	if !ok || lendingCacheAtTxHash == nil {
		lendingCacheAtTxHash = make(map[common.Hash]lendingstate.LendingItemHistoryItem)
	}
	orderKey := lendingstate.GetLendingItemHistoryKey(LendingToken, CollateralToken, hash)
	_, ok = lendingCacheAtTxHash[orderKey]
	if !ok {
		lendingCacheAtTxHash[orderKey] = lastState
	}
	l.lendingItemHistory.Add(txhash, lendingCacheAtTxHash)
}

func (l *Lending) UpdateLendingTradeCache(hash common.Hash, txhash common.Hash, lastState lendingstate.LendingTradeHistoryItem) {
	var lendingCacheAtTxHash map[common.Hash]lendingstate.LendingTradeHistoryItem
	lendingCacheAtTxHash, ok := l.lendingTradeHistory.Get(txhash)
	if !ok || lendingCacheAtTxHash == nil {
		lendingCacheAtTxHash = make(map[common.Hash]lendingstate.LendingTradeHistoryItem)
	}
	_, ok = lendingCacheAtTxHash[hash]
	if !ok {
		lendingCacheAtTxHash[hash] = lastState
	}
	l.lendingTradeHistory.Add(txhash, lendingCacheAtTxHash)
}

func (l *Lending) ProcessLiquidationData(header *types.Header, chain consensus.ChainContext, statedb *state.StateDB, tradingState *tradingstate.TradingStateDB, lendingState *lendingstate.LendingStateDB) (updatedTrades map[common.Hash]*lendingstate.LendingTrade, liquidatedTrades, autoRepayTrades, autoTopUpTrades, autoRecallTrades []*lendingstate.LendingTrade, err error) {
	time := new(big.Int).SetUint64(header.Time)
	updatedTrades = map[common.Hash]*lendingstate.LendingTrade{} // sum of liquidatedTrades, autoRepayTrades, autoTopUpTrades, autoRecallTrades
	liquidatedTrades = []*lendingstate.LendingTrade{}
	autoRepayTrades = []*lendingstate.LendingTrade{}
	autoTopUpTrades = []*lendingstate.LendingTrade{}
	autoRecallTrades = []*lendingstate.LendingTrade{}

	allPairs, err := lendingstate.GetAllLendingPairs(statedb)
	if err != nil {
		log.Debug("Not found all trading pairs", "error", err)
		return updatedTrades, liquidatedTrades, autoRepayTrades, autoTopUpTrades, autoRecallTrades, nil
	}
	allLendingBooks, err := lendingstate.GetAllLendingBooks(statedb)
	if err != nil {
		log.Debug("Not found all lending books", "error", err)
		return updatedTrades, liquidatedTrades, autoRepayTrades, autoTopUpTrades, autoRecallTrades, nil
	}

	// liquidate trades by time
	for lendingBook := range allLendingBooks {
		lowestTime, tradingIds := lendingState.GetLowestLiquidationTime(lendingBook, time)
		log.Debug("ProcessLiquidationData time", "tradeIds", len(tradingIds))
		for lowestTime.Sign() > 0 && lowestTime.Cmp(time) < 0 {
			for _, tradingId := range tradingIds {
				log.Debug("ProcessRepay", "lowestTime", lowestTime, "time", time, "lendingBook", lendingBook.Hex(), "tradingId", tradingId.Hex())
				trade, err := l.ProcessRepayLendingTrade(header, chain, lendingState, statedb, tradingState, lendingBook, tradingId.Big().Uint64())
				if err != nil {
					log.Error("Fail when process payment ", "time", time, "lendingBook", lendingBook.Hex(), "tradingId", tradingId, "error", err)
					return updatedTrades, liquidatedTrades, autoRepayTrades, autoTopUpTrades, autoRecallTrades, err
				}
				if trade != nil && trade.Hash != (common.Hash{}) {
					updatedTrades[trade.Hash] = trade
					if trade.Status == lendingstate.TradeStatusLiquidated {
						liquidatedTrades = append(liquidatedTrades, trade)
					} else if trade.Status == lendingstate.TradeStatusClosed {
						autoRepayTrades = append(autoRepayTrades, trade)
					}
				}
			}
			lowestTime, tradingIds = lendingState.GetLowestLiquidationTime(lendingBook, time)
		}
	}

	for _, lendingPair := range allPairs {
		orderbook := tradingstate.GetTradingOrderBookHash(lendingPair.CollateralToken, lendingPair.LendingToken)
		_, collateralPrice, err := l.GetCollateralPrices(header, chain, statedb, tradingState, lendingPair.CollateralToken, lendingPair.LendingToken)
		if err != nil || collateralPrice == nil || collateralPrice.Sign() == 0 {
			log.Error("Fail when get price collateral/lending ", "CollateralToken", lendingPair.CollateralToken.Hex(), "LendingToken", lendingPair.LendingToken.Hex(), "error", err)
			// ignore this pair, do not throw error
			continue
		}
		// liquidate trades
		highestLiquidatePrice, liquidationData := tradingState.GetHighestLiquidationPriceData(orderbook, collateralPrice)
		for highestLiquidatePrice.Sign() > 0 && collateralPrice.Cmp(highestLiquidatePrice) < 0 {
			for lendingBook, tradingIds := range liquidationData {
				for _, tradingIdHash := range tradingIds {
					trade := lendingState.GetLendingTrade(lendingBook, tradingIdHash)
					if trade.AutoTopUp {
						if newTrade, err := l.AutoTopUp(statedb, tradingState, lendingState, lendingBook, tradingIdHash, collateralPrice); err == nil {
							// if this action complete successfully, do not liquidate this trade in this epoch
							log.Debug("AutoTopUp", "borrower", trade.Borrower.Hex(), "collateral", newTrade.CollateralToken.Hex(), "tradingIdHash", tradingIdHash.Hex(), "newLockedAmount", newTrade.CollateralLockedAmount)
							autoTopUpTrades = append(autoTopUpTrades, newTrade)
							updatedTrades[newTrade.Hash] = newTrade
							continue
						}
					}
					log.Debug("LiquidationTrade", "highestLiquidatePrice", highestLiquidatePrice, "lendingBook", lendingBook.Hex(), "tradingIdHash", tradingIdHash.Hex())
					newTrade, err := l.LiquidationTrade(lendingState, statedb, tradingState, lendingBook, tradingIdHash.Big().Uint64())
					if err != nil {
						log.Error("Fail when remove liquidation newTrade", "time", time, "lendingBook", lendingBook.Hex(), "tradingIdHash", tradingIdHash.Hex(), "error", err)
						return updatedTrades, liquidatedTrades, autoRepayTrades, autoTopUpTrades, autoRecallTrades, err
					}
					if newTrade != nil && newTrade.Hash != (common.Hash{}) {
						newTrade.Status = lendingstate.TradeStatusLiquidated
						liquidationData := lendingstate.LiquidationData{
							RecallAmount:      common.Big0,
							LiquidationAmount: newTrade.CollateralLockedAmount,
							CollateralPrice:   collateralPrice,
							Reason:            lendingstate.LiquidatedByPrice,
						}
						extraData, _ := json.Marshal(liquidationData)
						newTrade.ExtraData = string(extraData)
						liquidatedTrades = append(liquidatedTrades, newTrade)
						updatedTrades[newTrade.Hash] = newTrade
					}
				}
			}
			highestLiquidatePrice, liquidationData = tradingState.GetHighestLiquidationPriceData(orderbook, collateralPrice)
		}
		// recall trades
		depositRate, liquidationRate, recallRate := lendingstate.GetCollateralDetail(statedb, lendingPair.CollateralToken)
		recalLiquidatePrice := new(big.Int).Mul(collateralPrice, common.BaseRecall)
		recalLiquidatePrice = new(big.Int).Div(recalLiquidatePrice, recallRate)
		newLiquidatePrice := new(big.Int).Mul(collateralPrice, liquidationRate)
		newLiquidatePrice = new(big.Int).Div(newLiquidatePrice, depositRate)
		allLowertLiquidationData := tradingState.GetAllLowerLiquidationPriceData(orderbook, recalLiquidatePrice)
		log.Debug("ProcessLiquidationData", "orderbook", orderbook.Hex(), "collateralPrice", collateralPrice, "recallRate", recallRate, "recalLiquidatePrice", recalLiquidatePrice, "newLiquidatePrice", newLiquidatePrice, "allLowertLiquidationData", len(allLowertLiquidationData))
		for price, liquidationData := range allLowertLiquidationData {
			if price.Sign() > 0 && recalLiquidatePrice.Cmp(price) > 0 {
				for lendingBook, tradingIds := range liquidationData {
					for _, tradingIdHash := range tradingIds {
						log.Debug("Process Recall", "price", price, "lendingBook", lendingBook, "tradingIdHash", tradingIdHash.Hex())
						trade := lendingState.GetLendingTrade(lendingBook, tradingIdHash)
						log.Debug("TestRecall", "borrower", trade.Borrower.Hex(), "lendingToken", trade.LendingToken.Hex(), "collateral", trade.CollateralToken.Hex(), "price", price, "tradingIdHash", tradingIdHash.Hex())
						if trade.AutoTopUp {
							_, newTrade, err := l.ProcessRecallLendingTrade(lendingState, statedb, tradingState, lendingBook, tradingIdHash, newLiquidatePrice)
							if err != nil {
								log.Error("ProcessRecallLendingTrade", "lendingBook", lendingBook.Hex(), "tradingIdHash", tradingIdHash.Hex(), "newLiquidatePrice", newLiquidatePrice, "err", err)
								return updatedTrades, liquidatedTrades, autoRepayTrades, autoTopUpTrades, autoRecallTrades, err
							}
							// if this action complete successfully, do not liquidate this trade in this epoch
							log.Debug("AutoRecall", "borrower", trade.Borrower.Hex(), "collateral", newTrade.CollateralToken.Hex(), "lendingBook", lendingBook.Hex(), "tradingIdHash", tradingIdHash.Hex(), "newLockedAmount", newTrade.CollateralLockedAmount)
							autoRecallTrades = append(autoRecallTrades, newTrade)
							updatedTrades[newTrade.Hash] = newTrade
						}
					}
				}
			}
		}
	}

	log.Debug("ProcessLiquidationData", "updatedTrades", len(updatedTrades), "liquidated", len(liquidatedTrades), "autoRepay", len(autoRepayTrades), "autoTopUp", len(autoTopUpTrades), "autoRecall", len(autoRecallTrades))
	return updatedTrades, liquidatedTrades, autoRepayTrades, autoTopUpTrades, autoRecallTrades, nil
}
