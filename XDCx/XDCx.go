package XDCx

import (
	"errors"
	"fmt"
	"math/big"
	"strconv"

	"github.com/XinFinOrg/XDPoSChain/XDCx/tradingstate"
	"github.com/XinFinOrg/XDPoSChain/XDCxDAO"
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
	defaultCacheLimit  = 1024
	MaximumTxMatchSize = 1000
)

var (
	ErrNonceTooHigh = errors.New("nonce too high")
	ErrNonceTooLow  = errors.New("nonce too low")
)

type Config struct {
	DataDir string `toml:",omitempty"`
	DBName  string `toml:",omitempty"`
}

// DefaultConfig represents (shocker!) the default configuration.
var DefaultConfig = Config{
	DataDir: "",
}

type XDCX struct {
	// Order related
	db         XDCxDAO.XDCXDAO
	Triegc     *prque.Prque[int64, common.Hash] // Priority queue mapping block numbers to tries to gc
	StateCache tradingstate.Database            // State database to reuse between imports (contains state cache)    *XDCx_state.TradingStateDB

	sdkNode           bool
	tokenDecimalCache *lru.Cache[common.Address, *big.Int]
	orderCache        *lru.Cache[common.Hash, map[common.Hash]tradingstate.OrderHistoryItem]
}

func NewLDBEngine(cfg *Config) *XDCxDAO.BatchDatabase {
	datadir := cfg.DataDir
	batchDB := XDCxDAO.NewBatchDatabaseWithEncode(datadir, 0)
	return batchDB
}

func New(stack *node.Node, cfg *Config) *XDCX {
	XDCX := &XDCX{
		Triegc:            prque.New[int64, common.Hash](nil),
		tokenDecimalCache: lru.NewCache[common.Address, *big.Int](defaultCacheLimit),
		orderCache:        lru.NewCache[common.Hash, map[common.Hash]tradingstate.OrderHistoryItem](tradingstate.OrderCacheLimit),
	}

	// default DBEngine: levelDB
	XDCX.db = NewLDBEngine(cfg)

	XDCX.StateCache = tradingstate.NewDatabase(XDCX.db)

	return XDCX
}

func (XDCx *XDCX) GetLevelDB() XDCxDAO.XDCXDAO {
	return XDCx.db
}

func (XDCx *XDCX) ProcessOrderPending(header *types.Header, coinbase common.Address, chain consensus.ChainContext, pending map[common.Address]types.OrderTransactions, statedb *state.StateDB, XDCXstatedb *tradingstate.TradingStateDB) ([]tradingstate.TxDataMatch, map[common.Hash]tradingstate.MatchingResult) {
	txMatches := []tradingstate.TxDataMatch{}
	matchingResults := map[common.Hash]tradingstate.MatchingResult{}

	txs := types.NewOrderTransactionByNonce(types.OrderTxSigner{}, pending)
	numberTx := 0
	for {
		tx := txs.Peek()
		if tx == nil {
			break
		}
		if numberTx > MaximumTxMatchSize {
			break
		}
		numberTx++
		log.Debug("ProcessOrderPending start", "len", len(pending))
		log.Debug("Get pending orders to process", "address", tx.UserAddress(), "nonce", tx.Nonce())
		V, R, S := tx.Signature()

		bigstr := V.String()
		n, e := strconv.ParseInt(bigstr, 10, 8)
		if e != nil {
			continue
		}

		order := &tradingstate.OrderItem{
			Nonce:           big.NewInt(int64(tx.Nonce())),
			Quantity:        tx.Quantity(),
			Price:           tx.Price(),
			ExchangeAddress: tx.ExchangeAddress(),
			UserAddress:     tx.UserAddress(),
			BaseToken:       tx.BaseToken(),
			QuoteToken:      tx.QuoteToken(),
			Status:          tx.Status(),
			Side:            tx.Side(),
			Type:            tx.Type(),
			Hash:            tx.OrderHash(),
			OrderID:         tx.OrderID(),
			Signature: &tradingstate.Signature{
				V: byte(n),
				R: common.BigToHash(R),
				S: common.BigToHash(S),
			},
		}

		log.Info("Process order pending", "orderPending", order, "BaseToken", order.BaseToken.Hex(), "QuoteToken", order.QuoteToken)
		originalOrder := &tradingstate.OrderItem{}
		*originalOrder = *order
		originalOrder.Quantity = tradingstate.CloneBigInt(order.Quantity)

		newTrades, newRejectedOrders, err := XDCx.CommitOrder(header, coinbase, chain, statedb, XDCXstatedb, tradingstate.GetTradingOrderBookHash(order.BaseToken, order.QuoteToken), order)

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
		originalOrder.OrderID = order.OrderID
		originalOrder.ExtraData = order.ExtraData
		originalOrderValue, err := tradingstate.EncodeBytesItem(originalOrder)
		if err != nil {
			log.Error("Can't encode", "order", originalOrder, "err", err)
			continue
		}
		txMatch := tradingstate.TxDataMatch{
			Order: originalOrderValue,
		}
		txMatches = append(txMatches, txMatch)
		matchingResults[tradingstate.GetMatchingResultCacheKey(order)] = tradingstate.MatchingResult{
			Trades:  newTrades,
			Rejects: newRejectedOrders,
		}
	}
	return txMatches, matchingResults
}

// return average price of the given pair in the last epoch
func (XDCx *XDCX) GetAveragePriceLastEpoch(chain consensus.ChainContext, statedb *state.StateDB, tradingStateDb *tradingstate.TradingStateDB, baseToken common.Address, quoteToken common.Address) (*big.Int, error) {
	price := tradingStateDb.GetMediumPriceBeforeEpoch(tradingstate.GetTradingOrderBookHash(baseToken, quoteToken))
	if price != nil && price.Sign() > 0 {
		log.Debug("GetAveragePriceLastEpoch", "baseToken", baseToken.Hex(), "quoteToken", quoteToken.Hex(), "price", price)
		return price, nil
	} else {
		inversePrice := tradingStateDb.GetMediumPriceBeforeEpoch(tradingstate.GetTradingOrderBookHash(quoteToken, baseToken))
		log.Debug("GetAveragePriceLastEpoch", "baseToken", baseToken.Hex(), "quoteToken", quoteToken.Hex(), "inversePrice", inversePrice)
		if inversePrice != nil && inversePrice.Sign() > 0 {
			quoteTokenDecimal, err := XDCx.GetTokenDecimal(chain, statedb, quoteToken)
			if err != nil || quoteTokenDecimal.Sign() == 0 {
				return nil, fmt.Errorf("fail to get tokenDecimal: Token: %v . Err: %v", quoteToken, err)
			}
			baseTokenDecimal, err := XDCx.GetTokenDecimal(chain, statedb, baseToken)
			if err != nil || baseTokenDecimal.Sign() == 0 {
				return nil, fmt.Errorf("fail to get tokenDecimal: Token: %v . Err: %v", baseToken, err)
			}
			price = new(big.Int).Mul(baseTokenDecimal, quoteTokenDecimal)
			price = new(big.Int).Div(price, inversePrice)
			log.Debug("GetAveragePriceLastEpoch", "baseToken", baseToken.Hex(), "quoteToken", quoteToken.Hex(), "baseTokenDecimal", baseTokenDecimal, "quoteTokenDecimal", quoteTokenDecimal, "inversePrice", inversePrice)
			return price, nil
		}
	}
	return nil, nil
}

// return tokenQuantity (after convert from XDC to token), tokenPriceInXDC, error
func (XDCx *XDCX) ConvertXDCToToken(chain consensus.ChainContext, statedb *state.StateDB, tradingStateDb *tradingstate.TradingStateDB, token common.Address, quantity *big.Int) (*big.Int, *big.Int, error) {
	if token == common.XDCNativeAddressBinary {
		return quantity, common.BasePrice, nil
	}
	tokenPriceInXDC, err := XDCx.GetAveragePriceLastEpoch(chain, statedb, tradingStateDb, token, common.XDCNativeAddressBinary)
	if err != nil || tokenPriceInXDC == nil || tokenPriceInXDC.Sign() <= 0 {
		return common.Big0, common.Big0, err
	}

	tokenDecimal, err := XDCx.GetTokenDecimal(chain, statedb, token)
	if err != nil || tokenDecimal.Sign() == 0 {
		return common.Big0, common.Big0, fmt.Errorf("fail to get tokenDecimal: Token: %v . Err: %v", token, err)
	}
	tokenQuantity := new(big.Int).Mul(quantity, tokenDecimal)
	tokenQuantity = new(big.Int).Div(tokenQuantity, tokenPriceInXDC)
	return tokenQuantity, tokenPriceInXDC, nil
}

func (XDCx *XDCX) GetTradingState(block *types.Block, author common.Address) (*tradingstate.TradingStateDB, error) {
	root, err := XDCx.GetTradingStateRoot(block, author)
	if err != nil {
		return nil, err
	}
	if XDCx.StateCache == nil {
		return nil, errors.New("not initialized XDCx")
	}
	return tradingstate.New(root, XDCx.StateCache)
}
func (XDCx *XDCX) GetEmptyTradingState() (*tradingstate.TradingStateDB, error) {
	return tradingstate.New(tradingstate.EmptyRoot, XDCx.StateCache)
}

func (XDCx *XDCX) GetStateCache() tradingstate.Database {
	return XDCx.StateCache
}

func (XDCx *XDCX) HasTradingState(block *types.Block, author common.Address) bool {
	root, err := XDCx.GetTradingStateRoot(block, author)
	if err != nil {
		return false
	}
	_, err = XDCx.StateCache.OpenTrie(root)
	return err == nil
}

func (XDCx *XDCX) GetTriegc() *prque.Prque[int64, common.Hash] {
	return XDCx.Triegc
}

func (XDCx *XDCX) GetTradingStateRoot(block *types.Block, author common.Address) (common.Hash, error) {
	for _, tx := range block.Transactions() {
		to := tx.To()
		if to != nil && *to == common.TradingStateAddrBinary && *tx.From() == author {
			data := tx.Data()
			if len(data) >= 32 {
				return common.BytesToHash(data[:32]), nil
			}
		}
	}
	return tradingstate.EmptyRoot, nil
}

func (XDCx *XDCX) UpdateOrderCache(baseToken, quoteToken common.Address, orderHash common.Hash, txhash common.Hash, lastState tradingstate.OrderHistoryItem) {
	orderCacheAtTxHash, ok := XDCx.orderCache.Get(txhash)
	if !ok || orderCacheAtTxHash == nil {
		orderCacheAtTxHash = make(map[common.Hash]tradingstate.OrderHistoryItem)
	}
	orderKey := tradingstate.GetOrderHistoryKey(baseToken, quoteToken, orderHash)
	_, ok = orderCacheAtTxHash[orderKey]
	if !ok {
		orderCacheAtTxHash[orderKey] = lastState
	}
	XDCx.orderCache.Add(txhash, orderCacheAtTxHash)
}
