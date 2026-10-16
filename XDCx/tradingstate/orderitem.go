package tradingstate

import (
	"fmt"
	"math/big"
	"strconv"
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/log"
)

const (
	OrderStatusNew           = "NEW"
	OrderStatusOpen          = "OPEN"
	OrderStatusPartialFilled = "PARTIAL_FILLED"
	OrderStatusFilled        = "FILLED"
	OrderStatusCancelled     = "CANCELLED"
	OrderStatusRejected      = "REJECTED"
)

// OrderItem : info that will be store in database
type OrderItem struct {
	Quantity        *big.Int       `json:"quantity,omitempty"`
	Price           *big.Int       `json:"price,omitempty"`
	ExchangeAddress common.Address `json:"exchangeAddress,omitempty"`
	UserAddress     common.Address `json:"userAddress,omitempty"`
	BaseToken       common.Address `json:"baseToken,omitempty"`
	QuoteToken      common.Address `json:"quoteToken,omitempty"`
	Status          string         `json:"status,omitempty"`
	Side            string         `json:"side,omitempty"`
	Type            string         `json:"type,omitempty"`
	Hash            common.Hash    `json:"hash,omitempty"`
	TxHash          common.Hash    `json:"txHash,omitempty"`
	Signature       *Signature     `json:"signature,omitempty"`
	FilledAmount    *big.Int       `json:"filledAmount,omitempty"`
	Nonce           *big.Int       `json:"nonce,omitempty"`
	CreatedAt       time.Time      `json:"createdAt,omitempty"`
	UpdatedAt       time.Time      `json:"updatedAt,omitempty"`
	OrderID         uint64         `json:"orderID,omitempty"`
	ExtraData       string         `json:"extraData,omitempty"`
}

// Signature struct
type Signature struct {
	V byte
	R common.Hash
	S common.Hash
}

// VerifyOrder verify orderItem
func (o *OrderItem) VerifyOrder(state *state.StateDB) error {
	if err := o.VerifyBasicOrderInfo(); err != nil {
		return err
	}
	if err := o.verifyRelayer(state); err != nil {
		return err
	}
	if o.Status == OrderNew {
		if err := VerifyPair(state, o.ExchangeAddress, o.BaseToken, o.QuoteToken); err != nil {
			return err
		}
	}
	return nil
}

// VerifyBasicOrderInfo verify basic info
func (o *OrderItem) VerifyBasicOrderInfo() error {
	if o.Status == OrderNew {
		if o.Type == Limit {
			if err := o.verifyPrice(); err != nil {
				return err
			}
		}
		if err := o.verifyQuantity(); err != nil {
			return err
		}
		if err := o.verifyOrderSide(); err != nil {
			return err
		}
		if err := o.verifyOrderType(); err != nil {
			return err
		}
	}
	if err := o.verifyStatus(); err != nil {
		return err
	}
	if err := o.verifySignature(); err != nil {
		return err
	}
	return nil
}

// verify whether the exchange applies to become relayer
func (o *OrderItem) verifyRelayer(state *state.StateDB) error {
	if !IsValidRelayer(state, o.ExchangeAddress) {
		return ErrInvalidRelayer
	}
	return nil
}

// verify signatures
func (o *OrderItem) verifySignature() error {
	bigstr := o.Nonce.String()
	n, err := strconv.ParseInt(bigstr, 10, 64)
	if err != nil {
		return ErrInvalidSignature
	}
	V := big.NewInt(int64(o.Signature.V))
	R := o.Signature.R.Big()
	S := o.Signature.S.Big()

	tx := types.NewOrderTransaction(uint64(n), o.Quantity, o.Price, o.ExchangeAddress, o.UserAddress,
		o.BaseToken, o.QuoteToken, o.Status, o.Side, o.Type, o.Hash, o.OrderID)
	tx.ImportSignature(V, R, S)
	from, _ := types.OrderSender(types.OrderTxSigner{}, tx)
	if from != tx.UserAddress() {
		return ErrInvalidSignature
	}
	return nil
}

// verify order type
func (o *OrderItem) verifyOrderType() error {
	if _, ok := MatchingOrderType[o.Type]; !ok {
		log.Debug("Invalid order type", "type", o.Type)
		return ErrInvalidOrderType
	}
	return nil
}

// verify order side
func (o *OrderItem) verifyOrderSide() error {
	if o.Side != Bid && o.Side != Ask {
		log.Debug("Invalid orderSide", "side", o.Side)
		return ErrInvalidOrderSide
	}
	return nil
}

// verifyPrice make sure price is a positive number
func (o *OrderItem) verifyPrice() error {
	if o.Price == nil || o.Price.Sign() <= 0 {
		log.Debug("Invalid price", "price", o.Price.String())
		return ErrInvalidPrice
	}
	return nil
}

// verifyQuantity make sure quantity is a positive number
func (o *OrderItem) verifyQuantity() error {
	if o.Quantity == nil || o.Quantity.Sign() <= 0 {
		log.Debug("Invalid quantity", "quantity", o.Quantity.String())
		return ErrInvalidQuantity
	}
	return nil
}

// verifyStatus make sure status is NEW OR CANCELLED
func (o *OrderItem) verifyStatus() error {
	if o.Status != Cancel && o.Status != OrderNew {
		log.Debug("Invalid status", "status", o.Status)
		return ErrInvalidStatus
	}
	return nil
}

func IsValidRelayer(statedb *state.StateDB, address common.Address) bool {
	contract, ok := relayerRegistrationSMC(statedb)
	if !ok {
		return false
	}
	slot := RelayerMappingSlot["RELAYER_LIST"]
	locRelayerState := GetLocMappingAtKey(address.Hash(), slot)

	locBigDeposit := new(big.Int).SetUint64(uint64(0)).Add(locRelayerState, RelayerStructMappingSlot["_deposit"])
	locHashDeposit := common.BigToHash(locBigDeposit)
	balance := statedb.GetState(contract, locHashDeposit).Big()
	if balance.Cmp(new(big.Int).Mul(common.BasePrice, common.RelayerLockedFund)) <= 0 {
		log.Debug("Relayer is not in relayer list", "relayer", address, "balance", balance)
		return false
	}
	if IsResignedRelayer(address, statedb) {
		log.Debug("Relayer has resigned", "relayer", address)
		return false
	}
	return true
}

func VerifyPair(statedb *state.StateDB, exchangeAddress, baseToken, quoteToken common.Address) error {
	baseTokenLength := GetBaseTokenLength(exchangeAddress, statedb)
	quoteTokenLength := GetQuoteTokenLength(exchangeAddress, statedb)
	if baseTokenLength != quoteTokenLength {
		return fmt.Errorf("invalid length of baseTokenList: %d . QuoteTokenList: %d", baseTokenLength, quoteTokenLength)
	}
	var baseIndexes []uint64
	for i := uint64(0); i < baseTokenLength; i++ {
		if baseToken == GetBaseTokenAtIndex(exchangeAddress, statedb, i) {
			baseIndexes = append(baseIndexes, i)
		}
	}
	if len(baseIndexes) == 0 {
		return fmt.Errorf("basetoken not found in relayer registration. BaseToken: %s. Exchange: %s", baseToken.Hex(), exchangeAddress.Hex())
	}
	for _, index := range baseIndexes {
		if quoteToken == GetQuoteTokenAtIndex(exchangeAddress, statedb, index) {
			return nil
		}
	}
	return fmt.Errorf("invalid exchange pair. Base: %s. Quote: %s. Exchange: %s", baseToken.Hex(), quoteToken.Hex(), exchangeAddress.Hex())
}

func VerifyBalance(statedb *state.StateDB, XDCxStateDb *TradingStateDB, order *types.OrderTransaction, baseDecimal, quoteDecimal *big.Int) error {
	var quotePrice *big.Int
	if order.QuoteToken() != common.XDCNativeAddressBinary {
		quotePrice = XDCxStateDb.GetLastPrice(GetTradingOrderBookHash(order.QuoteToken(), common.XDCNativeAddressBinary))
		log.Debug("TryGet quotePrice QuoteToken/XDC", "quotePrice", quotePrice)
		if quotePrice == nil || quotePrice.Sign() == 0 {
			inversePrice := XDCxStateDb.GetLastPrice(GetTradingOrderBookHash(common.XDCNativeAddressBinary, order.QuoteToken()))
			log.Debug("TryGet inversePrice XDC/QuoteToken", "inversePrice", inversePrice)
			if inversePrice != nil && inversePrice.Sign() > 0 {
				quotePrice = new(big.Int).Mul(common.BasePrice, quoteDecimal)
				quotePrice = new(big.Int).Div(quotePrice, inversePrice)
				log.Debug("TryGet quotePrice after get inversePrice XDC/QuoteToken", "quotePrice", quotePrice, "quoteTokenDecimal", quoteDecimal)
			}
		}
	} else {
		quotePrice = common.BasePrice
	}
	feeRate := GetExRelayerFee(order.ExchangeAddress(), statedb)
	balanceResult, err := GetSettleBalance(quotePrice, order.Side(), feeRate, order.BaseToken(), order.QuoteToken(), order.Price(), feeRate, baseDecimal, quoteDecimal, order.Quantity())
	if err != nil {
		return err
	}
	expectedBalance := balanceResult.Taker.OutTotal
	actualBalance := GetTokenBalance(order.UserAddress(), balanceResult.Taker.OutToken, statedb)
	if actualBalance.Cmp(expectedBalance) < 0 {
		return fmt.Errorf("token: %s . ExpectedBalance: %s . ActualBalance: %s", balanceResult.Taker.OutToken.Hex(), expectedBalance, actualBalance)
	}
	return nil
}

// MarshalSignature marshals the signature struct to []byte
func (s *Signature) MarshalSignature() ([]byte, error) {
	sigBytes1 := s.R.Bytes()
	sigBytes2 := s.S.Bytes()
	sigBytes3 := s.V - 27

	sigBytes := append([]byte{}, sigBytes1...)
	sigBytes = append(sigBytes, sigBytes2...)
	sigBytes = append(sigBytes, sigBytes3)

	return sigBytes, nil
}

// Verify returns the address that corresponds to the given signature and signed message
func (s *Signature) Verify(hash common.Hash) (common.Address, error) {
	hashBytes := hash.Bytes()
	sigBytes, err := s.MarshalSignature()
	if err != nil {
		return common.Address{}, err
	}

	pubKey, err := crypto.SigToPub(hashBytes, sigBytes)
	if err != nil {
		return common.Address{}, err
	}
	address := crypto.PubkeyToAddress(*pubKey)
	return address, nil
}
