package lendingstate

import (
	"math/big"
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/crypto/keccak"
)

const (
	TradeStatusOpen       = "OPEN"
	TradeStatusClosed     = "CLOSED"
	TradeStatusLiquidated = "LIQUIDATED"
)

type LendingTrade struct {
	Borrower               common.Address `json:"borrower"`
	Investor               common.Address `json:"investor"`
	LendingToken           common.Address `json:"lendingToken"`
	CollateralToken        common.Address `json:"collateralToken"`
	BorrowingOrderHash     common.Hash    `json:"borrowingOrderHash"`
	InvestingOrderHash     common.Hash    `json:"investingOrderHash"`
	BorrowingRelayer       common.Address `json:"borrowingRelayer"`
	InvestingRelayer       common.Address `json:"investingRelayer"`
	Term                   uint64         `json:"term"`
	Interest               uint64         `json:"interest"`
	CollateralPrice        *big.Int       `json:"collateralPrice"`
	LiquidationPrice       *big.Int       `json:"liquidationPrice"`
	CollateralLockedAmount *big.Int       `json:"collateralLockedAmount"`
	AutoTopUp              bool           `json:"autoTopUp"`
	LiquidationTime        uint64         `json:"liquidationTime"`
	DepositRate            *big.Int       `json:"depositRate"`
	LiquidationRate        *big.Int       `json:"liquidationRate"`
	RecallRate             *big.Int       `json:"recallRate"`
	Amount                 *big.Int       `json:"amount"`
	BorrowingFee           *big.Int       `json:"borrowingFee"`
	InvestingFee           *big.Int       `json:"investingFee"`
	Status                 string         `json:"status"`
	TakerOrderSide         string         `json:"takerOrderSide"`
	TakerOrderType         string         `json:"takerOrderType"`
	MakerOrderType         string         `json:"makerOrderType"`
	TradeId                uint64         `json:"tradeId"`
	Hash                   common.Hash    `json:"hash"`
	TxHash                 common.Hash    `json:"txHash"`
	ExtraData              string         `json:"extraData"`
	CreatedAt              time.Time      `json:"createdAt"`
	UpdatedAt              time.Time      `json:"updatedAt"`
}

func (t *LendingTrade) ComputeHash() common.Hash {
	sha := keccak.NewLegacyKeccak256()
	sha.Write(t.InvestingOrderHash.Bytes())
	sha.Write(t.BorrowingOrderHash.Bytes())
	return common.BytesToHash(sha.Sum(nil))
}
