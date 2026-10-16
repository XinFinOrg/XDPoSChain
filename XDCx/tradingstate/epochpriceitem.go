package tradingstate

import (
	"math/big"

	"github.com/XinFinOrg/XDPoSChain/common"
)

type EpochPriceItem struct {
	Epoch     uint64      `json:"epoch"`
	Orderbook common.Hash `json:"orderbook"`
	Hash      common.Hash `json:"hash"`
	Price     *big.Int    `json:"price"`
}
