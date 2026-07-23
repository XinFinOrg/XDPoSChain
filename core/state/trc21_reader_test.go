package state

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
)

// TestValidateTRC21TxShortCalldata reproduces CertiK XDC-01: data[:4] panics
// when calldata is non-nil but shorter than 4 bytes and the sender has a
// non-zero TRC21 balance at the token.
func TestValidateTRC21TxShortCalldata(t *testing.T) {
	statedb, err := New(types.EmptyRootHash, NewDatabase(rawdb.NewMemoryDatabase()))
	if err != nil {
		t.Fatalf("failed to create state: %v", err)
	}

	from := common.HexToAddress("0x1111111111111111111111111111111111111111")
	token := common.HexToAddress("0x2222222222222222222222222222222222222222")

	// Seed balances[from] != 0 so ValidateTRC21Tx takes the data[:4] branch.
	balanceKey := GetLocMappingAtKey(from.Hash(), SlotTRC21Token["balances"])
	statedb.SetState(token, common.BigToHash(balanceKey), common.BigToHash(big.NewInt(1)))
	// minFee can be zero; the panic happens before any fee comparison.
	statedb.SetState(token, GetLocSimpleVariable(SlotTRC21Token["minFee"]), common.Hash{})

	cases := [][]byte{
		{},                     // empty non-nil
		{0x01},                 // 1 byte
		{0x01, 0x02},           // 2 bytes
		{0x01, 0x02, 0x03},     // 3 bytes
	}

	for _, data := range cases {
		t.Run(fmt.Sprintf("len_%d", len(data)), func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic on len=%d calldata: %v", len(data), r)
				}
			}()
			if ok := statedb.ValidateTRC21Tx(from, token, data); ok {
				t.Fatalf("expected false for short calldata (len=%d), got true", len(data))
			}
		})
	}
}
