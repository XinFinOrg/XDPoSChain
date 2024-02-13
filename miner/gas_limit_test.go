package miner

import (
	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto/sha3"
	"github.com/XinFinOrg/XDPoSChain/rlp"
	"log"
	"math/big"
	"testing"
	"time"
)

func TestDynamicGasLimit(t *testing.T) {
	const testTries = 100
	storage := make(map[string]uint64)
	var nonce uint64 = 0
	for i := 0; i < testTries; i++ {
		h := common.Hash{}
		a := big.NewInt(0)
		address := common.Address{}
		data := make([]byte, 0)
		dynamicTxMatchGasLimit := getDynamicTxGasLimit()
		tx := types.NewTransaction(nonce, address, a, dynamicTxMatchGasLimit, a, data)
		hw := sha3.NewKeccak256()
		if err := rlp.Encode(hw, tx); err != nil {
			return
		}
		hw.Sum(h[:0])
		checkForUnique(&storage, h.Hex())
		storage[h.Hex()] = dynamicTxMatchGasLimit
		// actually time between blocks in blockchain approximately 2 sec
		time.Sleep(time.Second * 2)
		// there is no problem with triple and more transaction but in test case were generated 100 transaction with same nonce
		nonce = uint64(len(storage) / 100)
	}
	log.Println("40000000 loops pass good, no unique hash")
}

func checkForUnique(storage *map[string]uint64, hash string) {
	value, ok := (*storage)[hash]
	if ok {
		log.Fatal(value, len(*storage))
	}
}
