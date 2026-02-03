package core

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/common/sort"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/utils"
)

// HOW TO RUN THIS TEST:
// go test -v -run TestMasternodeSortScenarios core/blockchain_sort_test.go

func TestMasternodeSortScenarios(t *testing.T) {
	fmt.Printf("=== Test Masternode Sort Scenario 1, 25 nodes:\n")
	ms := createMSList(25, false)
	runMasternodeSort(t, ms)
	fmt.Printf("=== Test Masternode Sort Scenario 2, 25 nodes reversed order:\n")
	ms = createMSList(25, true)
	runMasternodeSort(t, ms)
	fmt.Printf("=== Test Masternode Sort Scenario 3, 24 nodes:\n")
	ms = createMSList(24, false)
	runMasternodeSort(t, ms)
	fmt.Printf("=== Test Masternode Sort Scenario 4, 24 nodes reversed order:\n")
	ms = createMSList(24, true)
	runMasternodeSort(t, ms)

}
func runMasternodeSort(t *testing.T, ms []utils.Masternode) {
	fmt.Printf("Before sorting (%d nodes):\n", len(ms))
	for i, m := range ms {
		fmt.Printf("  [%d] Address: %s\n", i, m.Address.Hex())
	}
	sort.Slice(ms, func(i, j int) bool {
		return ms[i].Stake.Cmp(ms[j].Stake) >= 0
	})
	fmt.Printf("\nAfter sorting:\n")
	for i, m := range ms {
		fmt.Printf("  [%d] Address: %s\n", i, m.Address.Hex())
	}
	fmt.Printf("\n")
}

func createMSList(num int, reverse bool) []utils.Masternode {
	ms := make([]utils.Masternode, num)
	for i := 0; i < num; i++ {
		var addr string
		if reverse {
			addr = fmt.Sprintf("0x%040d", num-i) // reverse order
		} else {
			addr = fmt.Sprintf("0x%040d", i+1)
		}
		ms[i] = utils.Masternode{
			Address: common.HexToAddress(addr),
			Stake:   big.NewInt(int64(1000)), // different stake
		}
	}
	return ms
}
