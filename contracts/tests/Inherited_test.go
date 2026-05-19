package tests

import (
	"fmt"
	"math/big"
	"os"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/accounts/abi/bind"
	"github.com/XinFinOrg/XDPoSChain/accounts/abi/bind/backends"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/log"
	"github.com/XinFinOrg/XDPoSChain/params"
)

var (
	mainKey, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	mainAddr   = crypto.PubkeyToAddress(mainKey.PublicKey)
)

// TestPriceFeed tests price feed.
func TestPriceFeed(t *testing.T) {
	glogger := log.NewGlogHandler(log.NewTerminalHandler(os.Stderr, false))
	glogger.Verbosity(log.LevelTrace)
	log.SetDefault(log.NewLogger(glogger))

	testChainConfig := *params.TestXDPoSMockChainConfig
	testChainConfig.TIPXDCXCancellationFeeBlock = big.NewInt(0)

	// init genesis
	contractBackend := backends.NewXDCSimulatedBackend(
		types.GenesisAlloc{
			mainAddr: {Balance: big.NewInt(0).Mul(big.NewInt(10000000000000), big.NewInt(10000000000000))},
		},
		42000000,
		&testChainConfig,
	)
	transactOpts, err := bind.NewKeyedTransactorWithChainID(mainKey, testChainConfig.ChainID)
	if err != nil {
		t.Fatal("can't create transactor: ", err)
	}
	// deploy payer swap SMC
	addr, contract, err := DeployMyInherited(transactOpts, contractBackend)
	if err != nil {
		t.Fatal("can't deploy smart contract: ", err)
	}
	fmt.Println("addr", addr.Hex())
	tx, err := contract.Foo()
	if err != nil {
		t.Fatal("can't run function Foo() in  smart contract: ", err)
	}
	fmt.Println("tx", tx)
}
