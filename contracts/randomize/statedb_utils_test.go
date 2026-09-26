package randomize

import (
	"context"
	"math/big"
	"reflect"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/accounts/abi/bind"
	"github.com/XinFinOrg/XDPoSChain/accounts/abi/bind/backends"
	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/contracts"
	randomizeContract "github.com/XinFinOrg/XDPoSChain/contracts/randomize/contract"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// TestRandomizeStatedbUtils answers the question behind reading the randomize
// values off the state: do StateDB.GetSecret and StateDB.GetOpening answer what
// the contract answers, given the same storage? Those two getters are what
// eth/hooks asks for a masternode's secrets and opening since it stopped calling
// the contract, and nothing in the repository ever compared them against the
// contract that owns the storage.
//
// The comparison is set up the way contracts/validator does for the voting
// contract: run the real contract so its own code writes the storage, then read
// that storage twice, once through abigen over eth_call and once through the
// getters, and require the two readings to match. Populating the storage any
// other way would make the comparison worthless - if nothing is written, both
// readings are empty and they still agree.
func TestRandomizeStatedbUtils(t *testing.T) {
	// Keep this test on a legacy tx path. NewSimulatedBackend now uses
	// AllEthashProtocolChanges with post-London forks enabled, which switches
	// contract deployment to dynamic-fee txs and breaks this legacy-signer flow.
	legacyConfig := *params.AllEthashProtocolChanges
	futureForkBlock := big.NewInt(1_000_000_000)
	legacyConfig.EIP1559Block = new(big.Int).Set(futureForkBlock)
	legacyConfig.CancunBlock = new(big.Int).Set(futureForkBlock)
	legacyConfig.PragueBlock = new(big.Int).Set(futureForkBlock)
	legacyConfig.OsakaBlock = new(big.Int).Set(futureForkBlock)

	balance := new(big.Int).SetUint64(1000000000000)
	deployBackend := backends.NewXDCSimulatedBackend(types.GenesisAlloc{acc1Addr: {Balance: balance}}, 42000000, &legacyConfig)
	defer deployBackend.Close()
	deployOpts, err := bind.NewKeyedTransactorWithChainID(acc1Key, legacyConfig.ChainID)
	if err != nil {
		t.Fatalf("can't create deploy transactor: %v", err)
	}
	deployOpts.GasLimit = 4200000
	deployedAt, _, err := DeployRandomize(deployOpts, deployBackend)
	if err != nil {
		t.Fatalf("can't deploy the randomize contract: %v", err)
	}
	deployBackend.Commit()
	code, err := deployBackend.CodeAt(context.Background(), deployedAt, nil)
	if err != nil {
		t.Fatalf("can't read the deployed randomize code: %v", err)
	}

	// The same code sitting at the address the getters read from, which is the
	// address the genesis allocations put it at. Nothing is copied but the code:
	// the storage below is written by the contract itself.
	backend := backends.NewXDCSimulatedBackend(types.GenesisAlloc{
		acc1Addr:                  {Balance: balance},
		common.RandomizeSMCBinary: {Code: code},
	}, 42000000, &legacyConfig)
	defer backend.Close()

	signer := types.HomesteadSigner{}
	ctx := context.Background()
	randomizeKeyValue := contracts.RandStringByte(32)

	// Each setter only accepts a block whose number modulo 900 falls in its own
	// window - the secret one in [800, 850), the opening one in [850, 900) - so
	// walk the chain far enough to send each of them inside its window. Note
	// that i is not the number of the block a transaction lands in: a fresh
	// backend's first pending block is number 1, SendTransaction builds that
	// pending block on top of the last committed one, and a Commit follows every
	// send here, so the transaction of iteration i lands in block i+1. The
	// secret one therefore lands in 801 and the opening one in 851, and the loop
	// ends at block 901.
	for i := 0; i <= 900; i++ {
		nonce := uint64(i)
		var unsigned *types.Transaction
		switch i {
		case 800:
			unsigned, err = contracts.BuildTxSecretRandomize(nonce, common.RandomizeSMCBinary, 900, randomizeKeyValue)
			if err != nil {
				t.Fatalf("can't create the randomize secret tx: %v", err)
			}
		case 850:
			unsigned, err = contracts.BuildTxOpeningRandomize(nonce, common.RandomizeSMCBinary, randomizeKeyValue)
			if err != nil {
				t.Fatalf("can't create the randomize opening tx: %v", err)
			}
		default:
			unsigned = types.NewTransaction(nonce, common.Address{}, new(big.Int), 21000, new(big.Int), nil)
		}
		tx, err := types.SignTx(unsigned, signer, acc1Key)
		if err != nil {
			t.Fatalf("can't sign tx at block %d: %v", i, err)
		}
		if err := backend.SendTransaction(ctx, tx); err != nil {
			t.Fatalf("can't send tx at block %d: %v", i, err)
		}
		backend.Commit()
	}

	randomize, err := randomizeContract.NewXDCRandomizeCaller(common.RandomizeSMCBinary, backend)
	if err != nil {
		t.Fatalf("can't get a randomize caller: %v", err)
	}
	secrets, err := randomize.GetSecret(nil, acc1Addr)
	if err != nil {
		t.Fatalf("can't get secrets from the randomize contract: %v", err)
	}
	opening, err := randomize.GetOpening(nil, acc1Addr)
	if err != nil {
		t.Fatalf("can't get opening from the randomize contract: %v", err)
	}
	// Insist that the contract really stored something. A setter that reverted
	// stores nothing, and SendTransaction would not say so - a reverted
	// transaction is still mined, with a failed receipt - and then both readings
	// below come back zero and agree for no reason. The key is ASCII, so neither
	// value the setters store is ever zero, which is what lets these two checks
	// tell a written slot from an untouched one.
	var zeroOpening [32]byte
	if len(secrets) == 0 {
		t.Fatalf("the contract stored no secrets, so this comparison can say nothing")
	}
	if opening == zeroOpening {
		t.Fatalf("the contract stored no opening, so this comparison can say nothing")
	}

	statedb, err := backend.BlockChain().State()
	if err != nil {
		t.Fatalf("can't get statedb: %v", err)
	}
	secretsFromState := statedb.GetSecret(acc1Addr)
	if !reflect.DeepEqual(secrets, secretsFromState) {
		t.Fatalf("secrets not equal, statedb utils is wrong:\ncontract reading\n%v\nstatedb reading\n%v", secrets, secretsFromState)
	}
	if opening != statedb.GetOpening(acc1Addr) {
		t.Fatalf("opening not equal, statedb utils is wrong:\ncontract reading\n%v\nstatedb reading\n%v", opening, statedb.GetOpening(acc1Addr))
	}
}
