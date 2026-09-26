// Copyright 2024 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package bind_test

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/accounts/abi/bind/backends"
	"github.com/XinFinOrg/XDPoSChain/accounts/abi/bind/v2"
	"github.com/XinFinOrg/XDPoSChain/accounts/abi/bind/v2/internal/contracts/events"
	"github.com/XinFinOrg/XDPoSChain/accounts/abi/bind/v2/internal/contracts/nested_libraries"
	"github.com/XinFinOrg/XDPoSChain/accounts/abi/bind/v2/internal/contracts/solc_errors"
	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/ethclient"
	"github.com/XinFinOrg/XDPoSChain/ethclient/simulated"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// This file holds the parts of upstream's lib_test.go that exercise deploying
// with library dependencies and filtering events. Upstream keeps two more cases
// in that file, TestEventUnpackEmptyTopics and TestWatchEventsIgnoreMismatch.
// They are carried by watch_events_test.go instead, which lands with the event
// signature error changes: those cases assert the sentinels exported there, and
// this file's package (bind_test) cannot reach unexported ones. If that change
// does not land, the two cases have to be added back here.

// testKey comes from util_test.go.
var testAddr = crypto.PubkeyToAddress(testKey.PublicKey)

func testSetup() (*backends.SimulatedBackend, error) {
	config := *params.TestXDPoSMockChainConfig
	// The balance is the one the other tests of this package fund the account
	// with (see util_test.go): upstream funds it with a tenth of it, which does
	// not cover the five deployments this repository's chain configuration
	// prices them at.
	backend := backends.NewXDCSimulatedBackend(
		types.GenesisAlloc{
			testAddr: {Balance: big.NewInt(100000000000000000)},
		},
		10000000,
		&config,
	)
	return backend, nil
}

func makeTestDeployer(backend simulated.Client) func(input, deployer []byte) (common.Address, *types.Transaction, error) {
	chainId, _ := backend.ChainID(context.Background())
	return bind.DefaultDeployer(bind.NewKeyedTransactor(testKey, chainId), backend)
}

// makeTestDeployerWithNonceAssignment is similar to makeTestDeployer,
// but it returns a deployer that automatically tracks nonce,
// enabling the deployment of multiple contracts from the same account.
func makeTestDeployerWithNonceAssignment(backend simulated.Client) func(input, deployer []byte) (common.Address, *types.Transaction, error) {
	chainId, _ := backend.ChainID(context.Background())
	return bind.DeployerWithNonceAssignment(bind.NewKeyedTransactor(testKey, chainId), backend)
}

// test that deploying a contract with library dependencies works,
// verifying by calling method on the deployed contract.
func TestDeploymentLibraries(t *testing.T) {
	bindBackend, err := testSetup()
	if err != nil {
		t.Fatalf("err setting up test: %v", err)
	}
	defer bindBackend.Backend.Close()

	c := nested_libraries.NewC1()
	constructorInput := c.PackConstructor(big.NewInt(42), big.NewInt(1))
	deploymentParams := &bind.DeploymentParams{
		Contracts: []*bind.MetaData{&nested_libraries.C1MetaData},
		Inputs:    map[string][]byte{nested_libraries.C1MetaData.ID: constructorInput},
	}
	res, err := bind.LinkAndDeploy(deploymentParams, makeTestDeployerWithNonceAssignment(bindBackend.Client()))
	if err != nil {
		t.Fatalf("err: %+v\n", err)
	}
	bindBackend.Commit()

	if len(res.Addresses) != 5 {
		t.Fatalf("deployment should have generated 5 addresses.  got %d", len(res.Addresses))
	}
	for _, tx := range res.Txs {
		_, err = bind.WaitDeployed(context.Background(), bindBackend, tx.Hash())
		if err != nil {
			t.Fatalf("error deploying library: %+v", err)
		}
	}

	doInput := c.PackDo(big.NewInt(1))
	contractAddr := res.Addresses[nested_libraries.C1MetaData.ID]
	callOpts := &bind.CallOpts{From: common.Address{}, Context: context.Background()}
	instance := c.Instance(bindBackend, contractAddr)
	internalCallCount, err := bind.Call(instance, callOpts, doInput, c.UnpackDo)
	if err != nil {
		t.Fatalf("err unpacking result: %v", err)
	}
	if internalCallCount.Uint64() != 6 {
		t.Fatalf("expected internal call count of 6.  got %d.", internalCallCount.Uint64())
	}
}

// Same as TestDeployment.  However, stagger the deployments with overrides:
// first deploy the library deps and then the contract.
func TestDeploymentWithOverrides(t *testing.T) {
	bindBackend, err := testSetup()
	if err != nil {
		t.Fatalf("err setting up test: %v", err)
	}
	defer bindBackend.Backend.Close()

	// deploy all the library dependencies of our target contract, but not the target contract itself.
	deploymentParams := &bind.DeploymentParams{
		Contracts: nested_libraries.C1MetaData.Deps,
	}
	res, err := bind.LinkAndDeploy(deploymentParams, makeTestDeployerWithNonceAssignment(bindBackend))
	if err != nil {
		t.Fatalf("err: %+v\n", err)
	}
	bindBackend.Commit()

	if len(res.Addresses) != 4 {
		t.Fatalf("deployment should have generated 4 addresses.  got %d", len(res.Addresses))
	}
	for _, tx := range res.Txs {
		_, err = bind.WaitDeployed(context.Background(), bindBackend, tx.Hash())
		if err != nil {
			t.Fatalf("error deploying library: %+v", err)
		}
	}

	c := nested_libraries.NewC1()
	constructorInput := c.PackConstructor(big.NewInt(42), big.NewInt(1))
	overrides := res.Addresses

	// deploy the contract
	deploymentParams = &bind.DeploymentParams{
		Contracts: []*bind.MetaData{&nested_libraries.C1MetaData},
		Inputs:    map[string][]byte{nested_libraries.C1MetaData.ID: constructorInput},
		Overrides: overrides,
	}
	res, err = bind.LinkAndDeploy(deploymentParams, makeTestDeployer(bindBackend))
	if err != nil {
		t.Fatalf("err: %+v\n", err)
	}
	bindBackend.Commit()

	if len(res.Addresses) != 1 {
		t.Fatalf("deployment should have generated 1 address.  got %d", len(res.Addresses))
	}
	for _, tx := range res.Txs {
		_, err = bind.WaitDeployed(context.Background(), bindBackend, tx.Hash())
		if err != nil {
			t.Fatalf("error deploying library: %+v", err)
		}
	}

	// call the deployed contract and make sure it returns the correct result
	doInput := c.PackDo(big.NewInt(1))
	instance := c.Instance(bindBackend, res.Addresses[nested_libraries.C1MetaData.ID])
	callOpts := new(bind.CallOpts)
	internalCallCount, err := bind.Call(instance, callOpts, doInput, c.UnpackDo)
	if err != nil {
		t.Fatalf("error calling contract: %v", err)
	}
	if internalCallCount.Uint64() != 6 {
		t.Fatalf("expected internal call count of 6.  got %d.", internalCallCount.Uint64())
	}
}

// returns transaction auth to send a basic transaction from testAddr
func defaultTxAuth() *bind.TransactOpts {
	signer := types.LatestSigner(params.AllDevChainProtocolChanges)
	opts := &bind.TransactOpts{
		From:  testAddr,
		Nonce: nil,
		Signer: func(address common.Address, tx *types.Transaction) (*types.Transaction, error) {
			signature, err := crypto.Sign(signer.Hash(tx).Bytes(), testKey)
			if err != nil {
				return nil, err
			}
			signedTx, err := tx.WithSignature(signer, signature)
			if err != nil {
				return nil, err
			}
			return signedTx, nil
		},
		Context: context.Background(),
	}
	return opts
}

func TestEvents(t *testing.T) {
	// test watch/filter logs method on a contract that emits various kinds of events (struct-containing, etc.)
	backend, err := testSetup()
	if err != nil {
		t.Fatalf("error setting up testing env: %v", err)
	}
	defer backend.Backend.Close()

	deploymentParams := &bind.DeploymentParams{
		Contracts: []*bind.MetaData{&events.CMetaData},
	}
	res, err := bind.LinkAndDeploy(deploymentParams, makeTestDeployer(backend))
	if err != nil {
		t.Fatalf("error deploying contract for testing: %v", err)
	}

	backend.Commit()
	if _, err := bind.WaitDeployed(context.Background(), backend, res.Txs[events.CMetaData.ID].Hash()); err != nil {
		t.Fatalf("WaitDeployed failed %v", err)
	}

	c := events.NewC()
	instance := c.Instance(backend, res.Addresses[events.CMetaData.ID])

	newCBasic1Ch := make(chan *events.CBasic1)
	newCBasic2Ch := make(chan *events.CBasic2)
	watchOpts := &bind.WatchOpts{}
	sub1, err := bind.WatchEvents(instance, watchOpts, c.UnpackBasic1Event, newCBasic1Ch)
	if err != nil {
		t.Fatalf("WatchEvents returned error: %v", err)
	}
	sub2, err := bind.WatchEvents(instance, watchOpts, c.UnpackBasic2Event, newCBasic2Ch)
	if err != nil {
		t.Fatalf("WatchEvents returned error: %v", err)
	}
	defer sub1.Unsubscribe()
	defer sub2.Unsubscribe()

	packedInput := c.PackEmitMulti()
	tx, err := bind.Transact(instance, defaultTxAuth(), packedInput)
	if err != nil {
		t.Fatalf("failed to send transaction: %v", err)
	}
	backend.Commit()
	if _, err := bind.WaitMined(context.Background(), backend, tx.Hash()); err != nil {
		t.Fatalf("error waiting for tx to be mined: %v", err)
	}

	timeout := time.NewTimer(2 * time.Second)
	e1Count := 0
	e2Count := 0
	for {
		select {
		case <-newCBasic1Ch:
			e1Count++
		case <-newCBasic2Ch:
			e2Count++
		case <-timeout.C:
			goto done
		}
		if e1Count == 2 && e2Count == 1 {
			break
		}
	}
done:
	if e1Count != 2 {
		t.Fatalf("expected event type 1 count to be 2.  got %d", e1Count)
	}
	if e2Count != 1 {
		t.Fatalf("expected event type 2 count to be 1.  got %d", e2Count)
	}

	// now, test that we can filter those same logs after they were included in the chain

	filterOpts := &bind.FilterOpts{
		Start:   0,
		Context: context.Background(),
	}
	it, err := bind.FilterEvents(instance, filterOpts, c.UnpackBasic1Event)
	if err != nil {
		t.Fatalf("error filtering logs %v\n", err)
	}
	it2, err := bind.FilterEvents(instance, filterOpts, c.UnpackBasic2Event)
	if err != nil {
		t.Fatalf("error filtering logs %v\n", err)
	}

	e1Count = 0
	e2Count = 0
	for it.Next() {
		e1Count++
	}
	// Next sets the error only as it returns false, so it has to be read after
	// the loop; reading it inside the body of a successful iteration never sees it.
	if err := it.Error(); err != nil {
		t.Fatalf("got error while iterating events for e1: %v", err)
	}
	for it2.Next() {
		e2Count++
	}
	if err := it2.Error(); err != nil {
		t.Fatalf("got error while iterating events for e2: %v", err)
	}
	if e1Count != 2 {
		t.Fatalf("expected e1Count of 2 from filter call.  got %d", e1Count)
	}
	if e2Count != 1 {
		t.Fatalf("expected e2Count of 1 from filter call.  got %d", e2Count)
	}
}

func TestErrors(t *testing.T) {
	// test that a contract call's custom revert data can be extracted and unpacked
	// into the generated error type
	backend, err := testSetup()
	if err != nil {
		t.Fatalf("error setting up testing env: %v", err)
	}
	defer backend.Backend.Close()

	deploymentParams := &bind.DeploymentParams{
		Contracts: []*bind.MetaData{&solc_errors.CMetaData},
	}
	res, err := bind.LinkAndDeploy(deploymentParams, makeTestDeployer(backend))
	if err != nil {
		t.Fatalf("error deploying contract for testing: %v", err)
	}

	backend.Commit()
	if _, err := bind.WaitDeployed(context.Background(), backend, res.Txs[solc_errors.CMetaData.ID].Hash()); err != nil {
		t.Fatalf("WaitDeployed failed %v", err)
	}

	c := solc_errors.NewC()
	instance := c.Instance(backend, res.Addresses[solc_errors.CMetaData.ID])
	packedInput := c.PackFoo()
	opts := &bind.CallOpts{From: res.Addresses[solc_errors.CMetaData.ID]}
	_, err = bind.Call[struct{}](instance, opts, packedInput, nil)
	if err == nil {
		t.Fatalf("expected call to fail")
	}
	raw, hasRevertErrorData := ethclient.RevertErrorData(err)
	if !hasRevertErrorData {
		t.Fatalf("expected call error to contain revert error data.")
	}
	rawUnpackedErr, err := c.UnpackError(raw)
	if err != nil {
		t.Fatalf("expected to unpack error")
	}

	unpackedErr, ok := rawUnpackedErr.(*solc_errors.CBadThing)
	if !ok {
		t.Fatalf("unexpected type for error")
	}
	if unpackedErr.Arg1.Cmp(big.NewInt(0)) != 0 {
		t.Fatalf("bad unpacked error result: expected Arg1 field to be 0.  got %s", unpackedErr.Arg1.String())
	}
	if unpackedErr.Arg2.Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("bad unpacked error result: expected Arg2 field to be 1.  got %s", unpackedErr.Arg2.String())
	}
	if unpackedErr.Arg3.Cmp(big.NewInt(2)) != 0 {
		t.Fatalf("bad unpacked error result: expected Arg3 to be 2.  got %s", unpackedErr.Arg3.String())
	}
	if unpackedErr.Arg4 != false {
		t.Fatalf("bad unpacked error result: expected Arg4 to be false.  got true")
	}
}
