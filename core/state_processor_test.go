// Copyright 2020 The go-ethereum Authors
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

package core

import (
	"crypto/ecdsa"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strings"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/tracing"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/crypto/keccak"
	"github.com/XinFinOrg/XDPoSChain/ethdb/memorydb"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/XinFinOrg/XDPoSChain/rpc"
	"github.com/XinFinOrg/XDPoSChain/trie"
	"github.com/holiman/uint256"
)

type noopConsensusEngine struct{}

func (noopConsensusEngine) Author(header *types.Header) (common.Address, error) {
	return common.Address{}, nil
}
func (noopConsensusEngine) VerifyHeader(chain consensus.ChainReader, header *types.Header, fullVerify bool) error {
	return nil
}
func (noopConsensusEngine) VerifyHeaders(chain consensus.ChainReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	quit := make(chan struct{})
	results := make(chan error, len(headers))
	for range headers {
		results <- nil
	}
	close(results)
	return quit, results
}
func (noopConsensusEngine) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	return nil
}
func (noopConsensusEngine) VerifySeal(chain consensus.ChainReader, header *types.Header) error {
	return nil
}
func (noopConsensusEngine) Prepare(chain consensus.ChainReader, header *types.Header) error {
	return nil
}
func (noopConsensusEngine) Finalize(chain consensus.ChainReader, header *types.Header, state vm.StateDB, parentState *state.StateDB, txs []*types.Transaction, uncles []*types.Header, receipts []*types.Receipt) (*types.Block, error) {
	return nil, nil
}
func (noopConsensusEngine) Seal(chain consensus.ChainReader, block *types.Block, stop <-chan struct{}) (*types.Block, error) {
	return block, nil
}
func (noopConsensusEngine) CalcDifficulty(chain consensus.ChainReader, time uint64, parent *types.Header) *big.Int {
	return common.Big0
}
func (noopConsensusEngine) APIs(chain consensus.ChainReader) []rpc.API { return nil }

// TestStateProcessorErrors tests the output from the 'core' errors
// as defined in core/error.go. These errors are generated when the
// blockchain imports bad blocks, meaning blocks which have valid headers but
// contain invalid transactions
func TestStateProcessorErrors(t *testing.T) {
	var (
		config = &params.ChainConfig{
			ChainID:                big.NewInt(1),
			HomesteadBlock:         big.NewInt(0),
			EIP150Block:            big.NewInt(0),
			EIP155Block:            big.NewInt(0),
			EIP158Block:            big.NewInt(0),
			ByzantiumBlock:         big.NewInt(0),
			ConstantinopleBlock:    big.NewInt(0),
			PetersburgBlock:        big.NewInt(0),
			IstanbulBlock:          big.NewInt(0),
			TIPTRC21FeeBlock:       big.NewInt(0),
			Gas50xBlock:            big.NewInt(0),
			BerlinBlock:            big.NewInt(0),
			LondonBlock:            big.NewInt(0),
			ShanghaiBlock:          big.NewInt(0),
			EIP1559Block:           big.NewInt(0),
			CancunBlock:            big.NewInt(0),
			PragueBlock:            big.NewInt(0),
			OsakaBlock:             big.NewInt(0),
			TRC21IssuerSMC:         params.TestnetChainConfig.TRC21IssuerSMC,
			XDCXListingSMC:         params.TestnetChainConfig.XDCXListingSMC,
			RelayerRegistrationSMC: params.TestnetChainConfig.RelayerRegistrationSMC,
			LendingRegistrationSMC: params.TestnetChainConfig.LendingRegistrationSMC,
			Ethash:                 new(params.EthashConfig),
		}
		signer  = types.LatestSigner(config)
		key1, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		key2, _ = crypto.HexToECDSA("0202020202020202020202020202020202020202020202020202002020202020")
	)
	var makeTx = func(key *ecdsa.PrivateKey, nonce uint64, to common.Address, amount *big.Int, gasLimit uint64, gasPrice *big.Int, data []byte) *types.Transaction {
		tx, _ := types.SignTx(types.NewTransaction(nonce, to, amount, gasLimit, gasPrice, data), signer, key)
		return tx
	}
	var mkDynamicTx = func(nonce uint64, to common.Address, gasLimit uint64, gasTipCap, gasFeeCap *big.Int) *types.Transaction {
		tx, _ := types.SignTx(types.NewTx(&types.DynamicFeeTx{
			Nonce:     nonce,
			GasTipCap: gasTipCap,
			GasFeeCap: gasFeeCap,
			Gas:       gasLimit,
			To:        &to,
			Value:     big.NewInt(0),
		}), signer, key1)
		return tx
	}
	var mkDynamicCreationTx = func(nonce uint64, gasLimit uint64, gasTipCap, gasFeeCap *big.Int, data []byte) *types.Transaction {
		tx, _ := types.SignTx(types.NewTx(&types.DynamicFeeTx{
			Nonce:     nonce,
			GasTipCap: gasTipCap,
			GasFeeCap: gasFeeCap,
			Gas:       gasLimit,
			Value:     big.NewInt(0),
			Data:      data,
		}), signer, key1)
		return tx
	}
	var mkSetCodeTx = func(nonce uint64, to common.Address, gasLimit uint64, gasTipCap, gasFeeCap *big.Int, authlist []types.SetCodeAuthorization) *types.Transaction {
		tx, err := types.SignTx(types.NewTx(&types.SetCodeTx{
			Nonce:     nonce,
			GasTipCap: uint256.MustFromBig(gasTipCap),
			GasFeeCap: uint256.MustFromBig(gasFeeCap),
			Gas:       gasLimit,
			To:        to,
			Value:     new(uint256.Int),
			AuthList:  authlist,
		}), signer, key1)
		if err != nil {
			t.Fatal(err)
		}
		return tx
	}

	{ // Tests against a 'recent' chain definition
		var (
			db    = rawdb.NewMemoryDatabase()
			gspec = &Genesis{
				Config: config,
				Alloc: types.GenesisAlloc{
					common.HexToAddress("0x71562b71999873DB5b286dF957af199Ec94617F7"): types.Account{
						Balance: big.NewInt(1000000000000000000), // 1 ether
						Nonce:   0,
					},
					common.HexToAddress("0xfd0810DD14796680f72adf1a371963d0745BCc64"): types.Account{
						Balance: big.NewInt(1000000000000000000), // 1 ether
						Nonce:   math.MaxUint64,
					},
				},
			}
			blockchain, _ = NewBlockChain(db, nil, gspec, ethash.NewFaker(), vm.Config{})
		)
		defer blockchain.Stop()
		num := big.NewInt(1)
		rules := config.Rules(num)
		bigNumber := new(big.Int).SetBytes(common.MaxHash.Bytes())
		tooBigNumber := new(big.Int).Set(bigNumber)
		tooBigNumber.Add(tooBigNumber, common.Big1)
		maxInitCodeSize := params.MaxInitCodeSize
		if rules.IsOsaka {
			maxInitCodeSize = params.MaxInitCodeSizeOsaka
		}
		tooBigInitCode := make([]byte, maxInitCodeSize+1)
		tooBigInitCodeIntrinsicGas, err := IntrinsicGas(tooBigInitCode, nil, nil, true, rules.IsHomestead, rules.IsEIP1559)
		if err != nil {
			t.Fatal(err)
		}
		tooBigInitCodeRequiredGas := tooBigInitCodeIntrinsicGas
		if rules.IsPrague {
			tooBigInitCodeFloorGas, err := FloorDataGas(tooBigInitCode)
			if err != nil {
				t.Fatal(err)
			}
			if tooBigInitCodeFloorGas > tooBigInitCodeRequiredGas {
				tooBigInitCodeRequiredGas = tooBigInitCodeFloorGas
			}
		}
		tooBigInitCodeTx := mkDynamicCreationTx(0, tooBigInitCodeRequiredGas+1000, common.Big0, big.NewInt(params.InitialBaseFee), tooBigInitCode)
		gasLimit := blockchain.CurrentHeader().GasLimit
		for i, tt := range []struct {
			txs  []*types.Transaction
			want string
		}{
			{ // ErrNonceTooLow
				txs: []*types.Transaction{
					makeTx(key1, 0, common.Address{}, big.NewInt(0), params.TxGas, big.NewInt(12500000000), nil),
					makeTx(key1, 0, common.Address{}, big.NewInt(0), params.TxGas, big.NewInt(12500000000), nil),
				},
				want: "could not apply tx 1 [0xecd6a889a307155b3562cd64c86957e36fa58267cb4efbbe39aa692fd7aab09a]: nonce too low: address xdc71562b71999873DB5b286dF957af199Ec94617F7, tx: 0 state: 1",
			},
			{ // ErrNonceTooHigh
				txs: []*types.Transaction{
					makeTx(key1, 100, common.Address{}, big.NewInt(0), params.TxGas, big.NewInt(875000000), nil),
				},
				want: "could not apply tx 0 [0xdebad714ca7f363bd0d8121c4518ad48fa469ca81b0a081be3d10c17460f751b]: nonce too high: address xdc71562b71999873DB5b286dF957af199Ec94617F7, tx: 100 state: 0",
			},
			{ // ErrNonceMax
				txs: []*types.Transaction{
					makeTx(key2, math.MaxUint64, common.Address{}, big.NewInt(0), params.TxGas, big.NewInt(875000000), nil),
				},
				want: "could not apply tx 0 [0x84ea18d60eb2bb3b040e3add0eb72f757727122cc257dd858c67cb6591a85986]: nonce has max value: address xdcfd0810DD14796680f72adf1a371963d0745BCc64, nonce: 18446744073709551615",
			},
			{ // ErrGasLimitReached
				txs: []*types.Transaction{
					makeTx(key1, 0, common.Address{}, big.NewInt(0), gasLimit+1, big.NewInt(12500000000), nil),
				},
				want: "could not apply tx 0 [0x141d5093bebc1570bf844ff66c14113a4516f601f8e4df7aa4d575a4e9bcaa33]: gas limit reached, have: 4712388, need: 4712389",
			},
			{ // ErrInsufficientFundsForTransfer
				txs: []*types.Transaction{
					makeTx(key1, 0, common.Address{}, big.NewInt(1000000000000000000), params.TxGas, big.NewInt(12500000000), nil),
				},
				want: "could not apply tx 0 [0x50f89093bf5ad7f4ae6f9e3bad44d4dc130247ea0429df0cf78873584a76dfa1]: insufficient funds for gas * price + value: address xdc71562b71999873DB5b286dF957af199Ec94617F7 have 1000000000000000000 want 1000262500000000000",
			},
			{ // ErrInsufficientFunds
				txs: []*types.Transaction{
					makeTx(key1, 0, common.Address{}, big.NewInt(0), params.TxGas, big.NewInt(900000000000000000), nil),
				},
				want: "could not apply tx 0 [0x4a69690c4b0cd85e64d0d9ea06302455b01e10a83db964d60281739752003440]: insufficient funds for gas * price + value: address xdc71562b71999873DB5b286dF957af199Ec94617F7 have 1000000000000000000 want 18900000000000000000000",
			},
			// ErrGasUintOverflow
			// One missing 'core' error is ErrGasUintOverflow: "gas uint64 overflow",
			// In order to trigger that one, we'd have to allocate a _huge_ chunk of data, such that the
			// multiplication len(data) +gas_per_byte overflows uint64. Not testable at the moment
			{ // ErrIntrinsicGas
				txs: []*types.Transaction{
					makeTx(key1, 0, common.Address{}, big.NewInt(0), params.TxGas-1000, big.NewInt(12500000000), nil),
				},
				want: "could not apply tx 0 [0xa3484a466ffa8a88dc95e6ff520c853659dfc5507039c0b1452c2b845438771b]: intrinsic gas too low: have 20000, want 21000",
			},
			{ // ErrGasLimitReached
				txs: []*types.Transaction{
					makeTx(key1, 0, common.Address{}, big.NewInt(0), gasLimit+1, big.NewInt(12500000000), nil),
				},
				want: "could not apply tx 0 [0x141d5093bebc1570bf844ff66c14113a4516f601f8e4df7aa4d575a4e9bcaa33]: gas limit reached, have: 4712388, need: 4712389",
			},
			{ // ErrFeeCapTooLow
				txs: []*types.Transaction{
					mkDynamicTx(0, common.Address{}, params.TxGas, big.NewInt(0), big.NewInt(0)),
				},
				want: "could not apply tx 0 [0xc4ab868fef0c82ae0387b742aee87907f2d0fc528fc6ea0a021459fb0fc4a4a8]: max fee per gas less than block base fee: address xdc71562b71999873DB5b286dF957af199Ec94617F7, maxFeePerGas: 0 baseFee: 12500000000",
			},
			{ // ErrTipVeryHigh
				txs: []*types.Transaction{
					mkDynamicTx(0, common.Address{}, params.TxGas, tooBigNumber, big.NewInt(1)),
				},
				want: "could not apply tx 0 [0x15b8391b9981f266b32f3ab7da564bbeb3d6c21628364ea9b32a21139f89f712]: max priority fee per gas higher than 2^256-1: address xdc71562b71999873DB5b286dF957af199Ec94617F7, maxPriorityFeePerGas bit length: 257",
			},
			{ // ErrFeeCapVeryHigh
				txs: []*types.Transaction{
					mkDynamicTx(0, common.Address{}, params.TxGas, big.NewInt(1), tooBigNumber),
				},
				want: "could not apply tx 0 [0x48bc299b83fdb345c57478f239e89814bb3063eb4e4b49f3b6057a69255c16bd]: max fee per gas higher than 2^256-1: address xdc71562b71999873DB5b286dF957af199Ec94617F7, maxFeePerGas bit length: 257",
			},
			{ // ErrTipAboveFeeCap
				txs: []*types.Transaction{
					mkDynamicTx(0, common.Address{}, params.TxGas, big.NewInt(2), big.NewInt(1)),
				},
				want: "could not apply tx 0 [0xf987a31ff0c71895780a7612f965a0c8b056deb54e020bb44fa478092f14c9b4]: max priority fee per gas higher than max fee per gas: address xdc71562b71999873DB5b286dF957af199Ec94617F7, maxPriorityFeePerGas: 2, maxFeePerGas: 1",
			},
			{ // ErrInsufficientFunds
				// Available balance:           1000000000000000000
				// Effective cost:                   18375000021000
				// FeeCap * gas:                1050000000000000000
				// This test is designed to have the effective cost be covered by the balance, but
				// the extended requirement on FeeCap*gas < balance to fail
				txs: []*types.Transaction{
					mkDynamicTx(0, common.Address{}, params.TxGas, big.NewInt(1), big.NewInt(50000000000000)),
				},
				want: "could not apply tx 0 [0x413603cd096a87f41b1660d3ed3e27d62e1da78eac138961c0a1314ed43bd129]: insufficient funds for gas * price + value: address xdc71562b71999873DB5b286dF957af199Ec94617F7 have 1000000000000000000 want 1050000000000000000",
			},
			{ // Another ErrInsufficientFunds, this one to ensure that feecap/tip of max u256 is allowed
				txs: []*types.Transaction{
					mkDynamicTx(0, common.Address{}, params.TxGas, bigNumber, bigNumber),
				},
				want: "could not apply tx 0 [0xd82a0c2519acfeac9a948258c47e784acd20651d9d80f9a1c67b4137651c3a24]: insufficient funds for gas * price + value: address xdc71562b71999873DB5b286dF957af199Ec94617F7 have 1000000000000000000 want 2431633873983640103894990685182446064918669677978451844828609264166175722438635000",
			},
			{ // ErrMaxInitCodeSizeExceeded
				txs: []*types.Transaction{
					tooBigInitCodeTx,
				},
				want: fmt.Sprintf("could not apply tx 0 [%s]: max initcode size exceeded: code size %d limit %d", tooBigInitCodeTx.Hash().Hex(), len(tooBigInitCode), maxInitCodeSize),
			},
			{ // ErrIntrinsicGas: Not enough gas to cover init code
				txs: []*types.Transaction{
					mkDynamicCreationTx(0, 54299, common.Big0, big.NewInt(params.InitialBaseFee), make([]byte, 320)),
				},
				want: "could not apply tx 0 [0x83f0bd65f2c2ad82de0da306aa93dea5e47d4ba0cd9f23ec4ce3fd0a3246da1c]: intrinsic gas too low: have 54299, want 54300",
			},
			{ // ErrEmptyAuthList
				txs: []*types.Transaction{
					mkSetCodeTx(0, common.Address{}, params.TxGas, big.NewInt(params.InitialBaseFee), big.NewInt(params.InitialBaseFee), nil),
				},
				want: "could not apply tx 0 [0x2fadb4fa7ccf8564edc21590f8d94a5b93a981b2bb2de8256978cb7361bc69de]: EIP-7702 transaction with empty auth list (sender 0x71562b71999873DB5b286dF957af199Ec94617F7)",
			},
			// ErrSetCodeTxCreate cannot be tested: it is impossible to create a SetCode-tx with nil `to`.
			{ // ErrGasLimitTooHigh
				txs: []*types.Transaction{
					makeTx(key1, 0, common.Address{}, big.NewInt(0), params.MaxTxGas+1, big.NewInt(params.InitialBaseFee), nil),
				},
				want: "could not apply tx 0 [0xb49a1f798a865850a62b4deb6a71efb9150e5bf11a46b3f331fec62baa0547b4]: transaction gas limit too high (cap: 16777216, tx: 16777217)",
			},
		} {
			block := GenerateBadBlock(t, gspec.ToBlock(), ethash.NewFaker(), tt.txs, gspec.Config)
			_, err := blockchain.InsertChain(types.Blocks{block})
			if err == nil {
				t.Fatal("block imported without errors")
			}
			if have, want := err.Error(), tt.want; have != want {
				t.Errorf("test %d:\nhave \"%v\"\nwant \"%v\"\n", i, have, want)
			}
		}
	}

	// ErrTxTypeNotSupported, For this, we need an older chain
	{
		var (
			db         = rawdb.NewMemoryDatabase()
			futureFork = big.NewInt(1_000_000_000)
			gspec      = &Genesis{
				Config: &params.ChainConfig{
					ChainID:             big.NewInt(1),
					HomesteadBlock:      big.NewInt(0),
					EIP150Block:         big.NewInt(0),
					EIP155Block:         big.NewInt(0),
					EIP158Block:         big.NewInt(0),
					ByzantiumBlock:      big.NewInt(0),
					ConstantinopleBlock: big.NewInt(0),
					PetersburgBlock:     big.NewInt(0),
					IstanbulBlock:       big.NewInt(0),
					TIPTRC21FeeBlock:    big.NewInt(0),
					Gas50xBlock:         new(big.Int).Set(futureFork),
					BerlinBlock:         new(big.Int).Set(futureFork),
					LondonBlock:         new(big.Int).Set(futureFork),
					MergeBlock:          new(big.Int).Set(futureFork),
					ShanghaiBlock:       new(big.Int).Set(futureFork),
					EIP1559Block:        new(big.Int).Set(futureFork),
					CancunBlock:         new(big.Int).Set(futureFork),
					PragueBlock:         new(big.Int).Set(futureFork),
					OsakaBlock:          new(big.Int).Set(futureFork),
					Ethash:              new(params.EthashConfig),
				},
				Alloc: types.GenesisAlloc{
					common.HexToAddress("0x71562b71999873DB5b286dF957af199Ec94617F7"): types.Account{
						Balance: big.NewInt(1000000000000000000), // 1 ether
						Nonce:   0,
					},
				},
			}
			blockchain *BlockChain
		)
		setXinFinForksToFuture(gspec.Config, futureFork)
		var err error
		blockchain, err = NewBlockChain(db, nil, gspec, ethash.NewFaker(), vm.Config{})
		if err != nil {
			t.Fatalf("failed to create old-chain blockchain: %v", err)
		}
		defer blockchain.Stop()
		for i, tt := range []struct {
			txs  []*types.Transaction
			want string
		}{
			{ // ErrTxTypeNotSupported
				txs: []*types.Transaction{
					mkDynamicTx(0, common.Address{}, params.TxGas-1000, big.NewInt(0), big.NewInt(0)),
				},
				want: "transaction type not supported",
			},
		} {
			block := GenerateBadBlock(t, gspec.ToBlock(), ethash.NewFaker(), tt.txs, gspec.Config)
			_, err := blockchain.InsertChain(types.Blocks{block})
			if err == nil {
				t.Fatal("block imported without errors")
			}
			if have, want := err.Error(), tt.want; have != want {
				t.Errorf("test %d:\nhave \"%v\"\nwant \"%v\"\n", i, have, want)
			}
		}
	}
}

// TestStateProcessorDenylistHardForkBoundary tests state processor denylist hard fork boundary.
func TestStateProcessorDenylistHardForkBoundary(t *testing.T) {
	testDenylistedReceiver := common.HexToAddress("0x5248bfb72fd4f234e062d3e9bb76f08643004fcd")
	if !common.IsInDenylist(&testDenylistedReceiver) {
		t.Fatalf("test receiver is not denylisted: %v", testDenylistedReceiver.Hex())
	}

	key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	if err != nil {
		t.Fatalf("failed to parse test key: %v", err)
	}
	from := crypto.PubkeyToAddress(key.PublicKey)

	newConfig := func(forkBlock uint64) *params.ChainConfig {
		futureFork := big.NewInt(1_000_000_000)
		cfg := &params.ChainConfig{
			ChainID:                     big.NewInt(1),
			HomesteadBlock:              big.NewInt(0),
			DenylistBlock:               new(big.Int).SetUint64(forkBlock),
			EIP150Block:                 big.NewInt(0),
			EIP155Block:                 big.NewInt(0),
			EIP158Block:                 big.NewInt(0),
			ByzantiumBlock:              big.NewInt(0),
			ConstantinopleBlock:         big.NewInt(0),
			PetersburgBlock:             big.NewInt(0),
			IstanbulBlock:               big.NewInt(0),
			TIPTRC21FeeBlock:            big.NewInt(0),
			Gas50xBlock:                 big.NewInt(0),
			BerlinBlock:                 big.NewInt(0),
			LondonBlock:                 big.NewInt(0),
			ShanghaiBlock:               big.NewInt(0),
			EIP1559Block:                big.NewInt(0),
			CancunBlock:                 big.NewInt(0),
			PragueBlock:                 big.NewInt(0),
			OsakaBlock:                  big.NewInt(0),
			TIPXDCXCancellationFeeBlock: nil,
			Ethash:                      new(params.EthashConfig),
		}
		setXinFinForksToFuture(cfg, futureFork)
		cfg.TIPSigningBlock = big.NewInt(0)
		cfg.TIPRandomizeBlock = big.NewInt(0)
		cfg.TIPIncreaseMasternodesBlock = big.NewInt(0)
		cfg.DenylistBlock = new(big.Int).SetUint64(forkBlock)
		return cfg
	}

	run := func(t *testing.T, forkBlock uint64, expectDenylistErr bool) {
		t.Helper()

		cfg := newConfig(forkBlock)
		signer := types.LatestSigner(cfg)
		tx, err := types.SignTx(types.NewTransaction(0, testDenylistedReceiver, big.NewInt(1), params.TxGas, big.NewInt(params.InitialBaseFee), nil), signer, key)
		if err != nil {
			t.Fatalf("failed to sign tx: %v", err)
		}

		gspec := &Genesis{
			Config: cfg,
			Alloc: types.GenesisAlloc{
				from: {
					Balance: big.NewInt(1_000_000_000_000_000_000),
					Nonce:   0,
				},
			},
		}
		db := rawdb.NewMemoryDatabase()
		blockchain, err := NewBlockChain(db, nil, gspec, ethash.NewFaker(), vm.Config{})
		if err != nil {
			t.Fatalf("failed to create blockchain: %v", err)
		}
		defer blockchain.Stop()

		block := GenerateBadBlock(t, gspec.ToBlock(), ethash.NewFaker(), []*types.Transaction{tx}, cfg)
		_, err = blockchain.InsertChain(types.Blocks{block})
		if err == nil {
			t.Fatal("expected block import error")
		}

		hasDenylistErr := strings.Contains(err.Error(), "receiver in denylist")
		if hasDenylistErr != expectDenylistErr {
			t.Fatalf("unexpected denylist error presence (fork=%d): have=%v err=%v", forkBlock, hasDenylistErr, err)
		}
	}

	t.Run("below hardfork does not trigger denylist guard", func(t *testing.T) {
		run(t, 2, false)
	})
	t.Run("at hardfork triggers denylist guard", func(t *testing.T) {
		run(t, 1, true)
	})
}

// TestStateProcessorSpecialApplyTransactionsUseChainConfig tests block
// processing uses the configured system-contract addresses when classifying
// XDCX/XDCZ apply transactions.
func TestStateProcessorSpecialApplyTransactionsUseChainConfig(t *testing.T) {
	key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	if err != nil {
		t.Fatalf("failed to parse test key: %v", err)
	}
	from := crypto.PubkeyToAddress(key.PublicKey)
	tokenAddr := common.HexToAddress("0x1234567890123456789012345678901234567890")
	constantZeroCode := common.FromHex("0x600060005260206000f3")

	newConfig := func() *params.ChainConfig {
		cfg := &params.ChainConfig{
			ChainID:                     big.NewInt(1),
			HomesteadBlock:              big.NewInt(0),
			TIPXDCXBlock:                big.NewInt(0),
			EIP150Block:                 big.NewInt(0),
			EIP155Block:                 big.NewInt(0),
			EIP158Block:                 big.NewInt(0),
			ByzantiumBlock:              big.NewInt(0),
			ConstantinopleBlock:         big.NewInt(0),
			PetersburgBlock:             big.NewInt(0),
			IstanbulBlock:               big.NewInt(0),
			TIPTRC21FeeBlock:            big.NewInt(0),
			Gas50xBlock:                 big.NewInt(0),
			BerlinBlock:                 big.NewInt(0),
			LondonBlock:                 big.NewInt(0),
			ShanghaiBlock:               big.NewInt(0),
			EIP1559Block:                big.NewInt(0),
			CancunBlock:                 big.NewInt(0),
			PragueBlock:                 big.NewInt(0),
			OsakaBlock:                  big.NewInt(0),
			TRC21IssuerSMC:              params.TestnetChainConfig.TRC21IssuerSMC,
			XDCXListingSMC:              params.TestnetChainConfig.XDCXListingSMC,
			RelayerRegistrationSMC:      params.TestnetChainConfig.RelayerRegistrationSMC,
			LendingRegistrationSMC:      params.TestnetChainConfig.LendingRegistrationSMC,
			TIPXDCXCancellationFeeBlock: nil,
			Ethash:                      new(params.EthashConfig),
		}
		return cfg
	}

	tests := []struct {
		name     string
		to       func(*params.ChainConfig) common.Address
		method   string
		isApply  func(*types.Transaction, *params.ChainConfig) bool
		validate func(consensus.ChainContext, *big.Int, *state.StateDB, common.Address) error
	}{
		{
			name:   "XDCX",
			to:     func(cfg *params.ChainConfig) common.Address { return cfg.XDCXListingSMC },
			method: common.XDCXApplyMethod,
			isApply: func(tx *types.Transaction, cfg *params.ChainConfig) bool {
				return tx.IsXDCXApplyTransaction(cfg)
			},
			validate: ValidateXDCXApplyTransaction,
		},
		{
			name:   "XDCZ",
			to:     func(cfg *params.ChainConfig) common.Address { return cfg.TRC21IssuerSMC },
			method: common.XDCZApplyMethod,
			isApply: func(tx *types.Transaction, cfg *params.ChainConfig) bool {
				return tx.IsXDCZApplyTransaction(cfg)
			},
			validate: ValidateXDCZApplyTransaction,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := newConfig()
			signer := types.LatestSigner(cfg)
			data := append(common.FromHex(tt.method), common.LeftPadBytes(tokenAddr.Bytes(), 32)...)
			tx, err := types.SignTx(types.NewTransaction(0, tt.to(cfg), big.NewInt(0), 50000, big.NewInt(params.InitialBaseFee), data), signer, key)
			if err != nil {
				t.Fatalf("failed to sign tx: %v", err)
			}
			if !tt.isApply(tx, cfg) {
				t.Fatal("expected transaction to be classified as special apply")
			}

			gspec := &Genesis{
				Config: cfg,
				Alloc: types.GenesisAlloc{
					from: {
						Balance: big.NewInt(1_000_000_000_000_000_000),
						Nonce:   0,
					},
					tokenAddr: {
						Balance: big.NewInt(0),
						Nonce:   1,
						Code:    constantZeroCode,
					},
				},
			}
			db := rawdb.NewMemoryDatabase()
			blockchain, err := NewBlockChain(db, nil, gspec, ethash.NewFaker(), vm.Config{})
			if err != nil {
				t.Fatalf("failed to create blockchain: %v", err)
			}
			defer blockchain.Stop()

			block := GenerateBadBlock(t, gspec.ToBlock(), ethash.NewFaker(), []*types.Transaction{tx}, cfg)
			statedb, err := blockchain.State()
			if err != nil {
				t.Fatalf("failed to get state: %v", err)
			}
			if err := tt.validate(blockchain, block.Number(), statedb.Copy(), tokenAddr); err == nil {
				t.Fatal("expected direct special apply validation error")
			}
			_, _, _, err = blockchain.Processor().Process(block, statedb, nil, vm.Config{}, map[common.Address]*big.Int{})
			if err == nil {
				t.Fatal("expected processing error")
			}
			if !strings.Contains(err.Error(), "invalid balance slot") {
				t.Fatalf("expected special apply validation error, got %v", err)
			}
		})
	}
}

func TestStateProcessorDoesNotDeleteBlockSignersAtGenesisTIPSigning(t *testing.T) {
	t.Parallel()

	config := params.TestChainConfig.Clone()
	config.TIPSigningBlock = big.NewInt(0)
	config.PragueBlock = nil
	config.OsakaBlock = nil
	db := rawdb.NewMemoryDatabase()
	gspec := &Genesis{
		Config: config,
		Alloc: types.GenesisAlloc{
			common.BlockSignersBinary: {Balance: big.NewInt(1)},
		},
		GasLimit:   1,
		Difficulty: big.NewInt(1),
	}
	blockchain, err := NewBlockChain(db, nil, gspec, noopConsensusEngine{}, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create blockchain: %v", err)
	}
	defer blockchain.Stop()

	statedb, err := blockchain.State()
	if err != nil {
		t.Fatalf("failed to get state: %v", err)
	}
	if err := statedb.EnsureChainConfig(config); err != nil {
		t.Fatalf("failed to ensure chain config: %v", err)
	}
	rootBefore := statedb.IntermediateRoot(false)
	block := blockchain.GetBlockByNumber(0)
	if _, _, _, err := blockchain.Processor().Process(block, statedb, nil, vm.Config{}, map[common.Address]*big.Int{}); err != nil {
		t.Fatalf("process failed: %v", err)
	}
	if !statedb.Exist(common.BlockSignersBinary) {
		t.Fatal("expected block signers account to remain at genesis")
	}
	if rootAfter := statedb.IntermediateRoot(false); rootAfter != rootBefore {
		t.Fatalf("unexpected state root drift at genesis: have %s want %s", rootAfter, rootBefore)
	}
}

// GenerateBadBlock constructs a "block" which contains the transactions. The transactions are not expected to be
// valid, and no proper post-state can be made. But from the perspective of the blockchain, the block is sufficiently
// valid to be considered for import:
// - valid pow (fake), ancestry, difficulty, gaslimit etc
func GenerateBadBlock(t *testing.T, parent *types.Block, engine consensus.Engine, txs types.Transactions, config *params.ChainConfig) *types.Block {
	header := &types.Header{
		ParentHash: parent.Hash(),
		Coinbase:   parent.Coinbase(),
		Difficulty: engine.CalcDifficulty(&fakeChainReader{config: config, engine: engine}, parent.Time()+10, &types.Header{
			Number:     parent.Number(),
			Time:       parent.Time(),
			Difficulty: parent.Difficulty(),
			UncleHash:  parent.UncleHash(),
		}),
		GasLimit:  parent.GasLimit(),
		Number:    new(big.Int).Add(parent.Number(), common.Big1),
		Time:      parent.Time() + 10,
		UncleHash: types.EmptyUncleHash,
	}
	if config.IsEIP1559(header.Number) {
		header.BaseFee = params.BaseFeeForBlock(config, header.Number)
	}
	var receipts []*types.Receipt
	// The post-state result doesn't need to be correct (this is a bad block), but we do need something there
	// Preferably something unique. So let's use a combo of blocknum + txhash
	hasher := keccak.NewLegacyKeccak256()
	hasher.Write(header.Number.Bytes())
	var cumulativeGas uint64
	for _, tx := range txs {
		txh := tx.Hash()
		hasher.Write(txh[:])
		receipt := types.NewReceipt(nil, false, cumulativeGas+tx.Gas())
		receipt.TxHash = tx.Hash()
		receipt.GasUsed = tx.Gas()
		receipts = append(receipts, receipt)
		cumulativeGas += tx.Gas()
	}
	header.Root = common.BytesToHash(hasher.Sum(nil))
	// Assemble and return the final block for sealing
	return types.NewBlock(header, &types.Body{Transactions: txs}, receipts, trie.NewStackTrie(nil))
}

// TestApplyTransactionWithEVMTracer tests that tracer's OnTxStart and OnTxEnd
// are called for all transaction types, including non-EVM special transactions.
func TestApplyTransactionWithEVMTracer(t *testing.T) {
	var (
		config = &params.ChainConfig{
			ChainID:                big.NewInt(1),
			HomesteadBlock:         big.NewInt(0),
			EIP150Block:            big.NewInt(0),
			EIP155Block:            big.NewInt(0),
			EIP158Block:            big.NewInt(0),
			ByzantiumBlock:         big.NewInt(0),
			ConstantinopleBlock:    big.NewInt(0),
			PetersburgBlock:        big.NewInt(0),
			IstanbulBlock:          big.NewInt(0),
			TIPTRC21FeeBlock:       big.NewInt(0),
			Gas50xBlock:            big.NewInt(0),
			BerlinBlock:            big.NewInt(0),
			LondonBlock:            big.NewInt(0),
			EIP1559Block:           big.NewInt(0),
			TRC21IssuerSMC:         params.TestnetChainConfig.TRC21IssuerSMC,
			XDCXListingSMC:         params.TestnetChainConfig.XDCXListingSMC,
			RelayerRegistrationSMC: params.TestnetChainConfig.RelayerRegistrationSMC,
			LendingRegistrationSMC: params.TestnetChainConfig.LendingRegistrationSMC,
			Ethash:                 new(params.EthashConfig),
		}
		signer     = types.LatestSigner(config)
		testKey, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		testAddr   = crypto.PubkeyToAddress(testKey.PublicKey)
	)

	tests := []struct {
		name       string
		to         *common.Address
		expectOnTx bool // expect OnTxStart/OnTxEnd to be called
	}{
		{
			name:       "BlockSignersBinary transaction",
			to:         &common.BlockSignersBinary,
			expectOnTx: true,
		},
		{
			name:       "XDCXAddrBinary transaction",
			to:         &common.XDCXAddrBinary,
			expectOnTx: true,
		},
		{
			name: "Regular transaction",
			to: func() *common.Address {
				addr := common.HexToAddress("0x1234567890123456789012345678901234567890")
				return &addr
			}(),
			expectOnTx: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test database and genesis
			db := rawdb.NewMemoryDatabase()
			gspec := &Genesis{
				Config: config,
				Alloc: types.GenesisAlloc{
					testAddr: types.Account{
						Balance: big.NewInt(1000000000000000000), // 1 ether
						Nonce:   0,
					},
				},
			}
			genesis := gspec.MustCommit(db)
			blockchain, _ := NewBlockChain(db, nil, gspec, ethash.NewFaker(), vm.Config{})
			defer blockchain.Stop()

			// Create state database
			statedb, err := blockchain.State()
			if err != nil {
				t.Fatalf("Failed to get state: %v", err)
			}

			// Create a transaction with sufficient gas price to avoid base fee errors
			tx := types.NewTransaction(0, *tt.to, big.NewInt(0), 100000, big.NewInt(20000000000), nil)
			signedTx, err := types.SignTx(tx, signer, testKey)
			if err != nil {
				t.Fatalf("Failed to sign transaction: %v", err)
			}

			// Create a mock tracer
			onTxStartCalled := false
			onTxEndCalled := false
			mockTracer := &tracing.Hooks{
				OnTxStart: func(vmContext *tracing.VMContext, tx *types.Transaction, from common.Address) {
					onTxStartCalled = true
					if tx == nil {
						t.Error("OnTxStart called with nil transaction")
					}
					if from != testAddr {
						t.Errorf("OnTxStart called with wrong from address: got %v, want %v", from, testAddr)
					}
				},
				OnTxEnd: func(receipt *types.Receipt, err error) {
					onTxEndCalled = true
				},
			}

			// Create EVM with tracer
			vmConfig := vm.Config{
				Tracer: mockTracer,
			}

			msg, err := TransactionToMessage(signedTx, signer, nil, nil, nil, config)
			if err != nil {
				t.Fatalf("Failed to create message: %v", err)
			}

			gasPool := new(GasPool).AddGas(1000000)
			blockNumber := big.NewInt(1)
			blockHash := genesis.Hash()

			vmContext := NewEVMBlockContext(blockchain.CurrentBlock(), blockchain, nil)
			evm := vm.NewEVM(vmContext, statedb, nil, blockchain.Config(), vmConfig)

			// Apply transaction
			var usedGas uint64
			_, _, _, err = ApplyTransactionWithEVM(msg, gasPool, statedb, blockNumber, blockHash, signedTx, &usedGas, evm, big.NewInt(0))
			// NOTE: Some special transactions (like BlockSignersBinary or XDCXAddrBinary)
			// may fail in test environment due to missing configuration or state, but
			// the tracer should still be called at the beginning of ApplyTransactionWithEVM.
			// We don't fail the test on transaction execution error as long as tracer was invoked.
			if err != nil {
				t.Logf("Transaction execution returned error (expected for some special txs): %v", err)
			}

			// Verify tracer was called
			if tt.expectOnTx {
				if !onTxStartCalled {
					t.Error("OnTxStart was not called")
				}
				if !onTxEndCalled {
					t.Error("OnTxEnd was not called")
				}
			}
		})
	}
}

// TestApplyTransactionWithEVMStateChangeHooks tests apply transaction with evm state change hooks.
func TestApplyTransactionWithEVMStateChangeHooks(t *testing.T) {
	var (
		config = &params.ChainConfig{
			ChainID:                big.NewInt(1),
			HomesteadBlock:         big.NewInt(0),
			EIP150Block:            big.NewInt(0),
			EIP155Block:            big.NewInt(0),
			EIP158Block:            big.NewInt(0),
			ByzantiumBlock:         big.NewInt(0),
			ConstantinopleBlock:    big.NewInt(0),
			PetersburgBlock:        big.NewInt(0),
			IstanbulBlock:          big.NewInt(0),
			TIPTRC21FeeBlock:       big.NewInt(0),
			Gas50xBlock:            big.NewInt(0),
			BerlinBlock:            big.NewInt(0),
			LondonBlock:            big.NewInt(0),
			EIP1559Block:           big.NewInt(0),
			TRC21IssuerSMC:         params.TestnetChainConfig.TRC21IssuerSMC,
			XDCXListingSMC:         params.TestnetChainConfig.XDCXListingSMC,
			RelayerRegistrationSMC: params.TestnetChainConfig.RelayerRegistrationSMC,
			LendingRegistrationSMC: params.TestnetChainConfig.LendingRegistrationSMC,
			Ethash:                 new(params.EthashConfig),
		}
		signer      = types.LatestSigner(config)
		testKey, _  = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		sender      = crypto.PubkeyToAddress(testKey.PublicKey)
		recipient   = common.HexToAddress("0x1234567890123456789012345678901234567890")
		hookInvoked bool
	)

	db := rawdb.NewMemoryDatabase()
	gspec := &Genesis{
		Config: config,
		Alloc: types.GenesisAlloc{
			sender: {
				Balance: big.NewInt(1000000000000000000),
				Nonce:   0,
			},
		},
	}
	genesis := gspec.MustCommit(db)
	blockchain, _ := NewBlockChain(db, nil, gspec, ethash.NewFaker(), vm.Config{})
	defer blockchain.Stop()

	statedb, err := blockchain.State()
	if err != nil {
		t.Fatalf("Failed to get state: %v", err)
	}

	tx := types.NewTransaction(0, recipient, big.NewInt(1), 21000, big.NewInt(20000000000), nil)
	signedTx, err := types.SignTx(tx, signer, testKey)
	if err != nil {
		t.Fatalf("Failed to sign tx: %v", err)
	}

	hooks := &tracing.Hooks{
		OnBalanceChange: func(addr common.Address, prev, new *big.Int, reason tracing.BalanceChangeReason) {
			hookInvoked = true
		},
	}
	hookedState := state.NewHookedState(statedb, hooks)

	vmContext := NewEVMBlockContext(blockchain.CurrentBlock(), blockchain, nil)
	evmenv := vm.NewEVM(vmContext, hookedState, nil, blockchain.Config(), vm.Config{Tracer: hooks})

	msg, err := TransactionToMessage(signedTx, signer, nil, big.NewInt(1), nil, config)
	if err != nil {
		t.Fatalf("Failed to build message: %v", err)
	}

	gasPool := new(GasPool).AddGas(1000000)
	var usedGas uint64
	_, _, _, err = ApplyTransactionWithEVM(msg, gasPool, statedb, big.NewInt(1), genesis.Hash(), signedTx, &usedGas, evmenv, nil)
	if err != nil {
		t.Fatalf("ApplyTransactionWithEVM failed: %v", err)
	}
	if !hookInvoked {
		t.Fatal("expected OnBalanceChange to be invoked, but it was not")
	}
}

// TestApplyTransactionWithEVMOnTxStartUsesExecutionGasPrice tests apply transaction with evm on tx start uses execution gas price.
func TestApplyTransactionWithEVMOnTxStartUsesExecutionGasPrice(t *testing.T) {
	var (
		config = &params.ChainConfig{
			ChainID:                big.NewInt(1),
			HomesteadBlock:         big.NewInt(0),
			EIP150Block:            big.NewInt(0),
			EIP155Block:            big.NewInt(0),
			EIP158Block:            big.NewInt(0),
			ByzantiumBlock:         big.NewInt(0),
			ConstantinopleBlock:    big.NewInt(0),
			PetersburgBlock:        big.NewInt(0),
			IstanbulBlock:          big.NewInt(0),
			TIPTRC21FeeBlock:       big.NewInt(0),
			Gas50xBlock:            big.NewInt(0),
			BerlinBlock:            big.NewInt(0),
			LondonBlock:            big.NewInt(0),
			EIP1559Block:           big.NewInt(0),
			TRC21IssuerSMC:         params.TestnetChainConfig.TRC21IssuerSMC,
			XDCXListingSMC:         params.TestnetChainConfig.XDCXListingSMC,
			RelayerRegistrationSMC: params.TestnetChainConfig.RelayerRegistrationSMC,
			LendingRegistrationSMC: params.TestnetChainConfig.LendingRegistrationSMC,
			Ethash:                 new(params.EthashConfig),
		}
		signer            = types.LatestSigner(config)
		testKey, _        = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		sender            = crypto.PubkeyToAddress(testKey.PublicKey)
		recipient         = common.HexToAddress("0x1234567890123456789012345678901234567890")
		rawGasPrice       = big.NewInt(20000000000)
		executionGasPrice = big.NewInt(7)
	)

	db := rawdb.NewMemoryDatabase()
	gspec := &Genesis{
		Config: config,
		Alloc: types.GenesisAlloc{
			sender: {
				Balance: big.NewInt(1000000000000000000),
				Nonce:   0,
			},
		},
	}
	genesis := gspec.MustCommit(db)
	blockchain, err := NewBlockChain(db, nil, gspec, ethash.NewFaker(), vm.Config{})
	if err != nil {
		t.Fatalf("Failed to create blockchain: %v", err)
	}
	defer blockchain.Stop()

	statedb, err := blockchain.State()
	if err != nil {
		t.Fatalf("Failed to get state: %v", err)
	}

	tx := types.NewTransaction(0, recipient, big.NewInt(1), 21000, rawGasPrice, nil)
	signedTx, err := types.SignTx(tx, signer, testKey)
	if err != nil {
		t.Fatalf("Failed to sign tx: %v", err)
	}

	var seenGasPrice *big.Int
	hooks := &tracing.Hooks{
		OnTxStart: func(vmContext *tracing.VMContext, tx *types.Transaction, from common.Address) {
			if tx == nil {
				t.Fatal("OnTxStart called with nil transaction")
			}
			if from != sender {
				t.Fatalf("OnTxStart called with wrong from address: got %v want %v", from, sender)
			}
			if vmContext.GasPrice == nil {
				t.Fatal("OnTxStart saw nil gas price")
			}
			seenGasPrice = new(big.Int).Set(vmContext.GasPrice)
		},
	}

	msg, err := TransactionToMessage(signedTx, signer, nil, big.NewInt(1), nil, config)
	if err != nil {
		t.Fatalf("Failed to build message: %v", err)
	}
	msg.GasPrice = new(big.Int).Set(executionGasPrice)

	gasPool := new(GasPool).AddGas(1000000)
	vmContext := NewEVMBlockContext(blockchain.CurrentBlock(), blockchain, nil)
	evmenv := vm.NewEVM(vmContext, statedb, nil, blockchain.Config(), vm.Config{Tracer: hooks})

	var usedGas uint64
	_, _, _, err = ApplyTransactionWithEVM(msg, gasPool, statedb, big.NewInt(1), genesis.Hash(), signedTx, &usedGas, evmenv, nil)
	if err != nil {
		t.Fatalf("ApplyTransactionWithEVM failed: %v", err)
	}
	if seenGasPrice == nil {
		t.Fatal("expected OnTxStart to observe gas price")
	}
	if seenGasPrice.Cmp(executionGasPrice) != 0 {
		t.Fatalf("OnTxStart saw wrong execution gas price: got %v want %v", seenGasPrice, executionGasPrice)
	}
	if seenGasPrice.Cmp(rawGasPrice) == 0 {
		t.Fatalf("OnTxStart unexpectedly saw raw tx gas price: %v", seenGasPrice)
	}
}

// TestApplyTransactionWithEVMRejectsValueOverflow tests apply transaction with evm rejects value overflow.
func TestApplyTransactionWithEVMRejectsValueOverflow(t *testing.T) {
	t.Parallel()

	config := &params.ChainConfig{
		ChainID:                big.NewInt(1),
		HomesteadBlock:         big.NewInt(0),
		EIP150Block:            big.NewInt(0),
		EIP155Block:            big.NewInt(0),
		EIP158Block:            big.NewInt(0),
		ByzantiumBlock:         big.NewInt(0),
		TIPTRC21FeeBlock:       big.NewInt(0),
		Gas50xBlock:            big.NewInt(1_000_000_000),
		BerlinBlock:            big.NewInt(1_000_000_000),
		LondonBlock:            big.NewInt(1_000_000_000),
		MergeBlock:             big.NewInt(1_000_000_000),
		ShanghaiBlock:          big.NewInt(1_000_000_000),
		EIP1559Block:           big.NewInt(1_000_000_000),
		CancunBlock:            big.NewInt(1_000_000_000),
		PragueBlock:            big.NewInt(1_000_000_000),
		OsakaBlock:             big.NewInt(1_000_000_000),
		TRC21IssuerSMC:         params.TestnetChainConfig.TRC21IssuerSMC,
		XDCXListingSMC:         params.TestnetChainConfig.XDCXListingSMC,
		RelayerRegistrationSMC: params.TestnetChainConfig.RelayerRegistrationSMC,
		LendingRegistrationSMC: params.TestnetChainConfig.LendingRegistrationSMC,
		Ethash:                 new(params.EthashConfig),
	}
	signer := types.LatestSigner(config)
	key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	if err != nil {
		t.Fatalf("Failed to create key: %v", err)
	}
	sender := crypto.PubkeyToAddress(key.PublicKey)
	recipient := common.HexToAddress("0x1234567890123456789012345678901234567890")
	tooBigValue := new(big.Int).Lsh(big.NewInt(1), 256)
	hugeBalance := new(big.Int).Lsh(big.NewInt(1), 300)

	db := rawdb.NewMemoryDatabase()
	gspec := &Genesis{
		Config: config,
		Alloc: types.GenesisAlloc{
			sender: {
				Balance: hugeBalance,
			},
		},
	}
	setXinFinForksToFuture(config, big.NewInt(1_000_000_000))
	genesis := gspec.MustCommit(db)
	blockchain, err := NewBlockChain(db, nil, gspec, ethash.NewFaker(), vm.Config{})
	if err != nil {
		t.Fatalf("Failed to create blockchain: %v", err)
	}
	defer blockchain.Stop()

	statedb, err := blockchain.State()
	if err != nil {
		t.Fatalf("Failed to get state: %v", err)
	}
	tx := types.NewTransaction(0, recipient, tooBigValue, 21000, big.NewInt(1), nil)
	signedTx, err := types.SignTx(tx, signer, key)
	if err != nil {
		t.Fatalf("Failed to sign tx: %v", err)
	}
	msg, err := TransactionToMessage(signedTx, signer, nil, big.NewInt(1), nil, config)
	if err != nil {
		t.Fatalf("Failed to build message: %v", err)
	}
	vmContext := NewEVMBlockContext(blockchain.CurrentBlock(), blockchain, nil)
	evmenv := vm.NewEVM(vmContext, statedb, nil, blockchain.Config(), vm.Config{})
	gasPool := new(GasPool).AddGas(1000000)
	var usedGas uint64
	_, _, _, err = ApplyTransactionWithEVM(msg, gasPool, statedb, big.NewInt(1), genesis.Hash(), signedTx, &usedGas, evmenv, nil)
	if !errors.Is(err, types.ErrUint256Overflow) {
		t.Fatalf("expected %v, got %v", types.ErrUint256Overflow, err)
	}
}

// TestProcessParentBlockHash tests process parent block hash.
func TestProcessParentBlockHash(t *testing.T) {
	var (
		chainConfig = params.MergedTestChainConfig
		hashA       = common.Hash{0x01}
		hashB       = common.Hash{0x02}
		header      = &types.Header{ParentHash: hashA, Number: big.NewInt(2), Difficulty: big.NewInt(0)}
		parent      = &types.Header{ParentHash: hashB, Number: big.NewInt(1), Difficulty: big.NewInt(0)}
		coinbase    = common.Address{}
	)
	test := func(statedb *state.StateDB) {
		statedb.SetNonce(params.HistoryStorageAddress, 1, tracing.NonceChangeUnspecified)
		statedb.SetCode(params.HistoryStorageAddress, params.HistoryStorageCode)
		statedb.IntermediateRoot(true)

		vmContext := NewEVMBlockContext(header, nil, &coinbase)
		evm := vm.NewEVM(vmContext, statedb, nil, chainConfig, vm.Config{})
		ProcessParentBlockHash(header.ParentHash, evm)

		vmContext = NewEVMBlockContext(parent, nil, &coinbase)
		evm = vm.NewEVM(vmContext, statedb, nil, chainConfig, vm.Config{})
		ProcessParentBlockHash(parent.ParentHash, evm)

		// make sure that the state is correct
		if have := getParentBlockHash(statedb, 1); have != hashA {
			t.Errorf("want parent hash %v, have %v", hashA, have)
		}
		if have := getParentBlockHash(statedb, 0); have != hashB {
			t.Errorf("want parent hash %v, have %v", hashB, have)
		}
	}
	t.Run("MPT", func(t *testing.T) {
		statedb, _ := state.New(types.EmptyRootHash, state.NewDatabase(rawdb.NewDatabase(memorydb.New())))
		test(statedb)
	})
}

// TestProcessParentBlockHashPragueGuard tests process parent block hash prague guard.
func TestProcessParentBlockHashPragueGuard(t *testing.T) {
	config := *params.MergedTestChainConfig
	config.PragueBlock = big.NewInt(10)

	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabase(rawdb.NewDatabase(memorydb.New())))
	blockNumber := big.NewInt(5)
	random := common.Hash{}
	blockContext := vm.BlockContext{
		CanTransfer: CanTransfer,
		Transfer:    Transfer,
		GetHash:     func(uint64) common.Hash { return common.Hash{} },
		Coinbase:    common.Address{},
		BlockNumber: blockNumber,
		Time:        0,
		Difficulty:  big.NewInt(0),
		GasLimit:    0,
		BaseFee:     nil,
		Random:      &random,
	}
	evm := vm.NewEVM(blockContext, statedb, nil, &config, vm.Config{})
	ProcessParentBlockHash(common.Hash{0x01}, evm)

	if code := statedb.GetCode(params.HistoryStorageAddress); len(code) != 0 {
		t.Fatalf("unexpected history contract code predeploy: %x", code)
	}
	if have := getParentBlockHash(statedb, 0); have != (common.Hash{}) {
		t.Fatalf("expected empty history slot, have %v", have)
	}
}

// TestTransactionToMessageRejectsMissingTokenFeeConfig tests transaction to message rejects missing token fee config.
func TestTransactionToMessageRejectsMissingTokenFeeConfig(t *testing.T) {
	config := params.TestChainConfig.Clone()
	signer := types.LatestSigner(config)
	key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	if err != nil {
		t.Fatalf("failed to create key: %v", err)
	}
	recipient := common.HexToAddress("0x1234567890123456789012345678901234567890")
	tx := types.NewTransaction(0, recipient, big.NewInt(1), 21000, big.NewInt(1), nil)
	signedTx, err := types.SignTx(tx, signer, key)
	if err != nil {
		t.Fatalf("failed to sign tx: %v", err)
	}

	tests := []struct {
		name        string
		cfg         *params.ChainConfig
		errContains string
	}{
		{
			name:        "nil chain config",
			cfg:         nil,
			errContains: "chain config is nil",
		},
		{
			name: "nil trc21 fee block",
			cfg: func() *params.ChainConfig {
				cfg := params.TestChainConfig.Clone()
				cfg.TIPTRC21FeeBlock = nil
				return cfg
			}(),
			errContains: "missing TIPTRC21FeeBlock",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := TransactionToMessage(signedTx, signer, big.NewInt(1), big.NewInt(1), nil, tt.cfg)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.errContains) {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestTransactionToMessageAllowsNilGas50xBlock tests transaction to message allows nil gas 50 x block.
func TestTransactionToMessageAllowsNilGas50xBlock(t *testing.T) {
	config := params.TestChainConfig.Clone()
	config.Gas50xBlock = nil
	config.TIPTRC21FeeBlock = big.NewInt(10)

	signer := types.LatestSigner(config)
	key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	if err != nil {
		t.Fatalf("failed to create key: %v", err)
	}
	recipient := common.HexToAddress("0x1234567890123456789012345678901234567890")
	tx := types.NewTransaction(0, recipient, big.NewInt(1), 21000, big.NewInt(1), nil)
	signedTx, err := types.SignTx(tx, signer, key)
	if err != nil {
		t.Fatalf("failed to sign tx: %v", err)
	}

	msg, err := TransactionToMessage(signedTx, signer, big.NewInt(1), big.NewInt(11), nil, config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	wantPrice, err := params.GetGasPriceForTRC21(big.NewInt(11), config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg.GasPrice.Cmp(wantPrice) != 0 {
		t.Fatalf("unexpected gas price: have %v want %v", msg.GasPrice, wantPrice)
	}
}

// TestApplyTransactionWithEVMKeepsCoinbaseFeeRecipientAtTIPTRC21ActivationBlock tests apply transaction with evm keeps coinbase fee recipient at tiptrc 21 activation block.
func TestApplyTransactionWithEVMKeepsCoinbaseFeeRecipientAtTIPTRC21ActivationBlock(t *testing.T) {
	config := &params.ChainConfig{
		ChainID:                big.NewInt(1),
		HomesteadBlock:         big.NewInt(0),
		EIP150Block:            big.NewInt(0),
		EIP155Block:            big.NewInt(0),
		EIP158Block:            big.NewInt(0),
		ByzantiumBlock:         big.NewInt(0),
		TIPTRC21FeeBlock:       big.NewInt(0),
		Gas50xBlock:            big.NewInt(1_000_000_000),
		BerlinBlock:            big.NewInt(1_000_000_000),
		LondonBlock:            big.NewInt(1_000_000_000),
		MergeBlock:             big.NewInt(1_000_000_000),
		ShanghaiBlock:          big.NewInt(1_000_000_000),
		EIP1559Block:           big.NewInt(1_000_000_000),
		CancunBlock:            big.NewInt(1_000_000_000),
		PragueBlock:            big.NewInt(1_000_000_000),
		OsakaBlock:             big.NewInt(1_000_000_000),
		TRC21IssuerSMC:         params.TestnetChainConfig.TRC21IssuerSMC,
		XDCXListingSMC:         params.TestnetChainConfig.XDCXListingSMC,
		RelayerRegistrationSMC: params.TestnetChainConfig.RelayerRegistrationSMC,
		LendingRegistrationSMC: params.TestnetChainConfig.LendingRegistrationSMC,
		Ethash:                 new(params.EthashConfig),
	}

	signer := types.LatestSigner(config)
	key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	if err != nil {
		t.Fatalf("failed to create key: %v", err)
	}
	sender := crypto.PubkeyToAddress(key.PublicKey)
	recipient := common.HexToAddress("0x1234567890123456789012345678901234567890")
	coinbase := common.HexToAddress("0x1000000000000000000000000000000000000001")
	owner := common.HexToAddress("0x2000000000000000000000000000000000000002")

	db := rawdb.NewMemoryDatabase()
	gspec := &Genesis{
		Config: config,
		Alloc: types.GenesisAlloc{
			sender: {
				Balance: big.NewInt(1),
				Nonce:   0,
			},
		},
	}
	genesis := gspec.MustCommit(db)
	blockchain, err := NewBlockChain(db, nil, gspec, ethash.NewFaker(), vm.Config{})
	if err != nil {
		t.Fatalf("failed to create blockchain: %v", err)
	}
	defer blockchain.Stop()

	statedb, err := blockchain.State()
	if err != nil {
		t.Fatalf("failed to get state: %v", err)
	}
	setCandidateOwnerInState(statedb, coinbase, owner)

	tx := types.NewTransaction(0, recipient, big.NewInt(0), 21000, big.NewInt(1), nil)
	signedTx, err := types.SignTx(tx, signer, key)
	if err != nil {
		t.Fatalf("failed to sign tx: %v", err)
	}

	blockNumber := new(big.Int).Set(config.TIPTRC21FeeBlock)
	msg, err := TransactionToMessage(signedTx, signer, big.NewInt(1_000_000_000_000), blockNumber, nil, config)
	if err != nil {
		t.Fatalf("failed to build message: %v", err)
	}
	wantPrice, err := params.GetGasPriceForTRC21(blockNumber, config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg.GasPrice.Cmp(wantPrice) != 0 {
		t.Fatalf("expected activation block token fee pricing to use pre-fork gas price: have %v want %v", msg.GasPrice, wantPrice)
	}

	vmContext := NewEVMBlockContext(&types.Header{
		Number:     new(big.Int).Set(blockNumber),
		GasLimit:   1_000_000,
		Difficulty: big.NewInt(0),
		Time:       1,
	}, blockchain, &coinbase)
	evmenv := vm.NewEVM(vmContext, statedb, nil, blockchain.Config(), vm.Config{})
	gasPool := new(GasPool).AddGas(1_000_000)
	var usedGas uint64

	_, gasUsed, tokenFeeUsed, err := ApplyTransactionWithEVM(msg, gasPool, statedb, blockNumber, genesis.Hash(), signedTx, &usedGas, evmenv, big.NewInt(1_000_000_000_000))
	if err != nil {
		t.Fatalf("ApplyTransactionWithEVM failed: %v", err)
	}
	if !tokenFeeUsed {
		t.Fatal("expected token fee path to be used")
	}
	fee := new(big.Int).Mul(new(big.Int).SetUint64(gasUsed), wantPrice)
	if got := statedb.GetBalance(owner); got.Sign() != 0 {
		t.Fatalf("expected owner to receive no fee at activation block, have %v", got)
	}
	if got := statedb.GetBalance(coinbase); got.Cmp(fee) != 0 {
		t.Fatalf("expected coinbase to receive activation block fee %v, have %v", fee, got)
	}
	if usedGas != gasUsed {
		t.Fatalf("unexpected used gas accumulator: have %d want %d", usedGas, gasUsed)
	}
}

// setCandidateOwnerInState seeds the candidate-owner mapping for validator
// ownership tests.
func setCandidateOwnerInState(statedb *state.StateDB, candidate, owner common.Address) {
	locValidatorsState := state.GetLocMappingAtKey(candidate.Hash(), 1)
	statedb.SetState(common.MasternodeVotingSMCBinary, common.BigToHash(locValidatorsState), owner.Hash())
}

// TestProcessParentBlockHashBackfillMissingHistory tests process parent block hash backfill missing history.
func TestProcessParentBlockHashBackfillMissingHistory(t *testing.T) {
	config := *params.MergedTestChainConfig
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabase(rawdb.NewDatabase(memorydb.New())))
	blockNumber := big.NewInt(int64(params.HistoryServeWindow + 1))
	available := map[uint64]common.Hash{
		1:   {0x11},
		100: {0x22},
	}

	random := common.Hash{}
	blockContext := vm.BlockContext{
		CanTransfer: CanTransfer,
		Transfer:    Transfer,
		GetHash: func(n uint64) common.Hash {
			if hash, ok := available[n]; ok {
				return hash
			}
			return common.Hash{}
		},
		Coinbase:    common.Address{},
		BlockNumber: blockNumber,
		Time:        0,
		Difficulty:  big.NewInt(0),
		GasLimit:    0,
		BaseFee:     nil,
		Random:      &random,
	}
	evm := vm.NewEVM(blockContext, statedb, nil, &config, vm.Config{})
	ProcessParentBlockHash(common.Hash{0x01}, evm)

	if have := getParentBlockHash(statedb, 1); have != available[1] {
		t.Fatalf("expected hash at slot 1, have %v", have)
	}
	if have := getParentBlockHash(statedb, 100); have != available[100] {
		t.Fatalf("expected hash at slot 100, have %v", have)
	}
	if have := getParentBlockHash(statedb, 2); have != (common.Hash{}) {
		t.Fatalf("expected empty history slot, have %v", have)
	}
}

// TestProcessParentBlockHashCodeMismatchPanics tests process parent block hash code mismatch panics.
func TestProcessParentBlockHashCodeMismatchPanics(t *testing.T) {
	config := *params.MergedTestChainConfig
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabase(rawdb.NewDatabase(memorydb.New())))
	statedb.SetCode(params.HistoryStorageAddress, []byte{0x01})

	blockNumber := big.NewInt(1)
	random := common.Hash{}
	blockContext := vm.BlockContext{
		CanTransfer: CanTransfer,
		Transfer:    Transfer,
		GetHash:     func(uint64) common.Hash { return common.Hash{} },
		Coinbase:    common.Address{},
		BlockNumber: blockNumber,
		Time:        0,
		Difficulty:  big.NewInt(0),
		GasLimit:    0,
		BaseFee:     nil,
		Random:      &random,
	}
	evm := vm.NewEVM(blockContext, statedb, nil, &config, vm.Config{})

	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on history storage code mismatch")
		}
	}()
	ProcessParentBlockHash(common.Hash{0x01}, evm)
}

func getParentBlockHash(statedb *state.StateDB, number uint64) common.Hash {
	ringIndex := number % params.HistoryServeWindow
	var key common.Hash
	binary.BigEndian.PutUint64(key[24:], ringIndex)
	return statedb.GetState(params.HistoryStorageAddress, key)
}

// TestApplyTransactionForReplayKeepsTheNonEVMTxLog checks that a replay records the same log
// entry block processing does for a transaction the EVM never executes. The entry is not a
// receipt artefact: StateDB.AddLog advances the block wide log count, so a replay that left
// it out would give every log the following transactions emit an index the chain never had,
// and callTracer reports those indexes.
//
// The two routes do not only share that log: the sign route also bumps the sender nonce and
// the empty route leaves it alone, so the nonce is a second observable effect the replay has
// to reproduce. It is checked here as well, because a replay that dropped the nonce handling
// would still match on the log while leaving every later transaction of the sender one nonce
// behind.
func TestApplyTransactionForReplayKeepsTheNonEVMTxLog(t *testing.T) {
	for _, tc := range []struct {
		name       string
		to         common.Address
		tipSigning *big.Int
		tipXDCX    *big.Int
		wantNonce  uint64
	}{
		{name: "trading state address, receiver fork active", to: common.TradingStateAddrBinary, tipXDCX: common.Big0, wantNonce: 0},
		{name: "block signers address, signing fork active", to: common.BlockSignersBinary, tipSigning: common.Big0, wantNonce: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var (
				config = &params.ChainConfig{
					ChainID:                big.NewInt(1),
					HomesteadBlock:         big.NewInt(0),
					EIP150Block:            big.NewInt(0),
					EIP155Block:            big.NewInt(0),
					EIP158Block:            big.NewInt(0),
					ByzantiumBlock:         big.NewInt(0),
					ConstantinopleBlock:    big.NewInt(0),
					PetersburgBlock:        big.NewInt(0),
					IstanbulBlock:          big.NewInt(0),
					BerlinBlock:            big.NewInt(0),
					LondonBlock:            big.NewInt(0),
					EIP1559Block:           big.NewInt(0),
					TIPTRC21FeeBlock:       big.NewInt(0),
					Gas50xBlock:            big.NewInt(0),
					TRC21IssuerSMC:         params.TestnetChainConfig.TRC21IssuerSMC,
					XDCXListingSMC:         params.TestnetChainConfig.XDCXListingSMC,
					RelayerRegistrationSMC: params.TestnetChainConfig.RelayerRegistrationSMC,
					LendingRegistrationSMC: params.TestnetChainConfig.LendingRegistrationSMC,
					TIPSigningBlock:        tc.tipSigning,
					TIPXDCXBlock:           tc.tipXDCX,
					Ethash:                 new(params.EthashConfig),
				}
				signer     = types.LatestSigner(config)
				testKey, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
				sender     = crypto.PubkeyToAddress(testKey.PublicKey)
				blockNum   = big.NewInt(1)
			)

			db := rawdb.NewMemoryDatabase()
			gspec := &Genesis{
				Config: config,
				Alloc: types.GenesisAlloc{
					sender: {Balance: big.NewInt(1000000000000000000)},
				},
			}
			genesis := gspec.MustCommit(db)
			blockchain, err := NewBlockChain(db, nil, gspec, ethash.NewFaker(), vm.Config{})
			if err != nil {
				t.Fatalf("Failed to create the blockchain: %v", err)
			}
			defer blockchain.Stop()

			statedb, err := blockchain.State()
			if err != nil {
				t.Fatalf("Failed to get state: %v", err)
			}
			to := tc.to
			signedTx, err := types.SignTx(types.NewTx(&types.LegacyTx{
				Nonce:    0,
				To:       &to,
				Value:    big.NewInt(0),
				Gas:      21000,
				GasPrice: big.NewInt(1),
			}), signer, testKey)
			if err != nil {
				t.Fatalf("Failed to sign tx: %v", err)
			}
			msg, err := TransactionToMessage(signedTx, signer, nil, blockNum, nil, config)
			if err != nil {
				t.Fatalf("Failed to build message: %v", err)
			}

			// The same transaction, once through the replay and once through block processing.
			replayState := statedb.Copy()
			replayEVM := vm.NewEVM(NewEVMBlockContext(blockchain.CurrentBlock(), blockchain, nil), replayState, nil, config, vm.Config{})
			replayState.SetTxContext(signedTx.Hash(), 0)
			if err := ApplyTransactionForReplay(msg, new(GasPool).AddGas(1000000), blockNum, signedTx, replayEVM, nil); err != nil {
				t.Fatalf("ApplyTransactionForReplay failed: %v", err)
			}

			evmState := statedb.Copy()
			evmEVM := vm.NewEVM(NewEVMBlockContext(blockchain.CurrentBlock(), blockchain, nil), evmState, nil, config, vm.Config{})
			evmState.SetTxContext(signedTx.Hash(), 0)
			var usedGas uint64
			if _, _, _, err := ApplyTransactionWithEVM(msg, new(GasPool).AddGas(1000000), evmState, blockNum, genesis.Hash(), signedTx, &usedGas, evmEVM, nil); err != nil {
				t.Fatalf("ApplyTransactionWithEVM failed: %v", err)
			}

			want := evmState.GetLogs(signedTx.Hash(), blockNum.Uint64(), genesis.Hash())
			if len(want) != 1 {
				t.Fatalf("block processing recorded %d logs, want 1", len(want))
			}
			got := replayState.GetLogs(signedTx.Hash(), blockNum.Uint64(), genesis.Hash())
			if len(got) != len(want) {
				t.Fatalf("replay recorded %d logs, block processing %d", len(got), len(want))
			}
			for i := range want {
				if got[i].Address != want[i].Address || got[i].Index != want[i].Index {
					t.Fatalf("replay log %d = {address: %v, index: %d}, block processing = {address: %v, index: %d}", i, got[i].Address, got[i].Index, want[i].Address, want[i].Index)
				}
			}

			// The nonce the same transaction leaves behind: block processing bumps it on the
			// sign route and leaves it alone on the empty route. Pin it to the route first, so
			// the comparison below cannot pass on two paths that both leave the nonce alone.
			wantNonce := evmState.GetNonce(sender)
			if wantNonce != tc.wantNonce {
				t.Fatalf("block processing left nonce %d, want %d", wantNonce, tc.wantNonce)
			}
			if gotNonce := replayState.GetNonce(sender); gotNonce != wantNonce {
				t.Fatalf("replay left nonce %d, block processing %d", gotNonce, wantNonce)
			}
		})
	}
}

// replayTestKey is the key of the sender of the transactions the replay tests below drive.
const replayTestKey = "b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291"

// replayTestSender is the address replayTestKey signs for.
func replayTestSender() common.Address {
	key, err := crypto.HexToECDSA(replayTestKey)
	if err != nil {
		panic(err)
	}
	return crypto.PubkeyToAddress(key.PublicKey)
}

// replayTestConfig is the chain config the replay tests below share: no signing fork and no
// XDCX receiver fork, so an ordinary transaction takes the EVM route, and the TRC21 fee fork
// active from genesis, so the fee of such a transaction goes to the owner of the block
// coinbase rather than to the coinbase itself (core/state_transition.go).
func replayTestConfig() *params.ChainConfig {
	return &params.ChainConfig{
		ChainID:                big.NewInt(1),
		HomesteadBlock:         big.NewInt(0),
		EIP150Block:            big.NewInt(0),
		EIP155Block:            big.NewInt(0),
		EIP158Block:            big.NewInt(0),
		ByzantiumBlock:         big.NewInt(0),
		ConstantinopleBlock:    big.NewInt(0),
		PetersburgBlock:        big.NewInt(0),
		IstanbulBlock:          big.NewInt(0),
		BerlinBlock:            big.NewInt(0),
		LondonBlock:            big.NewInt(0),
		EIP1559Block:           big.NewInt(0),
		TIPTRC21FeeBlock:       big.NewInt(0),
		Gas50xBlock:            big.NewInt(0),
		TRC21IssuerSMC:         params.TestnetChainConfig.TRC21IssuerSMC,
		XDCXListingSMC:         params.TestnetChainConfig.XDCXListingSMC,
		RelayerRegistrationSMC: params.TestnetChainConfig.RelayerRegistrationSMC,
		LendingRegistrationSMC: params.TestnetChainConfig.LendingRegistrationSMC,
		Ethash:                 new(params.EthashConfig),
	}
}

// replayTestFixture is what the replay tests below drive: the state of a chain that holds
// nothing but its genesis block, and one ordinary transaction from replayTestKey.
type replayTestFixture struct {
	config      *params.ChainConfig
	chain       *BlockChain
	statedb     *state.StateDB
	genesisHash common.Hash
	// header is the block context the replay and block processing are driven with. It sits
	// above TIPTRC21FeeBlock and carries a base fee, which preCheck dereferences while
	// EIP-1559 is active (core/state_transition.go).
	header *types.Header
	tx     *types.Transaction
	msg    *Message
}

func newReplayTestFixture(t *testing.T, alloc types.GenesisAlloc) *replayTestFixture {
	t.Helper()
	config := replayTestConfig()
	db := rawdb.NewMemoryDatabase()
	gspec := &Genesis{Config: config, Alloc: alloc}
	genesis := gspec.MustCommit(db)
	blockchain, err := NewBlockChain(db, nil, gspec, ethash.NewFaker(), vm.Config{})
	if err != nil {
		t.Fatalf("Failed to create the blockchain: %v", err)
	}
	t.Cleanup(blockchain.Stop)

	statedb, err := blockchain.State()
	if err != nil {
		t.Fatalf("Failed to get state: %v", err)
	}
	signer := types.LatestSigner(config)
	testKey, err := crypto.HexToECDSA(replayTestKey)
	if err != nil {
		t.Fatalf("Failed to parse the test key: %v", err)
	}
	header := &types.Header{Number: big.NewInt(1), Difficulty: big.NewInt(1), BaseFee: new(big.Int)}
	to := common.HexToAddress("0x00000000000000000000000000000000deadbeef")
	tx, err := types.SignTx(types.NewTx(&types.LegacyTx{
		Nonce:    0,
		To:       &to,
		Value:    big.NewInt(0),
		Gas:      params.TxGas,
		GasPrice: big.NewInt(1),
	}), signer, testKey)
	if err != nil {
		t.Fatalf("Failed to sign tx: %v", err)
	}
	msg, err := TransactionToMessage(tx, signer, nil, header.Number, header.BaseFee, config)
	if err != nil {
		t.Fatalf("Failed to build message: %v", err)
	}
	return &replayTestFixture{
		config:      config,
		chain:       blockchain,
		statedb:     statedb,
		genesisHash: genesis.Hash(),
		header:      header,
		tx:          tx,
		msg:         msg,
	}
}

// TestApplyTransactionForReplayMirrorsBlockProcessing drives one ordinary transaction through
// the replay and through block processing and compares what the two leave behind. The non-EVM
// routes are covered by TestApplyTransactionForReplayKeepsTheNonEVMTxLog; this one covers the
// EVM route, where the replay used to differ from block processing twice: it handed the zero
// address to ApplyMessage as the coinbase owner, so while the TRC21 fee fork is active the
// fee went nowhere instead of to the owner of the block coinbase (core/state_transition.go),
// and it skipped the historical balance bypass, which the test below covers.
//
// The block context carries a coinbase whose owner is recorded in the state, because the fee
// goes to GetOwner(coinbase): with nobody recorded there both paths credit nobody, and the
// comparison would pass on a replay that credits nobody either.
func TestApplyTransactionForReplayMirrorsBlockProcessing(t *testing.T) {
	var (
		sender   = replayTestSender()
		coinbase = common.HexToAddress("0x0000000000000000000000000000000000c0ffee")
		owner    = common.HexToAddress("0x0000000000000000000000000000000000beefed")
	)
	f := newReplayTestFixture(t, types.GenesisAlloc{sender: {Balance: big.NewInt(1000000000000000000)}})

	// GetOwner reads validatorsState[coinbase].owner out of the masternode voting contract;
	// slot 1 is slotValidatorMapping["validatorsState"] (core/state/statedb_utils.go).
	setCoinbaseOwner := func(statedb *state.StateDB) {
		loc := state.GetLocMappingAtKey(coinbase.Hash(), 1)
		statedb.SetState(common.MasternodeVotingSMCBinary, common.BigToHash(loc), common.BytesToHash(owner.Bytes()))
	}
	newEVM := func(statedb *state.StateDB) *vm.EVM {
		return vm.NewEVM(NewEVMBlockContext(f.header, f.chain, &coinbase), statedb, nil, f.config, vm.Config{})
	}

	replayState := f.statedb.Copy()
	setCoinbaseOwner(replayState)
	replayState.SetTxContext(f.tx.Hash(), 0)
	if err := ApplyTransactionForReplay(f.msg, new(GasPool).AddGas(1000000), f.header.Number, f.tx, newEVM(replayState), nil); err != nil {
		t.Fatalf("ApplyTransactionForReplay failed: %v", err)
	}

	evmState := f.statedb.Copy()
	setCoinbaseOwner(evmState)
	evmState.SetTxContext(f.tx.Hash(), 0)
	var usedGas uint64
	if _, _, _, err := ApplyTransactionWithEVM(f.msg, new(GasPool).AddGas(1000000), evmState, f.header.Number, f.genesisHash, f.tx, &usedGas, newEVM(evmState), nil); err != nil {
		t.Fatalf("ApplyTransactionWithEVM failed: %v", err)
	}

	// The fee: block processing credits gasUsed*gasPrice to the owner of the coinbase. Pin
	// that credit to a non-zero amount first, so the comparison cannot pass on two paths
	// that both credit nobody.
	wantFee := evmState.GetBalance(owner)
	if wantFee.Sign() == 0 {
		t.Fatal("block processing credited no fee to the owner of the coinbase")
	}
	if gotFee := replayState.GetBalance(owner); gotFee.Cmp(wantFee) != 0 {
		t.Fatalf("replay credited %v to the owner of the coinbase, block processing %v", gotFee, wantFee)
	}

	// The nonce: an ordinary transaction bumps it on both paths.
	wantNonce := evmState.GetNonce(sender)
	if wantNonce != 1 {
		t.Fatalf("block processing left nonce %d, want 1", wantNonce)
	}
	if gotNonce := replayState.GetNonce(sender); gotNonce != wantNonce {
		t.Fatalf("replay left nonce %d, block processing %d", gotNonce, wantNonce)
	}
}

// TestApplyTransactionForReplayAppliesHistoricalBalanceBypass checks that the replay applies
// the historical balance bypass block processing applies before it executes a transaction
// (core/state_processor_historical_bypass.go). The sender is deliberately left out of the
// genesis allocation: the balance its transaction needs comes from the bypass alone, so a
// replay that dropped the call fails with ErrInsufficientFunds instead of quietly succeeding.
//
// The bypass table is a package level map keyed by block number, so this test adds its own
// entry and drops it again afterwards. It must not run in parallel: other tests of this
// package process blocks and read the same map while they do.
func TestApplyTransactionForReplayAppliesHistoricalBalanceBypass(t *testing.T) {
	sender := replayTestSender()
	historicalBalanceBypassByBlock[1] = historicalBalanceBypass{addr: sender, balance: big.NewInt(1000000)}
	t.Cleanup(func() { delete(historicalBalanceBypassByBlock, 1) })

	f := newReplayTestFixture(t, types.GenesisAlloc{})
	newEVM := func(statedb *state.StateDB) *vm.EVM {
		return vm.NewEVM(NewEVMBlockContext(f.header, f.chain, nil), statedb, nil, f.config, vm.Config{})
	}

	replayState := f.statedb.Copy()
	replayState.SetTxContext(f.tx.Hash(), 0)
	if err := ApplyTransactionForReplay(f.msg, new(GasPool).AddGas(1000000), f.header.Number, f.tx, newEVM(replayState), nil); err != nil {
		t.Fatalf("ApplyTransactionForReplay failed: %v", err)
	}

	evmState := f.statedb.Copy()
	evmState.SetTxContext(f.tx.Hash(), 0)
	var usedGas uint64
	if _, _, _, err := ApplyTransactionWithEVM(f.msg, new(GasPool).AddGas(1000000), evmState, f.header.Number, f.genesisHash, f.tx, &usedGas, newEVM(evmState), nil); err != nil {
		t.Fatalf("ApplyTransactionWithEVM failed: %v", err)
	}

	want := evmState.GetBalance(sender)
	if want.Sign() == 0 {
		t.Fatal("block processing left the sender with no balance")
	}
	if got := replayState.GetBalance(sender); got.Cmp(want) != 0 {
		t.Fatalf("replay left the sender with balance %v, block processing %v", got, want)
	}
}

// TestApplyTransactionForReplayRefusesATracingEVM pins ErrReplayTracingEVM: the replay never
// fires OnTxStart/OnTxEnd, so it refuses an EVM that carries a tracer instead of handing back
// a state the caller cannot explain.
func TestApplyTransactionForReplayRefusesATracingEVM(t *testing.T) {
	f := newReplayTestFixture(t, types.GenesisAlloc{replayTestSender(): {Balance: big.NewInt(1000000000000000000)}})
	evm := vm.NewEVM(NewEVMBlockContext(f.header, f.chain, nil), f.statedb, nil, f.config, vm.Config{Tracer: &tracing.Hooks{}})

	err := ApplyTransactionForReplay(f.msg, new(GasPool).AddGas(1000000), f.header.Number, f.tx, evm, nil)
	if !errors.Is(err, ErrReplayTracingEVM) {
		t.Fatalf("ApplyTransactionForReplay returned %v, want %v", err, ErrReplayTracingEVM)
	}
}

// nativeRouteFinalisationChanges records the balance-change callbacks a state reports, so a
// test can ask what a finalisation observed rather than only where it landed.
type nativeRouteFinalisationChanges struct {
	reasons []tracing.BalanceChangeReason
	addrs   []common.Address
}

func (r *nativeRouteFinalisationChanges) hooks() *tracing.Hooks {
	return &tracing.Hooks{OnBalanceChange: func(addr common.Address, _, _ *big.Int, reason tracing.BalanceChangeReason) {
		r.reasons = append(r.reasons, reason)
		r.addrs = append(r.addrs, addr)
	}}
}

// TestNativeRoutesFinaliseTheStateTheEVMCarries covers the finalisation of the two native
// routes, ApplySignTransaction and ApplyEmptyTransaction. Both used to finalise the plain
// *state.StateDB behind the EVM and now finalise evm.StateDB instead (finaliseTxState), and on
// a traced path that state is a hookedStateDB, whose Finalise reports the balance of an account
// that self-destructed and still holds ether to the tracer. Neither route can produce such an
// account, because neither of them enters the EVM, so the two states are equivalent there; both
// halves below exist to keep that from being an assumption.
//
// The first half is the discriminator, run once per route: it leaves a self-destructed,
// non-empty account in the journal and requires the callback to fire. That account cannot
// appear on a real block, where every transaction finalises before the next one starts, but it
// is what separates a
// finalisation handed evm.StateDB from one handed the plain statedb - and keeping the events of
// block processing is exactly why finaliseTxState takes the state the EVM carries.
//
// The second half drives both routes over a state that holds no such account and requires
// nothing to be reported, with the hooked run pinned to the plain run's root. What it cannot do
// is separate the two implementations, because on these routes they are equal by construction:
// handing in the plain statedb again would leave it green. It guards the premise, not the
// pairing.
func TestNativeRoutesFinaliseTheStateTheEVMCarries(t *testing.T) {
	var (
		sender   = replayTestSender()
		coinbase = common.HexToAddress("0x0000000000000000000000000000000000c0ffee")
		burnt    = common.HexToAddress("0x00000000000000000000000000000000000000bb")
	)
	f := newReplayTestFixture(t, types.GenesisAlloc{sender: {Balance: big.NewInt(1000000000000000000)}})
	// Both native routes have to be active for this test to reach them.
	f.config.TIPSigningBlock = big.NewInt(0)
	f.config.TIPXDCXBlock = big.NewInt(0)
	f.config.TIPXDCXReceiverDisableBlock = nil
	cfg := f.config
	testKey, err := crypto.HexToECDSA(replayTestKey)
	if err != nil {
		t.Fatalf("Failed to parse the test key: %v", err)
	}
	signer := types.LatestSigner(cfg)

	newEVM := func(stateDB vm.StateDB) *vm.EVM {
		return vm.NewEVM(NewEVMBlockContext(f.header, f.chain, &coinbase), stateDB, nil, cfg, vm.Config{})
	}
	newNativeTx := func(nonce uint64, to common.Address) (*types.Transaction, *Message) {
		t.Helper()
		tx, err := types.SignTx(types.NewTx(&types.LegacyTx{
			Nonce:    nonce,
			To:       &to,
			Gas:      params.TxGas,
			GasPrice: big.NewInt(1),
		}), signer, testKey)
		if err != nil {
			t.Fatalf("Failed to sign the transaction to %v: %v", to, err)
		}
		msg, err := TransactionToMessage(tx, signer, nil, f.header.Number, f.header.BaseFee, cfg)
		if err != nil {
			t.Fatalf("Failed to build the message of the transaction to %v: %v", to, err)
		}
		return tx, msg
	}

	routes := []struct {
		name      string
		to        common.Address
		wantNonce uint64
		apply     func(*vm.EVM, *state.StateDB, *Message, *types.Transaction) error
	}{
		{
			name:      "sign route",
			to:        common.BlockSignersBinary,
			wantNonce: 1,
			apply: func(evm *vm.EVM, statedb *state.StateDB, msg *Message, tx *types.Transaction) error {
				var usedGas uint64
				_, _, _, err := ApplySignTransaction(msg, cfg, statedb, f.header.Number, f.genesisHash, tx, &usedGas, evm)
				return err
			},
		},
		{
			name:      "empty route",
			to:        common.TradingStateAddrBinary,
			wantNonce: 0,
			apply: func(evm *vm.EVM, statedb *state.StateDB, msg *Message, tx *types.Transaction) error {
				var usedGas uint64
				_, _, _, err := ApplyEmptyTransaction(msg, cfg, statedb, f.header.Number, f.genesisHash, tx, &usedGas, evm)
				return err
			},
		},
	}

	// Discriminator first, and for both routes: an account that self-destructed and then
	// received ether is exactly what a hooked finalisation reports and a plain one does not.
	for _, tc := range routes {
		t.Run("probe/"+tc.name, func(t *testing.T) {
			probeState := f.statedb.Copy()
			probeState.AddBalance(burnt, big.NewInt(7), tracing.BalanceChangeUnspecified)
			probeState.SelfDestruct(burnt)
			probeState.AddBalance(burnt, big.NewInt(9), tracing.BalanceChangeUnspecified)
			probeTx, probeMsg := newNativeTx(0, tc.to)
			probeState.SetTxContext(probeTx.Hash(), 0)
			probeEvents := &nativeRouteFinalisationChanges{}
			if err := tc.apply(newEVM(state.NewHookedState(probeState, probeEvents.hooks())), probeState, probeMsg, probeTx); err != nil {
				t.Fatalf("%s failed on the probe state: %v", tc.name, err)
			}
			if len(probeEvents.reasons) != 1 || probeEvents.reasons[0] != tracing.BalanceDecreaseSelfdestructBurn || probeEvents.addrs[0] != burnt {
				t.Fatalf("%s reported %v for %v, want exactly one %v for %v", tc.name, probeEvents.reasons, probeEvents.addrs, tracing.BalanceDecreaseSelfdestructBurn, burnt)
			}
		})
	}

	for _, tc := range routes {
		t.Run(tc.name, func(t *testing.T) {
			tx, msg := newNativeTx(0, tc.to)

			hookedState := f.statedb.Copy()
			hookedEvents := &nativeRouteFinalisationChanges{}
			hookedState.SetTxContext(tx.Hash(), 0)
			if err := tc.apply(newEVM(state.NewHookedState(hookedState, hookedEvents.hooks())), hookedState, msg, tx); err != nil {
				t.Fatalf("%s failed on the hooked state: %v", tc.name, err)
			}
			if len(hookedEvents.reasons) != 0 {
				t.Fatalf("%s reported %v to the tracer, want nothing: neither route enters the EVM", tc.name, hookedEvents.reasons)
			}
			if got := hookedState.GetNonce(sender); got != tc.wantNonce {
				t.Fatalf("%s left the sender nonce at %d, want %d", tc.name, got, tc.wantNonce)
			}

			plainState := f.statedb.Copy()
			plainState.SetTxContext(tx.Hash(), 0)
			if err := tc.apply(newEVM(plainState), plainState, msg, tx); err != nil {
				t.Fatalf("%s failed on the plain state: %v", tc.name, err)
			}
			hookedRoot := hookedState.IntermediateRoot(cfg.IsEIP158(f.header.Number))
			plainRoot := plainState.IntermediateRoot(cfg.IsEIP158(f.header.Number))
			if hookedRoot != plainRoot {
				t.Fatalf("%s left root %x on the hooked state and %x on the plain one", tc.name, hookedRoot, plainRoot)
			}
		})
	}
}

// TestApplyTransactionForReplayPaysTheTRC21FeeOfAFailedTransaction covers the TRC21 fee
// branch of the replay: while the TRC21 fee fork is active, block processing charges the
// fee of a failed transaction to the sender's token balance (PayFeeWithTRC21TxFail, see
// core/state/trc21_reader.go), and the replay has to do the same. A replay that dropped the
// branch would leave the token balances where the failed execution left them.
//
// The token carries a body that reverts, so the transaction fails on its own and the test
// does not have to name which transaction does. Its balance is larger than the token's
// minFee, so the fee has something to move, and the token is registered with the issuer
// together with its capacity, so the capacity lookup the caller does for tx.To() finds one
// and hands it to the replay as balanceFee.
func TestApplyTransactionForReplayPaysTheTRC21FeeOfAFailedTransaction(t *testing.T) {
	const (
		senderTokenBalance = 1000
		tokenMinFee        = 10
	)
	var (
		sender = replayTestSender()
		issuer = common.HexToAddress("0x00000000000000000000000000000000000000bb")
		token  = common.HexToAddress("0x00000000000000000000000000000000000000aa")
	)
	config := replayTestConfig()
	config.TRC21IssuerSMC = issuer

	// GetTRC21FeeCapacityFromState reads the token list and the per-token capacity off the
	// issuer contract, so both slots have to be seeded.
	slotTokensHash := common.BigToHash(new(big.Int).SetUint64(state.SlotTRC21Issuer["tokens"]))
	tokenSlot := state.GetLocDynamicArrAtElement(slotTokensHash, 0, 1)
	tokenStateSlot := common.BigToHash(state.GetLocMappingAtKey(token.Hash(), state.SlotTRC21Issuer["tokensState"]))
	// buyGas bounds BalanceTokenFee by GasLimit * the TRC21 gas price of the block, so ask
	// the config for that price instead of assuming one.
	gasPrice, err := params.GetGasPriceForTRC21(common.Big1, config)
	if err != nil {
		t.Fatalf("failed to read the TRC21 gas price: %v", err)
	}
	feeCapacity := new(big.Int).Mul(new(big.Int).SetUint64(params.TxGas), gasPrice)

	senderBalanceSlot := common.BigToHash(state.GetLocMappingAtKey(sender.Hash(), state.SlotTRC21Token["balances"]))
	issuerBalanceSlot := common.BigToHash(state.GetLocMappingAtKey(issuer.Hash(), state.SlotTRC21Token["balances"]))

	db := rawdb.NewMemoryDatabase()
	gspec := &Genesis{
		Config: config,
		Alloc: types.GenesisAlloc{
			sender: {Balance: new(big.Int).Mul(big.NewInt(params.Ether), big.NewInt(2))},
			issuer: {
				Storage: map[common.Hash]common.Hash{
					slotTokensHash: common.BigToHash(big.NewInt(1)),
					tokenSlot:      common.BytesToHash(token.Bytes()),
					tokenStateSlot: common.BigToHash(feeCapacity),
				},
			},
			token: {
				// PUSH1 0, PUSH1 0, REVERT: every call to it fails.
				Code: []byte{0x60, 0x00, 0x60, 0x00, 0xfd},
				Storage: map[common.Hash]common.Hash{
					senderBalanceSlot: common.BigToHash(big.NewInt(senderTokenBalance)),
					state.GetLocSimpleVariable(state.SlotTRC21Token["minFee"]): common.BigToHash(big.NewInt(tokenMinFee)),
					state.GetLocSimpleVariable(state.SlotTRC21Token["issuer"]): common.BytesToHash(issuer.Bytes()),
				},
			},
		},
	}
	blockchain, err := NewBlockChain(db, nil, gspec, ethash.NewFaker(), vm.Config{})
	if err != nil {
		t.Fatalf("failed to create the blockchain: %v", err)
	}
	t.Cleanup(blockchain.Stop)

	statedb, err := blockchain.State()
	if err != nil {
		t.Fatalf("failed to get the state: %v", err)
	}
	testKey, err := crypto.HexToECDSA(replayTestKey)
	if err != nil {
		t.Fatalf("failed to parse the test key: %v", err)
	}
	signer := types.LatestSigner(config)
	header := &types.Header{Number: big.NewInt(1), Difficulty: big.NewInt(1), BaseFee: new(big.Int)}
	tx, err := types.SignTx(types.NewTx(&types.LegacyTx{
		Nonce:    0,
		To:       &token,
		Value:    big.NewInt(0),
		Gas:      params.TxGas,
		GasPrice: big.NewInt(1),
	}), signer, testKey)
	if err != nil {
		t.Fatalf("failed to sign the transaction: %v", err)
	}
	// balanceFee is what production hands in: the capacity it looked up for tx.To().
	msg, err := TransactionToMessage(tx, signer, feeCapacity, header.Number, header.BaseFee, config)
	if err != nil {
		t.Fatalf("failed to build the message: %v", err)
	}
	newEVM := func(stateDB *state.StateDB) *vm.EVM {
		return vm.NewEVM(NewEVMBlockContext(header, blockchain, nil), stateDB, nil, config, vm.Config{})
	}

	replayState := statedb.Copy()
	replayState.SetTxContext(tx.Hash(), 0)
	if err := ApplyTransactionForReplay(msg, new(GasPool).AddGas(params.TxGas), header.Number, tx, newEVM(replayState), feeCapacity); err != nil {
		t.Fatalf("ApplyTransactionForReplay failed: %v", err)
	}

	evmState := statedb.Copy()
	evmState.SetTxContext(tx.Hash(), 0)
	var usedGas uint64
	if _, _, _, err := ApplyTransactionWithEVM(msg, new(GasPool).AddGas(params.TxGas), evmState, header.Number, header.Hash(), tx, &usedGas, newEVM(evmState), feeCapacity); err != nil {
		t.Fatalf("ApplyTransactionWithEVM failed: %v", err)
	}

	// Pin the charge block processing made before comparing: without it the comparison
	// below would also pass on two paths that both left the token balances alone.
	wantSender := common.BigToHash(big.NewInt(senderTokenBalance - tokenMinFee))
	if got := evmState.GetState(token, senderBalanceSlot); got != wantSender {
		t.Fatalf("block processing left the sender token balance at %v, want %v", got.Big(), wantSender.Big())
	}
	if got := replayState.GetState(token, senderBalanceSlot); got != wantSender {
		t.Fatalf("replay left the sender token balance at %v, block processing %v", got.Big(), wantSender.Big())
	}
	// The fee has to have landed on the issuer the token names.
	wantIssuer := common.BigToHash(big.NewInt(tokenMinFee))
	if got := evmState.GetState(token, issuerBalanceSlot); got != wantIssuer {
		t.Fatalf("block processing credited the issuer with %v, want %v", got.Big(), wantIssuer.Big())
	}
	if got := replayState.GetState(token, issuerBalanceSlot); got != wantIssuer {
		t.Fatalf("replay credited the issuer with %v, block processing %v", got.Big(), wantIssuer.Big())
	}
}
