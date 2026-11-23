// Copyright 2026 The XDPoSChain Authors
// This file is part of the XDPoSChain library.
//
// The XDPoSChain library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The XDPoSChain library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the XDPoSChain library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// signerSourceEngine is a no-op engine that reports a fixed candidate list.
type signerSourceEngine struct {
	noopConsensusEngine
	signers []common.Address
}

func (e *signerSourceEngine) GetAuthorisedSignersFromSnapshot(consensus.ChainReader, *types.Header) ([]common.Address, error) {
	return e.signers, nil
}

// signRuleTx signs a transaction to BlockSigners from key with the given data.
func signRuleTx(t *testing.T, config *params.ChainConfig, key *ecdsa.PrivateKey, nonce uint64, data []byte) *types.Transaction {
	t.Helper()
	tx := types.NewTransaction(nonce, common.BlockSignersBinary, big.NewInt(0), 200000, big.NewInt(0), data)
	signed, err := types.SignTx(tx, types.MakeSigner(config, big.NewInt(1)), key)
	if err != nil {
		t.Fatalf("sign tx: %v", err)
	}
	return signed
}

// signCallData is a sign(number, hash) call.
func signCallData(number uint64, hash common.Hash) []byte {
	data := common.Hex2Bytes(common.HexSignMethod)
	data = append(data, common.LeftPadBytes(new(big.Int).SetUint64(number).Bytes(), 32)...)
	return append(data, hash.Bytes()...)
}

// TestProcessAppliesSignTxRulesFromFork checks that block processing rejects a
// block whose sign transactions break the rules from TIPSignTxRules on, on
// both processing paths, and accepts it before the fork.
func TestProcessAppliesSignTxRulesFromFork(t *testing.T) {
	t.Parallel()

	candidateKey, _ := crypto.GenerateKey()
	outsiderKey, _ := crypto.GenerateKey()
	candidate := crypto.PubkeyToAddress(candidateKey.PublicKey)

	newConfig := func(forkBlock *big.Int) *params.ChainConfig {
		// Every fork is active from genesis, so TIPSignTxRules at block 1 is in
		// order; TIPSigning is active, so BlockSigners txs take the sign route.
		config := params.TestChainConfig.Clone()
		config.TIPSignTxRulesBlock = forkBlock
		return config
	}
	honest := func(c *params.ChainConfig) types.Transactions {
		return types.Transactions{signRuleTx(t, c, candidateKey, 0, signCallData(0, common.Hash{1}))}
	}
	tests := []struct {
		name string
		txs  func(*params.ChainConfig) types.Transactions
		// want is the error once the fork is active; before it every block passes.
		want error
	}{
		{"honest", honest, nil},
		{"malformed data", func(c *params.ChainConfig) types.Transactions {
			return types.Transactions{signRuleTx(t, c, candidateKey, 0, make([]byte, 100))}
		}, ErrSignTxData},
		{"non-candidate sender", func(c *params.ChainConfig) types.Transactions {
			return types.Transactions{signRuleTx(t, c, outsiderKey, 0, signCallData(0, common.Hash{1}))}
		}, ErrSignTxNotCandidate},
		{"two from one sender", func(c *params.ChainConfig) types.Transactions {
			return types.Transactions{
				signRuleTx(t, c, candidateKey, 0, signCallData(0, common.Hash{1})),
				signRuleTx(t, c, candidateKey, 1, signCallData(0, common.Hash{2})),
			}
		}, ErrSignTxDuplicateSender},
	}
	for _, tt := range tests {
		for _, fork := range []struct {
			name  string
			block *big.Int
		}{{"before fork", nil}, {"after fork", big.NewInt(1)}} {
			t.Run(tt.name+"/"+fork.name, func(t *testing.T) {
				config := newConfig(fork.block)
				gspec := &Genesis{Config: config, Alloc: types.GenesisAlloc{common.BlockSignersBinary: {Balance: big.NewInt(1)}}}
				blockchain, err := NewBlockChain(rawdb.NewMemoryDatabase(), nil, gspec, noopConsensusEngine{}, vm.Config{})
				if err != nil {
					t.Fatalf("failed to create blockchain: %v", err)
				}
				defer blockchain.Stop()

				block := GenerateBadBlock(t, gspec.ToBlock(), noopConsensusEngine{}, tt.txs(config), config)
				processor := NewStateProcessor(config, blockchain, &signerSourceEngine{signers: []common.Address{candidate}})
				want := tt.want
				if fork.block == nil {
					want = nil
				}

				statedb, err := blockchain.State()
				if err != nil {
					t.Fatalf("state: %v", err)
				}
				_, _, _, err = processor.Process(block, statedb, nil, vm.Config{}, map[common.Address]*big.Int{})
				if !errors.Is(err, want) || (want == nil && err != nil) {
					t.Fatalf("Process: err = %v, want %v", err, want)
				}

				statedb, err = blockchain.State()
				if err != nil {
					t.Fatalf("state: %v", err)
				}
				_, _, _, err = processor.ProcessBlockNoValidator(&CalculatedBlock{block: block}, statedb, nil, vm.Config{}, map[common.Address]*big.Int{})
				if !errors.Is(err, want) || (want == nil && err != nil) {
					t.Fatalf("ProcessBlockNoValidator: err = %v, want %v", err, want)
				}
			})
		}
	}
}

// TestSignTxRulesUnknownParentIsLocal checks that a sign transaction checked
// against a parent this node does not have fails as a local condition, not as
// a bad block: the missing header is this node's state, not the block's fault.
func TestSignTxRulesUnknownParentIsLocal(t *testing.T) {
	t.Parallel()

	key, _ := crypto.GenerateKey()
	candidate := crypto.PubkeyToAddress(key.PublicKey)
	config := params.TestChainConfig
	rules := NewSignTxRules(config, big.NewInt(1), &signerSourceEngine{signers: []common.Address{candidate}}, nil, nil)

	err := rules.Check(signRuleTx(t, config, key, 0, signCallData(0, common.Hash{1})), candidate)
	if err == nil {
		t.Fatal("Check passed without a parent header")
	}
	if errors.Is(err, ErrSignTxNotCandidate) {
		t.Fatalf("err = %v, the sender is blamed for a missing parent", err)
	}
	if !IsLocalInsertError(err) || classifyInsertErr(err).badBlock {
		t.Fatalf("err = %v: local = %v, badBlock = %v, want a local condition that is not a bad block", err, IsLocalInsertError(err), classifyInsertErr(err).badBlock)
	}
}

// failingSignerSource is a no-op engine whose candidate list cannot be read.
type failingSignerSource struct {
	noopConsensusEngine
	err error
}

func (e *failingSignerSource) GetAuthorisedSignersFromSnapshot(consensus.ChainReader, *types.Header) ([]common.Address, error) {
	return nil, e.err
}

// TestProcessSignTxSnapshotFailureIsLocal checks that a candidate list the
// engine cannot read fails block processing as a local condition, not as a
// bad block.
func TestProcessSignTxSnapshotFailureIsLocal(t *testing.T) {
	t.Parallel()

	key, _ := crypto.GenerateKey()
	config := params.TestChainConfig.Clone()
	config.TIPSignTxRulesBlock = big.NewInt(1)
	gspec := &Genesis{Config: config, Alloc: types.GenesisAlloc{common.BlockSignersBinary: {Balance: big.NewInt(1)}}}
	blockchain, err := NewBlockChain(rawdb.NewMemoryDatabase(), nil, gspec, noopConsensusEngine{}, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create blockchain: %v", err)
	}
	defer blockchain.Stop()

	block := GenerateBadBlock(t, gspec.ToBlock(), noopConsensusEngine{}, types.Transactions{signRuleTx(t, config, key, 0, signCallData(0, common.Hash{1}))}, config)
	engine := &failingSignerSource{err: fmt.Errorf("%w", consensus.ErrGapSnapshotUnavailable)}
	processor := NewStateProcessor(config, blockchain, engine)
	statedb, err := blockchain.State()
	if err != nil {
		t.Fatalf("state: %v", err)
	}
	_, _, _, err = processor.Process(block, statedb, nil, vm.Config{}, map[common.Address]*big.Int{})
	if !errors.Is(err, consensus.ErrGapSnapshotUnavailable) {
		t.Fatalf("err = %v, want %v", err, consensus.ErrGapSnapshotUnavailable)
	}
	if !IsLocalInsertError(err) || classifyInsertErr(err).badBlock {
		t.Fatalf("err = %v: local = %v, badBlock = %v, want a local condition that is not a bad block", err, IsLocalInsertError(err), classifyInsertErr(err).badBlock)
	}
}
