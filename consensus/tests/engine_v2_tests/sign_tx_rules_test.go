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

package engine_v2_tests

import (
	"errors"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/XinFinOrg/XDPoSChain/trie"
)

// XDPoS keeps the candidate list sign transactions are checked against. The
// sign transaction rules find it through a type assertion, so losing the
// method would silently turn the sender rule off; this fails the build instead.
// It lives here because package XDPoS cannot import core without a cycle.
var _ core.SignerSource = (*XDPoS.XDPoS)(nil)

// TestProcessSignTxRulesWithXDPoS checks that block processing with the XDPoS
// engine rejects a block holding a sign transaction from a non-candidate once
// TIPSignTxRules is active, and lets one from a candidate through.
func TestProcessSignTxRulesWithXDPoS(t *testing.T) {
	t.Parallel()
	blockchain, _, parent, _, _, _ := PrepareXDCTestBlockChainForV2Engine(t, int(params.TestXDPoSMockChainConfig.XDPoS.Epoch)+10, params.TestXDPoSMockChainConfig, nil)
	if core.SignerSourceOf(blockchain.Engine()) == nil {
		t.Fatal("the XDPoS engine is not a SignerSource")
	}

	// The shared helper keeps TIPSigning in the future; the processor here
	// routes sign transactions and applies the rules from genesis.
	config := blockchain.Config().Clone()
	config.TIPSigningBlock = big.NewInt(0)
	config.TIPSignTxRulesBlock = big.NewInt(0)
	processor := core.NewStateProcessor(config, blockchain, blockchain.Engine())

	number := parent.NumberU64() + 1
	signed := blockchain.GetHeaderByNumber(parent.NumberU64() - parent.NumberU64()%common.MergeSignRange)
	outsiderKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	for _, tt := range []struct {
		name string
		tx   func() (*types.Transaction, error)
		want error
	}{
		// The header carries no V2 extra, so a block that passes every
		// transaction fails only at Finalize.
		{"candidate", func() (*types.Transaction, error) { return signingTxWithKey(signed, 0, acc1Key) }, core.ErrFinalize},
		{"non-candidate", func() (*types.Transaction, error) { return signingTxWithKey(signed, 0, outsiderKey) }, core.ErrSignTxNotCandidate},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tx, err := tt.tx()
			if err != nil {
				t.Fatalf("sign tx: %v", err)
			}
			header := &types.Header{
				ParentHash: parent.Hash(),
				Number:     new(big.Int).SetUint64(number),
				GasLimit:   testGasLimit,
				Time:       parent.Time() + 2,
				Difficulty: big.NewInt(1),
			}
			block := types.NewBlock(header, &types.Body{Transactions: types.Transactions{tx}}, nil, trie.NewStackTrie(nil))
			statedb, err := blockchain.StateAt(parent.Root())
			if err != nil {
				t.Fatalf("parent state: %v", err)
			}
			_, _, _, err = processor.Process(block, statedb, nil, vm.Config{}, map[common.Address]*big.Int{})
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
		})
	}
}
