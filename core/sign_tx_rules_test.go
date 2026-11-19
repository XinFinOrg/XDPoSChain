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

package core_test

import (
	"errors"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/contracts"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// signTxRulesConfig has TIPSigning and TIP2019 active from genesis and a 900
// block epoch, so the window is 1800 blocks.
func signTxRulesConfig() *params.ChainConfig {
	cfg := params.TestXDPoSMockChainConfig.Clone()
	cfg.TIPSigningBlock = big.NewInt(0)
	cfg.TIP2019Block = big.NewInt(0)
	cfg.XDPoS.Epoch = 900
	return cfg
}

// signData is the call data of a sign(number, hash) call.
func signData(number uint64, hash common.Hash) []byte {
	data := common.Hex2Bytes(common.HexSignMethod)
	data = append(data, common.LeftPadBytes(new(big.Int).SetUint64(number).Bytes(), 32)...)
	return append(data, hash.Bytes()...)
}

// staticSigners is a SignerSource with a fixed candidate list.
type staticSigners struct {
	signers []common.Address
	err     error
	calls   int
}

func (s *staticSigners) GetAuthorisedSignersFromSnapshot(consensus.ChainReader, *types.Header) ([]common.Address, error) {
	s.calls++
	return s.signers, s.err
}

func TestCheckSignTxFields(t *testing.T) {
	cfg := signTxRulesConfig()
	block := big.NewInt(2010)
	honest := contracts.CreateTxSign(big.NewInt(1995), common.HexToHash("0x01"), 7, common.BlockSignersBinary)
	legacy := func(to common.Address, value *big.Int, data []byte) *types.Transaction {
		return types.NewTransaction(0, to, value, 200000, big.NewInt(0), data)
	}
	tests := []struct {
		name string
		tx   *types.Transaction
		want error
	}{
		{"honest CreateTxSign", honest, nil},
		{"window edge, 1800 blocks back", legacy(common.BlockSignersBinary, big.NewInt(0), signData(210, common.Hash{1})), nil},
		{"not a sign transaction", legacy(common.HexToAddress("0x1234"), big.NewInt(5), []byte{1, 2, 3}), nil},
		{"access list tx", types.NewTx(&types.AccessListTx{ChainID: cfg.ChainID, To: &common.BlockSignersBinary, Gas: 200000, GasPrice: big.NewInt(0), Data: signData(1995, common.Hash{1})}), core.ErrSignTxType},
		{"dynamic fee tx", types.NewTx(&types.DynamicFeeTx{ChainID: cfg.ChainID, To: &common.BlockSignersBinary, Gas: 200000, GasFeeCap: big.NewInt(0), GasTipCap: big.NewInt(0), Data: signData(1995, common.Hash{1})}), core.ErrSignTxType},
		{"short data", legacy(common.BlockSignersBinary, big.NewInt(0), signData(1995, common.Hash{1})[:67]), core.ErrSignTxData},
		{"long data", legacy(common.BlockSignersBinary, big.NewInt(0), append(signData(1995, common.Hash{1}), 0)), core.ErrSignTxData},
		{"wrong selector", legacy(common.BlockSignersBinary, big.NewInt(0), append([]byte{1, 2, 3, 4}, signData(1995, common.Hash{1})[4:]...)), core.ErrSignTxData},
		{"value", legacy(common.BlockSignersBinary, big.NewInt(1), signData(1995, common.Hash{1})), core.ErrSignTxValue},
		{"signs the including block", legacy(common.BlockSignersBinary, big.NewInt(0), signData(2010, common.Hash{1})), core.ErrSignTxFutureBlock},
		{"signs a future block", legacy(common.BlockSignersBinary, big.NewInt(0), signData(2025, common.Hash{1})), core.ErrSignTxFutureBlock},
		{"not a merge block", legacy(common.BlockSignersBinary, big.NewInt(0), signData(1996, common.Hash{1})), core.ErrSignTxNotMergeBlock},
		{"out of window", legacy(common.BlockSignersBinary, big.NewInt(0), signData(195, common.Hash{1})), core.ErrSignTxOutOfWindow},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := core.CheckSignTxFields(cfg, block, tt.tx)
			if !errors.Is(err, tt.want) || (tt.want == nil && err != nil) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestCheckSignTxFieldsBeforeTIPSigning(t *testing.T) {
	cfg := signTxRulesConfig()
	cfg.TIPSigningBlock = big.NewInt(5000)
	// Before TIPSigning a BlockSigners transaction runs in the EVM and is not
	// a sign transaction, so the rules do not apply.
	tx := types.NewTransaction(0, common.BlockSignersBinary, big.NewInt(1), 200000, big.NewInt(0), []byte{1})
	if err := core.CheckSignTxFields(cfg, big.NewInt(2000), tx); err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
}

func TestCheckSignTxFieldsBeforeTIP2019(t *testing.T) {
	cfg := signTxRulesConfig()
	cfg.TIP2019Block = big.NewInt(5000)
	// Before TIP2019 every block is signed, not only merge blocks.
	tx := types.NewTransaction(0, common.BlockSignersBinary, big.NewInt(0), 200000, big.NewInt(0), signData(1996, common.Hash{1}))
	if err := core.CheckSignTxFields(cfg, big.NewInt(2000), tx); err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
}

func TestSignTxRulesSenderAndDuplicates(t *testing.T) {
	cfg := signTxRulesConfig()
	alice, bob, mallory := common.HexToAddress("0xa1"), common.HexToAddress("0xb0"), common.HexToAddress("0xbad")
	source := &staticSigners{signers: []common.Address{alice, bob}}
	rules := core.NewSignTxRules(cfg, big.NewInt(2000), source, nil, &types.Header{Number: big.NewInt(1999)})

	sign := func(nonce uint64, number uint64) *types.Transaction {
		return contracts.CreateTxSign(new(big.Int).SetUint64(number), common.Hash{byte(number)}, nonce, common.BlockSignersBinary)
	}
	other := types.NewTransaction(0, common.HexToAddress("0x1234"), big.NewInt(1), 21000, big.NewInt(1), nil)

	// A regular transaction neither loads the candidates nor counts.
	if err := rules.Check(other, mallory); err != nil {
		t.Fatalf("regular tx: %v", err)
	}
	rules.Record(other, mallory)
	if source.calls != 0 {
		t.Fatalf("candidates loaded for a block without sign transactions")
	}
	if err := rules.Check(sign(0, 1995), mallory); !errors.Is(err, core.ErrSignTxNotCandidate) {
		t.Fatalf("non-candidate: err = %v, want %v", err, core.ErrSignTxNotCandidate)
	}
	first := sign(0, 1995)
	if err := rules.Check(first, alice); err != nil {
		t.Fatalf("first from alice: %v", err)
	}
	// Check alone does not count: the same transaction still passes.
	if err := rules.Check(sign(1, 1980), alice); err != nil {
		t.Fatalf("unrecorded second from alice: %v", err)
	}
	rules.Record(first, alice)
	if err := rules.Check(sign(1, 1980), alice); !errors.Is(err, core.ErrSignTxDuplicateSender) {
		t.Fatalf("second from alice: err = %v, want %v", err, core.ErrSignTxDuplicateSender)
	}
	if err := rules.Check(sign(0, 1995), bob); err != nil {
		t.Fatalf("first from bob: %v", err)
	}
	if err := rules.Check(types.NewTransaction(0, common.BlockSignersBinary, big.NewInt(0), 0, big.NewInt(0), []byte{1}), bob); !errors.Is(err, core.ErrSignTxData) {
		t.Fatalf("field rules not applied: err = %v", err)
	}
	if source.calls != 1 {
		t.Fatalf("candidates loaded %d times, want 1", source.calls)
	}
}

func TestSignTxRulesCandidateLoadError(t *testing.T) {
	cfg := signTxRulesConfig()
	loadErr := errors.New("snapshot unavailable")
	rules := core.NewSignTxRules(cfg, big.NewInt(2000), &staticSigners{err: loadErr}, nil, &types.Header{Number: big.NewInt(1999)})
	if err := rules.Check(contracts.CreateTxSign(big.NewInt(1995), common.Hash{1}, 0, common.BlockSignersBinary), common.HexToAddress("0xa1")); !errors.Is(err, loadErr) {
		t.Fatalf("err = %v, want %v", err, loadErr)
	}
}

func TestSignTxRulesWithoutSignerSource(t *testing.T) {
	cfg := signTxRulesConfig()
	if core.SignerSourceOf(nil) != nil {
		t.Fatalf("SignerSourceOf(nil) is not nil")
	}
	rules := core.NewSignTxRules(cfg, big.NewInt(2000), nil, nil, nil)
	if err := rules.Check(contracts.CreateTxSign(big.NewInt(1995), common.Hash{1}, 0, common.BlockSignersBinary), common.HexToAddress("0xa1")); err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
}
