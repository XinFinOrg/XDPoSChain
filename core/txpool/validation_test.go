// Copyright 2025 The go-ethereum Authors
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

package txpool

import (
	"crypto/ecdsa"
	"encoding/binary"
	"errors"
	"math"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/holiman/uint256"
)

func TestValidateTransactionEIP2681(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	head := &types.Header{
		Number:     big.NewInt(1),
		GasLimit:   5000000,
		Time:       1,
		Difficulty: big.NewInt(1),
	}

	signer := types.LatestSigner(params.TestChainConfig)

	// Create validation options
	opts := &ValidationOptions{
		Config:       params.TestChainConfig,
		Accept:       0xFF, // Accept all transaction types
		MaxSize:      32 * 1024,
		MaxBlobCount: 6,
		MinTip:       big.NewInt(0),
	}

	tests := []struct {
		name    string
		nonce   uint64
		wantErr error
	}{
		{
			name:    "normal nonce",
			nonce:   42,
			wantErr: nil,
		},
		{
			name:    "max allowed nonce (2^64-2)",
			nonce:   math.MaxUint64 - 1,
			wantErr: nil,
		},
		{
			name:    "EIP-2681 nonce overflow (2^64-1)",
			nonce:   math.MaxUint64,
			wantErr: core.ErrNonceMax,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tx := createTestTransaction(key, tt.nonce)
			err := ValidateTransaction(tx, head, signer, opts)

			if tt.wantErr == nil {
				if err != nil {
					t.Errorf("ValidateTransaction() error = %v, wantErr nil", err)
				}
			} else {
				if err == nil {
					t.Errorf("ValidateTransaction() error = nil, wantErr %v", tt.wantErr)
				} else if !errors.Is(err, tt.wantErr) {
					t.Errorf("ValidateTransaction() error = %v, wantErr %v", err, tt.wantErr)
				}
			}
		})
	}
}

// createTestTransaction creates a basic transaction for testing
func createTestTransaction(key *ecdsa.PrivateKey, nonce uint64) *types.Transaction {
	to := common.HexToAddress("0x0000000000000000000000000000000000000001")

	txdata := &types.LegacyTx{
		Nonce:    nonce,
		To:       &to,
		Value:    big.NewInt(1000),
		Gas:      21000,
		GasPrice: big.NewInt(1),
		Data:     nil,
	}

	tx := types.NewTx(txdata)
	signedTx, _ := types.SignTx(tx, types.HomesteadSigner{}, key)
	return signedTx
}

// TestValidateTransactionFrameTxForkGate covers EIP-8141 pool validation:
// frame transactions are rejected while the FrameTx fork is inactive
// (the default on every preset network), and once the fork is active the
// protocol signature rules and the EIP-7825 gas-limit constraint apply.
func TestValidateTransactionFrameTxForkGate(t *testing.T) {
	makeFrameTx := func(executionGas uint64, sigs []types.FrameSignature) *types.Transaction {
		return types.NewFrameTx(
			uint256.NewInt(1), // TestChainConfig chain ID
			0,
			common.HexToAddress("0x00000000000000000000000000000000000bbbbb"),
			[]types.Frame{
				// Recognized self-relay validation prefix: self_verify.
				{Mode: types.FrameModeVerify, Flags: 0x3, Limits: types.FrameLimits{Execution: executionGas}},
			},
			sigs,
			types.FrameFees{
				GasTipCap:  uint256.NewInt(1),
				GasFeeCap:  uint256.NewInt(100),
				BlobFeeCap: uint256.NewInt(0),
			},
			nil,
		)
	}

	// makeUnrecognizedPrefixTx builds a frame sequence outside the four
	// recognized validation prefixes (a bare DEFAULT + SENDER pair).
	makeUnrecognizedPrefixTx := func() *types.Transaction {
		target := common.HexToAddress("0x00000000000000000000000000000000000aaaaa")
		return types.NewFrameTx(
			uint256.NewInt(1),
			0,
			common.HexToAddress("0x00000000000000000000000000000000000bbbbb"),
			[]types.Frame{
				{Mode: types.FrameModeDefault, Limits: types.FrameLimits{Execution: 50000}},
				{Mode: types.FrameModeSender, Limits: types.FrameLimits{Execution: 50000}, Value: uint256.NewInt(1), Target: &target},
			},
			nil,
			types.FrameFees{
				GasTipCap:  uint256.NewInt(1),
				GasFeeCap:  uint256.NewInt(100),
				BlobFeeCap: uint256.NewInt(0),
			},
			nil,
		)
	}

	// makeExpiryTx builds a self-relay prefix prefixed by an expiry
	// verifier frame carrying the given deadline.
	makeExpiryTx := func(deadline uint64) *types.Transaction {
		var data [8]byte
		binary.BigEndian.PutUint64(data[:], deadline)
		verifier := types.FrameExpiryVerifier
		return types.NewFrameTx(
			uint256.NewInt(1),
			0,
			common.HexToAddress("0x00000000000000000000000000000000000bbbbb"),
			[]types.Frame{
				{Mode: types.FrameModeVerify, Target: &verifier, Flags: 0x0, Data: data[:], Limits: types.FrameLimits{Execution: 10000}},
				{Mode: types.FrameModeVerify, Flags: 0x3, Limits: types.FrameLimits{Execution: 50000}},
			},
			nil,
			types.FrameFees{
				GasTipCap:  uint256.NewInt(1),
				GasFeeCap:  uint256.NewInt(100),
				BlobFeeCap: uint256.NewInt(0),
			},
			nil,
		)
	}

	head := &types.Header{
		Number:     big.NewInt(1),
		GasLimit:   5_000_000,
		Time:       1,
		Difficulty: big.NewInt(0), // merge rules active
	}
	opts := &ValidationOptions{
		Accept:       0xFF, // accept all transaction types
		MaxSize:      32 * 1024 * 1024,
		MaxBlobCount: 6,
		MinTip:       big.NewInt(0),
	}

	// Case 1: fork inactive (default config): rejection even with Accept=0xFF.
	opts.Config = params.TestChainConfig
	if err := ValidateTransaction(makeFrameTx(100000, nil), head, types.LatestSigner(params.TestChainConfig), opts); err == nil {
		t.Fatal("frame transaction accepted while FrameTx fork inactive")
	} else if !errors.Is(err, core.ErrTxTypeNotSupported) {
		t.Fatalf("unexpected error for inactive fork: %v", err)
	}

	// Fork-active configuration: same preset with FrameTxTime scheduled at 0.
	activeCfg := *params.TestChainConfig
	activeCfg.FrameTxTime = new(uint64)
	*activeCfg.FrameTxTime = 0
	signer := types.MakeSigner(&activeCfg, head.Number, head.Time)
	opts.Config = &activeCfg

	// Case 2: fork active, well-formed transaction passes static validation.
	if err := ValidateTransaction(makeFrameTx(100000, nil), head, signer, opts); err != nil {
		t.Fatalf("valid frame transaction rejected at active fork: %v", err)
	}

	// Case 3: fork active, structurally invalid signature entry (recovery id
	// of 2 with zero scalars) fails ValidateFrameSignatures.
	badSig := make([]byte, 65)
	badSig[0] = 0x02 // v = 2, an unsupported recovery id
	badSigs := []types.FrameSignature{
		{Scheme: types.FrameSigSchemeSecp256k1, Signature: badSig},
	}
	if err := ValidateTransaction(makeFrameTx(100000, badSigs), head, signer, opts); err == nil {
		t.Fatal("frame transaction with invalid signature accepted")
	}

	// Case 4: fork active, execution gas over the EIP-7825 cap fails.
	if err := ValidateTransaction(makeFrameTx(params.MaxTxGas, nil), head, signer, opts); err == nil {
		t.Fatal("frame transaction over TX_MAX_GAS_LIMIT accepted")
	}

	// Case 5: fork active, a frame sequence outside the recognized
	// validation prefixes fails the EIP-8141 public-mempool structural rules.
	if err := ValidateTransaction(makeUnrecognizedPrefixTx(), head, signer, opts); err == nil {
		t.Fatal("frame transaction with unrecognized validation prefix accepted")
	} else if !errors.Is(err, types.ErrFrameValidationPrefix) {
		t.Fatalf("unexpected error for unrecognized prefix: %v", err)
	}

	// Case 6: fork active, a recognized prefix whose declared execution
	// limits exceed MAX_VERIFY_GAS fails admission.
	if err := ValidateTransaction(makeFrameTx(types.FrameMaxVerifyGas+1, nil), head, signer, opts); err == nil {
		t.Fatal("frame transaction over MAX_VERIFY_GAS accepted")
	} else if !errors.Is(err, types.ErrFrameValidationPrefix) {
		t.Fatalf("unexpected error for verify-gas cap: %v", err)
	}

	// Case 7: expiry verifier deadline freshness against the head
	// timestamp (head.Time == 1). A future deadline is admitted; deadline
	// 0 is expired and must be dropped.
	if err := ValidateTransaction(makeExpiryTx(1000), head, signer, opts); err != nil {
		t.Fatalf("frame transaction with future expiry deadline rejected: %v", err)
	}
	if err := ValidateTransaction(makeExpiryTx(0), head, signer, opts); err == nil {
		t.Fatal("frame transaction with expired expiry deadline accepted")
	} else if !errors.Is(err, types.ErrFrameValidationPrefix) {
		t.Fatalf("unexpected error for expired deadline: %v", err)
	}
}
