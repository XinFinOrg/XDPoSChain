// Copyright 2026 The go-ethereum Authors
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

package usbwallet

import (
	"bytes"
	"encoding/binary"
	"io"
	"math/big"
	"strings"
	"testing"

	"github.com/holiman/uint256"

	"github.com/XinFinOrg/XDPoSChain/accounts"
	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/log"
	"github.com/XinFinOrg/XDPoSChain/rlp"
)

// recordingDevice captures every chunk written to the hardware wallet and fails
// all reads, so ledgerExchange stops right after the request has been sent and
// the test only has to look at what the driver tried to deliver.
type recordingDevice struct {
	writes [][]byte
}

func (d *recordingDevice) Write(p []byte) (int, error) {
	chunk := make([]byte, len(p))
	copy(chunk, p)
	d.writes = append(d.writes, chunk)
	return len(p), nil
}

func (d *recordingDevice) Read(p []byte) (int, error) { return 0, io.EOF }

// requestData reassembles the APDU sent to the device and returns its data field.
func (d *recordingDevice) requestData(t *testing.T) []byte {
	t.Helper()

	var apdu []byte
	for _, chunk := range d.writes {
		if len(chunk) < 5 {
			t.Fatalf("chunk shorter than the HID transport header: %d bytes", len(chunk))
		}
		apdu = append(apdu, chunk[5:]...)
	}
	if len(apdu) < 7 {
		t.Fatalf("APDU too short: %d bytes", len(apdu))
	}
	if got, want := int(binary.BigEndian.Uint16(apdu)), len(apdu)-2; got != want {
		t.Fatalf("APDU length prefix mismatch: have %d, want %d", got, want)
	}
	return apdu[7:]
}

// expectedPath encodes a derivation path the way ledgerSign does.
func expectedPath(path []uint32) []byte {
	out := make([]byte, 1+4*len(path))
	out[0] = byte(len(path))
	for i, component := range path {
		binary.BigEndian.PutUint32(out[1+4*i:], component)
	}
	return out
}

func newSetCodeTx(t *testing.T, chainID *big.Int) *types.Transaction {
	t.Helper()

	auth := types.SetCodeAuthorization{
		ChainID: *uint256.NewInt(1),
		Address: common.HexToAddress("0x0000000000000000000000000000000000000020"),
		Nonce:   7,
		V:       1,
		R:       *uint256.NewInt(1),
		S:       *uint256.NewInt(2),
	}
	return types.NewTx(&types.SetCodeTx{
		ChainID:    uint256.MustFromBig(chainID),
		Nonce:      1,
		GasTipCap:  uint256.NewInt(1),
		GasFeeCap:  uint256.NewInt(2),
		Gas:        21000,
		To:         common.HexToAddress("0x0000000000000000000000000000000000000030"),
		Value:      uint256.NewInt(0),
		AccessList: types.AccessList{},
		AuthList:   []types.SetCodeAuthorization{auth},
	})
}

// TestLedgerSignSetCodeTransaction verifies that an EIP-7702 transaction is
// encoded and sent to the device. Without the SetCodeTxType branch the type fell
// through every case, txrlp stayed nil and only the derivation path reached the
// Ledger.
func TestLedgerSignSetCodeTransaction(t *testing.T) {
	chainID := big.NewInt(5151)
	tx := newSetCodeTx(t, chainID)

	device := new(recordingDevice)
	driver := &ledgerDriver{device: device, version: [3]byte{1, 17, 0}, log: log.Root()}

	path := []uint32(accounts.DefaultBaseDerivationPath)
	// The fake device fails every read on purpose, only the request matters.
	if _, _, err := driver.ledgerSign(path, tx, chainID); err == nil {
		t.Fatal("expected the fake device read to fail")
	}
	data := device.requestData(t)
	encodedPath := expectedPath(path)
	if len(data) <= len(encodedPath) {
		t.Fatalf("no transaction payload sent: have %d bytes, the derivation path alone is %d", len(data), len(encodedPath))
	}
	if !bytes.Equal(data[:len(encodedPath)], encodedPath) {
		t.Fatalf("derivation path mismatch: have %x, want %x", data[:len(encodedPath)], encodedPath)
	}
	payload := data[len(encodedPath):]
	if payload[0] != types.SetCodeTxType {
		t.Fatalf("transaction type mismatch: have %d, want %d", payload[0], types.SetCodeTxType)
	}
	var fields []rlp.RawValue
	if err := rlp.DecodeBytes(payload[1:], &fields); err != nil {
		t.Fatalf("failed to decode the transaction sent to the device: %v", err)
	}
	if want := 10; len(fields) != want {
		t.Fatalf("field count mismatch: have %d, want %d (the authorization list is missing)", len(fields), want)
	}
	var gotChainID *big.Int
	if err := rlp.DecodeBytes(fields[0], &gotChainID); err != nil {
		t.Fatalf("failed to decode the chain id: %v", err)
	}
	if gotChainID.Cmp(chainID) != 0 {
		t.Fatalf("chain id mismatch: have %v, want %v", gotChainID, chainID)
	}
}

// TestLedgerSignDynamicFeeTransaction keeps the pre-existing typed transaction
// path covered after the if/else chain was rewritten into a switch.
func TestLedgerSignDynamicFeeTransaction(t *testing.T) {
	chainID := big.NewInt(5151)
	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     1,
		GasTipCap: big.NewInt(1),
		GasFeeCap: big.NewInt(2),
		Gas:       21000,
		Value:     big.NewInt(0),
	})

	device := new(recordingDevice)
	driver := &ledgerDriver{device: device, version: [3]byte{1, 17, 0}, log: log.Root()}

	path := []uint32(accounts.DefaultBaseDerivationPath)
	if _, _, err := driver.ledgerSign(path, tx, chainID); err == nil {
		t.Fatal("expected the fake device read to fail")
	}
	data := device.requestData(t)
	encodedPath := expectedPath(path)
	if len(data) <= len(encodedPath) {
		t.Fatalf("no transaction payload sent: have %d bytes, the derivation path alone is %d", len(data), len(encodedPath))
	}
	if payload := data[len(encodedPath):]; payload[0] != types.DynamicFeeTxType {
		t.Fatalf("transaction type mismatch: have %d, want %d", payload[0], types.DynamicFeeTxType)
	}
}

// TestLedgerSignTypedTxVersionGate checks the firmware gates added for typed
// transactions: EIP-2930/EIP-1559 require app v1.9.0 and EIP-7702 requires
// v1.17.0. Older apps must fail locally instead of sending an unsupported
// transaction to the device.
func TestLedgerSignTypedTxVersionGate(t *testing.T) {
	chainID := big.NewInt(5151)
	tests := []struct {
		name    string
		version [3]byte
		tx      *types.Transaction
		want    string
	}{
		{
			name:    "access list below 1.9.0",
			version: [3]byte{1, 8, 0},
			tx: types.NewTx(&types.AccessListTx{
				ChainID:  chainID,
				GasPrice: big.NewInt(1),
				Gas:      21000,
			}),
			want: "1.9.0",
		},
		{
			name:    "dynamic fee below 1.9.0",
			version: [3]byte{1, 8, 9},
			tx: types.NewTx(&types.DynamicFeeTx{
				ChainID:   chainID,
				GasTipCap: big.NewInt(1),
				GasFeeCap: big.NewInt(2),
				Gas:       21000,
			}),
			want: "1.9.0",
		},
		{
			name:    "setcode below 1.17.0",
			version: [3]byte{1, 16, 9},
			tx:      newSetCodeTx(t, chainID),
			want:    "1.17.0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			driver := &ledgerDriver{version: tt.version, log: log.Root()}
			_, _, err := driver.SignTx(accounts.DefaultBaseDerivationPath, tt.tx, chainID)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("want an error mentioning %q, have %v", tt.want, err)
			}
		})
	}
}

// TestLedgerVersionLessThan covers both boundaries of the helper.
func TestLedgerVersionLessThan(t *testing.T) {
	tests := []struct {
		version             [3]byte
		major, minor, patch byte
		want                bool
	}{
		{[3]byte{1, 8, 9}, 1, 9, 0, true},
		{[3]byte{1, 9, 0}, 1, 9, 0, false},
		{[3]byte{1, 9, 1}, 1, 9, 0, false},
		{[3]byte{0, 9, 9}, 1, 0, 0, true},
		{[3]byte{2, 0, 0}, 1, 17, 0, false},
		{[3]byte{1, 16, 9}, 1, 17, 0, true},
	}
	for _, tt := range tests {
		if got := ledgerVersionLessThan(tt.version, tt.major, tt.minor, tt.patch); got != tt.want {
			t.Errorf("ledgerVersionLessThan(%v, %d, %d, %d) = %v, want %v", tt.version, tt.major, tt.minor, tt.patch, got, tt.want)
		}
	}
}
