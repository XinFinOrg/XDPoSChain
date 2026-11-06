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

package types

import (
	"bytes"
	"errors"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/rlp"
)

var (
	subnetTestAddr1 = common.HexToAddress("0x41e1d8b6ba0c50bd0d2d2a9e5ddd1d97d7bd3a3a")
	subnetTestAddr2 = common.HexToAddress("0xc168e3f6f37bb37a6e4b0d03fdbf6f3e1d1a2b3c")
	subnetTestAddr3 = common.HexToAddress("0xd11c2f9fb4b0b7e0c1a5e8c42c4a7d91a9e3b6f0")
)

func subnetTestHeader() *Header {
	return &Header{
		ParentHash:  common.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111"),
		UncleHash:   EmptyUncleHash,
		Coinbase:    subnetTestAddr2,
		Root:        common.HexToHash("0x2222222222222222222222222222222222222222222222222222222222222222"),
		TxHash:      EmptyRootHash,
		ReceiptHash: EmptyRootHash,
		Difficulty:  big.NewInt(1),
		Number:      big.NewInt(451),
		GasLimit:    420000000,
		GasUsed:     21000,
		Time:        1700000000,
		Extra:       common.FromHex("0x02f84e"),
		Validator:   common.FromHex("0xab"),
		Subnet:      true,
	}
}

// The vectors were produced by the XDC-Subnet client (XinFinOrg/XDC-Subnet
// master, core/types.Header and engine_v2 sigHash) from the same headers, so
// they pin the wire compatibility with existing subnet clients and contracts.
func TestSubnetHeaderGoldenVectors(t *testing.T) {
	headers := map[string]*Header{}
	headers["empty"] = subnetTestHeader()
	h := subnetTestHeader()
	h.Validators = PackAddresses([]common.Address{subnetTestAddr1, subnetTestAddr2, subnetTestAddr3})
	headers["epochswitch"] = h
	h = subnetTestHeader()
	h.NextValidators = PackAddresses([]common.Address{subnetTestAddr1, subnetTestAddr2, subnetTestAddr3})
	h.Penalties = PackAddresses([]common.Address{subnetTestAddr3})
	headers["gapplusone"] = h

	tests := []struct {
		name, rlp, hash, sealHash string
	}{
		{name: "empty", rlp: "f90201a01111111111111111111111111111111111111111111111111111111111111111a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794c168e3f6f37bb37a6e4b0d03fdbf6f3e1d1a2b3ca02222222222222222222222222222222222222222222222222222222222222222a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000018201c3841908b100825208846553f1008302f84ea0000000000000000000000000000000000000000000000000000000000000000088000000000000000081abc0c0c0", hash: "0x79272129711ddedac5fe011a2fd88fe693a8c094ed6595ebb597e3ebe8e3c48a", sealHash: "0xd02b8c5a4da9f8e24753c06f6467757b87f1a60dd1606d7dd419f393b60601d6"},
		{name: "epochswitch", rlp: "f90241a01111111111111111111111111111111111111111111111111111111111111111a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794c168e3f6f37bb37a6e4b0d03fdbf6f3e1d1a2b3ca02222222222222222222222222222222222222222222222222222222222222222a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000018201c3841908b100825208846553f1008302f84ea0000000000000000000000000000000000000000000000000000000000000000088000000000000000081abf83f9441e1d8b6ba0c50bd0d2d2a9e5ddd1d97d7bd3a3a94c168e3f6f37bb37a6e4b0d03fdbf6f3e1d1a2b3c94d11c2f9fb4b0b7e0c1a5e8c42c4a7d91a9e3b6f0c0c0", hash: "0x63c47afe1bc37981095adb9b604aa23c1d23f1bb8baeda583dd012742b5d0ad4", sealHash: "0xb37e0ebe60776c412ad0acdcacf5aa2cbc34eaed117bb19ca392fdaf37c31df6"},
		{name: "gapplusone", rlp: "f90256a01111111111111111111111111111111111111111111111111111111111111111a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794c168e3f6f37bb37a6e4b0d03fdbf6f3e1d1a2b3ca02222222222222222222222222222222222222222222222222222222222222222a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000018201c3841908b100825208846553f1008302f84ea0000000000000000000000000000000000000000000000000000000000000000088000000000000000081abc0f83f9441e1d8b6ba0c50bd0d2d2a9e5ddd1d97d7bd3a3a94c168e3f6f37bb37a6e4b0d03fdbf6f3e1d1a2b3c94d11c2f9fb4b0b7e0c1a5e8c42c4a7d91a9e3b6f0d594d11c2f9fb4b0b7e0c1a5e8c42c4a7d91a9e3b6f0", hash: "0xc7aa701606b36baba9f88b08e6171e64d97666f32c48aec41b30cdc5600e768d", sealHash: "0xfed071f4d0126132f87d9a27124834a7a424550ef1e8c87fd76e654a9cf6ea12"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := headers[tt.name]
			enc, err := rlp.EncodeToBytes(h)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			if want := common.FromHex(tt.rlp); !bytes.Equal(enc, want) {
				t.Fatalf("rlp mismatch\n got %x\nwant %x", enc, want)
			}
			if got := h.Hash(); got != common.HexToHash(tt.hash) {
				t.Errorf("hash mismatch: got %s want %s", got.Hex(), tt.hash)
			}
			sealHash, err := h.SubnetSealHash()
			if err != nil {
				t.Fatalf("seal hash: %v", err)
			}
			if sealHash != common.HexToHash(tt.sealHash) {
				t.Errorf("seal hash mismatch: got %s want %s", sealHash.Hex(), tt.sealHash)
			}

			var dec Header
			if err := rlp.DecodeBytes(enc, &dec); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if !dec.Subnet {
				t.Fatal("decoded header lost the subnet layout")
			}
			if dec.Hash() != h.Hash() {
				t.Fatalf("round trip hash mismatch: got %s want %s", dec.Hash().Hex(), h.Hash().Hex())
			}
			if !bytes.Equal(dec.Validators, h.Validators) || !bytes.Equal(dec.NextValidators, h.NextValidators) || !bytes.Equal(dec.Penalties, h.Penalties) {
				t.Fatal("round trip changed the address fields")
			}
		})
	}
}

// A legacy header must keep its layout, with and without a base fee, and must
// never be taken for a subnet header.
func TestLegacyHeaderLayoutUnchanged(t *testing.T) {
	for _, baseFee := range []*big.Int{nil, big.NewInt(12500000000)} {
		h := subnetTestHeader()
		h.Subnet = false
		h.Validators = PackAddresses([]common.Address{subnetTestAddr1, subnetTestAddr2})
		h.Penalties = PackAddresses([]common.Address{subnetTestAddr3})
		h.BaseFee = baseFee

		// The reference encoding is the field list of the legacy layout.
		fields := []interface{}{h.ParentHash, h.UncleHash, h.Coinbase, h.Root, h.TxHash, h.ReceiptHash, h.Bloom, h.Difficulty, h.Number, h.GasLimit, h.GasUsed, h.Time, h.Extra, h.MixDigest, h.Nonce, h.Validators, h.Validator, h.Penalties}
		if baseFee != nil {
			fields = append(fields, baseFee)
		}
		want, _ := rlp.EncodeToBytes(fields)
		got, err := rlp.EncodeToBytes(h)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("legacy layout changed (baseFee %v)\n got %x\nwant %x", baseFee, got, want)
		}
		var dec Header
		if err := rlp.DecodeBytes(got, &dec); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if dec.Subnet {
			t.Fatal("legacy header decoded as subnet")
		}
		if dec.Hash() != h.Hash() {
			t.Fatal("legacy round trip hash mismatch")
		}
	}
}

func TestSubnetHeaderRejectsInvalidFields(t *testing.T) {
	h := subnetTestHeader()
	h.BaseFee = big.NewInt(1)
	if _, err := rlp.EncodeToBytes(h); !errors.Is(err, errSubnetHeaderBaseFee) {
		t.Fatalf("want base fee error, got %v", err)
	}
	h = subnetTestHeader()
	h.Penalties = make([]byte, common.AddressLength+1)
	if _, err := rlp.EncodeToBytes(h); !errors.Is(err, errSubnetHeaderAddresses) {
		t.Fatalf("want address error, got %v", err)
	}
	// A subnet header whose address list holds a short string must not decode.
	h = subnetTestHeader()
	short := []interface{}{h.ParentHash, h.UncleHash, h.Coinbase, h.Root, h.TxHash, h.ReceiptHash, h.Bloom, h.Difficulty, h.Number, h.GasLimit, h.GasUsed, h.Time, h.Extra, h.MixDigest, h.Nonce, h.Validator, [][]byte{{0x01}}, []common.Address{}, []common.Address{}}
	bad, _ := rlp.EncodeToBytes(short)
	if subnet, err := isSubnetHeaderRLP(bad); err != nil || !subnet {
		t.Fatalf("test input is not shaped like a subnet header: %v %v", subnet, err)
	}
	var dec Header
	if err := rlp.DecodeBytes(bad, &dec); err == nil {
		t.Fatal("decoded a subnet header with a 1-byte address")
	}
}

// Copies and blocks keep the subnet layout, so the hash of a block is the hash
// of its subnet header.
func TestSubnetHeaderSurvivesCopyAndBlock(t *testing.T) {
	h := subnetTestHeader()
	h.NextValidators = PackAddresses([]common.Address{subnetTestAddr1})
	cpy := CopyHeader(h)
	if !cpy.Subnet || cpy.Hash() != h.Hash() {
		t.Fatal("CopyHeader dropped the subnet layout")
	}
	block := NewBlockWithHeader(h)
	enc, err := rlp.EncodeToBytes(block)
	if err != nil {
		t.Fatal(err)
	}
	var dec Block
	if err := rlp.DecodeBytes(enc, &dec); err != nil {
		t.Fatal(err)
	}
	if dec.Hash() != h.Hash() || !dec.Header().Subnet {
		t.Fatal("block round trip changed the subnet header")
	}
	if h.HashNoValidator() == h.Hash() {
		t.Fatal("HashNoValidator must ignore the seal")
	}
	unsealed := CopyHeader(h)
	unsealed.Validator = nil
	if unsealed.HashNoValidator() != h.HashNoValidator() {
		t.Fatal("HashNoValidator depends on the seal")
	}
}
