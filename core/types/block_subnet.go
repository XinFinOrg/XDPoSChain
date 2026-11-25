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
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/rlp"
)

// A header has one of two RLP layouts. Both share the first 15 fields
// (parentHash ... nonce) and differ in the XDPoS fields that follow:
//
//	legacy: validators(bytes), validator(bytes), penalties(bytes), [baseFee]
//	subnet: validator(bytes), validators([]address), nextValidators([]address), penalties([]address)
//
// The subnet layout is the one of the XDC subnet clients (the Go XDC-Subnet
// client and Nethermind's XDPoSSubnet engine) and the one the subnet checkpoint
// contracts parse, so it has to be reproduced byte for byte. In memory both
// layouts keep the address fields packed as 20-byte runs; only the wire form
// differs. Header.Subnet selects the layout on encoding, and decoding infers it
// from the 17th item, which is a byte string in the legacy layout and a list in
// the subnet layout.

// subnetHeaderFields is the number of items in a subnet header.
const subnetHeaderFields = 19

// subnetValidatorsIndex is the position of the validators list in a subnet
// header; the same position holds the validator seal (a string) in the legacy
// layout.
const subnetValidatorsIndex = 16

var (
	errSubnetHeaderBaseFee   = errors.New("subnet header cannot carry a base fee")
	errSubnetHeaderAddresses = errors.New("subnet header address field is not a whole number of addresses")
)

// legacyHeader has the fields and RLP layout of Header without its methods, so
// encoding it uses the reflection codec. The fields tagged rlp:"-" are skipped.
type legacyHeader Header

// subnetHeaderRLP is the RLP layout of a subnet header.
type subnetHeaderRLP struct {
	ParentHash     common.Hash
	UncleHash      common.Hash
	Coinbase       common.Address
	Root           common.Hash
	TxHash         common.Hash
	ReceiptHash    common.Hash
	Bloom          Bloom
	Difficulty     *big.Int
	Number         *big.Int
	GasLimit       uint64
	GasUsed        uint64
	Time           uint64
	Extra          []byte
	MixDigest      common.Hash
	Nonce          BlockNonce
	Validator      []byte
	Validators     []common.Address
	NextValidators []common.Address
	Penalties      []common.Address
}

// EncodeRLP implements rlp.Encoder.
func (h *Header) EncodeRLP(w io.Writer) error {
	if !h.Subnet {
		return rlp.Encode(w, (*legacyHeader)(h))
	}
	enc, err := h.subnetRLP()
	if err != nil {
		return err
	}
	return rlp.Encode(w, enc)
}

// DecodeRLP implements rlp.Decoder.
func (h *Header) DecodeRLP(s *rlp.Stream) error {
	raw, err := s.Raw()
	if err != nil {
		return err
	}
	subnet, err := isSubnetHeaderRLP(raw)
	if err != nil {
		return err
	}
	if !subnet {
		var dec legacyHeader
		if err := rlp.DecodeBytes(raw, &dec); err != nil {
			return err
		}
		*h = Header(dec)
		return nil
	}
	var dec subnetHeaderRLP
	if err := rlp.DecodeBytes(raw, &dec); err != nil {
		return err
	}
	*h = Header{
		ParentHash:     dec.ParentHash,
		UncleHash:      dec.UncleHash,
		Coinbase:       dec.Coinbase,
		Root:           dec.Root,
		TxHash:         dec.TxHash,
		ReceiptHash:    dec.ReceiptHash,
		Bloom:          dec.Bloom,
		Difficulty:     dec.Difficulty,
		Number:         dec.Number,
		GasLimit:       dec.GasLimit,
		GasUsed:        dec.GasUsed,
		Time:           dec.Time,
		Extra:          dec.Extra,
		MixDigest:      dec.MixDigest,
		Nonce:          dec.Nonce,
		Validator:      dec.Validator,
		Validators:     PackAddresses(dec.Validators),
		NextValidators: PackAddresses(dec.NextValidators),
		Penalties:      PackAddresses(dec.Penalties),
		Subnet:         true,
	}
	return nil
}

// subnetRLP converts the header to its subnet wire form.
func (h *Header) subnetRLP() (*subnetHeaderRLP, error) {
	if h.BaseFee != nil {
		return nil, errSubnetHeaderBaseFee
	}
	validators, err := unpackAddresses(h.Validators)
	if err != nil {
		return nil, fmt.Errorf("validators: %w", err)
	}
	nextValidators, err := unpackAddresses(h.NextValidators)
	if err != nil {
		return nil, fmt.Errorf("nextValidators: %w", err)
	}
	penalties, err := unpackAddresses(h.Penalties)
	if err != nil {
		return nil, fmt.Errorf("penalties: %w", err)
	}
	return &subnetHeaderRLP{
		ParentHash:     h.ParentHash,
		UncleHash:      h.UncleHash,
		Coinbase:       h.Coinbase,
		Root:           h.Root,
		TxHash:         h.TxHash,
		ReceiptHash:    h.ReceiptHash,
		Bloom:          h.Bloom,
		Difficulty:     h.Difficulty,
		Number:         h.Number,
		GasLimit:       h.GasLimit,
		GasUsed:        h.GasUsed,
		Time:           h.Time,
		Extra:          h.Extra,
		MixDigest:      h.MixDigest,
		Nonce:          h.Nonce,
		Validator:      h.Validator,
		Validators:     validators,
		NextValidators: nextValidators,
		Penalties:      penalties,
	}, nil
}

// SubnetSealHash returns the hash a subnet block producer signs: the keccak256
// of the subnet header without its validator seal and without nextValidators,
// i.e. rlp([parentHash ... nonce, validators([]address), penalties([]address)]).
func (h *Header) SubnetSealHash() (common.Hash, error) {
	enc, err := h.subnetRLP()
	if err != nil {
		return common.Hash{}, err
	}
	return rlpHash([]interface{}{
		enc.ParentHash,
		enc.UncleHash,
		enc.Coinbase,
		enc.Root,
		enc.TxHash,
		enc.ReceiptHash,
		enc.Bloom,
		enc.Difficulty,
		enc.Number,
		enc.GasLimit,
		enc.GasUsed,
		enc.Time,
		enc.Extra,
		enc.MixDigest,
		enc.Nonce,
		enc.Validators,
		enc.Penalties,
	}), nil
}

// isSubnetHeaderRLP reports whether raw, an RLP encoded header, uses the subnet
// layout: exactly 19 items with a list at position 16.
func isSubnetHeaderRLP(raw []byte) (bool, error) {
	content, _, err := rlp.SplitList(raw)
	if err != nil {
		return false, err
	}
	var kind rlp.Kind
	items := 0
	for len(content) > 0 {
		var k rlp.Kind
		k, _, content, err = rlp.Split(content)
		if err != nil {
			return false, err
		}
		if items == subnetValidatorsIndex {
			kind = k
		}
		items++
	}
	return items == subnetHeaderFields && kind == rlp.List, nil
}

// PackAddresses concatenates addresses into the packed form headers keep them
// in. It returns nil for an empty list.
func PackAddresses(addrs []common.Address) []byte {
	if len(addrs) == 0 {
		return nil
	}
	packed := make([]byte, 0, len(addrs)*common.AddressLength)
	for _, addr := range addrs {
		packed = append(packed, addr[:]...)
	}
	return packed
}

// unpackAddresses splits packed addresses, rejecting a trailing partial one.
func unpackAddresses(packed []byte) ([]common.Address, error) {
	if len(packed)%common.AddressLength != 0 {
		return nil, errSubnetHeaderAddresses
	}
	return common.ExtractAddressFromBytes(packed), nil
}
