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

package types

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/common/hexutil"
	"github.com/holiman/uint256"
)

// JSON representation of the EIP-8141 frame transaction sub-objects,
// following the repository's Ethereum JSON-RPC conventions: camelCase field
// names, hexutil quantities for numbers, 0x-prefixed hex for byte arrays.
// These are shared by the transaction JSON codec and the RPC argument
// parsing (internal/ethapi).

type frameLimitsJSON struct {
	Execution hexutil.Uint64 `json:"execution"`
	State     hexutil.Uint64 `json:"state"`
}

type frameJSON struct {
	Mode   hexutil.Uint64  `json:"mode"`
	Flags  hexutil.Uint64  `json:"flags"`
	Target *common.Address `json:"target,omitempty"`
	Limits frameLimitsJSON `json:"limits"`
	Value  *hexutil.Big    `json:"value"`
	Data   hexutil.Bytes   `json:"data"`
	Input  hexutil.Bytes   `json:"input,omitempty"` // accepted as an alias for "data" on decode, never emitted
}

type frameSignatureJSON struct {
	Scheme    hexutil.Uint64 `json:"scheme"`
	Signer    hexutil.Bytes  `json:"signer"`
	Msg       hexutil.Bytes  `json:"msg"`
	Signature hexutil.Bytes  `json:"signature"`
}

// MarshalJSON marshals a frame using the EIP-8141 JSON field layout.
func (f Frame) MarshalJSON() ([]byte, error) {
	enc := frameJSON{
		Mode:  hexutil.Uint64(f.Mode),
		Flags: hexutil.Uint64(f.Flags),
		Limits: frameLimitsJSON{
			Execution: hexutil.Uint64(f.Limits.Execution),
			State:     hexutil.Uint64(f.Limits.State),
		},
		Data: f.Data,
	}
	if f.Target != nil {
		target := *f.Target
		enc.Target = &target
	}
	if f.Value != nil {
		enc.Value = (*hexutil.Big)(f.Value.ToBig())
	}
	return json.Marshal(&enc)
}

// UnmarshalJSON unmarshals a frame. It accepts "data" and the legacy alias
// "input" for the calldata field.
func (f *Frame) UnmarshalJSON(input []byte) error {
	var dec frameJSON
	if err := json.Unmarshal(input, &dec); err != nil {
		return err
	}
	if dec.Mode > math.MaxUint8 {
		return fmt.Errorf("frame mode %d overflows uint8", uint64(dec.Mode))
	}
	if dec.Flags > math.MaxUint8 {
		return fmt.Errorf("frame flags %d overflows uint8", uint64(dec.Flags))
	}
	f.Mode = uint8(dec.Mode)
	f.Flags = uint8(dec.Flags)
	f.Target = dec.Target
	f.Limits = FrameLimits{
		Execution: uint64(dec.Limits.Execution),
		State:     uint64(dec.Limits.State),
	}
	f.Value = uint256.NewInt(0)
	if dec.Value != nil {
		value, overflow := uint256.FromBig(dec.Value.ToInt())
		if overflow {
			return errors.New("frame value overflows uint256")
		}
		f.Value = value
	}
	switch {
	case len(dec.Data) > 0:
		f.Data = dec.Data
	case len(dec.Input) > 0:
		f.Data = dec.Input
	default:
		f.Data = []byte{}
	}
	return nil
}

// MarshalJSON marshals a frame signature entry using the EIP-8141 JSON field
// layout: scheme, signer, msg, signature.
func (s FrameSignature) MarshalJSON() ([]byte, error) {
	return json.Marshal(frameSignatureJSON{
		Scheme:    hexutil.Uint64(s.Scheme),
		Signer:    s.Signer,
		Msg:       s.Msg,
		Signature: s.Signature,
	})
}

// UnmarshalJSON unmarshals a frame signature entry.
func (s *FrameSignature) UnmarshalJSON(input []byte) error {
	var dec frameSignatureJSON
	if err := json.Unmarshal(input, &dec); err != nil {
		return err
	}
	if dec.Scheme > math.MaxUint8 {
		return fmt.Errorf("signature scheme %d overflows uint8", uint64(dec.Scheme))
	}
	s.Scheme = uint8(dec.Scheme)
	s.Signer = dec.Signer
	s.Msg = dec.Msg
	s.Signature = dec.Signature
	return nil
}
