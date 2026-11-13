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

package ethapi

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/common/hexutil"
	"github.com/XinFinOrg/XDPoSChain/core/types"
)

// Subnet headers report their address fields as address lists, empty ones as
// [], and add nextValidators; legacy headers keep the packed hex form.
func TestRPCMarshalSubnetHeader(t *testing.T) {
	a, b := common.HexToAddress("0x01"), common.HexToAddress("0x02")
	header := &types.Header{
		Number:         big.NewInt(451),
		Difficulty:     big.NewInt(1),
		NextValidators: types.PackAddresses([]common.Address{a, b}),
		Penalties:      types.PackAddresses([]common.Address{b}),
		Subnet:         true,
	}
	fields := RPCMarshalHeader(header)
	blob, err := json.Marshal(map[string]interface{}{
		"validators":     fields["validators"],
		"nextValidators": fields["nextValidators"],
		"penalties":      fields["penalties"],
	})
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Validators     []common.Address `json:"validators"`
		NextValidators []common.Address `json:"nextValidators"`
		Penalties      []common.Address `json:"penalties"`
	}
	if err := json.Unmarshal(blob, &got); err != nil {
		t.Fatalf("subnet fields are not address lists: %s: %v", blob, err)
	}
	if got.Validators == nil || len(got.Validators) != 0 || len(got.NextValidators) != 2 || got.NextValidators[1] != b || len(got.Penalties) != 1 || got.Penalties[0] != b {
		t.Fatalf("unexpected subnet fields %s", blob)
	}
	if fields["hash"] != header.Hash() {
		t.Fatal("hash is not the subnet header hash")
	}

	header.Subnet = false
	legacy := RPCMarshalHeader(header)
	if _, ok := legacy["nextValidators"]; ok {
		t.Fatal("legacy header reports nextValidators")
	}
	if _, ok := legacy["penalties"].(hexutil.Bytes); !ok {
		t.Fatalf("legacy penalties are not packed bytes: %T", legacy["penalties"])
	}
}
