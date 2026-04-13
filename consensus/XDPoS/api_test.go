package XDPoS

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/utils"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/stretchr/testify/assert"
)

func TestCalculateSignersVote(t *testing.T) {
	info := make(map[string]SignerTypes)
	votes := utils.NewPool()
	masternodes := []common.Address{{1}, {2}, {3}}

	vote1 := types.Vote{
		Signature: types.Signature{1},
		ProposedBlockInfo: &types.BlockInfo{
			Hash:   common.Hash{1},
			Round:  types.Round(10),
			Number: big.NewInt(910),
		},
		GapNumber: 450,
	}
	vote1.SetSigner(common.Address{1})

	vote2 := types.Vote{
		Signature: types.Signature{2},
		ProposedBlockInfo: &types.BlockInfo{
			Hash:   common.Hash{1},
			Round:  types.Round(10),
			Number: big.NewInt(910),
		},
		GapNumber: 450,
	}
	vote2.SetSigner(common.Address{2})

	votes.Add(&vote1)
	votes.Add(&vote2)

	calculateSigners(info, votes.Get(), masternodes)
	assert.Equal(t, info["10:450:910:0x0100000000000000000000000000000000000000000000000000000000000000"].CurrentNumber, 2)
}

func TestCalculateSignersTimeout(t *testing.T) {
	info := make(map[string]SignerTypes)
	timeouts := utils.NewPool()
	masternodes := []common.Address{{1}, {2}, {3}}

	timeout1 := types.Timeout{
		Signature: types.Signature{1},
		Round:     types.Round(10),
		GapNumber: 450,
	}
	timeout1.SetSigner(common.Address{1})

	timeout2 := types.Timeout{
		Signature: types.Signature{2},
		Round:     types.Round(10),
		GapNumber: 450,
	}
	timeout1.SetSigner(common.Address{2})

	timeouts.Add(&timeout1)
	timeouts.Add(&timeout2)

	calculateSigners(info, timeouts.Get(), masternodes)
	assert.Equal(t, info["10:450"].CurrentNumber, 2)
}

func TestJsonNumberToBigInt(t *testing.T) {
	tests := []struct {
		name   string
		input  json.Number
		want   *big.Int
		wantOk bool
	}{
		{
			name:   "plain decimal integer",
			input:  json.Number("4500000000000000000000"),
			want:   new(big.Int).Mul(big.NewInt(45), new(big.Int).Exp(big.NewInt(10), big.NewInt(20), nil)),
			wantOk: true,
		},
		{
			name:   "scientific notation 4.5e+21",
			input:  json.Number("4.5e+21"),
			want:   new(big.Int).Mul(big.NewInt(45), new(big.Int).Exp(big.NewInt(10), big.NewInt(20), nil)),
			wantOk: true,
		},
		{
			name:   "scientific notation 1e+18",
			input:  json.Number("1e+18"),
			want:   new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil),
			wantOk: true,
		},
		{
			name:   "scientific notation uppercase E",
			input:  json.Number("4.5E+21"),
			want:   new(big.Int).Mul(big.NewInt(45), new(big.Int).Exp(big.NewInt(10), big.NewInt(20), nil)),
			wantOk: true,
		},
		{
			name:   "zero",
			input:  json.Number("0"),
			want:   big.NewInt(0),
			wantOk: true,
		},
		{
			name:   "small integer",
			input:  json.Number("12345"),
			want:   big.NewInt(12345),
			wantOk: true,
		},
		{
			name:   "fractional value truncates",
			input:  json.Number("1.23e+1"),
			want:   big.NewInt(12),
			wantOk: true,
		},
		{
			name:   "decimal without exponent",
			input:  json.Number("123.456"),
			want:   big.NewInt(123),
			wantOk: true,
		},
		{
			name:   "decimal whole number",
			input:  json.Number("1000.0"),
			want:   big.NewInt(1000),
			wantOk: true,
		},
		{
			name:   "negative integer",
			input:  json.Number("-500"),
			want:   big.NewInt(-500),
			wantOk: true,
		},
		{
			name:   "invalid string",
			input:  json.Number("not_a_number"),
			want:   nil,
			wantOk: false,
		},
		{
			name:   "empty string",
			input:  json.Number(""),
			want:   nil,
			wantOk: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := jsonNumberToBigInt(tt.input)
			if tt.wantOk {
				assert.True(t, ok, "input %q: parse failed, expected %s", tt.input, tt.want)
				assert.Equal(t, 0, tt.want.Cmp(got), "input %q: expected %s but got %s", tt.input, tt.want, got)
			} else {
				assert.False(t, ok, "input %q: expected parse failure but got %s", tt.input, got)
				assert.Nil(t, got, "input %q: expected nil but got %s", tt.input, got)
			}
		})
	}
}
