// Copyright 2026 The XDPoSChain Authors
// This file is part of the XDPoSChain library.

package vm

import (
	"errors"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/params"
)

// TestContractSizeLimits pins which limit each rule set answers with. Osaka is
// a case of its own: the fork order lets a chain schedule it with the earlier
// forks unset, so the limit cannot hang on EIP1559 and EIP158 alone.
func TestContractSizeLimits(t *testing.T) {
	tests := []struct {
		name      string
		rules     params.Rules
		codeLimit uint64
		initLimit uint64
	}{
		{
			name:      "amsterdam",
			rules:     params.Rules{IsAmsterdam: true},
			codeLimit: params.MaxCodeSizeAmsterdam,
			initLimit: params.MaxInitCodeSizeAmsterdam,
		},
		{
			name:      "osaka without the earlier forks",
			rules:     params.Rules{IsOsaka: true},
			codeLimit: params.MaxCodeSize,
			initLimit: params.MaxInitCodeSize,
		},
		{
			name:      "osaka with the earlier forks",
			rules:     params.Rules{IsEIP158: true, IsEIP1559: true, IsOsaka: true},
			codeLimit: params.MaxCodeSize,
			initLimit: params.MaxInitCodeSize,
		},
		{
			name:      "the earlier forks alone",
			rules:     params.Rules{IsEIP158: true, IsEIP1559: true},
			codeLimit: params.MaxCodeSize,
			initLimit: params.MaxInitCodeSize,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := CheckMaxCodeSize(&tt.rules, tt.codeLimit); err != nil {
				t.Errorf("code size %d should be allowed: %v", tt.codeLimit, err)
			}
			if err := CheckMaxCodeSize(&tt.rules, tt.codeLimit+1); !errors.Is(err, ErrMaxCodeSizeExceeded) {
				t.Errorf("code size %d should be rejected with %v, got %v", tt.codeLimit+1, ErrMaxCodeSizeExceeded, err)
			}
			if err := CheckMaxInitCodeSize(&tt.rules, tt.initLimit); err != nil {
				t.Errorf("initcode size %d should be allowed: %v", tt.initLimit, err)
			}
			if err := CheckMaxInitCodeSize(&tt.rules, tt.initLimit+1); !errors.Is(err, ErrMaxInitCodeSizeExceeded) {
				t.Errorf("initcode size %d should be rejected with %v, got %v", tt.initLimit+1, ErrMaxInitCodeSizeExceeded, err)
			}
		})
	}
}

// TestContractSizeLimitsUnconstrainedBeforeTheirForks checks that a rule set
// without any of the forks that carry a size limit leaves both sizes alone.
func TestContractSizeLimitsUnconstrainedBeforeTheirForks(t *testing.T) {
	rules := params.Rules{}
	if err := CheckMaxCodeSize(&rules, 1<<20); err != nil {
		t.Errorf("code size should be unconstrained without the forks that carry the limit: %v", err)
	}
	if err := CheckMaxInitCodeSize(&rules, 1<<20); err != nil {
		t.Errorf("initcode size should be unconstrained without the forks that carry the limit: %v", err)
	}
}
