package main

import (
	"strings"
	"testing"
)

func TestValidateGenesisInputAcceptsValidSeatLimits(t *testing.T) {
	input := NewGenesisInput()
	if err := validateGenesisInput(input); err != nil {
		t.Fatalf("expected valid input, got %v", err)
	}
}

func TestValidateGenesisInputRejectsNegativeSeatLimits(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*GenesisInput)
		want   string
	}{
		{
			name: "negative maxMasternodes",
			mutate: func(input *GenesisInput) {
				input.MaxMasternodes = -1
			},
			want: "maxMasternodes must be non-negative",
		},
		{
			name: "negative maxProtectorNodes",
			mutate: func(input *GenesisInput) {
				input.MaxProtectorNodes = -1
			},
			want: "maxProtectorNodes must be non-negative",
		},
		{
			name: "negative maxObserverNodes",
			mutate: func(input *GenesisInput) {
				input.MaxObserverNodes = -1
			},
			want: "maxObserverNodes must be non-negative",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := NewGenesisInput()
			tt.mutate(input)
			err := validateGenesisInput(input)
			if err == nil {
				t.Fatal("expected validation error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected error containing %q, got %v", tt.want, err)
			}
		})
	}
}
