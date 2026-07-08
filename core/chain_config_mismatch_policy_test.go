package core

import (
	"strings"
	"testing"
)

func TestNormalizeChainConfigMismatchPolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input ChainConfigMismatchPolicy
		want  ChainConfigMismatchPolicy
	}{
		{
			name:  "empty defaults to exit",
			input: "",
			want:  DefaultChainConfigMismatchPolicy,
		},
		{
			name:  "non-empty preserved",
			input: MismatchIgnoreMismatch,
			want:  MismatchIgnoreMismatch,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := NormalizeChainConfigMismatchPolicy(tt.input)
			if got != tt.want {
				t.Fatalf("unexpected normalized policy: have %q want %q", got, tt.want)
			}
		})
	}
}

func TestParseChainConfigMismatchPolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		input     string
		want      ChainConfigMismatchPolicy
		wantError bool
	}{
		{
			name:  "empty defaults to exit",
			input: "",
			want:  DefaultChainConfigMismatchPolicy,
		},
		{
			name:  "whitespace defaults to exit",
			input: "   \t\n",
			want:  DefaultChainConfigMismatchPolicy,
		},
		{
			name:  "trimmed rewind-and-update",
			input: "  rewind-and-update  ",
			want:  MismatchRewindAndUpdate,
		},
		{
			name:  "exit",
			input: "exit",
			want:  MismatchExit,
		},
		{
			name:  "update-config-only",
			input: "update-config-only",
			want:  MismatchUpdateConfigOnly,
		},
		{
			name:  "ignore-mismatch",
			input: "ignore-mismatch",
			want:  MismatchIgnoreMismatch,
		},
		{
			name:      "invalid value",
			input:     "invalid",
			wantError: true,
		},
		{
			name:      "invalid mixed case",
			input:     "Continue",
			wantError: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseChainConfigMismatchPolicy(tt.input)
			if tt.wantError {
				if err == nil {
					t.Fatalf("expected error for input %q", tt.input)
				}
				if !strings.Contains(err.Error(), "invalid chain config mismatch policy") {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("unexpected parsed policy: have %q want %q", got, tt.want)
			}
		})
	}
}
