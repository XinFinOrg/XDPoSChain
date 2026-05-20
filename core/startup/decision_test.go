// Package startup isolates the first startup routing step that decides which
// genesis view drives initialization and whether startup must stop before later
// hydrate, compatibility, or persistence work begins.
//
// The package contract is Facts -> Decision:
//
// Facts is a normalized summary of startup evidence collected outside this
// package, such as whether the database already has a canonical genesis header,
// whether chain configuration or override metadata exists, whether a caller
// supplied a genesis, and whether the current startup is writable.
//
// Decide is a pure routing function. Given the same Facts it always returns the
// same Action, without reading storage, mutating state, or hydrating configs.
// That Action tells the caller which genesis source is authoritative for this
// startup, whether committing genesis is allowed, whether stored configuration
// should be preferred, whether the historical v1 same-hash built-in override
// path should be promoted to the explicit override marker schema, or whether
// startup must terminate with a DecisionError.
//
// This separation keeps the critical "which genesis drives startup + recovery
// policy" choice explicit and testable. Callers remain responsible for
// gathering evidence into Facts and for executing the returned Action.

package startup

import (
	"errors"
	"reflect"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/params"
)

func TestDecide(t *testing.T) {
	tests := []struct {
		name  string
		facts Facts
		want  Action
	}{
		{
			name: "empty db without provided genesis writes default genesis",
			facts: Facts{
				CanonicalHash: common.Hash{},
				Writable:      true,
			},
			want: Action{
				GenesisSource:      GenesisSourceDefaultMainnet,
				AllowCommitGenesis: true,
			},
		},
		{
			name: "empty db with zero-value mode resolves readonly default mainnet without allowing genesis commit",
			facts: Facts{
				CanonicalHash: common.Hash{},
			},
			want: Action{
				GenesisSource:      GenesisSourceDefaultMainnetReadonly,
				AllowCommitGenesis: false,
			},
		},
		{
			name: "missing config with trusted override returns explicit chain-config-missing error",
			facts: Facts{
				CanonicalHash:              params.TestnetGenesisHash,
				HasStoredConfig:            false,
				HasGenesisHeader:           true,
				TrustedOverride:            true,
				Writable:                   true,
				AllowBuiltInCustomRecovery: true,
			},
			want: Action{
				TerminalError: DecisionErrorChainConfigNotFound,
			},
		},
		{
			name: "stored config without canonical genesis header is rejected as invalid facts",
			facts: Facts{
				CanonicalHash:   params.TestnetGenesisHash,
				HasStoredConfig: true,
			},
			want: Action{TerminalError: DecisionErrorInvalidFacts},
		},
		{
			name: "stored config without genesis header is rejected before routing",
			facts: Facts{
				CanonicalHash:    params.TestnetGenesisHash,
				HasStoredConfig:  true,
				HasGenesisHeader: false,
				Writable:         true,
			},
			want: Action{TerminalError: DecisionErrorInvalidFacts},
		},
		{
			name: "missing config without genesis header fails explicitly",
			facts: Facts{
				CanonicalHash:    params.TestnetGenesisHash,
				HasStoredConfig:  false,
				HasGenesisHeader: false,
				TrustedOverride:  true,
				Writable:         true,
			},
			want: Action{TerminalError: DecisionErrorGenesisHeaderNotFound},
		},
		{
			name: "stored config happy path returns explicit stored source",
			facts: Facts{
				CanonicalHash:    params.TestnetGenesisHash,
				HasStoredConfig:  true,
				HasGenesisHeader: true,
				Writable:         true,
			},
			want: Action{GenesisSource: GenesisSourceStored},
		},
		{
			name: "legacy override with matching provided genesis prefers stored config and promotes marker on writable startup",
			facts: Facts{
				CanonicalHash:              params.TestnetGenesisHash,
				HasStoredConfig:            true,
				HasGenesisHeader:           true,
				HasProvidedGenesis:         true,
				ProvidedMatchesStored:      true,
				LegacyStoredOverride:       true,
				ProvidedRestatesBuiltIn:    true,
				Writable:                   true,
				AllowBuiltInCustomRecovery: true,
			},
			want: Action{
				GenesisSource:         GenesisSourceStored,
				PreferStoredConfig:    true,
				PromoteOverrideMarker: true,
			},
		},
		{
			name: "trusted override with bundled provided genesis prefers stored config without migration",
			facts: Facts{
				CanonicalHash:              params.TestnetGenesisHash,
				HasStoredConfig:            true,
				HasGenesisHeader:           true,
				HasProvidedGenesis:         true,
				ProvidedMatchesStored:      true,
				TrustedOverride:            true,
				ProvidedRestatesBuiltIn:    true,
				Writable:                   true,
				AllowBuiltInCustomRecovery: true,
			},
			want: Action{GenesisSource: GenesisSourceStored, PreferStoredConfig: true},
		},
		{
			name: "readonly startup prefers stored config without promoting legacy override marker",
			facts: Facts{
				CanonicalHash:              params.TestnetGenesisHash,
				HasStoredConfig:            true,
				HasGenesisHeader:           true,
				HasProvidedGenesis:         true,
				ProvidedMatchesStored:      true,
				LegacyStoredOverride:       true,
				ProvidedRestatesBuiltIn:    true,
				Writable:                   false,
				AllowBuiltInCustomRecovery: true,
			},
			want: Action{GenesisSource: GenesisSourceStored, PreferStoredConfig: true, PromoteOverrideMarker: false},
		},
		{
			name: "trusted override without explicit recovery permission is rejected",
			facts: Facts{
				CanonicalHash:              params.TestnetGenesisHash,
				HasStoredConfig:            true,
				HasGenesisHeader:           true,
				HasProvidedGenesis:         true,
				ProvidedMatchesStored:      true,
				TrustedOverride:            true,
				ProvidedRestatesBuiltIn:    true,
				Writable:                   true,
				AllowBuiltInCustomRecovery: false,
			},
			want: Action{TerminalError: DecisionErrorGenesisConfigConflict},
		},
		{
			name: "trusted override with explicit recovery permission prefers stored config",
			facts: Facts{
				CanonicalHash:              params.TestnetGenesisHash,
				HasStoredConfig:            true,
				HasGenesisHeader:           true,
				HasProvidedGenesis:         true,
				ProvidedMatchesStored:      true,
				TrustedOverride:            true,
				ProvidedRestatesBuiltIn:    true,
				Writable:                   true,
				AllowBuiltInCustomRecovery: true,
			},
			want: Action{GenesisSource: GenesisSourceStored, PreferStoredConfig: true},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := Decide(test.facts)
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("unexpected startup action:\n%#v\nwant:\n%#v", got, test.want)
			}
		})
	}
}

func TestMissingChainConfigFacts(t *testing.T) {
	tests := []struct {
		name     string
		hash     common.Hash
		override bool
		writable bool
		want     Facts
	}{
		{
			name:     "writable startup keeps writable flag",
			hash:     params.TestnetGenesisHash,
			override: true,
			writable: true,
			want: Facts{
				CanonicalHash:    params.TestnetGenesisHash,
				HasGenesisHeader: true,
				TrustedOverride:  true,
				Writable:         true,
			},
		},
		{
			name:     "readonly startup flips readonly flag",
			hash:     params.TestnetGenesisHash,
			override: true,
			writable: false,
			want: Facts{
				CanonicalHash:    params.TestnetGenesisHash,
				HasGenesisHeader: true,
				TrustedOverride:  true,
				Writable:         false,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := MissingChainConfigFacts(test.hash, test.override, test.writable)
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("unexpected startup facts:\n%#v\nwant:\n%#v", got, test.want)
			}
		})
	}
}

func TestStoredOverrideFacts(t *testing.T) {
	got := StoredOverrideFacts(params.TestnetGenesisHash, StoredOverrideOpts{
		HasProvidedGenesis:      true,
		OriginalGenesisHash:     params.TestnetGenesisHash,
		TrustedOverride:         true,
		LegacyStoredOverride:    false,
		ProvidedRestatesBuiltIn: true,
		Writable:                false,
	})
	want := Facts{
		CanonicalHash:           params.TestnetGenesisHash,
		HasStoredConfig:         true,
		HasGenesisHeader:        true,
		HasProvidedGenesis:      true,
		ProvidedMatchesStored:   true,
		TrustedOverride:         true,
		ProvidedRestatesBuiltIn: true,
		Writable:                false,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected startup facts:\n%#v\nwant:\n%#v", got, want)
	}

	got = StoredOverrideFacts(params.TestnetGenesisHash, StoredOverrideOpts{
		HasProvidedGenesis:      true,
		OriginalGenesisHash:     common.Hash{},
		TrustedOverride:         false,
		LegacyStoredOverride:    true,
		ProvidedRestatesBuiltIn: true,
		Writable:                true,
	})
	want = Facts{
		CanonicalHash:           params.TestnetGenesisHash,
		HasStoredConfig:         true,
		HasGenesisHeader:        true,
		HasProvidedGenesis:      true,
		ProvidedMatchesStored:   false,
		LegacyStoredOverride:    true,
		ProvidedRestatesBuiltIn: true,
		Writable:                true,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected startup facts for writable path:\n%#v\nwant:\n%#v", got, want)
	}
}

func TestFactsValidate(t *testing.T) {
	tests := []struct {
		name  string
		facts Facts
		want  error
	}{
		{
			name: "stored config requires genesis header",
			facts: Facts{
				CanonicalHash:   params.TestnetGenesisHash,
				HasStoredConfig: true,
			},
			want: ErrInvalidFacts,
		},
		{
			name: "provided matches stored requires provided genesis",
			facts: Facts{
				CanonicalHash:         params.TestnetGenesisHash,
				HasGenesisHeader:      true,
				ProvidedMatchesStored: true,
			},
			want: ErrInvalidFacts,
		},
		{
			name: "stored override facts builder remains valid",
			facts: StoredOverrideFacts(params.TestnetGenesisHash, StoredOverrideOpts{
				HasProvidedGenesis:      true,
				OriginalGenesisHash:     params.TestnetGenesisHash,
				TrustedOverride:         true,
				ProvidedRestatesBuiltIn: true,
				Writable:                true,
			}),
			want: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.facts.Validate()
			if !errors.Is(err, test.want) {
				t.Fatalf("unexpected validation result: have %v want %v", err, test.want)
			}
		})
	}
}

func TestDecisionErrorStringAndToError(t *testing.T) {
	if got := DecisionErrorInvalidFacts.String(); got != "invalid startup facts" {
		t.Fatalf("unexpected invalid-facts string form: %q", got)
	}

	if got := DecisionErrorGenesisHeaderNotFound.String(); got != "genesis header not found" {
		t.Fatalf("unexpected string form: %q", got)
	}

	if err := DecisionErrorNone.ToError(); err != nil {
		t.Fatalf("expected nil error for none decision, have %v", err)
	}

	err := DecisionErrorGenesisHeaderNotFound.ToError()
	if !errors.Is(err, ErrGenesisHeaderNotFound) {
		t.Fatalf("unexpected error classification: have %v want %v", err, ErrGenesisHeaderNotFound)
	}
	if got := err.Error(); got != "genesis header not found" {
		t.Fatalf("unexpected error form: %q", got)
	}

	err = DecisionErrorInvalidFacts.ToError()
	if !errors.Is(err, ErrInvalidFacts) {
		t.Fatalf("unexpected invalid-facts classification: have %v want %v", err, ErrInvalidFacts)
	}
}
