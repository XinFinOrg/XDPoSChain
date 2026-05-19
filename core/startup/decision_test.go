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
// startup must terminate with a terminal error.
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

func assertActionEqual(t *testing.T, got, want Action) {
	t.Helper()
	if got.GenesisSource != want.GenesisSource ||
		got.AllowCommitGenesis != want.AllowCommitGenesis ||
		got.PreferStoredConfig != want.PreferStoredConfig ||
		got.PromoteOverrideMarker != want.PromoteOverrideMarker ||
		!errors.Is(got.TerminalError, want.TerminalError) {
		t.Fatalf("unexpected startup action:\n%#v\nwant:\n%#v", got, want)
	}
}

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
				TerminalError: ErrChainConfigNotFound,
			},
		},
		{
			name: "stored config without canonical genesis header is rejected as invalid facts",
			facts: Facts{
				CanonicalHash:   params.TestnetGenesisHash,
				HasStoredConfig: true,
			},
			want: Action{TerminalError: ErrInvalidFacts},
		},
		{
			name: "stored config without genesis header is rejected before routing",
			facts: Facts{
				CanonicalHash:    params.TestnetGenesisHash,
				HasStoredConfig:  true,
				HasGenesisHeader: false,
				Writable:         true,
			},
			want: Action{TerminalError: ErrInvalidFacts},
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
			want: Action{TerminalError: ErrGenesisHeaderNotFound},
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
			want: Action{TerminalError: ErrGenesisConfigConflict},
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
			assertActionEqual(t, got, test.want)
		})
	}
}

func TestDecideStoredSourceZeroValueFlagsRemainResolved(t *testing.T) {
	action := Decide(Facts{
		CanonicalHash:    params.TestnetGenesisHash,
		HasStoredConfig:  true,
		HasGenesisHeader: true,
	})
	if action.GenesisSource != GenesisSourceStored {
		t.Fatalf("unexpected startup source: have %v want %v", action.GenesisSource, GenesisSourceStored)
	}
	if action.AllowCommitGenesis {
		t.Fatal("stored source should not request genesis commit")
	}
	if action.PreferStoredConfig {
		t.Fatal("stored source happy path should not request stored-config preference override")
	}
	if action.PromoteOverrideMarker {
		t.Fatal("stored source happy path should not request override marker promotion")
	}
	if action.TerminalError != nil {
		t.Fatalf("unexpected terminal error: %v", action.TerminalError)
	}
}

func TestDecideNeverReturnsInvalidGenesisSourceForNonTerminalFacts(t *testing.T) {
	tests := []struct {
		name  string
		facts Facts
	}{
		{
			name: "provided genesis on empty writable db",
			facts: Facts{
				CanonicalHash:      common.Hash{},
				HasProvidedGenesis: true,
				Writable:           true,
			},
		},
		{
			name: "default mainnet on empty writable db",
			facts: Facts{
				CanonicalHash: common.Hash{},
				Writable:      true,
			},
		},
		{
			name: "readonly default mainnet on empty readonly db",
			facts: Facts{
				CanonicalHash: common.Hash{},
			},
		},
		{
			name: "stored config happy path",
			facts: Facts{
				CanonicalHash:    params.TestnetGenesisHash,
				HasStoredConfig:  true,
				HasGenesisHeader: true,
			},
		},
		{
			name: "stored override recovery path",
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
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			action := Decide(test.facts)
			if action.TerminalError != nil {
				t.Fatalf("unexpected terminal error: %v", action.TerminalError)
			}
			if action.GenesisSource == GenesisSourceInvalid {
				t.Fatalf("Decide returned invalid genesis source for facts %#v", test.facts)
			}
		})
	}
}

func TestMustResolveDecisionActionPanicsOnNonTerminalInvalidSource(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic for non-terminal invalid genesis source")
		}
	}()

	_ = mustResolveDecisionAction(Action{GenesisSource: GenesisSourceInvalid})
}

func TestMustResolveDecisionActionAllowsTerminalErrors(t *testing.T) {
	action := Action{TerminalError: ErrInvalidFacts}
	if got := mustResolveDecisionAction(action); got != action {
		t.Fatalf("unexpected terminal action: have %#v want %#v", got, action)
	}
}

func TestClassifyDecisionOverrideRoute(t *testing.T) {
	tests := []struct {
		name  string
		facts Facts
		want  decisionOverrideRoute
	}{
		{
			name: "trusted override without stored config and without recovery opt-in is conflict",
			facts: Facts{
				CanonicalHash:    params.TestnetGenesisHash,
				HasGenesisHeader: true,
				TrustedOverride:  true,
			},
			want: decisionOverrideRouteConflict,
		},
		{
			name: "trusted override without stored config and with recovery opt-in is missing config",
			facts: Facts{
				CanonicalHash:              params.TestnetGenesisHash,
				HasGenesisHeader:           true,
				TrustedOverride:            true,
				AllowBuiltInCustomRecovery: true,
			},
			want: decisionOverrideRouteMissingTrustedConfig,
		},
		{
			name: "stored override recovery without opt-in is conflict",
			facts: Facts{
				CanonicalHash:           params.TestnetGenesisHash,
				HasStoredConfig:         true,
				HasGenesisHeader:        true,
				HasProvidedGenesis:      true,
				ProvidedMatchesStored:   true,
				LegacyStoredOverride:    true,
				ProvidedRestatesBuiltIn: true,
			},
			want: decisionOverrideRouteConflict,
		},
		{
			name: "stored override recovery with opt-in is recovery route",
			facts: Facts{
				CanonicalHash:              params.TestnetGenesisHash,
				HasStoredConfig:            true,
				HasGenesisHeader:           true,
				HasProvidedGenesis:         true,
				ProvidedMatchesStored:      true,
				LegacyStoredOverride:       true,
				ProvidedRestatesBuiltIn:    true,
				AllowBuiltInCustomRecovery: true,
			},
			want: decisionOverrideRouteStoredRecovery,
		},
		{
			name: "plain stored startup has no override route",
			facts: Facts{
				CanonicalHash:    params.TestnetGenesisHash,
				HasStoredConfig:  true,
				HasGenesisHeader: true,
			},
			want: decisionOverrideRouteNone,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := classifyDecisionOverrideRoute(test.facts); got != test.want {
				t.Fatalf("unexpected decision override route: got %v want %v", got, test.want)
			}
		})
	}
}

func TestClassifyEmptyDecisionRoute(t *testing.T) {
	tests := []struct {
		name  string
		facts Facts
		want  emptyDecisionRoute
	}{
		{
			name: "provided genesis on empty db uses provided route",
			facts: Facts{
				CanonicalHash:      common.Hash{},
				HasProvidedGenesis: true,
			},
			want: emptyDecisionRouteProvided,
		},
		{
			name: "writable empty db uses default writable route",
			facts: Facts{
				CanonicalHash: common.Hash{},
				Writable:      true,
			},
			want: emptyDecisionRouteWritableDefault,
		},
		{
			name: "readonly empty db uses readonly default route",
			facts: Facts{
				CanonicalHash: common.Hash{},
			},
			want: emptyDecisionRouteReadonlyDefault,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := classifyEmptyDecisionRoute(test.facts); got != test.want {
				t.Fatalf("unexpected empty decision route: got %v want %v", got, test.want)
			}
		})
	}
}

func TestClassifyDecisionAction(t *testing.T) {
	tests := []struct {
		name  string
		facts Facts
		want  Action
	}{
		{
			name: "empty writable startup resolves default mainnet action",
			facts: Facts{
				CanonicalHash: common.Hash{},
				Writable:      true,
			},
			want: Action{GenesisSource: GenesisSourceDefaultMainnet, AllowCommitGenesis: true},
		},
		{
			name: "missing genesis header resolves terminal header error",
			facts: Facts{
				CanonicalHash:    params.TestnetGenesisHash,
				HasStoredConfig:  false,
				HasGenesisHeader: false,
			},
			want: Action{TerminalError: ErrGenesisHeaderNotFound},
		},
		{
			name: "trusted override without opt-in resolves conflict action",
			facts: Facts{
				CanonicalHash:           params.TestnetGenesisHash,
				HasStoredConfig:         true,
				HasGenesisHeader:        true,
				HasProvidedGenesis:      true,
				ProvidedMatchesStored:   true,
				TrustedOverride:         true,
				ProvidedRestatesBuiltIn: true,
			},
			want: Action{TerminalError: ErrGenesisConfigConflict},
		},
		{
			name: "override recovery resolves stored-preferred action",
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
			want: Action{GenesisSource: GenesisSourceStored, PreferStoredConfig: true, PromoteOverrideMarker: true},
		},
		{
			name: "trusted override without stored config and with opt-in resolves missing-config action",
			facts: Facts{
				CanonicalHash:              params.TestnetGenesisHash,
				HasGenesisHeader:           true,
				TrustedOverride:            true,
				AllowBuiltInCustomRecovery: true,
			},
			want: Action{TerminalError: ErrChainConfigNotFound},
		},
		{
			name: "plain stored startup resolves stored action",
			facts: Facts{
				CanonicalHash:    params.TestnetGenesisHash,
				HasStoredConfig:  true,
				HasGenesisHeader: true,
			},
			want: Action{GenesisSource: GenesisSourceStored},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertActionEqual(t, classifyDecisionAction(test.facts), test.want)
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

func TestClassifyFactsValidation(t *testing.T) {
	tests := []struct {
		name  string
		facts Facts
		want  factsViolation
	}{
		{
			name:  "empty canonical hash without persisted startup state is valid",
			facts: Facts{},
			want:  factsViolationNone,
		},
		{
			name: "empty canonical hash rejects stored startup state",
			facts: Facts{
				HasStoredConfig: true,
			},
			want: factsViolationEmptyCanonicalState,
		},
		{
			name: "legacy override without stored config is rejected explicitly",
			facts: Facts{
				CanonicalHash:        params.TestnetGenesisHash,
				HasGenesisHeader:     true,
				LegacyStoredOverride: true,
			},
			want: factsViolationLegacyOverrideNeedsStoredConfig,
		},
		{
			name: "built-in restatement without override backing is rejected explicitly",
			facts: Facts{
				CanonicalHash:           params.TestnetGenesisHash,
				HasGenesisHeader:        true,
				HasProvidedGenesis:      true,
				ProvidedRestatesBuiltIn: true,
			},
			want: factsViolationRestatesBuiltInNeedsOverride,
		},
		{
			name: "valid stored override facts remain valid",
			facts: StoredOverrideFacts(params.TestnetGenesisHash, StoredOverrideOpts{
				HasProvidedGenesis:      true,
				OriginalGenesisHash:     params.TestnetGenesisHash,
				TrustedOverride:         true,
				ProvidedRestatesBuiltIn: true,
			}),
			want: factsViolationNone,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := classifyFactsValidation(test.facts); got != test.want {
				t.Fatalf("unexpected facts violation: got %v want %v", got, test.want)
			}
		})
	}
}

func TestActionTerminalErrorUsesDirectErrors(t *testing.T) {
	terminalErrorField, ok := reflect.TypeOf(Action{}).FieldByName("TerminalError")
	if !ok {
		t.Fatal("TerminalError field missing from startup action")
	}
	errorType := reflect.TypeOf((*error)(nil)).Elem()
	if !terminalErrorField.Type.Implements(errorType) {
		t.Fatalf("TerminalError should be an error, have %v", terminalErrorField.Type)
	}

	action := Decide(Facts{
		CanonicalHash:    params.TestnetGenesisHash,
		HasStoredConfig:  false,
		HasGenesisHeader: false,
	})
	if !errors.Is(action.TerminalError, ErrGenesisHeaderNotFound) {
		t.Fatalf("unexpected terminal error classification: have %v want %v", action.TerminalError, ErrGenesisHeaderNotFound)
	}

	invalid := Decide(Facts{
		CanonicalHash:   params.TestnetGenesisHash,
		HasStoredConfig: true,
	})
	if !errors.Is(invalid.TerminalError, ErrInvalidFacts) {
		t.Fatalf("unexpected invalid-facts classification: have %v want %v", invalid.TerminalError, ErrInvalidFacts)
	}
}
