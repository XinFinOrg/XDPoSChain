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
	"fmt"

	"github.com/XinFinOrg/XDPoSChain/common"
)

type GenesisSource uint8

const (
	GenesisSourceNone GenesisSource = iota
	GenesisSourceProvided
	GenesisSourceBuiltIn
	GenesisSourceStored
	GenesisSourceDefaultMainnet
	GenesisSourceDefaultMainnetReadonly
)

type DecisionError uint8

const (
	DecisionErrorNone DecisionError = iota
	DecisionErrorInvalidFacts
	DecisionErrorChainConfigNotFound
	DecisionErrorGenesisHeaderNotFound
	DecisionErrorGenesisConfigConflict
)

var (
	ErrInvalidFacts          = errors.New("invalid startup facts")
	ErrChainConfigNotFound   = errors.New("chain config not found")
	ErrGenesisHeaderNotFound = errors.New("genesis header not found")
	ErrGenesisConfigConflict = errors.New("genesis config conflict")
)

func (err DecisionError) String() string {
	switch err {
	case DecisionErrorNone:
		return "no startup decision error"
	case DecisionErrorInvalidFacts:
		return "invalid startup facts"
	case DecisionErrorChainConfigNotFound:
		return "chain config not found"
	case DecisionErrorGenesisHeaderNotFound:
		return "genesis header not found"
	case DecisionErrorGenesisConfigConflict:
		return "genesis config conflict"
	default:
		return "unknown startup decision error"
	}
}

func (err DecisionError) ToError() error {
	switch err {
	case DecisionErrorNone:
		return nil
	case DecisionErrorInvalidFacts:
		return ErrInvalidFacts
	case DecisionErrorChainConfigNotFound:
		return ErrChainConfigNotFound
	case DecisionErrorGenesisHeaderNotFound:
		return ErrGenesisHeaderNotFound
	case DecisionErrorGenesisConfigConflict:
		return ErrGenesisConfigConflict
	default:
		return fmt.Errorf("unknown startup decision error: %d", err)
	}
}

type Action struct {
	GenesisSource      GenesisSource
	AllowCommitGenesis bool
	PreferStoredConfig bool
	// PromoteOverrideMarker upgrades the historical v1 same-hash built-in
	// override storage path, which persisted only the custom chain config and no
	// explicit override marker, to the current explicit-marker schema.
	PromoteOverrideMarker bool
	TerminalError         DecisionError
}

// Decide isolates the high-level startup routing from later hydrate,
// compatibility, and persistence details. When stored genesis and stored
// config are already authoritative and no terminal or override-specific action
// is required, it returns GenesisSourceStored explicitly.
func Decide(facts Facts) Action {
	if err := facts.Validate(); err != nil {
		return Action{TerminalError: DecisionErrorInvalidFacts}
	}
	if facts.CanonicalHash == (common.Hash{}) {
		action := Action{AllowCommitGenesis: facts.Writable}
		if facts.HasProvidedGenesis {
			action.GenesisSource = GenesisSourceProvided
		} else if action.AllowCommitGenesis {
			action.GenesisSource = GenesisSourceDefaultMainnet
		} else {
			action.GenesisSource = GenesisSourceDefaultMainnetReadonly
		}
		return action
	}
	if !facts.HasGenesisHeader {
		return Action{TerminalError: DecisionErrorGenesisHeaderNotFound}
	}
	if !facts.AllowBuiltInCustomRecovery {
		if !facts.HasStoredConfig && facts.TrustedOverride {
			return Action{TerminalError: DecisionErrorGenesisConfigConflict}
		}
		if (facts.TrustedOverride || facts.LegacyStoredOverride) && facts.HasProvidedGenesis && facts.ProvidedMatchesStored && facts.ProvidedRestatesBuiltIn {
			return Action{TerminalError: DecisionErrorGenesisConfigConflict}
		}
	}
	if !facts.HasStoredConfig && facts.TrustedOverride {
		return Action{TerminalError: DecisionErrorChainConfigNotFound}
	}
	if (facts.TrustedOverride || facts.LegacyStoredOverride) && facts.HasProvidedGenesis && facts.ProvidedMatchesStored && facts.ProvidedRestatesBuiltIn {
		action := Action{GenesisSource: GenesisSourceStored, PreferStoredConfig: true}
		if facts.Writable {
			action.PromoteOverrideMarker = facts.LegacyStoredOverride
		}
		return action
	}
	return Action{GenesisSource: GenesisSourceStored}
}
