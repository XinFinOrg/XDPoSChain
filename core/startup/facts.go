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
	"fmt"

	"github.com/XinFinOrg/XDPoSChain/common"
)

type Facts struct {
	CanonicalHash         common.Hash
	HasStoredConfig       bool
	HasGenesisHeader      bool
	HasProvidedGenesis    bool
	ProvidedMatchesStored bool
	TrustedOverride       bool
	// LegacyStoredOverride means the database is still on the historical v1
	// same-hash built-in override path: the custom chain config was stored under
	// the built-in genesis hash, but the explicit override marker was never
	// written.
	LegacyStoredOverride    bool
	ProvidedRestatesBuiltIn bool
	Writable                bool
	// AllowBuiltInCustomRecovery requires an explicit operator opt-in before a
	// same-hash custom override may supersede bundled built-in chain config.
	AllowBuiltInCustomRecovery bool
}

// Validate rejects internally inconsistent startup facts before routing.
func (facts Facts) Validate() error {
	if facts.CanonicalHash == (common.Hash{}) {
		if facts.HasStoredConfig || facts.HasGenesisHeader || facts.TrustedOverride || facts.LegacyStoredOverride || facts.ProvidedMatchesStored || facts.ProvidedRestatesBuiltIn {
			return fmt.Errorf("empty canonical hash cannot carry stored startup state: %w", ErrInvalidFacts)
		}
		return nil
	}
	if facts.HasStoredConfig && !facts.HasGenesisHeader {
		return fmt.Errorf("stored config requires canonical genesis header: %w", ErrInvalidFacts)
	}
	if facts.LegacyStoredOverride && !facts.HasStoredConfig {
		return fmt.Errorf("legacy stored override requires stored config: %w", ErrInvalidFacts)
	}
	if facts.ProvidedMatchesStored && !facts.HasProvidedGenesis {
		return fmt.Errorf("provided/stored match requires provided genesis: %w", ErrInvalidFacts)
	}
	if facts.ProvidedRestatesBuiltIn && !facts.HasProvidedGenesis {
		return fmt.Errorf("built-in restatement requires provided genesis: %w", ErrInvalidFacts)
	}
	if facts.ProvidedRestatesBuiltIn && !(facts.TrustedOverride || facts.LegacyStoredOverride) {
		return fmt.Errorf("built-in restatement is only meaningful for override-backed startup: %w", ErrInvalidFacts)
	}
	return nil
}

type StoredOverrideOpts struct {
	HasProvidedGenesis  bool
	OriginalGenesisHash common.Hash
	TrustedOverride     bool
	// LegacyStoredOverride carries the same historical v1 same-hash override
	// meaning as Facts.LegacyStoredOverride.
	LegacyStoredOverride       bool
	ProvidedRestatesBuiltIn    bool
	Writable                   bool
	AllowBuiltInCustomRecovery bool
}

// MissingChainConfigFacts builds startup facts for a database that already has
// a canonical genesis header but no stored chain configuration yet.
func MissingChainConfigFacts(hash common.Hash, trustedOverride, writable bool) Facts {
	return Facts{
		CanonicalHash:    hash,
		HasGenesisHeader: true,
		TrustedOverride:  trustedOverride,
		Writable:         writable,
	}
}

// StoredOverrideFacts builds startup facts for a database that already carries
// stored chain-config or override state to reconcile during startup.
func StoredOverrideFacts(hash common.Hash, opts StoredOverrideOpts) Facts {
	return Facts{
		CanonicalHash:              hash,
		HasStoredConfig:            true,
		HasGenesisHeader:           true,
		HasProvidedGenesis:         opts.HasProvidedGenesis,
		ProvidedMatchesStored:      opts.HasProvidedGenesis && opts.OriginalGenesisHash == hash,
		TrustedOverride:            opts.TrustedOverride,
		LegacyStoredOverride:       opts.LegacyStoredOverride,
		ProvidedRestatesBuiltIn:    opts.ProvidedRestatesBuiltIn,
		Writable:                   opts.Writable,
		AllowBuiltInCustomRecovery: opts.AllowBuiltInCustomRecovery,
	}
}
