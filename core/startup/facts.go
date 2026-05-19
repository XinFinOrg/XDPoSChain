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

type factsViolation uint8

const (
	factsViolationNone factsViolation = iota
	factsViolationEmptyCanonicalState
	factsViolationStoredConfigNeedsGenesisHeader
	factsViolationLegacyOverrideNeedsStoredConfig
	factsViolationProvidedMatchNeedsProvidedGenesis
	factsViolationRestatesBuiltInNeedsProvidedGenesis
	factsViolationRestatesBuiltInNeedsOverride
)

func classifyFactsValidation(facts Facts) factsViolation {
	if facts.CanonicalHash == (common.Hash{}) {
		if !facts.HasStoredConfig && !facts.HasGenesisHeader && !facts.TrustedOverride &&
			!facts.LegacyStoredOverride && !facts.ProvidedMatchesStored && !facts.ProvidedRestatesBuiltIn {
			return factsViolationNone
		}
		return factsViolationEmptyCanonicalState
	}

	hasOverrideBacking := facts.TrustedOverride || facts.LegacyStoredOverride

	switch {
	case facts.HasStoredConfig && !facts.HasGenesisHeader:
		return factsViolationStoredConfigNeedsGenesisHeader
	case facts.LegacyStoredOverride && !facts.HasStoredConfig:
		return factsViolationLegacyOverrideNeedsStoredConfig
	case facts.ProvidedMatchesStored && !facts.HasProvidedGenesis:
		return factsViolationProvidedMatchNeedsProvidedGenesis
	case facts.ProvidedRestatesBuiltIn && !facts.HasProvidedGenesis:
		return factsViolationRestatesBuiltInNeedsProvidedGenesis
	case facts.ProvidedRestatesBuiltIn && !hasOverrideBacking:
		return factsViolationRestatesBuiltInNeedsOverride
	default:
		return factsViolationNone
	}
}

// Validate rejects internally inconsistent startup facts before routing.
func (facts Facts) Validate() error {
	violation := classifyFactsValidation(facts)
	switch violation {
	case factsViolationNone:
		return nil
	case factsViolationEmptyCanonicalState:
		return fmt.Errorf("empty canonical hash cannot carry stored startup state: %w", ErrInvalidFacts)
	case factsViolationStoredConfigNeedsGenesisHeader:
		return fmt.Errorf("stored config requires canonical genesis header: %w", ErrInvalidFacts)
	case factsViolationLegacyOverrideNeedsStoredConfig:
		return fmt.Errorf("legacy stored override requires stored config: %w", ErrInvalidFacts)
	case factsViolationProvidedMatchNeedsProvidedGenesis:
		return fmt.Errorf("provided/stored match requires provided genesis: %w", ErrInvalidFacts)
	case factsViolationRestatesBuiltInNeedsProvidedGenesis:
		return fmt.Errorf("built-in restatement requires provided genesis: %w", ErrInvalidFacts)
	case factsViolationRestatesBuiltInNeedsOverride:
		return fmt.Errorf("built-in restatement is only meaningful for override-backed startup: %w", ErrInvalidFacts)
	default:
		return fmt.Errorf("unknown startup facts validation violation %d: %w", violation, ErrInvalidFacts)
	}
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
