package startup

import (
	"errors"

	"github.com/XinFinOrg/XDPoSChain/common"
)

type GenesisSource uint8

const (
	GenesisSourceInvalid GenesisSource = iota
	GenesisSourceProvided
	GenesisSourceBuiltIn
	GenesisSourceStored
	GenesisSourceDefaultMainnet
	GenesisSourceDefaultMainnetReadonly
)

var (
	ErrInvalidFacts          = errors.New("invalid startup facts")
	ErrChainConfigNotFound   = errors.New("chain config not found")
	ErrGenesisHeaderNotFound = errors.New("genesis header not found")
	ErrGenesisConfigConflict = errors.New("genesis config conflict")
)

type Action struct {
	// GenesisSource carries the routing decision. The zero value is invalid and
	// must never escape Decide as a non-terminal outcome. In particular,
	// GenesisSourceStored with the remaining fields left at their zero values is
	// a valid terminal outcome meaning startup should use stored genesis/config
	// as-is and perform no extra recovery work; it is not an "undecided"
	// sentinel.
	GenesisSource      GenesisSource
	AllowCommitGenesis bool
	PreferStoredConfig bool
	// PromoteOverrideMarker upgrades the historical v1 same-hash built-in
	// override storage path, which persisted only the custom chain config and no
	// explicit override marker, to the current explicit-marker schema.
	PromoteOverrideMarker bool
	TerminalError         error
}

type emptyDecisionRoute uint8

const (
	emptyDecisionRouteProvided emptyDecisionRoute = iota
	emptyDecisionRouteWritableDefault
	emptyDecisionRouteReadonlyDefault
)

type decisionOverrideRoute uint8

const (
	decisionOverrideRouteNone decisionOverrideRoute = iota
	decisionOverrideRouteConflict
	decisionOverrideRouteMissingTrustedConfig
	decisionOverrideRouteStoredRecovery
)

func hasStoredOverrideRecovery(facts Facts) bool {
	return (facts.TrustedOverride || facts.LegacyStoredOverride) && facts.HasProvidedGenesis && facts.ProvidedMatchesStored && facts.ProvidedRestatesBuiltIn
}

func classifyEmptyDecisionRoute(facts Facts) emptyDecisionRoute {
	switch {
	case facts.HasProvidedGenesis:
		return emptyDecisionRouteProvided
	case facts.Writable:
		return emptyDecisionRouteWritableDefault
	default:
		return emptyDecisionRouteReadonlyDefault
	}
}

func classifyDecisionAction(facts Facts) Action {
	if facts.CanonicalHash == (common.Hash{}) {
		switch classifyEmptyDecisionRoute(facts) {
		case emptyDecisionRouteProvided:
			return Action{GenesisSource: GenesisSourceProvided, AllowCommitGenesis: facts.Writable}
		case emptyDecisionRouteWritableDefault:
			return Action{GenesisSource: GenesisSourceDefaultMainnet, AllowCommitGenesis: true}
		default:
			return Action{GenesisSource: GenesisSourceDefaultMainnetReadonly}
		}
	}

	if !facts.HasGenesisHeader {
		return Action{TerminalError: ErrGenesisHeaderNotFound}
	}

	switch classifyDecisionOverrideRoute(facts) {
	case decisionOverrideRouteConflict:
		return Action{TerminalError: ErrGenesisConfigConflict}
	case decisionOverrideRouteMissingTrustedConfig:
		return Action{TerminalError: ErrChainConfigNotFound}
	case decisionOverrideRouteStoredRecovery:
		return Action{
			GenesisSource:         GenesisSourceStored,
			PreferStoredConfig:    true,
			PromoteOverrideMarker: facts.Writable && facts.LegacyStoredOverride,
		}
	default:
		return Action{GenesisSource: GenesisSourceStored}
	}
}

func classifyDecisionOverrideRoute(facts Facts) decisionOverrideRoute {
	switch {
	case !facts.AllowBuiltInCustomRecovery && (!facts.HasStoredConfig && facts.TrustedOverride || hasStoredOverrideRecovery(facts)):
		return decisionOverrideRouteConflict
	case !facts.HasStoredConfig && facts.TrustedOverride:
		return decisionOverrideRouteMissingTrustedConfig
	case hasStoredOverrideRecovery(facts):
		return decisionOverrideRouteStoredRecovery
	default:
		return decisionOverrideRouteNone
	}
}

func mustResolveDecisionAction(action Action) Action {
	if action.TerminalError != nil {
		return action
	}
	if action.GenesisSource == GenesisSourceInvalid {
		panic("startup.Decide produced invalid non-terminal genesis source")
	}
	return action
}

// Decide isolates the high-level startup routing from later hydrate,
// compatibility, and persistence details. When stored genesis and stored
// config are already authoritative and no terminal or override-specific action
// is required, it returns GenesisSourceStored explicitly. In that resolved
// stored-state path, the other Action fields may remain at their zero values.
func Decide(facts Facts) Action {
	if err := facts.Validate(); err != nil {
		return Action{TerminalError: err}
	}
	return mustResolveDecisionAction(classifyDecisionAction(facts))
}
