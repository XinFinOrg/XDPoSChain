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

// # Startup routing overview
//
// The startup path in core/genesis.go is split into two decision layers:
//
//  1. startup.Facts -> startup.Action
//     Pure routing for "which source should drive startup right now?"
//
//  2. builtInChainConfigFacts -> builtInChainConfigAction
//     Built-in-only canonicalization for "does the chosen config still need
//     to collapse back to the bundled built-in config?"
//
// The first layer is easiest to reason about as a small state machine over a
// few orthogonal fact dimensions:
//
//	identity: canonical hash empty? provided matches stored? provided restates built-in?
//	storage:  stored chain-config blob present? genesis header present?
//	trust:    override marker present? historical v1 same-hash built-in
//	          override path inferred from stored config state?
//	mode:     writable startup or read-only startup?
//
// Those facts map to a small set of routing actions before any fork-order,
// compatibility, or persistence work happens:
//
//	choose genesis source        -> provided / built-in / default mainnet
//	allow commit                 -> only on writable empty-db startup
//	require explicit genesis     -> same-hash override lost its stored config
//	prefer stored config         -> trusted stored override should win
//	promote override marker      -> writable upgrade from the historical v1
//	                                 same-hash built-in override path that
//	                                 stored only the custom config, not the
//	                                 explicit marker
//	terminal error               -> chain-config missing or built-in conflict
//
// ASCII map of the routing layer:
//
//	+------------------- canonical hash present? -------------------+
//	| no                                                          yes |
//	|                                                              |
//	v                                                              v
//	[empty DB]                                           [stored genesis exists]
//	|                                                     |
//	+-- provided genesis? -- yes --> source=provided      +-- stored config missing? -- yes -->
//	|                          no --> source=default           |                              |
//	|                                                         trusted override?           no trusted override
//	+-- writable? --------- yes --> allowCommitGenesis         |                              |
//	                           no --> read-only source only    v                              v
//	                                                        require explicit          try bundled recovery
//	                                                        genesis / not found       or return missing config
//
//	[stored genesis exists, stored config present]
//	|
//	+-- trusted or legacy override?
//	       |
//	       +-- provided genesis matches stored hash and restates built-in?
//	              |
//	              +-- yes --> prefer stored config
//	              |           + writable + legacy v1 path -> promote explicit
//	              |             override marker
//	              |
//	              +-- no  --> continue with normal compatibility and built-in checks
//
// Everything after that falls through to the existing orchestration below:
// config hydration, built-in canonicalization, compatibility checks, and DB
// writes stay local to core/genesis.go.
