package ethapi

import (
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// AttachStateChainConfig ensures a StateDB carries the active chain config
// before config-dependent helpers inspect chain-specific state, without
// overriding an already attached config.
func AttachStateChainConfig(statedb *state.StateDB, config *params.ChainConfig) (*state.StateDB, error) {
	if err := statedb.EnsureChainConfig(config); err != nil {
		return nil, err
	}
	return statedb, nil
}
