package engine_v1

import (
	"testing"

	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// TestConstructorsFillUnsetEpoch pins that both constructors copy the consensus
// parameters and fill an unset epoch with the engine default, so an engine built
// here cannot divide by a zero epoch and the caller's config is left as written.
func TestConstructorsFillUnsetEpoch(t *testing.T) {
	tests := []struct {
		name      string
		construct func(*params.ChainConfig) *XDPoS_v1
	}{
		{name: "New", construct: func(cfg *params.ChainConfig) *XDPoS_v1 { return New(cfg, rawdb.NewMemoryDatabase()) }},
		{name: "NewFaker", construct: func(cfg *params.ChainConfig) *XDPoS_v1 { return NewFaker(rawdb.NewMemoryDatabase(), cfg) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := params.TestXDPoSMockChainConfig.Clone()
			cfg.XDPoS = cfg.XDPoS.Clone()
			cfg.XDPoS.Epoch = 0

			engine := test.construct(cfg)

			if engine.config.Epoch != params.DefaultXDPoSEpoch {
				t.Fatalf("engine epoch: have %d want %d", engine.config.Epoch, params.DefaultXDPoSEpoch)
			}
			if cfg.XDPoS.Epoch != 0 {
				t.Fatalf("constructor filled the caller's config in place: %d", cfg.XDPoS.Epoch)
			}
		})
	}
}

// TestConstructorsRefuseMissingXDPoSConfig pins that neither constructor
// dereferences an absent consensus config. There is nothing to copy for a config
// without XDPoS parameters, so the engine is nil rather than a panic - NewFaker
// used to dereference it - and a caller cannot end up with an engine whose epoch
// conversions read a nil config.
func TestConstructorsRefuseMissingXDPoSConfig(t *testing.T) {
	withoutXDPoS := params.TestXDPoSMockChainConfig.Clone()
	withoutXDPoS.XDPoS = nil

	tests := []struct {
		name      string
		construct func(*params.ChainConfig) *XDPoS_v1
	}{
		{name: "New", construct: func(cfg *params.ChainConfig) *XDPoS_v1 { return New(cfg, rawdb.NewMemoryDatabase()) }},
		{name: "NewFaker", construct: func(cfg *params.ChainConfig) *XDPoS_v1 { return NewFaker(rawdb.NewMemoryDatabase(), cfg) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if engine := test.construct(nil); engine != nil {
				t.Fatalf("constructor built an engine for a nil chain config: %v", engine)
			}
			if engine := test.construct(withoutXDPoS); engine != nil {
				t.Fatalf("constructor built an engine for a config without XDPoS parameters: %v", engine)
			}
		})
	}
}
