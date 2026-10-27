package core

import (
	"github.com/XinFinOrg/XDPoSChain/params"
)

// ErrInvalidEpochGap reports an XDPoS chain config whose schedule cannot place
// a gap block inside an epoch. It is the params sentinel, so a config rejected
// by either gate satisfies the same errors.Is check.
var ErrInvalidEpochGap = params.ErrInvalidEpochGap

// checkXDPoSSchedule enforces the XDPoS schedule bound core accepts. The rule
// and its rationale live in params.XDPoSConfig.CheckSchedule, which
// ChainConfig.CheckConfigForkOrder also runs; this helper keeps core's earlier
// gate, which sees a config before XDPoS.New rewrites a missing epoch to 900.
// A chain config without an XDPoS section is not an XDPoS chain and is left
// alone.
//
// The call sites do not cover the same inputs. Genesis.commit and the genesis
// and config resolvers run before XDPoS.New, so they see Epoch == 0 as well;
// the newBlockChain gate runs after the engine has rewritten it to 900 and
// only catches a caller-supplied Gap outside the bound.
//
// Three of the four call sites also run immediately after CheckConfigForkOrder,
// whose params gate judges the same set, so on those paths this helper cannot
// reject anything that call accepts; they stay as the gate position, not as a
// second rule. newBlockChain is the one no other check covers: the
// NewBlockChain*Resolved opens take a caller-supplied config and skip
// CheckConfigForkOrder.
func checkXDPoSSchedule(cfg *params.ChainConfig) error {
	if cfg == nil {
		return nil
	}
	return cfg.XDPoS.CheckSchedule()
}
