package core

import (
	"errors"
	"fmt"

	"github.com/XinFinOrg/XDPoSChain/params"
)

// ErrInvalidEpochGap reports an XDPoS chain config whose schedule cannot place
// a gap block inside an epoch.
var ErrInvalidEpochGap = errors.New("invalid XDPoS schedule")

// checkXDPoSSchedule enforces 0 < gap < epoch on the configs core accepts. A
// chain config without an XDPoS section is not an XDPoS chain and is left
// alone. Outside the bound a schedule has no consistent meaning: the two gap
// predicates disagree on Gap == Epoch (isGapBlockNumber accepts it,
// isNextEpochGapBlock refuses it), and for Gap > Epoch the v1 engine's
// checkpoint-minus-Gap lookup addresses heights those predicates never report.
// A violating config is therefore rejected where it enters the chain rather
// than interpreted.
//
// The call sites do not cover the same inputs. Genesis.commit and the genesis
// and config resolvers run before XDPoS.New, so they see Epoch == 0 as well;
// the newBlockChain gate runs after the engine has rewritten it to 900 and
// only catches a caller-supplied Gap outside the bound.
func checkXDPoSSchedule(cfg *params.ChainConfig) error {
	if cfg == nil || cfg.XDPoS == nil {
		return nil
	}
	epoch, gap := cfg.XDPoS.Epoch, cfg.XDPoS.Gap
	if gap == 0 || gap >= epoch {
		return fmt.Errorf("%w: XDPoS.Epoch %d, XDPoS.Gap %d (want 0 < gap < epoch)", ErrInvalidEpochGap, epoch, gap)
	}
	return nil
}
