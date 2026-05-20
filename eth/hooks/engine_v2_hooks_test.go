package hooks

import (
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// TestResolvePreUpgradeLimitPenaltyEpochUsesHistoricalValue tests the
// pre-upgrade path stays pinned to the historical V2 constant.
func TestResolvePreUpgradeLimitPenaltyEpochUsesHistoricalValue(t *testing.T) {
	if got := resolvePreUpgradeLimitPenaltyEpoch(); got != common.LimitPenaltyEpochV2 {
		t.Fatalf("unexpected pre-upgrade limit penalty epoch: have %d want %d", got, common.LimitPenaltyEpochV2)
	}
}

// TestResolvePostUpgradeLimitPenaltyEpochDefaultsToOne tests the post-upgrade
// path preserves the legacy fallback of one epoch when config is unset.
func TestResolvePostUpgradeLimitPenaltyEpochDefaultsToOne(t *testing.T) {
	if got := resolvePostUpgradeLimitPenaltyEpoch(nil); got != 1 {
		t.Fatalf("unexpected nil-config post-upgrade limit penalty epoch: have %d want %d", got, 1)
	}

	if got := resolvePostUpgradeLimitPenaltyEpoch(&params.V2Config{}); got != 1 {
		t.Fatalf("unexpected zero-value post-upgrade limit penalty epoch: have %d want %d", got, 1)
	}
}

// TestResolvePostUpgradeLimitPenaltyEpochUsesConfiguredValue tests the
// post-upgrade path still honors an explicit configuration value.
func TestResolvePostUpgradeLimitPenaltyEpochUsesConfiguredValue(t *testing.T) {
	cfg := &params.V2Config{LimitPenaltyEpoch: 2}
	if got := resolvePostUpgradeLimitPenaltyEpoch(cfg); got != 2 {
		t.Fatalf("unexpected configured post-upgrade limit penalty epoch: have %d want %d", got, 2)
	}
}
