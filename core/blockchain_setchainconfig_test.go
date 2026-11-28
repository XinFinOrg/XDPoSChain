package core

import (
	"bytes"
	"strings"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/log"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// TestSetChainConfigLogsInvalidSchedule pins the only trace an invalid schedule
// leaves on the path that installs it without rejecting it.
func TestSetChainConfigLogsInvalidSchedule(t *testing.T) {
	var buf bytes.Buffer
	prevLog := log.Root()
	glog := log.NewGlogHandler(log.NewTerminalHandlerWithLevel(&buf, log.LevelTrace, false))
	glog.Verbosity(log.LevelTrace)
	log.SetDefault(log.NewLogger(glog))
	defer log.SetDefault(prevLog)

	chain := &BlockChain{}
	chain.SetChainConfig(params.TestXDPoSMockChainConfig.Clone())
	if strings.Contains(buf.String(), "Chain config has an invalid XDPoS schedule") {
		t.Fatalf("a valid schedule was logged as invalid: %q", buf.String())
	}
	for _, schedule := range []*params.XDPoSConfig{
		{Epoch: 0, Gap: 450},
		{Epoch: 900, Gap: 0},
		{Epoch: 900, Gap: 900},
		{Epoch: 900, Gap: 1200},
	} {
		buf.Reset()
		chain.SetChainConfig(&params.ChainConfig{XDPoS: schedule})
		if !strings.Contains(buf.String(), "Chain config has an invalid XDPoS schedule") {
			t.Fatalf("invalid schedule %+v was not logged", schedule)
		}
	}
}
