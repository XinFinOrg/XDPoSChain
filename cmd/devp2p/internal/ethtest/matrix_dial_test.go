package ethtest

import (
	"fmt"
	"os"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/p2p"
	"github.com/XinFinOrg/XDPoSChain/p2p/enode"
)

// Real node pairs cannot negotiate xdc/164 or xdc/100 against an XDC166 peer,
// so the pinned dial is the honest coverage; skips without MATRIX_ENODE and
// MATRIX_CHAINDIR
func TestMatrixPinnedVersionHandshake(t *testing.T) {
	enodeStr := os.Getenv("MATRIX_ENODE")
	chainDir := os.Getenv("MATRIX_CHAINDIR")
	if enodeStr == "" || chainDir == "" {
		t.Skip("MATRIX_ENODE/MATRIX_CHAINDIR not set (devnet matrix only)")
	}
	node, err := enode.Parse(enode.ValidSchemes, enodeStr)
	if err != nil {
		t.Fatalf("bad MATRIX_ENODE: %v", err)
	}
	suite, err := NewSuite(node, chainDir, "", "")
	if err != nil {
		t.Fatalf("failed to load chain dir %s: %v", chainDir, err)
	}
	for _, version := range []uint{ethProtoVersionXDpos164, ethProtoVersionXDpos2, ethProtoVersionXDpos166} {
		t.Run(fmt.Sprintf("xdc%d", version), func(t *testing.T) {
			key, err := crypto.GenerateKey()
			if err != nil {
				t.Fatalf("generate key: %v", err)
			}
			conn, err := suite.dialAs(key)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer conn.Close()
			// Pin the advertised caps so negotiation cannot settle higher
			conn.caps = []p2p.Cap{{Name: "eth", Version: version}}
			conn.ourHighestProtoVersion = version
			if err := conn.handshake(); err != nil {
				t.Fatalf("devp2p handshake at pinned xdc/%d failed: %v", version, err)
			}
			if err := conn.statusExchange(suite.chain, nil); err != nil {
				t.Fatalf("status exchange at pinned xdc/%d failed: %v", version, err)
			}
			if conn.negotiatedProtoVersion != version {
				t.Fatalf("negotiated xdc/%d, want xdc/%d", conn.negotiatedProtoVersion, version)
			}
		})
	}
}
