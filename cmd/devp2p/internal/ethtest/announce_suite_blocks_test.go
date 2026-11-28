package ethtest

import (
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	ethproto "github.com/XinFinOrg/XDPoSChain/eth/protocols/eth"
	"github.com/XinFinOrg/XDPoSChain/rlp"
)

func announcementTestBlock(t *testing.T, number uint64) ([]byte, []byte, common.Hash) {
	t.Helper()
	header := &types.Header{Number: new(big.Int).SetUint64(number), Difficulty: big.NewInt(1), GasLimit: 1000000, Time: number}
	block := types.NewBlockWithHeader(header)
	blockData, err := rlp.EncodeToBytes(&ethproto.NewBlockPacket{Block: block, TD: big.NewInt(1)})
	if err != nil {
		t.Fatalf("encode NewBlockPacket: %v", err)
	}
	hashData, err := rlp.EncodeToBytes(&ethproto.NewBlockHashesPacket{{Hash: block.Hash(), Number: number}})
	if err != nil {
		t.Fatalf("encode NewBlockHashesPacket: %v", err)
	}
	return blockData, hashData, block.Hash()
}

func feedAnnouncement(t *testing.T, code uint64, data []byte, watched common.Hash) error {
	t.Helper()
	client, peer := newFramePeer(t)
	conn := &Conn{Conn: client}
	written := make(chan error, 1)
	go func() {
		_, err := peer.Write(protoOffset(ethProto)+code, data)
		written <- err
	}()
	err := expectNoBlockAnnouncement(conn, 0, watched)
	if werr := <-written; werr != nil {
		t.Fatalf("peer write: %v", werr)
	}
	return err
}

func TestExpectNoBlockAnnouncementIgnoresUnrelatedMinedBlock(t *testing.T) {
	blockData, hashData, _ := announcementTestBlock(t, 625)
	unrelated := common.HexToHash("0x1234")
	if err := feedAnnouncement(t, ethproto.NewBlockMsg, blockData, unrelated); err != nil {
		t.Fatalf("unrelated mined block counted as propagation: %v", err)
	}
	if err := feedAnnouncement(t, ethproto.NewBlockHashesMsg, hashData, unrelated); err != nil {
		t.Fatalf("unrelated mined hash counted as propagation: %v", err)
	}
}

func TestExpectNoBlockAnnouncementCatchesWatchedBlock(t *testing.T) {
	blockData, hashData, watched := announcementTestBlock(t, 300)
	if err := feedAnnouncement(t, ethproto.NewBlockMsg, blockData, watched); err == nil {
		t.Fatal("propagated watched block accepted")
	}
	if err := feedAnnouncement(t, ethproto.NewBlockHashesMsg, hashData, watched); err == nil {
		t.Fatal("propagated watched hash accepted")
	}
}

func TestExpectNoBlockAnnouncementRejectsUndecodableFrame(t *testing.T) {
	if err := feedAnnouncement(t, ethproto.NewBlockMsg, []byte{0xff}, common.HexToHash("0x1234")); err == nil {
		t.Fatal("undecodable announcement accepted")
	}
	if err := feedAnnouncement(t, ethproto.NewBlockHashesMsg, []byte{0xff}, common.HexToHash("0x1234")); err == nil {
		t.Fatal("undecodable hash announcement accepted")
	}
}
