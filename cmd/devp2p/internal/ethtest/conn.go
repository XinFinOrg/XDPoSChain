package ethtest

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/eth"
	"github.com/XinFinOrg/XDPoSChain/p2p"
	"github.com/XinFinOrg/XDPoSChain/p2p/rlpx"
	"github.com/XinFinOrg/XDPoSChain/rlp"
)

const (
	ethProtoVersion63     uint = 63
	ethProtoVersionXDpos2 uint = 100
)

const connTimeout = 2 * time.Second

const statusMsgCode = eth.StatusMsg

var errDisc = errors.New("disconnect")

type statusPacket struct {
	ProtocolVersion uint32
	NetworkId       uint64
	TD              *big.Int
	CurrentBlock    common.Hash
	GenesisBlock    common.Hash
}

// Conn represents an individual RLPx connection used by ethtest.
type Conn struct {
	*rlpx.Conn
	ourKey                 *ecdsa.PrivateKey
	negotiatedProtoVersion uint
	ourHighestProtoVersion uint
	caps                   []p2p.Cap
}

func (s *Suite) dial() (*Conn, error) {
	key, err := crypto.GenerateKey()
	if err != nil {
		return nil, err
	}
	return s.dialAs(key)
}

func (s *Suite) dialAs(key *ecdsa.PrivateKey) (*Conn, error) {
	tcpEndpoint, ok := s.Dest.TCPEndpoint()
	if !ok {
		return nil, fmt.Errorf("node has no TCP endpoint")
	}
	fd, err := net.DialTimeout("tcp", tcpEndpoint.String(), handshakeTimeout)
	if err != nil {
		return nil, err
	}
	conn := &Conn{Conn: rlpx.NewConn(fd, s.Dest.Pubkey())}
	conn.ourKey = key
	if _, err := conn.Handshake(conn.ourKey); err != nil {
		conn.Close()
		return nil, err
	}
	conn.caps = []p2p.Cap{
		{Name: "eth", Version: ethProtoVersionXDpos2},
		{Name: "eth", Version: ethProtoVersion63},
	}
	conn.ourHighestProtoVersion = ethProtoVersionXDpos2
	return conn, nil
}

// Read reads a raw RLPx packet from the connection.
func (c *Conn) Read() (uint64, []byte, error) {
	c.SetReadDeadline(time.Now().Add(connTimeout))
	code, data, _, err := c.Conn.Read()
	if err != nil {
		return 0, nil, err
	}
	return code, data, nil
}

// Write writes an RLPx packet to the connection with protocol-relative code.
func (c *Conn) Write(proto Proto, code uint64, msg interface{}) error {
	c.SetWriteDeadline(time.Now().Add(connTimeout))
	payload, err := rlp.EncodeToBytes(msg)
	if err != nil {
		return err
	}
	_, err = c.Conn.Write(protoOffset(proto)+code, payload)
	return err
}

func (c *Conn) negotiateEthProtocol(caps []p2p.Cap) {
	var highest uint
	for _, capability := range caps {
		if capability.Name != "eth" {
			continue
		}
		if capability.Version > highest && capability.Version <= c.ourHighestProtoVersion {
			highest = capability.Version
		}
	}
	c.negotiatedProtoVersion = highest
}

func (s *Suite) dialAndPeer(status *statusPacket) (*Conn, error) {
	c, err := s.dial()
	if err != nil {
		return nil, err
	}
	if err := c.peer(s.chain, status); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

func (c *Conn) peer(chain *Chain, status *statusPacket) error {
	if err := c.handshake(); err != nil {
		return fmt.Errorf("handshake failed: %v", err)
	}
	if err := c.statusExchange(chain, status); err != nil {
		return fmt.Errorf("status exchange failed: %v", err)
	}
	return nil
}

func (c *Conn) handshake() error {
	pub0 := crypto.FromECDSAPub(&c.ourKey.PublicKey)[1:]
	ourHandshake := &protoHandshake{
		Version: 5,
		Caps:    c.caps,
		ID:      pub0,
	}
	if err := c.Write(baseProto, handshakeMsg, ourHandshake); err != nil {
		return fmt.Errorf("write to connection failed: %v", err)
	}
	code, data, err := c.Read()
	if err != nil {
		return fmt.Errorf("error reading handshake: %v", err)
	}
	if code != handshakeMsg {
		return fmt.Errorf("bad handshake: got msg code %d", code)
	}
	msg := new(protoHandshake)
	if err := rlp.DecodeBytes(data, &msg); err != nil {
		return fmt.Errorf("error decoding handshake msg: %v", err)
	}
	if msg.Version >= 5 {
		c.SetSnappy(true)
	}
	c.negotiateEthProtocol(msg.Caps)
	if c.negotiatedProtoVersion == 0 {
		return fmt.Errorf("could not negotiate eth protocol (remote caps: %v)", msg.Caps)
	}
	return nil
}

func makeStatusPacket(chain *Chain, version uint) *statusPacket {
	return &statusPacket{
		ProtocolVersion: uint32(version),
		NetworkId:       chain.config.ChainID.Uint64(),
		TD:              chain.TD(),
		CurrentBlock:    chain.Head().Hash(),
		GenesisBlock:    chain.blocks[0].Hash(),
	}
}

func (c *Conn) statusExchange(chain *Chain, status *statusPacket) error {
	statusCode := protoOffset(ethProto) + statusMsgCode
forRead:
	for {
		code, data, err := c.Read()
		if err != nil {
			return fmt.Errorf("failed to read from connection: %w", err)
		}
		switch code {
		case statusCode:
			msg := new(statusPacket)
			if err := rlp.DecodeBytes(data, msg); err != nil {
				return fmt.Errorf("error decoding status packet: %w", err)
			}
			if msg.GenesisBlock != chain.blocks[0].Hash() {
				return fmt.Errorf("wrong genesis block in status: have %#x want %#x", msg.GenesisBlock, chain.blocks[0].Hash())
			}
			break forRead
		case discMsg:
			return errDisc
		case pingMsg:
			if err := c.Write(baseProto, pongMsg, []byte{}); err != nil {
				return fmt.Errorf("failed to reply pong: %w", err)
			}
		default:
			if getProto(code) == baseProto {
				continue
			}
			return fmt.Errorf("bad status message: code %d", code)
		}
	}

	if c.negotiatedProtoVersion == 0 {
		return errors.New("eth protocol version must be set in Conn")
	}
	if status == nil {
		status = makeStatusPacket(chain, c.negotiatedProtoVersion)
	}
	if err := c.Write(ethProto, statusMsgCode, status); err != nil {
		return fmt.Errorf("write status to connection failed: %v", err)
	}
	return nil
}

// ReadEth reads and decodes the next eth-subprotocol message.
func (c *Conn) ReadEth() (interface{}, error) {
	for {
		code, data, err := c.Read()
		if err != nil {
			return nil, err
		}
		if code == discMsg {
			return nil, errDisc
		}
		if code == pingMsg {
			if err := c.Write(baseProto, pongMsg, []byte{}); err != nil {
				return nil, fmt.Errorf("failed to reply pong: %w", err)
			}
			continue
		}
		if getProto(code) != ethProto {
			continue
		}
		return decodeEthPayload(code-protoOffset(ethProto), data)
	}
}

func decodeEthPayload(code uint64, data []byte) (interface{}, error) {
	var msg interface{}
	switch code {
	case eth.StatusMsg:
		msg = new(statusPacket)
	case eth.NewBlockHashesMsg:
		msg = new(rlp.RawValue)
	case eth.NewBlockMsg:
		msg = new(rlp.RawValue)
	case eth.GetBlockHeadersMsg:
		msg = new(getBlockHeadersData)
	case eth.BlockHeadersMsg:
		msg = new(blockHeadersData)
	case eth.GetBlockBodiesMsg:
		msg = new(getBlockBodiesData)
	case eth.BlockBodiesMsg:
		msg = new(blockBodiesData)
	case eth.GetNodeDataMsg:
		msg = new(rlp.RawValue)
	case eth.NodeDataMsg:
		msg = new(rlp.RawValue)
	case eth.GetReceiptsMsg:
		msg = new(getReceiptsData)
	case eth.ReceiptsMsg:
		msg = new(receiptsData)
	case eth.TxMsg:
		msg = new(types.Transactions)
	case eth.OrderTxMsg:
		msg = new([]rlp.RawValue)
	case eth.LendingTxMsg:
		msg = new([]rlp.RawValue)
	case eth.VoteMsg:
		msg = new(rlp.RawValue)
	case eth.TimeoutMsg:
		msg = new(rlp.RawValue)
	case eth.SyncInfoMsg:
		msg = new(rlp.RawValue)
	default:
		return nil, fmt.Errorf("unhandled eth msg code %d", code)
	}
	if err := rlp.DecodeBytes(data, msg); err != nil {
		return nil, fmt.Errorf("unable to decode eth msg: %v", err)
	}
	return msg, nil
}
