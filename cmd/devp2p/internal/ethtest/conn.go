package ethtest

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/forkid"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	ethproto "github.com/XinFinOrg/XDPoSChain/eth/protocols/eth"
	"github.com/XinFinOrg/XDPoSChain/p2p"
	"github.com/XinFinOrg/XDPoSChain/p2p/rlpx"
	"github.com/XinFinOrg/XDPoSChain/rlp"
)

const (
	// Local copy of the wire version the node states in eth/protocols/eth, kept
	// here on purpose (see protocol.go)
	ethProtoVersionXDpos2   uint = 100
	ethProtoVersionXDpos164 uint = 164
	ethProtoVersionXDpos166 uint = 166
)

const connTimeout = 2 * time.Second

const statusMsgCode = ethproto.StatusMsg

var errDisc = errors.New("disconnect")

type statusPacket struct {
	ProtocolVersion uint32
	NetworkId       uint64
	TD              *big.Int
	CurrentBlock    common.Hash
	GenesisBlock    common.Hash
}

// Sixth fork-id field the node validates from xdc/164 on; xdc/100 keeps the
// five-field shape
type statusPacketFork struct {
	ProtocolVersion uint32
	NetworkId       uint64
	TD              *big.Int
	CurrentBlock    common.Hash
	GenesisBlock    common.Hash
	ForkID          forkid.ID
}

// Conn represents an individual RLPx connection used by ethtest.
type Conn struct {
	*rlpx.Conn
	ourKey                 *ecdsa.PrivateKey
	negotiatedProtoVersion uint
	ourHighestProtoVersion uint
	caps                   []p2p.Cap
	// Reported by the node in status; live cases anchor on these instead of the
	// fixture chain
	remoteHead common.Hash
	remoteTD   *big.Int
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

// dialXdc166 appends xdc/166 after the RLPx handshake; caps feed the devp2p hello
func (s *Suite) dialXdc166() (*Conn, error) {
	key, err := crypto.GenerateKey()
	if err != nil {
		return nil, err
	}
	conn, err := s.dialAs(key)
	if err != nil {
		return nil, err
	}
	conn.caps = append(conn.caps, p2p.Cap{Name: "eth", Version: ethProtoVersionXDpos166})
	conn.ourHighestProtoVersion = ethProtoVersionXDpos166
	return conn, nil
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

// From xdc/164 on the node validates the fork id, so the packet gains the
// sixth field, derived from the same chain config the node runs
func makeStatusPacket(chain *Chain, version uint) interface{} {
	base := statusPacketFork{
		ProtocolVersion: uint32(version),
		NetworkId:       chain.config.ChainID.Uint64(),
		TD:              chain.TD(),
		CurrentBlock:    chain.Head().Hash(),
		GenesisBlock:    chain.blocks[0].Hash(),
	}
	if version >= ethProtoVersionXDpos164 {
		base.ForkID = forkid.NewID(chain.config, chain.blocks[0], chain.Head().NumberU64())
		return &base
	}
	return &statusPacket{
		ProtocolVersion: base.ProtocolVersion,
		NetworkId:       base.NetworkId,
		TD:              base.TD,
		CurrentBlock:    base.CurrentBlock,
		GenesisBlock:    base.GenesisBlock,
	}
}

func (c *Conn) statusExchange(chain *Chain, status interface{}) error {
	statusCode := protoOffset(ethProto) + statusMsgCode
forRead:
	for {
		code, data, err := c.Read()
		if err != nil {
			return fmt.Errorf("failed to read from connection: %w", err)
		}
		switch code {
		case statusCode:
			// The six-field payload fails the five-field shape
			var genesisBlock common.Hash
			if c.negotiatedProtoVersion >= ethProtoVersionXDpos164 {
				msg := new(statusPacketFork)
				if err := rlp.DecodeBytes(data, msg); err != nil {
					return fmt.Errorf("error decoding status packet: %w", err)
				}
				genesisBlock = msg.GenesisBlock
				c.remoteHead = msg.CurrentBlock
				c.remoteTD = msg.TD
			} else {
				msg := new(statusPacket)
				if err := rlp.DecodeBytes(data, msg); err != nil {
					return fmt.Errorf("error decoding status packet: %w", err)
				}
				genesisBlock = msg.GenesisBlock
				c.remoteHead = msg.CurrentBlock
				c.remoteTD = msg.TD
			}
			if genesisBlock != chain.blocks[0].Hash() {
				return fmt.Errorf("wrong genesis block in status: have %#x want %#x", genesisBlock, chain.blocks[0].Hash())
			}
			break forRead
		case discMsg:
			return errDisc
		case pingMsg:
			if err := c.Write(baseProto, pongMsg, []byte{}); err != nil {
				return fmt.Errorf("failed to reply pong: %w", err)
			}
		default:
			if proto := getProto(code); proto == baseProto || proto == unknownProto {
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

// isXdc166MsgCode admits only codes decodeXdc166Payload decodes
func isXdc166MsgCode(code uint64) bool {
	if code < protoOffset(ethProto) {
		return false
	}
	ethCode := code - protoOffset(ethProto)
	if ethCode > ethproto.LendingTxMsg && ethCode < ethproto.GetNodeDataMsg {
		return false
	}
	return ethCode <= ethproto.ReceiptsMsg || (ethCode >= ethproto.VoteMsg && ethCode <= ethproto.PooledTransactionsMsg)
}

// ReadXdc166 must only be used on connections that negotiated xdc/166
func (c *Conn) ReadXdc166() (uint64, interface{}, error) {
	for {
		code, data, err := c.Read()
		if err != nil {
			return 0, nil, err
		}
		if code == discMsg {
			return 0, nil, errDisc
		}
		if code == pingMsg {
			if err := c.Write(baseProto, pongMsg, []byte{}); err != nil {
				return 0, nil, fmt.Errorf("failed to reply pong: %w", err)
			}
			continue
		}
		if !isXdc166MsgCode(code) {
			continue
		}
		return decodeXdc166Payload(code-protoOffset(ethProto), data)
	}
}

func decodeEthPayload(code uint64, data []byte) (interface{}, error) {
	var msg interface{}
	switch code {
	case ethproto.StatusMsg:
		msg = new(statusPacket)
	case ethproto.NewBlockHashesMsg:
		msg = new(rlp.RawValue)
	case ethproto.NewBlockMsg:
		msg = new(rlp.RawValue)
	case ethproto.GetBlockHeadersMsg:
		msg = new(getBlockHeadersData)
	case ethproto.BlockHeadersMsg:
		msg = new(blockHeadersData)
	case ethproto.GetBlockBodiesMsg:
		msg = new(getBlockBodiesData)
	case ethproto.BlockBodiesMsg:
		msg = new(blockBodiesData)
	case ethproto.GetNodeDataMsg:
		msg = new(rlp.RawValue)
	case ethproto.NodeDataMsg:
		msg = new(rlp.RawValue)
	case ethproto.GetReceiptsMsg:
		msg = new(getReceiptsData)
	case ethproto.ReceiptsMsg:
		msg = new(receiptsData)
	case ethproto.TransactionMsg:
		msg = new(types.Transactions)
	case ethproto.NewPooledTransactionHashesMsg:
		// Broadcasts reach every peer; response waiters must be able to skip
		// them
		msg = new(ethproto.NewPooledTransactionHashesPacket)
	case ethproto.OrderTxMsg:
		msg = new([]rlp.RawValue)
	case ethproto.LendingTxMsg:
		msg = new([]rlp.RawValue)
	case ethproto.VoteMsg:
		msg = new(rlp.RawValue)
	case ethproto.TimeoutMsg:
		msg = new(rlp.RawValue)
	case ethproto.SyncInfoMsg:
		msg = new(rlp.RawValue)
	default:
		return nil, fmt.Errorf("unhandled eth msg code %d", code)
	}
	if err := rlp.DecodeBytes(data, msg); err != nil {
		return nil, fmt.Errorf("unable to decode eth msg: %v", err)
	}
	return msg, nil
}

// decodeXdc166Payload returns a zero request id for codes outside the five 66 pairs
func decodeXdc166Payload(code uint64, data []byte) (uint64, interface{}, error) {
	switch code {
	case ethproto.GetBlockHeadersMsg:
		wrapped := new(getBlockHeadersPacket166)
		if err := rlp.DecodeBytes(data, wrapped); err != nil {
			return 0, nil, fmt.Errorf("unable to decode eth msg: %v", err)
		}
		return wrapped.RequestId, wrapped.Request, nil
	case ethproto.BlockHeadersMsg:
		wrapped := new(blockHeadersPacket166)
		if err := rlp.DecodeBytes(data, wrapped); err != nil {
			return 0, nil, fmt.Errorf("unable to decode eth msg: %v", err)
		}
		return wrapped.RequestId, &wrapped.Headers, nil
	case ethproto.GetBlockBodiesMsg:
		wrapped := new(getBlockBodiesPacket166)
		if err := rlp.DecodeBytes(data, wrapped); err != nil {
			return 0, nil, fmt.Errorf("unable to decode eth msg: %v", err)
		}
		return wrapped.RequestId, &wrapped.Hashes, nil
	case ethproto.BlockBodiesMsg:
		wrapped := new(blockBodiesPacket166)
		if err := rlp.DecodeBytes(data, wrapped); err != nil {
			return 0, nil, fmt.Errorf("unable to decode eth msg: %v", err)
		}
		return wrapped.RequestId, &wrapped.Bodies, nil
	case ethproto.GetNodeDataMsg:
		wrapped := new(getNodeDataPacket166)
		if err := rlp.DecodeBytes(data, wrapped); err != nil {
			return 0, nil, fmt.Errorf("unable to decode eth msg: %v", err)
		}
		return wrapped.RequestId, &wrapped.Hashes, nil
	case ethproto.NodeDataMsg:
		wrapped := new(nodeDataPacket166)
		if err := rlp.DecodeBytes(data, wrapped); err != nil {
			return 0, nil, fmt.Errorf("unable to decode eth msg: %v", err)
		}
		return wrapped.RequestId, &wrapped.Data, nil
	case ethproto.GetReceiptsMsg:
		wrapped := new(getReceiptsPacket166)
		if err := rlp.DecodeBytes(data, wrapped); err != nil {
			return 0, nil, fmt.Errorf("unable to decode eth msg: %v", err)
		}
		return wrapped.RequestId, &wrapped.Hashes, nil
	case ethproto.ReceiptsMsg:
		wrapped := new(receiptsPacket166)
		if err := rlp.DecodeBytes(data, wrapped); err != nil {
			return 0, nil, fmt.Errorf("unable to decode eth msg: %v", err)
		}
		return wrapped.RequestId, &wrapped.Receipts, nil
	case ethproto.GetPooledTransactionsMsg:
		wrapped := new(getPooledTransactionsPacket166)
		if err := rlp.DecodeBytes(data, wrapped); err != nil {
			return 0, nil, fmt.Errorf("unable to decode eth msg: %v", err)
		}
		return wrapped.RequestId, &wrapped.Hashes, nil
	case ethproto.PooledTransactionsMsg:
		wrapped := new(pooledTransactionsPacket166)
		if err := rlp.DecodeBytes(data, wrapped); err != nil {
			return 0, nil, fmt.Errorf("unable to decode eth msg: %v", err)
		}
		return wrapped.RequestId, &wrapped.Txs, nil
	case ethproto.NewPooledTransactionHashesMsg:
		// Peers announce pooled tx hashes at any time; keep the frame opaque
		msg := new(rlp.RawValue)
		if err := rlp.DecodeBytes(data, msg); err != nil {
			return 0, nil, fmt.Errorf("unable to decode eth msg: %v", err)
		}
		return 0, msg, nil
	default:
		msg, err := decodeEthPayload(code, data)
		return 0, msg, err
	}
}
