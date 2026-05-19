package core

import (
	stdsha256 "crypto/sha256"
	"encoding/binary"
	stdmath "math"
	"math/big"
	"sort"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// chainConfigDigestVersion identifies the canonical semantic encoding used by
// hashChainConfigSemantic. Bump this when the encoding changes: older digests
// will stop matching the fast path and chainConfigJSONEqual will fall back to
// field-level semantic comparison until both sides are re-encoded. Update the
// pinned digest expectations in core/chainconfig_equal_test.go at the same time.
const chainConfigDigestVersion byte = 1

func defaultHashChainConfigSemanticVersioned(cfg *params.ChainConfig) (byte, [32]byte) {
	return chainConfigDigestVersion, hashChainConfigSemantic(cfg)
}

// chainConfigJSONEqual compares two chain configs, using a digest fast path
// before falling back to field-level semantic comparison.
func (deps genesisDeps) chainConfigJSONEqual(a, b *params.ChainConfig) (bool, error) {
	hashSemanticVersioned := deps.hashChainConfigSemanticVersioned
	if hashSemanticVersioned == nil {
		hashSemanticVersioned = defaultHashChainConfigSemanticVersioned
	}
	if a == b {
		return true, nil
	}
	if a == nil || b == nil {
		return a == nil && b == nil, nil
	}
	if fastEqual, ok := fastChainConfigJSONEqual(a, b, hashSemanticVersioned); ok {
		return fastEqual, nil
	}
	return a.Equal(b), nil
}

// fastChainConfigJSONEqual returns semantic equality and whether no fallback is needed.
func fastChainConfigJSONEqual(a, b *params.ChainConfig, hashSemanticVersioned func(*params.ChainConfig) (byte, [32]byte)) (bool, bool) {
	if a == b {
		return true, true
	}
	if a == nil || b == nil {
		return a == nil && b == nil, true
	}
	if !equalBigInt(a.ChainID, b.ChainID) {
		return false, true
	}
	if !equalChainConfigForkFields(a, b) {
		return false, true
	}
	aVersion, aDigest := hashSemanticVersioned(a)
	bVersion, bDigest := hashSemanticVersioned(b)
	if aVersion != bVersion {
		return false, false
	}
	return aDigest == bDigest, true
}

// equalChainConfigForkFields reports whether all fork activation blocks match.
func equalChainConfigForkFields(a, b *params.ChainConfig) bool {
	if a == nil || b == nil {
		return a == b
	}
	equal := true
	params.ForEachChainConfigForkBlockPair(a, b, func(_ string, aValue, bValue *big.Int) {
		if equal && !equalBigInt(aValue, bValue) {
			equal = false
		}
	})
	if !equal {
		return false
	}
	return true
}

// hashChainConfigSemantic hashes the semantic contents of cfg into a stable digest.
func hashChainConfigSemantic(cfg *params.ChainConfig) [32]byte {
	digest := newChainConfigDigest()
	digest.writeChainConfig(cfg)
	return digest.sum()
}

type chainConfigDigest struct {
	buf   []byte
	tmp32 [32]byte
}

// newChainConfigDigest allocates a reusable encoder for semantic config hashing.
func newChainConfigDigest() *chainConfigDigest {
	return &chainConfigDigest{buf: make([]byte, 0, 2048)}
}

// sum returns the SHA-256 digest of the encoded config buffer.
func (d *chainConfigDigest) sum() [32]byte {
	return stdsha256.Sum256(d.buf)
}

// writeChainConfig appends cfg to the digest buffer in canonical field order.
func (d *chainConfigDigest) writeChainConfig(cfg *params.ChainConfig) {
	d.writeByte(chainConfigDigestVersion)
	if !d.writeNilMarker(cfg == nil) {
		return
	}
	d.writeBigInt(cfg.ChainID)
	wroteDAOForkSupport := false
	params.ForEachChainConfigForkBlock(cfg, func(name string, value *big.Int) {
		if !wroteDAOForkSupport && name == "EIP150Block" {
			d.writeBool(cfg.DAOForkSupport)
			wroteDAOForkSupport = true
		}
		d.writeBigInt(value)
	})
	if !wroteDAOForkSupport {
		d.writeBool(cfg.DAOForkSupport)
	}
	params.ForEachChainConfigXDCSystemContract(cfg, func(_ string, value common.Address) {
		d.writeAddress(value)
	})
	d.writeBool(cfg.Ethash != nil)
	d.writeClique(cfg.Clique)
	d.writeXDPoS(cfg.XDPoS)
}

// writeClique appends the Clique subsection to the digest buffer.
func (d *chainConfigDigest) writeClique(cfg *params.CliqueConfig) {
	if !d.writeNilMarker(cfg == nil) {
		return
	}
	d.writeUint64(cfg.Period)
	d.writeUint64(cfg.Epoch)
}

// writeXDPoS appends the XDPoS subsection to the digest buffer.
func (d *chainConfigDigest) writeXDPoS(cfg *params.XDPoSConfig) {
	if !d.writeNilMarker(cfg == nil) {
		return
	}
	d.writeUint64(cfg.Period)
	d.writeUint64(cfg.Epoch)
	d.writeUint64(cfg.Reward)
	d.writeUint64(cfg.RewardCheckpoint)
	d.writeUint64(cfg.Gap)
	d.writeAddress(cfg.FoundationWalletAddr)
	d.writeInt(cfg.MaxMasternodesV2)
	d.writeBool(cfg.SkipV1Validation)
	d.writeV2(cfg.V2)
}

// writeV2 appends the V2 scheduling and config state to the digest buffer.
func (d *chainConfigDigest) writeV2(v2 *params.V2) {
	if !d.writeNilMarker(v2 == nil) {
		return
	}
	v2.WithReadOnlySnapshot(func(switchEpoch uint64, switchBlock *big.Int, currentConfig *params.V2Config, allConfigs map[uint64]*params.V2Config, _ []uint64) {
		d.writeUint64(switchEpoch)
		d.writeBigInt(switchBlock)
		d.writeV2Config(currentConfig)
		if !d.writeNilMarker(allConfigs == nil) {
			return
		}
		keys := make([]uint64, 0, len(allConfigs))
		for key := range allConfigs {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
		d.writeUint64(uint64(len(keys)))
		for _, key := range keys {
			d.writeUint64(key)
			d.writeV2Config(allConfigs[key])
		}
	})
}

// writeV2Config appends a V2Config value to the digest buffer.
func (d *chainConfigDigest) writeV2Config(cfg *params.V2Config) {
	if !d.writeNilMarker(cfg == nil) {
		return
	}
	d.writeInt(cfg.MaxMasternodes)
	d.writeInt(cfg.MaxProtectorNodes)
	d.writeInt(cfg.MaxObverserNodes)
	d.writeUint64(cfg.SwitchRound)
	d.writeInt(cfg.MinePeriod)
	d.writeInt(cfg.TimeoutSyncThreshold)
	d.writeInt(cfg.TimeoutPeriod)
	d.writeFloat64(cfg.CertThreshold)
	d.writeFloat64(cfg.MasternodeReward)
	d.writeFloat64(cfg.ProtectorReward)
	d.writeFloat64(cfg.ObserverReward)
	d.writeInt(cfg.MinimumMinerBlockPerEpoch)
	d.writeInt(cfg.LimitPenaltyEpoch)
	d.writeInt(cfg.MinimumSigningTx)
	d.writeExpTimeout(&cfg.ExpTimeoutConfig)
}

// writeExpTimeout appends an exponential-timeout config to the digest buffer.
func (d *chainConfigDigest) writeExpTimeout(cfg *params.ExpTimeoutConfig) {
	if !d.writeNilMarker(cfg == nil) {
		return
	}
	d.writeFloat64(cfg.Base)
	d.writeByte(cfg.MaxExponent)
}

// writeBigInt appends a length-prefixed big.Int encoding to the digest buffer.
func (d *chainConfigDigest) writeBigInt(n *big.Int) {
	if !d.writeNilMarker(n == nil) {
		return
	}
	byteLen := (n.BitLen() + 7) / 8
	d.writeUint64(uint64(byteLen))
	if byteLen == 0 {
		return
	}
	if byteLen <= len(d.tmp32) {
		encoded := n.FillBytes(d.tmp32[:])
		d.buf = append(d.buf, encoded[len(encoded)-byteLen:]...)
		return
	}
	d.buf = append(d.buf, n.Bytes()...)
}

// writeAddress appends addr bytes to the digest buffer.
func (d *chainConfigDigest) writeAddress(addr common.Address) {
	d.buf = append(d.buf, addr[:]...)
}

// writeBool appends a canonical boolean byte to the digest buffer.
func (d *chainConfigDigest) writeBool(v bool) {
	if v {
		d.writeByte(1)
		return
	}
	d.writeByte(0)
}

// writeInt appends v as a uint64 to the digest buffer.
func (d *chainConfigDigest) writeInt(v int) {
	d.writeUint64(uint64(v))
}

// writeUint64 appends v as big-endian bytes to the digest buffer.
func (d *chainConfigDigest) writeUint64(v uint64) {
	start := len(d.buf)
	d.buf = append(d.buf, 0, 0, 0, 0, 0, 0, 0, 0)
	binary.BigEndian.PutUint64(d.buf[start:], v)
}

// writeFloat64 appends v using IEEE-754 bit encoding.
func (d *chainConfigDigest) writeFloat64(v float64) {
	d.writeUint64(stdmath.Float64bits(v))
}

// writeByte appends a single byte to the digest buffer.
func (d *chainConfigDigest) writeByte(v byte) {
	d.buf = append(d.buf, v)
}

// writeNilMarker appends a presence marker and reports whether encoding should continue.
func (d *chainConfigDigest) writeNilMarker(isNil bool) bool {
	if isNil {
		d.writeByte(0)
		return false
	}
	d.writeByte(1)
	return true
}

// equalBigInt reports whether a and b are numerically equal.
func equalBigInt(a, b *big.Int) bool {
	if a == b {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return a.Cmp(b) == 0
}
