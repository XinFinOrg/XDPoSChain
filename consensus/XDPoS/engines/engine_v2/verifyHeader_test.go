package engine_v2

import (
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/falcon"
)

var falconType = falcon.SigCompressed
var addr2FalconPk = make(map[common.Address][]byte)

func verifyFalconSignature(bytesToBeVerified []byte, signature types.Signature, signer common.Address) error {

	signerPk := addr2FalconPk[signer]
	err := falcon.Verify(signature, bytesToBeVerified, signerPk, falconType)
	if err != nil {
		return err
	}

	return nil
}

func TestFalconSignatureVerify(t *testing.T) {
	header := &types.Header{
		Root:       common.HexToHash("0x1234567890123456789012345678901234567890"),
		Number:     big.NewInt(int64(999)),
		ParentHash: common.HexToHash("0x9876543210987654321098765432109876543210"),
	}

	signer := common.HexToAddress("0x1234567890123456789012345678901234567890")
	keyPair, err := falcon.GenerateKeyPair(9)
	if err != nil {
		t.Fatal(err)
	}
	bytesToBeVerified := sigBytes(header)
	signature, err := falcon.Sign(bytesToBeVerified, keyPair.PrivateKey, falconType)
	if err != nil {
		t.Fatal(err)
	}
	// mock this map
	addr2FalconPk[signer] = keyPair.PublicKey

	err = verifyFalconSignature(bytesToBeVerified, signature, signer)
	if err != nil {
		t.Fatal(err)
	}
}
