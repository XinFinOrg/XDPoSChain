package engine_v2

import (
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/falcon"
)

var falconType = falcon.SigCompressed

func verifyFalconSignature(signedBytesToBeVerified []byte, signature types.Signature, signer common.Address) error {
	// mock this map
	addr2FalconPk := make(map[common.Address][]byte)
	addr2FalconPk[signer] = []byte("mock_falcon_pk")

	signerPk := addr2FalconPk[signer]
	err := falcon.Verify(signature, signedBytesToBeVerified, signerPk, falconType)
	if err != nil {
		return err
	}

	return nil
}

func TestFalconSignatureVerify(t *testing.T) {
	err := verifyFalconSignature([]byte("mock_signed_bytes"), types.Signature{}, common.Address{})
	if err != nil {
		t.Fatal(err)
	}
}
