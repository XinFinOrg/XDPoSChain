// Scenario-a2 fixture re-encoder (R1-P repair, approved 2026-11-11: synthetic
// replacement fixture signed by the harness key — the original scenario-a2
// signing key is unrecoverable and the frame sighash covers the fee fields).
// Untracked one-off tooling; run: go run ./scengen
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/holiman/uint256"
)

const originalRaw = "06f8ab83013e0380944be69a6c63ab9e5d909bcacc24375a51625b0d40f7cc010380c68261a88261a88080e9028094c67c1da5fd98d573182ca4b0da2686ba7cc1f0ccc8830186a0830493e087038d7ea4c6800080f848f846018080b84100f8efd76b30f53ac46bdaa758281be64e7e6ade06712c5656cbb8f97d339c01ec7361916a44b6e436cd06d17c01f8c788db5b1f00295c4af58b25ba05c179a142cd850165a0bc008504a817c80080c0"

func mustKey(h string) []byte { return common.FromHex(h) }

func main() {
	// Decode the original to clone its exact structure.
	orig := new(types.Transaction)
	if err := orig.UnmarshalBinary(common.FromHex(originalRaw)); err != nil {
		panic(err)
	}
	of := orig.FramePayload()
	fmt.Printf("original: sender=%s nonce=%d maxGas=%d frames=%d sigs=%d\n",
		of.Sender.Hex(), of.Nonce, of.MaxGas(), len(of.Frames), len(of.Signatures))
	for i, fr := range of.Frames {
		tgt := "nil"
		if fr.Target != nil {
			tgt = fr.Target.Hex()
		}
		fmt.Printf("  frame[%d]: mode=%d flags=0x%x target=%s limits=(%d,%d) value=%v data=%dB\n",
			i, fr.Mode, fr.Flags, tgt, fr.Limits.Execution, fr.Limits.State, fr.Value, len(fr.Data))
	}

	// Deep-copy the frames (same scenario structure).
	frames := make([]types.Frame, len(of.Frames))
	for i, fr := range of.Frames {
		frames[i] = fr
		if fr.Target != nil {
			t := *fr.Target
			frames[i].Target = &t
		}
		if fr.Value != nil {
			frames[i].Value = new(uint256.Int).Set(fr.Value)
		}
		if fr.Data != nil {
			frames[i].Data = append([]byte{}, fr.Data...)
		}
	}

	// Synthetic sender: the package-core harness key.
	senderKey, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	if err != nil {
		panic(err)
	}
	senderAddr := crypto.PubkeyToAddress(senderKey.PublicKey)

	// R1-P aggregate fee budget: GasFeeCap = MaxGas × baseFee rounded up to the
	// next gwei boundary (8,746,615,000,000,000 wei); GasTipCap per-gas 6 Gwei.
	feeCap, ok := new(big.Int).SetString("8746615000000000", 10)
	if !ok {
		panic("feeCap")
	}
	ftx := &types.FrameTx{
		ChainID:    uint256.MustFromBig(big.NewInt(81411)),
		Nonce:      of.Nonce,
		Sender:     senderAddr,
		Frames:     frames,
		Signatures: []types.FrameSignature{{Scheme: types.FrameSigSchemeSecp256k1}},
		Fees: types.FrameFees{
			GasTipCap:  uint256.MustFromBig(big.NewInt(6_000_000_000)),
			GasFeeCap:  uint256.MustFromBig(feeCap),
			BlobFeeCap: uint256.NewInt(0),
		},
		BlobHashes: of.BlobHashes,
	}
	digest := ftx.SigHash()
	sig, err := crypto.Sign(digest.Bytes(), senderKey)
	if err != nil {
		panic(err)
	}
	ftx.Signatures[0].Signature = append(append([]byte{}, sig[64]), sig[0:64]...)

	raw, err := types.NewTx(ftx).MarshalBinary()
	if err != nil {
		panic(err)
	}
	fmt.Printf("synthetic: sender=%s hash=%s\n", senderAddr.Hex(), types.NewTx(ftx).Hash().Hex())
	fmt.Printf("synthetic raw (%d bytes, sha256 %x):\n%s\n", len(raw), sha256.Sum256(raw), hex.EncodeToString(raw))

	// Self-check: unmarshal + protocol validation of the produced bytes.
	rt := new(types.Transaction)
	if err := rt.UnmarshalBinary(raw); err != nil {
		panic(err)
	}
	if err := types.ValidateFrameSignatures(rt); err != nil {
		fmt.Println("SELF-CHECK FAIL:", err)
		os.Exit(1)
	}
	fmt.Println("self-check: ValidateFrameSignatures OK")
}
