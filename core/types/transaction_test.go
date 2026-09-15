// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package types

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/XinFinOrg/XDPoSChain/rlp"
	"github.com/holiman/uint256"
)

// The values in those tests are from the Transaction Tests
// at github.com/ethereum/tests.
var (
	testAddr = common.HexToAddress("b94f5374fce5edbc8e2a8697c15331677e6ebf0b")

	emptyTx = NewTransaction(
		0,
		common.HexToAddress("095e7baea6a6c7c4c2dfeb977efac326af552d87"),
		big.NewInt(0), 0, big.NewInt(0),
		nil,
	)

	rightvrsTx, _ = NewTransaction(
		3,
		testAddr,
		big.NewInt(10),
		2000,
		big.NewInt(1),
		common.FromHex("5544"),
	).WithSignature(
		HomesteadSigner{},
		common.Hex2Bytes("98ff921201554726367d2be8c804a7ff89ccf285ebc57dff8ae4c44b9c19ac4a8887321be575c8095f789dd4c743dfe42c1820f9231f98a962b210e3ac2452a301"),
	)

	emptyEip2718Tx = NewTx(&AccessListTx{
		ChainID:  big.NewInt(1),
		Nonce:    3,
		To:       &testAddr,
		Value:    big.NewInt(10),
		Gas:      25000,
		GasPrice: big.NewInt(1),
		Data:     common.FromHex("5544"),
	})

	signedEip2718Tx, _ = emptyEip2718Tx.WithSignature(
		NewEIP2930Signer(big.NewInt(1)),
		common.Hex2Bytes("c9519f4f2b30335884581971573fadf60c6204f59a911df35ee8a540456b266032f1e8e2c5dd761f9e4f88f41c8310aeaba26a8bfcdacfedfa12ec3862d3752101"),
	)
)

// TestDecodeEmptyTypedTx tests decode empty typed tx.
func TestDecodeEmptyTypedTx(t *testing.T) {
	input := []byte{0x80}
	var tx Transaction
	err := rlp.DecodeBytes(input, &tx)
	if err != errShortTypedTx {
		t.Fatal("wrong error:", err)
	}
}

// TestTransactionSigHash tests transaction sig hash.
func TestTransactionSigHash(t *testing.T) {
	var homestead HomesteadSigner
	if homestead.Hash(emptyTx) != common.HexToHash("c775b99e7ad12f50d819fcd602390467e28141316969f4b57f0626f74fe3b386") {
		t.Errorf("empty transaction hash mismatch, got %x", emptyTx.Hash())
	}
	if homestead.Hash(rightvrsTx) != common.HexToHash("fe7a79529ed5f7c3375d06b26b186a8644e0e16c373d7a12be41c62d6042b77a") {
		t.Errorf("RightVRS transaction hash mismatch, got %x", rightvrsTx.Hash())
	}
}

// TestTransactionEncode tests transaction encode.
func TestTransactionEncode(t *testing.T) {
	txb, err := rlp.EncodeToBytes(rightvrsTx)
	if err != nil {
		t.Fatalf("encode error: %v", err)
	}
	should := common.FromHex("f86103018207d094b94f5374fce5edbc8e2a8697c15331677e6ebf0b0a8255441ca098ff921201554726367d2be8c804a7ff89ccf285ebc57dff8ae4c44b9c19ac4aa08887321be575c8095f789dd4c743dfe42c1820f9231f98a962b210e3ac2452a3")
	if !bytes.Equal(txb, should) {
		t.Errorf("encoded RLP mismatch, got %x", txb)
	}
}

// TestEIP2718TransactionSigHash tests eip 2718 transaction sig hash.
func TestEIP2718TransactionSigHash(t *testing.T) {
	s := NewEIP2930Signer(big.NewInt(1))
	if s.Hash(emptyEip2718Tx) != common.HexToHash("49b486f0ec0a60dfbbca2d30cb07c9e8ffb2a2ff41f29a1ab6737475f6ff69f3") {
		t.Errorf("empty EIP-2718 transaction hash mismatch, got %x", s.Hash(emptyEip2718Tx))
	}
	if s.Hash(signedEip2718Tx) != common.HexToHash("49b486f0ec0a60dfbbca2d30cb07c9e8ffb2a2ff41f29a1ab6737475f6ff69f3") {
		t.Errorf("signed EIP-2718 transaction hash mismatch, got %x", s.Hash(signedEip2718Tx))
	}
}

// This test checks signature operations on access list transactions.
func TestEIP2930Signer(t *testing.T) {
	var (
		key, _  = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		keyAddr = crypto.PubkeyToAddress(key.PublicKey)
		signer1 = NewEIP2930Signer(big.NewInt(1))
		signer2 = NewEIP2930Signer(big.NewInt(2))
		tx0     = NewTx(&AccessListTx{Nonce: 1})
		tx1     = NewTx(&AccessListTx{ChainID: big.NewInt(1), Nonce: 1})
		tx2, _  = SignNewTx(key, signer2, &AccessListTx{ChainID: big.NewInt(2), Nonce: 1})
	)

	tests := []struct {
		tx             *Transaction
		signer         Signer
		wantSignerHash common.Hash
		wantSenderErr  error
		wantSignErr    error
		wantHash       common.Hash // after signing
	}{
		{
			tx:             tx0,
			signer:         signer1,
			wantSignerHash: common.HexToHash("846ad7672f2a3a40c1f959cd4a8ad21786d620077084d84c8d7c077714caa139"),
			wantSenderErr:  ErrInvalidChainId,
			wantHash:       common.HexToHash("1ccd12d8bbdb96ea391af49a35ab641e219b2dd638dea375f2bc94dd290f2549"),
		},
		{
			tx:             tx1,
			signer:         signer1,
			wantSenderErr:  ErrInvalidSig,
			wantSignerHash: common.HexToHash("846ad7672f2a3a40c1f959cd4a8ad21786d620077084d84c8d7c077714caa139"),
			wantHash:       common.HexToHash("1ccd12d8bbdb96ea391af49a35ab641e219b2dd638dea375f2bc94dd290f2549"),
		},
		{
			// This checks what happens when trying to sign an unsigned tx for the wrong chain.
			tx:             tx1,
			signer:         signer2,
			wantSenderErr:  ErrInvalidChainId,
			wantSignerHash: common.HexToHash("367967247499343401261d718ed5aa4c9486583e4d89251afce47f4a33c33362"),
			wantSignErr:    ErrInvalidChainId,
		},
		{
			// This checks what happens when trying to re-sign a signed tx for the wrong chain.
			tx:             tx2,
			signer:         signer1,
			wantSenderErr:  ErrInvalidChainId,
			wantSignerHash: common.HexToHash("846ad7672f2a3a40c1f959cd4a8ad21786d620077084d84c8d7c077714caa139"),
			wantSignErr:    ErrInvalidChainId,
		},
	}

	for i, test := range tests {
		sigHash := test.signer.Hash(test.tx)
		if sigHash != test.wantSignerHash {
			t.Errorf("test %d: wrong sig hash: got %x, want %x", i, sigHash, test.wantSignerHash)
		}
		sender, err := Sender(test.signer, test.tx)
		if !errors.Is(err, test.wantSenderErr) {
			t.Errorf("test %d: wrong Sender error %q", i, err)
		}
		if err == nil && sender != keyAddr {
			t.Errorf("test %d: wrong sender address %x", i, sender)
		}
		signedTx, err := SignTx(test.tx, test.signer, key)
		if !errors.Is(err, test.wantSignErr) {
			t.Fatalf("test %d: wrong SignTx error %q", i, err)
		}
		if signedTx != nil {
			if signedTx.Hash() != test.wantHash {
				t.Errorf("test %d: wrong tx hash after signing: got %x, want %x", i, signedTx.Hash(), test.wantHash)
			}
		}
	}
}

// TestEIP2718TransactionEncode tests eip 2718 transaction encode.
func TestEIP2718TransactionEncode(t *testing.T) {
	// RLP representation
	{
		have, err := rlp.EncodeToBytes(signedEip2718Tx)
		if err != nil {
			t.Fatalf("encode error: %v", err)
		}
		want := common.FromHex("b86601f8630103018261a894b94f5374fce5edbc8e2a8697c15331677e6ebf0b0a825544c001a0c9519f4f2b30335884581971573fadf60c6204f59a911df35ee8a540456b2660a032f1e8e2c5dd761f9e4f88f41c8310aeaba26a8bfcdacfedfa12ec3862d37521")
		if !bytes.Equal(have, want) {
			t.Errorf("encoded RLP mismatch, got %x", have)
		}
	}
	// Binary representation
	{
		have, err := signedEip2718Tx.MarshalBinary()
		if err != nil {
			t.Fatalf("encode error: %v", err)
		}
		want := common.FromHex("01f8630103018261a894b94f5374fce5edbc8e2a8697c15331677e6ebf0b0a825544c001a0c9519f4f2b30335884581971573fadf60c6204f59a911df35ee8a540456b2660a032f1e8e2c5dd761f9e4f88f41c8310aeaba26a8bfcdacfedfa12ec3862d37521")
		if !bytes.Equal(have, want) {
			t.Errorf("encoded RLP mismatch, got %x", have)
		}
	}
}

func decodeTx(data []byte) (*Transaction, error) {
	var tx Transaction
	t, err := &tx, rlp.Decode(bytes.NewReader(data), &tx)

	return t, err
}

func defaultTestKey() (*ecdsa.PrivateKey, common.Address) {
	key, _ := crypto.HexToECDSA("45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8")
	addr := crypto.PubkeyToAddress(key.PublicKey)
	return key, addr
}

// TestRecipientEmpty tests recipient empty.
func TestRecipientEmpty(t *testing.T) {
	_, addr := defaultTestKey()
	tx, err := decodeTx(common.Hex2Bytes("f8498080808080011ca09b16de9d5bdee2cf56c28d16275a4da68cd30273e2525f3959f5d62557489921a0372ebd8fb3345f7db7b5a86d42e24d36e983e259b0664ceb8c227ec9af572f3d"))
	if err != nil {
		t.Fatal(err)
	}

	from, err := Sender(HomesteadSigner{}, tx)
	if err != nil {
		t.Fatal(err)
	}
	if addr != from {
		t.Error("derived address doesn't match")
	}
}

// TestRecipientNormal tests recipient normal.
func TestRecipientNormal(t *testing.T) {
	_, addr := defaultTestKey()

	tx, err := decodeTx(common.Hex2Bytes("f85d80808094000000000000000000000000000000000000000080011ca0527c0d8f5c63f7b9f41324a7c8a563ee1190bcbf0dac8ab446291bdbf32f5c79a0552c4ef0a09a04395074dab9ed34d3fbfb843c2f2546cc30fe89ec143ca94ca6"))
	if err != nil {
		t.Fatal(err)
	}

	from, err := Sender(HomesteadSigner{}, tx)
	if err != nil {
		t.Fatal(err)
	}

	if addr != from {
		t.Fatal("derived address doesn't match")
	}
}

// TestTransactionJSON tests transaction json.
func TestTransactionJSON(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("could not generate key: %v", err)
	}
	signer := NewEIP155Signer(common.Big1)

	for i := uint64(0); i < 25; i++ {
		var tx *Transaction
		switch i % 2 {
		case 0:
			tx = NewTransaction(i, common.Address{1}, common.Big0, 1, common.Big2, []byte("abcdef"))
		case 1:
			tx = NewContractCreation(i, common.Big0, 1, common.Big2, []byte("abcdef"))
		}

		tx, err := SignTx(tx, signer, key)
		if err != nil {
			t.Fatalf("could not sign transaction: %v", err)
		}

		data, err := json.Marshal(tx)
		if err != nil {
			t.Errorf("json.Marshal failed: %v", err)
		}

		var parsedTx *Transaction
		if err := json.Unmarshal(data, &parsedTx); err != nil {
			t.Errorf("json.Unmarshal failed: %v", err)
		}

		// compare nonce, price, gaslimit, recipient, amount, payload, V, R, S
		if tx.Hash() != parsedTx.Hash() {
			t.Errorf("parsed tx differs from original tx, want %v, got %v", tx, parsedTx)
		}
		if tx.ChainId().Cmp(parsedTx.ChainId()) != 0 {
			t.Errorf("invalid chain id, want %d, got %d", tx.ChainId(), parsedTx.ChainId())
		}
	}
}

// TestTransactionCoding tests transaction coding.
func TestTransactionCoding(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("could not generate key: %v", err)
	}
	var (
		signer    = NewEIP2930Signer(common.Big1)
		addr      = common.HexToAddress("0x0000000000000000000000000000000000000001")
		recipient = common.HexToAddress("095e7baea6a6c7c4c2dfeb977efac326af552d87")
		accesses  = AccessList{{Address: addr, StorageKeys: []common.Hash{{0}}}}
	)
	for i := uint64(0); i < 500; i++ {
		var txdata TxData
		switch i % 5 {
		case 0:
			// Legacy tx.
			txdata = &LegacyTx{
				Nonce:    i,
				To:       &recipient,
				Gas:      1,
				GasPrice: big.NewInt(2),
				Data:     []byte("abcdef"),
			}
		case 1:
			// Legacy tx contract creation.
			txdata = &LegacyTx{
				Nonce:    i,
				Gas:      1,
				GasPrice: big.NewInt(2),
				Data:     []byte("abcdef"),
			}
		case 2:
			// Tx with non-zero access list.
			txdata = &AccessListTx{
				ChainID:    big.NewInt(1),
				Nonce:      i,
				To:         &recipient,
				Gas:        123457,
				GasPrice:   big.NewInt(10),
				AccessList: accesses,
				Data:       []byte("abcdef"),
			}
		case 3:
			// Tx with empty access list.
			txdata = &AccessListTx{
				ChainID:  big.NewInt(1),
				Nonce:    i,
				To:       &recipient,
				Gas:      123457,
				GasPrice: big.NewInt(10),
				Data:     []byte("abcdef"),
			}
		case 4:
			// Contract creation with access list.
			txdata = &AccessListTx{
				ChainID:    big.NewInt(1),
				Nonce:      i,
				Gas:        123457,
				GasPrice:   big.NewInt(10),
				AccessList: accesses,
			}
		}
		tx, err := SignNewTx(key, signer, txdata)
		if err != nil {
			t.Fatalf("could not sign transaction: %v", err)
		}
		// RLP
		parsedTx, err := encodeDecodeBinary(tx)
		if err != nil {
			t.Fatal(err)
		}
		assertEqual(parsedTx, tx)

		// JSON
		parsedTx, err = encodeDecodeJSON(tx)
		if err != nil {
			t.Fatal(err)
		}
		assertEqual(parsedTx, tx)
	}
}

func encodeDecodeJSON(tx *Transaction) (*Transaction, error) {
	data, err := json.Marshal(tx)
	if err != nil {
		return nil, fmt.Errorf("json encoding failed: %v", err)
	}
	var parsedTx = &Transaction{}
	if err := json.Unmarshal(data, &parsedTx); err != nil {
		return nil, fmt.Errorf("json decoding failed: %v", err)
	}
	return parsedTx, nil
}

func encodeDecodeBinary(tx *Transaction) (*Transaction, error) {
	data, err := tx.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("rlp encoding failed: %v", err)
	}
	var parsedTx = &Transaction{}
	if err := parsedTx.UnmarshalBinary(data); err != nil {
		return nil, fmt.Errorf("rlp decoding failed: %v", err)
	}
	return parsedTx, nil
}

func assertEqual(orig *Transaction, cpy *Transaction) error {
	// compare nonce, price, gaslimit, recipient, amount, payload, V, R, S
	if want, got := orig.Hash(), cpy.Hash(); want != got {
		return fmt.Errorf("parsed tx differs from original tx, want %v, got %v", want, got)
	}
	if want, got := orig.ChainId(), cpy.ChainId(); want.Cmp(got) != 0 {
		return fmt.Errorf("invalid chain id, want %d, got %d", want, got)
	}
	if orig.AccessList() != nil {
		if !reflect.DeepEqual(orig.AccessList(), cpy.AccessList()) {
			return errors.New("access list wrong!")
		}
	}
	return nil
}

// TestTransactionSizes tests transaction sizes.
func TestTransactionSizes(t *testing.T) {
	signer := NewLondonSigner(big.NewInt(123))
	key, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	to := common.HexToAddress("0x01")
	for i, txdata := range []TxData{
		&AccessListTx{
			ChainID:  big.NewInt(123),
			Nonce:    0,
			To:       nil,
			Value:    big.NewInt(1000),
			Gas:      21000,
			GasPrice: big.NewInt(100000),
		},
		&LegacyTx{
			Nonce:    1,
			GasPrice: big.NewInt(500),
			Gas:      1000000,
			To:       &to,
			Value:    big.NewInt(1),
		},
		&AccessListTx{
			ChainID:  big.NewInt(123),
			Nonce:    1,
			GasPrice: big.NewInt(500),
			Gas:      1000000,
			To:       &to,
			Value:    big.NewInt(1),
			AccessList: AccessList{
				AccessTuple{
					Address:     common.HexToAddress("0x01"),
					StorageKeys: []common.Hash{common.HexToHash("0x01")},
				}},
		},
		&DynamicFeeTx{
			ChainID:   big.NewInt(123),
			Nonce:     1,
			Gas:       1000000,
			To:        &to,
			Value:     big.NewInt(1),
			GasTipCap: big.NewInt(500),
			GasFeeCap: big.NewInt(500),
		},
	} {
		tx, err := SignNewTx(key, signer, txdata)
		if err != nil {
			t.Fatalf("test %d: %v", i, err)
		}
		bin, _ := tx.MarshalBinary()

		// Check initial calc
		if have, want := int(tx.Size()), len(bin); have != want {
			t.Errorf("test %d: size wrong, have %d want %d", i, have, want)
		}
		// Check cached version too
		if have, want := int(tx.Size()), len(bin); have != want {
			t.Errorf("test %d: (cached) size wrong, have %d want %d", i, have, want)
		}
		// Check unmarshalled version too
		utx := new(Transaction)
		if err := utx.UnmarshalBinary(bin); err != nil {
			t.Fatalf("test %d: failed to unmarshal tx: %v", i, err)
		}
		if have, want := int(utx.Size()), len(bin); have != want {
			t.Errorf("test %d: (unmarshalled) size wrong, have %d want %d", i, have, want)
		}
	}
}

// BenchmarkEffectiveGasTipCmp benchmarks effective gas tip cmp.
func BenchmarkEffectiveGasTipCmp(b *testing.B) {
	signer := LatestSigner(params.TestChainConfig)
	key, _ := crypto.GenerateKey()
	txdata := &DynamicFeeTx{
		ChainID:   big.NewInt(1),
		Nonce:     0,
		GasTipCap: big.NewInt(2000000000),
		GasFeeCap: big.NewInt(3000000000),
		Gas:       21000,
		To:        &common.Address{},
		Value:     big.NewInt(0),
		Data:      nil,
	}
	tx, _ := SignNewTx(key, signer, txdata)
	other, _ := SignNewTx(key, signer, txdata)
	baseFee := uint256.NewInt(1000000000) // 1 gwei

	b.Run("Original", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			tx.EffectiveGasTipCmp(other, baseFee)
		}
	})
}

// TestLatestSignerUsesModernSignerForXDPoSMockChainConfig tests latest signer uses modern signer for xd po s mock chain config.
func TestLatestSignerUsesModernSignerForXDPoSMockChainConfig(t *testing.T) {
	signer := LatestSigner(params.TestXDPoSMockChainConfig)
	if _, ok := signer.(pragueSigner); !ok {
		t.Fatalf("unexpected signer type %T, want pragueSigner for TestXDPoSMockChainConfig", signer)
	}
}

// TestLatestSignerNilConfigPanics tests latest signer fails fast for nil config.
func TestLatestSignerNilConfigPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic for nil config")
		}
	}()
	LatestSigner(nil)

}

// TestMakeSignerNilConfigPanics tests make signer fails fast for nil config.
func TestMakeSignerNilConfigPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic for nil config")
		}
	}()
	MakeSigner(nil, big.NewInt(0))
}

// TestEffectiveGasTipIntCmpMatchesBigIntSemantics tests effective gas tip int cmp matches big int semantics.
func TestEffectiveGasTipIntCmpMatchesBigIntSemantics(t *testing.T) {
	tests := []struct {
		name     string
		tipCap   int64
		feeCap   int64
		baseFee  *uint256.Int
		otherTip uint64
	}{
		{
			name:     "nil base fee",
			tipCap:   20,
			feeCap:   100,
			baseFee:  nil,
			otherTip: 10,
		},
		{
			name:     "regular effective tip",
			tipCap:   20,
			feeCap:   100,
			baseFee:  uint256.NewInt(50),
			otherTip: 19,
		},
		{
			name:     "fee cap below base fee",
			tipCap:   20,
			feeCap:   40,
			baseFee:  uint256.NewInt(50),
			otherTip: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tx := NewTx(&DynamicFeeTx{
				ChainID:   big.NewInt(1),
				Nonce:     0,
				GasTipCap: big.NewInt(tc.tipCap),
				GasFeeCap: big.NewInt(tc.feeCap),
				Gas:       21000,
				To:        &common.Address{},
				Value:     big.NewInt(0),
			})
			other := uint256.NewInt(tc.otherTip)

			got := tx.EffectiveGasTipIntCmp(other, tc.baseFee)

			var want int
			if tc.baseFee == nil {
				want = tx.GasTipCapIntCmp(other.ToBig())
			} else {
				want = tx.EffectiveGasTipValue(tc.baseFee.ToBig()).Cmp(other.ToBig())
			}

			if got != want {
				t.Fatalf("unexpected comparison result: got %d, want %d", got, want)
			}
		})
	}
}

// TestEffectiveGasTipNilBaseFeeReturnsTipCap tests effective gas tip nil base fee returns tip cap.
func TestEffectiveGasTipNilBaseFeeReturnsTipCap(t *testing.T) {
	tx := NewTx(&DynamicFeeTx{
		ChainID:   big.NewInt(1),
		Nonce:     0,
		GasTipCap: big.NewInt(20),
		GasFeeCap: big.NewInt(1),
		Gas:       21000,
		To:        &common.Address{},
		Value:     big.NewInt(0),
	})

	tip, err := tx.EffectiveGasTip(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tip.Cmp(big.NewInt(20)) != 0 {
		t.Fatalf("unexpected effective tip: got %v, want %v", tip, 20)
	}
}

// TestCalcEffectiveGasTipClearsDstOnFeeCapBelowBaseFee tests calc effective gas tip clears dst on fee cap below base fee.
func TestCalcEffectiveGasTipClearsDstOnFeeCapBelowBaseFee(t *testing.T) {
	tx := NewTx(&DynamicFeeTx{
		ChainID:   big.NewInt(1),
		Nonce:     0,
		GasTipCap: big.NewInt(20),
		GasFeeCap: big.NewInt(40),
		Gas:       21000,
		To:        &common.Address{},
		Value:     big.NewInt(0),
	})
	dst := uint256.NewInt(123)

	err := tx.calcEffectiveGasTip(dst, uint256.NewInt(50))
	if !errors.Is(err, ErrGasFeeCapTooLow) {
		t.Fatalf("unexpected error: got %v, want %v", err, ErrGasFeeCapTooLow)
	}
	if dst.Sign() != 0 {
		t.Fatalf("expected dst to be cleared on error, got %v", dst)
	}
}

// TestIsNonEVMTx tests the IsNonEVMTx method to ensure it correctly identifies
// transactions that are handled by native code rather than EVM execution.
func TestIsNonEVMTx(t *testing.T) {
	tests := []struct {
		name     string
		tx       *Transaction
		expected bool
	}{
		{
			name:     "nil transaction",
			tx:       nil,
			expected: false,
		},
		{
			name:     "contract creation (nil to)",
			expected: false,
		},
		{
			name: "regular transaction",
			tx: NewTransaction(
				0,
				common.HexToAddress("0x1234567890123456789012345678901234567890"),
				big.NewInt(0),
				0,
				big.NewInt(0),
				nil,
			),
			expected: false,
		},
		{
			name: "BlockSignersBinary transaction",
			tx: NewTransaction(
				0,
				common.BlockSignersBinary,
				big.NewInt(0),
				0,
				big.NewInt(0),
				nil,
			),
			expected: true,
		},
		{
			name: "XDCXAddrBinary transaction",
			tx: NewTransaction(
				0,
				common.XDCXAddrBinary,
				big.NewInt(0),
				0,
				big.NewInt(0),
				nil,
			),
			expected: true,
		},
		{
			name: "TradingStateAddrBinary transaction",
			tx: NewTransaction(
				0,
				common.TradingStateAddrBinary,
				big.NewInt(0),
				0,
				big.NewInt(0),
				nil,
			),
			expected: true,
		},
		{
			name: "XDCXLendingAddressBinary transaction",
			tx: NewTransaction(
				0,
				common.XDCXLendingAddressBinary,
				big.NewInt(0),
				0,
				big.NewInt(0),
				nil,
			),
			expected: true,
		},
		{
			name: "XDCXLendingFinalizedTradeAddressBinary transaction",
			tx: NewTransaction(
				0,
				common.XDCXLendingFinalizedTradeAddressBinary,
				big.NewInt(0),
				0,
				big.NewInt(0),
				nil,
			),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Handle the contract creation case separately
			var tx *Transaction
			if tt.name == "contract creation (nil to)" {
				tx = NewContractCreation(0, big.NewInt(0), 0, big.NewInt(0), nil)
			} else {
				tx = tt.tx
			}

			result := tx.IsNonEVMTx()
			if result != tt.expected {
				t.Errorf("IsNonEVMTx() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestApplyTransactionClassifiersRequireConfiguredSystemAddresses tests apply
// transaction classifiers require the configured non-zero target address.
func TestApplyTransactionClassifiersRequireConfiguredSystemAddresses(t *testing.T) {
	tests := []struct {
		name        string
		method      string
		setConfig   func(*params.ChainConfig, common.Address)
		classify    func(*Transaction, *params.ChainConfig) bool
		addressName string
		address     common.Address
	}{
		{
			name:   "XDCX",
			method: common.XDCXApplyMethod,
			setConfig: func(config *params.ChainConfig, address common.Address) {
				config.XDCXListingSMC = address
			},
			classify:    (*Transaction).IsXDCXApplyTransaction,
			addressName: "XDCXListingSMC",
			address:     common.HexToAddress("0x1000000000000000000000000000000000000001"),
		},
		{
			name:   "XDCZ",
			method: common.XDCZApplyMethod,
			setConfig: func(config *params.ChainConfig, address common.Address) {
				config.TRC21IssuerSMC = address
			},
			classify:    (*Transaction).IsXDCZApplyTransaction,
			addressName: "TRC21IssuerSMC",
			address:     common.HexToAddress("0x2000000000000000000000000000000000000002"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := append(common.FromHex(tt.method), make([]byte, 32)...)
			zeroAddressTx := NewTransaction(
				0,
				common.Address{},
				big.NewInt(0),
				21000,
				big.NewInt(1),
				data,
			)

			if tt.classify(zeroAddressTx, nil) {
				t.Fatalf("expected nil config to not classify zero-address transaction as %s apply", tt.name)
			}

			zeroConfig := &params.ChainConfig{}
			if tt.classify(zeroAddressTx, zeroConfig) {
				t.Fatalf("expected zero %s address to not classify zero-address transaction as %s apply", tt.addressName, tt.name)
			}

			config := &params.ChainConfig{}
			tt.setConfig(config, tt.address)
			matchingTx := NewTransaction(
				0,
				tt.address,
				big.NewInt(0),
				21000,
				big.NewInt(1),
				data,
			)
			if !tt.classify(matchingTx, config) {
				t.Fatalf("expected non-zero configured %s to match %s apply transaction", tt.addressName, tt.name)
			}
		})
	}
}
