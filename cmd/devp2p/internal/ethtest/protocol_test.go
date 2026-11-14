package ethtest

import (
	"testing"

	ethproto "github.com/XinFinOrg/XDPoSChain/eth/protocols/eth"
)

func TestGetProtoXdcFrameCodes(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("getProto panicked on an XDC frame: %v", r)
		}
	}()
	for _, code := range xdcRelayFrameCodes {
		frame := protoOffset(ethProto) + code
		if got := getProto(frame); got != unknownProto {
			t.Errorf("getProto(%d) = %v, want unknownProto", frame, got)
		}
	}
}

func TestGetProtoWindowBoundaries(t *testing.T) {
	for _, tt := range []struct {
		code uint64
		want Proto
	}{
		{0, baseProto},
		{baseProtoLen - 1, baseProto},
		{baseProtoLen, ethProto},
		{baseProtoLen + ethProtoLen - 1, ethProto},
		{baseProtoLen + ethProtoLen, snapProto},
		{baseProtoLen + ethProtoLen + snapProtoLen - 1, snapProto},
		{baseProtoLen + ethProtoLen + snapProtoLen, unknownProto},
		{protoOffset(ethProto) + ethproto.VoteMsg - 1, unknownProto},
		{protoOffset(ethProto) + ethproto.PooledTransactionsMsg + 1, unknownProto},
		{^uint64(0), unknownProto},
	} {
		if got := getProto(tt.code); got != tt.want {
			t.Errorf("getProto(%d) = %v, want %v", tt.code, got, tt.want)
		}
	}
}
