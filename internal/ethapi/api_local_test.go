// Copyright 2026 The go-ethereum Authors
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

package ethapi

import (
	"context"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common/hexutil"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/rpc"
	"github.com/stretchr/testify/require"
)

type debugTransportBackend struct {
	*backendMock
	db ethdb.Database
}

func newDebugTransportBackend(t *testing.T) *debugTransportBackend {
	t.Helper()

	db := rawdb.NewMemoryDatabase()
	require.NoError(t, db.Put([]byte("debug-key"), []byte("debug-value")))

	return &debugTransportBackend{
		backendMock: newBackendMock(),
		db:          db,
	}
}

func (b *debugTransportBackend) ChainDb() ethdb.Database {
	return b.db
}

func TestDebugSetHeadTransportExposure(t *testing.T) {
	backend := newDebugTransportBackend(t)
	apis := GetAPIs(backend, nil)

	openServer := rpc.NewServer()
	localServer := rpc.NewServer()
	for _, api := range apis {
		if !api.Local {
			require.NoError(t, openServer.RegisterName(api.Namespace, api.Service))
		}
		require.NoError(t, localServer.RegisterName(api.Namespace, api.Service))
	}

	openClient := rpc.DialInProc(openServer)
	defer openClient.Close()
	localClient := rpc.DialInProc(localServer)
	defer localClient.Close()

	ctx := context.Background()
	var block string
	err := openClient.CallContext(ctx, &block, "debug_printBlock", uint64(0))
	if isMethodNotFound(err) {
		t.Fatalf("expected debug_printBlock to remain exposed on open RPC, got %v", err)
	}

	var dbValue hexutil.Bytes
	err = openClient.CallContext(ctx, &dbValue, "debug_dbGet", "debug-key")
	require.NoError(t, err)
	require.Equal(t, hexutil.Bytes([]byte("debug-value")), dbValue)

	err = openClient.CallContext(ctx, nil, "debug_setHead", hexutil.Uint64(0))
	if !isMethodNotFound(err) {
		t.Fatalf("expected debug_setHead to be hidden from open RPC, got %v", err)
	}

	err = localClient.CallContext(ctx, nil, "debug_setHead", hexutil.Uint64(0))
	require.NoError(t, err)
}

func isMethodNotFound(err error) bool {
	rpcErr, ok := err.(rpc.Error)
	return ok && rpcErr.ErrorCode() == -32601
}
