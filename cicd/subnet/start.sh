#!/bin/bash
# Starts a subnet node. It takes the environment of the XDC-Subnet image
# (xinfinorg/xdcsubnets), so subnet deployments, such as the ones the subnet
# generator writes, can run this image unchanged:
#
#   PRIVATE_KEY            hex key of the node (required on first start)
#   NETWORK_ID             network id (default 102)
#   BOOTNODES              comma separated enode URLs
#   PORT, RPCPORT, WSPORT  p2p, HTTP-RPC and WS-RPC ports (30303, 8545, 8555)
#   RPC_API                HTTP and WS API modules (default db,eth,net,txpool,web3,XDPoS)
#   STATS_SERVICE_ADDRESS  ethstats host:port, with STATS_SECRET and INSTANCE_NAME
#   SYNC_MODE, GC_MODE, LOG_LEVEL, GASPRICE, GASLIMIT, EXTIP
#
# The genesis is read from /work/genesis.json and must enable the subnet rules
# with "isSubnet": true in its XDPoS config.
set -e

DATA_DIR=/work/xdcchain
GENESIS=/work/genesis.json

if [ ! -f "$GENESIS" ]; then
  echo "No genesis at $GENESIS"
  exit 1
fi

if [ ! -d "$DATA_DIR/XDC/chaindata" ]; then
  if [ -z "$PRIVATE_KEY" ]; then
    echo "PRIVATE_KEY environment variable has not been set."
    exit 1
  fi
  echo "${PRIVATE_KEY#0x}" > /tmp/key
  wallet=$(XDC account import --password /work/.pwd --datadir "$DATA_DIR" /tmp/key | awk -F '[{}]' '{print $2}')
  rm -f /tmp/key
  XDC --datadir "$DATA_DIR" init "$GENESIS" 2>&1 | tee "$DATA_DIR/init.log"
else
  wallet=$(XDC account list --datadir "$DATA_DIR" | head -n 1 | awk -F '[{}]' '{print $2}')
fi

args=(
  --datadir "$DATA_DIR"
  --networkid "${NETWORK_ID:-102}"
  --port "${PORT:-30303}"
  --syncmode "${SYNC_MODE:-full}"
  --gcmode "${GC_MODE:-full}"
  --verbosity "${LOG_LEVEL:-3}"
  --http --http-addr 0.0.0.0 --http-port "${RPCPORT:-8545}" --http-corsdomain "*" --http-vhosts "*"
  --http-api "${RPC_API:-db,eth,net,txpool,web3,XDPoS}"
  --ws --ws-addr 0.0.0.0 --ws-port "${WSPORT:-8555}" --ws-origins "*"
  --ws-api "${RPC_API:-db,eth,net,txpool,web3,XDPoS}"
  --unlock "$wallet" --password /work/.pwd --mine
  --miner-gasprice "${GASPRICE:-1}"
  --miner-gaslimit "${GASLIMIT:-420000000}"
)
if [ -n "$BOOTNODES" ]; then
  args+=(--bootnodes "$BOOTNODES")
fi
if [ -n "$EXTIP" ]; then
  args+=(--nat "extip:$EXTIP")
fi
if [ -n "$STATS_SERVICE_ADDRESS" ]; then
  name="$wallet"
  if [ -n "$INSTANCE_NAME" ]; then
    name="$INSTANCE_NAME-$wallet"
  fi
  args+=(--ethstats "$name:${STATS_SECRET:-subnet-stats-server}@$STATS_SERVICE_ADDRESS")
fi

echo "Starting subnet node $wallet"
# exec, so XDC receives the container's stop signal and shuts down cleanly,
# writing its state; behind a pipe the signal would reach this shell instead
# and the node would be killed, losing the state of its recent blocks.
exec XDC "${args[@]}" > >(tee -a "$DATA_DIR/xdc.log") 2>&1
