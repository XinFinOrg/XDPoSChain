#!/bin/bash

# A subnet deployment mounts its own genesis at /work/genesis.json and sets no
# NETWORK, like the XDC-Subnet image it replaces.
if [ -z "$NETWORK" ] && [ -f /work/genesis.json ]; then
    NETWORK=subnet
fi

case "$NETWORK" in
    "")
        echo "NETWORK environment variable must be set. Allowed values: mainnet/testnet/devnet/local/subnet"
        exit 1
        ;;
    mainnet|testnet|devnet|local|subnet)
        ;;
    *)
        echo "Invalid NETWORK: $NETWORK. Allowed: mainnet/testnet/devnet/local/subnet"
        exit 1
        ;;
esac

echo "Select to run $NETWORK..."
cp -n /work/"$NETWORK"/* /work

echo "Start Node..."
exec /work/start.sh
