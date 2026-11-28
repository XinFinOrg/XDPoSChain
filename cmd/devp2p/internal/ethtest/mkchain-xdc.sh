#!/usr/bin/env bash
#
# Generates the XDC-compatible fixture chain committed under testdata/xdc/,
# the shared chain model of the rlpx eth-test suite and its local devnet
# (issue #2968). The upstream mkchain.sh fixtures are hive-generated PoS chains
# no XDC node can run; this script emits the XDC shape instead:
#
#   genesis phase: an XDPoS v2 genesis built by puppeth's non-interactive
#                  path (masternodes from testdata/xdc/fixture-keys.json,
#                  genesis contracts deployed, chain id 5152) plus the funded
#                  sender accounts injected into the alloc,
#   chain phase:   a four-node throwaway devnet sealing MKCHAIN_LENGTH real
#                  XDPoS blocks (~2s each), then the chain exported back out
#                  as chain.rlp, headstate.json and txinfo.json.
#
# The committed artifacts under testdata/xdc/ are the fixture's source of
# truth: real BFT seals and timestamps cannot be replayed byte-for-byte, so a
# rerun produces a new chain rather than the committed one. Regenerating means
# recomitting every file together, then re-running the fixture checks:
#
#   go test ./cmd/devp2p/internal/ethtest -run 'TestXDCFixture'
#
# Usage: mkchain-xdc.sh [genesis|chain|all]
# Requires build/bin/{puppeth,XDC,bootnode} (make all) and python3.
#
# Using the committed fixture against a live node (the node and the suite must
# run the exact chain committed above, so both commands take the same files):
#   XDC --datadir <dir> init cmd/devp2p/internal/ethtest/testdata/xdc/genesis.json
#   XDC --datadir <dir> import cmd/devp2p/internal/ethtest/testdata/xdc/chain.rlp
#   XDC --datadir <dir> --networkid 5152 <start flags>
#   build/bin/devp2p rlpx eth-test --node <enode> \
#       --chain cmd/devp2p/internal/ethtest/testdata/xdc

set -eu
set -o pipefail

ROOT=$(cd "$(dirname "$0")/../../../.." && pwd)
PKGDIR="$ROOT/cmd/devp2p/internal/ethtest"
FIXDIR="$PKGDIR/testdata/xdc"
KEYS_FILE="$FIXDIR/fixture-keys.json"

XDC_BIN=${XDC_BIN:-$ROOT/build/bin/XDC}
PUPPETH_BIN=${PUPPETH_BIN:-$ROOT/build/bin/puppeth}
BOOTNODE_BIN=${BOOTNODE_BIN:-$ROOT/build/bin/bootnode}
LENGTH=${MKCHAIN_LENGTH:-600}
WORKDIR=${MKCHAIN_WORKDIR:-/tmp/ethtest-fixture-devnet}
WAIT_TIMEOUT=${MKCHAIN_TIMEOUT:-2700}
CHAIN_ID=5152
PASSWORD=ethtest-fixture
SENDER_FUNDS_WEI=1000000000000000000000000 # 1M XDC per sender account
BASE_PORT=30345
BASE_RPC_PORT=8615
NODES=4

die() { echo "mkchain-xdc: $*" >&2; exit 1; }

for bin in "$XDC_BIN" "$PUPPETH_BIN" "$BOOTNODE_BIN"; do
    [ -x "$bin" ] || die "missing $bin, run make all first"
done
command -v python3 >/dev/null || die "python3 is required"
command -v curl >/dev/null || die "curl is required"
[ -f "$KEYS_FILE" ] || die "missing $KEYS_FILE"

PHASE=${1:-all}
case "$PHASE" in
genesis|chain|all) ;;
*) die "usage: mkchain-xdc.sh [genesis|chain|all]" ;;
esac

if [ "$PHASE" = genesis ] || [ "$PHASE" = all ]; then
    if [ -s "$FIXDIR/genesis.json" ] && [ -z "${MKCHAIN_FORCE:-}" ]; then
        die "$FIXDIR/genesis.json already exists; set MKCHAIN_FORCE=1 to regenerate"
    fi

    echo "== writing puppeth genesis input =="
    INPUT_YAML=$(mktemp /tmp/mkchain-xdc-input.XXXXXX.yaml)
    GENERATED_GENESIS=$(mktemp /tmp/mkchain-xdc-genesis.XXXXXX.json)
    trap 'rm -f "$INPUT_YAML" "$GENERATED_GENESIS"' EXIT
    python3 - "$KEYS_FILE" "$INPUT_YAML" "$CHAIN_ID" <<'PYEOF'
import json, sys

keys_path, yaml_path, chain_id = sys.argv[1], sys.argv[2], sys.argv[3]
keys = json.load(open(keys_path))
masternodes = sorted(keys["masternodes"])
if not masternodes:
    sys.exit("fixture-keys.json carries no masternodes")
lines = [
    "name: ethtest-fixture",
    "chainid: %s" % chain_id,
    "epoch: 900",
    "masternodesowner: %s" % masternodes[0],
    "masternodes:",
]
lines += ["  - %s" % addr for addr in masternodes]
lines += [
    "stakingthreshold: 10000000",
    "rewardyield: 10",
    'foundationwalletaddress: "0x0000000000000000000000000000000000000068"',
]
open(yaml_path, "w").write("\n".join(lines) + "\n")
PYEOF

    echo "== running puppeth (deploys the genesis contracts) =="
    "$PUPPETH_BIN" --network "ethtestfixture$CHAIN_ID" \
        --inpath "$INPUT_YAML" --outpath "$GENERATED_GENESIS" 2>&1 | tail -5

    echo "== injecting senders and writing suite fixtures =="
    python3 - "$GENERATED_GENESIS" "$KEYS_FILE" "$FIXDIR" "$SENDER_FUNDS_WEI" <<'PYEOF'
import json, sys

genesis_path, keys_path, fixdir = sys.argv[1], sys.argv[2], sys.argv[3]
funds = int(sys.argv[4])
genesis = json.load(open(genesis_path))
keys = json.load(open(keys_path))
def canon(addr):
    addr = addr.lower()
    return addr if addr.startswith("0x") else "0x" + addr

# Puppeth writes the alloc keyed by unprefixed addresses, the fixture keys and
# the suite use 0x-prefixed ones. Canonicalise once so the merge below cannot
# add a second spelling of an account: the loader keys the alloc by
# common.UnprefixedAddress, so a duplicate silently drops the first entry.
alloc = {}
for key, value in genesis["alloc"].items():
    addr = canon(key)
    if addr in alloc and alloc[addr] != value:
        sys.exit("genesis alloc carries %s twice with different values" % addr)
    alloc[addr] = value
genesis["alloc"] = alloc

for addr in keys["masternodes"]:
    alloc.setdefault(canon(addr), {"balance": "0x0"})
for addr in keys["senders"]:
    alloc[canon(addr)] = {"balance": hex(funds)}
with open(fixdir + "/genesis.json", "w") as f:
    json.dump(genesis, f, indent=2)
    f.write("\n")
accounts = {addr: {"key": info["key"]} for addr, info in keys["senders"].items()}
with open(fixdir + "/accounts.json", "w") as f:
    json.dump(accounts, f, indent=2)
    f.write("\n")
print("senders funded:", ", ".join(sorted(keys["senders"])))
PYEOF
    echo "== genesis phase done: $FIXDIR/genesis.json + accounts.json =="
    # Drop the temporaries now: the chain phase replaces the EXIT trap below and
    # would otherwise leave them behind on the `all` path.
    rm -f "$INPUT_YAML" "$GENERATED_GENESIS"
    trap - EXIT
fi

if [ "$PHASE" = chain ] || [ "$PHASE" = all ]; then
    [ -s "$FIXDIR/genesis.json" ] || die "no $FIXDIR/genesis.json, run the genesis phase first"

    if [ -e "$WORKDIR" ] && [ -n "$(ls -A "$WORKDIR" 2>/dev/null)" ]; then
        die "$WORKDIR is not empty; remove it or point MKCHAIN_WORKDIR elsewhere"
    fi
    mkdir -p "$WORKDIR/nodes" "$WORKDIR/logs"
    echo "$PASSWORD" > "$WORKDIR/.pwd"
    cp "$FIXDIR/genesis.json" "$WORKDIR/genesis.json"

    PIDS=()
    cleanup() {
        if [ ${#PIDS[@]} -eq 0 ]; then
            return
        fi
        for pid in "${PIDS[@]}"; do
            kill -INT "$pid" 2>/dev/null || true
        done
    }
    trap cleanup EXIT

    echo "== seeding $NODES nodes (keys, accounts, genesis) =="
    for i in $(seq 0 $((NODES - 1))); do
        NAME="pn$i" # pn<i>: private-network node <i>
        DATA="$WORKDIR/nodes/$NAME"
        mkdir -p "$DATA/XDC"

        ADDR=$(python3 -c "
import json
keys = json.load(open('$KEYS_FILE'))['masternodes']
print(sorted(keys)[$i])
")
        KEY_PRIV=$(python3 -c "
import json
keys = json.load(open('$KEYS_FILE'))['masternodes']
print(keys[sorted(keys)[$i]]['key'][2:])
")
        "$XDC_BIN" account import --password "$WORKDIR/.pwd" --datadir "$DATA" \
            <(echo "$KEY_PRIV") >/dev/null
        "$XDC_BIN" init --datadir "$DATA" "$WORKDIR/genesis.json" >/dev/null

        "$BOOTNODE_BIN" -genkey "$DATA/XDC/nodekey"
        "$BOOTNODE_BIN" -nodekey "$DATA/XDC/nodekey" -writeaddress > "$WORKDIR/nodes/$NAME.pub"
        echo "$ADDR" > "$WORKDIR/nodes/$NAME.addr"
    done

    echo "== writing static-node lists =="
    for i in $(seq 0 $((NODES - 1))); do
        DATA="$WORKDIR/nodes/pn$i"
        {
            echo "[Node.P2P]"
            echo "StaticNodes = ["
            for j in $(seq 0 $((NODES - 1))); do
                [ "$j" -eq "$i" ] && continue
                echo "  \"enode://$(cat "$WORKDIR/nodes/pn$j.pub")@127.0.0.1:$((BASE_PORT + j))\","
            done
            echo "]"
        } > "$DATA/XDC/config.toml"
    done

    echo "== starting $NODES devnet nodes =="
    for i in $(seq 0 $((NODES - 1))); do
        NAME="pn$i"
        DATA="$WORKDIR/nodes/$NAME"
        PORT=$((BASE_PORT + i))
        RPC_PORT=$((BASE_RPC_PORT + i))
        ADDR=$(cat "$WORKDIR/nodes/$NAME.addr")
        nohup "$XDC_BIN" \
            --nodiscover \
            --txpool.pricelimit 1 \
            --config "$DATA/XDC/config.toml" \
            --gcmode archive \
            --syncmode full \
            --datadir "$DATA" \
            --networkid "$CHAIN_ID" \
            --verbosity 3 \
            --gasprice "1" \
            --targetgaslimit 4700000 \
            --password "$WORKDIR/.pwd" \
            --unlock "$ADDR" \
            --port "$PORT" \
            --rpc \
            --rpcaddr "127.0.0.1" \
            --rpcport "$RPC_PORT" \
            --rpcapi admin,eth,debug,miner,net,rpc,txpool,web3,XDPoS \
            > "$WORKDIR/logs/$NAME.log" 2>&1 &
        PIDS+=($!)
        echo "node $NAME started (pid $!, port $PORT, rpc $RPC_PORT)"
    done

    echo "== waiting for head block $LENGTH (logs: $WORKDIR/logs) =="
    RPC="http://127.0.0.1:$BASE_RPC_PORT"
    START_TS=$(date +%s)
    while :; do
        sleep 10
        for pid in "${PIDS[@]}"; do
            kill -0 "$pid" 2>/dev/null || die "node pid $pid exited; see $WORKDIR/logs"
        done
        HEAD=$(curl -s -X POST -H 'Content-Type: application/json' \
            --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' "$RPC" \
            | python3 -c "import json,sys; print(int(json.load(sys.stdin)['result'], 16))" 2>/dev/null || echo 0)
        ELAPSED=$(( $(date +%s) - START_TS ))
        echo "head=$HEAD elapsed=${ELAPSED}s"
        if [ "${HEAD:-0}" -ge "$LENGTH" ]; then
            break
        fi
        if [ "$ELAPSED" -gt "$WAIT_TIMEOUT" ]; then
            die "timed out waiting for block $LENGTH (head=$HEAD)"
        fi
    done

    echo "== stopping nodes =="
    for pid in "${PIDS[@]}"; do
        kill -INT "$pid" 2>/dev/null || true
    done
    for pid in "${PIDS[@]}"; do
        for _ in $(seq 1 30); do
            kill -0 "$pid" 2>/dev/null || break
            sleep 1
        done
    done
    trap - EXIT
    for pid in "${PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            die "node pid $pid is still running; refusing to export from a live datadir"
        fi
    done

    echo "== exporting chain.rlp + headstate.json =="
    DATA="$WORKDIR/nodes/pn0"
    # `XDC export <file> <first> <last>` appends (utils.ExportAppendChain opens
    # the target with O_APPEND): exporting straight into the fixture directory
    # would grow the committed chain.rlp with a second copy of blocks 1..600 on
    # every rerun, and the suite loader rejects that at index 600. Export to a
    # scratch file and replace the fixture only after the export succeeded.
    EXPORT_TMP="$WORKDIR/chain.rlp"
    "$XDC_BIN" --datadir "$DATA" --syncmode full export "$EXPORT_TMP" 1 "$LENGTH" 2>&1 | tail -2
    mv -f "$EXPORT_TMP" "$FIXDIR/chain.rlp"
    # XDC's dump defaults to iterative JSON-lines output. The sealing DB
    # records preimages only for accounts touched during sealing, so accounts
    # funded by the genesis alloc come out without an address (secure-key-only)
    # and cannot key the address-mapped state.Dump the suite's loader expects.
    # Keep the address-resolvable accounts; the loader falls back to the
    # genesis alloc for the rest (Chain.Balance).
    "$XDC_BIN" --datadir "$DATA" dump --iterative "$LENGTH" > "$WORKDIR/logs/headstate.jsonl" 2>>"$WORKDIR/logs/dump.log"
    python3 - "$WORKDIR/logs/headstate.jsonl" "$FIXDIR/headstate.json" <<'PYEOF'
import json, sys

lines = [json.loads(line) for line in open(sys.argv[1]) if line.strip()]
root, accounts = lines[0]["root"], {}
for account in lines[1:]:
    address = account.get("address")
    if not address:
        continue
    accounts[address] = account
if not accounts:
    sys.exit("headstate dump carries no address-resolvable accounts")
with open(sys.argv[2], "w") as f:
    json.dump({"root": root, "accounts": accounts}, f, indent=2)
    f.write("\n")
print("headstate accounts:", len(accounts))
PYEOF
    printf '{"tx-largereceipt": null}\n' > "$FIXDIR/txinfo.json"

    python3 - "$FIXDIR" <<'PYEOF'
import json, sys

fixdir = sys.argv[1]
dump = json.load(open(fixdir + "/headstate.json"))
if not dump.get("accounts"):
    sys.exit("headstate.json carries no accounts")
genesis = json.load(open(fixdir + "/genesis.json"))
senders = json.load(open(fixdir + "/accounts.json"))
funded = sum(1 for addr in senders if genesis["alloc"].get(addr, {}).get("balance"))
print("genesis-funded senders:", funded, "/", len(senders))
PYEOF
    echo "== chain phase done: $FIXDIR/{chain.rlp,headstate.json,txinfo.json} =="
fi
