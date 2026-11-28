#!/bin/sh
# Assign packages to shards by name, not by position: shard is
# cksum(import path) % total, so a package added, renamed or removed moves that
# package and nothing else.
#
# Usage:
#   <package list> | build/shard.sh INDEX TOTAL    print the packages of shard INDEX (1-based)
#   <package list> | build/shard.sh --check TOTAL  verify the shards partition the list
#   build/shard.sh --check-groups WORKFLOW PKG...  verify each PKG has lanes 1..n and nothing else does
#
# --check fails on an empty shard, a missing package or a package listed twice.
set -eu

shard_of() {
	# POSIX cksum: independent of machine, locale and list order.
	h=$(printf '%s' "$1" | cksum | cut -d' ' -f1)
	echo $((h % total + 1))
}

assign() {
	while IFS= read -r pkg; do
		[ -n "$pkg" ] || continue
		if [ "$(shard_of "$pkg")" = "$index" ]; then
			echo "$pkg"
		fi
	done
	# A non-matching last iteration would fail the caller's `set -e`.
	return 0
}

if [ "${1-}" = "--check" ]; then
	total=${2:?usage: build/shard.sh --check TOTAL}
	work=$(mktemp -d)
	trap 'rm -rf "$work"' EXIT
	cat > "$work/list"
	[ -s "$work/list" ] || { echo "error: empty package list" >&2; exit 1; }
	# A package listed twice would run twice and leave a shard short; say so first.
	dups=$(sort "$work/list" | uniq -d)
	[ -z "$dups" ] || { echo "error: duplicate packages:" >&2; echo "$dups" >&2; exit 1; }
	sort -u "$work/list" > "$work/want"

	i=1
	while [ "$i" -le "$total" ]; do
		index=$i assign < "$work/list" | sort -u > "$work/shard.$i"
		echo "shard $i/$total: $(wc -l < "$work/shard.$i" | tr -d ' ') packages" >&2
		[ -s "$work/shard.$i" ] || { echo "error: shard $i/$total is empty" >&2; exit 1; }
		i=$((i + 1))
	done

	cat "$work"/shard.* | sort > "$work/got"
	if ! cmp -s "$work/want" "$work/got"; then
		echo "error: the shards do not partition the package list:" >&2
		comm -3 "$work/want" "$work/got" >&2 || true
		exit 1
	fi

	echo "ok: $total shards cover $(wc -l < "$work/want" | tr -d ' ') packages" >&2
	exit 0
fi

# --check-groups reads the workflow file back: the expected package list comes
# from the caller (RACE_HEAVY), every expected package must declare lanes 1..n,
# and no lane may name a package outside the list.
if [ "${1-}" = "--check-groups" ]; then
	workflow=${2:?usage: build/shard.sh --check-groups <workflow> <pkg>...}
	shift 2
	[ "$#" -ge 1 ] || { echo "usage: build/shard.sh --check-groups <workflow> <pkg>..." >&2; exit 1; }
	[ -f "$workflow" ] || { echo "error: $workflow: no such file" >&2; exit 1; }
	expected=""
	for p in "$@"; do
		expected="$expected ${p#./}"
	done
	awk -v expected="$expected" '
	# Fields are read as tokens, so key order and quoting do not matter; a lane
	# still has to be one line.
	{
		pkg = ""; i = ""; n = ""
		line = $0
		gsub(/[{},]/, " ", line)
		gsub(/"/, "", line)
		nf = split(line, tok, /[ \t]+/)
		for (k = 1; k < nf; k++) {
			if (tok[k] == "pkg:") pkg = tok[k + 1]
			else if (tok[k] == "i:") i = tok[k + 1]
			else if (tok[k] == "n:") n = tok[k + 1]
		}
		if (pkg == "" || i == "" || n == "") next
		sub(/^\.\//, "", pkg)
		i += 0; n += 0
		if (n < 1 || i < 1 || i > n) {
			printf "error: %s declares lane %d of %d\n", pkg, i, n > "/dev/stderr"
			bad = 1
		}
		if (pkg in tot && tot[pkg] != n) {
			printf "error: %s declares both n=%d and n=%d\n", pkg, tot[pkg], n > "/dev/stderr"
			bad = 1
		}
		tot[pkg] = n
		if ((pkg SUBSEP i) in seen) {
			printf "error: %s has two lanes numbered %d\n", pkg, i > "/dev/stderr"
			bad = 1
		}
		seen[pkg SUBSEP i] = 1
		cnt[pkg]++
	}
	END {
		sub(/^[ \t]+/, "", expected)
		nexp = split(expected, exps, /[ \t]+/)
		# Every expected package has to be in the matrix.
		for (k = 1; k <= nexp; k++) {
			if (!(exps[k] in tot)) {
				printf "error: %s is in RACE_HEAVY but has no group lanes\n", exps[k] > "/dev/stderr"
				bad = 1
			}
		}
		# No lane may name a package outside it, or that package runs twice.
		for (p in tot) {
			found = 0
			for (k = 1; k <= nexp; k++) {
				if (exps[k] == p) { found = 1; break }
			}
			if (!found) {
				printf "error: %s has group lanes but is not in RACE_HEAVY\n", p > "/dev/stderr"
				bad = 1
			}
		}
		pkgs = 0
		for (p in tot) {
			pkgs++
			if (cnt[p] != tot[p]) {
				printf "error: %s has %d lanes, declares %d\n", p, cnt[p], tot[p] > "/dev/stderr"
				bad = 1
			}
			for (j = 1; j <= tot[p]; j++) {
				if (!((p SUBSEP j) in seen)) {
					printf "error: %s lane %d/%d is missing\n", p, j, tot[p] > "/dev/stderr"
					bad = 1
				}
			}
		}
		if (bad) exit 1
		printf "ok: %d group packages, every lane 1..n present\n", pkgs > "/dev/stderr"
	}' "$workflow"
	exit 0
fi

index=${1:?usage: build/shard.sh INDEX TOTAL}
total=${2:?usage: build/shard.sh INDEX TOTAL}
case "$index$total" in
*[!0-9]*) echo "error: shard index and total must be numbers" >&2; exit 1 ;;
esac
[ "$total" -ge 1 ] && [ "$index" -ge 1 ] && [ "$index" -le "$total" ] ||
	{ echo "error: shard $index is not in 1..$total" >&2; exit 1; }

assign
