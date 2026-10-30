#!/bin/sh
# Assign packages to shards by name, not by position.
#
# A package's shard is cksum(import path) % total, so a package added, renamed
# or removed moves that package and nothing else. What this replaces was a line
# range over `go list`: one new package - even one with no test files - shifted
# every boundary after it, and with them the balance the split had been measured
# for. The shift was silent, and the lane that grew was only noticed when it ran
# into its watchdog.
#
# A package whose measured cost would unbalance a shard can still be pinned by
# hand: build/shard-overrides.txt, if it exists, holds "<import path> <shard>"
# one per line and wins over the hash. It is not in the tree because the hash
# has needed no exception yet - the expensive packages each have a lane of their
# own - so create it when a lane's measured time says one package has to move.
# Blank lines and lines starting with # are ignored in it.
#
# Usage:
#   <package list> | build/shard.sh INDEX TOTAL    print the packages of shard INDEX (1-based)
#   <package list> | build/shard.sh --check TOTAL  verify the shards partition the list
#
# --check is what keeps the split honest: it fails on an empty shard, on a
# package that is missing from every shard, and on a package that appears twice.
set -eu

overrides=$(dirname "$0")/shard-overrides.txt

# pinned prints the shard this package is fixed to, or fails if it is not pinned.
pinned() {
	[ -f "$overrides" ] || return 1
	awk -v p="$1" '$1 == p && $2 ~ /^[0-9]+$/ { print $2; found = 1; exit } END { exit !found }' "$overrides"
}

shard_of() {
	if p=$(pinned "$1"); then
		echo "$p"
		return
	fi
	# cksum is POSIX and does not depend on the machine, the locale or the
	# order the list arrives in, which is the whole point of using it here.
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
	# A loop whose last iteration did not match leaves the function with a
	# non-zero status, and the caller runs under `set -e`.
	return 0
}

if [ "${1-}" = "--check" ]; then
	total=${2:?usage: build/shard.sh --check TOTAL}
	work=$(mktemp -d)
	trap 'rm -rf "$work"' EXIT
	cat > "$work/list"
	[ -s "$work/list" ] || { echo "error: empty package list" >&2; exit 1; }
	# De-duplicating both sides below would hide a package listed twice, which
	# is the one thing the partitions cannot survive: it would run twice and
	# the shard it was taken from would look short. Say so first.
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

	# A pin for a package that no longer exists is dead weight and hides the
	# reason the shard was balanced the way it was, so say so. A line whose
	# shard is not a number is worse: pinned() would ignore it and the package
	# would silently hash, so it is an error here.
	if [ -f "$overrides" ]; then
		bad=$(awk '$1 !~ /^#/ && NF && $2 !~ /^[0-9]+$/ { print NR ": " $0 }' "$overrides")
		[ -z "$bad" ] || { echo "error: malformed pins in $overrides:" >&2; echo "$bad" >&2; exit 1; }
		awk '$1 !~ /^#/ && NF && $2 ~ /^[0-9]+$/ { print $1 }' "$overrides" |
			while IFS= read -r pkg; do
				grep -qxF "$pkg" "$work/want" || echo "warning: $pkg is pinned but not in the list" >&2
			done
	fi

	echo "ok: $total shards cover $(wc -l < "$work/want" | tr -d ' ') packages" >&2
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
