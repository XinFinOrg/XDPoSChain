# This Makefile is meant to be used by people that do not usually work
# with Go source code. If you know what GOPATH is then you probably
# don't need to bother with make.

.PHONY: XDC evm all test clean

GOBIN = $(shell pwd)/build/bin
GO ?= latest
GORUN = go run

#? XDC: Build XDC.
XDC:
	@echo "Rebuild the XDC"
	go run build/ci.go install ./cmd/XDC
	@echo "Done building."
	@echo "Run \"$(GOBIN)/XDC\" to launch XDC."

XDC-devnet-local: XDC
	@echo "Run the devnet script in local"
	cd cicd/devnet && ./start-local-devnet.sh

bootnode:
	go run build/ci.go install ./cmd/bootnode
	@echo "Done building."
	@echo "Run \"$(GOBIN)/bootnode\" to launch a bootnode."

puppeth:
	go run build/ci.go install ./cmd/puppeth
	@echo "Done building."
	@echo "Run \"$(GOBIN)/puppeth\" to launch puppeth."

#? all: Build all packages and executables.
all:
	go run build/ci.go install

#? test: Run the tests.
test: all
	go run build/ci.go test -failfast

#? quick-test: Run tests in short mode (testing.Short()), fail fast.
quick-test: all
	go run build/ci.go test -short -failfast

# The CI job runs these, so the carve-out, the package list (test files only) and
# the shard split live here. -p 4 is why rpc stands alone: its 32 MiB websocket
# test trips the codec's 30s pong timeout. -failfast is left out so one run
# reports every race. pkgs is assigned before use and checked non-empty, since
# /bin/sh has no pipefail and an empty slice would fall back to ./... with rpc.
#? race-test: Run tests under the race detector (short mode).
race-test: all race-test-bulk race-test-rpc

#? race-test-full: Run the full (non-short) suite under the race detector.
race-test-full: all race-test-full-bulk race-test-full-groups race-test-full-rpc

# One slice per shard, two in CI; the default is the whole pass. Membership is a
# function of the import path (build/shard.sh).
RACE_SHARDS ?= 1
RACE_SHARD ?= 1
RACE_PKGS = go list -f '{{if or .TestGoFiles .XTestGoFiles}}{{.ImportPath}}{{end}}' ./... | grep -v "XDPoSChain/rpc$$"

# The packages that cost more than a lane on their own, and the list everything
# else is sliced from: they run as test-name slices (race-test-full-group) and
# the rest is split by import path, see build/shard.sh. cmd/XDC has 41 tests and
# costs 79s: one package, so no split of the tree can move it.
RACE_HEAVY = consensus/tests/engine_v2_tests core cmd/XDC

# No race lane at all for this one. The RingCT and Bulletproof verifiers it
# covers are reachable only through RING_SIG_VERIFY (0x1e) and
# BULLET_PROOF_VERIFY (0x28), and no transaction has ever called either on
# mainnet or Apothem (#2895); its own suite is 328s of the detector's 1827s.
# The precompile call paths still run under -race through core/vm, so this drops
# the exhaustive crypto tests, not the code they exercise. Delete this line when
# the package itself goes.
RACE_SKIP = core/vm/privacy

# rpc and the two lists above never appear in a bulk slice: one grep, so a
# package cannot be dropped from the lanes by adding it to a list here and
# forgetting the pattern.
empty :=
space := $(empty) $(empty)
RACE_ABSENT = rpc $(RACE_HEAVY) $(RACE_SKIP)
RACE_REST_PKGS = go list -f '{{if or .TestGoFiles .XTestGoFiles}}{{.ImportPath}}{{end}}' ./... \
	| grep -vE "XDPoSChain/($(subst $(space),|,$(RACE_ABSENT)))$$"

race-test-bulk:
	set -e; pkgs=$$($(RACE_PKGS) | build/shard.sh $(RACE_SHARD) $(RACE_SHARDS)); \
	[ -n "$$pkgs" ]; go run build/ci.go test -race -short -p 4 $$pkgs

race-test-rpc:
	go run build/ci.go test -race -short ./rpc/

# The timeout belongs below the step's watchdog, not above it: ci.go defaults to
# 45m, which outlives the 12m the lane allows, so a hung test was killed with the
# runner and left no goroutine dump - the shape of the 12m timeout in #2942.
# Ten minutes is still several times the slowest lane.
race-test-full-bulk:
	set -e; pkgs=$$($(RACE_REST_PKGS) | build/shard.sh $(RACE_SHARD) $(RACE_SHARDS)); \
	[ -n "$$pkgs" ]; go run build/ci.go test -race -timeout 10m -p 4 $$pkgs

# The test names of a heavy package are not listed anywhere: a lane asks the
# package for them, sorts them and takes every GROUP_N-th one, so a test added
# later runs in exactly one lane and no table needs maintaining.
GROUP_PKG ?=
GROUP_I ?= 1
GROUP_N ?= 1
race-test-full-group:
	set -e; tests=$$(go test -tags=integrationtests -list '^Test' $(GROUP_PKG) \
		| grep -E '^Test[A-Za-z0-9_]+$$' | sort \
		| awk -v i=$(GROUP_I) -v n=$(GROUP_N) 'NR % n == i - 1'); \
	[ -n "$$tests" ]; \
	pattern=$$(printf '%s\n' "$$tests" | paste -sd '|' -); \
	go run build/ci.go test -race -timeout 10m -run "^($$pattern)$$" $(GROUP_PKG)

# The whole of each heavy package, plus the one the CI lanes skip, for a
# local full pass.
race-test-full-groups:
	set -e; for p in $(RACE_HEAVY) $(RACE_SKIP); do go run build/ci.go test -race -p 4 ./$$p || exit 1; done

race-test-full-rpc:
	go run build/ci.go test -race -timeout 4m ./rpc/

#? check-shards: Verify the detector's shard split covers its package list.
# The split is derived from the package names, so it cannot drop a package; what
# it can do is leave a shard empty (the lane then fails on `[ -n "$pkgs" ]`) or
# keep a pin for a package that was renamed. Both are cheap to catch here and
# expensive to debug in a job that timed out. CI runs this in the static job, so
# a pull request that touches the split is checked even when the race lanes are
# skipped for having no Go changes.
#
# The lane count is a hand-written list in the workflow, so it is counted there:
# a lane dropped without RACE_SHARDS moving would take its packages out of the
# run without any shard coming out empty.
check-shards:
	@set -e; \
	lanes=$$(grep -cE 'name: "bulk [0-9]+/[0-9]+"' .github/workflows/ci.yml); \
	[ "$$lanes" = "$(RACE_SHARDS)" ] || { \
		echo "error: ci.yml has $$lanes bulk lanes, RACE_SHARDS is $(RACE_SHARDS)" >&2; exit 1; }; \
	$(RACE_REST_PKGS) | build/shard.sh --check $(RACE_SHARDS)

#? lint: Run certain pre-selected linters.
lint: ## Run linters.
	$(GORUN) build/ci.go lint

#? tidy: Verify go.mod and go.sum are updated.
tidy: ## Run 'go mod tidy'.
	$(GORUN) build/ci.go tidy

#? generate: Verify everything is 'go generate'.
generate: ## Run 'go generate ./...'.
	$(GORUN) build/ci.go generate

#? baddeps: Verify certain dependencies are avoided.
baddeps:
	$(GORUN) build/ci.go baddeps

#? fmt: Ensure consistent code formatting.
# Enumerate the Go files of this checkout with git instead of find: the repo root
# may contain nested checkouts (e.g. .worktrees/), which both blows up the
# argument list and makes fmt rewrite files that belong to other checkouts.
fmt:
	git ls-files -z --cached --others --exclude-standard -- '*.go' | xargs -0r gofmt -s -w

#? clean: Clean go cache, built executables, and the auto generated folder.
clean:
	go clean -cache
	go clean -testcache
	go clean -modcache
	rm -fr build/_workspace/pkg/ $(GOBIN)/*

# The devtools target installs tools required for 'go generate'.
# You need to put $GOBIN (or $GOPATH/bin) in your PATH to use 'go generate'.

#? devtools: Install recommended developer tools.
# The versions are the ones the checked-in generated files were produced with.
# Most `go:generate` directives are `go run <pkg>` and resolve their version
# through go.mod, so keep stringer and gencodec in step with those requirements.
# protoc is the exception: it shells out to protoc-gen-go on $PATH, whose
# version is echoed into the headers of accounts/usbwallet/trezor.
# TODO: protoc-gen-go is pinned here to v1.34.2, the release recorded in
# build/checksums.txt, while go.mod's `tool` requirement still resolves it to
# google.golang.org/protobuf v1.31.0. Align them once that runtime is raised.
# protoc itself is installed outside this target: keep it at 27.1
# (build/checksums.txt), otherwise those trezor headers move with it.
devtools:
	env GOBIN= go install golang.org/x/tools/cmd/stringer@v0.37.0
	env GOBIN= go install github.com/fjl/gencodec@v0.1.2
	env GOBIN= go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.34.2
	env GOBIN= go install ./cmd/abigen
	@type "solc" 2> /dev/null || echo 'Please install solc'
	@type "protoc" 2> /dev/null || echo 'Please install protoc'

#? help: Get more info on make commands.
help: Makefile
	@echo ''
	@echo 'Usage:'
	@echo '  make [target]'
	@echo ''
	@echo 'Targets:'
	@sed -n 's/^#?//p' $< | column -t -s ':' |  sort | sed -e 's/^/ /'
