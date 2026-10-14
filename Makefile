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
race-test-full: all race-test-full-bulk race-test-full-rpc

# One slice per shard, four in CI; the default is the whole pass.
RACE_SHARDS ?= 1
RACE_SHARD ?= 1
RACE_PKGS = go list -f '{{if or .TestGoFiles .XTestGoFiles}}{{.ImportPath}}{{end}}' ./... | grep -v "XDPoSChain/rpc$$"

race-test-bulk:
	set -e; pkgs=$$($(RACE_PKGS) | awk -v i=$(RACE_SHARD) -v n=$(RACE_SHARDS) 'NR % n == i - 1'); \
	[ -n "$$pkgs" ]; go run build/ci.go test -race -short -p 4 $$pkgs

race-test-rpc:
	go run build/ci.go test -race -short ./rpc/

race-test-full-bulk:
	set -e; pkgs=$$($(RACE_PKGS)); [ -n "$$pkgs" ]; go run build/ci.go test -race -p 4 $$pkgs

race-test-full-rpc:
	go run build/ci.go test -race ./rpc/

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
