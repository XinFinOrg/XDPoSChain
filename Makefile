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

# race-test mirrors the CI race job (.github/workflows/ci.yml): the bulk pass
# runs four packages at a time without rpc, then rpc on its own. Under -p 4 the
# 32 MiB websocket test trips the codec's 30s pong timeout and fails as a plain
# connection error, hiding any real race in the packages that follow. -failfast
# is left out on purpose: the sweep exists to report every race in one go.
#
# The package list is collected before testing it: an argument list throws the
# substitution's exit status away, and an empty list makes build/ci.go fall back
# to ./... with rpc included. make runs recipes with /bin/sh, which has no
# pipefail, so this catches go list failing outright; a partial failure still
# leaves every package path in the list, where go test reports it.
#
# -short skips the long consensus cases (skipLongInShortMode under
# consensus/tests/engine_v2_tests), the discover UDP/lookup cases and the tests/
# performance cases; only the plain CI shards run those, without -race.
# race-test-full covers them when a change touches those paths.
#? race-test: Run tests under the race detector (short mode).
race-test: all
	set -e; pkgs=$$(go list ./... | grep -vE "XDPoSChain/rpc$$"); go run build/ci.go test -race -short -p 4 $$pkgs
	go run build/ci.go test -race -short ./rpc/

#? race-test-full: Run the full (non-short) suite under the race detector.
race-test-full: all
	set -e; pkgs=$$(go list ./... | grep -vE "XDPoSChain/rpc$$"); go run build/ci.go test -race -p 4 $$pkgs
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
fmt:
	gofmt -s -w $(shell find . -name "*.go")

#? clean: Clean go cache, built executables, and the auto generated folder.
clean:
	go clean -cache
	go clean -testcache
	go clean -modcache
	rm -fr build/_workspace/pkg/ $(GOBIN)/*

# The devtools target installs tools required for 'go generate'.
# You need to put $GOBIN (or $GOPATH/bin) in your PATH to use 'go generate'.

#? devtools: Install recommended developer tools.
devtools:
	env GOBIN= go install golang.org/x/tools/cmd/stringer@latest
	env GOBIN= go install github.com/fjl/gencodec@latest
	env GOBIN= go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
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
