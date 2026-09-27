# Build, test and release portal. Run "make help" for the targets.

BINARY  := portal
PKG     := ./cmd/portal
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

# Static binaries without cgo, so they run on any machine of the target OS.
export CGO_ENABLED := 0

.PHONY: all build install test vet fmt lint cross clean help

all: lint test build ## Lint, test and build

build: ## Build bin/portal for this machine
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY)$(shell go env GOEXE) $(PKG)

install: ## Install portal into $(go env GOPATH)/bin
	go install -trimpath -ldflags "$(LDFLAGS)" $(PKG)

test: ## Run all tests (no external network needed)
	go test ./...

vet: ## Run go vet for every target OS
	@for os in linux darwin windows; do echo "go vet ($$os)"; GOOS=$$os go vet ./... || exit 1; done

fmt: ## Format all Go files
	gofmt -w .

lint: vet ## Check formatting, run go vet, and staticcheck if it is installed
	@test -z "$$(gofmt -l .)" || { echo "These files need gofmt:"; gofmt -l .; exit 1; }
	@if command -v staticcheck >/dev/null 2>&1; then staticcheck ./...; else echo "staticcheck not installed; skipping (go install honnef.co/go/tools/cmd/staticcheck@latest)"; fi

cross: ## Build release binaries for all platforms into dist/
	@mkdir -p dist
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; ext=; [ $$os = windows ] && ext=.exe; \
		out=dist/$(BINARY)-$(VERSION)-$$os-$$arch$$ext; \
		echo "building $$out"; \
		GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" -o $$out $(PKG) || exit 1; \
	done

clean: ## Remove build output
	rm -rf bin dist

help: ## Show this help
	@grep -E '^[a-z]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-8s %s\n", $$1, $$2}'
