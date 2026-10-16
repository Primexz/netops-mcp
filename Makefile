GO ?= go
GOFMT ?= gofmt
GOLANGCI_LINT ?= golangci-lint
PYTHON ?= python3
VENDOR ?= all

ifeq ($(filter $(VENDOR),all securepoint mikrotik),)
$(error VENDOR must be all, securepoint, or mikrotik)
endif

.PHONY: build test check verify fmt fmt-check lint research catalog cross-build research-securepoint research-mikrotik catalog-securepoint catalog-mikrotik

fmt:
	$(GO) fmt ./...

fmt-check:
	@unformatted="$$($(GOFMT) -l cmd internal)" || exit 1; \
	if [ -n "$$unformatted" ]; then \
		printf 'Run make fmt to format these Go files:\n%s\n' "$$unformatted"; \
		exit 1; \
	fi

lint:
	$(GOLANGCI_LINT) run ./...

build:
	$(GO) build -trimpath -o bin/sp-utm-mcp ./cmd/sp-utm-mcp
	$(GO) build -trimpath -o bin/mikrotik-mcp ./cmd/mikrotik-mcp

test:
	$(GO) test -race ./...

check:
	$(GO) vet ./...
	$(GO) run ./cmd/sp-utm-mcp --config configs/sp-utm.example.toml --check
	$(GO) run ./cmd/sp-utm-mcp --config configs/sp-utm.example.toml --transport http --check
	$(GO) run ./cmd/mikrotik-mcp --config configs/mikrotik.example.toml --check
	$(GO) run ./cmd/mikrotik-mcp --config configs/mikrotik.example.toml --transport http --check

verify: fmt-check lint test check build

research: $(if $(filter all securepoint,$(VENDOR)),research-securepoint) $(if $(filter all mikrotik,$(VENDOR)),research-mikrotik)

catalog: $(if $(filter all securepoint,$(VENDOR)),catalog-securepoint) $(if $(filter all mikrotik,$(VENDOR)),catalog-mikrotik)

research-securepoint:
	$(PYTHON) tools/securepoint/research_wiki.py

catalog-securepoint:
	$(PYTHON) tools/securepoint/build_catalog.py
	$(PYTHON) tools/securepoint/finalize_catalog.py
	$(PYTHON) tools/securepoint/report_coverage.py

research-mikrotik:
	$(GO) run ./cmd/mikrotik-cataloggen --fetch

catalog-mikrotik:
	$(GO) run ./cmd/mikrotik-cataloggen

cross-build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -o dist/sp-utm-mcp-linux-amd64 ./cmd/sp-utm-mcp
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -o dist/mikrotik-mcp-linux-amd64 ./cmd/mikrotik-mcp
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GO) build -trimpath -o dist/sp-utm-mcp-darwin-arm64 ./cmd/sp-utm-mcp
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GO) build -trimpath -o dist/mikrotik-mcp-darwin-arm64 ./cmd/mikrotik-mcp
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build -trimpath -o dist/sp-utm-mcp-windows-amd64.exe ./cmd/sp-utm-mcp
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build -trimpath -o dist/mikrotik-mcp-windows-amd64.exe ./cmd/mikrotik-mcp
