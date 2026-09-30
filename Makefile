# Orynval Labs — build, test, and one-command demos.
#
# Everything runs locally and offline. No target reaches the network.

GO       ?= go
BIN      := bin
TOOLS    := nhi-ghost mcp-drift trust-proof
PKG      := ./...

# nhi-ghost / mcp-drift demo trees and the trust-proof demo inputs.
NHI_FIXTURES   := internal/nhi/testdata
MCP_FIXTURES   := internal/mcp/testdata
TRUST_QUESTS   := internal/trustproof/testdata/questions.csv
TRUST_EVIDENCE := internal/trustproof/testdata/evidence

.PHONY: all build test race vet fmt fmtcheck check cover clean \
        demo demo-nhi demo-mcp demo-trust

all: check build

build: $(TOOLS:%=$(BIN)/%)

$(BIN)/%: FORCE
	@mkdir -p $(BIN)
	$(GO) build -o $@ ./cmd/$*

FORCE:

test:
	$(GO) test $(PKG)

race:
	$(GO) test -race $(PKG)

vet:
	$(GO) vet $(PKG)

fmt:
	gofmt -w .

# fmtcheck fails (non-empty output) if any file needs formatting.
fmtcheck:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then \
		echo "gofmt needed on:"; echo "$$out"; exit 1; \
	fi
	@echo "gofmt: clean"

check: fmtcheck vet test

cover:
	$(GO) test -cover $(PKG)

# --- one-command demos (run against synthetic fixtures only) ---

demo: demo-nhi demo-mcp demo-trust

demo-nhi:
	@echo "== nhi-ghost =="
	$(GO) run ./cmd/nhi-ghost $(NHI_FIXTURES)

demo-mcp:
	@echo "== mcp-drift =="
	$(GO) run ./cmd/mcp-drift $(MCP_FIXTURES)

demo-trust:
	@echo "== trust-proof =="
	$(GO) run ./cmd/trust-proof --questions $(TRUST_QUESTS) --evidence $(TRUST_EVIDENCE)

clean:
	rm -rf $(BIN)
