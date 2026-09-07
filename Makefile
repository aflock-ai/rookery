.PHONY: build test test-race test-coverage tidy verify-isolated lint lint-fix vet vulncheck deadcode docs catalog-verify catalog-verify-live catalog-record help bpf-lint bpf-build

# Workspace members (parsed from go.work, excluding comments)
MODULES = $(shell grep '^\s*\./' go.work | sed 's/^[[:space:]]*//' | sed 's|^\.\/||')

# Directory holding the generated, CI-verified eBPF object + its Makefile.
BPF_DIR = plugins/attestors/commandrun/ebpf/bpf

# ── Build ────────────────────────────────────────────────────────────
build: ## Build all modules in workspace
	@for dir in $(MODULES); do echo "building $$dir..."; (cd $$dir && go build ./...) || exit 1; done

# ── Test ─────────────────────────────────────────────────────────────
test: ## Run all tests
	@for dir in $(MODULES); do echo "testing $$dir..."; (cd $$dir && go test -count=1 ./...) || exit 1; done

test-race: ## Run all tests with race detector
	@for dir in $(MODULES); do echo "testing $$dir (race)..."; (cd $$dir && go test -race -count=1 ./...) || exit 1; done

test-coverage: ## Run tests with coverage report
	@for dir in $(MODULES); do echo "testing $$dir (coverage)..."; (cd $$dir && go test -short -coverprofile=coverage-$$dir.out -count=1 ./...) || exit 1; done

# ── Lint ─────────────────────────────────────────────────────────────
lint: ## Run golangci-lint
	@for dir in $(MODULES); do echo "linting $$dir..."; (cd $$dir && golangci-lint run ./... --timeout 10m) || exit 1; done

lint-fix: ## Run golangci-lint with auto-fix
	@for dir in $(MODULES); do echo "linting $$dir (fix)..."; (cd $$dir && golangci-lint run ./... --timeout 10m --fix) || exit 1; done

vet: ## Run go vet on all modules
	@for dir in $(MODULES); do echo "vetting $$dir..."; (cd $$dir && go vet ./...) || exit 1; done

bpf-lint: ## Compile-lint the eBPF object source (clang -Wall -Werror); needs clang+bpftool+BTF
	@./scripts/bpf-lint.sh

bpf-build: ## Regenerate the committed canonical eBPF object (pinned arch); CI byte-verifies this
	@$(MAKE) -C $(BPF_DIR) bpf-build

vulncheck: ## Run govulncheck for known vulnerabilities
	@for dir in $(MODULES); do echo "checking $$dir..."; (cd $$dir && govulncheck ./...); done

deadcode: ## Find unreachable functions
	@for dir in $(MODULES); do (cd $$dir && deadcode -test ./...) 2>&1; done

# ── Maintenance ──────────────────────────────────────────────────────
tidy: ## Tidy all module dependencies
	@for dir in $$(find . -name 'go.mod' -exec dirname {} \;); do \
		echo "tidying $$dir"; \
		(cd $$dir && go mod tidy); \
	done

verify-isolated: ## Verify each module builds outside workspace
	@for dir in $$(find . -name 'go.mod' -not -path './go.mod' -exec dirname {} \;); do \
		echo "verifying $$dir"; \
		(cd $$dir && GOWORK=off go build ./...) || exit 1; \
	done
	@echo "All modules build in isolation"

# ── Docs ─────────────────────────────────────────────────────────────
docs: ## Regenerate docs from source: attestor-catalog.md (bash) + attestor-catalog.json (registry+detector.yaml introspection)
	@./scripts/gen-attestor-catalog.sh
	@(cd presets/all && GOWORK=off go run ./cmd/gen-catalog)

# ── Catalog verification ─────────────────────────────────────────────
catalog-verify: ## Verify the attestor catalog: contracts parse + fixtures match real-run evidence
	@echo "verifying catalog contracts..."
	@(cd attestation && go test -count=1 -run 'Contract|EmbeddedCatalog' ./detection/) || exit 1
	@echo "verifying catalog fixtures (all contracted attestors)..."
	@echo "  (unfiltered ./catalogtest/ also runs TestFixturesNoSecrets — the public-sync secret-scan gate)"
	@(cd presets/all && go test -count=1 ./catalogtest/) || exit 1
	@echo "catalog verified."

catalog-verify-live: ## Re-run the REAL tools and verify the contract holds against fresh output (the un-forgeable anchor). Needs the tools installed (syft, govulncheck, gosec, trivy) + network.
	@echo "live-verifying catalog contracts against freshly-run real tools..."
	@(cd presets/all && go test -count=1 -tags live -run TestCatalogLiveReverify ./catalogtest/ -catalog.live.strict) || exit 1
	@echo "catalog live-verified."

catalog-record: ## Re-record a fixture from a REAL tool run. Usage: make catalog-record FIXTURE=plugins/attestors/<name>/testdata/fixtures/<case>
	@test -n "$(FIXTURE)" || { echo "set FIXTURE=<path to fixture dir containing record.sh>"; exit 1; }
	@test -x "$(FIXTURE)/record.sh" || { echo "no executable $(FIXTURE)/record.sh"; exit 1; }
	@"$(FIXTURE)/record.sh"

# ── Help ─────────────────────────────────────────────────────────────
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
