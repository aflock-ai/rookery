.PHONY: build test test-race test-coverage tidy verify-isolated lint lint-fix vet vulncheck deadcode help

# Workspace members (parsed from go.work, excluding comments)
MODULES = $(shell grep '^\s*\./' go.work | sed 's/^[[:space:]]*//' | sed 's|^\.\/||')

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

# ── Help ─────────────────────────────────────────────────────────────
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
