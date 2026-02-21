.PHONY: build test test-race test-coverage tidy verify-isolated lint lint-fix vet vulncheck deadcode help

# ── Build ────────────────────────────────────────────────────────────
build: ## Build all modules in workspace
	go build ./...

# ── Test ─────────────────────────────────────────────────────────────
test: ## Run all tests
	go test -count=1 ./...

test-race: ## Run all tests with race detector
	go test -race -count=1 ./...

test-coverage: ## Run tests with coverage report
	go test -short -coverprofile=coverage.out -count=1 ./...
	go tool cover -func=coverage.out | tail -1

# ── Lint ─────────────────────────────────────────────────────────────
lint: ## Run golangci-lint
	golangci-lint run ./... --timeout 10m

lint-fix: ## Run golangci-lint with auto-fix
	golangci-lint run ./... --timeout 10m --fix

vet: ## Run go vet on all modules
	go vet ./...

vulncheck: ## Run govulncheck for known vulnerabilities
	govulncheck ./...

deadcode: ## Find unreachable functions
	deadcode -test ./...

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
