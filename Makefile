.PHONY: build test tidy verify-isolated

# Build all modules in workspace
build:
	go build ./...

# Test all modules in workspace
test:
	go test ./...

# Tidy all modules
tidy:
	@for dir in $$(find . -name 'go.mod' -exec dirname {} \;); do \
		echo "tidying $$dir"; \
		(cd $$dir && go mod tidy); \
	done

# Verify each module builds in isolation (no workspace)
verify-isolated:
	@for dir in $$(find . -name 'go.mod' -not -path './go.mod' -exec dirname {} \;); do \
		echo "verifying $$dir"; \
		(cd $$dir && GOWORK=off go build ./...) || exit 1; \
	done
	@echo "All modules build in isolation"
