#!/bin/bash
# Pre-commit hook for aflock
# Install with: make install-hooks

set -e

echo "Running pre-commit checks..."
echo ""

# Run pre-commit target
make pre-commit

echo ""
echo "All pre-commit checks passed!"
