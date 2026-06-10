# cilock hang repro harness — fast iteration loop (colima half).
#
#   make cilock          rebuild the linux/arm64 cilock from the rookery subtree
#   make offline         no-network signing scenario (must stay clean)
#   make source-git      attest → staging Archivista (needs creds; hunts hangs)
#   make stall           attest against a black-hole TCP endpoint
#   make loop S=stall    rebuild + run in one shot (the iteration unit)
#
# Pair with the GitHub-Actions half: .github/workflows/cilock-hang-repro.yml
# (workflow_dispatch) runs the same probe on the self-hosted runner where the
# ambient-OIDC keyless path actually exists.

ROOKERY := $(abspath ../../cilock)
HERE := $(shell pwd)
S ?= offline

.PHONY: cilock offline source-git stall loop key

key:
	@test -f $(HERE)/k.key || openssl ecparam -name prime256v1 -genkey -noout -out $(HERE)/k.key

cilock:
	cd $(ROOKERY) && GOWORK=off GOOS=linux GOARCH=arm64 CGO_ENABLED=0 \
		go build -o $(HERE)/bin/cilock-linux ./cmd/cilock
	@echo "built $(HERE)/bin/cilock-linux"

offline source-git stall: key
	./run.sh $@

loop: cilock key
	./run.sh $(S)
