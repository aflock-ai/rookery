module github.com/aflock-ai/rookery/plugins/signers/debug-signer

go 1.26.0

replace github.com/aflock-ai/rookery/attestation => ../../../attestation

require github.com/aflock-ai/rookery/attestation v0.0.0-00010101000000-000000000000

require (
	filippo.io/edwards25519 v1.1.0 // indirect
	github.com/edwarnicke/gitoid v0.0.0-20220710194850-1be5bfda1f9d // indirect
	github.com/pkg/errors v0.9.1 // indirect
	go.step.sm/crypto v0.76.0 // indirect
	golang.org/x/crypto v0.48.0 // indirect
	golang.org/x/mod v0.33.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
)
