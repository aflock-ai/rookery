module github.com/aflock-ai/rookery/plugins/attestors/commandrun/ebpf

go 1.26.4

require (
	github.com/aflock-ai/rookery/attestation v0.0.0-00010101000000-000000000000
	github.com/cilium/ebpf v0.18.0
	golang.org/x/sys v0.45.0
)

require (
	filippo.io/edwards25519 v1.1.1 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/rogpeppe/go-internal v1.14.1 // indirect
	go.step.sm/crypto v0.76.0 // indirect
	golang.org/x/crypto v0.52.0 // indirect
	golang.org/x/mod v0.36.0 // indirect
)

replace github.com/aflock-ai/rookery/attestation => ../../../../attestation
