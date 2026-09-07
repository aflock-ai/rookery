module github.com/aflock-ai/rookery/plugins/attestors/commandrun/ebpf

go 1.26.3

require (
	github.com/aflock-ai/rookery/attestation v0.0.0-00010101000000-000000000000
	github.com/cilium/ebpf v0.22.0
	golang.org/x/sys v0.45.0
)

require (
	filippo.io/edwards25519 v1.2.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	go.step.sm/crypto v0.81.0 // indirect
	golang.org/x/crypto v0.52.0 // indirect
	golang.org/x/mod v0.36.0 // indirect
)

replace github.com/aflock-ai/rookery/attestation => ../../../../attestation
