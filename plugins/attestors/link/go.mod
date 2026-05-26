module github.com/aflock-ai/rookery/plugins/attestors/link

go 1.26.3

replace github.com/aflock-ai/rookery/attestation => ../../../attestation

replace github.com/aflock-ai/rookery/plugins/attestors/commandrun => ../commandrun

replace github.com/aflock-ai/rookery/plugins/attestors/commandrun/ebpf => ../commandrun/ebpf

replace github.com/aflock-ai/rookery/plugins/attestors/environment => ../environment

replace github.com/aflock-ai/rookery/plugins/attestors/material => ../material

replace github.com/aflock-ai/rookery/plugins/attestors/product => ../product

replace github.com/aflock-ai/rookery/plugins/attestors/inclusion-proof => ../inclusion-proof

require (
	github.com/aflock-ai/rookery/attestation v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/attestors/commandrun v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/attestors/environment v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/attestors/material v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/attestors/product v0.0.0-00010101000000-000000000000
	github.com/invopop/jsonschema v0.13.0
)

require (
	filippo.io/edwards25519 v1.1.1 // indirect
	github.com/aflock-ai/rookery/plugins/attestors/commandrun/ebpf v0.0.0-00010101000000-000000000000 // indirect
	github.com/aflock-ai/rookery/plugins/attestors/inclusion-proof v0.0.0-00010101000000-000000000000 // indirect
	github.com/bahlo/generic-list-go v0.2.0 // indirect
	github.com/buger/jsonparser v1.1.2 // indirect
	github.com/cilium/ebpf v0.18.0 // indirect
	github.com/edwarnicke/gitoid v0.0.0-20220710194850-1be5bfda1f9d // indirect
	github.com/gabriel-vasile/mimetype v1.4.13 // indirect
	github.com/gobwas/glob v0.2.3 // indirect
	github.com/mailru/easyjson v0.9.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/transparency-dev/merkle v0.0.2 // indirect
	github.com/wk8/go-ordered-map/v2 v2.1.8 // indirect
	go.step.sm/crypto v0.76.0 // indirect
	golang.org/x/crypto v0.48.0 // indirect
	golang.org/x/mod v0.33.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
