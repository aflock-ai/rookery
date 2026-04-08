module github.com/aflock-ai/rookery/plugins/attestors/sbom

go 1.26.0

replace github.com/aflock-ai/rookery/attestation => ../../../attestation

replace github.com/aflock-ai/rookery/plugins/attestors/product => ../product

replace github.com/aflock-ai/rookery/plugins/attestors/commandrun => ../commandrun

require (
	github.com/CycloneDX/cyclonedx-go v0.10.0
	github.com/aflock-ai/rookery/attestation v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/attestors/product v0.0.0-00010101000000-000000000000
	github.com/invopop/jsonschema v0.13.0
	github.com/spdx/tools-golang v0.5.7
)

require (
	filippo.io/edwards25519 v1.1.0 // indirect
	github.com/aflock-ai/rookery/plugins/attestors/commandrun v0.0.0-00010101000000-000000000000 // indirect
	github.com/anchore/go-struct-converter v0.1.0 // indirect
	github.com/bahlo/generic-list-go v0.2.0 // indirect
	github.com/buger/jsonparser v1.1.2 // indirect
	github.com/edwarnicke/gitoid v0.0.0-20220710194850-1be5bfda1f9d // indirect
	github.com/gabriel-vasile/mimetype v1.4.13 // indirect
	github.com/gobwas/glob v0.2.3 // indirect
	github.com/mailru/easyjson v0.9.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/wk8/go-ordered-map/v2 v2.1.8 // indirect
	go.step.sm/crypto v0.76.0 // indirect
	golang.org/x/crypto v0.48.0 // indirect
	golang.org/x/mod v0.33.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
