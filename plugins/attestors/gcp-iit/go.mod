module github.com/aflock-ai/rookery/plugins/attestors/gcp-iit

go 1.25.0

replace github.com/aflock-ai/rookery/attestation => ../../../attestation

replace github.com/aflock-ai/rookery/plugins/attestors/jwt => ../jwt

require (
	github.com/aflock-ai/rookery/attestation v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/attestors/jwt v0.0.0-00010101000000-000000000000
	github.com/invopop/jsonschema v0.13.0
	google.golang.org/grpc v1.78.0
)

require (
	filippo.io/edwards25519 v1.1.0 // indirect
	github.com/bahlo/generic-list-go v0.2.0 // indirect
	github.com/buger/jsonparser v1.1.1 // indirect
	github.com/edwarnicke/gitoid v0.0.0-20220710194850-1be5bfda1f9d // indirect
	github.com/gobwas/glob v0.2.3 // indirect
	github.com/mailru/easyjson v0.9.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/wk8/go-ordered-map/v2 v2.1.8 // indirect
	go.step.sm/crypto v0.76.0 // indirect
	golang.org/x/crypto v0.47.0 // indirect
	golang.org/x/mod v0.33.0 // indirect
	golang.org/x/sys v0.40.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251222181119-0a764e51fe1b // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	gopkg.in/go-jose/go-jose.v2 v2.6.3 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
