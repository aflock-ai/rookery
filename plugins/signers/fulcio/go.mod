module github.com/aflock-ai/rookery/plugins/signers/fulcio

go 1.26.0

replace github.com/aflock-ai/rookery/attestation => ../../../attestation

require (
	github.com/aflock-ai/rookery/attestation v0.0.0-00010101000000-000000000000
	github.com/go-jose/go-jose/v3 v3.0.4
	github.com/mattn/go-isatty v0.0.20
	github.com/sigstore/fulcio v1.8.5
	github.com/sigstore/sigstore v1.10.4
	github.com/stretchr/testify v1.11.1
	go.step.sm/crypto v0.76.0
	google.golang.org/grpc v1.79.3
	google.golang.org/protobuf v1.36.11
	gopkg.in/go-jose/go-jose.v2 v2.6.3
)

require (
	filippo.io/edwards25519 v1.1.0 // indirect
	github.com/coreos/go-oidc/v3 v3.17.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/edwarnicke/gitoid v0.0.0-20220710194850-1be5bfda1f9d // indirect
	github.com/go-jose/go-jose/v4 v4.1.3 // indirect
	github.com/google/go-containerregistry v0.20.7 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.27.4 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/pkg/browser v0.0.0-20240102092130-5ac0b6a4141c // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/rogpeppe/go-internal v1.14.1 // indirect
	github.com/secure-systems-lab/go-securesystemslib v0.9.1 // indirect
	github.com/sigstore/protobuf-specs v0.5.0 // indirect
	golang.org/x/crypto v0.48.0 // indirect
	golang.org/x/mod v0.33.0 // indirect
	golang.org/x/net v0.50.0 // indirect
	golang.org/x/oauth2 v0.35.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
	golang.org/x/term v0.40.0 // indirect
	golang.org/x/text v0.34.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260128011058-8636f8732409 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260203192932-546029d2fa20 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
