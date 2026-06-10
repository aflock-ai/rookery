module github.com/aflock-ai/rookery/plugins/signers/spiffe

go 1.26.4

replace github.com/aflock-ai/rookery/attestation => ../../../attestation

require (
	github.com/aflock-ai/rookery/attestation v0.0.0-00010101000000-000000000000
	github.com/spiffe/go-spiffe/v2 v2.6.0
)

require (
	filippo.io/edwards25519 v1.1.1 // indirect
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/go-jose/go-jose/v4 v4.1.4 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	go.opentelemetry.io/otel/sdk/metric v1.43.0 // indirect
	go.step.sm/crypto v0.76.0 // indirect
	golang.org/x/crypto v0.52.0 // indirect
	golang.org/x/mod v0.36.0 // indirect
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/text v0.37.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260203192932-546029d2fa20 // indirect
	google.golang.org/grpc v1.79.3 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)
