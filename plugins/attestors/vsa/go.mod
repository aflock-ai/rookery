module github.com/aflock-ai/rookery/plugins/attestors/vsa

go 1.26.0

replace github.com/aflock-ai/rookery/attestation => ../../../attestation

require (
	github.com/aflock-ai/rookery/attestation v0.0.0-00010101000000-000000000000
	github.com/invopop/jsonschema v0.13.0
)

require (
	github.com/bahlo/generic-list-go v0.2.0 // indirect
	github.com/buger/jsonparser v1.1.2 // indirect
	github.com/mailru/easyjson v0.9.0 // indirect
	github.com/wk8/go-ordered-map/v2 v2.1.8 // indirect
)
