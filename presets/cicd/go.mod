module github.com/aflock-ai/rookery/presets/cicd

go 1.26.0

replace github.com/aflock-ai/rookery/attestation => ../../attestation

replace github.com/aflock-ai/rookery/plugins/attestors/commandrun => ../../plugins/attestors/commandrun

replace github.com/aflock-ai/rookery/plugins/attestors/environment => ../../plugins/attestors/environment

replace github.com/aflock-ai/rookery/plugins/attestors/git => ../../plugins/attestors/git

replace github.com/aflock-ai/rookery/plugins/attestors/github => ../../plugins/attestors/github

replace github.com/aflock-ai/rookery/plugins/attestors/gitlab => ../../plugins/attestors/gitlab

replace github.com/aflock-ai/rookery/plugins/attestors/jwt => ../../plugins/attestors/jwt

replace github.com/aflock-ai/rookery/plugins/attestors/material => ../../plugins/attestors/material

replace github.com/aflock-ai/rookery/plugins/attestors/product => ../../plugins/attestors/product

replace github.com/aflock-ai/rookery/plugins/attestors/slsa => ../../plugins/attestors/slsa

replace github.com/aflock-ai/rookery/plugins/attestors/aws-codebuild => ../../plugins/attestors/aws-codebuild

replace github.com/aflock-ai/rookery/plugins/attestors/jenkins => ../../plugins/attestors/jenkins

replace github.com/aflock-ai/rookery/plugins/attestors/oci => ../../plugins/attestors/oci

replace github.com/aflock-ai/rookery/plugins/signers/file => ../../plugins/signers/file

require (
	github.com/aflock-ai/rookery/plugins/attestors/commandrun v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/attestors/environment v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/attestors/git v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/attestors/github v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/attestors/gitlab v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/attestors/material v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/attestors/product v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/attestors/slsa v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/signers/file v0.0.0-00010101000000-000000000000
)

require (
	dario.cat/mergo v1.0.1 // indirect
	filippo.io/edwards25519 v1.1.0 // indirect
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/ProtonMail/go-crypto v1.1.6 // indirect
	github.com/aflock-ai/rookery/attestation v0.0.0-00010101000000-000000000000 // indirect
	github.com/aflock-ai/rookery/plugins/attestors/aws-codebuild v0.0.0-00010101000000-000000000000 // indirect
	github.com/aflock-ai/rookery/plugins/attestors/jenkins v0.0.0-00010101000000-000000000000 // indirect
	github.com/aflock-ai/rookery/plugins/attestors/jwt v0.0.0-00010101000000-000000000000 // indirect
	github.com/aflock-ai/rookery/plugins/attestors/oci v0.0.0-00010101000000-000000000000 // indirect
	github.com/aws/aws-sdk-go-v2 v1.41.1 // indirect
	github.com/aws/aws-sdk-go-v2/config v1.32.7 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.19.7 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.17 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.17 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.17 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/codebuild v1.68.9 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.17 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.0.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.30.9 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.35.13 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.41.6 // indirect
	github.com/aws/smithy-go v1.24.0 // indirect
	github.com/bahlo/generic-list-go v0.2.0 // indirect
	github.com/buger/jsonparser v1.1.1 // indirect
	github.com/cloudflare/circl v1.6.1 // indirect
	github.com/cyphar/filepath-securejoin v0.4.1 // indirect
	github.com/edwarnicke/gitoid v0.0.0-20220710194850-1be5bfda1f9d // indirect
	github.com/emirpasic/gods v1.18.1 // indirect
	github.com/gabriel-vasile/mimetype v1.4.13 // indirect
	github.com/go-git/gcfg v1.5.1-0.20230307220236-3a3c6141e376 // indirect
	github.com/go-git/go-billy/v5 v5.6.2 // indirect
	github.com/go-git/go-git/v5 v5.16.5 // indirect
	github.com/gobwas/glob v0.2.3 // indirect
	github.com/golang/groupcache v0.0.0-20241129210726-2c02b8208cf8 // indirect
	github.com/invopop/jsonschema v0.13.0 // indirect
	github.com/jbenet/go-context v0.0.0-20150711004518-d14ea06fba99 // indirect
	github.com/kevinburke/ssh_config v1.2.0 // indirect
	github.com/mailru/easyjson v0.9.0 // indirect
	github.com/pjbgf/sha1cd v0.3.2 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/sergi/go-diff v1.4.0 // indirect
	github.com/skeema/knownhosts v1.3.1 // indirect
	github.com/wk8/go-ordered-map/v2 v2.1.8 // indirect
	github.com/xanzy/ssh-agent v0.3.3 // indirect
	go.step.sm/crypto v0.76.0 // indirect
	golang.org/x/crypto v0.48.0 // indirect
	golang.org/x/exp v0.0.0-20260209203927-2842357ff358 // indirect
	golang.org/x/mod v0.33.0 // indirect
	golang.org/x/net v0.50.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
	gopkg.in/go-jose/go-jose.v2 v2.6.3 // indirect
	gopkg.in/warnings.v0 v0.1.2 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
