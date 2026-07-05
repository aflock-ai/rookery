module github.com/aflock-ai/rookery/presets/all

go 1.26.4

// Core
replace github.com/aflock-ai/rookery/attestation => ../../attestation

replace github.com/aflock-ai/rookery/cilock => ../../cilock

replace github.com/aflock-ai/rookery/plugins/attestors/inclusion-proof => ../../plugins/attestors/inclusion-proof

// Attestor plugins
replace github.com/aflock-ai/rookery/plugins/attestors/asff => ../../plugins/attestors/asff

replace github.com/aflock-ai/rookery/plugins/attestors/aws-codebuild => ../../plugins/attestors/aws-codebuild

replace github.com/aflock-ai/rookery/plugins/attestors/aws-config => ../../plugins/attestors/aws-config

replace github.com/aflock-ai/rookery/plugins/attestors/aws-iid => ../../plugins/attestors/aws-iid

replace github.com/aflock-ai/rookery/plugins/attestors/commandrun => ../../plugins/attestors/commandrun

replace github.com/aflock-ai/rookery/plugins/attestors/commandrun/ebpf => ../../plugins/attestors/commandrun/ebpf

replace github.com/aflock-ai/rookery/plugins/attestors/configuration => ../../plugins/attestors/configuration

replace github.com/aflock-ai/rookery/plugins/attestors/docker => ../../plugins/attestors/docker

replace github.com/aflock-ai/rookery/plugins/attestors/docker-bench => ../../plugins/attestors/docker-bench

replace github.com/aflock-ai/rookery/plugins/attestors/environment => ../../plugins/attestors/environment

replace github.com/aflock-ai/rookery/plugins/attestors/falco => ../../plugins/attestors/falco

replace github.com/aflock-ai/rookery/plugins/attestors/gcp-iit => ../../plugins/attestors/gcp-iit

replace github.com/aflock-ai/rookery/plugins/attestors/git => ../../plugins/attestors/git

replace github.com/aflock-ai/rookery/plugins/attestors/github => ../../plugins/attestors/github

replace github.com/aflock-ai/rookery/plugins/attestors/githubaction => ../../plugins/attestors/githubaction

replace github.com/aflock-ai/rookery/plugins/attestors/githubwebhook => ../../plugins/attestors/githubwebhook

replace github.com/aflock-ai/rookery/plugins/attestors/gitlab => ../../plugins/attestors/gitlab

replace github.com/aflock-ai/rookery/plugins/attestors/govulncheck => ../../plugins/attestors/govulncheck

replace github.com/aflock-ai/rookery/plugins/attestors/inspec => ../../plugins/attestors/inspec

replace github.com/aflock-ai/rookery/plugins/attestors/jenkins => ../../plugins/attestors/jenkins

replace github.com/aflock-ai/rookery/plugins/attestors/jwt => ../../plugins/attestors/jwt

replace github.com/aflock-ai/rookery/plugins/attestors/k8smanifest => ../../plugins/attestors/k8smanifest

replace github.com/aflock-ai/rookery/plugins/attestors/kube-bench => ../../plugins/attestors/kube-bench

replace github.com/aflock-ai/rookery/plugins/attestors/link => ../../plugins/attestors/link

replace github.com/aflock-ai/rookery/plugins/attestors/linkerd-check => ../../plugins/attestors/linkerd-check

replace github.com/aflock-ai/rookery/plugins/attestors/lockfiles => ../../plugins/attestors/lockfiles

replace github.com/aflock-ai/rookery/plugins/attestors/material => ../../plugins/attestors/material

replace github.com/aflock-ai/rookery/plugins/attestors/maven => ../../plugins/attestors/maven

replace github.com/aflock-ai/rookery/plugins/attestors/oci => ../../plugins/attestors/oci

replace github.com/aflock-ai/rookery/plugins/attestors/omnitrail => ../../plugins/attestors/omnitrail

replace github.com/aflock-ai/rookery/plugins/attestors/oscap => ../../plugins/attestors/oscap

replace github.com/aflock-ai/rookery/plugins/attestors/pip-install => ../../plugins/attestors/pip-install

replace github.com/aflock-ai/rookery/plugins/attestors/policyverify => ../../plugins/attestors/policyverify

replace github.com/aflock-ai/rookery/plugins/attestors/product => ../../plugins/attestors/product

replace github.com/aflock-ai/rookery/plugins/attestors/prowler => ../../plugins/attestors/prowler

replace github.com/aflock-ai/rookery/plugins/attestors/sarif => ../../plugins/attestors/sarif

replace github.com/aflock-ai/rookery/plugins/attestors/sbom => ../../plugins/attestors/sbom

replace github.com/aflock-ai/rookery/plugins/attestors/scubagoggles => ../../plugins/attestors/scubagoggles

replace github.com/aflock-ai/rookery/plugins/attestors/secretscan => ../../plugins/attestors/secretscan

replace github.com/aflock-ai/rookery/plugins/attestors/sinkhole-flows => ../../plugins/attestors/sinkhole-flows

replace github.com/aflock-ai/rookery/plugins/attestors/slsa => ../../plugins/attestors/slsa

replace github.com/aflock-ai/rookery/plugins/attestors/steampipe => ../../plugins/attestors/steampipe

replace github.com/aflock-ai/rookery/plugins/attestors/structured-data => ../../plugins/attestors/structured-data

replace github.com/aflock-ai/rookery/plugins/attestors/system-packages => ../../plugins/attestors/system-packages

replace github.com/aflock-ai/rookery/plugins/attestors/test-results => ../../plugins/attestors/test-results

replace github.com/aflock-ai/rookery/plugins/attestors/trivy => ../../plugins/attestors/trivy

replace github.com/aflock-ai/rookery/plugins/attestors/vex => ../../plugins/attestors/vex

replace github.com/aflock-ai/rookery/plugins/attestors/vsa => ../../plugins/attestors/vsa

// Signer plugins
replace github.com/aflock-ai/rookery/plugins/signers/debug-signer => ../../plugins/signers/debug-signer

replace github.com/aflock-ai/rookery/plugins/signers/file => ../../plugins/signers/file

replace github.com/aflock-ai/rookery/plugins/signers/fulcio => ../../plugins/signers/fulcio

replace github.com/aflock-ai/rookery/plugins/signers/kms/aws => ../../plugins/signers/kms/aws

replace github.com/aflock-ai/rookery/plugins/signers/kms/azure => ../../plugins/signers/kms/azure

replace github.com/aflock-ai/rookery/plugins/signers/kms/gcp => ../../plugins/signers/kms/gcp

replace github.com/aflock-ai/rookery/plugins/signers/spiffe => ../../plugins/signers/spiffe

replace github.com/aflock-ai/rookery/plugins/signers/vault => ../../plugins/signers/vault

replace github.com/aflock-ai/rookery/plugins/signers/vault-transit => ../../plugins/signers/vault-transit

require (
	github.com/aflock-ai/rookery/attestation v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/cilock v0.0.0-20260526030653-bb247c9ce799
	github.com/aflock-ai/rookery/plugins/attestors/asff v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/attestors/aws-codebuild v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/attestors/aws-config v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/attestors/aws-iid v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/attestors/commandrun v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/attestors/configuration v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/attestors/docker v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/attestors/docker-bench v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/attestors/environment v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/attestors/falco v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/attestors/gcp-iit v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/attestors/git v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/attestors/github v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/attestors/github-review v0.0.0-20260526031329-c5a7d8b6c1d3
	github.com/aflock-ai/rookery/plugins/attestors/githubaction v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/attestors/githubwebhook v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/attestors/gitlab v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/attestors/go-build v0.0.0-20260526031329-c5a7d8b6c1d3
	github.com/aflock-ai/rookery/plugins/attestors/govulncheck v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/attestors/inclusion-proof v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/attestors/inspec v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/attestors/jenkins v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/attestors/jwt v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/attestors/k8smanifest v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/attestors/kube-bench v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/attestors/link v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/attestors/linkerd-check v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/attestors/lockfiles v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/attestors/material v0.1.0
	github.com/aflock-ai/rookery/plugins/attestors/maven v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/attestors/oci v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/attestors/omnitrail v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/attestors/oscap v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/attestors/pip-install v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/attestors/policyverify v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/attestors/product v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/attestors/prowler v0.0.0-20260522233336-64c65b91ab8f
	github.com/aflock-ai/rookery/plugins/attestors/sarif v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/attestors/sbom v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/attestors/scubagoggles v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/attestors/secretscan v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/attestors/sinkhole-flows v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/attestors/slsa v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/attestors/steampipe v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/attestors/structured-data v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/attestors/system-packages v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/attestors/test-results v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/attestors/trivy v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/attestors/vex v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/attestors/vsa v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/signers/debug-signer v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/signers/file v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/signers/fulcio v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/signers/kms/aws v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/signers/kms/azure v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/signers/kms/gcp v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/signers/spiffe v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/signers/vault v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/signers/vault-transit v0.0.0-00010101000000-000000000000
	github.com/spf13/cobra v1.10.2
	gopkg.in/yaml.v3 v3.0.1
)

require (
	cloud.google.com/go v0.123.0 // indirect
	cloud.google.com/go/auth v0.18.1 // indirect
	cloud.google.com/go/auth/oauth2adapt v0.2.8 // indirect
	cloud.google.com/go/compute/metadata v0.9.0 // indirect
	cloud.google.com/go/iam v1.5.3 // indirect
	cloud.google.com/go/kms v1.25.0 // indirect
	cloud.google.com/go/longrunning v0.8.0 // indirect
	dario.cat/mergo v1.0.1 // indirect
	filippo.io/edwards25519 v1.1.1 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.21.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/azidentity v1.13.1 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.11.2 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys v1.4.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/internal v1.2.0 // indirect
	github.com/AzureAD/microsoft-authentication-library-for-go v1.6.0 // indirect
	github.com/BobuSumisu/aho-corasick v1.0.3 // indirect
	github.com/Masterminds/goutils v1.1.1 // indirect
	github.com/Masterminds/semver/v3 v3.4.0 // indirect
	github.com/Masterminds/sprig/v3 v3.3.0 // indirect
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/ProtonMail/go-crypto v1.1.6 // indirect
	github.com/STARRY-S/zip v0.2.3 // indirect
	github.com/aflock-ai/rookery/plugins/attestors/commandrun/ebpf v0.0.0-00010101000000-000000000000 // indirect
	github.com/agnivade/levenshtein v1.2.1 // indirect
	github.com/andybalholm/brotli v1.2.0 // indirect
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
	github.com/aws/aws-sdk-go-v2/service/kms v1.49.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.0.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.30.9 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.35.13 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.41.6 // indirect
	github.com/aws/smithy-go v1.24.0 // indirect
	github.com/aymanbagabas/go-osc52/v2 v2.0.1 // indirect
	github.com/bahlo/generic-list-go v0.2.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/bodgit/plumbing v1.3.0 // indirect
	github.com/bodgit/sevenzip v1.6.1 // indirect
	github.com/bodgit/windows v1.0.1 // indirect
	github.com/buger/jsonparser v1.1.2 // indirect
	github.com/cenkalti/backoff/v4 v4.3.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/charmbracelet/lipgloss v0.5.0 // indirect
	github.com/cilium/ebpf v0.18.0 // indirect
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/coreos/go-oidc/v3 v3.17.0 // indirect
	github.com/cyphar/filepath-securejoin v0.6.1 // indirect
	github.com/danieljoos/wincred v1.2.3 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0 // indirect
	github.com/digitorus/pkcs7 v0.0.0-20250730155240-ffadbf3f398c // indirect
	github.com/digitorus/timestamp v0.0.0-20250524132541-c45532741eea // indirect
	github.com/dsnet/compress v0.0.2-0.20230904184137-39efe44ab707 // indirect
	github.com/emirpasic/gods v1.18.1 // indirect
	github.com/fatih/color v1.18.0 // indirect
	github.com/fatih/semgroup v1.2.0 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/fxamacker/cbor/v2 v2.9.0 // indirect
	github.com/gabriel-vasile/mimetype v1.4.13 // indirect
	github.com/gitleaks/go-gitdiff v0.9.1 // indirect
	github.com/go-git/gcfg v1.5.1-0.20230307220236-3a3c6141e376 // indirect
	github.com/go-git/go-billy/v5 v5.9.0 // indirect
	github.com/go-git/go-git/v5 v5.19.1 // indirect
	github.com/go-jose/go-jose/v4 v4.1.4 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-viper/mapstructure/v2 v2.4.0 // indirect
	github.com/gobwas/glob v0.2.3 // indirect
	github.com/goccy/go-json v0.10.5 // indirect
	github.com/godbus/dbus/v5 v5.2.2 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.0 // indirect
	github.com/golang/groupcache v0.0.0-20241129210726-2c02b8208cf8 // indirect
	github.com/google/go-containerregistry v0.20.7 // indirect
	github.com/google/s2a-go v0.1.9 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.11 // indirect
	github.com/googleapis/gax-go/v2 v2.17.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.27.4 // indirect
	github.com/h2non/filetype v1.1.3 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/go-retryablehttp v0.7.8 // indirect
	github.com/hashicorp/go-rootcerts v1.0.2 // indirect
	github.com/hashicorp/go-secure-stdlib/parseutil v0.2.0 // indirect
	github.com/hashicorp/go-secure-stdlib/strutil v0.1.2 // indirect
	github.com/hashicorp/go-sockaddr v1.0.7 // indirect
	github.com/hashicorp/go-version v1.7.0 // indirect
	github.com/hashicorp/golang-lru/v2 v2.0.7 // indirect
	github.com/hashicorp/hcl v1.0.1-vault-7 // indirect
	github.com/hashicorp/vault/api v1.22.0 // indirect
	github.com/hashicorp/vault/api/auth/kubernetes v0.10.0 // indirect
	github.com/huandu/xstrings v1.5.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/invopop/jsonschema v0.13.0 // indirect
	github.com/jbenet/go-context v0.0.0-20150711004518-d14ea06fba99 // indirect
	github.com/jellydator/ttlcache/v3 v3.4.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/kevinburke/ssh_config v1.2.0 // indirect
	github.com/klauspost/compress v1.18.2 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/klauspost/pgzip v1.2.6 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/lestrrat-go/blackmagic v1.0.4 // indirect
	github.com/lestrrat-go/dsig v1.0.0 // indirect
	github.com/lestrrat-go/dsig-secp256k1 v1.0.0 // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/httprc/v3 v3.0.2 // indirect
	github.com/lestrrat-go/jwx/v3 v3.0.13 // indirect
	github.com/lestrrat-go/option/v2 v2.0.0 // indirect
	github.com/lucasb-eyer/go-colorful v1.2.0 // indirect
	github.com/mailru/easyjson v0.9.0 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-runewidth v0.0.16 // indirect
	github.com/mholt/archives v0.1.5 // indirect
	github.com/mikelolasagasti/xz v1.0.1 // indirect
	github.com/minio/minlz v1.0.1 // indirect
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/mitchellh/mapstructure v1.5.1-0.20231216201459-8508981c8b6c // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.3-0.20250322232337-35a7c28c31ee // indirect
	github.com/muesli/reflow v0.2.1-0.20210115123740-9e1d0d53df68 // indirect
	github.com/muesli/termenv v0.15.1 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/nwaples/rardecode/v2 v2.2.0 // indirect
	github.com/olekukonko/errors v1.1.0 // indirect
	github.com/olekukonko/ll v0.0.9 // indirect
	github.com/olekukonko/tablewriter v1.1.0 // indirect
	github.com/open-policy-agent/opa v1.13.1 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/pelletier/go-toml/v2 v2.2.4 // indirect
	github.com/pierrec/lz4/v4 v4.1.22 // indirect
	github.com/pjbgf/sha1cd v0.6.0 // indirect
	github.com/pkg/browser v0.0.0-20240102092130-5ac0b6a4141c // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/prometheus/client_golang v1.23.2 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.67.5 // indirect
	github.com/prometheus/procfs v0.17.0 // indirect
	github.com/rcrowley/go-metrics v0.0.0-20250401214520-65e299d6c5c9 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/rs/zerolog v1.33.0 // indirect
	github.com/ryanuber/go-glob v1.0.0 // indirect
	github.com/sagikazarmark/locafero v0.11.0 // indirect
	github.com/santhosh-tekuri/jsonschema/v5 v5.3.1 // indirect
	github.com/secure-systems-lab/go-securesystemslib v0.10.0 // indirect
	github.com/segmentio/asm v1.2.1 // indirect
	github.com/sergi/go-diff v1.4.0 // indirect
	github.com/shopspring/decimal v1.4.0 // indirect
	github.com/sigstore/fulcio v1.8.5 // indirect
	github.com/sigstore/protobuf-specs v0.5.0 // indirect
	github.com/sigstore/sigstore v1.10.4 // indirect
	github.com/sirupsen/logrus v1.9.4 // indirect
	github.com/skeema/knownhosts v1.3.1 // indirect
	github.com/sorairolake/lzip-go v0.3.8 // indirect
	github.com/sourcegraph/conc v0.3.1-0.20240121214520-5f936abd7ae8 // indirect
	github.com/spf13/afero v1.15.0 // indirect
	github.com/spf13/cast v1.10.0 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/spf13/viper v1.21.0 // indirect
	github.com/spiffe/go-spiffe/v2 v2.6.0 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	github.com/tchap/go-patricia/v2 v2.3.3 // indirect
	github.com/tetratelabs/wazero v1.9.0 // indirect
	github.com/transparency-dev/merkle v0.0.2 // indirect
	github.com/ulikunitz/xz v0.5.15 // indirect
	github.com/valyala/fastjson v1.6.7 // indirect
	github.com/vektah/gqlparser/v2 v2.5.31 // indirect
	github.com/wasilibs/go-re2 v1.9.0 // indirect
	github.com/wasilibs/wazero-helpers v0.0.0-20240620070341-3dff1577cd52 // indirect
	github.com/wk8/go-ordered-map/v2 v2.1.8 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/xanzy/ssh-agent v0.3.3 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20190905194746-02993c407bfb // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	github.com/yashtewari/glob-intersection v0.2.0 // indirect
	github.com/zalando/go-keyring v0.2.8 // indirect
	github.com/zricethezav/gitleaks/v8 v8.30.0 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.63.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.64.0 // indirect
	go.opentelemetry.io/otel v1.43.0 // indirect
	go.opentelemetry.io/otel/metric v1.43.0 // indirect
	go.opentelemetry.io/otel/sdk v1.43.0 // indirect
	go.opentelemetry.io/otel/trace v1.43.0 // indirect
	go.step.sm/crypto v0.76.0 // indirect
	go.yaml.in/yaml/v2 v2.4.3 // indirect
	go.yaml.in/yaml/v3 v3.0.4 // indirect
	go4.org v0.0.0-20230225012048-214862532bf5 // indirect
	golang.org/x/crypto v0.52.0 // indirect
	golang.org/x/exp v0.0.0-20260410095643-746e56fc9e2f // indirect
	golang.org/x/mod v0.36.0 // indirect
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/oauth2 v0.35.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/term v0.43.0 // indirect
	golang.org/x/text v0.37.0 // indirect
	golang.org/x/time v0.14.0 // indirect
	google.golang.org/api v0.266.0 // indirect
	google.golang.org/genproto v0.0.0-20260128011058-8636f8732409 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260128011058-8636f8732409 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260203192932-546029d2fa20 // indirect
	google.golang.org/grpc v1.79.3 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	gopkg.in/go-jose/go-jose.v2 v2.6.3 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/ini.v1 v1.67.1 // indirect
	gopkg.in/warnings.v0 v0.1.2 // indirect
	k8s.io/apimachinery v0.35.0 // indirect
	k8s.io/klog/v2 v2.130.1 // indirect
	k8s.io/kube-openapi v0.0.0-20250910181357-589584f1c912 // indirect
	k8s.io/utils v0.0.0-20251002143259-bc988d571ff4 // indirect
	sigs.k8s.io/json v0.0.0-20250730193827-2d320260d730 // indirect
	sigs.k8s.io/randfill v1.0.0 // indirect
	sigs.k8s.io/structured-merge-diff/v6 v6.3.0 // indirect
	sigs.k8s.io/yaml v1.6.0 // indirect
)
