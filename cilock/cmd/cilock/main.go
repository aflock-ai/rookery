//go:debug fips140=on

// CIlock is a witness-compatible CI attestation CLI with all attestors and signers.
package main

import (
	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/cilock/internal/cmd"

	// All attestor plugins
	_ "github.com/aflock-ai/rookery/plugins/attestors/aws-codebuild"
	_ "github.com/aflock-ai/rookery/plugins/attestors/aws-iid"
	_ "github.com/aflock-ai/rookery/plugins/attestors/commandrun"
	_ "github.com/aflock-ai/rookery/plugins/attestors/configuration"
	_ "github.com/aflock-ai/rookery/plugins/attestors/docker"
	_ "github.com/aflock-ai/rookery/plugins/attestors/environment"
	_ "github.com/aflock-ai/rookery/plugins/attestors/gcp-iit"
	_ "github.com/aflock-ai/rookery/plugins/attestors/git"
	_ "github.com/aflock-ai/rookery/plugins/attestors/github"
	_ "github.com/aflock-ai/rookery/plugins/attestors/githubwebhook"
	_ "github.com/aflock-ai/rookery/plugins/attestors/gitlab"
	_ "github.com/aflock-ai/rookery/plugins/attestors/jenkins"
	_ "github.com/aflock-ai/rookery/plugins/attestors/jwt"
	_ "github.com/aflock-ai/rookery/plugins/attestors/k8smanifest"
	_ "github.com/aflock-ai/rookery/plugins/attestors/link"
	_ "github.com/aflock-ai/rookery/plugins/attestors/lockfiles"
	_ "github.com/aflock-ai/rookery/plugins/attestors/material"
	_ "github.com/aflock-ai/rookery/plugins/attestors/maven"
	_ "github.com/aflock-ai/rookery/plugins/attestors/oci"
	_ "github.com/aflock-ai/rookery/plugins/attestors/omnitrail"
	_ "github.com/aflock-ai/rookery/plugins/attestors/policyverify"
	_ "github.com/aflock-ai/rookery/plugins/attestors/product"
	_ "github.com/aflock-ai/rookery/plugins/attestors/sarif"
	_ "github.com/aflock-ai/rookery/plugins/attestors/sbom"
	_ "github.com/aflock-ai/rookery/plugins/attestors/secretscan"
	_ "github.com/aflock-ai/rookery/plugins/attestors/slsa"
	_ "github.com/aflock-ai/rookery/plugins/attestors/system-packages"
	_ "github.com/aflock-ai/rookery/plugins/attestors/vex"

	// All signer plugins
	_ "github.com/aflock-ai/rookery/plugins/signers/debug-signer"
	_ "github.com/aflock-ai/rookery/plugins/signers/file"
	_ "github.com/aflock-ai/rookery/plugins/signers/fulcio"
	_ "github.com/aflock-ai/rookery/plugins/signers/kms/aws"
	_ "github.com/aflock-ai/rookery/plugins/signers/kms/azure"
	_ "github.com/aflock-ai/rookery/plugins/signers/kms/gcp"
	_ "github.com/aflock-ai/rookery/plugins/signers/spiffe"
	_ "github.com/aflock-ai/rookery/plugins/signers/vault"
	_ "github.com/aflock-ai/rookery/plugins/signers/vault-transit"
)

func main() {
	// Register legacy witness.dev type aliases so cilock can consume
	// attestations produced by witness (and vice versa).
	attestation.RegisterLegacyAliases()
	cmd.Execute()
}
