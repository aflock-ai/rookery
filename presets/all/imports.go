// Copyright 2025 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package all registers all available attestor and signer plugins.
package all

import (
	// attestors
	_ "github.com/aflock-ai/rookery/plugins/attestors/aws-codebuild"
	_ "github.com/aflock-ai/rookery/plugins/attestors/aws-iid"
	_ "github.com/aflock-ai/rookery/plugins/attestors/commandrun"
	_ "github.com/aflock-ai/rookery/plugins/attestors/configuration"
	_ "github.com/aflock-ai/rookery/plugins/attestors/docker"
	_ "github.com/aflock-ai/rookery/plugins/attestors/environment"
	_ "github.com/aflock-ai/rookery/plugins/attestors/gcp-iit"
	_ "github.com/aflock-ai/rookery/plugins/attestors/git"
	_ "github.com/aflock-ai/rookery/plugins/attestors/github"
	_ "github.com/aflock-ai/rookery/plugins/attestors/githubaction"
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
	_ "github.com/aflock-ai/rookery/plugins/attestors/product"
	_ "github.com/aflock-ai/rookery/plugins/attestors/sarif"
	_ "github.com/aflock-ai/rookery/plugins/attestors/sbom"
	_ "github.com/aflock-ai/rookery/plugins/attestors/secretscan"
	_ "github.com/aflock-ai/rookery/plugins/attestors/slsa"
	_ "github.com/aflock-ai/rookery/plugins/attestors/system-packages"
	_ "github.com/aflock-ai/rookery/plugins/attestors/vex"
	_ "github.com/aflock-ai/rookery/plugins/attestors/vsa"

	// signer providers
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
