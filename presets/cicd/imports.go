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

// Package cicd registers attestor and signer plugins commonly used in CI/CD pipelines.
package cicd

import (
	// attestors
	_ "github.com/aflock-ai/rookery/plugins/attestors/commandrun"
	_ "github.com/aflock-ai/rookery/plugins/attestors/configuration"
	_ "github.com/aflock-ai/rookery/plugins/attestors/environment"
	_ "github.com/aflock-ai/rookery/plugins/attestors/git"
	_ "github.com/aflock-ai/rookery/plugins/attestors/github"
	_ "github.com/aflock-ai/rookery/plugins/attestors/gitlab"
	_ "github.com/aflock-ai/rookery/plugins/attestors/material"
	_ "github.com/aflock-ai/rookery/plugins/attestors/product"
	_ "github.com/aflock-ai/rookery/plugins/attestors/slsa"

	// signer providers
	_ "github.com/aflock-ai/rookery/plugins/signers/file"
)
