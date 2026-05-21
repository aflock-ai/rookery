// Copyright 2025 The Witness Contributors
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

package k8smanifest

import (
	"github.com/aflock-ai/rookery/plugins/attestors/k8smanifest/internal/ociref"
)

// defaultResolver is shared so callers don't pay the cost of constructing one
// per Reference. The zero value uses http.DefaultClient.
var defaultResolver = &ociref.Resolver{}

// DigestForRef parses an OCI image reference and resolves it to its content
// digest via the registry's /v2 manifest endpoint.
func DigestForRef(reference string) (string, error) {
	return defaultResolver.Resolve(reference)
}
