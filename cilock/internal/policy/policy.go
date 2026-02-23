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

package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/aflock-ai/rookery/attestation/archivista"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/log"
)

// LoadPolicy attempts to load a policy from a file path. If the path is not a
// local file and an archivista client is provided, it treats the path as a
// gitoid and attempts to download the policy from the Archivista server.
func LoadPolicy(ctx context.Context, policyPath string, ac *archivista.Client) (dsse.Envelope, error) {
	policyEnvelope := dsse.Envelope{}

	filePolicy, err := os.Open(policyPath)
	if err != nil {
		if ac != nil {
			log.Infof("failed to open policy file, attempting to load from archivista: %v", err)
			return ac.Download(ctx, policyPath)
		}
		return policyEnvelope, fmt.Errorf("failed to open policy file: %w", err)
	}

	defer func() {
		if err := filePolicy.Close(); err != nil {
			log.Errorf("failed to close policy file: %v", err)
		}
	}()

	decoder := json.NewDecoder(filePolicy)
	if err := decoder.Decode(&policyEnvelope); err != nil {
		return policyEnvelope, fmt.Errorf("could not unmarshal policy envelope: %w", err)
	}

	return policyEnvelope, nil
}
