// Copyright 2024 The Witness Contributors
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

package environment

import (
	"strings"

	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/gobwas/glob"
)

// ObfuscateEnvironmentArray expects an array of strings representing environment variables.  Each element of the array is expected to be in the format of "KEY=VALUE".
// obfuscateList is the list of elements to obfuscate from variables, and for each element of variables that does not appear in the obfuscateList onAllowed will be called.
func ObfuscateEnvironmentArray(variables []string, obfuscateList map[string]struct{}, excludeKeys map[string]struct{}, onAllowed func(key, val, orig string)) { //nolint:gocognit // environment obfuscation requires complex matching logic
	obfuscateGlobList := []glob.Glob{}

	// Build a case-insensitive exact-match set from non-glob entries.
	// Without this, exact entries like "AWS_ACCESS_KEY_ID" only match that
	// exact casing — "aws_access_key_id" would slip through (R3-124).
	obfuscateListUpper := make(map[string]struct{}, len(obfuscateList))
	for k := range obfuscateList {
		if strings.Contains(k, "*") {
			// Normalize glob patterns to uppercase for case-insensitive matching.
			obfuscateGlobCompiled, err := glob.Compile(strings.ToUpper(k))
			if err != nil {
				log.Errorf("obfuscate glob pattern could not be interpreted: %v", err)
				continue
			}

			obfuscateGlobList = append(obfuscateGlobList, obfuscateGlobCompiled)
		} else {
			obfuscateListUpper[strings.ToUpper(k)] = struct{}{}
		}
	}

	for _, v := range variables {
		key, val := splitVariable(v)

		if _, inExcludKeys := excludeKeys[key]; !inExcludKeys {
			// Case-insensitive exact match for non-glob entries.
			if _, inObfuscateList := obfuscateListUpper[strings.ToUpper(key)]; inObfuscateList {
				val = "******"
			}

			for _, g := range obfuscateGlobList {
				// Normalize key to uppercase to match the uppercased glob patterns.
				matched, err := safeGlobMatch(g, strings.ToUpper(key))
				if err != nil {
					log.Debugf("glob match error for key %q: %v", key, err)
					continue
				}
				if matched {
					val = "******"
				}
			}
		}

		onAllowed(key, val, v)
	}
}
