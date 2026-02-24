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
	"fmt"
	"strings"

	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/gobwas/glob"
)

// safeGlobMatch wraps glob.Match with panic recovery. The gobwas/glob library
// can panic on certain patterns that compile successfully but trigger out-of-bounds
// access during matching. We treat panics as non-matches.
func safeGlobMatch(g glob.Glob, s string) (matched bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			matched = false
			err = fmt.Errorf("glob match panicked: %v", r)
		}
	}()
	return g.Match(s), nil
}

// FilterEnvironmentArray expects an array of strings representing environment variables.  Each element of the array is expected to be in the format of "KEY=VALUE".
// blockList is the list of elements to filter from variables, and for each element of variables that does not appear in the blockList onAllowed will be called.
func FilterEnvironmentArray(variables []string, blockList map[string]struct{}, excludeKeys map[string]struct{}, onAllowed func(key, val, orig string)) { //nolint:gocognit // environment filtering requires complex matching logic
	filterGlobList := []glob.Glob{}

	// Build a case-insensitive exact-match set from non-glob entries.
	// Without this, exact entries like "AWS_ACCESS_KEY_ID" only match that
	// exact casing — "aws_access_key_id" would slip through (R3-124).
	blockListUpper := make(map[string]struct{}, len(blockList))
	for k := range blockList {
		if strings.Contains(k, "*") {
			// Normalize glob patterns to uppercase for case-insensitive matching.
			// The default sensitive list uses uppercase patterns like *TOKEN*, *SECRET*,
			// but env var keys may be lowercase (e.g. my_token, aws_secret_key).
			filterGlobCompiled, err := glob.Compile(strings.ToUpper(k))
			if err != nil {
				log.Errorf("filter glob pattern could not be interpreted: %v", err)
				continue
			}

			filterGlobList = append(filterGlobList, filterGlobCompiled)
		} else {
			blockListUpper[strings.ToUpper(k)] = struct{}{}
		}
	}

	for _, v := range variables {
		key, val := splitVariable(v)
		filterOut := false

		if _, inExcludKeys := excludeKeys[key]; !inExcludKeys {
			// Case-insensitive exact match for non-glob entries.
			if _, inBlockList := blockListUpper[strings.ToUpper(key)]; inBlockList {
				filterOut = true
			}

			for _, g := range filterGlobList {
				// Normalize key to uppercase to match the uppercased glob patterns.
				matched, err := safeGlobMatch(g, strings.ToUpper(key))
				if err != nil {
					log.Debugf("glob match error for key %q: %v", key, err)
					continue
				}
				if matched {
					filterOut = true
					break
				}
			}
		}

		if !filterOut {
			onAllowed(key, val, v)
		}
	}
}
