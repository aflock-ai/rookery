// Copyright 2026 TestifySec, Inc.
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

package inclusionproof

import (
	"crypto"
	"crypto/subtle"
)

// hashSHA256 returns crypto.SHA256. Wrapped so the inclusion_proof.go file
// reads cleanly and we have one obvious place to swap the algorithm if
// (and only if) the package documentation's pinning is ever relaxed.
func hashSHA256() crypto.Hash { return crypto.SHA256 }

// subtleEqual is a passthrough to subtle.ConstantTimeCompare returning a
// bool. Kept out of the main attestor file so the cryptographic
// primitive isn't accidentally swapped for bytes.Equal in a refactor.
func subtleEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
