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

package yubipiv

import (
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"fmt"
	"sync"
)

// yubicoPIVRootPEM is the Yubico PIV Attestation Root CA
// ("CN=Yubico PIV Root CA Serial 263751"), published at
// https://developers.yubico.com/PIV/Introduction/piv-attestation-ca.pem
// and vendored here so attestation verification never depends on a network
// fetch. SHA-256 fingerprint:
// 63:EC:E9:14:E5:4D:D8:79:15:F3:40:33:C8:5A:F4:C0:69:6B:A1:51:2F:8A:DD:66:CE:D7:38:33:12:07:B5:46
//
// Yubico has issued exactly one PIV attestation root to date. If Yubico rotates
// the root, add the new cert to this pool (verification accepts any embedded
// root); callers needing a different trust anchor can use VerifyWithRoots.
//
//go:embed yubico_piv_root_ca.pem
var yubicoPIVRootPEM []byte

var (
	rootOnce sync.Once
	rootPool *x509.CertPool
	rootErr  error
)

// yubicoRoots returns the vendored Yubico PIV Root CA pool, parsed once.
func yubicoRoots() (*x509.CertPool, error) {
	rootOnce.Do(func() {
		pool := x509.NewCertPool()
		rest := yubicoPIVRootPEM
		n := 0
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				continue
			}
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				rootErr = fmt.Errorf("yubipiv: parse embedded root CA: %w", err)
				return
			}
			pool.AddCert(c)
			n++
		}
		if n == 0 {
			rootErr = fmt.Errorf("yubipiv: no CERTIFICATE found in embedded root CA bundle")
			return
		}
		rootPool = pool
	})
	return rootPool, rootErr
}
