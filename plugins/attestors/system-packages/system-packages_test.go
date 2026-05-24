// Copyright 2025 The Witness Contributors
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

package systempackages

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestNewSystemPackagesAttestor_AmazonLinux2023 verifies that an os-release
// file with ID="amzn" selects the RPM backend, not the Debian fallback.
// Regression test for rookery#110: Amazon Linux 2023's /etc/os-release uses
// ID="amzn" while the case statement only matched "amazon".
func TestNewSystemPackagesAttestor_AmazonLinux2023(t *testing.T) {
	osRelease := `NAME="Amazon Linux"
VERSION="2023"
ID="amzn"
ID_LIKE="fedora"
VERSION_ID="2023"
PLATFORM_ID="platform:al2023"
PRETTY_NAME="Amazon Linux 2023"
ANSI_COLOR="0;33"
CPE_NAME="cpe:2.3:o:amazon:amazon_linux:2023"
HOME_URL="https://aws.amazon.com/linux/amazon-linux-2023/"
`
	path := filepath.Join(t.TempDir(), "os-release")
	require.NoError(t, os.WriteFile(path, []byte(osRelease), 0644))

	a := newSystemPackagesAttestorWithPath(path)
	require.NotNil(t, a)
	_, ok := a.backend.(*RPMBackend)
	require.True(t, ok, "expected RPMBackend for Amazon Linux 2023 (ID=amzn), got %T", a.backend)
}

// TestNewSystemPackagesAttestor_AmazonLinux2 verifies the historical "amazon"
// ID still maps to the RPM backend.
func TestNewSystemPackagesAttestor_AmazonLinux2(t *testing.T) {
	osRelease := `NAME="Amazon Linux"
VERSION="2"
ID="amazon"
ID_LIKE="centos rhel fedora"
VERSION_ID="2"
PRETTY_NAME="Amazon Linux 2"
`
	path := filepath.Join(t.TempDir(), "os-release")
	require.NoError(t, os.WriteFile(path, []byte(osRelease), 0644))

	a := newSystemPackagesAttestorWithPath(path)
	require.NotNil(t, a)
	_, ok := a.backend.(*RPMBackend)
	require.True(t, ok, "expected RPMBackend for Amazon Linux 2 (ID=amazon), got %T", a.backend)
}

// TestNewSystemPackagesAttestor_Debian verifies the Debian backend still
// gets selected for Debian-family distros.
func TestNewSystemPackagesAttestor_Debian(t *testing.T) {
	osRelease := `NAME="Ubuntu"
VERSION="22.04 LTS"
ID=ubuntu
ID_LIKE=debian
VERSION_ID="22.04"
`
	path := filepath.Join(t.TempDir(), "os-release")
	require.NoError(t, os.WriteFile(path, []byte(osRelease), 0644))

	a := newSystemPackagesAttestorWithPath(path)
	require.NotNil(t, a)
	_, ok := a.backend.(*DebianBackend)
	require.True(t, ok, "expected DebianBackend for Ubuntu, got %T", a.backend)
}
