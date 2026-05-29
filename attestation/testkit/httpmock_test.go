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

package testkit

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
)

// TestStartMetadataMockServesRecordedIMDS proves the http-mock driver's metadata
// server replays the committed recorded IMDS responses to a REAL AWS SDK IMDS
// client — the exact client construction (config.LoadDefaultConfig +
// imds.NewFromConfig) the aws-iid attestor uses. It is the failing-first test
// for the http-mock driver: without startMetadataMock + the endpoint env wiring,
// the SDK client has no endpoint to reach and the dynamic-data fetch fails.
func TestStartMetadataMockServesRecordedIMDS(t *testing.T) {
	dir := t.TempDir()
	wantDoc := []byte(`{"instanceId":"i-0test","region":"us-east-1","accountId":"111122223333"}`)
	wantSig := []byte("ZHVtbXktc2lnbmF0dXJl")
	mustWrite(t, filepath.Join(dir, "doc.json"), wantDoc)
	mustWrite(t, filepath.Join(dir, "sig.txt"), wantSig)

	fx := &Fixture{
		Name: "imds",
		Dir:  dir,
		Mode: ModeHTTPMock,
		Options: map[string]any{
			optIMDSDocument:  "doc.json",
			optIMDSSignature: "sig.txt",
		},
	}

	srv := startMetadataMock(t, fx)
	t.Setenv(metadataEndpointEnv, srv.URL)

	cfg, err := awsconfig.LoadDefaultConfig(context.Background(), awsconfig.WithRegion("us-east-1"))
	if err != nil {
		t.Fatalf("load aws config: %v", err)
	}
	client := imds.NewFromConfig(cfg)

	gotDoc := fetchDynamic(t, client, "instance-identity/document")
	if string(gotDoc) != string(wantDoc) {
		t.Errorf("document = %q, want %q", gotDoc, wantDoc)
	}
	gotSig := fetchDynamic(t, client, "instance-identity/signature")
	if string(gotSig) != string(wantSig) {
		t.Errorf("signature = %q, want %q", gotSig, wantSig)
	}
}

func fetchDynamic(t *testing.T, c *imds.Client, path string) []byte {
	t.Helper()
	out, err := c.GetDynamicData(context.Background(), &imds.GetDynamicDataInput{Path: path})
	if err != nil {
		t.Fatalf("GetDynamicData(%s): %v", path, err)
	}
	b, err := io.ReadAll(out.Content)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

func mustWrite(t *testing.T, p string, b []byte) {
	t.Helper()
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
}
