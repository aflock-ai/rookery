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

package gcpiit

import (
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/plugins/attestors/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	a := New()
	require.NotNil(t, a)
	assert.Equal(t, Name, a.Name())
	assert.Equal(t, Type, a.Type())
	assert.Equal(t, RunType, a.RunType())
}

func TestConstants(t *testing.T) {
	assert.Equal(t, "gcp-iit", Name)
	assert.Equal(t, "https://aflock.ai/attestations/gcp-iit/v0.1", Type)
	assert.Equal(t, attestation.PreMaterialRunType, RunType)
}

func TestSchema(t *testing.T) {
	a := New()
	schema := a.Schema()
	assert.NotNil(t, schema)
}

func TestErrNotGCPIIT(t *testing.T) {
	err := ErrNotGCPIIT{}
	assert.Equal(t, "not a GCP IIT JWT", err.Error())
	assert.Implements(t, (*error)(nil), err)
}

func TestAttestorInterfaces(t *testing.T) {
	a := New()
	assert.Implements(t, (*attestation.Attestor)(nil), a)
	assert.Implements(t, (*attestation.Subjecter)(nil), a)
}

func TestSubjects(t *testing.T) {
	a := &Attestor{
		InstanceID:       "i-1234567890abcdef0",
		InstanceHostname: "my-instance.us-central1-a.c.my-project.internal",
		ProjectID:        "my-project-123",
		ProjectNumber:    "123456789",
		ClusterUID:       "cluster-uid-abc",
	}

	subjects := a.Subjects()
	assert.NotNil(t, subjects)
	assert.Len(t, subjects, 5)

	expectedPrefixes := []string{
		"instanceid:i-1234567890abcdef0",
		"instancename:my-instance.us-central1-a.c.my-project.internal",
		"projectid:my-project-123",
		"projectnumber:123456789",
		"clusteruid:cluster-uid-abc",
	}
	for _, prefix := range expectedPrefixes {
		_, ok := subjects[prefix]
		assert.True(t, ok, "Expected subject not found: %s", prefix)
	}
}

func TestSubjectsEmpty(t *testing.T) {
	a := &Attestor{}
	subjects := a.Subjects()
	assert.NotNil(t, subjects)
	// Empty fields still produce subjects with empty string digests
	assert.Len(t, subjects, 5)
}

func TestIdentityTokenURL(t *testing.T) {
	tests := []struct {
		name           string
		host           string
		serviceAccount string
		wantContains   []string
	}{
		{
			name:           "default service account",
			host:           "metadata.google.internal",
			serviceAccount: "default",
			wantContains: []string{
				"http://metadata.google.internal",
				"/computeMetadata/v1/instance/service-accounts/default/identity",
				"audience=witness-node-attestor",
				"format=full",
			},
		},
		{
			name:           "custom service account",
			host:           "custom-host",
			serviceAccount: "my-sa@project.iam.gserviceaccount.com",
			wantContains: []string{
				"http://custom-host",
				"my-sa@project.iam.gserviceaccount.com",
				"audience=witness-node-attestor",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := identityTokenURL(tt.host, tt.serviceAccount)
			for _, want := range tt.wantContains {
				assert.Contains(t, got, want)
			}
		})
	}
}

func TestParseJWTProjectInfo(t *testing.T) {
	tests := []struct {
		name       string
		claims     map[string]interface{}
		wantID     string
		wantName   string
		wantErr    bool
		errContain string
	}{
		{
			name: "valid email claim",
			claims: map[string]interface{}{
				"email": "sa@my-project-123456.iam.gserviceaccount.com",
			},
			wantID:   "123456",
			wantName: "my-project",
		},
		{
			name: "single segment project",
			claims: map[string]interface{}{
				"email": "sa@projectname-789.iam.gserviceaccount.com",
			},
			wantID:   "789",
			wantName: "projectname",
		},
		{
			name:       "no email claim",
			claims:     map[string]interface{}{},
			wantErr:    true,
			errContain: "unable to find email claim",
		},
		{
			name: "nil email claim",
			claims: map[string]interface{}{
				"email": nil,
			},
			wantErr:    true,
			errContain: "unable to find email claim",
		},
		{
			name: "email without @",
			claims: map[string]interface{}{
				"email": "invalid-email",
			},
			wantErr:    true,
			errContain: "unable to parse email",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jwtAttestor := jwt.New()
			jwtAttestor.Claims = tt.claims

			gotID, gotName, err := parseJWTProjectInfo(jwtAttestor)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContain != "" {
					assert.Contains(t, err.Error(), tt.errContain)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.wantID, gotID)
				assert.Equal(t, tt.wantName, gotName)
			}
		})
	}
}

func TestAttestFailsOutsideGCP(t *testing.T) {
	// Attest should fail when not running on GCP (can't reach metadata server)
	a := New()
	ctx, err := attestation.NewContext("test", []attestation.Attestor{})
	require.NoError(t, err)

	err = a.Attest(ctx)
	assert.Error(t, err, "Attest should fail when GCP metadata server is unreachable")
}
