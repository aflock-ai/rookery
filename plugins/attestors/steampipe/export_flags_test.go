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

// export_flags_test.go proves the two recordability bugs are fixed:
//
//  1. Export() defaults FALSE (embed the predicate in the signed collection)
//     and is opt-in via the registered "export" config option — mirroring the
//     sbom attestor. The old code hardcoded `return true`, which forced cilock
//     to strip the steampipe predicate into a sidecar that the verification
//     harness could not read.
//
//  2. The plugin / sql / id config options the CLI exposes as
//     --attestor-steampipe-{plugin,sql,id} actually drive the frontmatter (and
//     therefore the convention-keyed subjects). The old code set frontmatter
//     ONLY via the Go-API WithFrontmatter option the recipe driver calls, so a
//     plain `cilock run --attestations steampipe` emitted ZERO subjects.

package steampipe

import (
	"crypto"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
)

func sha256Hashes() []cryptoutil.DigestValue {
	return []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
}

func keysOfSubjects(m map[string]cryptoutil.DigestSet) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestExportDefaultsFalse(t *testing.T) {
	a := New()
	if a.export != defaultExport {
		t.Errorf("New().export = %t, want default %t", a.export, defaultExport)
	}
	if defaultExport != false {
		t.Errorf("defaultExport = %t, want false (embed predicate in collection by default)", defaultExport)
	}
	if a.Export() != false {
		t.Errorf("New().Export() = %t, want false — predicate must EMBED in the signed collection, not self-export to a sidecar", a.Export())
	}

	WithExport(true)(a)
	if !a.export || a.Export() != true {
		t.Errorf("WithExport(true) did not flip export on: export=%t Export()=%t", a.export, a.Export())
	}
}

// TestRegisteredExportDefaultsFalse exercises the path the CLI uses:
// attestation.GetAttestor applies the registered options' DEFAULT values.
// The default must leave Export() false so the predicate embeds.
func TestRegisteredExportDefaultsFalse(t *testing.T) {
	at, err := attestation.GetAttestor(Name)
	if err != nil {
		t.Fatalf("GetAttestor(%q): %v", Name, err)
	}
	exp, ok := at.(attestation.Exporter)
	if !ok {
		t.Fatalf("registered steampipe attestor is not an Exporter")
	}
	if exp.Export() {
		t.Errorf("registered attestor Export() defaults true — must default false so the predicate embeds in the signed collection")
	}
}

// TestPluginOptionDrivesFrontmatterAndSubjects proves the CLI-exposed
// "plugin"/"sql"/"id" options set the frontmatter so a plain (non-recipe) run
// produces convention-keyed subjects.
func TestPluginOptionDrivesFrontmatterAndSubjects(t *testing.T) {
	a := New()
	WithPlugin("aws")(a)
	WithID("aws-iam-users")(a)
	WithSQL("select account_id, arn from aws_iam_user")(a)

	if a.frontmatter.Plugin != "aws" {
		t.Errorf("WithPlugin did not set frontmatter.Plugin: got %q", a.frontmatter.Plugin)
	}
	if a.frontmatter.ID != "aws-iam-users" {
		t.Errorf("WithID did not set frontmatter.ID: got %q", a.frontmatter.ID)
	}
	if a.sql != "select account_id, arn from aws_iam_user" {
		t.Errorf("WithSQL did not set sql: got %q", a.sql)
	}

	// The plugin name is the routing key the subject convention reads. With it
	// set, an aws row must fan out aws:account:/aws:arn: subjects.
	rows := []map[string]any{{
		"account_id": "898769392027",
		"arn":        "arn:aws:iam::898769392027:user/demo",
	}}
	a.accumulateSubjects(rows, sha256Hashes())
	subs := a.Subjects()
	for _, want := range []string{"aws:account:898769392027", "aws:arn:arn:aws:iam::898769392027:user/demo"} {
		if _, ok := subs[want]; !ok {
			t.Errorf("plugin-driven subject %q missing; got %v", want, keysOfSubjects(subs))
		}
	}
}

// TestEmptyPluginOptionIsNoOp ensures applying the option default ("") through
// the registry does not clobber a frontmatter the recipe driver already set.
func TestEmptyPluginOptionIsNoOp(t *testing.T) {
	a := New()
	WithFrontmatter(QueryFrontmatter{Plugin: "aws", ID: "preset"})(a)
	WithPlugin("")(a) // registry SetDefaultVals applies the "" default
	WithID("")(a)
	WithSQL("")(a)
	if a.frontmatter.Plugin != "aws" || a.frontmatter.ID != "preset" {
		t.Errorf("empty option clobbered preset frontmatter: %+v", a.frontmatter)
	}
}

// TestPluginOptionViaRegistry drives the option through the registered setter,
// exactly as the cilock --attestor-steampipe-plugin flag does.
func TestPluginOptionViaRegistry(t *testing.T) {
	at, err := attestation.GetAttestor(Name)
	if err != nil {
		t.Fatalf("GetAttestor: %v", err)
	}
	applied, err := attestation.ApplyAttestorOptions(Name, at, map[string]any{
		"plugin": "aws",
		"sql":    "select account_id from aws_iam_user",
		"id":     "aws-iam-users",
	})
	if err != nil {
		t.Fatalf("ApplyAttestorOptions: %v", err)
	}
	sp, ok := applied.(*Attestor)
	if !ok {
		t.Fatalf("applied attestor is not *steampipe.Attestor: %T", applied)
	}
	if sp.frontmatter.Plugin != "aws" {
		t.Errorf("registry-applied plugin not set: %q", sp.frontmatter.Plugin)
	}
	if sp.sql != "select account_id from aws_iam_user" {
		t.Errorf("registry-applied sql not set: %q", sp.sql)
	}
	if sp.frontmatter.ID != "aws-iam-users" {
		t.Errorf("registry-applied id not set: %q", sp.frontmatter.ID)
	}
}
