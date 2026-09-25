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

package material

import (
	"fmt"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/registry"
)

// optBind is the config option behind --attestor-material-bind (#9946).
const optBind = "bind"

// binding records one file as a material under a chosen path.
//
// artifactsFrom compares a step's materials to an upstream step's artifacts BY
// PATH, so a downstream step that consumes an upstream product from somewhere
// else (the release sign job extracts the binary into a scratch directory,
// while build recorded it as /tmp/build/cilock) never lines up with it. A
// binding names the key explicitly: the digest is always of the bytes the file
// held when the material phase ran, before the wrapped command, and only the
// key is chosen. The key is a label; the digest is what the verifier compares.
type binding struct {
	recorded string // key in the materials map
	file     string // file hashed at material time
}

// parseBindings validates "RECORDED=FILE" specs. RECORDED must be a clean
// path with no ".." segment; FILE must be non-empty; RECORDED must be unique.
func parseBindings(specs []string) ([]binding, error) {
	out := make([]binding, 0, len(specs))
	seen := make(map[string]struct{}, len(specs))
	for _, spec := range specs {
		recorded, file, ok := strings.Cut(spec, "=")
		if !ok || recorded == "" || file == "" {
			return nil, fmt.Errorf("material bind %q: want RECORDED_PATH=FILE", spec)
		}
		if path.Clean(recorded) != recorded || recorded == "." {
			return nil, fmt.Errorf("material bind %q: recorded path must be clean", spec)
		}
		for _, seg := range strings.Split(recorded, "/") {
			if seg == ".." {
				return nil, fmt.Errorf("material bind %q: recorded path must not contain '..'", spec)
			}
		}
		if strings.Contains(file, "=") || strings.Contains(file, ",") {
			return nil, fmt.Errorf("material bind %q: one RECORDED_PATH=FILE per value", spec)
		}
		if _, dup := seen[recorded]; dup {
			return nil, fmt.Errorf("material bind %q: recorded path bound twice", spec)
		}
		seen[recorded] = struct{}{}
		out = append(out, binding{recorded: recorded, file: file})
	}
	return out, nil
}

// SetBindings configures --attestor-material-bind values. It fails on a
// malformed spec rather than dropping it.
func (a *Attestor) SetBindings(specs []string) error {
	b, err := parseBindings(specs)
	if err != nil {
		return err
	}
	a.bindings = b
	return nil
}

// hashBindings digests every bound file. Called in the material phase, before
// the wrapped command runs, so an in-place signer cannot change what is
// recorded. A missing or unreadable file fails the attestor: a binding exists
// because the policy needs that material, and dropping it would only move the
// failure to verification with a worse message.
func (a *Attestor) hashBindings(ctx *attestation.AttestationContext) error {
	if len(a.bindings) == 0 {
		return nil
	}
	a.bound = make(map[string]cryptoutil.DigestSet, len(a.bindings))
	for _, b := range a.bindings {
		// A relative FILE names a file in the attestation's working directory
		// (--workingdir), the same tree the walk records, not the process cwd.
		file := b.file
		if !filepath.IsAbs(file) {
			file = filepath.Join(ctx.WorkingDir(), file)
		}
		ds, err := cryptoutil.CalculateDigestSetFromFile(file, ctx.Hashes())
		if err != nil {
			return fmt.Errorf("material bind %s=%s: %w", b.recorded, b.file, err)
		}
		a.bound[b.recorded] = ds
	}
	return nil
}

// mergeBound adds the bound materials to mats. A path already present with a
// different digest is a contradiction about what the step consumed at that
// path, so it fails instead of choosing one.
func (a *Attestor) mergeBound(mats map[string]cryptoutil.DigestSet) error {
	keys := make([]string, 0, len(a.bound))
	for k := range a.bound {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		ds := a.bound[k]
		if existing, ok := mats[k]; ok && !existing.Equal(ds) {
			return fmt.Errorf("material bind %s: the capture also recorded this path with a different digest", k)
		}
		mats[k] = ds
	}
	return nil
}

func configOptions() []registry.Configurer {
	return []registry.Configurer{
		registry.StringSliceConfigOption(
			optBind,
			"Record FILE as a material under RECORDED_PATH (RECORDED_PATH=FILE, repeatable). The digest is taken before the command runs. Use it to consume an upstream step's product under the path that step recorded, so policy artifactsFrom compares the two digests.",
			nil,
			func(at attestation.Attestor, specs []string) (attestation.Attestor, error) {
				m, ok := at.(*Attestor)
				if !ok {
					return at, fmt.Errorf("unexpected attestor type: %T is not a material attestor", at)
				}
				if err := m.SetBindings(specs); err != nil {
					return m, err
				}
				return m, nil
			},
		),
	}
}
