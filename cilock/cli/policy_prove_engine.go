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

package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/log"
	attpolicy "github.com/aflock-ai/rookery/attestation/policy"
)

// The record-and-verify engine behind `cilock policy prove`: a scratch
// key, one `cilock run` per step, a scratch-signed policy, and a local
// verify whose refusal names the step and rule.
// proveFlagOffline keeps every cilock the engine spawns off the network.
const proveFlagOffline = "--offline"

func writeScratchKey(dir string) (keyPath, pubPath, keyID string, pubPEM []byte, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", "", nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", "", "", nil, err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", "", "", nil, err
	}
	keyPath = filepath.Join(dir, "scratch.key")
	pubPath = filepath.Join(dir, "scratch.pub")
	pubPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return "", "", "", nil, err
	}
	if err := os.WriteFile(pubPath, pubPEM, 0o600); err != nil {
		return "", "", "", nil, err
	}
	v, err := cryptoutil.NewVerifierFromReader(bytes.NewReader(pubPEM))
	if err != nil {
		return "", "", "", nil, err
	}
	keyID, err = v.KeyID()
	return keyPath, pubPath, keyID, pubPEM, err
}

type prover struct {
	ctx     context.Context
	self    string
	workdir string
	scratch string
	keyPath string
	pubPath string
	// signed is the scratch-signed policy verify checks evidence against.
	signed  string
	stderr  io.Writer
	runArgs []string
	// edges is each step's artifactsFrom, so a broken edge is reported as
	// producer->consumer.
	edges map[string][]string
}

// record runs `cilock run` for one step and returns the envelope path, or ""
// and the tail of the run's output when it wrote none. The wrapped command's
// output goes to stderr, so the report on stdout stays first.
func (p *prover) record(step, kind string, attestors []string, traced bool, argv []string) (string, string) {
	out := filepath.Join(p.scratch, fmt.Sprintf("%s.%s.json", step, kind))
	args := []string{"run", proveFlagOffline, "--enable-archivista=false", "-k", p.keyPath, "--step", step, "--material-manifest", "-o", out}
	for _, a := range attestors {
		args = append(args, "-a", a)
	}
	if traced {
		args = append(args, "--trace")
	}
	args = append(args, p.runArgs...)
	args = append(args, "--")
	args = append(args, argv...)
	_, _ = fmt.Fprintf(p.stderr, "cilock policy prove: recording the %s run of step %s: %s\n", kind, step, shellQuoteArgv(argv))
	tail := &tailBuffer{max: 600}
	c := exec.CommandContext(p.ctx, p.self, args...) //nolint:gosec // the agent's own command, through this cilock binary
	c.Dir = p.workdir
	// One writer for both streams: os/exec then copies them on a single
	// goroutine, and the tail locks regardless.
	both := io.MultiWriter(p.stderr, tail)
	c.Stdout = both
	c.Stderr = both
	c.Env = append(os.Environ(), "CILOCK_SKIP_VERSION_CHECK=1")
	runErr := c.Run()
	if _, err := os.Stat(out); err != nil {
		reason := strings.TrimSpace(tail.String())
		if runErr != nil {
			reason = runErr.Error() + ": " + reason
		}
		return "", lastLine(reason)
	}
	return out, ""
}

// signScratch writes the scratch copy of the draft, whose functionaries name
// the throwaway key and whose platform trust entries are dropped, and signs
// it with that key. This is the documented offline proof path: an explicit
// -k signer is never the enrolled agent (sign.go refuseAgentPolicySigning).
func (p *prover) signScratch(doc draftDoc, keyID string, pubPEM []byte) (string, error) {
	raw, err := encodeDraft(doc)
	if err != nil {
		return "", err
	}
	var scratch draftDoc
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&scratch); err != nil {
		return "", err
	}
	for _, name := range sortedStepNames(scratch) {
		step := asMap(draftSteps(scratch)[name])
		step["functionaries"] = []any{map[string]any{draftKeyType: flagPublicKey, "publickeyid": keyID}}
	}
	scratch["publickeys"] = map[string]any{keyID: map[string]any{"keyid": keyID, "key": base64.StdEncoding.EncodeToString(pubPEM)}}
	delete(scratch, "roots")
	delete(scratch, "timestampauthorities")
	unsigned := filepath.Join(p.scratch, "scratch-policy.json")
	if err := saveDraft(unsigned, scratch, false); err != nil {
		return "", err
	}
	signed := filepath.Join(p.scratch, "scratch-policy.signed.json")
	restore := silenceLog()
	defer restore()
	cmd := SignCmd()
	cmd.SetArgs([]string{proveFlagOffline, "-k", p.keyPath, "-f", unsigned, "-o", signed})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	if err := cmd.ExecuteContext(p.ctx); err != nil {
		return "", fmt.Errorf("sign the scratch copy: %w", err)
	}
	return signed, nil
}

// verify runs `cilock verify` in-process over the given envelopes and returns
// the reasons each refused step gave. A nil map and nil error is a pass; an
// error is a verify that could not reach a per-step verdict.
func (p *prover) verify(envelopes []string) (map[string][]string, error) {
	subjects := envelopeSubjects(envelopes)
	args := make([]string, 0, 6+2*len(envelopes)+2*len(subjects))
	args = append(args, proveFlagOffline, "--no-embedded-trust", "-p", p.signed, "-k", p.pubPath)
	for _, e := range envelopes {
		args = append(args, "-a", e)
	}
	for _, s := range subjects {
		args = append(args, "-s", s)
	}
	restore := silenceLog()
	cmd := VerifyCmd()
	cmd.SetArgs(args)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	err := cmd.ExecuteContext(p.ctx)
	restore()
	if err == nil {
		return nil, nil
	}
	var rejection *verifyRejectionError
	if !errors.As(err, &rejection) {
		return nil, err
	}
	refused := map[string][]string{}
	for name, result := range rejection.steps {
		if len(result.Passed) > 0 {
			continue
		}
		reasons := rejectionReasons(result, p.edges[name])
		if len(reasons) == 0 {
			reasons = []string{"no evidence for this step passed"}
		}
		// The scratch directory is deleted before the agent reads this;
		// name the evidence file, not a path that no longer exists.
		for i, r := range reasons {
			reasons[i] = strings.ReplaceAll(r, p.scratch+string(filepath.Separator), "")
		}
		refused[name] = reasons
	}
	if len(refused) == 0 {
		return nil, err
	}
	return refused, nil
}

// rejectionReasons turns a step's rejected collections into the messages an
// author acts on: the rego deny text, a broken artifactsFrom edge, or the
// verifier's own reason.
func rejectionReasons(result attpolicy.StepResult, producers []string) []string {
	var specific, generic []string
	seen := map[string]bool{}
	add := func(list *[]string, s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			*list = append(*list, s)
		}
	}
	for _, rc := range result.Rejected {
		if rc.Reason == nil {
			continue
		}
		denied, artifacts := collectReasons(rc.Reason)
		for _, d := range denied {
			add(&specific, d)
		}
		for _, a := range artifacts {
			if a == "no passed collections present" {
				// The step's own collection was already refused above; the
				// artifact pass had nothing left to check.
				continue
			}
			add(&specific, fmt.Sprintf("artifactsFrom %s->%s broken: %s", strings.Join(producers, ","), result.Step, a))
		}
		if len(denied) == 0 && len(artifacts) == 0 {
			add(&generic, rc.Reason.Error())
		}
	}
	return preferSpecificReasons(specific, generic)
}

// preferSpecificReasons drops umbrella reasons ("no passed collections",
// "failed to verify artifacts ... no passed collections present"): they
// restate a refusal already named, so they show only when nothing more
// specific was found.
func preferSpecificReasons(specific, generic []string) []string {
	if len(specific) > 0 {
		return specific
	}
	if len(generic) <= 1 {
		return generic
	}
	var named []string
	for _, g := range generic {
		if !strings.Contains(g, "no passed collections") {
			named = append(named, g)
		}
	}
	if len(named) > 0 {
		return named
	}
	return generic
}

// collectReasons walks an error tree (errors.Join and multi-unwrap included)
// for rego denials and artifact-chain failures.
func collectReasons(err error) (denied, artifacts []string) {
	var walk func(e error)
	walk = func(e error) {
		if e == nil {
			return
		}
		switch x := e.(type) {
		case attpolicy.ErrPolicyDenied:
			denied = append(denied, x.Reasons...)
			return
		case *attpolicy.ErrPolicyDenied:
			denied = append(denied, x.Reasons...)
			return
		case attpolicy.ErrVerifyArtifactsFailed:
			artifacts = append(artifacts, x.Reasons...)
			return
		case *attpolicy.ErrVerifyArtifactsFailed:
			artifacts = append(artifacts, x.Reasons...)
			return
		}
		if m, ok := e.(interface{ Unwrap() []error }); ok {
			for _, c := range m.Unwrap() {
				walk(c)
			}
			return
		}
		walk(errors.Unwrap(e))
	}
	walk(err)
	return denied, artifacts
}

// envelopeStatement is what prove reads back from the evidence it recorded.
type envelopeStatement struct {
	Subject []struct {
		Digest map[string]string `json:"digest"`
	} `json:"subject"`
	Predicate struct {
		Attestations []struct {
			Type        string          `json:"type"`
			Attestation json.RawMessage `json:"attestation"`
		} `json:"attestations"`
	} `json:"predicate"`
}

func readStatement(path string) (envelopeStatement, error) {
	var stmt envelopeStatement
	raw, err := os.ReadFile(path) //nolint:gosec // an envelope prove itself wrote into its scratch dir
	if err != nil {
		return stmt, err
	}
	var env dsse.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return stmt, err
	}
	err = json.Unmarshal(env.Payload, &stmt)
	return stmt, err
}

// envelopeSubjects lists every sha1/sha256 subject digest the envelopes
// carry, so verify can find each step's collection whatever it is bound to.
func envelopeSubjects(paths []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range paths {
		stmt, err := readStatement(p)
		if err != nil {
			continue
		}
		for _, s := range stmt.Subject {
			for _, alg := range []string{sha256Alg, "sha1"} {
				if h := s.Digest[alg]; h != "" && !seen[alg+h] {
					seen[alg+h] = true
					out = append(out, alg+":"+h)
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// silenceLog mutes the process logger while prove drives sign and verify
// in-process: their log lines would interleave with the report, and prove
// reports the verdicts itself.
func silenceLog() func() {
	prev := log.GetLogger()
	log.SetLogger(log.SilentLogger{})
	return func() { log.SetLogger(prev) }
}

// tailBuffer keeps the last max bytes written to it.
type tailBuffer struct {
	mu  sync.Mutex
	buf []byte
	max int
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = append(t.buf, p...)
	if len(t.buf) > t.max {
		t.buf = t.buf[len(t.buf)-t.max:]
	}
	return len(p), nil
}

func (t *tailBuffer) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(t.buf)
}

func lastLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndex(s, "\n"); i >= 0 {
		return strings.TrimSpace(s[i+1:])
	}
	return s
}

// stepRunAttestors derives the `-a` list that records what a step requires.
// Always-recorded attestors need no flag. A type no attestor in this cilock
// records is an error, because no run could satisfy the step.
func stepRunAttestors(step map[string]any) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, t := range stepAttestationTypes(step) {
		if a, ok := attestorByName(t); ok {
			if a.Always {
				continue
			}
			if !seen[a.Name] {
				seen[a.Name] = true
				out = append(out, a.Name)
			}
			continue
		}
		f, ok := attestation.FactoryByType(t)
		if !ok {
			return nil, fmt.Errorf("it requires %s, which no attestor in this cilock records. Next: `cilock attestors list` names the types it can record", t)
		}
		name := f().Name()
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	if len(out) == 0 {
		// An explicit -a list replaces the default one; environment is the
		// one default that needs no repository or platform.
		out = append(out, "environment")
	}
	return out, nil
}

func requiresType(step map[string]any, t string) bool {
	for _, x := range stepAttestationTypes(step) {
		if x == t {
			return true
		}
	}
	return false
}

// failingEvidence derives a step's failing run from its real one: the same
// statement with the command-run exit status set to 1, re-signed with the
// scratch key. Argv, products, materials and every other attestation stay as
// recorded, so a rule that admits this evidence would admit the pinned
// command failing for real; a wrapper such as `false` would have been
// refused by an argv pin alone and proved nothing about exit status.
func (p *prover) failingEvidence(step, good string) (string, error) {
	raw, err := os.ReadFile(good) //nolint:gosec // an envelope prove itself wrote into its scratch dir
	if err != nil {
		return "", err
	}
	var env dsse.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return "", err
	}
	var stmt map[string]any
	dec := json.NewDecoder(bytes.NewReader(env.Payload))
	dec.UseNumber()
	if err := dec.Decode(&stmt); err != nil {
		return "", err
	}
	flipped := false
	for _, a := range asList(asMap(stmt["predicate"])["attestations"]) {
		if entry := asMap(a); entry["type"] == typeCommandRun {
			att := asMap(entry["attestation"])
			if att == nil {
				continue
			}
			att["exitcode"] = json.Number("1")
			flipped = true
		}
	}
	if !flipped {
		return "", fmt.Errorf("the real run of step %s recorded no command-run attestation", step)
	}
	payload, err := json.Marshal(stmt)
	if err != nil {
		return "", err
	}
	keyFile, err := os.Open(p.keyPath)
	if err != nil {
		return "", err
	}
	defer func() { _ = keyFile.Close() }()
	signer, err := cryptoutil.NewSignerFromReader(keyFile)
	if err != nil {
		return "", err
	}
	signed, err := dsse.Sign(env.PayloadType, bytes.NewReader(payload), dsse.SignWithSigners(signer))
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(signed)
	if err != nil {
		return "", err
	}
	out := filepath.Join(p.scratch, step+".bad.json")
	return out, os.WriteFile(out, data, 0o600)
}
