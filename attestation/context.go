// Copyright 2022 The Witness Contributors
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

package attestation

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/gobwas/glob"
)

// EnvironmentCapturer is an interface for capturing and filtering environment variables.
// Implementations handle sensitive variable obfuscation/filtering.
type EnvironmentCapturer interface {
	Capture(env []string) map[string]string
}

type RunType string

const (
	PreMaterialRunType RunType = "prematerial"
	MaterialRunType    RunType = "material"
	ExecuteRunType     RunType = "execute"
	ProductRunType     RunType = "product"
	PostProductRunType RunType = "postproduct"
	VerifyRunType      RunType = "verify"
)

func runTypeOrder() []RunType {
	return []RunType{PreMaterialRunType, MaterialRunType, ExecuteRunType, ProductRunType, PostProductRunType}
}

func verifyTypeOrder() []RunType {
	return []RunType{VerifyRunType}
}

func (r RunType) String() string {
	return string(r)
}

type ErrAttestor struct {
	Name    string
	RunType RunType
	Reason  string
}

func (e ErrAttestor) Error() string {
	return fmt.Sprintf("error returned for attestor %s of run type %s: %s", e.Name, e.RunType, e.Reason)
}

// SoftError marks an attestor error as a "nothing to do" outcome rather than a
// contract violation. The CLI layer demotes wrapped errors to warnings and
// keeps the exit code at zero. Use this when an attestor ran successfully but
// the project didn't produce the kind of evidence the attestor wraps (e.g.
// sbom found no SBOM file, go-build saw no Go binary). Do NOT use it for
// signer failures, tracing-unsupported, key parse errors, or any other case
// where the attestor's contract was violated — those must surface as fatal
// (exit code 1) so CI can gate on cilock's exit code.
//
// Fixes finding #221 (exit-code inconsistency between attestor failure
// classes).
type SoftError struct {
	// Reason is the underlying short message the attestor would have
	// logged. Kept as a string so callers don't have to wrap a typed
	// error just to be classified as soft.
	Reason string
}

// Error implements error. The "soft:" prefix is purely for log readers; the
// classification itself is by type, not string match.
func (e SoftError) Error() string {
	if e.Reason == "" {
		return "soft: attestor had nothing to do"
	}
	return "soft: " + e.Reason
}

// NewSoftError returns a SoftError wrapping the given reason string. Helper
// so attestors don't have to import the SoftError struct literal directly
// everywhere they classify a "nothing to do" outcome.
func NewSoftError(reason string) error {
	return SoftError{Reason: reason}
}

// IsSoftError reports whether err (or any error in its unwrap chain) is a
// SoftError. Use on individual joined-error legs to decide whether to treat
// the leg as a warning or a fatal failure.
func IsSoftError(err error) bool {
	if err == nil {
		return false
	}
	var s SoftError
	return errors.As(err, &s)
}

type AttestationContextOption func(ctx *AttestationContext)

func WithOutputWriters(w []io.Writer) AttestationContextOption {
	return func(ctx *AttestationContext) {
		ctx.outputWriters = w
	}
}

func WithContext(ctx context.Context) AttestationContextOption {
	return func(actx *AttestationContext) {
		actx.ctx = ctx
	}
}

func WithHashes(hashes []cryptoutil.DigestValue) AttestationContextOption {
	return func(ctx *AttestationContext) {
		if len(hashes) > 0 {
			ctx.hashes = hashes
		}
	}
}

func WithWorkingDir(workingDir string) AttestationContextOption {
	return func(ctx *AttestationContext) {
		if workingDir != "" {
			ctx.workingDir = workingDir
		}
	}
}

func WithDirHashGlob(dirHashGlob []string) AttestationContextOption {
	return func(ctx *AttestationContext) {
		if len(dirHashGlob) > 0 {
			ctx.dirHashGlob = dirHashGlob

			ctx.dirHashGlobCompiled = make([]glob.Glob, 0, len(ctx.dirHashGlob))
			for _, dirHashGlobItem := range dirHashGlob {
				dirHashGlobItemCompiled, err := glob.Compile(dirHashGlobItem)
				if err != nil {
					log.Debugf("invalid dir hash glob pattern %q: %v", dirHashGlobItem, err)
					continue
				}
				ctx.dirHashGlobCompiled = append(ctx.dirHashGlobCompiled, dirHashGlobItemCompiled)
			}
		}
	}
}

// WithEnvironmentCapturer sets the EnvironmentCapturer on the AttestationContext.
func WithEnvironmentCapturer(c EnvironmentCapturer) AttestationContextOption {
	return func(ctx *AttestationContext) {
		ctx.environmentCapturer = c
	}
}

type CompletedAttestor struct {
	Attestor  Attestor
	StartTime time.Time
	EndTime   time.Time
	Error     error
}

// AttestationContext is a struct that hold configuration that can be used across all attestors.
type AttestationContext struct {
	ctx                 context.Context
	attestors           []Attestor
	workingDir          string
	dirHashGlob         []string
	dirHashGlobCompiled []glob.Glob
	hashes              []cryptoutil.DigestValue
	completedAttestors  []CompletedAttestor
	products            map[string]Product
	materials           map[string]cryptoutil.DigestSet
	stepName            string
	mutex               sync.RWMutex
	environmentCapturer EnvironmentCapturer
	outputWriters       []io.Writer

	// Capture mode selects where the material + product attestors get
	// their data: walk (legacy), trace (derive from command-run trace
	// events), ima (kernel measurements), or auto (default — pick best).
	// See attestation/capture_mode.go for the full semantics.
	captureMode CaptureMode

	// Cache pattern options control how the framework classifies a
	// tracee-written file as cache/temp vs product. See
	// CachePatternOptions for the full semantics. Default values
	// (zero struct) mean "use built-in defaults + env query."
	cachePatternOpts CachePatternOptions

	// Environment configuration fields used by the environment plugin
	envFilterVarsEnabled           bool
	envAdditionalKeys              []string
	envExcludeKeys                 []string
	envDisableDefaultSensitiveList bool
	envCaptureAllowlist            []string
}

type Product struct {
	MimeType string               `json:"mime_type"`
	Digest   cryptoutil.DigestSet `json:"digest"`
}

// NewContext creates a new AttestationContext.
func NewContext(stepName string, attestors []Attestor, opts ...AttestationContextOption) (*AttestationContext, error) {
	wd, err := os.Getwd()
	if err != nil {
		return nil, err
	}

	ctx := &AttestationContext{
		ctx:        context.Background(),
		attestors:  attestors,
		workingDir: wd,
		hashes:     []cryptoutil.DigestValue{{Hash: crypto.SHA256}, {Hash: crypto.SHA256, GitOID: true}, {Hash: crypto.SHA1, GitOID: true}},
		materials:  make(map[string]cryptoutil.DigestSet),
		products:   make(map[string]Product),
		stepName:   stepName,
	}

	for _, opt := range opts {
		opt(ctx)
	}

	return ctx, nil
}

func (ctx *AttestationContext) RunAttestors() error {
	attestors := make(map[RunType][]Attestor)
	for _, attestor := range ctx.attestors {
		if attestor.RunType() == "" {
			return ErrAttestor{
				Name:    attestor.Name(),
				RunType: attestor.RunType(),
				Reason:  "attestor run type not set",
			}
		}
		attestors[attestor.RunType()] = append(attestors[attestor.RunType()], attestor)
	}

	order := runTypeOrder()
	if attestors[VerifyRunType] != nil && len(attestors) > 1 {
		return fmt.Errorf("attestors of type %s cannot be run in conjunction with other attestor types", VerifyRunType)
	} else if attestors[VerifyRunType] != nil {
		order = verifyTypeOrder()
	}

	for _, k := range order {
		log.Infof("Starting %s attestors stage...", k.String())

		var wg sync.WaitGroup

		for _, att := range attestors[k] {
			wg.Add(1)
			go func(att Attestor) {
				defer wg.Done()
				ctx.runAttestor(att)
			}(att)
		}
		wg.Wait()
		log.Infof("Completed %s attestors stage...", k.String())
	}

	// Finalize phase: attestors that implement Finalizer get a second
	// pass AFTER every other attestor has completed. The intent is to
	// let early-running attestors (e.g., material attestor in trace
	// mode) augment themselves with data produced by later attestors
	// (e.g., the command-run trace). Material attestor short-circuits
	// its pre-execute walk in trace mode, then Finalize pulls the
	// captured input set from command-run and builds the merkle tree.
	for _, completed := range ctx.completedAttestors {
		f, ok := completed.Attestor.(Finalizer)
		if !ok {
			continue
		}
		log.Infof("Finalizing %v attestor...", completed.Attestor.Name())
		ftStart := time.Now()
		if err := f.Finalize(ctx); err != nil {
			log.Errorf("Finalize %v: %v", completed.Attestor.Name(), err)
		}
		log.Infof("Finished finalize %v... (%s)", completed.Attestor.Name(), time.Since(ftStart))
	}

	return nil
}

// Finalizer is an optional interface attestors can implement to run
// a second pass AFTER all other attestors have completed. Use for
// data dependencies that flow backwards in time relative to the
// declared RunType ordering — e.g., material attestor in trace
// mode pulling its inputs from command-run's captured trace.
type Finalizer interface {
	Finalize(ctx *AttestationContext) error
}

func (ctx *AttestationContext) runAttestor(attestor Attestor) {
	log.Infof("Starting %v attestor...", attestor.Name())

	startTime := time.Now()
	err := func() (retErr error) {
		defer func() {
			if r := recover(); r != nil {
				retErr = fmt.Errorf("attestor %s panicked: %v", attestor.Name(), r)
			}
		}()
		return attestor.Attest(ctx)
	}()
	if err != nil {
		ctx.mutex.Lock()
		ctx.completedAttestors = append(ctx.completedAttestors, CompletedAttestor{
			Attestor:  attestor,
			StartTime: startTime,
			EndTime:   time.Now(),
			Error:     err,
		})
		ctx.mutex.Unlock()
		return
	}

	ctx.mutex.Lock()
	ctx.completedAttestors = append(ctx.completedAttestors, CompletedAttestor{
		Attestor:  attestor,
		StartTime: startTime,
		EndTime:   time.Now(),
	})
	ctx.mutex.Unlock()

	if materialer, ok := attestor.(Materialer); ok {
		ctx.mutex.Lock()
		ctx.addMaterials(materialer)
		ctx.mutex.Unlock()
	}

	if producer, ok := attestor.(Producer); ok {
		ctx.mutex.Lock()
		ctx.addProducts(producer)
		ctx.mutex.Unlock()
	}

	log.Infof("Finished %v attestor... (%vs)", attestor.Name(), time.Since(startTime).Seconds())
}

func (ctx *AttestationContext) OutputWriters() []io.Writer {
	return ctx.outputWriters
}

func (ctx *AttestationContext) DirHashGlob() []glob.Glob {
	return ctx.dirHashGlobCompiled
}

func (ctx *AttestationContext) CompletedAttestors() []CompletedAttestor {
	ctx.mutex.RLock()
	out := make([]CompletedAttestor, len(ctx.completedAttestors))
	copy(out, ctx.completedAttestors)
	ctx.mutex.RUnlock()
	return out
}

func (ctx *AttestationContext) WorkingDir() string {
	return ctx.workingDir
}

func (ctx *AttestationContext) Hashes() []cryptoutil.DigestValue {
	ctx.mutex.RLock()
	hashes := make([]cryptoutil.DigestValue, len(ctx.hashes))
	copy(hashes, ctx.hashes)
	ctx.mutex.RUnlock()
	return hashes
}

func (ctx *AttestationContext) Context() context.Context {
	return ctx.ctx
}

func (ctx *AttestationContext) Materials() map[string]cryptoutil.DigestSet {
	ctx.mutex.RLock()
	out := make(map[string]cryptoutil.DigestSet)
	for k, v := range ctx.materials {
		out[k] = v
	}
	ctx.mutex.RUnlock()
	return out
}

func (ctx *AttestationContext) Products() map[string]Product {
	ctx.mutex.RLock()
	out := make(map[string]Product)
	for k, v := range ctx.products {
		out[k] = v
	}
	ctx.mutex.RUnlock()
	return out
}

// CaptureMode returns the configured capture mode after normalization.
// An unset / "auto" value means "let the attestor pick the best
// available source at run time." Walk-mode operators see "walk";
// trace-mode operators see "trace"; etc.
func (ctx *AttestationContext) CaptureMode() CaptureMode {
	return ctx.captureMode.Normalize()
}

// CachePatterns returns the configured pattern options. Attestors
// pass these to ResolveCachePatterns + NewCachePathMatcher to build
// the classifier. Default (zero-valued) options resolve to "use
// DefaultCachePatterns + SystemCachePathsFromEnv."
func (ctx *AttestationContext) CachePatterns() CachePatternOptions {
	return ctx.cachePatternOpts
}

// RegisteredAttestors returns the full list of attestors registered
// with this context, regardless of whether they've completed. Used by
// attestors that run early (e.g., material) and need to know whether
// a later-running attestor (e.g., command-run with tracing) intends to
// supply data this attestor would otherwise have to compute itself.
// CompletedAttestors() is the right method for "what's already run";
// this method is for "what's planned to run."
func (ctx *AttestationContext) RegisteredAttestors() []Attestor {
	return ctx.attestors
}

func (ctx *AttestationContext) StepName() string {
	return ctx.stepName
}

// SetEnvironmentCapturer sets the EnvironmentCapturer on the context.
// This is typically called by the environment plugin during attestation.
func (ctx *AttestationContext) SetEnvironmentCapturer(c EnvironmentCapturer) {
	ctx.mutex.Lock()
	ctx.environmentCapturer = c
	ctx.mutex.Unlock()
}

func (ctx *AttestationContext) EnvFilterVarsEnabled() bool {
	return ctx.envFilterVarsEnabled
}

func (ctx *AttestationContext) EnvAdditionalKeys() []string {
	return ctx.envAdditionalKeys
}

func (ctx *AttestationContext) EnvExcludeKeys() []string {
	return ctx.envExcludeKeys
}

func (ctx *AttestationContext) EnvDisableDefaultSensitiveList() bool {
	return ctx.envDisableDefaultSensitiveList
}

// EnvCaptureAllowlist returns the positive allowlist of env-key patterns
// configured for capture (exact keys or globs). When non-empty, the
// environment attestor captures ONLY matching keys. When empty, all
// non-sensitive keys are captured (legacy behaviour).
func (ctx *AttestationContext) EnvCaptureAllowlist() []string {
	return ctx.envCaptureAllowlist
}

func (ctx *AttestationContext) addMaterials(materialer Materialer) {
	newMats := materialer.Materials()
	for k, v := range newMats {
		ctx.materials[k] = v
	}
}

func (ctx *AttestationContext) addProducts(producter Producer) {
	newProds := producter.Products()
	for k, v := range newProds {
		ctx.products[k] = v
	}
}
