// Copyright 2026 The Rookery Contributors
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

package commandrun

import (
	"crypto"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/plugins/attestors/commandrun/ebpf"
)

// ProgramRef is the record of the program argv[0] started. Every run writes
// one, traced or not, on every platform, with no flag to turn it off
// (docs/design/command-program-pinning.md section 3.1, lane P1a).
//
// It answers the question Cmd cannot: Cmd is the text the caller typed, and
// "terraform" names whatever the PATH found. This record names the file the
// exec's own lookup resolved, the real file behind every symlink, and the
// sha256 of that file's bytes.
//
// WHAT IT DOES NOT ASSERT. The digest is taken before the command starts,
// through one descriptor, and this build never proves those bytes are the
// bytes the kernel then executed: ExecutionBinding is always "unverified" here,
// with the reason in BindingReason. Binding at the exec is lane P3c (Linux) and
// P4 (macOS). Whether the program lies inside the checkout is lane P1c: until
// then Checkout.Relation is always "unknown", never "outside".
type ProgramRef struct {
	// Lookup is how argv[0] was turned into a path: a bare name searched on
	// PATH, a relative name resolved against the working directory, or an
	// absolute path.
	Lookup ProgramLookup `json:"lookup"`

	// Path is the absolute path the exec's own lookup produced. It is not
	// lexically cleaned: "./t" run in /w is "/w/./t", exactly as the kernel
	// walks it, because Clean would erase a `link/..` the kernel follows.
	Path string `json:"path"`

	// RealPath is the path read back from the descriptor that was hashed,
	// never from a second walk of the name, so it and Digest describe one file
	// object. RealPathSource says how it was read; RealPathReason says why it
	// is empty when RealPathSource is "unresolved".
	RealPath       string `json:"realPath,omitempty"`
	RealPathSource string `json:"realPathSource"`
	RealPathReason string `json:"realPathReason,omitempty"`

	// Digest covers the WHOLE file, with no size limit: sha256 always, plus
	// any algorithm the run's hash set adds. Absent only when Unresolved says
	// why.
	Digest    cryptoutil.DigestSet `json:"digest,omitempty"`
	SizeBytes int64                `json:"sizeBytes,omitempty"`

	// File is the identity of the same descriptor. Absent where the platform
	// has none to give (Windows identity is lane P1b).
	File *ProgramFile `json:"file,omitempty"`

	// Format is sniffed from the first bytes the hash read: elf, mach-o,
	// mach-o-universal, pe, script or other.
	Format string `json:"format,omitempty"`

	// Host is GOOS/GOARCH of the machine that ran the program.
	Host string `json:"host"`

	// Workdir is the directory the child started in.
	Workdir string `json:"workdir"`

	// Checkout says whether the program lies in the checkout. Always emitted.
	Checkout ProgramCheckout `json:"checkout"`

	// Wrapper is set when cilock itself started another program first and
	// that program then exec'd this one: sandbox-exec under --trace on macOS.
	Wrapper *ProgramWrapper `json:"wrapper,omitempty"`

	// Unresolved says why there is no Digest. It is never empty when Digest
	// is absent. The only expected cause is a program cilock cannot read.
	Unresolved string `json:"unresolved,omitempty"`

	// ExecutionBinding reuses the ScriptRef vocabulary and, like it, is ALWAYS
	// emitted, never omitempty: "" is not "verified", and a status that
	// vanishes when it is unfavourable makes absence ambiguous (see
	// ScriptRef.ExecutionBinding).
	ExecutionBinding ScriptExecutionBinding `json:"executionBinding"`
	BindingMethod    string                 `json:"bindingMethod,omitempty"`
	BindingReason    string                 `json:"bindingReason,omitempty"`
}

// ProgramLookup is how argv[0] became a path.
type ProgramLookup string

const (
	ProgramLookupPathSearch      ProgramLookup = "path-search"
	ProgramLookupWorkdirRelative ProgramLookup = "workdir-relative"
	ProgramLookupAbsolute        ProgramLookup = "absolute"
)

// Where RealPath came from.
const (
	RealPathFromProcFD            = "proc-self-fd"
	RealPathFromFGetPath          = "f-getpath"
	RealPathEvalSymlinksConfirmed = "evalsymlinks-confirmed"
	RealPathFromName              = "name"
	RealPathUnresolved            = "unresolved"
)

// ProgramFile is the kernel identity of the hashed descriptor.
type ProgramFile struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	// Links > 1 says RealPath is one name of several.
	Links uint64 `json:"links"`
	// SetID covers setuid, setgid and, on Linux, file capabilities. It is
	// always emitted: true or false only when established, and null (the
	// zero value) when it could not be, with SetIDReason saying why. A rule
	// that requires setId == false refuses null.
	SetID       *bool  `json:"setId"`
	SetIDReason string `json:"setIdReason,omitempty"`
	FSType      string `json:"fsType,omitempty"`
}

// CheckoutRelation is where the program lies relative to the checkout the git
// evidence names. It has no omitempty anywhere it appears: its zero value ""
// is NOT "outside", and a rule requiring "outside" must see "" as a refusal.
type CheckoutRelation string

const (
	CheckoutInside  CheckoutRelation = "inside"
	CheckoutOutside CheckoutRelation = "outside"
	CheckoutUnknown CheckoutRelation = "unknown"
)

// ProgramCheckout is the program's relation to the checkout.
type ProgramCheckout struct {
	Root     string           `json:"root,omitempty"`
	Relation CheckoutRelation `json:"relation"`
	Reason   string           `json:"reason,omitempty"`
}

// ProgramWrapper is a program cilock started in front of argv[0].
type ProgramWrapper struct {
	Kind       string               `json:"kind"`
	Path       string               `json:"path"`
	RealPath   string               `json:"realPath,omitempty"`
	Digest     cryptoutil.DigestSet `json:"digest,omitempty"`
	SizeBytes  int64                `json:"sizeBytes,omitempty"`
	File       *ProgramFile         `json:"file,omitempty"`
	Unresolved string               `json:"unresolved,omitempty"`
}

const (
	programReasonNotBound = "this CI/lock build does not bind the program to the exec: " +
		"the digest is of the file the lookup named, read before the command started"
	programReasonExecTargetChanged = "the exec target changed after the program was recorded"
	programReasonUnreadable        = "permission denied: the program is executable but not readable"
	checkoutReasonNotComputed      = "containment is not computed by this CI/lock build"
)

// Seams. Nothing in production assigns to them.
var (
	// fdRealPath reads a descriptor's path back from the kernel.
	fdRealPath = platformFDRealPath
	// evalSymlinks is the by-name fallback, used only when the descriptor
	// cannot answer, and trusted only when it names the descriptor's file.
	evalSymlinks = filepath.EvalSymlinks
	// testAfterProgramOpen runs between the open and every read of the
	// descriptor, where a name swap is the attack the descriptor defeats.
	testAfterProgramOpen func()
	// testBeforeExecGuard runs immediately before the exec-target guard.
	testBeforeExecGuard func(*exec.Cmd)
)

// programSnapshot is c.Path and c.Args as they were when the record was
// computed. The guard compares against this, not against ProgramRef.Path:
// Path is made absolute while Go leaves a relative c.Path relative, so a
// comparison with Path would fail every "./gradlew".
type programSnapshot struct {
	path string
	args []string
}

// recordProgram computes the program record from the constructed exec.Cmd:
// after c.Dir is set, before tracing or the privilege drop can rewrite
// c.Path. It uses the lookup exec.Command already performed, never a second
// one of its own.
func (r *CommandRun) recordProgram(c *exec.Cmd, hashes []cryptoutil.DigestValue) programSnapshot {
	r.Program = nil
	if c.Err != nil || len(r.Cmd) == 0 {
		// The lookup failed; Start will refuse and nothing runs, so no
		// attestation exists to carry a record.
		return programSnapshot{}
	}
	// Resolve the name Start will execute BEFORE measuring, and hand Start
	// that name: on Windows Start would otherwise add the PATHEXT extension
	// after the record hashed the extensionless name.
	target, err := resolveExecTarget(c)
	if err != nil {
		// Start makes the same lookup and would refuse too. Refusing here
		// keeps it from resolving a file the record never named.
		c.Err = err
		return programSnapshot{}
	}
	c.Path = target
	workdir := c.Dir
	if workdir == "" {
		if wd, err := getwd(); err == nil {
			workdir = wd
		}
	}
	// The file the launch runs, composed as the launch composes it (see
	// program_path_compose.go). A path the launch would refuse is refused
	// here, so nothing runs beside a record that could not name it.
	path, err := composeProgramPath(workdir, c.Path)
	if err != nil {
		c.Err = err
		return programSnapshot{}
	}

	m := measureProgramFile(path, programHashes(hashes))
	r.Program = &ProgramRef{
		Lookup:           programLookupOf(r.Cmd[0]),
		Path:             path,
		RealPath:         m.realPath,
		RealPathSource:   m.realPathSource,
		RealPathReason:   m.realPathReason,
		Digest:           m.digest,
		SizeBytes:        m.size,
		File:             m.file,
		Format:           m.format,
		Host:             runtime.GOOS + "/" + runtime.GOARCH,
		Workdir:          workdir,
		Checkout:         ProgramCheckout{Relation: CheckoutUnknown, Reason: checkoutReasonNotComputed},
		Unresolved:       m.unresolved,
		ExecutionBinding: ScriptBindingUnverified,
		BindingReason:    programReasonNotBound,
	}
	return programSnapshot{path: c.Path, args: slices.Clone(c.Args)}
}

// guardExecTarget runs immediately before Start. The record describes argv[0],
// but the kernel execs c.Path, so any rewrite of c.Path or c.Args after the
// record was computed must be one cilock names and records; anything else
// withdraws every claim the record could make about what runs.
func (r *CommandRun) guardExecTarget(snap programSnapshot, c *exec.Cmd, hashes []cryptoutil.DigestValue) {
	if r.Program == nil {
		return
	}
	if c.Path == snap.path && slices.Equal(c.Args, snap.args) {
		return
	}
	if kind, reason, ok := cilockWrapperOf(snap, c); ok {
		m := measureProgramFile(c.Path, programHashes(hashes))
		r.Program.Wrapper = &ProgramWrapper{
			Kind:       kind,
			Path:       c.Path,
			RealPath:   m.realPath,
			Digest:     m.digest,
			SizeBytes:  m.size,
			File:       m.file,
			Unresolved: m.unresolved,
		}
		r.Program.ExecutionBinding = ScriptBindingUnverified
		r.Program.BindingReason = reason
		return
	}
	r.Program.ExecutionBinding = ScriptBindingUnverified
	r.Program.BindingReason = programReasonExecTargetChanged
}

func programLookupOf(argv0 string) ProgramLookup {
	switch {
	case filepath.Base(argv0) == argv0:
		return ProgramLookupPathSearch
	case filepath.IsAbs(argv0):
		return ProgramLookupAbsolute
	default:
		return ProgramLookupWorkdirRelative
	}
}

// programHashes is the run's hash set with plain sha256 always present. A
// directory hash has no meaning for a file and is dropped.
func programHashes(hashes []cryptoutil.DigestValue) []cryptoutil.DigestValue {
	out := make([]cryptoutil.DigestValue, 0, len(hashes)+1)
	hasSHA256 := false
	for _, h := range hashes {
		if h.DirHash {
			continue
		}
		if h.Hash == crypto.SHA256 && !h.GitOID {
			hasSHA256 = true
		}
		out = append(out, h)
	}
	if !hasSHA256 {
		out = append([]cryptoutil.DigestValue{{Hash: crypto.SHA256}}, out...)
	}
	return out
}

type programMeasurement struct {
	realPath, realPathSource, realPathReason string
	digest                                   cryptoutil.DigestSet
	size                                     int64
	file                                     *ProgramFile
	format                                   string
	unresolved                               string
}

// measureProgramFile opens path once and derives everything from that one
// descriptor: the digest (inside the settle-and-bracket of file_hashing.go),
// the first bytes for the format, the identity and the real path.
func measureProgramFile(path string, hashes []cryptoutil.DigestValue) programMeasurement {
	f, err := openForHashing(path)
	if err != nil {
		return measureUnopenable(path, err)
	}
	defer func() { _ = f.Close() }()
	if testAfterProgramOpen != nil {
		testAfterProgramOpen()
	}

	var m programMeasurement
	m.realPath, m.realPathSource, m.realPathReason = realPathOfDescriptor(f, path)

	head := make([]byte, 8)
	var n int
	var headErr error
	d, st, err := digestOpenFileStat(f, hashes, func() {
		// Inside the bracket, so the format describes the hashed state.
		n, headErr = f.ReadAt(head, 0)
	})
	if err != nil {
		m.unresolved = programHashFailure(err)
		if fi, serr := f.Stat(); serr == nil {
			m.file = programFileFacts(f, fi)
		}
		return m
	}
	m.digest = d
	m.size = st.Size()
	m.file = programFileFacts(f, st)
	m.format = formatFromHead(head, n, headErr)
	return m
}

// realPathOfDescriptor reads the path back from the descriptor. When the
// platform cannot, it falls back to resolving the name, and keeps that answer
// only if it names the same file the descriptor holds.
func realPathOfDescriptor(f *os.File, path string) (string, string, string) {
	if p, source, err := fdRealPath(f); err == nil {
		return p, source, ""
	} else if rp, confirmErr := confirmedEvalSymlinks(f, path); confirmErr == nil {
		return rp, RealPathEvalSymlinksConfirmed, ""
	} else {
		return "", RealPathUnresolved, fmt.Sprintf("descriptor readback failed (%v) and the name could not be confirmed against the descriptor (%v)", err, confirmErr)
	}
}

func confirmedEvalSymlinks(f *os.File, path string) (string, error) {
	rp, err := evalSymlinks(path)
	if err != nil {
		return "", err
	}
	byName, err := os.Stat(rp)
	if err != nil {
		return "", err
	}
	byFD, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !os.SameFile(byName, byFD) {
		return "", errors.New("the resolved name is a different file from the one hashed")
	}
	return rp, nil
}

// measureUnopenable records a program that could not be opened for reading.
// The run proceeds: an execute-only program is still executable.
func measureUnopenable(path string, openErr error) programMeasurement {
	var m programMeasurement
	if errors.Is(openErr, fs.ErrPermission) {
		m.unresolved = programReasonUnreadable
	} else {
		m.unresolved = "could not open the program: " + openErr.Error()
	}
	m.realPath, m.realPathSource, m.file = pathOnlyFacts(path)
	if m.realPath == "" {
		m.realPathReason = "the program could not be opened and its name could not be resolved"
	}
	return m
}

func programHashFailure(err error) string {
	switch {
	case errors.Is(err, errNotRegularFile):
		return "not a regular file"
	case errors.Is(err, ebpf.ErrWillNotSettle):
		return "still being written: " + err.Error()
	default:
		return "could not hash the program: " + err.Error()
	}
}

// formatFromHead names the format only from a read that succeeded; a short
// file ends in io.EOF and is sniffed from what it has. A failed read is no
// format at all, not "other".
func formatFromHead(head []byte, n int, err error) string {
	if err != nil && !errors.Is(err, io.EOF) {
		return ""
	}
	return sniffProgramFormat(head[:n])
}

// sniffProgramFormat names the executable format from its first bytes.
func sniffProgramFormat(b []byte) string {
	if len(b) >= 2 && b[0] == '#' && b[1] == '!' {
		return "script"
	}
	if len(b) >= 4 {
		switch binary.BigEndian.Uint32(b[:4]) {
		case 0x7f454c46: // \x7fELF
			return "elf"
		case 0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe:
			return "mach-o"
		case 0xcafebabe, 0xcafebabf:
			// A Java class file shares 0xcafebabe; its next word is a class
			// file version (45 or more), a fat header's is an arch count.
			if len(b) >= 8 && binary.BigEndian.Uint32(b[4:8]) < 45 {
				return "mach-o-universal"
			}
		}
	}
	if len(b) >= 2 && b[0] == 'M' && b[1] == 'Z' {
		return "pe"
	}
	return "other"
}

// nameOnlyFacts resolves a program by name when no descriptor to it exists.
// The result is labelled "name", because nothing ties it to the bytes.
func nameOnlyFacts(path string) (string, string, *ProgramFile) {
	rp, err := evalSymlinks(path)
	if err != nil {
		return "", RealPathUnresolved, nil
	}
	var pf *ProgramFile
	if f, err := os.Open(rp); err == nil { //nolint:gosec // G304: identifying the program the caller named
		if fi, err := f.Stat(); err == nil {
			pf = programFileFacts(f, fi)
		}
		_ = f.Close()
	} else if fi, err := os.Stat(rp); err == nil {
		// Unreadable: identity from the name, without the descriptor facts.
		pf = programFileFacts(nil, fi)
	}
	return rp, RealPathFromName, pf
}

func boolRef(b bool) *bool { return &b }
