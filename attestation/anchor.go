// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package attestation

// The anchor contract's core types and its registry
// (docs/design/attestation-anchors.md, sections 2.2, 3.3, 3c).
//
// anchor_registry.json is the single source of the anchor kinds each attestor
// may emit or accept. It is data only here: no verification path reads it
// yet.

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"
	"unicode"
)

// AnchorKind is a digest space: two values of one kind are digests of the
// same kind of byte string, computed the same way.
type AnchorKind string

const (
	KindImageRegistryManifest AnchorKind = "image-registry-manifest"
	KindImageConfig           AnchorKind = "image-config"
	// KindGitCommit is the digest space of git commit objects (D15, 3.7): the
	// object id over "commit <len>\x00" and the commit's canonical bytes.
	KindGitCommit AnchorKind = "git-commit"
	// KindFileContent is reserved: no emitter and no acceptor may use it.
	KindFileContent AnchorKind = "file-content"
)

// AnchorRole says whether the step produced the artifact or is about it.
type AnchorRole string

const (
	RoleProduced AnchorRole = "produced"
	RoleAbout    AnchorRole = "about"
)

// AnchorBasis says how the verifier re-derives the value.
type AnchorBasis string

const (
	BasisMeasured AnchorBasis = "measured"
	BasisObserved AnchorBasis = "observed"
	BasisReported AnchorBasis = "reported"
)

// AnchorClass is a registry row's class.
type AnchorClass string

const (
	ClassAnchor    AnchorClass = "anchor"
	ClassAcceptor  AnchorClass = "acceptor"
	ClassNotAnchor AnchorClass = "not_anchor"
)

// Normalization names the encoding rule of a signed field (3c.1). A field
// has exactly one; it is never tried both ways.
type Normalization string

const (
	NormalizationBareHex      Normalization = "bare-hex"
	NormalizationPrefixed     Normalization = "prefixed"
	NormalizationRepoAtDigest Normalization = "repo-at-digest"
	NormalizationPURLVersion  Normalization = "purl-version"
)

// AnchorAlgorithm is the algorithm every kind admits. git-commit alone also
// admits sha1 (A3, a per-kind allowlist; see KindAlgorithms).
const AnchorAlgorithm = "sha256"

// AlgorithmSHA1 is admitted for KindGitCommit only. Whether a sha1 value came
// from the hardened (collision-detecting) git path is the registry row's gate,
// not the encoder's: Canonical reads the value's shape.
const AlgorithmSHA1 = "sha1"

// kindAlgorithms is A3: the algorithms each kind admits. A kind not listed
// (the reserved one, an unknown one) admits none.
var kindAlgorithms = map[AnchorKind][]string{
	KindImageRegistryManifest: {AnchorAlgorithm},
	KindImageConfig:           {AnchorAlgorithm},
	KindGitCommit:             {AlgorithmSHA1, AnchorAlgorithm},
}

// KindAlgorithms returns a copy of the algorithms kind admits, nil for none.
func KindAlgorithms(kind AnchorKind) []string {
	return slices.Clone(kindAlgorithms[kind])
}

// Identity is the canonical identity: the only thing ever compared.
type Identity struct {
	Kind      AnchorKind
	Algorithm string
	Value     string // lowercase hex: 64 characters, or 40 for a sha1 git-commit
}

// Anchor is one typed value. Key is "<prefix><tail>"; the tail is never compared.
type Anchor struct {
	Key      string
	Identity Identity
	Role     AnchorRole
	Basis    AnchorBasis
}

// AnchorContext gives an attestor read access to the other decoded,
// registered attestations of the same signed collection.
type AnchorContext interface {
	Sibling(attestationType string) []Attestor
}

// Anchorer returns the anchors (role produced) an attestor claims, sorted by Key.
type Anchorer interface {
	Anchors(AnchorContext) []Anchor
}

// Acceptor returns the typed subjects anchors may land on, sorted by Key.
type Acceptor interface {
	Acceptors(AnchorContext) []Anchor
}

var errNonCanonical = errors.New("non-canonical anchor value")

// Canonical turns a raw signed field into an identity, or refuses it. A
// refused value is never repaired: lowercasing or trimming would make two
// differently encoded claims agree when no tool emitted that agreement.
//
// The property every reader below keeps: an input maps to AT MOST ONE
// identity. An input with more than one plausible reading (the purl
// specification's right-to-left split, a first-boundary split as net/url
// makes, a reading after percent-decoding) is REJECTED, never resolved to one
// of them. A false identity match is a substitution; a rejection is safe.
func Canonical(kind AnchorKind, raw string, rule Normalization) (Identity, error) {
	if kind == KindGitCommit {
		return canonicalCommit(raw, rule)
	}
	if kind != KindImageRegistryManifest && kind != KindImageConfig {
		return Identity{}, fmt.Errorf("%w: kind %q is not an admitted kind", errNonCanonical, kind)
	}
	var value string
	var ok bool
	switch rule {
	case NormalizationBareHex:
		value, ok = raw, true
	case NormalizationPrefixed:
		value, ok = strings.CutPrefix(raw, "sha256:")
	case NormalizationRepoAtDigest:
		value, ok = cutRepoAtDigest(raw)
	case NormalizationPURLVersion:
		value, ok = purlDigest(raw)
	default:
		return Identity{}, fmt.Errorf("%w: unknown normalization %q", errNonCanonical, rule)
	}
	if !ok || !isLowerHex64(value) {
		return Identity{}, fmt.Errorf("%w: %s value is not canonical", errNonCanonical, rule)
	}
	return Identity{Kind: kind, Algorithm: AnchorAlgorithm, Value: value}, nil
}

// canonicalCommit reads a git-commit value. A commit id is bare lowercase hex
// and nothing else: 40 characters is a sha1 id, 64 a sha256 one, and the null
// id (all zeros, git's "no object") names no commit.
func canonicalCommit(raw string, rule Normalization) (Identity, error) {
	if rule != NormalizationBareHex {
		return Identity{}, fmt.Errorf("%w: a git-commit value is bare hex only, not %s", errNonCanonical, rule)
	}
	var alg string
	switch len(raw) {
	case sha1HexLen:
		alg = AlgorithmSHA1
	case sha256.Size * 2:
		alg = AnchorAlgorithm
	default:
		return Identity{}, fmt.Errorf("%w: a git-commit value is 40 or 64 hex characters", errNonCanonical)
	}
	if !isLowerHex(raw) || strings.Trim(raw, "0") == "" {
		return Identity{}, fmt.Errorf("%w: git-commit value is not canonical", errNonCanonical)
	}
	return Identity{Kind: KindGitCommit, Algorithm: alg, Value: raw}, nil
}

const sha1HexLen = 40

func isLowerHex64(s string) bool {
	return len(s) == sha256.Size*2 && isLowerHex(s)
}

func isLowerHex(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func cutLast(s, sep string) (before, after string, found bool) {
	if i := strings.LastIndex(s, sep); i >= 0 {
		return s[:i], s[i+len(sep):], true
	}
	return s, "", false
}

// ociRepository is the name and optional tag of an OCI reference, per the
// distribution reference grammar (github.com/distribution/reference,
// regexp.go): an optional host and port, lowercase path components, an
// optional tag. It admits no '@', '?', '#', '%' or whitespace.
var ociRepository = func() *regexp.Regexp {
	const (
		domainComponent = `(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])`
		host            = `(?:` + domainComponent + `(?:\.` + domainComponent + `)*|\[[a-fA-F0-9:]+\])`
		pathComponent   = `[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*`
		name            = `(?:` + host + `(?::[0-9]+)?/)?` + pathComponent + `(?:/` + pathComponent + `)*`
		tag             = `[\w][\w.-]{0,127}`
	)
	return regexp.MustCompile(`^` + name + `(?::` + tag + `)?$`)
}()

// cutRepoAtDigest reads "<repo>@sha256:<hex>". It cuts at the first '@', and
// the tail must then be exactly "sha256:" and 64 hex characters, which hold no
// '@': the first '@' is the last, so a right-to-left split reads the same
// digest. The repo must match the reference grammar, so no second digest
// hides in it percent-encoded or behind '?', '#' or a tag.
func cutRepoAtDigest(raw string) (string, bool) {
	repo, digest, found := strings.Cut(raw, "@")
	if !found || !ociRepository.MatchString(repo) {
		return "", false
	}
	return strings.CutPrefix(digest, "sha256:")
}

const purlTypeOCI = "oci"

// purlTypes are the package types whose version may carry an image digest.
var purlTypes = []string{"docker", purlTypeOCI}

// purlParts is one reading of a PURL after its "pkg:" scheme.
type purlParts struct {
	typ, path, version, qualifiers, subpath string
	hasQualifiers, hasSubpath               bool
}

// splitPURL reads rest at its separators from the left, at each first
// boundary as net/url does, or from the right, as the purl specification's
// how-to-parse procedure does. The type is split from the left in both.
func splitPURL(rest string, fromRight bool) (purlParts, bool) {
	cut := strings.Cut
	if fromRight {
		cut = cutLast
	}
	var p purlParts
	var ok bool
	rest, p.subpath, p.hasSubpath = cut(rest, "#")
	rest, p.qualifiers, p.hasQualifiers = cut(rest, "?")
	if p.typ, rest, ok = strings.Cut(rest, "/"); !ok {
		return purlParts{}, false
	}
	if p.path, p.version, ok = cut(rest, "@"); !ok {
		return purlParts{}, false
	}
	return p, true
}

// readPURL returns the one reading both directions agree on.
func readPURL(rest string) (purlParts, bool) {
	first, ok := splitPURL(rest, false)
	last, lastOK := splitPURL(rest, true)
	if !ok || !lastOK || first != last {
		return purlParts{}, false
	}
	return first, true
}

// purlDigest reads the digest from
// "pkg:<type>/[<namespace>/]<name>@<version>[?<qualifiers>][#<subpath>]".
func purlDigest(raw string) (string, bool) {
	rest, ok := strings.CutPrefix(raw, "pkg:")
	if !ok {
		return "", false
	}
	p, ok := readPURL(rest)
	if !ok || !validPURL(p) {
		return "", false
	}
	// The purl grammar gives the version one percent-decode (3c.1 rule 3).
	// Only the colon may be encoded: an escape of any other character spells
	// one the specification never encodes.
	for _, prefix := range []string{"sha256:", "sha256%3A", "sha256%3a"} {
		if hex, found := strings.CutPrefix(p.version, prefix); found {
			return hex, true
		}
	}
	return "", false
}

// purlUnreserved reports whether c may appear unencoded in a purl component:
// the specification's alphanumerics, ".-_~" and ':' (Annex C, unreserved).
func purlUnreserved(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || strings.IndexByte(".-_~:", c) >= 0
}

// onlyBytes reports whether s is non-empty and every byte satisfies ok.
func onlyBytes(s string, ok func(byte) bool) bool {
	for i := 0; i < len(s); i++ {
		if !ok(s[i]) {
			return false
		}
	}
	return s != ""
}

// validPURL checks every component outside the version: no separator, raw or
// percent-encoded, sits inside a component, so no other split reads another
// digest.
func validPURL(p purlParts) bool {
	if !slices.Contains(purlTypes, p.typ) {
		return false
	}
	segments := strings.Split(p.path, "/")
	// types/oci-definition.json: an oci purl has no namespace.
	if p.typ == purlTypeOCI && len(segments) != 1 {
		return false
	}
	for _, s := range segments {
		if !onlyBytes(s, purlUnreserved) {
			return false
		}
	}
	if p.hasQualifiers && !validPURLQualifiers(p.qualifiers) {
		return false
	}
	if p.hasSubpath {
		for _, s := range strings.Split(p.subpath, "/") {
			if s == "." || s == ".." || !onlyBytes(s, purlUnreserved) {
				return false
			}
		}
	}
	return true
}

// digestQualifierKeys name a digest of their own, a second reading beside the version.
var digestQualifierKeys = []string{"checksum", "checksums", "digest"}

func validPURLQualifiers(q string) bool {
	seen := map[string]bool{}
	for _, pair := range strings.Split(q, "&") {
		key, value, found := strings.Cut(pair, "=")
		if !found || seen[key] || slices.Contains(digestQualifierKeys, key) || !validQualifierKey(key) {
			return false
		}
		seen[key] = true
		// A raw '/' is admitted: the specification's own oci vectors carry it,
		// and no reading splits the qualifiers on it.
		valueByte := func(c byte) bool { return purlUnreserved(c) || c == '/' }
		decoded, err := url.PathUnescape(value)
		if err != nil || !onlyBytes(value, func(c byte) bool { return valueByte(c) || c == '%' }) ||
			!onlyBytes(decoded, valueByte) || strings.Contains(strings.ToLower(decoded), "sha256:") {
			return false
		}
	}
	return true
}

// validQualifierKey is Annex C's qualifier-key: lowercase, never encoded.
func validQualifierKey(key string) bool {
	return key != "" && 'a' <= key[0] && key[0] <= 'z' && onlyBytes(key, func(c byte) bool {
		return 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '.' || c == '-' || c == '_'
	})
}

// AnchorKinds returns the closed set of kinds, the reserved one last.
func AnchorKinds() []AnchorKind {
	return []AnchorKind{KindImageRegistryManifest, KindImageConfig, KindGitCommit, KindFileContent}
}

// Measurement is a core function from a fixture input artifact to the
// artifact bytes. The check compares lowercase hex(sha256(bytes)) with the
// attestor's value, so a measured value is re-derived without the attestor.
type Measurement func(inputPath string) ([]byte, error)

// MeasurementOCIConfigBlob reads the config blob that the first manifest.json
// entry of a docker-save archive names.
const MeasurementOCIConfigBlob = "oci-config-blob"

var measurements = map[string]Measurement{
	MeasurementOCIConfigBlob: measureOCIConfigBlob,
}

// AnchorMeasurements returns the closed list of measurement names, sorted.
func AnchorMeasurements() []string {
	names := make([]string, 0, len(measurements))
	for name := range measurements {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// LookupMeasurement returns the named measurement.
func LookupMeasurement(name string) (Measurement, bool) {
	m, ok := measurements[name]
	return m, ok
}

// maxArchiveEntry bounds a manifest.json or config entry read into memory.
const maxArchiveEntry = 256 * 1024 * 1024

func measureOCIConfigBlob(inputPath string) ([]byte, error) {
	f, err := os.Open(inputPath) //nolint:gosec // G304: the fixture input the check names
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	// Two passes over one handle, each hashing the whole stream: equal
	// digests prove both passes read the same bytes.
	manifestRaw, first, err := archiveEntry(f, "manifest.json")
	if err != nil {
		return nil, err
	}
	configName, err := manifestConfig(manifestRaw)
	if err != nil {
		return nil, fmt.Errorf("oci-config-blob: manifest.json: %w", err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	config, second, err := archiveEntry(f, configName)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(first, second) {
		return nil, errors.New("oci-config-blob: archive changed between reads")
	}
	if len(config) == 0 {
		return nil, errors.New("oci-config-blob: config blob is empty")
	}
	return config, nil
}

// manifestConfig returns the Config of manifest.json's first entry. That entry
// names Config exactly once, under every spelling encoding/json folds into the
// field: a reader keeping the first key and one keeping the last would read
// different blobs.
func manifestConfig(raw []byte) (string, error) {
	var manifests []json.RawMessage
	if err := json.Unmarshal(raw, &manifests); err != nil {
		return "", err
	}
	if len(manifests) == 0 {
		return "", errors.New("names no config")
	}
	dec := json.NewDecoder(bytes.NewReader(manifests[0]))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return "", errors.New("the first manifest is not an object")
	}
	var config string
	count := 0
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return "", err
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return "", err
		}
		if key, _ := tok.(string); strings.EqualFold(key, "Config") {
			count++
			if err := json.Unmarshal(value, &config); err != nil {
				return "", err
			}
		}
	}
	if count > 1 {
		return "", fmt.Errorf("names Config %d times", count)
	}
	if config == "" {
		return "", errors.New("names no config")
	}
	return config, nil
}

// archiveEntry returns the bytes of the entry called name, and the sha256 of
// the whole archive stream. The entry must be a regular file and the only one
// that extracts to name, and no parent path of name may be anything but a
// directory: a duplicate ("name", "./name", "/name", a case variant) or a
// link on the way gives an extracting reader, which keeps the last copy and
// follows links, other bytes than a reader that keeps the first.
func archiveEntry(r io.Reader, name string) ([]byte, []byte, error) {
	if !fs.ValidPath(name) || name == "." {
		return nil, nil, fmt.Errorf("oci-config-blob: %q is not a canonical archive path", name)
	}
	h := sha256.New()
	tr := tar.NewReader(io.TeeReader(r, h))
	var body []byte
	found := false
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("oci-config-blob: %w", err)
		}
		match, err := extractsTo(hdr, name)
		if err != nil {
			return nil, nil, err
		}
		if !match {
			continue
		}
		if found {
			return nil, nil, fmt.Errorf("oci-config-blob: more than one entry extracts to %s", name)
		}
		found = true
		if body, err = readRegularEntry(tr, hdr, name); err != nil {
			return nil, nil, err
		}
	}
	if !found {
		return nil, nil, fmt.Errorf("oci-config-blob: %s not found", name)
	}
	// Drain what the tar reader left unread, so the digest covers the whole file.
	if _, err := io.Copy(h, r); err != nil {
		return nil, nil, fmt.Errorf("oci-config-blob: %w", err)
	}
	return body, h.Sum(nil), nil
}

// extractsTo reports whether hdr extracts to name, compared as an extracting
// reader resolves it: cleaned, rooted and case-folded. A header that is not a
// directory at one of name's parent paths is refused.
func extractsTo(hdr *tar.Header, name string) (bool, error) {
	target := "/" + name
	entry := path.Clean("/" + hdr.Name)
	if hdr.Typeflag != tar.TypeDir && len(entry) < len(target) && strings.EqualFold(target[:len(entry)+1], entry+"/") {
		return false, fmt.Errorf("oci-config-blob: %s sits under %s, which is not a directory", name, hdr.Name)
	}
	return strings.EqualFold(entry, target), nil
}

// readRegularEntry reads the entry that extracts to name: a regular file
// stored under exactly that name.
func readRegularEntry(tr *tar.Reader, hdr *tar.Header, name string) ([]byte, error) {
	if hdr.Name != name {
		return nil, fmt.Errorf("oci-config-blob: entry %q extracts to %s under another name", hdr.Name, name)
	}
	if hdr.Typeflag != tar.TypeReg {
		return nil, fmt.Errorf("oci-config-blob: %s is not a regular file", name)
	}
	if hdr.Size < 0 || hdr.Size > maxArchiveEntry {
		return nil, fmt.Errorf("oci-config-blob: %s has invalid size %d", name, hdr.Size)
	}
	body := make([]byte, hdr.Size)
	if _, err := io.ReadFull(tr, body); err != nil {
		return nil, fmt.Errorf("oci-config-blob: read %s: %w", name, err)
	}
	return body, nil
}

// AnchorPrefixDenylist returns the subject key prefixes that may never be an
// anchor or acceptor prefix for any attestor (3.5).
func AnchorPrefixDenylist() []string {
	return slices.Clone(anchorPrefixDenylist)
}

const prefixTree = "tree:"

var anchorPrefixDenylist = []string{
	"parenthash:", "commithash:", "commitsha:", "commit:",
	"pullrequestheadsha:", "pullrequestheadref:", "pullrequest:", "mergecommitsha:", "pipelineurl:",
	"projecturl:", "joburl:", "jenkinsurl:", "codebuild-", "imagetag:", "imagereference:", "imageref:",
	"manifestdigest:", "tardigest:", "name:", "version:", "trivy:", prefixTree, "remote:", "refnameshort:",
	"authoremail:", "committeremail:", "reponame:", "repourl:", "repo:", "pr:", "reviewer:", "actionref:",
	"sender:", "event:", "layerdiffid", "materialdigest:", "materialuri:", "runimagedigest:", "artifact:",
	"policy:", "inventory:",
}

// SeedDenylistEntry is a subject a depth-0 seed may not match, keyed by the
// resolved attestor and prefix. An empty Version means every version.
type SeedDenylistEntry struct {
	Attestor string
	Version  string
	Prefix   string
	Note     string
}

// SeedDenylist returns the seed denylist (3.5).
func SeedDenylist() []SeedDenylistEntry {
	return slices.Clone(seedDenylist)
}

var seedDenylist = []SeedDenylistEntry{
	{Attestor: "docker", Prefix: "materialdigest:", Note: "the base image, shared by every image built on it"},
	{Attestor: "buildpacks", Prefix: "runimagedigest:", Note: "the run image, shared by every image built on it"},
	{Attestor: "oci", Prefix: "layerdiffid", Note: "a base layer is shared by every image on that base"},
	{Attestor: "material", Prefix: prefixTree, Note: "a root over a set of consumed files"},
	{Attestor: "product", Prefix: prefixTree, Note: "a root over a set of produced files; bridge seeds excepted"},
	{Attestor: "material", Version: "v0.1", Prefix: "file:", Note: "legacy consumed-file subjects"},
	{Attestor: "git", Prefix: "parenthash:", Note: "already unmatchable as sha1; kept for sha256 repositories"},
}

// HubValue is a value shared by unrelated artifacts; it is never an anchor
// and never a seed match. The list can only grow, and each entry names its
// evidence.
type HubValue struct {
	Value    string
	Evidence string
}

// HubValues returns the hub value list (A7).
func HubValues() []HubValue {
	return slices.Clone(hubValues)
}

var hubValues = []HubValue{
	{Value: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", Evidence: `sha256(""), also the empty RFC 6962 Merkle root material and product emit for an empty set`},
	{Value: "cdb4ee2aea69cc6a83331bbe96dc2caa9a299d21329efb0336fc02a82e1839a8", Evidence: `sha256("."), the name syft and trivy give a directory target`},
}

// The counters and verdicts of the closed reason list.
const (
	CounterAnchorsDropped   = "anchors_dropped"
	CounterLinksDropped     = "links_dropped"
	CounterPolicyRefused    = "policy refused"
	CounterAcceptorsDropped = "acceptors_dropped"
	CounterWitnessRejected  = "witness rejected"
	CounterSeedsDropped     = "seeds_dropped"
	CounterRequestRefused   = "request refused"
	CounterWorkflow         = "workflow diagnostic"
)

// AnchorReason is one entry of the closed reason list (4.8).
type AnchorReason struct {
	Counter string
	Reason  string
}

// AnchorReasons returns the closed list of reasons the engine, RunSync and
// the Judge workflow may emit.
func AnchorReasons() []AnchorReason {
	return slices.Clone(anchorReasons)
}

var anchorReasons = []AnchorReason{
	{CounterAnchorsDropped, "unregistered"},
	{CounterAnchorsDropped, "unrecomputable"},
	{CounterAnchorsDropped, "non-canonical"},
	{CounterAnchorsDropped, "hub"},
	{CounterAnchorsDropped, "legacy-dropped"},
	{CounterAnchorsDropped, "role-about"},
	{CounterAnchorsDropped, "multi-artifact"},
	{CounterAnchorsDropped, "not-admitted-by-product"},
	{CounterLinksDropped, "not-hardened"},
	{CounterLinksDropped, "multi-commit"},
	{CounterLinksDropped, "not-admitted-by-product"},
	{CounterPolicyRefused, "about-needs-policy-v0.2"},
	{CounterPolicyRefused, "about-unknown-value"},
	{CounterPolicyRefused, "policy-type-unknown"},
	{CounterAcceptorsDropped, "acceptor-unbacked"},
	{CounterWitnessRejected, "anchor-unbacked"},
	{CounterWitnessRejected, "source-commit-mismatch"},
	{CounterWitnessRejected, "seed-denylist"},
	{CounterWitnessRejected, "hub-seed"},
	{CounterWitnessRejected, "vsa-unmarked"},
	{CounterSeedsDropped, "envelope-subject"},
	{CounterSeedsDropped, "envelope-other-commit"},
	{CounterSeedsDropped, "envelope-no-commit"},
	{CounterRequestRefused, "extra-subject-with-commit"},
	{CounterRequestRefused, "other-commit"},
	{CounterWorkflow, "no-candidate-commit"},
}

// AnchorRegistryRow is one row of anchor_registry.json, one per
// (resolved attestor type, subject key prefix).
type AnchorRegistryRow struct {
	Attestor      string        `json:"attestor"`
	Prefix        string        `json:"prefix"`
	Class         AnchorClass   `json:"class"`
	Kind          AnchorKind    `json:"kind,omitempty"`
	Role          AnchorRole    `json:"role,omitempty"`
	Basis         AnchorBasis   `json:"basis,omitempty"`
	Algorithm     string        `json:"algorithm,omitempty"`
	SignedPath    string        `json:"signed_path,omitempty"`
	Normalization Normalization `json:"normalization,omitempty"`
	Gate          string        `json:"gate,omitempty"`
	Measurement   string        `json:"measurement,omitempty"`
	RecomputeFrom string        `json:"recompute_from,omitempty"`
	Rule          []string      `json:"rule,omitempty"`
	Golden        string        `json:"golden,omitempty"`
	Evidence      string        `json:"evidence"`
	Since         string        `json:"since"`
}

//go:embed anchor_registry.json
var anchorRegistryJSON []byte

var anchorRegistry []AnchorRegistryRow

// A registry that does not parse is a build defect, never a smaller registry.
func init() {
	rows, err := parseAnchorRegistry(anchorRegistryJSON)
	if err != nil {
		panic(fmt.Sprintf("anchor_registry.json: %v", err))
	}
	anchorRegistry = rows
}

// AnchorRegistryRows returns a copy of the compiled registry.
func AnchorRegistryRows() []AnchorRegistryRow {
	out := make([]AnchorRegistryRow, len(anchorRegistry))
	for i, r := range anchorRegistry {
		r.Rule = slices.Clone(r.Rule)
		out[i] = r
	}
	return out
}

const anchorRegistryVersion = 1

// predicateSource is recompute_from for a value read from the attestor's own
// signed predicate.
const predicateSource = "predicate"

func parseAnchorRegistry(b []byte) ([]AnchorRegistryRow, error) {
	var doc struct {
		Version int                 `json:"version"`
		Rows    []AnchorRegistryRow `json:"rows"`
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, errors.New("trailing data after the registry document")
	}
	if doc.Version != anchorRegistryVersion {
		return nil, fmt.Errorf("unsupported registry version %d", doc.Version)
	}
	if len(doc.Rows) == 0 {
		return nil, errors.New("registry has no rows")
	}
	seen := map[[2]string]bool{}
	for i, row := range doc.Rows {
		key := [2]string{row.Attestor, row.Prefix}
		if seen[key] {
			return nil, fmt.Errorf("row %d: duplicate row %s %s", i, row.Attestor, row.Prefix)
		}
		seen[key] = true
		if err := validateAnchorRow(row); err != nil {
			return nil, fmt.Errorf("row %d (%s %s): %w", i, row.Attestor, row.Prefix, err)
		}
	}
	return doc.Rows, nil
}

func validateAnchorRow(r AnchorRegistryRow) error {
	if r.Attestor == "" || strings.ContainsFunc(r.Attestor, unicode.IsSpace) {
		return errors.New("attestor must be a non-empty type URI")
	}
	if r.Prefix == "" || strings.ContainsFunc(r.Prefix, unicode.IsSpace) {
		return errors.New("prefix must be non-empty")
	}
	if r.Evidence == "" || r.Since == "" {
		return errors.New("evidence and since are required")
	}
	switch r.Class {
	case ClassNotAnchor:
		return validateNotAnchorRow(r)
	case ClassAnchor, ClassAcceptor:
		if len(r.Rule) != 0 {
			return errors.New("rule is for not_anchor rows only")
		}
		for _, check := range []func(AnchorRegistryRow) error{validateRowPrefix, validateRowIdentity, validateRowBasis, validateRowEncoding} {
			if err := check(r); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("unknown class %q", r.Class)
	}
}

func validateNotAnchorRow(r AnchorRegistryRow) error {
	if len(r.Rule) == 0 {
		return errors.New("a not_anchor row names the rules that exclude it")
	}
	if r.Kind != "" || r.Role != "" || r.Basis != "" || r.Algorithm != "" || r.SignedPath != "" ||
		r.Normalization != "" || r.Gate != "" || r.Measurement != "" || r.RecomputeFrom != "" || r.Golden != "" {
		return errors.New("a not_anchor row carries no identity fields")
	}
	return nil
}

func validateRowPrefix(r AnchorRegistryRow) error {
	if !strings.HasSuffix(r.Prefix, ":") {
		return errors.New("prefix must end with its ':' separator")
	}
	for _, denied := range anchorPrefixDenylist {
		if strings.HasPrefix(r.Prefix, denied) {
			return fmt.Errorf("prefix is on the anchor prefix denylist (%s)", denied)
		}
	}
	return nil
}

func validateRowIdentity(r AnchorRegistryRow) error {
	if r.Kind != KindImageRegistryManifest && r.Kind != KindImageConfig {
		return fmt.Errorf("kind %q is not an admitted kind", r.Kind)
	}
	if !slices.Contains(kindAlgorithms[r.Kind], r.Algorithm) {
		return fmt.Errorf("algorithm %q is not admitted for kind %s", r.Algorithm, r.Kind)
	}
	if r.Class == ClassAnchor && r.Role != RoleProduced {
		return errors.New("an anchor row has role produced")
	}
	if r.Class == ClassAcceptor && r.Role != RoleAbout {
		return errors.New("an acceptor row has role about")
	}
	return nil
}

func validateRowBasis(r AnchorRegistryRow) error {
	switch r.Basis {
	case BasisMeasured:
		if _, ok := measurements[r.Measurement]; !ok {
			return fmt.Errorf("measured row names no measurement from the closed list (%q)", r.Measurement)
		}
	case BasisObserved, BasisReported:
		if r.Class == ClassAnchor && r.Basis == BasisReported {
			return errors.New("a reported value is an acceptor only")
		}
		if r.Measurement != "" {
			return errors.New("only a measured row names a measurement")
		}
	default:
		return fmt.Errorf("unknown basis %q", r.Basis)
	}
	if r.RecomputeFrom == "" || (r.Basis == BasisObserved) == (r.RecomputeFrom == predicateSource) {
		return errors.New("recompute_from is a sibling type for observed rows and predicate otherwise")
	}
	return nil
}

func validateRowEncoding(r AnchorRegistryRow) error {
	switch r.Normalization {
	case NormalizationBareHex, NormalizationPrefixed, NormalizationRepoAtDigest, NormalizationPURLVersion:
	default:
		return fmt.Errorf("unknown normalization %q", r.Normalization)
	}
	if !strings.HasPrefix(r.SignedPath, "$.") {
		return errors.New("signed_path must be a JSON path rooted at $")
	}
	return nil
}
