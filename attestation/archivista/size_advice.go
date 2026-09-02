package archivista

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// largeEnvelopeBytes is where an envelope stops being routine.
//
// The number is not a guess and not a round number chosen for looks: it is the
// pushgate's own envelope read cap, defined twice and deliberately mirrored —
// MAX_RESPONSE_BYTES in jade/factory/edge/git/evidence.js and maxEnvelopeBytes
// in jade/factory/edge/git/bodylimit.go, both 4 MiB. Envelope JSON is served
// from Archivista, which makes it tenant-controlled, and the verification work
// it demands (JSON decode, base64, per-signature crypto) is proportional to
// the bytes accepted — so the cap is a DoS bound on attacker-controlled input,
// not a performance tuning knob.
//
// Past it the envelope cannot be read by the pushgate's EDGE FALLBACK
// verification path. It says nothing about the platform-verdict path, which is
// how a push is normally evaluated, and nothing about whether the upload will
// succeed. Those are three separate things and this threshold only speaks to
// the middle one; the message keeps them apart.
//
// Warning at this size is still right for uploads, because the size that
// forfeits the fallback is also comfortably past the size that starts costing
// real upload time.
const largeEnvelopeBytes = 4 << 20

// humanBytes renders a byte count the way an operator reads one. Uploads are
// reported in raw bytes elsewhere in this file because those lines are grepped
// by tooling; this one is for a person.
func humanBytes(n int) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := int64(n) / unit; v >= unit && exp < 3; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGT"[exp])
}

// sizeAdvice returns operator-facing guidance for an oversized envelope, or ""
// when the size is unremarkable.
//
// WHY THIS EXISTS. Measured 2026-08-30: a green 28-check gate produced an
// 18 MiB envelope and died with
//
//	archivista upload failed: classification=terminal reason=budget_exhausted
//	attempts=2 elapsed=4m0s bytes=17988881
//
// Every field in that line is true and none of them says what went wrong. The
// bulk was an untracked node_modules tree captured by the material attestor,
// which walks the entire working directory; the operator's actual remedy was
// to delete a directory. An error that reports a timeout for a problem that is
// really "you attested 600,000 files you did not mean to attest" costs a
// diagnosis cycle every time someone hits it.
//
// The advice deliberately names the usual cause rather than describing the
// general class. A message that says "consider reducing the envelope size" is
// the same as no message.
//
// STOP GUESSING, REPORT THE MEASUREMENT. This used to name a fixed list of
// suspects ("node_modules, dist, target, vendor, .venv") because the function
// only received a byte count. That guess is wrong about half the time, and the
// two halves have OPPOSITE remedies:
//
//   - 34.5 MiB on a tree carrying site/website/node_modules and
//     salespot/deploy/node_modules — untracked dependency trees. Deleting them
//     fixes it completely.
//   - 4.95 MiB on a clean tree — 17,152 leaves that are genuinely the
//     repository's tracked source. There is nothing to delete.
//
// Both are material-dominant, so naming the ATTESTOR does not tell them apart;
// only the contributing PATH PREFIXES do. The caller is holding the marshalled
// envelope at the moment it fails, so the breakdown is free to compute and is
// only computed once an upload has already failed on an oversized envelope.
//
// Everything here degrades to the size-only message rather than failing: an
// error path that can itself fail turns a diagnosable problem into a panic.
// sizeAdvice is the SIZE-ONLY form, used for the up-front warning that fires
// before the first upload attempt.
//
// It deliberately carries NO envelope-derived detail. That warning is emitted
// on every oversized upload, including ones that go on to SUCCEED, so putting
// the contents breakdown here would log repository structure on the happy path
// — which is both a disclosure the success path never promised and a boundary
// this file explicitly claims to hold. The detail belongs to
// sizeAdviceMeasured, which only runs once an upload has actually failed.
func sizeAdvice(size int) string {
	if size < largeEnvelopeBytes {
		return ""
	}
	var b strings.Builder
	writeSizeConsequences(&b, size)
	b.WriteString("  remedy: re-mint once before changing anything — an upload failure is not by " +
		"itself evidence that size caused it; a 34.5 MiB payload that failed twice re-uploaded " +
		"clean, unchanged and with no flags. If it fails, the error will report what is actually " +
		"in the envelope.")
	return b.String()
}

func writeSizeConsequences(b *strings.Builder, size int) {
	fmt.Fprintf(b, "the envelope is %s. Two separate consequences, and they are not the same problem:\n",
		humanBytes(size))
	b.WriteString("  - it uploads slowly, which is the usual reason this retry budget runs out;\n")
	fmt.Fprintf(b, "  - it is over the %s the pushgate will read of one envelope, so it cannot be "+
		"verified by the edge fallback path (the platform verdict path is unaffected).\n",
		humanBytes(largeEnvelopeBytes))
}

// sizeAdviceMeasured is the FAILURE-PATH form: size, plus the measured contents
// of the envelope and a remedy keyed to them.
func sizeAdviceMeasured(size int, body []byte) string {
	if size < largeEnvelopeBytes {
		return ""
	}
	var b strings.Builder
	writeSizeConsequences(&b, size)

	contribs := envelopeBreakdown(body)
	if len(contribs) == 0 {
		// No measurement available: the payload was absent, not JSON, not
		// base64, or carries no inline leaves (which is what a detached
		// material manifest, issue #8410, will look like). Say the suspects
		// are a GUESS rather than dressing one up as a finding.
		b.WriteString("  the envelope could not be decoded here, so this is a guess rather than a " +
			"measurement: the usual cause is a dependency or build directory captured as " +
			"materials/products — node_modules, dist, target, vendor, .venv — which the material " +
			"attestor records because it walks the whole working directory.\n")
		b.WriteString("  remedy: re-mint once before changing anything — an upload failure is not by " +
			"itself evidence that size caused it; a 34.5 MiB payload that failed twice re-uploaded " +
			"clean, unchanged and with no flags.")
		return b.String()
	}

	b.WriteString("  measured contents, largest attestor first (share of the attestation payload):\n")
	b.WriteString(renderContributions(contribs))
	b.WriteString(remedyFor(contribs, size))
	return b.String()
}

// envelopeSaving converts bytes of ATTESTATION payload the operator could
// remove into bytes of ENVELOPE, which is what the cap is measured in.
//
// A DSSE envelope is a JSON wrapper, the payload base64-encoded, and the
// signatures — and only the middle term moves when payload is removed. The
// wrapper and the signatures (a keyless signature carries a certificate chain
// and a timestamp, several KiB that do not shrink by a byte) are FIXED. The
// first version of this scaled the removed bytes by size/payload, which
// spreads that fixed overhead across the payload and over-promises by exactly
// the overhead's share: on a small envelope near the cap that is enough to
// call a deletion the fix when it is not.
//
// So the saving is the base64 growth of the removed bytes alone: three
// payload bytes become four. Rounded DOWN to the base64 quantum, and without
// the list separators that leave with each leaf, so the number can fall short
// of what deletion actually saves but never exceed it. Under-promising costs
// a sentence; over-promising costs an afternoon.
func envelopeSaving(attestationBytes int) int {
	if attestationBytes <= 0 {
		return 0
	}
	return 4 * (attestationBytes / 3)
}

// remedyFor keys the advice to the measured dominant contributor instead of to
// a fixed list.
//
// RE-MINT LEADS, and that ordering is itself a measurement. The budget_exhausted
// failures that motivated this whole message were TRANSIENT: the exact 34.5 MB
// payload that died twice re-uploaded clean with no flags at all. So neither
// --attestor-product-exclude-glob nor --archivista-upload-retry-budget was the
// thing that fixed it, and presenting either as "the remedy" teaches a
// superstition. That observation shows the flags were unnecessary in THAT
// instance; it does not show size never matters or that the budget can never
// help.
func remedyFor(contribs []attestorContribution, size int) string {
	var b strings.Builder
	b.WriteString("  remedy: re-mint once first. An upload failure is not by itself evidence that " +
		"size caused it — a 34.5 MiB payload that failed twice re-uploaded clean, unchanged and " +
		"with no flags.\n")

	top := contribs[0]
	// Classification below keys off the RAW name; only the rendered form is
	// sanitized. The two must not be swapped: quoting the name before the
	// prefix test would send a legitimate attestor to the wrong arm.
	shown := top.shown()
	switch {
	case strings.HasPrefix(top.Name, productAttestorName):
		b.WriteString("  " + shown + " dominates, which is unusual. Narrow it with ONE " +
			"--attestor-product-exclude-glob — the flag is last-one-wins, so repeating it silently " +
			"applies only the last pattern; put every tree in one brace alternation, e.g. " +
			"'{**/,}{node_modules,.venv}/**'. Exclude dependencies, never build output: recording " +
			"what the run produced is what the product attestor is for.")
	case strings.HasPrefix(top.Name, materialAttestorName):
		del := deletableGroups(top.Groups)
		maybe := ambiguousGroups(top.Groups)
		if len(del.Names) == 0 {
			b.WriteString("  " + shown + " dominates and the contributors above are the " +
				"repository's own tracked files, so there is nothing worth deleting. " +
				materialHasNoLever)
			b.WriteString(ambiguousAdvice(maybe))
			break
		}
		list := strings.Join(del.Names, ", ")
		named := "them"
		if del.More > 0 {
			list += " (and " + strconv.Itoa(del.More) + " smaller dependency " +
				plural(del.More, "tree", "trees") + " not named here)"
			named = "the " + strconv.Itoa(len(del.Names)) + " named"
		}
		pct := sharePct(del.TotalBytes, top.Bytes)
		// Two predictions from two byte counts. namedLeft is what the operator
		// who removes exactly the directories listed will get; allLeft is what
		// removing every dependency tree gets, unnamed ones included. The list
		// is bounded for readability, and a bound on what is DISPLAYED must not
		// be allowed to decide what is TRUE: three named trees that fall short
		// of the cap say nothing about whether the ones left unnamed clear it.
		namedLeft := size - envelopeSaving(del.NamedBytes)
		allLeft := size - envelopeSaving(del.TotalBytes)
		switch {
		case namedLeft < largeEnvelopeBytes:
			b.WriteString("  " + shown + " dominates, and the largest contributors are " +
				"dependency-shaped trees in the working directory: " + list + " — " + pct + " of it. " +
				"The material attestor walks the whole working directory, so removing " + named +
				" before attesting would take the envelope to about " + humanBytes(namedLeft) +
				", under the " + humanBytes(largeEnvelopeBytes) + " cap — that fixes it if they " +
				"are untracked. " + confirmUntracked)
		case allLeft < largeEnvelopeBytes:
			b.WriteString("  " + shown + " dominates, and the largest contributors are " +
				"dependency-shaped trees in the working directory: " + list + " — " + pct + " of it. " +
				"Removing only " + named + " would take the envelope to about " + humanBytes(namedLeft) +
				", still over the " + humanBytes(largeEnvelopeBytes) + " cap; removing every " +
				"such tree, the " + strconv.Itoa(del.More) + " smaller " +
				plural(del.More, "one", "ones") + " included, would take it to about " +
				humanBytes(allLeft) + ", under the cap — that fixes it if they are untracked. " +
				confirmUntracked)
		default:
			b.WriteString("  " + shown + " dominates. Dependency-shaped trees are present — " + list +
				" — at " + pct + " of it, but removing every one of them, unnamed ones included, " +
				"would still leave about " + humanBytes(allLeft) + ", over the " +
				humanBytes(largeEnvelopeBytes) + " cap. " + materialHasNoLever)
		}
		b.WriteString(ambiguousAdvice(maybe))
	default:
		b.WriteString("  " + shown + " dominates. Reduce what that attestor records, or accept " +
			"the size if it is genuinely intended.")
	}
	return b.String()
}

const (
	materialAttestorName = "material/"
	productAttestorName  = "product/"
)

// attestorContribution is one attestor's share of the envelope.
//
// Name is the RAW short form of the predicate type and is what the remedy
// classifies on. It is never written to output directly: the type URI comes
// out of the envelope, which is tenant-controlled data, so it gets the same
// treatment as a path — see shown.
type attestorContribution struct {
	Name   string
	Bytes  int
	Leaves int
	Groups []pathGroup
}

// shown is the attestor's name as it may be interpolated into a log line or
// an error message. Every site that renders an attestor goes through here;
// classification keeps using the raw Name.
func (c attestorContribution) shown() string {
	return safeText(c.Name)
}

// pathGroup is a directory prefix's share of one attestor's leaves.
type pathGroup struct {
	Prefix string
	Leaves int
	Bytes  int
}

// dependencyTreeSegments are path segments that mark a tree a package manager
// USUALLY built from a manifest and will build again — the shape whose removal
// is worth predicting. They are counted toward that prediction; they are not
// proof the tree is disposable.
//
// THE ENVELOPE CANNOT SAY WHETHER A TREE IS TRACKED. A material leaf carries
// a path, a file digest and a leaf hash and nothing else
// (plugins/attestors/material/material.go), and the git attestor's status
// lists only CHANGED files: an ignored node_modules never appears in it and a
// committed one is unmodified, so it does not appear either. This repository
// carries committed node_modules fixtures under bootstrap/act/…/testdata, and a
// large enough one would look exactly like an untracked dependency tree from
// here. So the remedy states its prediction as conditional on `git ls-files
// <dir>` printing nothing, and keeps the structural fix as the answer when it
// does not — see confirmUntracked. Grouping AT the segment names the exact
// directory to check (`site/website/node_modules/`) rather than a useless
// common ancestor (`site/`).
var dependencyTreeSegments = map[string]bool{
	"node_modules": true, ".venv": true, "venv": true,
	"site-packages": true, ".tox": true, ".gradle": true, ".cache": true,
}

// ambiguousTreeSegments are names that USUALLY hold build output or vendored
// copies but are routinely tracked source too — a Go module's committed
// `vendor/`, a `dist/` that is the published artifact, a `build/` directory of
// scripts. The name alone does not make them disposable, so they are grouped
// (the operator wants the exact directory) and offered as candidates to check,
// never counted toward a deletion the remedy promises will clear the cap.
var ambiguousTreeSegments = map[string]bool{
	"vendor": true, "target": true, "dist": true, "build": true,
}

// isTreeSegment reports whether a path segment ends a group for reporting.
func isTreeSegment(seg string) bool {
	return dependencyTreeSegments[seg] || ambiguousTreeSegments[seg]
}

// ambiguousGroups names the groups whose prefix carries an ambiguous segment,
// largest first, bounded like the deletable list.
func ambiguousGroups(groups []pathGroup) []string {
	var matched []pathGroup
	for _, g := range groups {
		if prefixHasSegment(g.Prefix, ambiguousTreeSegments) {
			matched = append(matched, g)
		}
	}
	sort.SliceStable(matched, func(i, j int) bool { return matched[i].Bytes > matched[j].Bytes })
	names := make([]string, 0, maxNamedDeletable)
	for i, g := range matched {
		if i >= maxNamedDeletable {
			break
		}
		names = append(names, safeText(g.Prefix))
	}
	return names
}

// ambiguousAdvice is the sentence for the candidates the remedy will not vouch
// for: present, possibly disposable, and the operator's call.
func ambiguousAdvice(names []string) string {
	if len(names) == 0 {
		return ""
	}
	return " Also present: " + strings.Join(names, ", ") + " — a name like that is often build " +
		"output or a vendored copy, but it is also often tracked source, so it is not counted " +
		"above; delete it only if `git ls-files <dir>` prints nothing."
}

func prefixHasSegment(prefix string, segments map[string]bool) bool {
	for seg := range segments {
		if strings.Contains(prefix, "/"+seg+"/") || strings.HasPrefix(prefix, seg+"/") {
			return true
		}
	}
	return false
}

// leafGroup picks the prefix a leaf is reported under.
//
// The depth is chosen to DISCRIMINATE the two measured shapes, not by taste:
//   - a fixed depth of 1 collapses site/website/node_modules into `site/`,
//     which hides the actionable directory;
//   - a dependency segment anywhere in the path wins and truncates there, so
//     the group is exactly the directory to delete;
//   - otherwise two segments, which separates `subtrees/rookery/` from
//     `judge-api/pkg/` in the tracked-source shape instead of merging them.
func leafGroup(path string) string {
	path = strings.TrimPrefix(path, "./")
	segs := strings.Split(path, "/")
	if len(segs) == 0 || path == "" {
		return "(unknown)"
	}
	// Directory segments only: the last element is the file name.
	for i := 0; i < len(segs)-1; i++ {
		if isTreeSegment(segs[i]) {
			return strings.Join(segs[:i+1], "/") + "/"
		}
	}
	switch {
	case len(segs) == 1:
		return "(repository root)"
	case len(segs) == 2:
		return segs[0] + "/"
	default:
		return segs[0] + "/" + segs[1] + "/"
	}
}

// materialHasNoLever is the shared tail for every arm where no flag will help.
const materialHasNoLever = "The " + materialNoLeverBody

// materialNoLeverBody is materialHasNoLever without its capital, for the
// arms that reach it mid-sentence.
const materialNoLeverBody = "material attestor walks the whole working directory and has NO " +
	"include/exclude glob option today, so no flag narrows it — the structural fix is the " +
	"detached material manifest (issue #8410)."

// confirmUntracked follows every prediction that deletion would clear the
// cap. The prediction is arithmetic on bytes in hand; whether the bytes MAY be
// deleted is not knowable from the envelope (see dependencyTreeSegments), so
// the sentence names the check and what each answer means.
const confirmUntracked = "Confirm that before deleting anything: `git ls-files <dir>` prints " +
	"nothing for a tree a package manager built and will rebuild, but lists a committed one — a " +
	"checked-in test fixture, say — and a committed tree is attested content, not clutter. If " +
	"these are committed there is nothing to delete, and the " + materialNoLeverBody

// WHY THE REMEDY KEYS OFF THE OUTCOME, NOT A SHARE.
//
// This first shipped as "call it the fix when dependency trees are >= 50% of
// the dominant attestor". That is a PROXY for the question that decides whether
// the sentence is true, and it is wrong in both directions:
//
//   - 45% dependencies on a 5.0 MiB envelope: removing them lands under the
//     4 MiB cap and genuinely IS the fix, but the share rule said "would save
//     little" and sent the operator to a structural issue instead.
//   - 99% dependencies on a 40 MiB envelope: removing every one of them still
//     leaves it far over the cap, but the share rule promised a fix — real work
//     for no result, which is exactly the failure this message exists to stop.
//
// Neither of the two real measured cases (4% and ~90%) sat anywhere near a
// boundary, so no amount of running them could have exposed this. The bytes are
// already in hand at this point, so the honest form is arithmetic:
//
//	size - deletableBytes < largeEnvelopeBytes  ->  deletion clears the cap.
//
// deletableBytes is counted in ATTESTATION bytes while size is ENVELOPE bytes;
// envelopeSaving does the conversion, and does it in the direction that may
// decline to promise a fix that would have worked but will not promise one
// that does not.
//
// The share is still REPORTED in both arms — it is useful context — it just no
// longer makes the decision.
//
// AND THE PROMISE IS CONDITIONAL. The envelope cannot say whether a tree is
// tracked (see dependencyTreeSegments), so even when the arithmetic says
// deletion clears the cap the sentence says "if they are untracked", names the
// one-line check, and keeps the structural fix as the answer for a committed
// tree. The decision "would deletion clear the cap" is made here; the decision
// "is deletion allowed" is the operator's, and the advice says so.

// maxNamedDeletable bounds how many directories the remedy lists. The operator
// needs the big ones, not an inventory.
const maxNamedDeletable = 3

// deletableTrees is what deletableGroups found. It carries TWO byte counts on
// purpose, because they answer two different questions:
//
//   - NamedBytes is the attestation bytes of the directories in Names, and is
//     the only honest basis for a prediction phrased as "remove these": an
//     operator who removes exactly what was listed gets exactly that number.
//   - TotalBytes is the attestation bytes of EVERY matching tree, named or
//     not, and is the only honest basis for "can deletion clear the cap at
//     all". Names is bounded for readability, and a display bound that was
//     allowed to make that decision would send an operator whose fourth and
//     fifth trees held the difference to a structural fix they do not need.
type deletableTrees struct {
	Names      []string // largest first, display-safe, at most maxNamedDeletable
	NamedBytes int      // attestation bytes of Names only
	TotalBytes int      // attestation bytes of every matching tree
	More       int      // matching trees beyond Names
}

// deletableGroups returns the dependency-shaped tree prefixes an operator
// could remove IF they are untracked, largest first, bounded for display, with
// the bytes of the named ones and of all of them kept apart (see
// deletableTrees).
func deletableGroups(groups []pathGroup) deletableTrees {
	var matched []pathGroup
	for _, g := range groups {
		if prefixHasSegment(g.Prefix, dependencyTreeSegments) {
			matched = append(matched, g)
		}
	}
	if len(matched) == 0 {
		return deletableTrees{}
	}
	sort.SliceStable(matched, func(i, j int) bool { return matched[i].Bytes > matched[j].Bytes })
	del := deletableTrees{Names: make([]string, 0, maxNamedDeletable)}
	for i, g := range matched {
		del.TotalBytes += g.Bytes
		if i >= maxNamedDeletable {
			del.More++
			continue
		}
		del.Names = append(del.Names, safeText(g.Prefix))
		del.NamedBytes += g.Bytes
	}
	return del
}

// envelopeBreakdown decodes a marshalled DSSE envelope and reports each
// attestor's byte contribution, largest first.
//
// It returns nil on ANY decoding problem. This runs while an error is being
// rendered, so every failure mode here has to reduce to "say less", never to a
// panic or a second error.
func envelopeBreakdown(body []byte) []attestorContribution {
	if len(body) == 0 {
		return nil
	}
	var env struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(body, &env); err != nil || env.Payload == "" {
		return nil
	}
	raw, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil
	}
	var stmt struct {
		Predicate struct {
			Attestations []struct {
				Type        string          `json:"type"`
				Attestation json.RawMessage `json:"attestation"`
			} `json:"attestations"`
		} `json:"predicate"`
	}
	if err := json.Unmarshal(raw, &stmt); err != nil {
		return nil
	}

	var out []attestorContribution
	for _, a := range stmt.Predicate.Attestations {
		c := attestorContribution{Name: shortAttestorName(a.Type), Bytes: len(a.Attestation)}
		c.Leaves, c.Groups = leafBreakdown(a.Attestation)
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Bytes > out[j].Bytes })
	return out
}

// leafBreakdown counts a predicate's inline leaves and groups them by path
// prefix. A predicate with no "leaves" key (a detached manifest, or an attestor
// that simply has none) yields 0 and nil, and the caller reports bytes only.
func leafBreakdown(pred []byte) (int, []pathGroup) {
	var p struct {
		Leaves []json.RawMessage `json:"leaves"`
	}
	if err := json.Unmarshal(pred, &p); err != nil || len(p.Leaves) == 0 {
		return 0, nil
	}
	byPrefix := map[string]*pathGroup{}
	for _, lr := range p.Leaves {
		var l struct {
			Path string `json:"path"`
		}
		if err := json.Unmarshal(lr, &l); err != nil {
			continue
		}
		g := leafGroup(l.Path)
		if byPrefix[g] == nil {
			byPrefix[g] = &pathGroup{Prefix: g}
		}
		byPrefix[g].Leaves++
		byPrefix[g].Bytes += len(lr)
	}
	groups := make([]pathGroup, 0, len(byPrefix))
	for _, g := range byPrefix {
		groups = append(groups, *g)
	}
	sort.SliceStable(groups, func(i, j int) bool {
		if groups[i].Bytes != groups[j].Bytes {
			return groups[i].Bytes > groups[j].Bytes
		}
		return groups[i].Prefix < groups[j].Prefix
	})
	return len(p.Leaves), groups
}

// shortAttestorName reduces a predicate type URI to the name an operator
// recognises: https://witness.dev/attestations/material/v0.3 -> material/v0.3.
func shortAttestorName(typeURI string) string {
	if typeURI == "" {
		return "(unnamed)"
	}
	segs := strings.Split(strings.TrimRight(typeURI, "/"), "/")
	if len(segs) >= 2 {
		return segs[len(segs)-2] + "/" + segs[len(segs)-1]
	}
	return segs[len(segs)-1]
}

// maxReportedGroups bounds the path-prefix block. Three lines distinguished
// both measured shapes; more turns a diagnosis into a wall.
const maxReportedGroups = 3

// renderContributions draws the per-attestor table, plus the contributing path
// prefixes for the dominant attestor — the block that tells "delete these
// dependency trees" apart from "this is just the repository".
//
// Shares are of the ATTESTATION PAYLOAD, not of the envelope. The envelope is
// the base64 of the statement plus signatures, so attestation bytes over
// envelope bytes understates every row by roughly a quarter and the column
// would never sum to 100%. The operator can only act on the attestation half,
// so that is the denominator the percentages are taken against.
func renderContributions(contribs []attestorContribution) string {
	total := 0
	for _, c := range contribs {
		total += c.Bytes
	}
	var b strings.Builder
	for i, c := range contribs {
		fmt.Fprintf(&b, "    %-18s %14s  %6s", c.shown(), commas(c.Bytes)+" B", sharePct(c.Bytes, total))
		if c.Leaves > 0 {
			fmt.Fprintf(&b, "  (%s %s)", commas(c.Leaves), plural(c.Leaves, "leaf", "leaves"))
		}
		b.WriteString("\n")
		if i != 0 {
			continue
		}
		for j, g := range c.Groups {
			if j >= maxReportedGroups {
				break
			}
			fmt.Fprintf(&b, "      %-30s %10s %s  %8s\n",
				safeText(g.Prefix), commas(g.Leaves), plural(g.Leaves, "leaf", "leaves"), humanBytes(g.Bytes))
		}
	}
	return b.String()
}

// safeText renders a string taken from the envelope — a directory prefix or an
// attestor's type — that is about to be interpolated into a LOG LINE and an
// error message.
//
// THE STRINGS ARE UNTRUSTED. Paths come from a walk of the working directory
// and attestor types from the predicate collection; in a supply-chain tool
// both are data an attacker may influence, and a value containing a newline
// would let that attacker forge whole log records — an "archivista upload
// succeeded" line, a fake verdict — inside our own output. Carriage returns
// and ANSI escapes are the same class of problem against a terminal. The
// existing product-attestor advice already treats build-output paths this way
// (plugins/attestors/product/maxproducts.go, shellSafePath).
//
// Quoting is an ALLOWLIST decision, not a blocklist: anything that is not a
// printable, non-quote rune sends the whole value through strconv.Quote,
// which escapes control characters instead of emitting them and reads
// unambiguously as data rather than as something to paste.
func safeText(p string) string {
	for _, r := range p {
		if !unicode.IsPrint(r) || r == '"' || r == '\\' {
			return strconv.Quote(p)
		}
	}
	return p
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// sharePct renders a share without ever printing a misleading "0.0%" for a
// contributor that is genuinely present.
func sharePct(n, total int) string {
	if total <= 0 {
		return "-"
	}
	p := float64(n) * 100 / float64(total)
	if p < 0.1 && p > 0 {
		return fmt.Sprintf("%.2f%%", p)
	}
	return fmt.Sprintf("%.1f%%", p)
}

// commas groups a byte or leaf count for a human reader. The machine-readable
// `bytes=` fields in the retry logs are deliberately left ungrouped; tooling
// parses those.
func commas(n int) string {
	s := strconv.Itoa(n)
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	var parts []string
	for len(s) > 3 {
		parts = append([]string{s[len(s)-3:]}, parts...)
		s = s[:len(s)-3]
	}
	parts = append([]string{s}, parts...)
	out := strings.Join(parts, ",")
	if neg {
		return "-" + out
	}
	return out
}

// sizeAdviceSuffix is sizeAdvice as a trailing fragment for an error format
// string, or "" when the size is unremarkable.
//
// It is a SUFFIX rather than a wrapper on purpose: the budget errors carry two
// %w verbs (the ErrRetryBudgetExhausted sentinel callers match with errors.Is,
// and the underlying attempt error), and rebuilding those messages as flat
// strings to attach advice would silently break every caller's sentinel check.
// Appending text cannot disturb an error chain.
func sizeAdviceSuffix(size int, body []byte) string {
	advice := sizeAdviceMeasured(size, body)
	if advice == "" {
		return ""
	}
	return "\n  " + advice
}

// decorateWithSizeAdvice appends sizeAdvice to a plain message. Used where
// there is no error chain to preserve.
func decorateWithSizeAdvice(msg string, size int, body []byte) string {
	return msg + sizeAdviceSuffix(size, body)
}
