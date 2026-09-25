// Copyright 2026 The Aflock Authors
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

package cryptoutil

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Certificate Transparency for the certificate path (#10032).
//
// Sigstore client spec §4.3: "Unless performing online verification, the
// Verifier MUST extract the SignedCertificateTimestamp embedded in the leaf
// certificate, and verify it." X509Verifier.Verify enforces that here:
//
//   - A leaf whose verified chain passes through a CT trust root's CA must
//     carry an embedded SCT that verifies against one of that root's logs.
//   - A leaf that embeds an SCT list must have at least one SCT that verifies
//     against a known log, whatever CA issued it. An SCT list nobody can check
//     is refused, never ignored.
//   - A leaf with no SCT whose CA is not a CT trust root verifies as before.
//     This is the platform CA's case, by construction: the platform Fulcio is
//     built with a nil CT log client (judge-api pkg/fulcioca/fulcio.go,
//     server.NewGRPCCAServer(nil, ...)), so it never logs and its leaves carry
//     no SCT. It is "not CT-logged" because it is absent from CTTrustRoots,
//     and a platform leaf that ever DID embed an SCT would be refused above.
//
// The Sigstore public-good trust root is always a CT trust root. It comes from
// the TUF-distributed trusted_root.json compiled into this package (see
// sigstore_public_good_trusted_root.json). Callers add others with
// WithCTTrustRoots.
//
// The SCT check follows RFC 6962 §3.2 for precertificate entries, the same
// construction sigstore-go's verify.VerifySignedCertificateTimestamp performs
// through certificate-transparency-go's ctutil.VerifySCT. It is written on the
// standard library because this module is imported by ~77 others; pulling
// certificate-transparency-go into every one of them costs more than the ~150
// lines below.

// oidSCTList is the RFC 6962 embedded SCT list extension.
var oidSCTList = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

// ErrSCTVerification is returned when a leaf's Certificate Transparency
// evidence is missing, malformed, or does not verify against a trusted log.
var ErrSCTVerification = errors.New("certificate transparency: embedded SCT did not verify")

// CTLog is a Certificate Transparency log a verifier trusts. The log ID is
// derived from the key (SHA-256 of its SubjectPublicKeyInfo), never taken
// from configuration.
type CTLog struct {
	URL        string
	PublicKey  crypto.PublicKey
	ValidFrom  time.Time // zero: no lower bound
	ValidUntil time.Time // zero: no upper bound
	id         [sha256.Size]byte
}

// NewCTLog builds a CTLog from its public key and validity window.
func NewCTLog(url string, pub crypto.PublicKey, validFrom, validUntil time.Time) (CTLog, error) {
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return CTLog{}, fmt.Errorf("ct log %q: %w", url, err)
	}
	return CTLog{URL: url, PublicKey: pub, ValidFrom: validFrom, ValidUntil: validUntil, id: sha256.Sum256(spki)}, nil
}

// CTTrustRoot names a CA that logs every certificate it issues, and the CT
// logs whose SCTs it embeds. A leaf whose chain passes through any cert in CAs
// (matched by public key) must carry a valid SCT from one of Logs.
type CTTrustRoot struct {
	Name string
	CAs  []*x509.Certificate
	Logs []CTLog
}

// X509VerifierOption configures an X509Verifier.
type X509VerifierOption func(*X509Verifier)

// WithCTTrustRoots adds CT trust roots to the always-present Sigstore
// public-good root.
func WithCTTrustRoots(roots ...CTTrustRoot) X509VerifierOption {
	return func(v *X509Verifier) {
		v.ctRoots = append(v.ctRoots, roots...)
	}
}

//go:embed sigstore_public_good_trusted_root.json
var publicGoodTrustedRootJSON []byte

var publicGoodCTRoots = sync.OnceValues(func() ([]CTTrustRoot, error) {
	return parseSigstoreTrustedRoot("sigstore-public-good", publicGoodTrustedRootJSON)
})

// PublicGoodCTTrustRoots returns the Sigstore public-good Fulcio CAs and CT
// logs compiled into this package.
func PublicGoodCTTrustRoots() ([]CTTrustRoot, error) {
	return publicGoodCTRoots()
}

// sigstoreTrustedRoot is the subset of dev.sigstore.trustroot.v1.TrustedRoot
// (protobuf JSON) this package reads.
type sigstoreTrustedRoot struct {
	CertificateAuthorities []struct {
		CertChain struct {
			Certificates []struct {
				RawBytes string `json:"rawBytes"`
			} `json:"certificates"`
		} `json:"certChain"`
	} `json:"certificateAuthorities"`
	CTLogs []struct {
		BaseURL string `json:"baseUrl"`
		LogID   struct {
			KeyID string `json:"keyId"`
		} `json:"logId"`
		PublicKey struct {
			RawBytes string `json:"rawBytes"`
			ValidFor struct {
				Start *time.Time `json:"start"`
				End   *time.Time `json:"end"`
			} `json:"validFor"`
		} `json:"publicKey"`
	} `json:"ctlogs"`
}

func parseSigstoreTrustedRoot(name string, raw []byte) ([]CTTrustRoot, error) {
	var tr sigstoreTrustedRoot
	if err := json.Unmarshal(raw, &tr); err != nil {
		return nil, fmt.Errorf("trusted root %s: %w", name, err)
	}
	root := CTTrustRoot{Name: name}
	for _, ca := range tr.CertificateAuthorities {
		for _, c := range ca.CertChain.Certificates {
			cert, err := parseBase64Certificate(c.RawBytes)
			if err != nil {
				return nil, fmt.Errorf("trusted root %s: CA certificate: %w", name, err)
			}
			root.CAs = append(root.CAs, cert)
		}
	}
	for _, l := range tr.CTLogs {
		log, err := parseTrustedRootCTLog(l.BaseURL, l.LogID.KeyID, l.PublicKey.RawBytes, l.PublicKey.ValidFor.Start, l.PublicKey.ValidFor.End)
		if err != nil {
			return nil, fmt.Errorf("trusted root %s: %w", name, err)
		}
		root.Logs = append(root.Logs, log)
	}
	if len(root.CAs) == 0 || len(root.Logs) == 0 {
		return nil, fmt.Errorf("trusted root %s: needs at least one CA and one CT log", name)
	}
	return []CTTrustRoot{root}, nil
}

func parseBase64Certificate(b64 string) (*x509.Certificate, error) {
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func parseTrustedRootCTLog(url, keyID, rawKey string, start, end *time.Time) (CTLog, error) {
	der, err := base64.StdEncoding.DecodeString(rawKey)
	if err != nil {
		return CTLog{}, fmt.Errorf("ct log %s: %w", url, err)
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return CTLog{}, fmt.Errorf("ct log %s: %w", url, err)
	}
	var from, until time.Time
	if start != nil {
		from = *start
	}
	if end != nil {
		until = *end
	}
	log, err := NewCTLog(url, pub, from, until)
	if err != nil {
		return CTLog{}, err
	}
	declared, err := base64.StdEncoding.DecodeString(keyID)
	if err != nil || !bytes.Equal(declared, log.id[:]) {
		return CTLog{}, fmt.Errorf("ct log %s: declared log ID does not match its key", url)
	}
	return log, nil
}

// ctTrustRoots is the public-good root plus any configured roots. The
// embedded root failing to load is an error, never an empty trust set.
func (v *X509Verifier) ctTrustRoots() ([]CTTrustRoot, error) {
	publicGood, err := PublicGoodCTTrustRoots()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSCTVerification, err)
	}
	return append(append([]CTTrustRoot{}, publicGood...), v.ctRoots...), nil
}

// ctRootsCovering returns the CT trust roots whose CAs appear (by public key)
// in any of chains, past the leaf.
func ctRootsCovering(roots []CTTrustRoot, chains [][]*x509.Certificate) []CTTrustRoot {
	var out []CTTrustRoot
	for _, r := range roots {
		if rootCoversChains(r, chains) {
			out = append(out, r)
		}
	}
	return out
}

func ctRootsCover(roots []CTTrustRoot, chains [][]*x509.Certificate) bool {
	return len(ctRootsCovering(roots, chains)) > 0
}

func rootCoversChains(r CTTrustRoot, chains [][]*x509.Certificate) bool {
	for _, chain := range chains {
		for _, c := range chain[1:] {
			for _, ca := range r.CAs {
				if bytes.Equal(c.RawSubjectPublicKeyInfo, ca.RawSubjectPublicKeyInfo) {
					return true
				}
			}
		}
	}
	return false
}

// checkCertificateTransparency applies the rules at the top of this file to a
// leaf and the chains x509 verification built for it.
func checkCertificateTransparency(leaf *x509.Certificate, chains [][]*x509.Certificate, roots []CTTrustRoot) error {
	scts, hasSCTs, err := embeddedSCTs(leaf)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSCTVerification, err)
	}
	required := ctRootsCovering(roots, chains)
	if len(required) == 0 && !hasSCTs {
		return nil
	}
	if !hasSCTs {
		return fmt.Errorf("%w: leaf %q is issued by CT-logging CA %q but embeds no SCT", ErrSCTVerification, leaf.Subject.String(), required[0].Name)
	}
	logsFrom := required
	if len(logsFrom) == 0 {
		logsFrom = roots
	}
	var logs []CTLog
	for _, r := range logsFrom {
		logs = append(logs, r.Logs...)
	}
	tbs, err := precertTBS(leaf)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSCTVerification, err)
	}
	lastErr := errors.New("no SCT from a trusted log")
	for _, chain := range chains {
		if len(chain) < 2 {
			continue
		}
		issuerKeyHash := sha256.Sum256(chain[1].RawSubjectPublicKeyInfo)
		for _, raw := range scts {
			if err := verifySCT(raw, issuerKeyHash, tbs, logs); err != nil {
				lastErr = err
				continue
			}
			return nil
		}
	}
	return fmt.Errorf("%w: leaf %q: %v", ErrSCTVerification, leaf.Subject.String(), lastErr)
}

// embeddedSCTs returns the serialized SCTs in the leaf's SCT list extension,
// and whether the extension is present at all.
func embeddedSCTs(leaf *x509.Certificate) ([][]byte, bool, error) {
	var ext []byte
	found := false
	for _, e := range leaf.Extensions {
		if !e.Id.Equal(oidSCTList) {
			continue
		}
		if found {
			return nil, true, errors.New("duplicate SCT list extension")
		}
		found = true
		ext = e.Value
	}
	if !found {
		return nil, false, nil
	}
	var list []byte
	if rest, err := asn1.Unmarshal(ext, &list); err != nil || len(rest) != 0 {
		return nil, true, errors.New("SCT list extension is not a single OCTET STRING")
	}
	body, rest, ok := readU16Prefixed(list)
	if !ok || len(rest) != 0 {
		return nil, true, errors.New("malformed SCT list")
	}
	var scts [][]byte
	for len(body) > 0 {
		var sct []byte
		sct, body, ok = readU16Prefixed(body)
		if !ok || len(sct) == 0 {
			return nil, true, errors.New("malformed SCT list entry")
		}
		scts = append(scts, sct)
	}
	if len(scts) == 0 {
		return nil, true, errors.New("empty SCT list")
	}
	return scts, true, nil
}

func readU16Prefixed(b []byte) ([]byte, []byte, bool) {
	if len(b) < 2 {
		return nil, nil, false
	}
	n := int(binary.BigEndian.Uint16(b))
	if len(b)-2 < n {
		return nil, nil, false
	}
	return b[2 : 2+n], b[2+n:], true
}

// sct is a parsed v1 SignedCertificateTimestamp (RFC 6962 §3.2).
type sct struct {
	logID      [sha256.Size]byte
	timestamp  []byte // 8 bytes, big endian milliseconds, as signed
	millis     uint64
	extensions []byte
	hashAlg    byte
	sigAlg     byte
	signature  []byte
}

func parseSCT(raw []byte) (sct, error) {
	const fixed = 1 + sha256.Size + 8
	var out sct
	if len(raw) < fixed || raw[0] != 0 {
		return out, errors.New("SCT is not a v1 SCT")
	}
	copy(out.logID[:], raw[1:1+sha256.Size])
	out.timestamp = raw[1+sha256.Size : fixed]
	out.millis = binary.BigEndian.Uint64(out.timestamp)
	exts, rest, ok := readU16Prefixed(raw[fixed:])
	if !ok || len(rest) < 2 {
		return out, errors.New("malformed SCT")
	}
	out.extensions = exts
	out.hashAlg, out.sigAlg = rest[0], rest[1]
	out.signature, rest, ok = readU16Prefixed(rest[2:])
	if !ok || len(rest) != 0 {
		return out, errors.New("malformed SCT signature")
	}
	return out, nil
}

func findCTLog(logs []CTLog, id [sha256.Size]byte) (*CTLog, error) {
	for i := range logs {
		if logs[i].id == id {
			return &logs[i], nil
		}
	}
	return nil, fmt.Errorf("SCT log ID %x is not a trusted log", id[:])
}

func (l *CTLog) checkWindow(millis uint64) error {
	if millis > uint64(1)<<62 {
		return errors.New("SCT timestamp out of range")
	}
	ts := time.UnixMilli(int64(millis)) //nolint:gosec // bounded above
	if !l.ValidFrom.IsZero() && ts.Before(l.ValidFrom) {
		return fmt.Errorf("SCT from %s at %s predates the log key's validity", l.URL, ts.UTC().Format(time.RFC3339))
	}
	if !l.ValidUntil.IsZero() && ts.After(l.ValidUntil) {
		return fmt.Errorf("SCT from %s at %s is after the log key's validity", l.URL, ts.UTC().Format(time.RFC3339))
	}
	return nil
}

// signedData is the digitally-signed struct for a precert_entry.
func (s sct) signedData(issuerKeyHash [sha256.Size]byte, tbs []byte) ([]byte, error) {
	if len(tbs) >= 1<<24 || len(s.extensions) >= 1<<16 {
		return nil, errors.New("SCT signed data too large")
	}
	var b bytes.Buffer
	b.WriteByte(0) // sct_version v1
	b.WriteByte(0) // signature_type certificate_timestamp
	b.Write(s.timestamp)
	b.Write([]byte{0, 1}) // entry_type precert_entry
	b.Write(issuerKeyHash[:])
	tbsLen := binary.BigEndian.AppendUint32(nil, uint32(len(tbs))) //nolint:gosec // bounded above
	b.Write(tbsLen[1:])                                            // uint24 length
	b.Write(tbs)
	_ = binary.Write(&b, binary.BigEndian, uint16(len(s.extensions))) //nolint:gosec // bounded above
	b.Write(s.extensions)
	return b.Bytes(), nil
}

// verifySCT checks one serialized v1 SCT over a precertificate entry against
// the given logs (RFC 6962 §3.2).
func verifySCT(raw []byte, issuerKeyHash [sha256.Size]byte, tbs []byte, logs []CTLog) error {
	parsed, err := parseSCT(raw)
	if err != nil {
		return err
	}
	log, err := findCTLog(logs, parsed.logID)
	if err != nil {
		return err
	}
	if err := log.checkWindow(parsed.millis); err != nil {
		return err
	}
	signed, err := parsed.signedData(issuerKeyHash, tbs)
	if err != nil {
		return err
	}
	if parsed.hashAlg != 4 { // sha256
		return fmt.Errorf("SCT hash algorithm %d is not SHA-256", parsed.hashAlg)
	}
	digest := sha256.Sum256(signed)
	switch pub := log.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if parsed.sigAlg != 3 || !ecdsa.VerifyASN1(pub, digest[:], parsed.signature) {
			return fmt.Errorf("SCT signature from %s does not verify", log.URL)
		}
	case *rsa.PublicKey:
		if parsed.sigAlg != 1 || rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], parsed.signature) != nil {
			return fmt.Errorf("SCT signature from %s does not verify", log.URL)
		}
	default:
		return fmt.Errorf("ct log %s has unsupported key type %T", log.URL, log.PublicKey)
	}
	return nil
}

// precertTBS rebuilds the TBSCertificate the log signed: the leaf's
// TBSCertificate with the SCT list extension removed and every other byte
// preserved.
func precertTBS(leaf *x509.Certificate) ([]byte, error) {
	var tbs asn1.RawValue
	if rest, err := asn1.Unmarshal(leaf.RawTBSCertificate, &tbs); err != nil || len(rest) != 0 {
		return nil, errors.New("malformed TBSCertificate")
	}
	var fields [][]byte
	removed := false
	for body := tbs.Bytes; len(body) > 0; {
		var field asn1.RawValue
		var err error
		body, err = asn1.Unmarshal(body, &field)
		if err != nil {
			return nil, errors.New("malformed TBSCertificate field")
		}
		if field.Class != asn1.ClassContextSpecific || field.Tag != 3 {
			fields = append(fields, field.FullBytes)
			continue
		}
		stripped, found, err := stripSCTExtension(field.Bytes)
		if err != nil {
			return nil, err
		}
		removed = removed || found
		if stripped != nil {
			fields = append(fields, stripped)
		}
	}
	if !removed {
		return nil, errors.New("leaf has no SCT list extension")
	}
	return asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: bytes.Join(fields, nil)})
}

// stripSCTExtension takes the content of the [3] extensions field and returns
// the re-encoded field without the SCT list extension, or nil when no other
// extension remains (an empty extensions field is omitted, not encoded).
func stripSCTExtension(explicit []byte) ([]byte, bool, error) {
	var extSeq asn1.RawValue
	if rest, err := asn1.Unmarshal(explicit, &extSeq); err != nil || len(rest) != 0 {
		return nil, false, errors.New("malformed extensions")
	}
	var kept []byte
	found := false
	for exts := extSeq.Bytes; len(exts) > 0; {
		var ext asn1.RawValue
		var err error
		exts, err = asn1.Unmarshal(exts, &ext)
		if err != nil {
			return nil, false, errors.New("malformed extension")
		}
		var oid asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(ext.Bytes, &oid); err != nil {
			return nil, false, errors.New("malformed extension OID")
		}
		if oid.Equal(oidSCTList) {
			found = true
			continue
		}
		kept = append(kept, ext.FullBytes...)
	}
	if len(kept) == 0 {
		return nil, found, nil
	}
	seq, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: kept})
	if err != nil {
		return nil, false, err
	}
	wrapped, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 3, IsCompound: true, Bytes: seq})
	return wrapped, found, err
}
