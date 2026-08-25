// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cli

import (
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // GnuPG compatibility fingerprint, not a trust decision.
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	attestationtimestamp "github.com/aflock-ai/rookery/attestation/timestamp"
	"github.com/aflock-ai/rookery/cilock/internal/auth"
	platformconfig "github.com/aflock-ai/rookery/cilock/internal/config"
	"github.com/digitorus/pkcs7"
)

const maxGitSignatureInput = 1 << 20

type gitVerifyArgs struct {
	statusFD      int
	signaturePath string
	contentPath   string
}

func IsGitVerifyInvocation(args []string) bool {
	hasStatus, hasVerify := false, false
	for _, arg := range args {
		hasStatus = hasStatus || strings.HasPrefix(arg, gitStatusFDFlag+"=") || arg == gitStatusFDFlag
		hasVerify = hasVerify || arg == "--verify" || arg == "-v"
	}
	return hasStatus && hasVerify
}

func RunGitProtocol(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if IsGitVerifyInvocation(args) {
		return RunGitVerifier(ctx, args, stdin, stdout, stderr)
	}
	return RunGitSigner(ctx, args, stdin, stdout, stderr)
}

// RunGitVerifier implements Git's gpg.x509.program verification protocol. Its
// argument and status compatibility is independently implemented against Git's
// documented GnuPG status protocol and cross-checked with the Apache-2.0 gitsign
// v0.17.1 adapter:
// https://github.com/sigstore/gitsign/blob/44f5e17fac6944fdde71c94d2e77ab075c9dca9f/internal/commands/root/verify.go
func RunGitVerifier(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	inv, err := parseGitVerifyArgs(args)
	if err != nil {
		return err
	}
	signature, err := readBoundedPath(inv.signaturePath, nil, maxGitSignatureInput)
	if err != nil {
		return fmt.Errorf("read Git signature: %w", err)
	}
	content, err := readBoundedPath(inv.contentPath, stdin, maxGitSignInput)
	if err != nil {
		return fmt.Errorf("read Git signed content: %w", err)
	}

	p7, cert, err := parseGitCMS(signature)
	if err != nil {
		return err
	}

	platformURL := platformconfig.Derive(os.Getenv(platformconfig.PlatformURLEnv)).PlatformURL
	fulcioRoots, tsaCerts, err := loadPinnedGitVerificationTrust(platformURL)
	if err != nil {
		return err
	}
	token, err := gitTimestampToken(p7)
	if err != nil {
		return err
	}
	verifiedAt, err := attestationtimestamp.NewVerifier(
		attestationtimestamp.VerifyWithCerts(tsaCerts),
	).Verify(ctx, bytes.NewReader(token), bytes.NewReader(p7.Signers[0].EncryptedDigest))
	if err != nil {
		return fmt.Errorf("verify mandatory Git signature timestamp: %w", err)
	}
	p7.Content = content
	intermediates := x509.NewCertPool()
	for _, candidate := range p7.Certificates {
		if !candidate.Equal(cert) {
			intermediates.AddCert(candidate)
		}
	}
	if err := p7.VerifyWithOpts(x509.VerifyOptions{
		Roots:         fulcioRoots,
		Intermediates: intermediates,
		CurrentTime:   verifiedAt,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}); err != nil {
		return fmt.Errorf("verify Git signature at trusted timestamp: %w", err)
	}
	return emitGitVerificationStatus(inv.statusFD, stdout, stderr, cert)
}

func parseGitCMS(signature []byte) (*pkcs7.PKCS7, *x509.Certificate, error) {
	block, rest := pem.Decode(signature)
	if block == nil || block.Type != "SIGNED MESSAGE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, nil, errors.New("git signature is not one closed PEM SIGNED MESSAGE")
	}
	p7, err := pkcs7.Parse(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse Git CMS signature: %w", err)
	}
	if len(p7.Signers) != 1 {
		return nil, nil, fmt.Errorf("git CMS signature has %d signers, want 1", len(p7.Signers))
	}
	cert := p7.GetOnlySigner()
	if cert == nil {
		return nil, nil, errors.New("git CMS signature has no unique signing certificate")
	}
	return p7, cert, nil
}

func parseGitVerifyArgs(args []string) (gitVerifyArgs, error) {
	inv := gitVerifyArgs{statusFD: -1}
	paths := make([]string, 0, 2)
	for i := 0; i < len(args); i++ {
		switch arg := args[i]; {
		case strings.HasPrefix(arg, gitStatusFDFlag+"="):
			fd, err := strconv.Atoi(strings.TrimPrefix(arg, gitStatusFDFlag+"="))
			if err != nil || fd < 0 {
				return inv, fmt.Errorf("invalid %s value", gitStatusFDFlag)
			}
			inv.statusFD = fd
		case arg == gitStatusFDFlag:
			fd, next, err := parseGitStatusFD(args, i)
			if err != nil {
				return inv, err
			}
			inv.statusFD, i = fd, next
		case arg == "--verify" || arg == "-v":
		default:
			paths = append(paths, arg)
		}
	}
	if inv.statusFD < 0 || len(paths) != 2 {
		return inv, errors.New("git verification requires --status-fd, a signature file, and signed content")
	}
	inv.signaturePath, inv.contentPath = paths[0], paths[1]
	return inv, nil
}

func readBoundedPath(path string, stdin io.Reader, limit int64) ([]byte, error) {
	reader := stdin
	var file *os.File
	if path != "-" {
		var err error
		file, err = os.Open(path) //nolint:gosec // Git supplies its temporary signature/content path.
		if err != nil {
			return nil, err
		}
		defer file.Close() //nolint:errcheck // read-only best-effort cleanup
		reader = file
	}
	if reader == nil {
		return nil, errors.New("standard input is unavailable")
	}
	raw, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("input exceeds %d bytes", limit)
	}
	return raw, nil
}

func loadPinnedGitVerificationTrust(platformURL string) (*x509.CertPool, []*x509.Certificate, error) {
	credential, err := auth.LookupAny(platformURL)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve platform trust pin: %w", err)
	}
	if credential == nil {
		return nil, nil, errors.New("git signature verification requires a CI/lock platform session; run 'cilock login'")
	}
	discovery, err := platformconfig.Discover(platformURL)
	if err != nil {
		return nil, nil, fmt.Errorf("discover platform signing trust: %w", err)
	}
	if discovery.Signing == nil || discovery.Signing.TrustBundlePEM == "" {
		return nil, nil, errors.New("platform discovery advertised no Fulcio trust bundle")
	}
	// Use the same discovery TOFU contract as ordinary `cilock verify`; never
	// adopt network-delivered Fulcio or TSA roots independently of the stored pin.
	// See VerifyOptions.applyDiscoveryTrust in internal/options/verify.go.
	sum := sha256.Sum256([]byte(discovery.Signing.TrustBundlePEM))
	pin := hex.EncodeToString(sum[:])
	switch {
	case credential.TrustBundleSPKI == "":
		persisted, err := auth.SetTrustBundleSPKI(platformURL, pin)
		if err != nil {
			return nil, nil, fmt.Errorf("pin platform signing trust: %w", err)
		}
		if !persisted {
			return nil, nil, errors.New("platform session cannot persist its signing trust pin")
		}
	case subtle.ConstantTimeCompare([]byte(credential.TrustBundleSPKI), []byte(pin)) != 1:
		return nil, nil, errors.New("platform signing trust changed; run 'cilock verify --trust-discovery' after validating the rotation")
	}
	fulcioCerts, _, err := splitPEMCertsBySelfSigned([]byte(discovery.Signing.TrustBundlePEM))
	if err != nil {
		return nil, nil, fmt.Errorf("parse platform Fulcio trust: %w", err)
	}
	if len(fulcioCerts) == 0 {
		return nil, nil, errors.New("platform Fulcio trust bundle has no self-signed root")
	}
	fulcioRoots := x509.NewCertPool()
	for _, cert := range fulcioCerts {
		fulcioRoots.AddCert(cert)
	}
	tsaPEM, err := platformconfig.FetchTSACertChain(platformURL, discovery)
	if err != nil {
		return nil, nil, fmt.Errorf("fetch platform TSA trust: %w", err)
	}
	tsaCerts, err := parsePEMCerts(tsaPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("parse platform TSA trust: %w", err)
	}
	return fulcioRoots, tsaCerts, nil
}

func gitTimestampToken(p7 *pkcs7.PKCS7) ([]byte, error) {
	if len(p7.Signers) != 1 {
		return nil, errors.New("git CMS signature must have exactly one signer")
	}
	var token []byte
	for _, attribute := range p7.Signers[0].UnauthenticatedAttributes {
		if !attribute.Type.Equal(oidAttributeTimeStampToken) {
			continue
		}
		if token != nil {
			return nil, errors.New("git CMS signature has multiple timestamp attributes")
		}
		var raw asn1.RawValue
		rest, err := asn1.Unmarshal(attribute.Value.Bytes, &raw)
		if err != nil || len(rest) != 0 || len(raw.FullBytes) == 0 {
			return nil, errors.New("git CMS timestamp attribute is malformed")
		}
		token = raw.FullBytes
	}
	if token == nil {
		return nil, errors.New("git CMS signature has no mandatory RFC 3161 timestamp")
	}
	return token, nil
}

func emitGitVerificationStatus(statusFD int, stdout, stderr io.Writer, cert *x509.Certificate) error {
	w := statusWriter(statusFD, stdout, stderr)
	fingerprint := sha1.Sum(cert.Raw) //nolint:gosec // GnuPG protocol identifier only.
	identity := cert.Subject.String()
	if len(cert.EmailAddresses) > 0 {
		identity = cert.EmailAddresses[0]
	} else if len(cert.URIs) > 0 {
		identity = cert.URIs[0].String()
	}
	identity = strings.ReplaceAll(identity, "%", "%25")
	identity = strings.ReplaceAll(identity, " ", "%20")
	fpr := hex.EncodeToString(fingerprint[:])
	if _, err := fmt.Fprintln(w, "[GNUPG:] NEWSIG"); err != nil {
		return fmt.Errorf("write Git verification status: %w", err)
	}
	if _, err := fmt.Fprintf(w, "[GNUPG:] GOODSIG %s %s\n", fpr, identity); err != nil {
		return fmt.Errorf("write Git verification result: %w", err)
	}
	if _, err := fmt.Fprintln(w, "[GNUPG:] TRUST_FULLY 0 chain"); err != nil {
		return fmt.Errorf("write Git trust result: %w", err)
	}
	return nil
}

func statusWriter(statusFD int, stdout, stderr io.Writer) io.Writer {
	switch statusFD {
	case 1:
		return stdout
	case 2:
		return stderr
	default:
		if statusFD >= 0 {
			if file := os.NewFile(uintptr(statusFD), "git-status"); file != nil {
				return file
			}
		}
		return stderr
	}
}
