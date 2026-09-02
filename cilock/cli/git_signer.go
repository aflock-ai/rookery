// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cli

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha1" //nolint:gosec // GnuPG status protocol requires the legacy certificate fingerprint shape.
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
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	attestationtimestamp "github.com/aflock-ai/rookery/attestation/timestamp"
	"github.com/aflock-ai/rookery/cilock/internal/auth"
	platformconfig "github.com/aflock-ai/rookery/cilock/internal/config"
	fulciosigner "github.com/aflock-ai/rookery/plugins/signers/fulcio"
	"github.com/digitorus/pkcs7"
)

const (
	maxGitSignInput = 16 << 20
	gitStatusFDFlag = "--status-fd"
)

var oidAttributeTimeStampToken = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14}

// gitSignerPlatformURL resolves the platform this Git signature is exchanged
// against — agent store first, then the env override, then the active login,
// then "" for the compiled default (judge#8738).
//
// Before this, the env var was the ONLY input: unset, it meant the compiled
// default, so a machine whose agent was enrolled anywhere else looked up the
// agent at the wrong platform, found nothing, and fell through to the human
// session — a valid signature naming the wrong principal, which this file's
// own precedence comment calls a false attestation nobody notices. Resolution
// now refuses the two states that used to produce that: an env override
// naming a platform with no agent while agents are enrolled elsewhere, and
// multiple enrolled agents with no selector.
func gitSignerPlatformURL(envURL string) (string, error) {
	enrolled, err := auth.EnrolledAgentPlatforms()
	if err != nil {
		// Fail closed: an unreadable agent store must not demote the
		// signature to the human session (same rule as ResolveSigningToken).
		return "", fmt.Errorf("read the enrolled agent store: %w", err)
	}
	if envURL != "" {
		norm := auth.NormalizeURL(envURL)
		for _, u := range enrolled {
			if u == norm {
				return norm, nil
			}
		}
		if len(enrolled) > 0 {
			return "", fmt.Errorf("%s names %s, but this machine's enrolled agent principal is at %s; "+
				"unset it or point it at the enrolled platform, or `cilock agent logout` before signing as anything else",
				platformconfig.PlatformURLEnv, norm, strings.Join(enrolled, ", "))
		}
		return envURL, nil
	}
	switch len(enrolled) {
	case 0:
		return auth.ActivePlatformURL(), nil
	case 1:
		return enrolled[0], nil
	default:
		return "", fmt.Errorf("multiple agent principals are enrolled (%s); set %s to select the platform this signature targets",
			strings.Join(enrolled, ", "), platformconfig.PlatformURLEnv)
	}
}

// resolveGitSignerPlatform is the one place the signer decides which platform
// it targets: agent-first URL resolution, the derived endpoints, and the
// cleartext refusal, together so RunGitSigner has a single failure branch.
func resolveGitSignerPlatform() (platformconfig.PlatformConfig, error) {
	platformURL, err := gitSignerPlatformURL(os.Getenv(platformconfig.PlatformURLEnv))
	if err != nil {
		return platformconfig.PlatformConfig{}, err
	}
	pc := platformconfig.Derive(platformURL)
	if err := platformconfig.RequireSecurePlatformURL(pc.PlatformURL); err != nil {
		return platformconfig.PlatformConfig{}, err
	}
	return pc, nil
}

var (
	resolveGitSigningToken = auth.ResolveSigningToken
	loadGitSigningSigner   = func(ctx context.Context, fulcioURL, token string) (cryptoutil.Signer, error) {
		return fulciosigner.New(
			fulciosigner.WithFulcioURL(fulcioURL),
			fulciosigner.WithToken(token),
			fulciosigner.WithUseHTTP(true),
		).Signer(ctx)
	}
	addGitSignatureTimestamp = func(ctx context.Context, signed *pkcs7.SignedData, tsaURL string) error {
		data := signed.GetSignedData()
		if len(data.SignerInfos) != 1 {
			return fmt.Errorf("git CMS envelope has %d signers, want 1", len(data.SignerInfos))
		}
		token, err := attestationtimestamp.NewTimestamper(
			attestationtimestamp.TimestampWithUrl(tsaURL),
		).Timestamp(ctx, bytes.NewReader(data.SignerInfos[0].EncryptedDigest))
		if err != nil {
			return err
		}
		if _, err := pkcs7.Parse(token); err != nil {
			return fmt.Errorf("parse timestamp token: %w", err)
		}

		// RFC 3161 signature timestamps are CMS unsigned attributes whose value is
		// the complete TimeStampToken ContentInfo. This uses the same existing
		// pkcs7 hook and shape as digitorus/pdfsign commit e377c1fb's signing path:
		// https://github.com/digitorus/pdfsign/blob/e377c1fb1583580227b36a690511ea17d9c77de0/sign/pdfsignature.go
		return data.SignerInfos[0].SetUnauthenticatedAttributes([]pkcs7.Attribute{{
			Type:  oidAttributeTimeStampToken,
			Value: asn1.RawValue{FullBytes: token},
		}})
	}
)

type gitSignerArgs struct {
	statusFD int
	input    string
	sign     bool
	detached bool
	armor    bool
}

// IsGitSignerInvocation recognizes only the machine protocol Git sends to its
// configured gpg.x509.program. It deliberately requires --status-fd plus a
// signing flag, so ordinary CI/lock arguments continue through Cobra.
func IsGitSignerInvocation(args []string) bool {
	hasStatus, hasSign := false, false
	for _, arg := range args {
		hasStatus = hasStatus || strings.HasPrefix(arg, gitStatusFDFlag+"=") || arg == gitStatusFDFlag
		hasSign = hasSign || arg == "--sign" || arg == "--detach-sign" ||
			(strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") && strings.Contains(strings.TrimPrefix(arg, "-"), "s"))
	}
	return hasStatus && hasSign
}

// RunGitSigner implements the GPG-compatible signing operation used by
// `git commit -S` when `gpg.format=x509` and `gpg.x509.program=cilock`.
//
// The CMS wire shape follows gitsign v0.17.1: detached SignedData, the leaf and
// intermediate certificates, PEM armor named "SIGNED MESSAGE", and an RFC 3161
// mandatory RFC 3161 unsigned timestamp attribute. CI/lock composes its existing
// Fulcio, PKCS#7, and TSA primitives, avoiding gitsign's otherwise-unused cloud
// provider and transparency-log dependency graph. See the Apache-2.0 upstream
// implementation at internal/signature/sign.go:
// https://github.com/sigstore/gitsign/blob/44f5e17fac6944fdde71c94d2e77ab075c9dca9f/internal/signature/sign.go
//
// The small status protocol emitted below is independently implemented from
// the GnuPG protocol; its compatibility values are cross-checked against
// gitsign v0.17.1's Apache-2.0 implementation at internal/gpg/status.go:
// https://github.com/sigstore/gitsign/blob/44f5e17fac6944fdde71c94d2e77ab075c9dca9f/internal/gpg/status.go
func RunGitSigner(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	inv, err := parseGitSignerArgs(args)
	if err != nil {
		return err
	}
	data, err := readGitSignInput(inv.input, stdin)
	if err != nil {
		return err
	}

	pc, err := resolveGitSignerPlatform()
	if err != nil {
		return err
	}
	identity, err := resolveGitSigningToken(pc.PlatformURL, pc.OIDCClientID)
	if err != nil {
		return err
	}
	signer, err := loadGitSigningSigner(ctx, pc.Fulcio, identity.Token)
	if err != nil {
		return fmt.Errorf("create keyless Git signer: %w", err)
	}
	bundler, ok := signer.(cryptoutil.TrustBundler)
	if !ok {
		return errors.New("fulcio Git signer did not expose its certificate chain")
	}
	cryptoSigner, ok := signer.(interface{ CryptoSigner() crypto.Signer })
	if !ok || cryptoSigner.CryptoSigner() == nil {
		return errors.New("fulcio Git signer did not expose its in-memory signing capability")
	}
	signed, err := pkcs7.NewSignedData(data)
	if err != nil {
		return fmt.Errorf("create Git CMS envelope: %w", err)
	}
	signed.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	if err := signed.AddSignerChain(
		bundler.Certificate(),
		cryptoSigner.CryptoSigner(),
		bundler.Intermediates(),
		pkcs7.SignerInfoConfig{},
	); err != nil {
		return fmt.Errorf("sign Git CMS envelope: %w", err)
	}
	signed.Detach()

	if err := addGitSignatureTimestamp(ctx, signed, pc.TSA); err != nil {
		return fmt.Errorf("timestamp Git signature: %w", err)
	}
	der, err := signed.Finish()
	if err != nil {
		return fmt.Errorf("serialize timestamped Git signature: %w", err)
	}
	if err := emitGitSigningStatus(inv.statusFD, stderr, bundler.Certificate()); err != nil {
		return err
	}
	if _, err := stdout.Write(pem.EncodeToMemory(&pem.Block{Type: "SIGNED MESSAGE", Bytes: der})); err != nil {
		return fmt.Errorf("write Git signature: %w", err)
	}
	return nil
}

func parseGitSignerArgs(args []string) (gitSignerArgs, error) {
	inv := gitSignerArgs{statusFD: -1}
	for i := 0; i < len(args); i++ {
		next, err := parseGitSignerArg(args, i, &inv)
		if err != nil {
			return inv, err
		}
		i = next
	}
	if inv.statusFD < 0 || !inv.sign || !inv.detached || !inv.armor {
		return inv, errors.New("git signing requires --status-fd with detached armored signing")
	}
	return inv, nil
}

func parseGitSignerArg(args []string, current int, inv *gitSignerArgs) (int, error) {
	arg := args[current]
	switch {
	case strings.HasPrefix(arg, gitStatusFDFlag+"="):
		fd, err := strconv.Atoi(strings.TrimPrefix(arg, gitStatusFDFlag+"="))
		if err != nil || fd < 0 {
			return current, fmt.Errorf("invalid %s value", gitStatusFDFlag)
		}
		inv.statusFD = fd
	case arg == gitStatusFDFlag:
		fd, next, err := parseGitStatusFD(args, current)
		if err != nil {
			return current, err
		}
		inv.statusFD = fd
		return next, nil
	case arg == "--sign":
		inv.sign = true
	case arg == "--detach-sign":
		inv.sign, inv.detached = true, true
	case arg == "--armor":
		inv.armor = true
	case strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--"):
		return parseShortGitSignerFlags(args, current, inv)
	default:
		if inv.input != "" {
			return current, errors.New("git signing accepts at most one input file")
		}
		inv.input = arg
	}
	return current, nil
}

func parseGitStatusFD(args []string, current int) (int, int, error) {
	next := current + 1
	if next >= len(args) {
		return 0, current, fmt.Errorf("%s requires a value", gitStatusFDFlag)
	}
	fd, err := strconv.Atoi(args[next]) //nolint:gosec // next is explicitly bounds-checked above.
	if err != nil || fd < 0 {
		return 0, current, fmt.Errorf("invalid %s value", gitStatusFDFlag)
	}
	return fd, next, nil
}

func parseShortGitSignerFlags(args []string, current int, inv *gitSignerArgs) (int, error) {
	for _, flag := range strings.TrimPrefix(args[current], "-") {
		switch flag {
		case 'b':
			inv.detached = true
		case 's':
			inv.sign = true
		case 'a':
			inv.armor = true
		case 'u':
			current++
			if current >= len(args) {
				return current, errors.New("-u requires a signing identity")
			}
		default:
			return current, fmt.Errorf("unsupported Git signing flag -%c", flag)
		}
	}
	return current, nil
}

func readGitSignInput(path string, stdin io.Reader) ([]byte, error) {
	reader := stdin
	var file *os.File
	if path != "" && path != "-" {
		var err error
		file, err = os.Open(path) //nolint:gosec // Git supplies the message file path.
		if err != nil {
			return nil, fmt.Errorf("open Git signing input: %w", err)
		}
		defer file.Close() //nolint:errcheck // read-only best-effort cleanup
		reader = file
	}
	raw, err := io.ReadAll(io.LimitReader(reader, maxGitSignInput+1))
	if err != nil {
		return nil, fmt.Errorf("read Git signing input: %w", err)
	}
	if len(raw) > maxGitSignInput {
		return nil, fmt.Errorf("git signing input exceeds %d bytes", maxGitSignInput)
	}
	return raw, nil
}

func emitGitSigningStatus(statusFD int, stderr io.Writer, cert *x509.Certificate) error {
	if statusFD < 0 {
		return nil
	}
	w := stderr
	if statusFD != 2 {
		if f := os.NewFile(uintptr(statusFD), "git-sign-status"); f != nil {
			w = f
		}
	}
	fingerprint := sha1.Sum(cert.Raw) //nolint:gosec // GnuPG status protocol fingerprint, not a security decision.
	pkAlgorithm := 19                 // RFC 4880 ECDSA, matching gitsign's ephemeral P-256 key.
	hashAlgorithm := hashAlgorithmID(cert.SignatureAlgorithm)
	if _, err := fmt.Fprintln(w, "[GNUPG:] BEGIN_SIGNING"); err != nil {
		return fmt.Errorf("write Git signing status: %w", err)
	}
	if _, err := fmt.Fprintf(w, "[GNUPG:] SIG_CREATED D %d %d 00 %d %s\n",
		pkAlgorithm, hashAlgorithm, time.Now().Unix(), hex.EncodeToString(fingerprint[:])); err != nil {
		return fmt.Errorf("write Git signing result: %w", err)
	}
	return nil
}

func hashAlgorithmID(algorithm x509.SignatureAlgorithm) int {
	switch algorithm {
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384:
		return 9 // RFC 4880 Hash Algorithm ID for SHA-384.
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512:
		return 10 // RFC 4880 Hash Algorithm ID for SHA-512.
	default:
		return 8 // RFC 4880 Hash Algorithm ID for SHA-256.
	}
}
