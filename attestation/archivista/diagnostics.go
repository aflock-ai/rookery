// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package archivista

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

// TokenSummary describes a bearer token for a log line without revealing it:
// a short fingerprint (first 8 hex of sha256) and, for a JWT, the unverified
// iat, exp and kid. It never includes any part of the token itself, so the
// fingerprint cannot be used to reconstruct it.
func TokenSummary(token string) string {
	if token == "" {
		return "none"
	}
	out := "fp=" + tokenFingerprint(token)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return out
	}
	var header struct {
		Kid string `json:"kid"`
	}
	var claims struct {
		Iat json.Number `json:"iat"`
		Exp json.Number `json:"exp"`
	}
	if decodeSegment(parts[0], &header) == nil {
		out += " kid=" + sanitizeLogValue(header.Kid)
	}
	if decodeSegment(parts[1], &claims) == nil {
		out += " iat=" + unixTime(claims.Iat) + " exp=" + unixTime(claims.Exp)
	}
	return out
}

func tokenFingerprint(token string) string {
	if token == "" {
		return "none"
	}
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:4])
}

func decodeSegment(seg string, dst any) error {
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	return dec.Decode(dst)
}

func unixTime(n json.Number) string {
	secs, err := n.Int64()
	if err != nil {
		return "unknown"
	}
	return time.Unix(secs, 0).UTC().Format(time.RFC3339)
}

func sanitizeLogValue(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > 64 {
		s = s[:64]
	}
	return s
}

// responseDiagnostics renders the response headers that identify which server
// answered and why it refused: WWW-Authenticate plus any request-id, pod,
// trace or served-by header, in a stable order.
func responseDiagnostics(h http.Header) string {
	var pairs []string
	for name, values := range h {
		lower := strings.ToLower(name)
		if lower == "www-authenticate" || strings.Contains(lower, "request-id") || strings.Contains(lower, "pod") ||
			strings.Contains(lower, "trace") || strings.Contains(lower, "served-by") {
			pairs = append(pairs, fmt.Sprintf("%s=%q", http.CanonicalHeaderKey(name), sanitizeLogValue(strings.Join(values, ","))))
		}
	}
	sort.Strings(pairs)
	return strings.Join(pairs, " ")
}

func bearerOf(req *http.Request) string {
	return strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
}
