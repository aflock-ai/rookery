// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package auth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aflock-ai/rookery/cilock/internal/config"
)

// agentExchangePath is the platform endpoint that trades an enrolled agent's
// long-lived refresh credential for a short-lived OIDC token the platform's
// embedded Fulcio trusts. Two-token model: the refresh credential is presented
// here and nowhere else; only the returned token ever reaches Fulcio.
const agentExchangePath = "/api/agent/credential-exchange"

// AgentSigningIdentity is a successful exchange: the short-lived signing token
// plus the SPIFFE ID the platform says this token signs under. The SPIFFE ID is
// what the run summary names as the acting principal, so it is read from the
// server's answer rather than reconstructed from the stored UUIDs.
type AgentSigningIdentity struct {
	Token     string
	TokenType string
	SPIFFEID  string
	// UploadToken is the bearer the platform hands the agent for Archivista,
	// so the evidence it signs reaches the platform under its own identity.
	// Empty when the platform minted none (an older platform, or one with no
	// PKI): the run then has no upload authority and must say so rather than
	// sign into the void. Never stored — re-minted on every exchange.
	UploadToken string
	// TrustDomain is the authority segment of SPIFFEID, already parsed and
	// already validated by the checks below.
	//
	// It is returned rather than left for the caller to re-derive because a
	// second derivation of one identity is exactly how two readings drift — and
	// here the caller needs it for a specific reason: an unpinned credential is
	// pinned from the FIRST exchange, and every later exchange in the same run
	// must be held to that same answer. A caller re-parsing the string would be
	// a second grammar to keep in step with this one.
	TrustDomain string
}

const (
	// spiffeScheme is the only URI scheme an agent principal is named under.
	// Stored WITHOUT the "://" so it can be compared against url.URL.Scheme,
	// which is the parsed component rather than a textual prefix of the whole
	// string.
	spiffeScheme = "spiffe"

	segmentTenant = "tenant"
	segmentAgent  = "agent"

	// agentPathSegments is the segment count of an agent path split on "/"
	// WITHOUT trimming separators first: the empty string before the leading
	// slash, then tenant, <tenant-id>, agent, <agent-id>.
	//
	// Counting the leading empty segment is what makes a stray separator a
	// refusal rather than something quietly normalized away. SPIFFE IDs compare
	// as strings, so "//tenant/<t>/agent/<a>" is a DIFFERENT identity from the
	// canonical spelling, not a typo to clean up.
	agentPathSegments = 5

	// maxSPIFFEIDBytes is the SPIFFE specification's ceiling on a whole ID. It
	// matches jade/factory/admission/certverify deliberately: this client and
	// that verifier must agree on what an id IS, or one signs what the other
	// refuses.
	maxSPIFFEIDBytes = 2048
)

// agentExchangeClient is the HTTP client the exchange uses. A package var so a
// test can shorten its timeout; production takes the 30s default.
//
// REDIRECTS ARE REFUSED, and that is a credential-confidentiality control
// rather than strictness for its own sake. This request's body carries the
// long-lived refresh credential, and RFC 9110 requires 307/308 to preserve the
// method and body — so a redirect hands the secret to whatever host the
// `Location` header names, including a cleartext one. The platform this talks
// to has no reason to redirect a POST, so refusing costs nothing real and
// closes an exfiltration path that a compromised or misconfigured hop could
// otherwise open without the operator seeing anything.
var agentExchangeClient = &http.Client{
	Timeout: 30 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		// ONLY THE SCHEME AND HOST ARE NAMED, never the full URL.
		//
		// url.URL.Redacted() is not sufficient here: it masks USERINFO and leaves
		// the query string intact, and the whole Location header is chosen by the
		// server. A broken or hostile endpoint can answer
		// `Location: https://elsewhere/?credential=<the secret>` and the "helpful"
		// error would put the bearer in a terminal and a log — the same accident
		// the refusal-body redaction exists to stop, arriving through the one
		// field that is server-controlled before any response body is read.
		//
		// Scheme and host are what an operator actually needs (WHERE was this
		// being sent), and they cannot carry a query.
		return fmt.Errorf(
			"refusing to follow a redirect to %s://%s: the agent credential exchange sends a "+
				"long-lived secret in its request body and will not forward it to another location",
			req.URL.Scheme, req.URL.Host)
	},
}

// redactedError renders an error with the refresh credential removed.
//
// EVERY error this package returns for an agent exchange passes through here,
// because every one of them can carry server-controlled text. The refusal body
// was the obvious path and was closed first; it was not the only one. A
// successful HTTP 200 can put the credential in `spiffe_id`, or in a JWT `sub`,
// and the mismatch errors quote both verbatim in order to be diagnosable. A
// redirect can put it in `Location`. Redacting at each site means the next error
// message someone adds is a new leak, so it is redacted at the boundary instead.
//
// THERE IS DELIBERATELY NO Unwrap. Unwrap would hand a caller the unredacted
// error, and `errors.Unwrap(err).Error()` would reintroduce exactly what this
// type exists to prevent. Nothing in this package returns a sentinel that a
// caller matches on, so nothing is lost today. If a sentinel is ever needed,
// carry it as a typed field on this struct and match that — do not add Unwrap.
type redactedError struct {
	text string
	// rejected is set when the PLATFORM answered and refused the credential
	// (a 401/403), as opposed to the request not completing or the answer
	// failing our own checks. Callers that decide whether a stored credential
	// is worth keeping key on this, never on the text.
	rejected bool
}

func (e *redactedError) Error() string { return e.text }

// agentRejectedError marks an exchange the platform examined and refused.
type agentRejectedError struct{ err error }

func (e *agentRejectedError) Error() string { return e.err.Error() }
func (e *agentRejectedError) Unwrap() error { return e.err }

// IsAgentCredentialRejected reports whether err is the platform's own refusal
// of the presented credential — the one outcome after which retrying with the
// same credential cannot succeed. A network failure, a 5xx, a response that
// failed our checks, or a locally-expired credential are NOT this: the
// credential may still be good and must not be discarded on their account.
func IsAgentCredentialRejected(err error) bool {
	var r *redactedError
	return errors.As(err, &r) && r.rejected
}

// ExchangeAgentCredential trades a stored agent credential for a short-lived
// signing token at <platformURL>/api/agent/credential-exchange.
//
// Refusals are uniform by design on the platform side — one identical status and
// body for an unknown credential, a foreign tenant, a revoked principal, and an
// unknown agent — so this function reports the server's message verbatim and
// makes no guess about which case occurred. Guessing client-side would hand an
// attacker the oracle the uniform response exists to deny.
//
// Every failure is an error. There is no degraded return: a caller on a signing
// path must fail the run rather than continue to another identity.
func ExchangeAgentCredential(platformURL string, cred AgentCredential) (AgentSigningIdentity, error) {
	id, err := exchangeAgentCredential(platformURL, cred)
	if err != nil {
		// THE SINGLE CHOKE POINT. Everything below can quote server-controlled
		// text — a refusal body, a redirect target, `spiffe_id`, a JWT `sub` — and
		// each of those is a place the refresh credential can come back at us. One
		// wrapper here is what makes that structural rather than a rule each new
		// error message has to remember.
		var rejected *agentRejectedError
		return AgentSigningIdentity{}, &redactedError{
			text:     redactCredential(err.Error(), cred),
			rejected: errors.As(err, &rejected),
		}
	}
	return id, nil
}

func exchangeAgentCredential(platformURL string, cred AgentCredential) (AgentSigningIdentity, error) {
	// Never attach the refresh credential over cleartext to a non-loopback host
	// (#5997). It is a long-lived bearer that mints signing certificates.
	if err := config.RequireSecurePlatformURL(platformURL); err != nil {
		return AgentSigningIdentity{}, err
	}
	// A credential past the ceiling it recorded is not presented at all. The
	// platform would refuse it anyway — this saves the round trip and, more to
	// the point, replaces the uniform "not accepted" with the one cause this
	// machine can actually name. Only a RECORDED ceiling counts: zero means the
	// platform is the sole authority, and it answers for itself.
	if now := time.Now(); cred.Expired(now) {
		return AgentSigningIdentity{}, fmt.Errorf("the agent principal %s expired at %s (%s ago); its authority was time-bound at enrollment and cannot be extended — run `cilock enroll agent` for a new ceremony",
			cred.AgentID, cred.ExpiresAt.Format(time.RFC3339), now.Sub(cred.ExpiresAt).Round(time.Second))
	}
	out, err := postAgentExchange(platformURL, cred)
	if err != nil {
		return AgentSigningIdentity{}, err
	}
	if out.Token == "" {
		return AgentSigningIdentity{}, fmt.Errorf("agent credential-exchange response carried no token")
	}
	// The SPIFFE ID is required, not decorative: it is the only thing that names
	// the principal in the run summary, and an agent run whose principal cannot
	// be named is exactly the ambiguity this whole path removes. A response
	// without a well-formed one is a refusal, not a partial success.
	if err := checkSPIFFEIDNamesCredential(out.SPIFFEID, cred); err != nil {
		return AgentSigningIdentity{}, err
	}
	if err := checkTokenSubjectNamesPrincipal(out.Token, out.SPIFFEID); err != nil {
		return AgentSigningIdentity{}, err
	}

	// PIN THE TRUST DOMAIN ON FIRST USE, and only after every other check has
	// passed — pinning a value from a response we were about to reject would
	// record the attacker's authority as the expected one.
	//
	// A pin failure does not fail the run. The exchange has already been
	// authorised and the identity already verified against everything this
	// machine knows; refusing to sign because a config file could not be written
	// would trade a real capability for a bookkeeping error. The consequence of
	// the miss is bounded and self-correcting: the next successful exchange tries
	// again.
	//
	// The parse cannot fail here: checkSPIFFEIDNamesCredential above ran the same
	// grammar and returned nil. It is re-run rather than threaded through because
	// the alternative is a second return path carrying a value that only matters
	// on one branch; an error here would mean the two calls disagreed, which is a
	// bug and not a runtime condition, so it refuses rather than guessing.
	td, _, _, err := parseAgentSPIFFEID(out.SPIFFEID)
	if err != nil {
		return AgentSigningIdentity{}, fmt.Errorf("internal: the validated principal %q did not re-parse: %w", out.SPIFFEID, err)
	}
	// RECORD THE AUTHORITATIVE CEILING. The enrollment callback's expires_at
	// travelled in the clear across the loopback; the platform's answer here
	// did not, and it is the copy the platform actually enforces. Every
	// successful exchange overwrites the local copy with it, so what
	// `agent status` reports and what the local pre-check refuses on is the
	// platform's number. Absent (an older platform) leaves the local copy as
	// it was; unparsable is a refusal, because a ceiling we cannot read is not
	// one we can enforce.
	if err := recordAnsweredExpiry(cred, out.ExpiresAt); err != nil {
		return AgentSigningIdentity{}, err
	}
	if cred.TrustDomain == "" {
		// THE PIN FAILING IS A REFUSAL, not a logged inconvenience.
		//
		// Discarding this error left two holes. A store that cannot be written
		// means the pin never lands, so the next run is unpinned too and the
		// protection silently never engages — nobody learns that the control they
		// believe in is inert. And a CONCURRENT first-use exchange that already
		// pinned a different authority is reported here as a mismatch; signing
		// after ignoring that is exactly the outcome the pin exists to prevent.
		if err := PinAgentTrustDomain(cred, td); err != nil {
			return AgentSigningIdentity{}, fmt.Errorf("recording the agent trust domain: %w", err)
		}
	}
	return AgentSigningIdentity{
		Token: out.Token, TokenType: out.TokenType, SPIFFEID: out.SPIFFEID, TrustDomain: td,
		UploadToken: out.UploadToken,
	}, nil
}

// agentExchangeAnswer is the platform's success body, before any of it is
// trusted.
type agentExchangeAnswer struct {
	Token           string `json:"token"`
	TokenType       string `json:"token_type"`
	SPIFFEID        string `json:"spiffe_id"`
	ExpiresAt       string `json:"expires_at"`
	UploadToken     string `json:"upload_token"`
	UploadTokenType string `json:"upload_token_type"`
}

// postAgentExchange performs the HTTP half of the exchange: build, send,
// classify the status, decode. Everything about whether the ANSWER is
// acceptable stays in exchangeAgentCredential.
func postAgentExchange(platformURL string, cred AgentCredential) (agentExchangeAnswer, error) {
	endpoint := strings.TrimRight(NormalizeURL(platformURL), "/") + agentExchangePath

	body, err := json.Marshal(map[string]string{
		"tenant_id":          cred.TenantID,
		"agent_id":           cred.AgentID,
		"refresh_credential": cred.RefreshCredential,
	})
	if err != nil {
		return agentExchangeAnswer{}, fmt.Errorf("build agent credential-exchange request: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return agentExchangeAnswer{}, fmt.Errorf("build agent credential-exchange request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := agentExchangeClient.Do(req)
	if err != nil {
		// The URL is safe to name; the request body is not, so it is never wrapped
		// into an error. net/http keeps the URL out of the error it returns for a
		// POST body, and there is no credential in the query string.
		return agentExchangeAnswer{}, fmt.Errorf("agent credential exchange at %s: %w", endpoint, err)
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort cleanup

	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024)) //nolint:errcheck // diagnostic only
		err := fmt.Errorf(
			"agent credential exchange refused by %s (HTTP %d): %s\n%s",
			endpoint, resp.StatusCode, redactCredential(strings.TrimSpace(string(msg)), cred),
			agentRefusalDiagnosis(platformURL, cred))
		// Only the platform's own examined refusal is a REJECTION: a 401 or
		// 403 whose body is the constant verdict the exchange endpoint writes
		// ({"error":"agent_credential_rejected", …}). A 5xx is the platform
		// failing to answer; a 401/403 with any other body is an ingress, a
		// WAF, or an unrelated authorization layer that never examined the
		// credential — and a credential is not discarded because a proxy was
		// misconfigured, any more than because the signer was down.
		if isPlatformCredentialVerdict(resp.StatusCode, msg) {
			return agentExchangeAnswer{}, &agentRejectedError{err: err}
		}
		return agentExchangeAnswer{}, err
	}

	var out agentExchangeAnswer
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return agentExchangeAnswer{}, fmt.Errorf("decode agent credential-exchange response: %w", err)
	}
	return out, nil
}

// agentRejectedVerdict is the `error` the exchange endpoint answers
// with when it examined the credential and refused it (judge-api
// handlers_agent_exchange.go: agentExchangeRefusal). One constant string for
// every cause, by design; the point here is only that the PLATFORM wrote it.
const agentRejectedVerdict = "agent_credential_rejected"

// isPlatformCredentialVerdict reports whether a non-200 answer is the
// platform's own refusal of the credential: the status the endpoint uses AND
// the structured body it writes. Either alone is not enough — the status is
// what every proxy speaks, and the body on a 200 is not a refusal.
func isPlatformCredentialVerdict(status int, body []byte) bool {
	if status != http.StatusUnauthorized && status != http.StatusForbidden {
		return false
	}
	var verdict struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &verdict); err != nil {
		return false
	}
	return verdict.Error == agentRejectedVerdict
}

// recordAnsweredExpiry stores the platform's expires_at from an exchange
// response. Empty (an older platform) is a no-op; unreadable is a refusal.
func recordAnsweredExpiry(cred AgentCredential, raw string) error {
	if raw == "" {
		return nil
	}
	ceiling, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return fmt.Errorf("the platform answered with an unreadable expires_at: %w", err)
	}
	if err := RecordAgentExpiry(cred, ceiling); err != nil {
		return fmt.Errorf("recording the agent's expiry: %w", err)
	}
	return nil
}

// checkSPIFFEIDNamesCredential requires the returned principal to be THE ONE
// THIS CREDENTIAL ENROLLS, not merely something SPIFFE-shaped.
//
// A prefix check accepts any `spiffe://…` string, so a server that answered
// with a different tenant or agent — through a bug, a misroute, or a hostile
// response — would have cilock sign under one principal while the run summary,
// which reads this field, names another. That is precisely the identity
// confusion the agent path exists to remove, arriving from the other end: the
// summary would be truthfully reporting a value that does not describe the
// signature.
//
// The credential's own tenant and agent ids are the authority here. They are
// local, they are what was sent, and they are what the operator enrolled — so
// the response is checked against them rather than the other way round.
//
// THE MATCH IS AN EXACT CANONICAL PARSE, NOT prefix+suffix. Substring anchoring
// on both ends leaves the MIDDLE unconstrained, and the middle is where the
// principal actually lives. Three shapes slip past a `HasPrefix`/`HasSuffix`
// pair while naming something other than the enrolled agent:
//
//	spiffe://td/extra/tenant/<t>/agent/<a>   extra leading segments — a
//	                                         DIFFERENT SPIFFE path, so a
//	                                         different principal
//	spiffe:///tenant/<t>/agent/<a>           empty trust domain; the authority
//	                                         that vouches for the name is
//	                                         missing entirely
//	spiffe://user:pw@td/tenant/<t>/agent/<a> userinfo, which SPIFFE forbids and
//	                                         which makes the effective host
//	                                         ambiguous to a naive reader
//
// So the whole URI is parsed and every component is pinned: scheme, a non-empty
// trust domain carrying no userinfo and no port, no query or fragment, and a
// path of exactly four segments in the canonical order.
//
// SEGMENTS ARE COMPARED AFTER INDIVIDUAL UNESCAPING, never by matching the
// decoded path as one string. `url.Parse` decodes `%2F` to `/`, so
// `spiffe://td/tenant/<t>%2Fagent%2F<a>/agent/x` has a decoded `Path` that
// reads exactly like the canonical form while being a different name — one
// principal's id wearing another's namespace. Splitting the ESCAPED path and
// unescaping each segment on its own keeps a separator that was escaped from
// ever becoming a separator.
//
// This is a NECESSARY condition, not a sufficient one: it binds the response to
// the request. The certificate's SAN is what finally binds the signature to the
// principal, and the platform is what binds the principal to the credential.
func checkSPIFFEIDNamesCredential(id string, cred AgentCredential) error {
	refuse := func(why string) error {
		return fmt.Errorf(
			"agent credential-exchange returned principal %q, which is not the enrolled "+
				"tenant %s / agent %s (%s); cilock will not sign as a principal it did not "+
				"present a credential for", id, cred.TenantID, cred.AgentID, why)
	}

	gotTD, gotTenant, gotAgent, err := parseAgentSPIFFEID(id)
	if err != nil {
		return refuse(err.Error())
	}
	if gotTenant != cred.TenantID || gotAgent != cred.AgentID {
		return refuse("it names a different tenant or agent")
	}
	// THE TRUST DOMAIN IS PART OF THE IDENTITY, and it is the part the operator
	// never supplied — so without this comparison it was entirely the server's
	// choice. `spiffe://someone-elses-factory/tenant/<mine>/agent/<mine>` passes
	// a tenant-and-agent check while naming a principal in a namespace this
	// operator never enrolled in, and the run summary would report it as the
	// enrolled agent. Two thirds of a SPIFFE ID is not the identity.
	//
	// An empty pin means the credential predates pinning or has not completed a
	// first exchange; the caller records the answer then. Once recorded, a
	// change is a refusal and never a re-pin — see PinAgentTrustDomain.
	if cred.TrustDomain != "" && gotTD != cred.TrustDomain {
		return refuse(fmt.Sprintf("it names the trust domain %q, but this agent is enrolled under %q", gotTD, cred.TrustDomain))
	}
	return nil
}

// parseAgentSPIFFEID takes an agent SPIFFE ID apart into its tenant and agent
// ids, or explains why it is not one.
//
// Split out from checkSPIFFEIDNamesCredential so the GRAMMAR and the COMPARISON
// are separate functions: this one decides whether the string is a well-formed
// agent principal at all, and the caller decides whether it is the RIGHT one.
// The errors are bare reasons rather than sentences, because the caller is what
// knows the ids to name in the message.
func parseAgentSPIFFEID(id string) (trustDomain, tenant, agent string, err error) {
	u, err := url.Parse(id)
	if err != nil {
		return "", "", "", errors.New("it is not a parseable URI")
	}

	// THE PARSE MUST BE LOSSLESS, and this is checked against the RAW BYTES
	// rather than against the parsed fields, because the parsed fields are
	// exactly what the loss removes.
	//
	// Enumerating decorations one at a time only closes the ones net/url
	// bothered to REMEMBER. A bare trailing "?" is remembered (ForceQuery), so a
	// check on it works. A bare trailing "#" is NOT: measured, ".../agent/a#"
	// yields Fragment=="", RawFragment=="" and ForceQuery==false — byte-identical
	// to an id carrying no fragment at all — while String() silently drops the
	// "#". No predicate over the parsed struct can separate those two inputs,
	// because by then they ARE the same value.
	//
	// WHY THAT MATTERS HERE AND NOT IN jade's certverify: this id arrives as a
	// STRING in the platform's exchange response, so the original bytes still
	// exist at this point and a mismatch is detectable. In certverify the id
	// arrives as a *url.URL out of cert.URIs, where crypto/x509 has already
	// normalized it — verified by crafting the SAN into DER by hand: the "#" is
	// gone before that package is entered, so the value it validates and the
	// value it reports are the same string and there is nothing to exploit.
	//
	// A SPIFFE ID is compared as a STRING (SPIFFE-ID spec §2). So an id we
	// accept under one spelling and then hand back under another is two
	// principals sharing one name: the pin, the tenant/agent comparison and the
	// run summary would all read the canonical form while the platform's own
	// record holds the decorated one. Requiring the round trip closes that whole
	// class at once instead of naming its members.
	if canonical := u.String(); canonical != id {
		return "", "", "", fmt.Errorf(
			"it is not canonical: it parses to %q, which is not the string it was given", canonical)
	}

	if err := checkSPIFFEURIShape(u); err != nil {
		return "", "", "", err
	}
	// SPIFFE caps an ID at 2048 bytes. Enforced here as well as in jade's
	// certverify because these are two parses of ONE grammar, and a limit
	// present in only one of them is precisely the drift the shared ontology
	// exists to prevent — the verifier would refuse an id this client had
	// already signed under.
	if n := len(id); n > maxSPIFFEIDBytes {
		return "", "", "", fmt.Errorf("it is %d bytes; a SPIFFE ID is at most %d", n, maxSPIFFEIDBytes)
	}

	// EscapedPath, not Path: see the note above on %2F.
	//
	// A rooted path splits to a leading "" — "/tenant/t/agent/a" gives
	// ["", "tenant", "t", "agent", "a"]. Anything else is not the canonical
	// shape, which is what makes an extra leading segment a refusal.
	segments := strings.Split(u.EscapedPath(), "/")
	if len(segments) != agentPathSegments || segments[0] != "" ||
		segments[1] != segmentTenant || segments[3] != segmentAgent {
		return "", "", "", errors.New("its path is not exactly /tenant/<tenant-id>/agent/<agent-id>")
	}

	// PERCENT-ENCODING IS REFUSED OUTRIGHT rather than decoded and compared.
	//
	// Decoding first makes `/tenant/%31.../agent/<a>` compare EQUAL to
	// `/tenant/1.../agent/<a>` — but those are two different strings, and SPIFFE
	// IDs compare as strings, so they are two different principals. Accepting the
	// encoded spelling means signing under an id that a policy pinned to the
	// canonical one would not match, while the run summary claims the enrolled
	// agent. The ids this exchange deals in are UUIDs; none of them needs an
	// escape, so refusing costs nothing real and removes the second spelling
	// entirely.
	for what, seg := range map[string]string{"tenant id": segments[2], "agent id": segments[4]} {
		if err := requireUnescapedSegment(what, seg); err != nil {
			return "", "", "", err
		}
	}
	return u.Hostname(), segments[2], segments[4], nil
}

// requireUnescapedSegment holds a path segment to an ALLOWLIST of
// [A-Za-z0-9._-] — which contains no "%", so a segment that passes carries no
// percent-encoding and its escaped and decoded spellings are the same bytes.
//
// An allowlist and not a denylist: once a value sits inside a SPIFFE path, "@"
// is an authority delimiter, ":" starts a port, and "%2F" becomes a separator
// the moment anything decodes the URI. There is no safe list of dangerous
// bytes, only a list of allowed ones. The dot segments are excluded because a
// normalizer can collapse them into a different path entirely.
func requireUnescapedSegment(what, segment string) error {
	if segment == "" {
		return fmt.Errorf("its %s segment is empty", what)
	}
	if segment == "." || segment == ".." {
		return fmt.Errorf("its %s segment is a dot segment", what)
	}
	for i := 0; i < len(segment); i++ {
		c := segment[i]
		if ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || ('0' <= c && c <= '9') ||
			c == '.' || c == '_' || c == '-' {
			continue
		}
		return fmt.Errorf("its %s segment contains %q, which a SPIFFE path segment may not", what, string(c))
	}
	return nil
}

// checkSPIFFEURIShape holds the non-path components of a SPIFFE ID to the one
// shape the specification allows: a scheme, an authority that is a bare host,
// and nothing else.
//
// Each rejected component is a place a second reading of the same string can
// hide. Userinfo and a port change what a reader takes the authority to be; a
// query or fragment carries text that some readers keep and others drop; an
// opaque URI (spiffe:tenant/x) has no authority at all, so its "path" lands in
// URL.Opaque where the segment checks would never look at it — an absence that
// would otherwise read as a pass.
func checkSPIFFEURIShape(u *url.URL) error {
	switch {
	case u.Scheme != spiffeScheme:
		return errors.New("its scheme is not spiffe")
	case u.Opaque != "":
		return errors.New("it carries no // authority, so it names no trust domain")
	case u.User != nil:
		return errors.New("it carries userinfo, which a SPIFFE ID must not")
	case u.RawQuery != "" || u.ForceQuery || u.Fragment != "":
		return errors.New("it carries a query or fragment, which a SPIFFE ID must not")
	case u.Hostname() == "":
		return errors.New("its trust domain is empty")
	// THE RAW AUTHORITY MUST BE THE TRUST DOMAIN EXACTLY, rather than merely
	// PARSING to it. Hostname() is lossy by design: it strips a port and it also
	// strips a TRAILING COLON, so "spiffe://td:/..." yields Port() == "" and
	// Hostname() == "td" and would sail past a `Port() != ""` check while being a
	// different string — and SPIFFE IDs compare as strings.
	//
	// Comparing Host against Hostname() closes the whole class (port, empty port,
	// any other authority decoration) instead of naming decorations one at a
	// time, which is precisely what let the empty port through. Found by review on
	// the sibling parse in jade/factory/admission/certverify; fixed here in the
	// same round because it is the same mechanism, not a nearby line.
	case u.Host != u.Hostname():
		return errors.New("its authority is not a bare trust domain (it carries a port or other decoration)")
	}
	return nil
}

// agentRefusalDiagnosis states what cilock can establish about a refused
// exchange FROM LOCAL STATE ALONE, so an operator whose agent legitimately
// cannot sign has somewhere to look.
//
// The server answers every refusal identically — unknown credential, foreign
// tenant, revoked principal, unknown agent — because a distinguishable answer
// is an oracle for probing which tenants and agents exist. This function does
// not weaken that: it reads the response neither for its status nor for its
// body, and takes no argument derived from either, so the text it produces is
// byte-identical for every refusal the platform can return. Everything in it
// comes from the platform URL cilock resolved and the credential cilock holds.
//
// The tenant and agent ids are printed because they are SPIFFE path segments
// and are not secret. The refresh credential is never printed — a helpful
// diagnostic block is exactly where a bearer gets leaked.
func agentRefusalDiagnosis(platformURL string, cred AgentCredential) string {
	normalized := NormalizeURL(platformURL)
	configured := "no — nothing is enrolled under that exact URL"
	if stored, err := LookupAgent(normalized); err == nil && stored != nil {
		configured = "yes"
	}
	var b strings.Builder
	b.WriteString("  cilock cannot tell which refusal this is — the platform answers them all identically.\n")
	b.WriteString("  What it can confirm on this machine:\n")
	_, _ = fmt.Fprintf(&b, "    platform URL (normalized):        %s\n", normalized)
	_, _ = fmt.Fprintf(&b, "    agent credential stored for it:   %s\n", configured)
	_, _ = fmt.Fprintf(&b, "    tenant_id presented:              %s\n", cred.TenantID)
	_, _ = fmt.Fprintf(&b, "    agent_id presented:               %s\n", cred.AgentID)
	b.WriteString("  Check that the platform URL and the two ids match the enrollment. Revocation is\n")
	b.WriteString("  checked server-side at every exchange, so a credential that worked before and\n")
	b.WriteString("  fails now may have been revoked — re-enroll to replace it.")
	return b.String()
}

// checkTokenSubjectNamesPrincipal requires the token that will be handed to
// Fulcio to name the SAME principal the response reports and the summary will
// print.
//
// checkSPIFFEIDNamesCredential binds the response to the REQUEST; this binds
// the response to the ARTIFACT that actually decides the certificate. Without
// it a response can carry the enrolled agent's id in `spiffe_id` and a token
// whose subject is a human email — cilock would install that token, Fulcio
// would mint a leaf with the HUMAN's identity, and the run summary would state
// the agent signed. Truthful reporting of a value that does not describe the
// signature is precisely the confusion the agent path exists to remove, so it
// fails closed here rather than being discovered in the evidence later.
//
// THIS IS NOT SIGNATURE VERIFICATION AND MUST NOT BE READ AS ANY. The token is
// unverified here; Fulcio verifies it against the platform's OIDC key, which is
// what makes the token authoritative at all. What this checks is INTERNAL
// CONSISTENCY of a response before cilock acts on it — that the two fields
// describe one principal. A response that lies in both fields identically is
// still refused upstream, because `spiffe_id` was already required to match the
// enrolled credential's own tenant and agent ids.
//
// Fulcio's SPIFFE issuer type derives the certificate's URI SAN from the
// token's `sub`, so a token whose `sub` is the enrolled principal is what makes
// the eventual SAN the enrolled principal.
func checkTokenSubjectNamesPrincipal(token, spiffeID string) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("agent credential-exchange returned a token that is not a JWT; cilock will not sign with a token it cannot attribute")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("agent credential-exchange token payload is not base64url: %w", err)
	}
	var claims struct {
		Subject string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return fmt.Errorf("agent credential-exchange token payload is not JSON: %w", err)
	}
	if claims.Subject != spiffeID {
		return fmt.Errorf(
			"agent credential-exchange returned a token for principal %q while naming %q; "+
				"cilock will not sign with a token whose subject is not the principal it reports",
			claims.Subject, spiffeID)
	}
	return nil
}

// redactCredential removes the refresh credential from any text the SERVER
// produced before that text reaches an error, a log line, or a terminal.
//
// The exchange reports the server's refusal verbatim, which is deliberate — the
// platform's message is the only thing that tells an operator what happened, and
// guessing client-side would hand an attacker the oracle the uniform response
// exists to deny. But "verbatim" must not mean "unfiltered": the request body
// carries a long-lived bearer, and an endpoint that is broken, misconfigured, or
// hostile can echo its input back in an error. That echo would then be printed
// and logged by the very code trying to be helpful, turning one bad response
// into a durable credential disclosure.
//
// WHAT THIS DOES NOT DO, stated plainly so nobody reads it as a boundary: it
// removes LITERAL occurrences. A hostile server that base64s, reverses, or
// chunks the credential defeats it, and no client-side filter can win that game
// against arbitrary encoding. The realistic failure this closes is the common
// one — a handler that reflects its request body into an error message. Treat it
// as hygiene on a trusted-but-fallible peer, not as a defence against a server
// that is actively trying to exfiltrate; a server in that position already holds
// the credential it was sent.
func redactCredential(text string, cred AgentCredential) string {
	secret := cred.RefreshCredential
	if secret == "" {
		return text
	}
	const marker = "[refresh credential redacted]"
	text = strings.ReplaceAll(text, secret, marker)

	// THE CREDENTIAL DOES NOT GO ONTO THE WIRE AS ITSELF, so matching only the
	// literal is matching the one form a reflecting server never sees.
	//
	// The request is JSON, and encoding/json rewrites the value on the way out:
	// quotes and backslashes structurally, control characters numerically, and
	// by default "<", ">" and "&" into <, >, &. A handler that
	// echoes what it received therefore hands back the ESCAPED spelling, which a
	// literal ReplaceAll walks straight past on its way into a terminal and a log.
	//
	// WHY THIS IS NOT AN OPEN-ENDED DENYLIST, since enumerating encodings usually
	// is one. The boundary is "every form THIS CLIENT PRODUCES", and it produces
	// exactly one: json.Marshal into the request body. A server that returns the
	// secret base64'd or percent-encoded is not reflecting our bytes, it is
	// transforming them — and a server doing that already holds the credential we
	// just sent it, so redaction was never what stood between it and the secret.
	// Redaction defends against an ACCIDENT reaching a log, and the accident has
	// one spelling.
	//
	// Derived from the same encoder the request uses rather than hand-written, so
	// it cannot drift from what is actually sent.
	if quoted, err := json.Marshal(secret); err == nil && len(quoted) >= 2 {
		// Drop the surrounding quotes json.Marshal adds; what appears inside a
		// reflected body is the escaped CONTENT, not a standalone JSON string.
		if wire := string(quoted[1 : len(quoted)-1]); wire != secret {
			text = strings.ReplaceAll(text, wire, marker)
		}
	}
	return text
}
