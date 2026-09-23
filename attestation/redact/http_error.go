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

package redact

import (
	"errors"
	"net/url"
	"strings"
)

// HTTPError returns err, the error of an HTTP request to rawURL, in a form
// that holds no URL credential in its text or anywhere in its chain, so it is
// safe to print and to wrap. rawURL is "" when a client library chose the URL.
//
// net/http's *url.Error takes out only the password of the URL it names, and
// after a redirect it names the URL redirected to. The error it wraps is text
// taken from URLs too: url.Parse quotes the bytes it refused ("invalid port
// \":SECRET\" after host"), a redirect quotes a Location that does not parse
// ("failed to parse Location header \"http://ci:SECRET@host:bad/keys\""), and
// a dial names the host Go read, which where the parsers disagree is part of
// a userinfo ("http://127.0.0.1:1/x@host" is user "127.0.0.1" to Python's
// proxy parser).
//
// So the result names the URL by URLCredentials, and keeps the error net/http
// wraps only when it can name nothing the redacted URL does not: the request
// was not redirected, the error holds no at-sign and quotes no URL, and the
// URL holds no credential or Go dials the host the redacted URL still names.
// Otherwise it says only what kind of failure it was, and does not wrap the
// original. An error from a library that wraps the *url.Error is flattened to
// its text.
//
// Two errors keep nothing. url.Parse cuts off the fragment before it parses
// and quotes only what it parsed, so "http://user:pw#rest@proxy" fails as
// `parse "http://user:pw": invalid port ":pw" after host`: a username and the
// start of a password with no at-sign left to mark them. When the caller does
// not know the URL, nothing can say what the quoted text was cut from, so a
// parse error anywhere in the chain gives errURLParseWithheld; re-parsing the
// quoted text cannot recover what was cut. And an error that quotes a URL, or
// url.Parse's text, outside any *url.Error is of a kind this does not know,
// so it gives errURLTextWithheld whatever URL the caller knows.
func HTTPError(rawURL string, err error) error {
	if err == nil {
		return nil
	}
	if rawURL == "" && chainHasParseError(err) {
		return errURLParseWithheld
	}
	if quotesURLOutsideURLError(err) {
		return errURLTextWithheld
	}
	var urlErr *url.Error
	if !errors.As(err, &urlErr) {
		if URLCredentialsInText(err.Error()) != err.Error() {
			return errors.New(URLCredentialsInText(err.Error()))
		}
		return err
	}
	if rawURL == "" {
		rawURL = urlErr.URL
	}
	endpoint := URLCredentials(rawURL)
	safe := &url.Error{Op: urlErr.Op, URL: endpoint, Err: urlErr.Err}
	withheld := detailWithheld(rawURL, endpoint, urlErr)
	if withheld {
		safe.Err = errors.New(failureKind(urlErr) + " (the detail is withheld because it can quote a URL credential)")
	} else if safe.Error() == urlErr.Error() && URLCredentialsInText(err.Error()) == err.Error() {
		return err // it names nothing the redacted URL does not
	}
	if err == error(urlErr) {
		return safe
	}
	text := strings.ReplaceAll(err.Error(), urlErr.Error(), safe.Error())
	if !strings.Contains(text, safe.Error()) || withheld && strings.Contains(text, urlErr.Err.Error()) {
		text = safe.Error() // the library's text holds the detail some other way
	}
	return errors.New(URLCredentialsInText(text))
}

// opParse is the Op of the *url.Error url.Parse returns.
const opParse = "parse"

var (
	errURLParseWithheld = errors.New("request URL could not be parsed (withheld)")
	errURLTextWithheld  = errors.New("request failed; its error quotes a URL (withheld)")
)

// chainHasParseError reports whether err or any error it wraps, through
// Unwrap() error and Unwrap() []error alike, is a *url.Error from url.Parse.
func chainHasParseError(err error) bool {
	found := false
	eachInChain(err, func(e error) {
		if urlErr, ok := e.(*url.Error); ok && urlErr.Op == opParse {
			found = true
		}
	})
	return found
}

// quotesURLOutsideURLError reports whether the text of err, with the text of
// every *url.Error in its chain taken out, still quotes a URL.
func quotesURLOutsideURLError(err error) bool {
	text := err.Error()
	eachInChain(err, func(e error) {
		if urlErr, ok := e.(*url.Error); ok {
			text = strings.ReplaceAll(text, urlErr.Error(), "")
		}
	})
	return quotesURL(text)
}

// quotesURL reports whether text names a scheme:// URL or quotes url.Parse,
// which a scheme-less URL fails in as `parse "//...`.
func quotesURL(text string) bool {
	return strings.Contains(text, "://") || strings.Contains(text, `parse "`)
}

// eachInChain calls visit with err and each error it wraps, outermost first.
func eachInChain(err error, visit func(error)) {
	if err == nil {
		return
	}
	visit(err)
	switch e := err.(type) {
	case interface{ Unwrap() error }:
		eachInChain(e.Unwrap(), visit)
	case interface{ Unwrap() []error }:
		for _, inner := range e.Unwrap() {
			eachInChain(inner, visit)
		}
	}
}

// detailWithheld reports whether the error urlErr wraps, from a request to
// rawURL, can name what its redacted form endpoint does not: the request was
// redirected, the error holds an at-sign or quotes a URL, or the URL holds a
// credential and Go did not parse it or dials a host endpoint no longer names.
func detailWithheld(rawURL, endpoint string, urlErr *url.Error) bool {
	if detail := urlErr.Err.Error(); strings.Contains(detail, "@") || quotesURL(detail) {
		return true // the detail quotes a URL, which may be one cut short
	}
	if urlErr.URL != rawURL && URLCredentials(urlErr.URL) != endpoint {
		return true // redirected
	}
	return endpoint != rawURL && (urlErr.Op == opParse || !dialsNamedHost(rawURL, endpoint))
}

// failureKind says what kind of failure urlErr is, without its detail.
func failureKind(urlErr *url.Error) string {
	switch {
	case urlErr.Op == opParse:
		return "the URL does not parse"
	case urlErr.Timeout():
		return "the request timed out"
	}
	return "the request failed"
}

// dialsNamedHost reports whether Go dials, for rawURL, the host that its
// redacted form endpoint names.
func dialsNamedHost(rawURL, endpoint string) bool {
	dialed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	named, err := url.Parse(endpoint)
	return err == nil && named.Host != "" && named.Host == dialed.Host
}
