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

package gitlab_review

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"time"
)

// maxPages bounds pagination; reaching it is an error, never a truncated
// list (a cap must not feed a count).
const maxPages = 1000

type client struct {
	base, token string
	http        *http.Client
}

func (c *client) do(path string) (int, http.Header, []byte, error) {
	if c.http == nil {
		c.http = &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse // never follow a redirect with the token
		}}
	}
	req, err := http.NewRequest(http.MethodGet, c.base+path, http.NoBody) //nolint:noctx // bounded by the client timeout
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("PRIVATE-TOKEN", c.token)
	resp, err := c.http.Do(req) //nolint:gosec // base is the operator's GitLab API root, https or loopback only
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close() //nolint:errcheck // best effort
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	return resp.StatusCode, resp.Header, body, err
}

// get reads one object into out (nil to only probe). It returns the status;
// err is a transport or decode failure of a 200.
func (c *client) get(path string, out any) (int, error) {
	st, _, body, err := c.do(path)
	if err != nil {
		return 0, err
	}
	if st == 200 && out != nil {
		if err := checkShape(body, out); err != nil {
			return st, fmt.Errorf("malformed body: %w", err)
		}
		if err := json.Unmarshal(body, out); err != nil {
			return st, fmt.Errorf("malformed body: %w", err)
		}
	}
	return st, nil
}

// shaped is a response type that declares the fields it records. A 200 that
// lacks one is missing evidence: decoding it would record a zero value (an
// empty rule list, a false setting, a note id of 0) as if GitLab had said so.
type shaped interface{ shape() shape }

// shape is what an object in a response must carry.
type shape struct {
	keys    []string         // present and non-null
	present []string         // present; null allowed (GitLab's null is a value)
	lists   map[string]shape // key (also in keys) -> the shape of each element
	check   func(map[string]json.RawMessage) error
}

var jsonNull = []byte("null")

func isNull(v json.RawMessage) bool { return bytes.Equal(bytes.TrimSpace(v), jsonNull) }

// checkShape refuses a null body, and a body (or, for a list, any element)
// that does not have the shape out declares.
func checkShape(body []byte, out any) error {
	if isNull(body) {
		return errors.New("the body is null")
	}
	if s, ok := out.(shaped); ok {
		return s.shape().validate(body)
	}
	t := reflect.TypeOf(out)
	if t.Kind() != reflect.Pointer || t.Elem().Kind() != reflect.Slice {
		return nil
	}
	s, ok := reflect.New(t.Elem().Elem()).Interface().(shaped)
	if !ok {
		return nil
	}
	return s.shape().validateList(body)
}

// positiveID refuses an id that is not a positive integer: GitLab ids start
// at 1, and a 0 recorded as an id would name no one.
func positiveID(v json.RawMessage) error {
	var id int64
	if err := json.Unmarshal(v, &id); err != nil || id <= 0 {
		return fmt.Errorf("id %s is not a positive integer", bytes.TrimSpace(v))
	}
	return nil
}

// userRef checks a user reference: present, an object, with a positive id.
// nullable admits a JSON null (merge_user before a merge).
func userRef(m map[string]json.RawMessage, key string, nullable bool) error {
	v, ok := m[key]
	switch {
	case !ok:
		return fmt.Errorf("field %q is missing", key)
	case isNull(v) && nullable:
		return nil
	case isNull(v):
		return fmt.Errorf("field %q is null", key)
	}
	var u map[string]json.RawMessage
	if err := json.Unmarshal(v, &u); err != nil {
		return fmt.Errorf("field %q: %w", key, err)
	}
	id, ok := u["id"]
	if !ok || isNull(id) {
		return fmt.Errorf("field %q has no id", key)
	}
	if err := positiveID(id); err != nil {
		return fmt.Errorf("field %q: %w", key, err)
	}
	return nil
}

func (s shape) validateList(body []byte) error {
	var items []json.RawMessage
	if err := json.Unmarshal(body, &items); err != nil {
		return err
	}
	for i, it := range items {
		if err := s.validate(it); err != nil {
			return fmt.Errorf("item %d: %w", i, err)
		}
	}
	return nil
}

func (s shape) validate(obj []byte) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(obj, &m); err != nil {
		return err
	}
	for _, k := range s.present {
		if _, ok := m[k]; !ok {
			return fmt.Errorf("field %q is missing", k)
		}
	}
	for _, k := range s.keys {
		v, ok := m[k]
		switch {
		case !ok:
			return fmt.Errorf("field %q is missing", k)
		case isNull(v):
			return fmt.Errorf("field %q is null", k)
		}
	}
	for k, el := range s.lists {
		if err := el.validateList(m[k]); err != nil {
			return fmt.Errorf("%s: %w", k, err)
		}
	}
	if s.check != nil {
		return s.check(m)
	}
	return nil
}

// getAll reads every page of a list into out (a pointer to a slice),
// following X-Next-Page to exhaustion.
func (c *client) getAll(path string, out any) error {
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	dst := reflect.ValueOf(out).Elem()
	page := "1"
	for n := 0; page != ""; n++ {
		if n == maxPages {
			return fmt.Errorf("gitlab-review: GET %s: more than %d pages; refusing a truncated list", path, maxPages)
		}
		p := fmt.Sprintf("%s%sper_page=100&page=%s", path, sep, page)
		st, hdr, body, err := c.do(p)
		if err != nil || st != 200 {
			return c.fail(p, st, err)
		}
		chunk := reflect.New(dst.Type())
		if err := checkShape(body, chunk.Interface()); err != nil {
			return c.fail(p, st, fmt.Errorf("malformed body: %w", err))
		}
		if err := json.Unmarshal(body, chunk.Interface()); err != nil {
			return c.fail(p, st, fmt.Errorf("malformed body: %w", err))
		}
		dst.Set(reflect.AppendSlice(dst, chunk.Elem()))
		page = strings.TrimSpace(hdr.Get("X-Next-Page"))
	}
	return nil
}

// fail is the loud error for a read that should have worked.
func (c *client) fail(path string, status int, err error) error {
	switch {
	case err != nil:
		return fmt.Errorf("gitlab-review: GET %s: %w", path, err)
	case status == 401:
		return fmt.Errorf("gitlab-review: GET %s: 401: the token was refused", path)
	case status == 403:
		return fmt.Errorf("gitlab-review: GET %s: 403: the token lacks the role for this read (approval settings need Maintainer)", path)
	default:
		return fmt.Errorf("gitlab-review: GET %s: unexpected status %d", path, status)
	}
}
