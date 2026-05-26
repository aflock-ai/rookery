// Copyright (c) Wassim Chegham — MIT license; see LICENSE.
//
// This file is a TestifySec-maintained rewrite of upstream
// github.com/wk8/go-ordered-map/v2@v2.1.8's json.go.
//
// Upstream's MarshalJSON / UnmarshalJSON use github.com/buger/jsonparser
// and github.com/mailru/easyjson. Both pull single-author / abandoned
// supply-chain risk into every consumer of OrderedMap — which in our
// monorepo means every attestor (~30 modules) and the main judge-api
// binary, transitively through invopop/jsonschema.
//
// This rewrite uses encoding/json's stdlib Decoder.Token() iteration to
// preserve insertion order on Unmarshal, and a hand-rolled stdlib
// bytes.Buffer-based writer for Marshal. The public API and on-wire JSON
// representation are unchanged from upstream — fuzz tests against the
// upstream JSON encoding/decoding round-trip stay green.
//
// Cost: removes github.com/buger/jsonparser and github.com/mailru/easyjson
// from the linked binary of every consumer. Drops the GHSA-6g7g-w4f8-9c9x
// (buger Delete() DoS) exposure surface entirely instead of just
// patching it.

package orderedmap

import (
	"bytes"
	"encoding"
	"encoding/json"
	"fmt"
	"reflect"
	"unicode/utf8"
)

var (
	_ json.Marshaler   = &OrderedMap[int, any]{}
	_ json.Unmarshaler = &OrderedMap[int, any]{}
)

// MarshalJSON implements the json.Marshaler interface.
func (om *OrderedMap[K, V]) MarshalJSON() ([]byte, error) { //nolint:funlen
	if om == nil || om.list == nil {
		return []byte("null"), nil
	}

	var buf bytes.Buffer
	buf.WriteByte('{')

	for pair, firstIteration := om.Oldest(), true; pair != nil; pair = pair.Next() {
		if firstIteration {
			firstIteration = false
		} else {
			buf.WriteByte(',')
		}

		if err := writeJSONKey(&buf, pair.Key); err != nil {
			return nil, err
		}
		buf.WriteByte(':')

		valBytes, err := json.Marshal(pair.Value)
		if err != nil {
			return nil, err
		}
		buf.Write(valBytes)
	}

	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// writeJSONKey emits a JSON object key for a typed map key. JSON object
// keys are always strings on the wire, so non-string keys are stringified
// the same way upstream's easyjson-backed code did:
//   - string         → JSON-encoded string
//   - encoding.TextMarshaler → quoted MarshalText output
//   - int*/uint*     → numeric-string ("123")
//   - wrapper types  → same after reflect.Kind dispatch
func writeJSONKey[K comparable](buf *bytes.Buffer, key K) error { //nolint:funlen,gocyclo
	switch k := any(key).(type) {
	case string:
		return encodeStringKey(buf, k)
	case encoding.TextMarshaler:
		text, err := k.MarshalText()
		if err != nil {
			return err
		}
		buf.WriteByte('"')
		buf.Write(text)
		buf.WriteByte('"')
		return nil
	case int:
		return encodeNumberKey(buf, fmt.Sprintf("%d", k))
	case int8:
		return encodeNumberKey(buf, fmt.Sprintf("%d", k))
	case int16:
		return encodeNumberKey(buf, fmt.Sprintf("%d", k))
	case int32:
		return encodeNumberKey(buf, fmt.Sprintf("%d", k))
	case int64:
		return encodeNumberKey(buf, fmt.Sprintf("%d", k))
	case uint:
		return encodeNumberKey(buf, fmt.Sprintf("%d", k))
	case uint8:
		return encodeNumberKey(buf, fmt.Sprintf("%d", k))
	case uint16:
		return encodeNumberKey(buf, fmt.Sprintf("%d", k))
	case uint32:
		return encodeNumberKey(buf, fmt.Sprintf("%d", k))
	case uint64:
		return encodeNumberKey(buf, fmt.Sprintf("%d", k))
	default:
		// Wrapper types around a primitive (`type myType string`, etc).
		// Dispatch on the underlying reflect.Kind.
		rv := reflect.ValueOf(key)
		switch rv.Type().Kind() {
		case reflect.String:
			return encodeStringKey(buf, rv.String())
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			return encodeNumberKey(buf, fmt.Sprintf("%d", rv.Int()))
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			return encodeNumberKey(buf, fmt.Sprintf("%d", rv.Uint()))
		default:
			return fmt.Errorf("unsupported key type: %T", key)
		}
	}
}

func encodeStringKey(buf *bytes.Buffer, s string) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	buf.Write(b)
	return nil
}

// encodeNumberKey writes a numeric key as a JSON string (e.g. `"123"`).
// JSON object keys must be strings on the wire; this matches what easyjson's
// IntStr/UintStr did in the upstream implementation.
func encodeNumberKey(buf *bytes.Buffer, n string) error {
	buf.WriteByte('"')
	buf.WriteString(n)
	buf.WriteByte('"')
	return nil
}

// UnmarshalJSON implements the json.Unmarshaler interface. Stdlib
// json.Decoder.Token() walks tokens in stream order, which is exactly
// what we need to preserve insertion order.
func (om *OrderedMap[K, V]) UnmarshalJSON(data []byte) error { //nolint:funlen,gocyclo
	if om.list == nil {
		om.initialize(0)
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()

	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return fmt.Errorf("expected JSON object, got %v", tok)
	}

	for dec.More() {
		// Read the key. json.Decoder returns string-typed keys for objects.
		keyTok, err := dec.Token()
		if err != nil {
			return err
		}
		keyStr, ok := keyTok.(string)
		if !ok {
			return fmt.Errorf("expected string key, got %T (%v)", keyTok, keyTok)
		}

		var key K
		if err := assignKey(&key, keyStr); err != nil {
			return err
		}

		// Read the value as raw JSON, then unmarshal into V via json.Unmarshal.
		var rawValue json.RawMessage
		if err := dec.Decode(&rawValue); err != nil {
			return err
		}
		var value V
		if err := json.Unmarshal(rawValue, &value); err != nil {
			return err
		}

		om.Set(key, value)
	}

	// Consume the closing brace.
	if _, err := dec.Token(); err != nil {
		return err
	}
	return nil
}

// assignKey converts the JSON object key (always a string on the wire)
// into the typed K of the OrderedMap. Mirrors the upstream key-decoding
// dispatch.
func assignKey[K comparable](dst *K, keyStr string) error { //nolint:funlen
	switch typedKey := any(dst).(type) {
	case *string:
		// json.Decoder.Token already returned a Go string with escapes
		// resolved; just validate UTF-8 (parity with upstream behavior).
		if !utf8.ValidString(keyStr) {
			return fmt.Errorf("not a valid UTF-8 string: %q", keyStr)
		}
		*typedKey = keyStr
		return nil
	case encoding.TextUnmarshaler:
		return typedKey.UnmarshalText([]byte(keyStr))
	case *int, *int8, *int16, *int32, *int64,
		*uint, *uint8, *uint16, *uint32, *uint64:
		// JSON object keys are strings; upstream went through json.Unmarshal
		// of the raw bytes, which expects the surrounding numeric format.
		// Quoting the keyStr matches that behavior.
		return json.Unmarshal([]byte(keyStr), typedKey)
	default:
		// Wrapper types around primitives.
		rv := reflect.ValueOf(dst).Elem()
		switch rv.Type().Kind() {
		case reflect.String:
			if !utf8.ValidString(keyStr) {
				return fmt.Errorf("not a valid UTF-8 string: %q", keyStr)
			}
			rv.Set(reflect.ValueOf(keyStr).Convert(rv.Type()))
			return nil
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
			reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			var raw any
			if err := json.Unmarshal([]byte(keyStr), &raw); err != nil {
				return err
			}
			rv.Set(reflect.ValueOf(raw).Convert(rv.Type()))
			return nil
		default:
			return fmt.Errorf("unsupported key type: %T", *dst)
		}
	}
}
