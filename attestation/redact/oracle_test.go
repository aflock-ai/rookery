// jade:ring local
//
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
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// oracleRow is a row of testdata/userinfo-oracle.json, which
// testdata/oracle/gen.py writes from the real parsers: a value, and every
// username and password Python's proxy parser, urlsplit or Go's net/url reads
// in it.
type oracleRow struct {
	Value       string
	Credentials []string
}

func userinfoOracle(t *testing.T) []oracleRow {
	t.Helper()
	raw, err := os.ReadFile("testdata/userinfo-oracle.json")
	require.NoError(t, err)
	var table struct{ Rows []oracleRow }
	require.NoError(t, json.Unmarshal(raw, &table))
	require.GreaterOrEqual(t, len(table.Rows), 60)
	return table.Rows
}

// No username or password that a real parser reads in a value survives any
// sink: an environment value, an argv element, or a line of command output
// that prints it bare, in shell quotes, or as a JSON string with a field after
// it. Text is cut into words at URL space, so a row whose userinfo holds a
// space is checked as a value and as an argv element only, and a scheme-less
// value needs host[:port] at the end of its word; both boundaries are
// documented on URLCredentialsInText.
func TestOracleUserinfoSurvivesNoSink(t *testing.T) {
	sinks := []struct {
		name   string
		redact func(string) string
		text   bool
	}{
		{"environment value", URLCredentials, false},
		{"argv element", URLCredentialsInArg, false},
		{"output line", func(v string) string { return URLCredentialsInText(v + "\n") }, true},
		{"single-quoted assignment", func(v string) string { return URLCredentialsInText("HTTPS_PROXY='" + v + "';\n") }, true},
		{"double-quoted assignment", func(v string) string { return URLCredentialsInText(`export HTTPS_PROXY="` + v + "\"\n") }, true},
		{"json log line", func(v string) string {
			return URLCredentialsInText(`{"proxy":` + jsonString(v) + `,"level":"info"}` + "\n")
		}, true},
	}
	for _, row := range userinfoOracle(t) {
		for _, sink := range sinks {
			if sink.text && strings.ContainsFunc(row.Value, func(r rune) bool { return r <= ' ' }) ||
				sink.name == "json log line" && !strings.Contains(row.Value, "://") {
				continue
			}
			got := sink.redact(row.Value)
			for _, credential := range row.Credentials {
				if strings.Contains(got, credential) || strings.Contains(got, strings.Trim(jsonString(credential), `"`)) {
					t.Errorf("%s: %q is signed as %q, which still holds %q", sink.name, row.Value, got, credential)
				}
			}
		}
	}
}

// jsonString is s as a JSON string, as a log encoder writes it: '"' and '\\'
// escaped, '<' and '>' not.
func jsonString(s string) string {
	var b strings.Builder
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	_ = e.Encode(s)
	return strings.TrimSuffix(b.String(), "\n")
}
