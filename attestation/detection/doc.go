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

package detection

import (
	"embed"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/aflock-ai/rookery/attestation/log"
	"gopkg.in/yaml.v3"
)

// docMarkdowns is the embedded catalog of long-form documentation, one
// <name>.doc.md per tool/attestor. This is the SINGLE SOURCE OF TRUTH for
// the prose users see — `cilock tools show <name>` renders from it and the
// cilock-docs website generates one page per entry from the exact same
// bytes, so the CLI and the website can never drift.
//
// Docs live here (not next to each plugin) because plugins are separate Go
// modules the detection package can't reach with go:embed; a single
// directory also gives the website a uniform "edit this page" link target.
//
//go:embed docs/*.doc.md
var docMarkdowns embed.FS

// DetectorDoc is the parsed form of a <name>.doc.md file: YAML frontmatter
// plus the body split into addressable H2 sections.
type DetectorDoc struct {
	Name            string       `json:"name"`
	Title           string       `json:"title"`
	Description     string       `json:"description"` // SEO summary (~30 words)
	SidebarPosition int          `json:"sidebar_position,omitempty"`
	ExamplesRepo    string       `json:"examples_repo,omitempty"` // path under attestor-compliance-examples
	Sections        []DocSection `json:"sections"`
	Body            string       `json:"body"` // full markdown body (sections concatenated)
}

// DocSection is one "## Heading" block of a doc body. Slug is a stable,
// CLI- and URL-addressable identifier derived from the heading.
type DocSection struct {
	Slug     string `json:"slug"`
	Title    string `json:"title"`
	Markdown string `json:"markdown"`
}

type docFrontmatter struct {
	Title           string `yaml:"title"`
	Description     string `yaml:"description"`
	SidebarPosition int    `yaml:"sidebar_position"`
	ExamplesRepo    string `yaml:"examples_repo"`
}

var (
	frontmatterRE = regexp.MustCompile(`(?s)\A---\n(.*?)\n---\n`)
	h2RE          = regexp.MustCompile(`(?m)^##\s+(.+?)\s*$`)
	slugCleanRE   = regexp.MustCompile(`[^a-z0-9]+`)
)

// slugify turns a heading like "Validated invocation" into "validated-invocation".
func slugify(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "`", "")
	s = slugCleanRE.ReplaceAllString(s, "-")
	return strings.Trim(s, "-")
}

// ParseDoc parses a <name>.doc.md byte stream into a DetectorDoc.
func ParseDoc(name string, raw []byte) (*DetectorDoc, error) {
	text := string(raw)
	doc := &DetectorDoc{Name: name}

	if m := frontmatterRE.FindStringSubmatch(text); m != nil {
		var fm docFrontmatter
		if err := yaml.Unmarshal([]byte(m[1]), &fm); err != nil {
			return nil, fmt.Errorf("doc %q: parse frontmatter: %w", name, err)
		}
		doc.Title = fm.Title
		doc.Description = fm.Description
		doc.SidebarPosition = fm.SidebarPosition
		doc.ExamplesRepo = fm.ExamplesRepo
		text = text[len(m[0]):]
	}
	doc.Body = strings.TrimSpace(text)

	// Split the body into H2 sections. Content before the first H2 (if any)
	// is kept as an unslugged "overview" section.
	idxs := h2RE.FindAllStringSubmatchIndex(doc.Body, -1)
	if len(idxs) == 0 {
		if doc.Body != "" {
			doc.Sections = []DocSection{{Slug: "overview", Title: "Overview", Markdown: doc.Body}}
		}
		return doc, nil
	}
	if pre := strings.TrimSpace(doc.Body[:idxs[0][0]]); pre != "" {
		doc.Sections = append(doc.Sections, DocSection{Slug: "overview", Title: "Overview", Markdown: pre})
	}
	for i, m := range idxs {
		title := strings.TrimSpace(doc.Body[m[2]:m[3]])
		start := m[0]
		end := len(doc.Body)
		if i+1 < len(idxs) {
			end = idxs[i+1][0]
		}
		doc.Sections = append(doc.Sections, DocSection{
			Slug:     slugify(title),
			Title:    title,
			Markdown: strings.TrimSpace(doc.Body[start:end]),
		})
	}
	return doc, nil
}

// LookupDoc returns the parsed doc for a detector, (nil,false,nil) if none
// is registered, or a parse error. Mirrors Lookup for detector.yaml.
func (r *Registry) LookupDoc(name string) (*DetectorDoc, bool, error) {
	r.mu.RLock()
	if cached, ok := r.docParsed[name]; ok {
		err := r.docErr[name]
		r.mu.RUnlock()
		if err != nil {
			return nil, true, err
		}
		return cached, true, nil
	}
	raw, ok := r.docRaw[name]
	r.mu.RUnlock()
	if !ok {
		return nil, false, nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if cached, ok := r.docParsed[name]; ok {
		return cached, true, r.docErr[name]
	}
	d, err := ParseDoc(name, raw)
	if err != nil {
		r.docErr[name] = err
		r.docParsed[name] = nil
		return nil, true, err
	}
	r.docParsed[name] = d
	return d, true, nil
}

// RegisterDoc stores raw doc bytes for a detector. Used by loadDocs and by
// tests; parsing is lazy.
func (r *Registry) RegisterDoc(name string, raw []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.docRaw[name] = raw
}

// DocNames returns the detector names that have a registered doc, sorted.
func (r *Registry) DocNames() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.docRaw))
	for n := range r.docRaw {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// loadDocs walks the embedded docs/ directory and registers each
// <name>.doc.md under its stem. Called from init().
func loadDocs() error {
	entries, err := fs.ReadDir(docMarkdowns, "docs")
	if err != nil {
		if errIsNoSuchFile(err) {
			return nil
		}
		return fmt.Errorf("detection docs: read docs/: %w", err)
	}
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".doc.md") {
			continue
		}
		raw, err := docMarkdowns.ReadFile(path.Join("docs", ent.Name()))
		if err != nil {
			return fmt.Errorf("detection docs: read %s: %w", ent.Name(), err)
		}
		key := strings.TrimSuffix(ent.Name(), ".doc.md")
		defaultRegistry.RegisterDoc(key, raw)
	}
	return nil
}

func init() {
	if err := loadDocs(); err != nil {
		log.Errorf("(detection/docs) failed to load embedded docs: %v — docs will be empty", err)
	}
}
