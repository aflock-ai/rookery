package jsonpath

import (
	"encoding/json"
	"testing"
)

// TestRFC9535ConformanceVectors exercises the subset against the
// RFC 9535 §2 example fixture (the bookstore JSON) and a handful of edges.
// Anything outside the documented subset (filters, slices, unions) must
// fail to parse rather than silently mis-select.
func TestRFC9535ConformanceVectors(t *testing.T) {
	const bookstore = `{
		"store": {
			"book": [
				{"category": "reference", "author": "Nigel Rees", "title": "Sayings of the Century", "price": 8.95},
				{"category": "fiction", "author": "Evelyn Waugh", "title": "Sword of Honour", "price": 12.99},
				{"category": "fiction", "author": "Herman Melville", "title": "Moby Dick", "isbn": "0-553-21311-3", "price": 8.99}
			],
			"bicycle": {"color": "red", "price": 399}
		}
	}`
	var root any
	if err := json.Unmarshal([]byte(bookstore), &root); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name      string
		query     string
		wantCount int
	}{
		{"root", "$", 1},
		{"named child shorthand", "$.store", 1},
		{"named child bracketed", "$['store']", 1},
		{"nested child", "$.store.book", 1},
		{"index 0", "$.store.book[0]", 1},
		{"index 2", "$.store.book[2]", 1},
		{"wildcard on array", "$.store.book[*]", 3},
		{"wildcard shorthand on array", "$.store.book.*", 3},
		{"wildcard on object", "$.store.*", 2},
		{"recursive descent named", "$..author", 3},
		// `..[*]` per RFC 9535 §1.5 returns every member value / array
		// element under the root: 1 (store) + 2 (book, bicycle) + 3
		// (books in array) + 4+4+5 (per-book fields) + 2 (bicycle
		// fields) = 21. The leaf scalar values themselves don't expand
		// under the trailing wildcard.
		{"recursive descent wildcard", "$..[*]", 21},
		{"single nested field", "$.store.book[0].author", 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			matches, err := Select(root, c.query)
			if err != nil {
				t.Fatalf("Select(%q) error: %v", c.query, err)
			}
			if len(matches) != c.wantCount {
				paths := make([]string, len(matches))
				for i, m := range matches {
					paths[i] = m.Path
				}
				t.Errorf("Select(%q) returned %d matches, want %d. paths=%v", c.query, len(matches), c.wantCount, paths)
			}
		})
	}
}

// TestNormalizedPathShape pins the canonical form (`$['k'][N]`) per RFC 9535
// §2.7. The structured-data attestor uses the path as part of the subject
// key; if the form drifts, the cross-attestation linkage breaks.
func TestNormalizedPathShape(t *testing.T) {
	root := map[string]any{"a": []any{map[string]any{"b": 1.0}}}
	matches, err := Select(root, "$.a[0].b")
	if err != nil {
		t.Fatalf("Select error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("want 1 match, got %d", len(matches))
	}
	if matches[0].Path != "$['a'][0]['b']" {
		t.Errorf("path = %q, want %q", matches[0].Path, "$['a'][0]['b']")
	}
}

// TestUnsupportedSyntaxFails — slices, unions, filters, and negative indices
// are out of subset scope. Better to error than to silently mis-select.
func TestUnsupportedSyntaxFails(t *testing.T) {
	bad := []string{
		"store.foo",      // missing root
		"$.foo[1:5]",     // slice
		"$.foo[1,2]",     // union
		"$.foo[?(@.x)]",  // filter
		"$.foo[-1]",      // negative index
		"$.",             // trailing dot
		"$..",            // trailing descent
		"$.foo[",         // unterminated bracket
		"$.foo[bar baz]", // unparseable
	}
	for _, q := range bad {
		t.Run(q, func(t *testing.T) {
			if _, err := Select(map[string]any{}, q); err == nil {
				t.Errorf("Select(%q): want error, got nil", q)
			}
		})
	}
}

// TestEmptyAndMissingPaths — selecting a missing key returns zero matches
// without error. Same for indexing past the end of an array. This matters
// for recipe authors: a quietly-empty subject list is a better signal than
// a hard error when the cloud API response shape varies between accounts.
func TestEmptyAndMissingPaths(t *testing.T) {
	root := map[string]any{"a": []any{1.0, 2.0}}
	for _, q := range []string{"$.b", "$.a[5]", "$.b.c"} {
		matches, err := Select(root, q)
		if err != nil {
			t.Fatalf("Select(%q) error: %v", q, err)
		}
		if len(matches) != 0 {
			t.Errorf("Select(%q): want 0 matches, got %d", q, len(matches))
		}
	}
}

// TestWildcardDeterministicOrder — object-wildcard iteration must visit keys
// in lexical order so two runs of the attestor against the same input emit
// identical subject lists.
func TestWildcardDeterministicOrder(t *testing.T) {
	root := map[string]any{"c": 3.0, "a": 1.0, "b": 2.0}
	matches, err := Select(root, "$.*")
	if err != nil {
		t.Fatalf("Select error: %v", err)
	}
	if len(matches) != 3 {
		t.Fatalf("want 3 matches, got %d", len(matches))
	}
	wantOrder := []string{"$['a']", "$['b']", "$['c']"}
	for i, want := range wantOrder {
		if matches[i].Path != want {
			t.Errorf("matches[%d].Path = %q, want %q", i, matches[i].Path, want)
		}
	}
}
