// TestifySec-maintained rewrite of github.com/wk8/go-ordered-map/v2@v2.1.8
// with json.go reimplemented on top of stdlib encoding/json instead of
// github.com/buger/jsonparser + github.com/mailru/easyjson. The public API
// and on-wire JSON format are unchanged.
//
// See README.md in this directory for the rationale. Imported via a
// `replace` directive in consumer go.mod files; the module path remains
// the upstream path so import statements elsewhere do not change.
module github.com/wk8/go-ordered-map/v2

go 1.26

require (
	github.com/bahlo/generic-list-go v0.2.0
	gopkg.in/yaml.v3 v3.0.1
)
