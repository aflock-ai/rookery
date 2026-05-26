# Vendored fork: github.com/zricethezav/gitleaks/v8 (slim)

TestifySec-maintained trim of upstream gitleaks/v8@v8.30.0 that drops the
load-bearing supply-chain pile:

- `github.com/charmbracelet/lipgloss` (+ termenv + lucasb-eyer + x/ansi cluster)
- `github.com/spf13/viper` (+ fsnotify + afero + mapstructure + locafero + cast + pflag cluster)
- `github.com/mholt/archives` (+ bodgit/sevenzip + lz4/zstd/rar/xz compression libs)
- `github.com/Masterminds/sprig/v3` (+ template helpers)
- The whole CLI surface (`cmd/`)

Total: ~46 modules dropped from cilock (and the same chain from judge-api via
the secretscan attestor).

## What stays

- `detect/` — the detection engine (DetectBytes, DetectString, Detect, Detector
  type, baseline filter, codec/ encoded-content decoders, location helpers)
- `config/` — Config type + rules + allowlists (viper-tagged structs preserved,
  the viper-runtime usage stripped)
- `regexp/` — internal regex helpers
- `logging/` — internal logger
- `report/finding.go` — the Finding struct
- `version/` — version string

## What's gone

- `cmd/` — CLI
- `sources/` — archive/file/git scanners (we only use DetectBytes on in-memory
  content)
- `report/{csv,sarif,json,junit,template,report,constants}.go` — output emitters
- All `*_test.go`, `testdata/`, `report_templates/`, `Dockerfile`, `Makefile`

## Required code changes (still TODO — see issue #179)

- `detect/utils.go` — strip `printFinding` (lipgloss) + `createScmLink` (sources)
- `detect/reader.go` — strip `sources.Fragment`-using helpers
- `detect/detect.go` — remove `createScmLink` callers, remove `printFinding` callers
- `config/config.go` — strip the `viper` import; `ViperConfig.Translate()` doesn't
  actually use viper at runtime, the name is historical

## Wiring

Once the trim compiles, the rookery `go.work` gets a single replace:

```
replace github.com/zricethezav/gitleaks/v8 => ./security-patches/gitleaks-slim
```

All consumer code keeps the same import paths.

## Upstream resync

When upstream gitleaks releases new versions (or just new detection rules
in `config/gitleaks.toml`), the canonical resync is to copy the new
`detect/`, `config/`, `regexp/`, `logging/`, `report/finding.go`,
`version/` files verbatim, then re-apply the strip patches. The drops
listed above are mechanical sed-style edits — see the commits in this
branch for the exact diff.
