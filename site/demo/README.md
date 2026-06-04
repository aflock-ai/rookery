# Homepage hero recording

The hero on the landing page is a **real, unscripted [Claude Code](https://claude.com/claude-code)
session** in which the developer asks Claude to secure curl's supply chain and
Claude runs the real `cilock` CLI to do it — wrapping a Trivy vulnerability
scan under **eBPF kernel-side tracing** and signing the result as an in-toto
attestation. Nothing in the recording is faked.

## Artifacts

- `static/img/hero-demo.cast` — the asciinema recording (the only artifact the
  page ships). It's **replayed in the browser** by `src/components/HeroPlayer`
  via [asciinema-player](https://github.com/asciinema/asciinema-player): real,
  selectable terminal text at ~50 KB, instead of a multi-hundred-KB GIF.
- `demo/hero-claude-md-prompt.md` — the `CLAUDE.md` placed in the demo working
  directory to steer Claude to the exact command (so the demo is deterministic).

To refresh the hero, re-record the cast (below) and replace
`static/img/hero-demo.cast` — no rendering step needed; the player reads the
cast directly. The recording shell is kept clean with a throwaway `ZDOTDIR`
(tidy prompt, no personal rc) and `claude --strict-mcp-config` (no personal
MCP servers leak into the capture).

## How the cast was captured

The recording was made on a Linux host (an aarch64 colima VM, kernel 6.8) so
that `--trace` exercises real eBPF capture:

1. **Stage the tools** (a real, recent build):
   - build `cilock` from `aflock-ai/rookery` `main` (`go build ./cilock/cmd/cilock`),
   - install `trivy`, pre-fetch its vuln DB (`trivy fs --download-db-only`) so the run is offline/quiet,
   - `git clone --depth 1 https://github.com/curl/curl`,
   - generate an ed25519 signing key (`openssl genpkey -algorithm ed25519`).
2. Drop `hero-claude-md-prompt.md` as `CLAUDE.md` in the working dir.
3. Record a Claude Code session and ask it: *"Secure the curl supply chain:
   wrap a vulnerability scan with cilock under eBPF tracing and sign the result."*

   ```bash
   asciinema rec hero.cast        # then run `claude` and send the prompt
   ```
4. Trim the tail (the quit keystrokes) so the cast ends on Claude's summary,
   then render with `agg` (see `npm run gen:hero`).

The exact `cilock` invocation Claude runs is in `hero-claude-md-prompt.md`:
`cilock run --step vulnerability-scan --trace ... -- trivy fs ... curl`, which
produces the signed `environment · git · material · command-run · product`
attestation set with the full process tree captured by eBPF.
