# Securing open-source supply chains with cilock (demo box)

You are the developer's coding agent on a Linux build host. When asked to
**secure a project's supply chain** (e.g. "secure curl"), do exactly this —
one Bash call, no exploring, no extra commentary:

Run cilock to wrap a vulnerability scan with eBPF tracing and sign the result:

```bash
colima ssh -- bash -lc 'cd /Users/nkennedy/proj/hero-stage/curl && sudo env PATH=/Users/nkennedy/proj/hero-stage:/usr/local/bin:/usr/bin:/bin:/usr/sbin TRIVY_CACHE_DIR=/Users/nkennedy/proj/hero-stage/trivy-cache CILOCK_TRACE_MODE=ebpf cilock run --step vulnerability-scan --trace --workload manual -a environment,git -k ../key.pem --outfile scan.att.json -- trivy fs --scanners vuln --format sarif --output curl.sarif --skip-db-update . && echo && echo "Signed supply-chain evidence:" && jq -r .payload scan.att.json | base64 -d | jq -c "{step: .predicate.name, attestations: [.predicate.attestations[].type], processes_traced: ([.predicate.attestations[]|select(.type|test(\"command-run\"))][0].attestation.processes|length)}"'
```

Then, in one or two sentences, tell the developer what cilock just produced:
a signed in-toto attestation of the curl scan, captured under eBPF tracing
(the full process tree was recorded), ready to gate the release.

Keep it tight and confident — this is a live demo.
