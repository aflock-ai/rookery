#!/usr/bin/env python3
"""Print a cilock receipt (a signed attestation collection) in plain English.

Usage: show_receipt.py <evidence/step.json>
"""
import base64
import json
import sys

env = json.load(open(sys.argv[1]))
stmt = json.loads(base64.b64decode(env["payload"]))
pred = stmt["predicate"]
by_type = {a["type"].split("/attestations/")[-1].split("/")[0]: a["attestation"] for a in pred["attestations"]}

run = by_type.get("command-run", {})
git = by_type.get("git", {})
print(f"  step       : {pred['name']}")
print(f"  command    : {' '.join(run.get('cmd', []))}")
print(f"  exit code  : {run.get('exitcode')}")
if git:
    print(f"  source     : commit {git.get('commithash', '')[:12]}")
for leaf in by_type.get("product", {}).get("leaves", []):
    print(f"  produced   : {leaf['path']}  (sha256 {leaf['fileDigest'][:16]}...)")
print(f"  signed by  : key {env['signatures'][0]['keyid'][:16]}...")
