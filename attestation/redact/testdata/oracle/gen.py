#!/usr/bin/env python3
# Copyright 2026 TestifySec, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Writes ../userinfo-oracle.json: for each value, the username and password
that Python's proxy parser (urllib.request._parse_proxy), urllib.parse.urlsplit
and Go's net/url (goreadings.go) read, and "credentials", every non-empty one
of them. The redact tests check that none survives a sink. Run it from this
directory: python3 gen.py
"""

import json
import platform
import subprocess
import urllib.parse
import urllib.request

# Every printable ASCII byte class, in the user, and in a password where a
# '/' after it takes the userinfo past the RFC 3986 authority.
BYTES = "<>\"'`{}|\\^[] %#?/@:;=,!$&()*+~"
VALUES = [f"http://ux{b}user:pxpass@proxy:3128" for b in BYTES] + [
    f"http://uxuser:px{b}pass/part@proxy:3128" for b in BYTES
] + [
    "http://u:sec<ret/part@proxy:3128",  # the review's value
    "u:sec<ret/part@proxy:3128",
    "//u:sec<ret/part@proxy:3128",
    "http://uxuser:pxpass@mid@proxy:3128",
    "http://ux@user:px@pass@proxy:3128",
    "http://:pxpass@proxy:3128",
    "http://uxuser:@proxy:3128",
    "http://:@proxy:3128",
]


def reading(read, value):
    try:
        user, password = read(value)
    except ValueError as e:
        return {"error": str(e)}
    return {"user": user, "password": password}


def main():
    go = subprocess.run(["go", "run", "goreadings.go"], input=json.dumps(VALUES),
                        capture_output=True, text=True, check=True)
    go_version = subprocess.run(["go", "env", "GOVERSION"], capture_output=True, text=True, check=True)
    rows = []
    for value, go_reading in zip(VALUES, json.loads(go.stdout), strict=True):
        row = {
            "value": value,
            "python_proxy": reading(lambda v: urllib.request._parse_proxy(v)[1:3], value),
            "python_urlsplit": reading(lambda v: (urllib.parse.urlsplit(v).username, urllib.parse.urlsplit(v).password), value),
            "go_net_url": go_reading,
        }
        found = [r.get(k) for r in list(row.values())[1:] for k in ("user", "password")]
        row["credentials"] = sorted({s for s in found if s})
        rows.append(json.dumps(row))
    with open("../userinfo-oracle.json", "w") as f:
        f.write('{"python": %s, "go": %s, "rows": [\n' % (json.dumps(platform.python_version()), json.dumps(go_version.stdout.strip())))
        f.write(",\n".join(rows) + "\n]}\n")


if __name__ == "__main__":
    main()
