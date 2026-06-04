#!/usr/bin/env python3
"""
Check that every docs/tools/*.md page (except index.md) follows the template
documented in TOOL_PAGES.md. Run from the repo root; exits 1 on any violation.
"""
import re, os, sys

def has_frontmatter_field(text, field):
    m = re.match(r'---\n(.*?)\n---', text, re.DOTALL)
    return bool(m) and re.search(rf'^{field}:', m.group(1), re.MULTILINE) is not None

def has_real_antipattern(text):
    lines, in_code = text.split('\n'), False
    for line in lines:
        if line.startswith('```'):
            in_code = not in_code
            continue
        if in_code and re.search(r'(bash|sh) -c.*\bcp\b.*\.(sarif|json|spdx|cdx|xml|yaml)', line):
            return True
    return False

checks = [
    ('description frontmatter', lambda t: has_frontmatter_field(t, 'description')),
    ('invisible JSON-LD',       lambda t: bool(re.search(r'<script[^>]*application/ld\+json', t))),
    ('## Validated invocation', lambda t: bool(re.search(r'^##\s+Validated invocation(?:s)?', t, re.MULTILINE))),
    ('## What gets captured',   lambda t: bool(re.search(r'^##\s+What gets captured', t, re.MULTILINE))),
    ('## Why this shape',       lambda t: bool(re.search(r'^##\s+Why this shape', t, re.MULTILINE))),
    ('## Validate it locally',  lambda t: bool(re.search(r'^##\s+Validate it locally', t, re.MULTILINE)) and 'jq' in t),
    ('## FAQ',                  lambda t: bool(re.search(r'^##\s+(FAQ|Frequently asked questions)', t, re.MULTILINE))),
    ('## See also',             lambda t: bool(re.search(r'^##\s+See also', t, re.MULTILINE))),
    ('matching attestor link',  lambda t: '../attestors/' in t),
    ('examples-repo link',      lambda t: 'attestor-compliance-examples' in t),
    ('NO cp antipattern',       lambda t: not has_real_antipattern(t)),
    ('NO --workingdir flag',    lambda t: '--workingdir' not in t),
    ('NO visible HowTo heading',lambda t: not re.search(r'^##+\s+(Schema\.org HowTo|Structured (data|metadata)|How to (run it|use this))', t, re.MULTILINE)),
]

failures = 0
for f in sorted(os.listdir('docs/tools')):
    if not f.endswith('.md') or f == 'index.md':
        continue
    with open(f'docs/tools/{f}') as fp:
        t = fp.read()
    fails = [name for name, fn in checks if not fn(t)]
    if fails:
        print(f'FAIL  docs/tools/{f}')
        for fail in fails:
            print(f'      ✗ {fail}')
        failures += 1
    else:
        print(f'OK    docs/tools/{f}')

if failures:
    print(f'\n{failures} page(s) violate the template. See TOOL_PAGES.md for the standard.')
    sys.exit(1)
print(f'\nAll tool pages compliant with TOOL_PAGES.md.')
