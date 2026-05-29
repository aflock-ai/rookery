# pip-install — live reproduction example

This directory holds a **real, signed reproduction** of the `pip-install`
attestor. It is the proof-of-correctness for this attestor, in place of the
hermetic replay/cross-check that the artifact-parsing attestors get.

## Why this attestor is proven by a reproduction, not by the hermetic gate

`pip-install` is a **live-environment introspector**, not an artifact parser:

- It shells out to `pip3`/`pip`/`python3 -m pip` (`pip list`, `pip show`,
  `python -c …`) against the **live Python interpreter** that the wrapped
  `pip install` just mutated — reading installed package versions, install
  `Location`s, site-packages `.py`/`.pth`/pickle files, and `setup.py` /
  `pyproject.toml` build backends.
- It makes **live, unauthenticated HTTP calls to `pypi.org`** (the JSON API +
  the PEP 740 integrity/provenance endpoint) for every installed package to
  record Trusted-Publisher provenance.

Because its predicate is a function of the live interpreter state **and** PyPI's
current network responses, it **cannot be replayed hermetically** by the
catalog-coverage harness the way pure artifact-parsing attestors can — there is
no fixed input file to feed it, and PyPI's responses (and the floating package
versions pip resolves) change over time. The detector contract marks this
explicitly: `stability.level: best-effort`, with `pep740Verification`,
`packages[].location`, and the discovered-file fields listed as
`volatile_fields`.

It is therefore **NOT wired into the merge-blocking hermetic gate**. Do not add
it to `presets/all/catalogtest/catalog_coverage_test.go`. It is proven instead
by **this** real reproduction: a genuine `pip install requests` produced a
genuine ed25519-signed attestation whose package coordinates and `pip://`
subjects are correct and independently verifiable.

## What's here

| File              | What it is                                                          |
| ----------------- | ------------------------------------------------------------------ |
| `attestation.json`| The REAL signed DSSE collection captured from one live run.        |
| `reproduce.sh`    | Runnable recipe to regenerate an equivalent capture (see below).   |
| `README.md`       | This file.                                                         |

## How to regenerate

```bash
./reproduce.sh                 # builds cilock-all from the tree, runs the capture
CILOCK_BIN=/path/cilock-all ./reproduce.sh   # reuse a prebuilt linux/amd64 binary
PKG=flask ./reproduce.sh       # capture a different package
```

The script: builds a `linux/amd64` `cilock-all` from this tree, starts a clean
`python:3.12-slim` container, generates an **ephemeral ed25519 key inside the
container** (it never leaves and is destroyed with the container — never
committed), runs `cilock run … -- pip install requests`, copies the signed
`attestation.json` out, and verifies the ed25519 signature over the DSSE PAE.

The cilock invocation that produced the committed evidence:

```bash
cilock run \
  --step pip-install-capture \
  --workload manual \
  --platform-url '' \
  --signer-file-key-path /tmp/key.pem \
  --attestations product,pip-install \
  --enable-archivista=false \
  --outfile /work/attestation.json \
  -- pip install requests
```

(`--platform-url ''` keeps the run fully offline — no TSA. `--workload manual`
makes `--attestations` the exact set; `product` is always recorded.)

## Observed real output (the committed `attestation.json`)

- **Outer envelope**: DSSE, `payloadType: application/vnd.in-toto+json`, 1
  ed25519 signature.
- **Statement**: in-toto `predicateType:
  https://aflock.ai/attestation-collection/v0.1`, collection name
  `pip-install-capture`, containing 4 attestations: `material/v0.3`,
  `command-run/v0.1`, `product/v0.3`, **`pip-install/v0.1`**.
- **Environment**: `pip 25.0.1`, `Python 3.12.13`.
- **`totalInstalled`: 6** packages (`pip` itself + the 5 installed by
  `pip install requests`):
  `requests==2.34.2`, `urllib3==2.7.0`, `idna==3.17`,
  `charset-normalizer==3.4.7`, `certifi==2026.5.20`, `pip==25.0.1`.
  (Package names/versions float as PyPI publishes new releases — yours may
  differ.)
- **Per-package install provenance** — every package carries
  `installType: "wheel"`, `installer: "pip"`, and `hasSetupPy: false`. These
  are read from on-disk markers: `installer` is the verbatim token from
  `<dist-info>/INSTALLER`; `installType` is `wheel` because each dist-info has
  a `WHEEL` marker and no `direct_url.json`/`setup.py` build step (a prebuilt
  wheel was dropped — no source build); `hasSetupPy` is `false` because a wheel
  install leaves no `setup.py` in pip's build cache. (Source builds — e.g.
  `pip install --no-binary :all: docopt` — instead yield
  `installType: "sdist"`, `hasSetupPy: true`, and `hasCmdClass` per the
  package's `setup.py`; an editable `pip install -e .` yields
  `installType: "editable"`.)
- **Subjects (6 `pip://` subjects)** — surfaced at the in-toto statement level
  namespaced by predicate type, each a `pip://<name>@<version>` whose digest is
  `sha256("<name>==<version>")` (the literal coordinate string, **not** the
  wheel artifact):
  - `pip://requests@2.34.2`           → `sha256:e1331cbc693de13421e9907802b60649d0418543f9fbde2fa2d1d8737fd36966`
  - `pip://urllib3@2.7.0`             → `sha256:7cafd154f328c9e59dcc03e51dd139f1c5232215e719820ce6e1a98e8266af15`
  - `pip://idna@3.17`                 → `sha256:f23f8052b1b8a768d197a3aa20bc46c4fc43c33472c96c9c53d3dc1699286060`
  - `pip://charset-normalizer@3.4.7`  → `sha256:71a76de036905a598ef6b17fbfe50e9518fb400fa2303a3c99e08440b7b47184`
  - `pip://certifi@2026.5.20`         → `sha256:780e07ca43c18fc3d7ee3d3c61f93b56d834a43cef2cad9ab073a02a33d818d5`
  - `pip://pip@25.0.1`                → `sha256:f56d5464df105c0a679293179d96dfd445a6b24e3c3883aefb848806bc4eb904`
- **`pep740Verification`: POPULATED** (5 entries — pip itself is skipped by the
  attestor). Every dependency returned a live PEP 740 attestation from PyPI with
  a GitHub Trusted-Publisher identity:
  - `requests`           → `psf/requests` · `publish.yml`
  - `urllib3`            → `urllib3/urllib3` · `publish.yml`
  - `idna`               → `kjd/idna` · `deploy.yml`
  - `charset-normalizer` → `jawah/charset_normalizer` · `cd.yml`
  - `certifi`            → `certifi/python-certifi` · `release.yml`

  PEP 740 population depends on PyPI's current provenance state and network
  availability; an empty `pep740Verification` on a future re-run is expected and
  acceptable (it is a `volatile_field`).

## Integrity of the committed evidence

| Item                         | Value                                                              |
| ---------------------------- | ----------------------------------------------------------------- |
| cilock-all binary sha256     | `f4b801c8f92572fac701dfcac64aa299fce8f114f5e0cf64a637c3dfd6f8a026` |
| `attestation.json` sha256    | `967e723880e13358b223b7fd86d0bed85e4a74a621f8f06975dad60184fb57a0` |
| DSSE signature key id        | `f3aa2dee58b611ce49641e2da4cda5907d569c212cbb3a7c3dd375172b295b05` |
| DSSE ed25519 verify          | **PASS** (`openssl pkeyutl -verify` over the DSSE PAE)            |

The signing key was an ephemeral ed25519 key generated inside the container and
destroyed with it; it is not present in this directory or in `attestation.json`
(the envelope carries only the signature + key id, no PEM body).

## Per-package install-provenance fields (now populated)

`PackageInfo` carries four install-provenance fields, all populated **honestly
from data the attestor reads off disk** — no heuristics, no synthetic values:

- **`installType`** (`"wheel"` | `"sdist"` | `"editable"`) — determined from
  on-disk markers under the package's install `Location`, in priority order:
  (a) an `<canonical>.egg-link` or `<canonical>*.egg-info` ⇒ `editable`;
  (b) `<dist-info>/direct_url.json` whose archive url ends `.whl` ⇒ `wheel`,
  `.tar.gz`/`.zip` ⇒ `sdist`; (c) build-evidence fallback — `hasSetupPy: true`
  (pip executed a `setup.py`) ⇒ `sdist`, else `wheel`. In this capture every
  package is `wheel` via path (c): index wheels have a `WHEEL` marker, no
  `direct_url.json`, and no build step.
- **`installer`** — the tool that installed the dist, read verbatim from
  `<dist-info>/INSTALLER` (here `"pip"`). **This field was renamed from
  `installerLog`**: there is no honest source for a pip "log snippet" (the
  attestor never captures pip stdout), so a `…Log` name holding `"pip"` would
  be misleading. The honest on-disk provenance is the `INSTALLER` token.
- **`hasSetupPy`** — `true` iff a `setup.py` belonging to *this* package was
  found and analyzed during the run (correlated by canonical name + project
  directory). A pure wheel install leaves no `setup.py` in pip's build cache,
  so it is correctly `false` here.
- **`hasCmdClass`** — `true` iff that correlated `setup.py` referenced
  `cmdclass` (custom build/install commands). `false` here (no `setup.py`).

These fields do not affect the package coordinates or `pip://` subjects, which
remain correct. They were verified against two real container installs: a
prebuilt-wheel install (`pip install requests` ⇒ all `wheel`/`hasSetupPy:
false`) and a forced source build (`pip install --no-binary :all: docopt` ⇒
`sdist`/`hasSetupPy: true`/`hasCmdClass: false`; `simplejson` ⇒
`hasCmdClass: true`).
