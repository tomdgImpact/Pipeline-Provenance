# Installation

Three ways in, depending on what you want to do. All of them are verified
against a clean environment; none of them requires an account anywhere.

| You want to | Use |
|---|---|
| Run `ppv` against your own repositories | [As a tool](#as-a-tool) |
| Add the gate to a pipeline | [In CI](#in-ci) |
| Change the code | [From source](#from-source) |

## Prerequisites

| | Version | Needed for |
|---|---|---|
| Python | **3.12 or later** | everything |
| [uv](https://docs.astral.sh/uv/) | 0.5 or later | the documented install paths |
| Chromium (via Playwright) | — | the browser test suite only |
| `cosign` | 2.x | `ppv verify` only — it **refuses** rather than degrading if absent |

`uv` on macOS or Linux:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Everything except `ppv verify` works offline and needs nothing else. There is no
service to sign up for, no API key, and no telemetry.

## As a tool

The tool installs into its own isolated environment with four runtime
dependencies (`click`, `jinja2`, `markupsafe`, `ruamel.yaml`). It does not touch
your system Python.

```bash
git clone https://github.com/tomdgImpact/Pipeline-Provenance
cd Pipeline-Provenance
uv tool install .
```

Once the repository is public you can skip the clone, pinning by commit SHA
rather than by tag — the tool refuses to let *you* run an unpinned reference, so
it does not ask you to make an exception for itself:

```bash
uv tool install "git+https://github.com/tomdgImpact/Pipeline-Provenance@<commit-sha>"
```

`pipx install .` works identically if you prefer it.

> **Not on PyPI.** `pipeline-provenance` has not been published to any package
> index. Any instruction telling you to `pip install pipeline-provenance` is
> wrong, including one you may find in an older copy of these docs.

### Verify the installation

```bash
ppv --version
ppv doctor
```

`doctor` prints every capability the installation does **not** have, rather than
listing only what works:

```
ppv 0.1.0  (result schema 1)
python 3.12.13 on darwin

  [  available] offline static audit - `ppv audit <path>`
  [  available] json, sarif and html output - `--format json|sarif|html`
  [  available] policy gate - `ppv gate <path>`
  [UNAVAILABLE] remote reference resolution - not implemented at this milestone
  [  available] admission verification - `ppv verify <artifact> ...`
  [UNAVAILABLE] signature backend - cosign is not installed on this host
  [UNAVAILABLE] expected signer identity configured - PPV_EXPECTED_SIGNER_IDENTITY has no default, by design
```

Two of those lines are the point of the tool. A capability reported
`UNAVAILABLE` is never silently degraded: any command depending on one refuses
to run rather than returning a result that reads as clean.

### Uninstall

```bash
uv tool uninstall pipeline-provenance
```

## In CI

The composite action installs the tool from its own checkout, so nothing is
fetched at build time and the version you pinned is the version that runs:

```yaml
      - uses: tomdgImpact/Pipeline-Provenance/.github/actions/policy-gate@<commit-sha>  # v0.1.0
        with:
          fail-on: critical
```

Full adoption path, including how to raise the threshold as your finding list
shrinks: [`MIGRATION.md`](MIGRATION.md).

## From source

For changing the code. This creates `.venv/`, installs the development
dependencies and the browser the interface suite drives:

```bash
git clone https://github.com/tomdgImpact/Pipeline-Provenance
cd Pipeline-Provenance
make install
make check
```

`make check` runs every gate CI blocks on: lint, strict type check, unit and
end-to-end suites, the adversarial corpus, and the demonstration. It takes under
a minute on a laptop.

| Target | Runs |
|---|---|
| `make check` | everything CI blocks on |
| `make test` | unit and end-to-end only, the fast loop |
| `make test-security` | the adversarial corpus |
| `make test-gui` | the browser suite (needs Chromium) |
| `make demo` | the three acts of the demonstration |
| `make bench` | every published figure, measured offline |
| `make audit-self` | the dependency, SAST and secret gates |

## Configuration

Every value the tool reads is listed in [`.env.example`](../.env.example) with
no values. There are only two you are likely to need:

| Variable | Default | Notes |
|---|---|---|
| `PPV_EXPECTED_SIGNER_IDENTITY` | **none, deliberately** | `ppv verify` refuses without it. An identity defaulting to "any" turns verification into decoration. |
| `PPV_GITHUB_TOKEN` | none | Read-only, for `--remote` reference resolution, which is not implemented at this milestone. |

## Troubleshooting

**`ppv: command not found` after `uv tool install`** — the tool directory is not
on your `PATH`. `uv tool update-shell`, then open a new shell.

**`make install` fails with "No virtual environment found"** — you are on an
older `uv`; the target creates `.venv` itself as of v0.1.0. Upgrade `uv`, or run
`uv venv --python 3.12` first.

**`make test-gui` fails with "Executable doesn't exist"** — the browser is not
installed. `uv run python -m playwright install chromium`.

**`ppv verify` refuses with "cannot verify the signature"** — `cosign` is not on
this host. That refusal is the designed behaviour, not a bug: verification that
cannot check a signature must not report success. Install `cosign` and retry.

**`ppv audit` exits 2** — no workflow definitions were found. Exit 2 means *not
assessed*, which is deliberately distinct from exit 0, *assessed and clean*.
