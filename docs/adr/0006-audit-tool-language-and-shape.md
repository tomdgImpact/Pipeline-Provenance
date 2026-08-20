# ADR-0006 — Audit tool as a Python CLI with machine-readable output

**Status:** Accepted — 2026-08-20

## Context

The audit tool has two audiences with incompatible needs. An engineer wants to
run one command against a repository and read a scored finding list. A pipeline
wants a machine-readable result it can gate on. A prospect reading the project
wants to recognise their own repository in the output.

## Decision

A single Python 3.12 CLI, `ppv`, with three output modes over one analysis
engine:

- `--format json` — the canonical result, schema-versioned.
- `--format sarif` — for code-scanning ingestion, so findings land where a
  security team already works.
- `--format html` — a self-contained scored report, no external assets, the
  artifact a human actually reads.

Analysis is static and offline by default; `--remote` is opt-in and requires an
explicit read-only token.

## Consequences

- Python brings `bandit` and `pip-audit` into the project's own CI, so the tool
  is subject to the class of checks it recommends.
- The HTML report is a real interface and therefore requires real interface
  tests. Browser coverage with Playwright becomes part of the definition of
  done, not an optional extra.
- Three output formats mean three things to keep in sync. Mitigated by
  rendering all three from one result object with a versioned schema, and
  asserting the invariant in tests.

## Alternatives rejected

- **A shell script.** Trivially portable, and unmaintainable past the third
  rule. No test story worth the name.
- **A GitHub App with a hosted dashboard.** Better product, wrong project:
  it introduces a service to operate and a data-handling story to defend, for
  an artifact whose purpose is to be read and self-hosted.
- **Go, for a single static binary.** Genuinely better distribution. Rejected
  because the surrounding security tooling the project must dogfood is
  Python-native, and one language in the repository beats two.
