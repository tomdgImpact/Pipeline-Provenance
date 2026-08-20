# Benchmarks

Offline by default and reproducible from a clean checkout. Every figure the
project publishes is produced here, and every figure carries the corpus, the
method and the date it was measured on — a number without those is not
comparable to anything, including itself a month later.

```bash
make bench            # everything measurable offline
python -m benchmarks.detection      # SC-001, SC-002
python -m benchmarks.performance    # SC-008
```

## Why detection is measured against `intent.md`, not `expected.json`

`expected.json` is generated from the tool's own output. Measuring against it
would only establish that the tool agrees with itself.

`intent.md` is hand-written, one per fixture, and was written **before** the
rule that detects the defect it describes. The detection benchmark parses the
declared defect table out of those files and compares the tool's findings
against it. That is a real measurement with a real denominator, and it is the
one published.

## What is not measured here

Detection quality on repositories nobody curated. The fixture corpus is small
and synthetic by construction, and a precision figure derived from it says
nothing about the long tail. `distribution.py` exists to close that gap against
public repositories; until it has been run and its output published, the README
says the figure is not available rather than substituting this one for it.
