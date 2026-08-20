# Published figures

Every number quoted in `README.md` is here, as the raw output of the harness
that produced it, dated and stamped with the ruleset version. A figure a reader
cannot re-derive is a figure they have to take on trust, and this project asks
for less trust than that.

| File | Answers | Reproduce with |
|---|---|---|
| `detection-2026-08-20.json` | SC-001, SC-002 — precision and recall against declared intent | `python -m benchmarks.detection --json` |
| `performance-2026-08-20.json` | SC-008 — audit wall clock, with the machine named | `python -m benchmarks.performance --json` |
| `distribution-2026-08-20.json` | SC-003 — invariant distribution across public repositories | `python -m benchmarks.distribution --online --output <file>` |

`benchmarks/results/` is scratch and is ignored. This directory is the record.

Figures are only comparable against the ruleset version recorded inside them.
When the ruleset changes, the figures are re-measured and re-dated rather than
edited in place.
