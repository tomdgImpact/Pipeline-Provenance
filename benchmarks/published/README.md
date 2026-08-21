# Published figures

Every number quoted in `README.md` is here, as the raw output of the harness
that produced it, dated and stamped with the ruleset version. A figure a reader
cannot re-derive is a figure they have to take on trust, and this project asks
for less trust than that.

| Figure | Answers | Current record | Reproduce with |
|---|---|---|---|
| detection | SC-001, SC-002 — precision and recall against declared intent | `detection-2026-08-21.json` | `python -m benchmarks.detection --json` |
| performance | SC-008 — audit wall clock, with the machine named | `performance-2026-08-21.json` | `python -m benchmarks.performance --json` |
| distribution | SC-003 — invariant distribution across public repositories | `distribution-2026-08-20.json` | `python -m benchmarks.distribution --online --output <file>` |

Earlier records are kept rather than deleted, so a reader can see how a figure
moved. The README always quotes the newest of each family, and
`tests/security/test_self_conformance.py` asserts it — by globbing for the most
recent file, not by naming a date, because a test pinned to a date keeps passing
against a record the README has stopped quoting.

`benchmarks/results/` is scratch and is ignored. This directory is the record.

Figures are only comparable against the ruleset version recorded inside them.
When the ruleset changes, the figures are re-measured and re-dated rather than
edited in place.
