# The demonstration

A deliberately malicious third-party action, run against two pipelines: one
naive, one hardened. It succeeds against the first and fails against the second,
and both halves are asserted — a demonstration where the attack silently fails
to work in the first place proves nothing at all.

## What is deliberately fake, and why

The action exfiltrates `DEMO_FAKE_TOKEN`, a value this repository generates for
the run. It is **not** a real `GITHUB_TOKEN` and never has been.

That is a deliberate limitation, not an accident. A public, reproducible
demonstration that moves a live credential is a demonstration that will one day
move a live credential by mistake. What is being demonstrated is that a
third-party step can read whatever the job holds and send it anywhere it likes —
the value's provenance changes nothing about that mechanism, and substituting a
real token would change nothing about the result except the blast radius.

The collector is bound to loopback and stores what it receives in memory for the
duration of the run.

## The three acts

| | Pipeline | Outcome | Blocked by |
|---|---|---|---|
| 1 | Naive | Token reaches the collector | nothing |
| 2 | Hardened | Action never executes | policy gate — unpinned reference (I1) |
| 3 | Hardened, action pinned and allowlisted | Action executes, reaches nothing | egress deny (I4), scoped secrets (I2), unattested artifact refused at admission (I3) |

Act 3 is the one worth reading. It grants the attacker everything the gate would
have taken away — a pinned, allowlisted, deliberately malicious action running
inside the job — and the remaining three invariants still hold.

## Running it

```bash
make demo          # locally, as a simulation of the pipeline semantics
```

The local run drives the real `ppv gate` and `ppv verify` and a real loopback
collector. What it does **not** reproduce is a GitHub runner's network stack:
act 3's egress denial is stood in for locally by an unroutable destination.

The `demonstration` job in `.github/workflows/ci.yml` closes that gap. It runs
the same three acts on a hosted runner behind a default-deny egress policy whose
allowlist omits every external host, and then runs
[`prove_egress_denied.sh`](prove_egress_denied.sh), which reaches for an unlisted
host and **fails the build if the request succeeds**. No test running inside the
job could establish that on its own — a control that is declared and not in
force is worse than no control, because it reads as one.

Both steps are blocking, and the suite fails if it collects fewer than three
tests or skips any.
