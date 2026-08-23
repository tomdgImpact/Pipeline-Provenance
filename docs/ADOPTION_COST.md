# What adopting this costs

The rest of this documentation says what the four invariants do and why they are
placed where they are. This document says what they cost a team that adopts
them, because that is the decision actually being made. It does not argue for
adoption. It prices it, including the cases where the price is not worth paying.

**Two kinds of number appear below, and they are labelled.**

- **Measured** — from the committed harness output in
  [`benchmarks/published/`](../benchmarks/published/) or from this repository's
  own history, with the file or commit named. Reproducible from a clean
  checkout.
- **Estimate** — a reasoned range with the assumptions that drive it stated next
  to it. Not a measurement, and not presented as one.

Where neither is available the answer below is "unknown". That happens more than
once, and each time is marked.

---

## 1. The starting position

**Measured** — `benchmarks/published/distribution-2026-08-20.json`, ruleset
2026.08.1, fourteen widely-used open-source projects, 101 workflow files:

| Invariant | Projects passing | Projects failing |
|---|---|---|
| I1 nothing runs unpinned | 0 / 14 | 14 / 14 |
| I2 secrets scoped to the job | 0 / 14 | 14 / 14 |
| I3 verifiable provenance | 4 / 14 | 10 / 14 |
| I4 egress denied by default | 0 / 14 | 14 / 14 |

I3 is the only invariant of the four that a repository can pass without doing
anything. The rule emits no finding when no job produces a deployable artifact
(`src/pipeline_provenance/rules/i3_provenance.py`), so a repository that ships
nothing passes it by absence rather than by control. Nothing in the sample
passes I1, I2 or I4 by any route.

The shape of an average project in that sample, **measured** from the same file:

| Quantity | Per project | Derivation |
|---|---|---|
| Workflow files | 7.2 | 101 / 14 |
| Jobs with no egress policy at all | 15.8 | 221 findings / 14; the rule fires once per job |
| Findings of every severity | 66 | 925 / 14, summed over the eleven rule classes that fired |

Inherit the sample's caveats with the numbers: it is small and deliberately
chosen rather than random, only `.github/workflows` was read, reusable workflows
called from other repositories were not followed, and I4 was assessed by
declaration because no runner was observed.

**The reference repository.** Every effort estimate below is for one repository
of roughly that shape: ~7 workflow files, ~16 jobs, ~30 third-party action
references, GitHub-hosted runners, one language ecosystem with a committed
lockfile. I1, I2 and I4 scale close to linearly with repository count. I3 does
not, and that turns out to matter (§5.3).

---

## 2. What the audit itself costs

**Measured** — `benchmarks/published/performance-2026-08-20.json`, median wall
clock over 20 repetitions, offline, on `macOS-26.6.1-arm64` / CPython 3.12.13.
The largest target measured is this repository at 3 workflow files: **94.4 ms
median, 120.0 ms maximum**. Every fixture target is under 14 ms.

Two honest consequences. First, the audit is not a line item; below a few
workflow files it is inside the noise of a CI job's startup. Second, the record
does not support extrapolating past three workflow files, and says so — a
monorepo with hundreds of workflows was not measured. What a team actually pays
per gated job is the install step in front of the audit, not the audit.

Reading your own finding list costs nothing and changes nothing:

```bash
ppv audit .                         # or --format html -o ppv.html to circulate it
```

---

## 3. Cost per invariant

### 3.1 I1 — nothing runs unpinned

**Engineering effort to adopt.** *Estimate:* 0.5 to 2 engineer-days for the
reference repository, plus about an hour to turn on Dependabot. The range is
driven by three things, in decreasing order: the number of *distinct* actions
(the lookup is per action, the edit is per reference), whether container base
images are in scope (per image, per Dockerfile), and the ecosystem's lockfile
story — a hash-pinned lockfile is one command in some ecosystems and a migration
in others. Multiply by repository count; there is no shared work to amortise.

**Measured anchor.** This repository carries 45 third-party `uses:` references
across three workflow files — 48 counting its own local actions — and they
resolve to **nine distinct third-party actions**. The number that governs
ongoing cost is nine, not forty-five.

**Ongoing friction.** Updates stop being free. That is not a side effect of the
control, it *is* the control: the ergonomic benefit of a mutable tag is exactly
the attacker's delivery channel ([ADR-0001](adr/0001-pin-by-digest-not-tag.md)).
Concretely, three things change in daily work:

- Every third-party update becomes a pull request with a diff a human has to
  look at. For nine distinct actions on a weekly Dependabot schedule, that is a
  small but permanent increase in review load, and it lands on whoever owns CI.
- Dependabot becomes load-bearing rather than convenient. A pinned set with no
  update mechanism rots, and a rotted pin is a stale vulnerability someone will
  point at later. This is why [`MIGRATION.md`](MIGRATION.md) step 1 puts
  Dependabot in the *same change* as the pinning, not in a follow-up ticket.
- Workflow files become less readable. `actions/checkout@fbc6f39` says less to a
  reviewer than `@v5`. The trailing version comment mitigates this and is itself
  checked (`I1/missing-version-comment`), which is why that rule exists and why
  it is LOW severity rather than an obstacle.

**False-refusal cost.** The gate refuses a reference that cannot be pinned: an
internal action referenced by branch during development, or a publisher who
ships tags and no stable commit to point at. There is no per-finding suppression
in this tool. The only escape hatch is the gate threshold (`--fail-on`), which
is coarse on purpose — accepting one unpinnable reference means leaving the
entire HIGH band off, which is a visible, argued decision rather than a comment
in a file. That coarseness is the cost of not having a suppression syntax, and
it is a deliberate trade (§3.5).

**What breaks first.** In week one, nested-path actions.
`github/codeql-action/upload-sarif` pins to the SHA of the *parent* repository,
not to something per-path, and the first person to try it will assume the tool
is wrong. Docker-based actions are the second. `MIGRATION.md` sequences around
both by putting pinning in a branch of its own, before any gate exists, so the
first encounter with this is a failing local audit rather than a blocked merge.

**What it retires.** **T-02** (action tag repointed after review) and **T-06**
(mutable base image tag replaced between build and deploy). Those are the only
two rows in the fourteen-row attack table whose residual column reads *None*.
I1 also contributes to T-01, T-03, T-04 and T-05 without closing any of them:
pinning is an integrity control, not an identity control, and it faithfully
preserves a typosquatted package pinned on day one.

### 3.2 I2 — secrets scoped to the job that needs them

**Engineering effort to adopt.** *Estimate:* 1 to 3 engineer-days for the
reference repository. Almost none of that is editing. The editing is one
`permissions: {}` per workflow file and a short block per job; the cost is
*discovery* — finding out which jobs were quietly relying on the default token
to do something you did not know they did. You find out by breaking them. The
range is driven by how many jobs write anything at all: comment on pull
requests, push tags, upload SARIF, update a release.

**Ongoing friction.** A job that needs a new scope becomes a pull request. That
is the whole objection and it is a fair one: adding one line to a workflow now
requires someone to agree that the scope is warranted. In exchange, the set of
jobs that can write to the repository is enumerable by reading the workflow
files, which it previously was not.

**False-refusal cost.** Real, and this repository is the example. **Measured:**
`ppv audit .` reports exactly one confirmed finding against this repository
today — `I2/excessive-permission` on the `sast` job, which holds
`security-events: write` in order to upload SARIF to code scanning. The rule is
right that write scope must be argued for; the argument is in
[`THREAT_MODEL.md`](THREAT_MODEL.md) §9. The escape hatch used here is
deliberately expensive: an entry in a test that fails **both** if a new
unaccepted finding appears **and** if this one is fixed without being removed
from the list. There is no comment syntax that silences a finding, by design.

**What breaks first.** The first job that needed the implicit write token. It
fails immediately and loudly with a 403, which is the best kind of failure.
`MIGRATION.md` puts permissions at step 2, after pinning and *before* the gate
exists, so these failures land as a red job on a branch rather than as a refused
merge on someone else's pull request.

**What it retires.** **T-10** (`pull_request_target` executing fork-controlled
code with write scope) and, together with I1, **T-01** (a malicious third-party
action reading `secrets.*`). Partially **T-07** (secrets in log output) — log
redaction is best-effort against a deliberate encoder and the threat model says
so. Residual on T-01 remains: an action legitimately given a secret still has
it.

### 3.3 I3 — provenance emitted and verified at admission

This invariant has two halves with very different prices, and conflating them is
the most common way to mis-plan this adoption.

**Engineering effort to adopt — the emitting half.** *Estimate:* 0.5 to 1
engineer-day for a repository with a single artifact-producing job, mostly spent
adopting the reusable workflow or lifting its attestation steps. Cheap.

**Engineering effort to adopt — the verifying half.** *Estimate:* 1 to 3
engineer-weeks, and the range assumes an admission point already exists — an
admission controller, a registry policy, a deployment gate. If none exists, this
is not an estimate, it is a project, and its size has nothing to do with this
tool. The honest planning question is not "how long does I3 take" but "do we own
a place where something can refuse an artifact".

The verifying half is also the only line item that **does not scale with
repository count**. One admission point serves every repository that deploys
through it. That inverts the usual intuition: the most expensive control here is
the cheapest one to roll out across a fleet.

**Ongoing friction.** Low in daily work, high at one specific moment: the
verifier asserts *identity* — repository, workflow path, trigger, issuer — so
renaming or moving a workflow file changes what production expects to see.
`PPV_EXPECTED_SIGNER_IDENTITY` has no default
([ADR-0002](adr/0002-keyless-signing.md)), which means a misconfigured verifier
refuses everything rather than accepting anything.

One cost that is not engineering time: **signing events are public**. Repository
and workflow names appear in a public transparency log. For a private repository
that is an information-disclosure trade-off which has to be made deliberately,
and it is the one step in the whole migration whose effects cannot be reverted
(§4).

**False-refusal cost.** The measured instance is in this repository's history.
Commit `7704fed` records `ppv` reporting I3 findings against this project's own
CI because a job uploads a Playwright trace on failure and the artifact
heuristic counted a crash dump as a deliverable. The tool was wrong, not the
pipeline. The fix moved the rule — a step guarded by `failure()` or
`cancelled()` is diagnostic by construction — rather than adding a suppression,
and `always()` is deliberately *not* treated as diagnostic because it runs on
success too. Demanding provenance for a crash dump is how a rule teaches
maintainers to ignore it.

**What breaks first.** For most teams, nothing breaks: they reach step 6, find
there is nowhere to put the verification, and stop. `ppv audit` then reports I3
as `unverified`, not as a pass — **measured**, that is exactly what it reports
against this repository today. `MIGRATION.md` sequences attestation (step 5)
before verification (step 6) so there is material to test a verifier against
before anything is allowed to refuse a deployment.

**What it retires.** **T-12** (an unattested artifact deployed because
verification was advisory) and **T-13** (attestation by the wrong identity),
both **only at the admission point**. Emitting provenance and not verifying it
retires nothing at all; it produces a signed statement no one reads. Residual on
T-13: trust in the OIDC issuer itself.

### 3.4 I4 — egress denied by default

**Engineering effort to adopt.** *Estimate:* 2 to 4 engineer-hours of wiring,
plus one calendar week in audit mode, plus 0.5 to 1 engineer-day of allowlist
curation afterwards. The calendar week is not effort and cannot be compressed by
adding people: the allowlist cannot be derived by reading a workflow, only by
observing one.

**Measured anchor.** Commit `828ec8a` applied the guard to this repository after
`ppv` reported **eight jobs with unrestricted outbound network access**. One
commit, +120 lines, eight jobs. The repository's CI now guards ten jobs and
carries 104 allowlist lines; counting the four wrapper lines per job, **144 of
`ci.yml`'s 379 lines — 38 % — are egress declaration**. That is the honest
visual cost of this control, and no amount of YAML tidying makes it disappear
from a reviewer's screen.

**Ongoing friction.** A new dependency host becomes a pull request. Add a test
tool that phones home, switch to a new package mirror, enable a new scanner —
each is a one-line change to an allowlist that someone has to approve. Teams
underestimate how often this happens until the first month.

**False-refusal cost.** The highest of the four, and structurally different from
the others: an I4 refusal happens at *build* time, not at gate time, so it
surfaces as a broken build rather than as a finding with a fix line. The escape
hatches are `mode: audit` — which degrades the control to telemetry and is
reported as `I4/egress-audit-only` (MEDIUM) precisely so the degraded state
cannot be quietly forgotten — and adding the host, which is a pull request.
Neither hides.

**What breaks first.** The host you did not know about. **Measured:** this
repository's own allowlist needed `mirror.gcr.io` and
`pkg-containers.githubusercontent.com`, neither of which anyone would have
written down from memory. `MIGRATION.md` step 3 sequences around this with a
week in `audit` mode before switching to `block`, and requires the guard to be
**the first step of the job** — anything before it runs unrestricted, and the
rule `I4/egress-policy-applied-late` is HIGH severity for that reason.

**What it retires.** **T-08** (secret exfiltrated over the network to an
attacker host) and **T-09** (DNS-channel exfiltration). Residual on both:
exfiltration through an already-allowlisted host. The control raises cost; it
does not close the category.

### 3.5 Why the escape hatches are deliberately awkward

There are exactly four ways to accept a finding in this system, and all four are
visible in version control:

| Hatch | Where it lives | What it costs |
|---|---|---|
| `--fail-on <severity>` | the workflow file | Accepts a whole severity band, not one finding |
| `--allow-unverified` | the workflow file | Off by default; a gate that passes on "I could not tell" is not a gate |
| `mode: audit` on the egress guard | the workflow file | Reported as `I4/egress-audit-only`, so the degraded state stays visible |
| An asserted exception in a test | `tests/security/` | Fails if a new finding appears **and** if the accepted one is fixed without removal |

There is no `# ppv:ignore` comment, and its absence is the point. This project
applied that rule to itself: commit `f4fd770` records its own SAST gate failing
on a `markupsafe.Markup` call, and the choice made was to remove the cause
rather than suppress the finding, because a suppression comment survives a
refactor that reintroduces the risk and a missing import does not.

The consequence is worth stating plainly to anyone approving this adoption: a
hatch that is easy to reach gets reached, and a control everyone has learned to
silence is a control in name only. The awkwardness is the mechanism. It is also
a real cost — a coarse `--fail-on` band means one unfixable finding can hold an
entire severity level hostage. `--invariant` is the narrower axis to reach for
first: it scopes what blocks without silencing what is reported (§6).

---

## 4. Sequencing, and why

[`MIGRATION.md`](MIGRATION.md) orders adoption as **audit → pin → permissions →
egress audit-then-block → gate at a rising threshold → attest → verify**. The
order is not arbitrary and it is not the order of importance. It is sorted by
two things: how cheaply a step can be undone, and how early a step's failures
teach something useful.

**0. Audit first, because it changes nothing.** The finding list is the
denominator for every estimate above. Without it, every number in this document
is someone else's average rather than yours. Reversibility: total, nothing was
changed.

**1. Pin first among the mutations, because it is mechanical.** Every edit is
reviewable line by line, the runtime behaviour of the pipeline is unchanged (the
same code runs, named immutably), and the entire step reverses with one
`git revert`. It must come before the gate: a gate turned on over unpinned
references makes the first red build a fight about the tool instead of a fight
about the reference.

**2. Permissions second, because the failures are fast and local.** Unlike
pinning, this changes behaviour — jobs lose scopes they were silently using. But
a missing scope fails immediately with a clear error, in one job, on a branch.
Doing it before the gate exists means these failures cost a branch, not a merge.
Reversibility: per job, one line.

**3. Egress third, in audit mode, because the input has to be observed.** This
is the only step with an irreducible calendar cost, so it starts early and runs
in the background while other work continues. Audit mode is a deliberately
incomplete state, and the tool refuses to score it as a pass — telemetry is not
a control. Reversibility: change `block` back to `audit`, or remove the step.

**4. Gate fourth, at a rising threshold, because that is what makes it
reversible in practice.** The severity ladder maps onto the finding
distribution, and the mapping is checkable. **Measured** — the eleven rule
classes that fired across the fourteen-project sample, banded by the severity
each rule assigns in `src/pipeline_provenance/rules/`:

| `--fail-on` | Rule classes that begin to block | Findings in the sample |
|---|---|---|
| `critical` | `I2/privileged-trigger`, only where fork-controlled code runs | ≤ 9, in ≤ 3 of 14 projects |
| `high` | `I1/unpinned-action`, `I2/implicit-token-scope`, `I3/no-provenance`, `I4/egress-policy-applied-late` | 194 cumulative |
| `medium` | `I4/no-egress-policy`, `I2/persisted-credentials`, `I3/no-sbom`, `I2/excessive-permission`, `I2/no-default-deny`, `I3/no-admission-verification` | 584 cumulative |
| `low` | `I1/missing-version-comment` | 925 cumulative |

Read the first row again: for eleven of the fourteen sampled projects, turning
the gate on at `critical` blocks **nothing at all** on day one. That is what
makes the gate safe to introduce before the work is finished — and each
subsequent raise is one line and one pull request, so the decision to start
enforcing a class of finding is recorded in history and reversed the same way.
The largest single class, 341 missing version comments, is LOW and therefore
blocks last, which is the correct order: it is the cheapest to fix and the least
dangerous to leave.

**5. Attest fifth, because it produces material rather than enforcing
anything.** It is cheap, it breaks nothing, and step 6 needs something to
verify. **This is the one step whose effects leave the repository**: signing
publishes repository and workflow identity to a public transparency log, and a
published log entry cannot be withdrawn
([ADR-0002](adr/0002-keyless-signing.md)). Every other step in the migration
reverses with a revert. This one reverses for future builds only. For a private
repository, that is a decision to make before the first signed build, not after.

**6. Verify last, because it is the only step that requires infrastructure
outside the repository** — and because until something refuses an artifact,
everything above it is preparation. It goes last not because it matters least
but because it is the only step whose prerequisite is organisational rather than
technical. It stays reversible by running the admission policy in a warning mode
before it refuses anything, which is the same audit-then-block shape as step 3.

The property worth holding onto across all seven steps: **no step requires the
previous one to be complete**, only started. That is what allows a team to stop
at step 3 for two quarters without the work done so far decaying — with the
single exception of pinning, which decays without Dependabot, which is why
Dependabot is inside step 1 rather than after it.

---

## 5. When not to adopt this

### 5.1 No admission point — I3 buys you a label

If nothing in your deployment path can refuse an artifact, steps 5 and 6 produce
a signed statement that nobody reads. `ppv audit` reports I3 as `unverified`
rather than failing, because a control outside the repository is not something a
static tool can see — and **measured**, that is exactly what it reports against
this repository, which ships a library and a workflow and does not own the
admission point for either.

[ADR-0004](adr/0004-verify-at-admission.md) states the consequence without
softening it: where a team has no admission point, the honest answer is that I3
is not enforced for them. Build-time verification is not a substitute; it runs
inside the untrusted context it is supposed to be checking, which is fast
feedback and zero security value against the adversary named in the threat
model. A team in this position should adopt I1, I2 and I4, emit attestations if
it is cheap, and treat I3 as a planned dependency on infrastructure it does not
yet have.

### 5.2 Self-hosted runners — I4 cannot be enforced, and the tool says so

The egress guard emits a warning on self-hosted runners rather than pretending
to work (`.github/actions/egress-guard/action.yml`), and I4 is reported as
unverified rather than claimed. T-11 — persistence across jobs on a self-hosted
runner — is listed in the attack table as **fully residual**: documented, not
enforced, and the audit tool reports on it without remediating it.

A self-hosted team gets I1, I2 and I3 at full value and I4 as documentation.
That is three quarters of the model, and it is worth saying out loud during
planning rather than discovering in week three.

### 5.3 A repository that ships nothing

If no job produces a deployable artifact, there is no supply chain downstream of
this repository and I3 does not apply — it passes by absence, which is what four
of the fourteen sampled projects do.

Do not extend that conclusion to the other three invariants. A repository that
ships nothing still runs third-party code on every push and still holds a job
token; asset A1 in the threat model exists whether or not anything is built. The
correct scope for such a repository is I1, I2 and I4, with I3 explicitly marked
not applicable rather than left looking unfinished.

### 5.4 No protected branch, no required status check

The policy gate is structural only because a required status check makes it
unskippable. Without one, a contributor can push a branch that removes it —
T-14, whose residual is that a repository administrator can remove the
requirement anyway. Adopting the gate without branch protection buys a signal in
a pull request, not a control, and pricing it as a control will make the first
bypass look like a tool failure. Fix branch protection first; it is cheaper than
everything in this document.

### 5.5 Not GitHub Actions, or workflows that live somewhere else

The threat model's reasoning transfers to other platforms; its enforcement
points do not. The audit tool reads `.github/workflows` and nothing else, and
`ppv doctor` reports remote reference resolution as **UNAVAILABLE** at this
milestone. An organisation that centralises its pipelines in a shared workflow
repository will get a partial reading of any repository that calls them — the
distribution benchmark carries the same caveat for the same reason. That is a
limitation of the measurement rather than of the invariants, but it means the
finding list underestimates rather than overestimates, and a plan built on it
will be short.

---

## 6. The cheapest useful step

If a team does exactly one thing: **pin every third-party action to a commit
digest, and enable Dependabot in the same change.** Step 1 of the migration, and
nothing else.

**What it costs.** *Estimate:* 0.5 to 2 engineer-days per repository, plus a
permanent, small increase in review load proportional to the number of distinct
actions — nine, in this repository's case, not the forty-five references that
resolve to them.

**What it buys.** T-02 and T-06 stop being reachable. Those are the only two
rows in the fourteen-row attack table whose residual column reads *None*; every
other control in this project narrows a threat without closing it. It also
removes the specific scenario this project is named after — a third-party action
you pinned to a tag reading every secret in the job, because the tag was
repointed after you reviewed it.

**What it does not buy, and saying so is part of the recommendation.** It does
not enforce anything: until a required status check runs the gate, pinning is a
convention, and conventions drift. It does not judge whether the thing you
pinned was the right thing — a typosquatted package pinned on day one is
faithfully preserved (T-03, T-04). It does nothing about secret scope or egress.
And it is the step most likely to rot, which is why Dependabot is not an
optional half of this recommendation.

**Why not "just run the audit".** Running `ppv audit` is cheaper still and it is
the right first move, but it is not the answer to this question: it buys a
number, not a retired threat row. A finding list that nobody acts on is
expensive in a different currency — the second time a team looks at an unchanged
list, they stop looking.

**How to enforce exactly this and nothing else.** Scope the gate to the
invariant you have actually adopted:

```bash
ppv gate . --invariant I1
```

Everything is still audited and every finding is still printed — narrowing the
gate does not narrow the report. What changes is what fails the build. The
verdict line names the gap on both the passing and the failing path:

```
gate: enforcing I1 only. NOT enforced: I2, I3, I4 — 5 finding(s) reported and not blocked.
gate: passed for I1.
```

That wording is deliberate. `gate: passed` on a gate covering one invariant of
four would be read as compliance by everyone downstream of it, which is the
failure this whole project argues against. A partial gate is a legitimate
adoption step; a partial gate that looks like a full one is not.

Add invariants to the flag as you adopt them. `--fail-on` still applies within
the scope, so the two axes compose: `--invariant I1 --invariant I2 --fail-on
high` enforces the two you have done, at the band you can hold.
