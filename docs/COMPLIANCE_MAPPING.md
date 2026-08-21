# Compliance mapping — what the four invariants are, and are not, evidence for

**Status:** version 1, 2026-08-21. Every framework version, date and clause
reference in this document was verified on **2026-08-21** against the sources
listed in [§8](#8-verification-log). Revisit on the review triggers in
[§9](#9-review-triggers).

**Audience:** a security leader who has to answer "where does this leave us"
to an auditor, a board, or a customer's procurement team.

---

## 1. Read this first: a technical control is not compliance

This is the load-bearing statement of the document, and it is not a
disclaimer bolted on for safety. It is the reason the document exists.

**Passing a technical control does not make an organisation compliant.**
Compliance is a determination — made by an auditor, a certification body, a
market surveillance authority or a supervisor — about an *organisation*,
against *evidence*, under a *scope* they define. It is not a property a CI
pipeline can hold. A pipeline can produce evidence. Whether that evidence is
sufficient is somebody else's decision, and they are entitled to reach a
different one.

Three consequences, stated plainly:

1. **An auditor may reject every mapping in this document.** The rows below
   are arguments, not findings. Each one asserts that a control produces
   something an assessor would plausibly want; none of them asserts that an
   assessor accepted it. Where a mapping rests on analogy rather than on the
   clause's own words, the row says so.

2. **Organisational controls cannot be executed as code and are out of scope
   here.** Governance and management accountability, risk acceptance,
   documented policy, roles and responsibilities, security training, supplier
   contracts and due diligence, incident reporting to authorities, record
   retention over a product's support period, and the periodic review of all
   of the above. These are the *majority* of every framework in this
   document. Nothing in this repository touches them, and no amount of
   pipeline hardening substitutes for them.

3. **Nothing here is legal advice**, and the scoping question — does this
   regulation apply to us at all — is answered by counsel and by the facts of
   the business, not by a mapping table.

One more, specific to this project: **`ppv` does not emit a compliance score,
a SLSA level, or a framework coverage percentage, and no such output is
planned.** A `ppv` pass means four named invariants hold. Anyone quoting a
`ppv` result as a compliance result is misquoting it, and the tool
deliberately gives them nothing to misquote.

## 2. How to read a claim

Every row in this document carries exactly one of three values. The
distinction between the first two is the whole point: conflating them is what
destroys credibility with an auditor, because the moment one over-claim is
caught, every other claim in the submission is re-opened.

| Claim | What it means | What it still requires |
|---|---|---|
| **Satisfies** | The control, as implemented, does the thing the clause asks for, across the scope the clause covers. | Evidence retention, an owner, and the assessor's acceptance. "Satisfies" is a technical statement, never a compliance verdict. |
| **Contributes evidence** | The control enforces a property or produces an artifact an assessor would want to see, but the clause asks for more than the control does. | Everything above, plus the rest of the clause — usually the organisational half. |
| **Does not touch** | The clause is outside what these four invariants do. Listed explicitly in [§7](#7-coverage-honesty), never silently omitted. | A different control, owned by somebody else. |

Across this entire document, **two** clauses are claimed as *Satisfies*, both
in NIST SSDF. Nothing in the CRA, NIS2 or DORA sections is. That ratio is the
honest answer, not a modest one.

The four invariants themselves are defined in
[`README.md`](../README.md) and [`docs/THREAT_MODEL.md`](THREAT_MODEL.md) §5.
Those documents are the source of truth for what the controls do; this one
only maps them.

---

## 3. SLSA Build track — the defensible mapping

**Framework version:** SLSA **v1.2**, status *Approved*, announced November
2025. Verified 2026-08-21 against `slsa.dev/spec/v1.2/about` (status) and the
release announcement on `slsa.dev/blog`. v1.2 is documented as backwards
compatible with v1.1; the Build track requirement names below are quoted from
`slsa.dev/spec/v1.2/build-requirements` as read on 2026-08-21. The Build
Environment track and the Dependency track are named as *in development* in
that announcement and are therefore not mapped.

This is the most defensible mapping in the document because SLSA describes
build integrity in the same terms this project does, and because its levels
attach to an artifact's provenance rather than to an organisation.

### 3.1 Where the invariants place a consumer

The subject of a SLSA level is a **build**, not a repository. The assessment
below is of a consumer building through
[`.github/workflows/hardened-build.yml`](../.github/workflows/hardened-build.yml)
on GitHub-hosted runners, and verifying at an admission point per
[ADR-0004](adr/0004-verify-at-admission.md).

**Result: SLSA v1.2 Build L2, including the consumer half that most
implementations skip. Not Build L3** — one of the two L3 requirements is no
longer failed (§3.2, a defect this analysis found and closed), the other is a
platform property this project cannot evidence (§3.3). Not-failed is not
satisfied, and the claim stays at L2 until someone other than its author says
otherwise.

| Build track requirement | Level | Met? | Why |
|---|---|---|---|
| *Provenance Exists* — the build process generates provenance identifying the output by cryptographic digest | L1 | **Yes** | `actions/attest-build-provenance` emits an in-toto statement bound to the artifact's digest ([ADR-0003](adr/0003-provenance-and-sbom-pair.md)) |
| *Hosted* — "All build steps ran using a hosted build platform" | L1–L3 | **Yes** | Default `runs-on: ubuntu-24.04`, a GitHub-hosted runner. A consumer overriding `runs-on` with a self-hosted runner voids this row and T-11 applies |
| *Provenance is Authentic* — provenance generated by the control plane, not by a tenant; consumers able to validate authenticity | L2 | **Yes** | GitHub's attestation service signs; the tenant workflow does not hold the signing key. GitHub documents that "Artifact attestations by itself provides SLSA v1.0 Build Level 2" (verified 2026-08-21) |
| *Consumer validates the authenticity of the provenance* | L2 | **Yes** | This is I3, and it is the half normally missing. `ppv verify` runs `cosign verify-blob-attestation` with an explicit `--certificate-identity`, refuses to run with no expected identity configured, and refuses rather than degrades when the backend is unreachable (`src/pipeline_provenance/attest/verify.py`) |
| *Provenance is Unforgeable* — "secret material used for authenticating the provenance … MUST NOT be accessible to the environment running the user-defined build steps" | L3 | **Not failed** | Caller-supplied build steps run in a job holding no signing scope; attestation happens in a separate job that runs no caller code. Not claimed as satisfied — see §3.2 |
| *Isolated* — overlapping builds cannot influence one another; a build cannot persist into a subsequent build environment | L3 | **Unevidenced** | See §3.3 |

### 3.2 Unforgeable provenance — a gap this analysis found, and closed

Writing this mapping surfaced a real defect in the shipped workflow, which has
since been fixed. It is recorded here rather than quietly overwritten, because
how a gap was found and closed is more informative than a table that was always
green.

**The defect.** `hardened-build.yml` executed `${{ inputs.build-command }}` —
arbitrary, caller-supplied — in the **same job** that held `id-token: write` and
`attestations: write`. GitHub exposes `ACTIONS_ID_TOKEN_REQUEST_TOKEN` to every
step of such a job, so a malicious build command could request that token and
obtain an attestation for an artifact of its choosing, under the reusable
workflow's identity. A valid signature over something nobody here built:
[`THREAT_MODEL.md`](THREAT_MODEL.md) row **T-13**, reachable without
compromising anything.

GitHub documents that reusable workflows plus artifact attestations reach SLSA
Build Level 3 (verified 2026-08-21). That pattern assumes the reusable
workflow's build steps are **fixed by the workflow's owner**. Accepting
`build-command` as a caller input re-opened the hole — tenant-controlled code
inside boundary B2 with B3's signing material in reach.

**The fix, and why it is structural.** The workflow now runs the caller's build
command in a `build` job holding **no write scope at all**, uploads the raw
output, and attests it in a separate `attest` job that runs no caller-supplied
code — only actions pinned by digest. The signing identity is not reachable from
anything the caller controls.

A warning in this document would not have been a fix. The property is enforced
by `tests/security/test_signing_identity_isolation.py`, which runs in the
adversarial corpus — its own blocking CI step, which fails if the suite collects
nothing or skips anything. It fails if **any** job in **any** shipped workflow
holds `id-token: write` or `attestations: write` while a caller-supplied input
reaches execution: in a `run:` block, through a job- or step-level `env:` value
(a caller who writes `PATH` or `BASH_ENV` chooses what a later step runs), or
through a `with:` input to one of this repository's own composite actions, which
interpolate their inputs into `run:` blocks. It was run against the defective
workflow at commit `af740da^` and fails there, naming the offending `Build` step;
a companion test asserts the converse, that the job which does run the caller's
command holds no write scope at all. `tests/e2e/test_shipped_workflow.py` asserts
the same split as part of the shipped workflow's shape.

Two things that test does **not** establish, named so its green is not read as
covering them. A caller-supplied value passed to a digest-pinned *third-party*
action is not flagged, because whether it reaches a shell is a property of that
action which a static check cannot see. And `runs-on: ${{ inputs.runs-on }}`
is not flagged: a caller pointing the attesting job at a runner they control is
a real exposure, but it is **T-11** — documented, explicitly not enforced, and
already carried as residual in the *Hosted* row of §3.1.

**Status:** *Provenance is Unforgeable* is no longer failed by this arrangement.
It is not therefore claimed as satisfied — see §3.3, which remains open, and §2
on the difference between a requirement being satisfied and a specific way of
failing it having been removed.

### 3.3 Precisely what is missing for Build L3 (2 of 2): isolation

*Isolated* is a property of the **build platform**, not of a workflow. It is
GitHub's to assert and GitHub's to demonstrate; nothing in this repository can
evidence it, and the audit tool cannot see it. SLSA publishes separate guidance
for assessing build platforms, which is a different exercise from auditing a
workflow.

This is also where the mapping meets the threat model's boundary: a compromised
CI platform is **out of scope** ([`docs/THREAT_MODEL.md`](THREAT_MODEL.md) §3).
The isolation requirement is therefore *inherited on trust*, not evidenced. A
consumer who needs L3 asserted rather than assumed needs a platform assessment
this project does not provide.

### 3.4 What SLSA does not score

Three of the four invariants contribute **nothing to a Build level**:

- **I1 (nothing runs unpinned).** The Build track does not require dependency
  pinning. The Dependency track that would is named as in development, not
  published. I1 remains one of the highest-value controls here and SLSA gives
  no credit for it.
- **I2 (secrets scoped, least privilege).** Touched only obliquely, through
  L3's restriction on access to signing material — which I2's job-scoped
  `permissions:` blocks help with but do not by themselves establish.
- **I4 (egress denied by default).** Not a Build track requirement at any
  level.

**SLSA Source track:** not addressed by any of the four invariants. Worth
naming because T-14 in the threat model — a workflow modified to remove the
policy gate — is answered by required status checks on protected branches,
which is a source-side control this project *depends on* and does not provide.

---

## 4. NIST SSDF (SP 800-218)

**Framework version:** NIST SP 800-218, **Secure Software Development
Framework (SSDF) Version 1.1**, published **February 2022**. Verified
2026-08-21: version and date read from the publication itself; current-version
status confirmed against the NIST SSDF project page at `csrc.nist.gov`, which
lists no superseding revision. SP 800-218A exists as a Generative AI community
profile and is **not** applicable here. Task text below is quoted from SP
800-218 v1.1.

SSDF is a framework of practices, not a certifiable standard: an organisation
adopts it, tailors it, and is measured against its own tailoring — including
under US federal software attestation regimes. That makes precise task-level
mapping useful and over-claiming cheap to catch.

### 4.1 Where the invariants land

| SSDF task | Task text (abridged) | Invariant | Claim | The gap |
|---|---|---|---|---|
| **PS.3.2** | "Collect, safeguard, maintain, and share provenance data for all components of each software release (e.g., in a software bill of materials [SBOM])" | I3 | **Satisfies** | For releases built through the hardened workflow only. The task's Example 3 — protecting provenance integrity and giving recipients a way to verify it — is the signature; Example 4 — updating provenance whenever components change — is met by regenerating both documents every build |
| **PS.2.1** | "Make software integrity verification information available to software acquirers" | I3 | **Satisfies** | With one caveat an assessor may press: the task's Example 2 speaks of "an established certificate authority for code signing". This project signs keyless through Sigstore/Fulcio ([ADR-0002](adr/0002-keyless-signing.md)). An assessor used to long-lived code-signing certificates may not accept a short-lived Fulcio certificate plus a transparency log as equivalent. The argument is in the ADR; it is an argument |
| **PS.3.1** | "Securely archive the necessary files and supporting data (e.g., integrity verification information, provenance data) to be retained for each software release" | I3 | Contributes evidence | The workflow uploads the artifact and SBOM with `retention-days: 14`. That is CI artifact retention, not a release archive. A retention policy per release is the consumer's to own, and 14 days will not satisfy anyone's |
| **PS.1.1** | "Store all forms of code – including source code, executable code, and configuration-as-code – based on the principle of least privilege" | I2 | Contributes evidence | I2 governs the token's access to the repository — explicit per-job `permissions:`, `persist-credentials: false`, no `pull_request_target`. It says nothing about who can access the repository as a human, which is most of what the task means |
| **PW.4.1** | "Acquire and maintain well-secured software components … from commercial, open-source, and other third-party developers" | I1 | Contributes evidence | Pinning makes acquisition *reproducible*, not *well-secured*. The task's Example 1 is reviewing and evaluating the component; I1 does no evaluation. Threat model T-03/T-04: pinning is an integrity control, not an identity control |
| **PW.4.4** | "Verify that acquired … third-party software components comply with the requirements … throughout their life cycles" | I1, I3 | Contributes evidence | The SBOM makes the "throughout their life cycles" question *answerable*. Nothing in the four invariants answers it. Continuous vulnerability checking against the SBOM is out of scope here |
| **PO.3.1** | "Specify which tools or tool types must or should be included in each toolchain …" | I1, I2 | Contributes evidence | The policy gate constrains which third-party actions may run and how they must be referenced. The task wants a defined toolchain policy; the gate enforces four properties of one |
| **PO.3.2** | "Follow recommended security practices to deploy, operate, and maintain tools and toolchains" | I1, I2, I4 | Contributes evidence | Matches the task's Example 3 (pipelines-as-code) squarely. Explicitly **not** matching Example 4, reproducible builds — [ADR-0005](adr/0005-reproducibility-claim.md) declines any general reproducibility claim and this document does not smuggle one in |
| **PO.3.3** | "Configure tools to generate artifacts of their support of secure software development practices" | I3 | Contributes evidence | The attestation set, and `ppv`'s JSON/SARIF output, are precisely such artifacts. The task's Example 3 also asks for enforced retention policies for that artifact data — see PS.3.1 above; not met |
| **PO.4.1**, **PO.4.2** | Define criteria for software security checks, and implement mechanisms to gather the information supporting them | I1–I4 | Contributes evidence | The four invariants plus a blocking `ppv gate` are a working instance of the pattern. The *criteria* remain the organisation's to define and to justify; this project supplies four of them and no basis for choosing them over others |
| **PO.5.1** | "Separate and protect each environment involved in software development" | I2, I4 | Contributes evidence — **by analogy, and an assessor may reject it** | The task's Example 2 is network segmentation between environments. I4 segments a *job's egress*, not an environment; I2 segments *privilege between jobs*. Both are the right shape at the wrong granularity. This is the weakest row in the table and is flagged rather than dressed up |
| **RV.1.1** | "Gather information from software acquirers, users, and public sources on potential vulnerabilities in the software and third-party components that the software uses" | I3 | Contributes evidence | The SBOM is the input that makes this tractable. The gathering, the monitoring and the investigation are untouched |

### 4.2 What SSDF asks for that these invariants do not do

Twenty-nine of SSDF v1.1's 42 tasks are untouched. Named, because a coverage
figure without the list is a number to hide behind:

- **All of PO.1 and PO.2** (security requirements, roles, training, management
  support) — organisational, by definition.
- **PO.5.2** (secure and harden development endpoints). This is the runner
  question. T-11 in the threat model is *fully residual*: self-hosted runner
  hardening is reported by the audit tool and not enforced by anything.
- **PW.1, PW.2** (secure design, design review against security requirements).
- **PW.4.2, PW.5.1** (creating well-secured components and well-secured code).
- **PW.6.1, PW.6.2** (compiler, interpreter and build tool hardening). Nothing
  in the four invariants inspects build tool flags.
- **PW.7, PW.8** (human code review; executable testing). The repository runs
  SAST and tests, but that is not one of the four invariants and is not
  claimed here.
- **PW.9** (secure default settings for the shipped software).
- **RV.1.2, RV.1.3, all of RV.2 and RV.3** (vulnerability analysis, disclosure
  policy, remediation, root-cause review). The entire *Respond to
  Vulnerabilities* group is essentially untouched: I3 hands a responder an
  SBOM and stops.

---

## 5. EU regulation — only where an obligation maps to a control

Mapped narrowly and on purpose. These instruments impose obligations on
organisations and on products placed on a market; a build control can at most
produce evidence toward the technical fraction of one. **No row in this
section claims *Satisfies*.**

### 5.1 Cyber Resilience Act — Regulation (EU) 2024/2847

**Status and dates**, verified 2026-08-21 against the European Commission's
CRA pages on `digital-strategy.ec.europa.eu`:

| Milestone | Date |
|---|---|
| Entered into force | 10 December 2024 |
| Chapter IV (notification of conformity assessment bodies) applies | 11 June 2026 |
| Article 14 (manufacturers' reporting obligations) applies | **11 September 2026** |
| Main obligations apply | 11 December 2027 |

**Applicability:** manufacturers of products with digital elements placed on
the EU market. Whether a given organisation is a manufacturer under the CRA is
a legal question, not a technical one.

**Reading this on 2026-08-21:** the Article 14 reporting obligation begins in
roughly three weeks. **Nothing in this project helps with it.** Reporting an
actively exploited vulnerability to ENISA and a national CSIRT within the
regulation's deadlines is a process with an on-call owner. Naming that, three
weeks out, is more useful than any mapping row below.

| CRA provision | Invariant | Claim | Why not more |
|---|---|---|---|
| **Annex I, Part II, point (1)** — identify and document vulnerabilities and components, including by drawing up a software bill of materials in a commonly used, machine-readable format covering at least the top-level dependencies | I3 | Contributes evidence | The **format** half is met and then some: CycloneDX JSON, machine-readable, regenerated every build, covering more than top-level dependencies. The **obligation** half is not: it runs across the product's support period, the SBOM belongs in the technical documentation retained under the CRA's documentation regime, and a 14-day CI artifact retention discharges none of that. See PS.3.1 in §4.1 — the same gap, twice |
| **Annex I, Part I, point (2)(a)** — made available on the market without known exploitable vulnerabilities | — | **Does not touch** | None of the four invariants asks whether a component has a known vulnerability. I1 pins; it does not judge. Stated because the SBOM row above invites exactly this over-reach |
| **Annex I, Part II, point (3)** — apply effective and regular tests and reviews of the security of the product | — | **Does not touch** | Product security testing, not pipeline structure |
| **Annex I, Part II, points (2), (4)–(8)** — remediation without delay, disclosure of fixed vulnerabilities, coordinated vulnerability disclosure policy, information sharing, secure update distribution, free and timely updates | — | **Does not touch** | Process and product obligations across the support period |
| **Article 14** — reporting actively exploited vulnerabilities and severe incidents | — | **Does not touch** | See above |

Clause-numbering note: the CRA's Annex I point references above were confirmed
on 2026-08-21 against two independent renderings of the Official Journal text
(`cyberresilienceact.eu`, `cra-facts.com`), which agree on both numbering and
wording. The EUR-Lex HTML rendering could not be retrieved directly at
verification time. **Confirm against EUR-Lex before quoting these references
in anything submitted to an authority.**

### 5.2 NIS2 — Directive (EU) 2022/2555

**Article 41 transposition deadline: 17 October 2024**, verified 2026-08-21.

**France — no transposed obligation to map to, as of the verification date.**
The transposition vehicle is the bill on the resilience of critical
infrastructure and the strengthening of cybersecurity (cited in the official
record as *projet de loi relatif à la résilience des infrastructures critiques
et au renforcement de la cybersécurité*), which also carries the CER directive
and DORA's national provisions. Verified 2026-08-21
against the Assemblée nationale legislative dossier (DLR5L17N50731) and ANSSI's
own transposition FAQ on `cyber.gouv.fr`:

- Tabled 15 October 2024, accelerated procedure engaged.
- Adopted by the Senate in first reading, 12 March 2025.
- Special commission report filed at the Assemblée nationale, 10 September 2025.
- **No definitive adoption or promulgation found in the official sources
  checked on 2026-08-21.** The ANSSI FAQ consulted was itself last updated
  2025-09-19, and states that NIS2 enters into force in France only once the
  law *and* the implementing decrees and orders are promulgated.

Two honest qualifications. First, absence of evidence in the sources checked is
not proof of non-adoption — **re-verify before relying on this**. Second, and
more consequentially: the technical requirements are deferred to implementing
decrees and ANSSI reference frameworks that **do not yet exist**. Any French
entity's concrete obligations will be set by texts nobody has read. A mapping
against the directive's own Article 21 is therefore the most that can be said,
and it is a mapping against a directive, not against the law that will bind.

Because NIS2 is a directive, obligations bind through national law. An entity
in a Member State that has transposed is bound by *that* law, whose wording may
differ from the Article 21 text below.

| NIS2 provision | Invariant | Claim | Why not more |
|---|---|---|---|
| **Article 21(2)(d)** — "supply chain security, including security-related aspects concerning the relationships between each entity and its direct suppliers or service providers" | I1 | Contributes evidence | I1 constrains what third-party code executes and freezes it to an immutable reference. The clause is about *relationships with suppliers* — assessment, contracts, the quality of the supplier's own practices. That is procurement work, and I1 does none of it |
| **Article 21(2)(e)** — "security in network and information systems acquisition, development and maintenance, including vulnerability handling and disclosure" | I1, I2, I3 | Contributes evidence | Reaches the *development* half: what enters a build, at what privilege, and what the artifact carries out. "Vulnerability handling and disclosure" is entirely untouched — no intake, no triage, no advisory, no disclosure policy |
| **Article 21(2)(a)–(c), (f)–(j)** — risk analysis policy, incident handling, business continuity, effectiveness assessment, cyber hygiene and training, cryptography policy, HR security and access control, MFA | — | **Does not touch** | Eight of the ten points |
| **Article 20** — management body approval and accountability, and training obligations for management | — | **Does not touch** | Named specifically because it is the clause most often forgotten by technical programmes, and it carries personal accountability |

### 5.3 DORA — Regulation (EU) 2022/2554

**Applies from 17 January 2025**, verified 2026-08-21. Directly applicable in
all Member States — no transposition required, which is why DORA binds today
where NIS2 in France does not.

**Applicability:** financial entities within DORA's scope, and — under a
separate regime — ICT third-party service providers designated as critical.
Whether an organisation is in scope is a legal determination.

| DORA provision | Invariant | Claim | Why not more |
|---|---|---|---|
| **Article 9** (protection and prevention) — policies ensuring resilience, continuity and availability, and "high standards of availability, authenticity, integrity and confidentiality of data"; preventing impairment of authenticity and integrity of information assets | I3 | Contributes evidence | A signed provenance statement verified at an admission point is a concrete mechanism for the *authenticity and integrity* of an ICT asset entering production. Article 9 asks for policies, monitoring and controls across all ICT systems; I3 covers one artifact class at one gate |
| **Commission Delegated Regulation (EU) 2024/1774, Article 16** — policy and procedure governing acquisition, development and maintenance of ICT systems, including testing and approval of ICT systems prior to use | I1, I3 | Contributes evidence | The policy gate before third-party code runs, and admission verification before production accepts, are two enforced approval points. The RTS requires a *documented policy* commensurate with criticality; code is not a policy, and this project ships no policy template |
| **Commission Delegated Regulation (EU) 2024/1774, Article 17** — ICT change management procedure | — | **Does not touch** | Named to mark the boundary: the invariants gate what a change may execute and produce, not how a change is requested, assessed, approved and recorded |
| **Articles 28–30** — ICT third-party risk strategy, register of information, preliminary concentration-risk assessment, key contractual provisions | — | **Does not touch**, and the confusion is worth naming | DORA's third-party chapter is about **contracted ICT service providers** — the register, the exit strategy, the mandatory contract terms. It is not about npm or PyPI dependencies. Presenting a pinning control or an SBOM as Chapter V evidence is a category error that a financial supervisor will catch, and it costs credibility on everything else in the submission |

---

## 6. Residual risk, carried forward

Nothing in this document changes the accepted residual risk in
[`docs/THREAT_MODEL.md`](THREAT_MODEL.md) §9. Four items bear directly on how
much weight any mapping above can hold:

1. **Provenance proves origin, never correctness.** A signed attestation for a
   backdoored artifact is a valid attestation. A SLSA level is a statement
   about a build process, never about the software it produced. Any assessor
   told "we are SLSA Build L2" and left to infer "therefore the software is
   sound" has been misled, whether or not that was intended.

2. **A compromised runner host, CI platform, or repository administrator
   defeats everything here** — including the required status checks that make
   the policy gate structural (T-14). This is not a gap to be closed by
   configuration; it is the boundary of the design. It also means SLSA's
   *Isolated* requirement (§3.3) is inherited on trust from GitHub, not
   evidenced by anything in this repository.

3. **I4 is assessed by declaration only.** The audit tool reads a declared
   egress allowlist; it does not observe a runner's network behaviour. Every
   row above that leans on I4 leans on a declaration. And an allowlisted host
   is still a channel: the control raises the cost of exfiltration, it does
   not close the category (T-08).

4. **First-resolution pinning inherits whatever was resolved first.** A
   typosquatted package pinned on day one is faithfully preserved forever
   (T-03, T-04). Every I1 row above should be read as "the same code runs
   every time", never as "the right code runs".

---

## 7. Coverage honesty

Percentages are given only where a **verified denominator** exists. Where one
does not, no percentage is given and the reason is stated — a fabricated
denominator makes a coverage figure worse than no figure at all.

| Framework | Denominator (verified) | Touched | Satisfied | Touched % |
|---|---|---|---|---|
| **SLSA v1.2 Build track** | Not a percentage — see note below | Build L2 of L3 reached | — | — |
| **SLSA v1.2 Source track** | 0 of the four invariants address it | 0 | 0 | **0%** |
| **NIST SSDF v1.1** | 42 active tasks (19 practices; 5 tasks in the table are "moved to" pointers and excluded) | 13 | 2 | **31% touched, 5% satisfied** |
| **CRA Annex I, Part II** (vulnerability handling) | 8 points | 1 | 0 | **13%** |
| **CRA Annex I, Part I, point (2)** (product properties) | 13 sub-points, (a)–(m) | 0 | 0 | **0%** |
| **NIS2 Article 21(2)** | 10 points, (a)–(j) | 2 | 0 | **20%** |
| **DORA** | **No verified denominator** | 2 provisions | 0 | **Not given** — DORA's articles were not enumerated against a primary source during verification, so any percentage would be invented. Two provisions are mapped; the rest is unassessed, which is not the same as untouched |

A percentage against a *clause count* is a weak metric in both directions: it
treats a one-line definition and a whole vulnerability-management programme as
equal units, and it says nothing about which clauses carry the weight. It is
given here because refusing to give it invites a worse guess. Read [§4.2](#42-what-ssdf-asks-for-that-these-invariants-do-not-do)
and the *Does not touch* rows in [§5](#5-eu-regulation--only-where-an-obligation-maps-to-a-control)
instead.

**Why no Build track percentage:** SLSA levels are ordinal and cumulative, not
a checklist to score. "Build L2 of 3, with the two named L3 requirements
unmet — one fixable in the workflow (§3.2), one not ours to evidence (§3.3)"
carries the information a percentage would destroy.

### What these four invariants do not touch, across every framework here

Consolidated, so it can be read without the tables:

- **Governance, management accountability and approval.** NIS2 Article 20 in
  particular, and every framework's equivalent.
- **Policy as a document.** Several clauses above ask for a documented,
  reviewed policy. Enforcement without a policy satisfies neither, and this
  project ships no policy templates.
- **Training and awareness.** SSDF PO.2 in full.
- **Supplier and third-party management.** Due diligence, contracts, registers,
  concentration risk, exit strategies. NIS2 21(2)(d)'s relationship half,
  DORA Articles 28–30 in full.
- **Vulnerability intake, triage, remediation and disclosure.** SSDF RV in
  substance, CRA Annex I Part II points (2)–(8), NIS2 21(2)(e)'s second half.
  The SBOM is an input to this work and is not this work.
- **Incident detection, response and regulatory reporting.** CRA Article 14,
  NIS2 21(2)(b), DORA's incident chapter.
- **Known-vulnerability status of what ships.** CRA Annex I Part I (2)(a).
  Pinning is not scanning.
- **Product security properties.** Secure defaults, attack surface, encryption
  of user data, logging — CRA Annex I Part I (2)(b)–(m). These are properties
  of the software, not of the pipeline that built it.
- **Runner and endpoint hardening.** SSDF PO.5.2. T-11 is fully residual.
- **Human access control to source.** SSDF PS.1.1's larger half.
- **Retention and archival of release evidence** over any period a regulator
  would recognise. The 14-day gap named twice above is real and unfixed.
- **Anything about correctness.** No control in this project makes any
  statement about whether the software works or is safe.

---

## 8. Verification log

Every framework version, status and date in this document was checked on
**2026-08-21**. Recorded here so a reader can re-run the check rather than
trust it, and so a stale citation is visible as stale rather than invisible.

| Claim | Source consulted | Verified |
|---|---|---|
| SLSA current version is **v1.2**, status *Approved* | `slsa.dev/spec/v1.2/about` | 2026-08-21 |
| SLSA v1.2 announced November 2025; backwards compatible with v1.1; Build Environment and Dependency tracks in development | `slsa.dev/blog` release announcement | 2026-08-21 |
| Build track requirement names and text (*Provenance Exists*, *Provenance is Authentic*, *Provenance is Unforgeable*, *Hosted*, *Isolated*) | `slsa.dev/spec/v1.2/build-requirements` | 2026-08-21 |
| Build L1/L2/L3 producer, platform and consumer obligations | `slsa.dev/spec/v1.1/levels` (v1.2 documented as backwards compatible) | 2026-08-21 |
| SLSA v1.2 defines a Build track and a Source track | `slsa.dev/spec/v1.2/tracks` | 2026-08-21 |
| "Artifact attestations by itself provides SLSA v1.0 Build Level 2" | GitHub Docs, artifact attestations concept page | 2026-08-21 |
| Reusable workflows plus artifact attestations reach SLSA v1.0 Build Level 3 | GitHub Docs, reusable workflows and SLSA Build L3 page | 2026-08-21 |
| SSDF current version is **SP 800-218 v1.1**, February 2022; no superseding revision listed | NIST SSDF project page, `csrc.nist.gov/projects/ssdf`, and the publication itself | 2026-08-21 |
| SSDF task text for PO.3.1–PO.3.3, PO.4.1–PO.4.2, PO.5.1–PO.5.2, PS.1.1, PS.2.1, PS.3.1–PS.3.2, PW.4.1, PW.4.4, PW.6.1–PW.6.2, RV.1.1–RV.1.3 | SP 800-218 v1.1 full text | 2026-08-21 |
| SSDF v1.1 has 42 active tasks across 19 practices | Enumerated from the SP 800-218 v1.1 task table, excluding 5 "moved to" pointers | 2026-08-21 |
| SP 800-218A is a Generative AI community profile, not a general revision | NIST SSDF project page | 2026-08-21 |
| CRA entered into force 10 Dec 2024; Chapter IV applies 11 June 2026; Article 14 applies 11 Sept 2026; main obligations 11 Dec 2027 | European Commission, `digital-strategy.ec.europa.eu` CRA pages | 2026-08-21 |
| CRA Annex I Part II point (1) SBOM wording, and Annex I Part I point (2)(a) | Two independent renderings of the OJ text (`cyberresilienceact.eu`, `cra-facts.com`), in agreement. **EUR-Lex HTML could not be retrieved at verification time** | 2026-08-21 |
| NIS2 Article 21(2)(a)–(j) text; Article 41 transposition deadline 17 October 2024 | Consolidated NIS2 article reference site | 2026-08-21 |
| French transposition: Senate first reading 12 March 2025; AN special commission report 10 September 2025; no definitive adoption found | Assemblée nationale dossier DLR5L17N50731; ANSSI transposition FAQ, `cyber.gouv.fr` (page itself last updated 2025-09-19) | 2026-08-21 |
| DORA applies from 17 January 2025; Articles 28/29/30 subject matter | Consolidated DORA article reference site | 2026-08-21 |
| Delegated Regulation (EU) 2024/1774 Article 16 (ICT systems acquisition, development, maintenance) and Article 17 (ICT change management) subject matter | Secondary renderings of the delegated regulation | 2026-08-21 |

### Deliberately omitted as unverifiable

Named rather than guessed, per
[`docs/ENGINEERING_PRINCIPLES.md`](ENGINEERING_PRINCIPLES.md) §7:

- **The exact day of SLSA v1.2's approval.** Sources consulted gave
  inconsistent days in November 2025. The month is used; the day is not.
- **Primary EUR-Lex text for the CRA, NIS2 and DORA.** The EUR-Lex HTML
  renderings did not return retrievable content at verification time. Clause
  numbering rests on secondary sources that agree with each other, and every
  such reference is flagged in situ. **Confirm against EUR-Lex before external
  use.**
- **DORA article-level enumeration**, and therefore any DORA coverage
  percentage. See §7.
- **The current French transposition status beyond 2026-08-21.** The most
  recent official source located was itself last updated 2025-09-19. Treat the
  §5.2 status as *last known*, not as *current*.
- **Any ISO/IEC 27001 or SOC 2 mapping.** Not attempted. Both are certification
  regimes whose scope statements and control selections are organisation
  specific; a generic mapping would be the exact kind of claim this document
  exists to refuse.
- **Any US federal software attestation form mapping** (secure software
  development attestation regimes referencing SSDF). The SSDF task mapping in
  §4 is the durable part; the attestation form's own wording and scope were
  not verified and are not cited.

---

## 9. Review triggers

Revisit this document when any of the following happens:

- A framework version above is superseded — in particular a new SLSA approved
  version, an SSDF revision, or a new SLSA Dependency or Build Environment
  track, which would give I1 somewhere to map for the first time.
- A CRA, NIS2 or DORA date passes, or French transposition completes and
  implementing decrees are published.
- The remaining SLSA Build L3 requirement in §3.3 becomes evidenceable.
- An invariant is added, or an existing one changes enforcement point —
  the same trigger as [`docs/THREAT_MODEL.md`](THREAT_MODEL.md) §10.
- **Any citation in §8 passes twelve months without re-verification.** A stale
  citation destroys the credibility this document exists to build, and it does
  so silently.
