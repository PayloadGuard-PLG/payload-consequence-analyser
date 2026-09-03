# Independent Verification of the External Audit — 2026-09-02

**Verification date:** 2026-09-02
**Baseline:** `payload-consequence-analyser` @ `a892575e4cdb70372f1684378554a751ad8d9b77`,
`payloadguard-test-harness` @ `214fa7736f1185f2f9f0fcadedeecc9fa4f30033`
**Method:** read-only against both repositories. No source file was modified and no GitHub mutation
was performed. This document is the only file added. Test suites and two new experiments were
executed; the sabotage experiment ran against a throwaway copy outside the repository. Execution
results are in Part 4, which corrects two claims made in Part 1 and Part 2.

## Purpose

An external party produced three documents on 2026-09-02 — a Baseline Protection Audit, a
Diagnostic Ledger, and a First-Pass Verification register — asserting sixteen findings
(BA-001 to BA-016). This register records an independent verification of those claims against the
code and the live GitHub state, at the same commits the auditor used, together with findings the
audit did not identify and file-level remediation specifications.

Every claim below was checked directly. Where a claim could not be checked from this session, it
is marked as such rather than inferred.

## Result

| Outcome | Count |
|---|---|
| Audit findings confirmed | 16 of 16 |
| Audit findings contradicted | 0 |
| Audit findings refined upward in severity or scope | 2 (BA-001, BA-011) |
| Additional findings identified | 19 (NF-1 to NF-19), 6 of them critical |

Three conclusions follow from the combined set that no individual finding states.

**1. BA-001 invalidates BA-006.** The merge barrier rests on a required status check posted by a
GitHub App whose private key is reachable by pull-request-controlled code. Whoever holds that key
can post a passing conclusion on any pull request in either repository. The protection layer cannot
be stronger than the key that signs its verdict, so the branch-protection evidence gap in BA-006 is
secondary to the key exposure in BA-001.

**2. The Z3 proof suite does not constrain the implementation (NF-11).** It never references
`_assess_consequence`. Demonstrated by experiment: with that function replaced by a stub returning
a constant SAFE verdict, all ten proofs still pass while 32 unit tests fail. This is the project's
headline public claim and it is not supported by the artefacts that assert it.

**3. Nothing binds the verified specifications to the shipped code (NF-12).** CrossHair and Dafny
verify `verification/consequence_pure.py` and `verification/dafny/assess_consequence.dfy`, which
are hand-written reimplementations. `analyze.py` contains no `MAX_SCORE` constant at all. Three
artefacts are held in agreement by convention, not by machine check.

On the evidence, that convention has held for values and failed for types. An exhaustive
differential over 3,732,480 input vectors found **zero** divergence in `status` or
`severity_score` — a genuine positive result, and NF-12 is qualified accordingly — while
`severity_score` is a **float** in the shipped scorer and an **int** in both verified
specifications. The risk NF-12 describes is not hypothetical; it has already been realised in the
one dimension nothing was checking.

---

## Part 1 — Verification of BA-001 to BA-016

### BA-001 — Pull-request-controlled code receives the GitHub App private key

**Verdict: Confirmed. Severity and blast radius refined upward.**

`.github/workflows/payloadguard.yml` triggers on `pull_request` and checks out with no `ref:`
parameter, so the default merge ref is used. The job then executes pull-request-controlled content
at three points before the secret-bearing step:

Three steps in the job execute pull-request-controlled content (dependency installation at `:32`,
the test run at `:35`, and the analyser at `:42`) before the credentialed step at `:93-100`, which
runs `post_check_run.py` with `PAYLOADGUARD_APP_ID`, `PAYLOADGUARD_PRIVATE_KEY` and
`PAYLOADGUARD_INSTALLATION_ID` in its environment.

Three corrections to the audit's framing:

1. The audit identifies the executed script as the vector. The exposure begins earlier, at
   dependency installation, which runs code before any project code does.
2. The asset is a GitHub App private key, not a repository secret. It mints installation access
   tokens for **every** installation of the App, not only these two repositories. The blast
   radius is therefore supply-chain scoped: any downstream repository that installs PayloadGuard.
3. It invalidates the merge barrier, per conclusion 1 above.

The audit's qualification is correct and worth restating: `pull_request` from a fork does not
receive repository secrets, so this is a same-repository write-access threat, not an anonymous
one.

**Remediation:** Phase 0.1 and 0.3.

### BA-002 — The harness baseline does not test current analyser development

**Verdict: Confirmed exactly.**

`payloadguard-test-harness/.github/workflows/payloadguard.yml:21` references
`payloadguard-plg/payload-consequence-analyser@fe6833887f34e77e53cf7e1dcf73c37297f5fea3`, the
v1.3.0 release commit, with the inline comment `# main`. The comment is wrong: that SHA is not
`main`, which is `a892575`.

Version identity is inconsistent across three sources, all verified:

| Source | Value |
|---|---|
| `analyze.py:29` | `__version__ = "1.3.0"` |
| `pyproject.toml:8` | `version = "1.3.0"` |
| `README.md:3` | `Version: 1.4.0-dev`, `Status: Production`, `Released: May 2026` |
| Latest GitHub release | `v1.3.0`, published 2026-05-31 |

**Remediation:** Phase 1.8 (repin, after the oracle is trustworthy) and Phase 2.1 (version
reconciliation).

### BA-003 — Regression pass/fail collapses three verdict bands

**Verdict: Confirmed exactly. Mechanism extended.**

The collapse is not a single defect in the regression runner. It occurs at four independent
layers, each discarding information the previous one still held:

| Layer | Location | Transformation |
|---|---|---|
| 1 | `analyze.py:2444-2449` | Four verdicts → three exit codes. `SAFE`, `REVIEW`, `CAUTION` all exit 0 |
| 2 | `action.yml:113-117` | Exit code → `verdict` output. `case $EXIT in 0) SAFE;; 2) DESTRUCTIVE;; *) ERROR` |
| 3 | `post_check_run.py:99-106` | Exit code → check conclusion. `0 → success`, `2 → failure`, else `action_required` |
| 4 | `run_regression.py::_conclusion_matches` | Conclusion → pass/fail. `expected==2 → require failure`, else require success |

`action.yml:49-52` advertises the `verdict` output as "SAFE, REVIEW, CAUTION, or DESTRUCTIVE". It
can only ever emit three of those four values, and `REVIEW` and `CAUTION` are not among them.

The fix is inexpensive because the information is not lost at source. The complete structured
verdict already exists in the JSON report at `report["verdict"]`, constructed at
`analyze.py:1508-1538` with `status`, `severity`, `severity_score`, `flags` and `recommendation`,
and serialised at `analyze.py:1323`. Nothing must be computed; the value must only be surfaced.

**Remediation:** Phase 1.1 and 1.2.

### BA-004 — Open test pull requests defeat temporal selection

**Verdict: Confirmed exactly.**

Live query returned exactly five open pull requests on the harness:

| PR | Branch | Fixture | Created |
|---|---|---|---|
| #5 | `safe/small-additive` | T01 | 2026-04-24 |
| #6 | `safe/docs-only` | T02 | 2026-04-24 |
| #7 | `safe/large-rename` | T12 | 2026-04-24 |
| #22 | `adversarial/unicode-payload` | A10 | 2026-04-24 |
| #56 | `test/megalodon-simulation` | MS01 | 2026-05-26 |

The first four are precisely the set with `temporal_group: "aging"` in `tools/test_cases.json`.
`run_regression.py::list_closed_test_prs` enumerates `state="closed"` only, and
`--mode temporal` filters to `temporal_group == "aging"`. The intersection is empty, so the run
prints `No closed test PRs found. Nothing to do.` and calls `sys.exit(0)`.

Temporal mode therefore cannot execute in the present repository state, and reports success while
doing so. No temporal claim in any project document is currently supported by a run.

**Remediation:** Phase 1.5, and a decision on the open pull requests (see Open Decisions).

### BA-005 — The harness workflow can appear successful after an action failure

**Verdict: Confirmed by control flow.**

`payloadguard-test-harness/.github/workflows/payloadguard.yml:19` sets `continue-on-error: true`
on the scan step. The enforcement step at `:45-50` reads:

```yaml
if [ "$EXIT_CODE" = "1" ]; then exit 1; fi
if [ "$EXIT_CODE" = "2" ]; then exit 2; fi
```

If the action fails before writing `exit_code` to `$GITHUB_OUTPUT`, `EXIT_CODE` is the empty
string, matches neither literal, and the step exits 0. The workflow reports success having
measured nothing.

**Remediation:** Phase 1.6.

### BA-006 — The human merge barrier cannot be proven with current visibility

**Verdict: Corroborated. Same limitation reproduced.**

This session has no branch-protection endpoint available either. Administrator enforcement, bypass
actors, required review rules, and force-push and deletion protection remain unverified from here.
The audit's request for owner-supplied evidence stands.

One addition: even complete protection evidence would not close this finding while BA-001 is open,
per conclusion 1. The required check is only as trustworthy as the key that signs it. BA-001
should be remediated before the protection evidence is treated as a safety case.

### BA-007 — Auto-remediation's documented permission contract is insufficient

**Verdict: Confirmed, and escalated. See NF-4.**

The audit states the documented `pull-requests: write` is insufficient. Verification shows the
feature cannot function on the documented path at all. Full detail in NF-4.

### BA-008 — The advertised runtime tier cannot be installed

**Verdict: Confirmed exactly. Failure mechanism identified. See NF-9.**

`action.yml:86` hardcodes `PG_VERSION=v2.0.0`. Live release listing returns six releases, the
latest `v1.3.0` (2026-05-31). No `v2.0.0` exists. The download at `:90-92` therefore 404s.

The consequence is more severe than "the tier does not activate" — see NF-9.

### BA-009 — Latest full regression failed, and its evidence expired

**Verdict: Confirmed. Extended by NF-8.**

Live workflow-run history for `regression.yml`: 26 runs total. Run `26714908079` (2026-05-31,
`workflow_dispatch`) concluded `failure`. Run `26705134938` (2026-05-31, `schedule`) concluded
`failure`. The last run with conclusion `success` is run 23, `26634664198`, on 2026-05-29.

There has been **no regression run of any kind since 2026-05-31** — 94 days.

### BA-010 — Build and release dependencies are not reproducibly constrained

**Verdict: Confirmed.**

`requirements.txt` uses lower-bound specifiers exclusively (`GitPython>=3.1.41`, `PyYAML>=6.0`,
and so on). No lock file and no hash pinning exist in either repository.
`.github/workflows/publish.yml:22-23,27-28` installs current `build` and `twine` unpinned and
authenticates with the long-lived `PYPI_API_TOKEN` secret. The runtime agent download in
`action.yml:90-92` performs no integrity check before `sudo` execution.

**Remediation:** Phase 2.4 and 2.6.

### BA-011 — Node 20 runtime removal is imminent

**Verdict: Confirmed, and made exact. Scope refined upward. See NF-7.**

The audit reports a warning without identifying which pins are affected. Each pinned action's
manifest was fetched at its exact commit and `runs.using` read directly:

| Pinned SHA | Action | Comment says | `runs.using` | Status |
|---|---|---|---|---|
| `34e114876b0b11c390a56381ad16ebd13914f8d5` | checkout | `# v4` | `node20` | **Must upgrade** |
| `a26af69be951a213d495a4c3e4e4022e16d87065` | setup-python | `# v5` | `node20` | **Must upgrade** |
| `f28e40c7f34bde8b3046d885e986cb6290c5673b` | github-script | `# v7` | `node20` | **Must upgrade** |
| `de0fac2e4500dabe0009e67214ff5f5447ce83dd` | checkout | `# v4` **and** `# v6` | `node24` | Comment wrong |
| `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` | upload-artifact | `# v4` **and** `# v7` | `node24` | Comment wrong |

Two SHAs carry contradictory version comments in different files. The same
`de0fac2e…` commit is labelled `# v4` in `verify-dafny.yml:22` and harness `regression.yml:23`,
and `# v6` in harness `payloadguard.yml:15`. The same `043fb46d…` commit is labelled `# v4` in
`verify-dafny.yml:66` and `# v7` in both harness workflows.

The critical extension is NF-7: two of the three node20 pins are inside `action.yml`.

### BA-012 — Verification and test-count claims are not reproduced by default CI

**Verdict: Confirmed. Superseded in importance by NF-11.**

`.github/workflows/payloadguard.yml:35` runs `pytest test_analyzer.py -v` only. No CrossHair or Z3
command appears in any workflow. `verify-dafny.yml` is path-filtered to
`verification/dafny/**`, so it does not run on a typical pull request.

Test count, executed: `pytest test_analyzer.py` collects **281** and reports **277 passed,
4 skipped**. The four skips are an artifact of this container — a broken system `cryptography`
build causes `import post_check_run` to raise, and `TestPostCheckRun._import_pcr` skips on
`BaseException`. They are not repository defects.

This corrects the framing in an earlier draft of this document. `README.md:465` claims
"274 tests pass, 7 skipped", which **sums to 281 — the correct collected total**. The total is
right; only the pass/skip split has drifted, and that split is environment-dependent: four
`post_check_run` skips gate on an importable `cryptography`, and four more at
`test_analyzer.py:1217,1224,1234,1244` gate on tree-sitter JS/TS grammars. An environment missing
some of those optional dependencies plausibly produces exactly 274/7.

The claims that remain wrong are those whose **total** does not reach 281:
`TEST_REGISTRY.md:4` ("272 passed · 7 skipped · 279 total") and `CLAUDE.md:98`
("267 tests, + 5 CrossHair = 272 total", which also omits the ten Z3 tests).

The substantive part of BA-012 stands unchanged: no workflow runs the proof suites. It is
superseded in importance by NF-11.

The deeper problem is NF-11: running the Z3 suite in CI would not substantiate the claim, because
the suite does not constrain the implementation.

### BA-013 — Recurring monitoring is absent or disabled

**Verdict: Confirmed. Inference strongly supported.**

`gitroll-scan.yml` last ran 2026-08-11 (run 68, `success`). The last push to `main` was
2026-06-11 (`a892575`, merge of PR #93). The interval is 61 days, matching GitHub's documented
60-day auto-disable rule for scheduled workflows in public repositories with no activity. The
causal claim still requires the Actions UI to confirm, as the audit states.

The last 30 workflow runs on the analyser are **all** GitRoll. No PayloadGuard pull-request scan
has run since June. The harness regression is `workflow_dispatch` only and last ran 2026-05-31.
No recurring regression is active in either repository.

### BA-014 — Security governance controls are missing

**Verdict: Confirmed.**

Filesystem check of both trees at the audited commits:

| Control | Analyser | Harness |
|---|---|---|
| `CODEOWNERS` (root, `.github/`, `docs/`) | Absent | Absent |
| `SECURITY.md` (root, `.github/`) | Absent | Absent |
| `.github/dependabot.yml` | Absent | Absent |
| `CONTRIBUTING.md` | Absent | Absent |
| CodeQL or Scorecard workflow | Absent | Absent |

`.github/` in both repositories contains only `workflows/`.

### BA-015 — Quick-start guidance uses mutable action references

**Verdict: Confirmed.**

`README.md:111` and `:153` use `actions/checkout@v4`. `README.md:117`, `:159` and `:175` reference
`PayloadGuard-PLG/payload-consequence-analyser@main`.

The analyser detects mutable references itself: `_scan_mutable_action_refs` flags any `uses:` value
whose ref is not a 40-character SHA, and emits them as `mutable_tag_warnings` in the JSON report.
The installation instructions therefore demonstrate a pattern the product reports as a finding.

### BA-016 — Repository identity and release documentation are inconsistent

**Verdict: Confirmed, and substantially broader than stated. See NF-13.**

The audit cites four examples. A sweep of all twelve documentation files found the inconsistency
is systemic: four mutually exclusive test counts in circulation, `MAX_SCORE` documented as both 31
and 36 within the same file in two separate files, three different layer counts, and a shipped
feature (L2d) absent from the whitepaper entirely. Full detail in NF-13 and Appendix A.

---

## Part 2 — Findings the audit did not identify

### NF-1 — Shell script injection in the distributed action — CRITICAL — **REMEDIATED**

> **Status: fixed.** Every `${{ }}` interpolation has been removed from every `run:` body in
> `action.yml` and all five workflows; attacker-influenced values now travel via `env:` and are
> dereferenced as quoted shell variables. `TestOwnWorkflowsNotInjectable` in `test_analyzer.py`
> guards against reintroduction and was verified by planting the old construct in a copy. The
> description below is retained as the record of what was wrong.

`action.yml:109-110` interpolates a pull-request-controlled value directly into a `shell: bash`
run block:

```yaml
run: |
  set +e
  python "${{ github.action_path }}/analyze.py" . \
    "${{ github.head_ref }}" "${{ github.base_ref }}" \
```

`action.yml:80` repeats the pattern unquoted:

```yaml
run: git fetch origin ${{ github.base_ref }}:${{ github.base_ref }}
```

Both patterns also appear in the analyser's own workflow at `.github/workflows/payloadguard.yml:21`
and `:42`.

`github.head_ref` is the source branch name of the pull request and is therefore attacker-chosen
on a fork pull request. `git check-ref-format` permits shell-significant characters in a ref name,
so a crafted branch name reaches the script body as code rather than as an argument. GitHub Actions
substitutes expressions before the shell parses the script, so quoting the expression does not
help; the value must not reach the script body at all. This is GitHub's documented
template-injection class, and `zizmor` detects it directly — see Phase 4.

Reproduction detail is deliberately withheld from this document while the finding is unremediated.

Scope. This is in `action.yml`, the composite action distributed to consumers, not only in internal
CI. Any repository running PayloadGuard on `pull_request` is within scope. Secrets are not passed
to fork pull requests, which bounds the immediate loss — but a consumer using
`pull_request_target`, a trigger PayloadGuard's own L2c layer flags as a poisoning signal, would
widen it substantially.

The correct mitigation is already applied two lines away. `action.yml:104` places
`pr-description` in `env:` as `PG_PR_DESCRIPTION` and `:111` dereferences it as
`"$PG_PR_DESCRIPTION"`. The same treatment for `head_ref` and `base_ref` closes the finding. The
pattern is understood; it was applied inconsistently.

**Remediation:** Phase 0.2.

### NF-2 — The regression runner reports success when every scan times out — CRITICAL

`run_regression.py` computes, after evaluation:

```python
missed = len(pr_sha_map) - len(scan_results)
```

`missed` is printed in the summary block and then never referenced again. The terminal condition
is:

```python
if args.mode != "temporal" and failed:
    sys.exit(1)
```

Timed-out scans never enter `scan_results`, so `evaluate_results` never iterates over them and
they never increment `failed`. If all 34 stable scans time out, `passed == failed == 0`, no
`sys.exit` is reached, `main()` returns, and the process exits 0.

A run in which nothing was measured is indistinguishable from a run in which everything passed.
This is the same failure mode that would mask a broken analyser pin, an expired `REGRESSION_PAT`,
or a workflow that no longer triggers — the exact conditions a regression suite exists to detect.
It is a strictly worse defect than BA-003 or BA-005, both of which at least require a scan to have
completed.

**Remediation:** Phase 1.3.

### NF-3 — No teardown guarantee around reopen and close — HIGH

`run_regression.py` executes the reopen loop, `wait_for_scans`, and the close loop as three
sequential statements with no `try`/`finally`. Job cancellation, job timeout, `KeyboardInterrupt`,
or any exception escaping `wait_for_scans` or `evaluate_results` leaves every reopened test pull
request open against a protected `main`.

The audit lists teardown proof as objective 6 of its proposed G1 batch. It is not only a test
objective; it is a present defect in the runner, and it is the mechanism by which the current five
open pull requests could multiply to thirty-nine.

**Remediation:** Phase 1.4.

### NF-4 — Auto-remediation cannot function on its documented path — HIGH

BA-007 states the documented permission set is insufficient. Verification shows the feature is
unreachable, not merely under-documented.

`WorkflowRemediator.open_pr` performs three API operations:

| Step | Call | Permission required |
|---|---|---|
| 2 | `POST /repos/{o}/{r}/git/refs` | Contents: write |
| 3 | `PUT /repos/{o}/{r}/contents/{path}` | Contents: write, and Workflows: write for `.github/workflows/**` |
| 4 | `POST /repos/{o}/{r}/pulls` | Pull requests: write |

The decisive point is step 3. `GITHUB_TOKEN` cannot create or update files under
`.github/workflows/`. There is no `workflows` key in the job-level `permissions:` schema, so the
capability cannot be granted. `action.yml:168` passes `inputs.repo-token`, defaulting to
`github.token` at `:13`. On the documented path the feature always fails.

The module docstring at `remediate.py:9-11` asserts a security model that is factually incorrect:

> Security model: new PR only (requires pull-requests: write). Never commits
> directly (that would require contents: write, exploitable via GITHUB_TOKEN).

Creating a ref and writing contents requires `contents: write` regardless of which branch is
targeted. The stated distinction does not exist.

Two further defects confirmed:

- `remediate.py`, `__main__` block: `_api_get(f'/repos/{owner}/{repo_name}/contents/{file_path}')`
  carries no `?ref=` parameter, so the GitHub API returns the file from the **default branch**.
  The targets were derived from the pull request's workflow diff, so a workflow added or modified
  in the pull request is patched from the wrong content, or 404s and is silently skipped with a
  warning.
- `open_pr` defaults `pr_branch` to the fixed literal `'payloadguard/pin-action-shas'`. The second
  invocation against the same repository receives 422 on ref creation, which is unhandled.

**Remediation:** Phase 3.1.

### NF-5 — Layer 2c has no expression-injection signal — HIGH

`_scan_github_actions_poisoning` implements seven signal families: `base64_payload`,
`credential_harvest`, `dormant_trigger_with_payload`, `forged_bot_author`,
`oidc_elevation_typosquatted` / `oidc_elevation_no_consumer`,
`pull_request_target_with_write_permissions` / `dangerous_trigger_pull_request_target`, and
`github_env_injection`.

None detects untrusted context expressions inside `run:` blocks.
`grep -niE "script.?injection|head_ref|expression.injection|untrusted.input" analyze.py` returns no
matches. `_ACTIONS_GITHUB_ENV_INJECTION` is adjacent but distinct: it matches
`echo PATH=… >> $GITHUB_ENV` and similar environment-file poisoning, not expression interpolation.

This is the most common GitHub Actions vulnerability class and the first one documented in
GitHub's secure-use guidance. Its absence is a detection gap in a product whose stated purpose is
detecting workflow poisoning.

The direct consequence: **PayloadGuard cannot detect NF-1 in its own `action.yml`.** Closing the
gap is both a genuine capability improvement and the most direct available demonstration that the
tool works on a real vulnerability class.

**Remediation:** Phase 5.

### NF-6 — Test and proof tooling ships as a runtime dependency — HIGH

`action.yml:75-76` runs `pip install -r "${{ github.action_path }}/requirements.txt"` in every
consumer's CI job. `requirements.txt` includes:

```
pytest>=7.0
z3-solver>=4.12.0
crosshair-tool>=0.0.104
pytest-timeout>=2.0
```

Every consumer of PayloadGuard installs an SMT solver and a symbolic-execution engine in order to
scan a diff. This is a material cost in install time and a material widening of the dependency
surface that reaches consumer runners.

It also contradicts `pyproject.toml:36-48`, whose `dependencies` list correctly excludes all four.
The repository ships two dependency manifests that disagree about what the product requires.

**Remediation:** Phase 2.4.

### NF-7 — The Node 20 removal breaks the product, not only internal CI — HIGH

Refines BA-011. Two of the three node20 pins are inside the composite action:

- `action.yml:73` — `actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065` (`node20`)
- `action.yml:127` — `actions/github-script@f28e40c7f34bde8b3046d885e986cb6290c5673b` (`node20`)

On the removal date every consumer's PayloadGuard step fails, independently of anything in this
repository's own workflows. The audit treats this as CI hygiene. It is a scheduled outage of the
distributed product.

Shipping the fix requires cutting a release, which routes through `publish.yml` — the unpinned,
long-lived-token publish path identified in BA-010. The two findings are coupled on the critical
path.

**Remediation:** Phase 0.4, which is not complete until a tag exists.

### NF-8 — The recorded green baseline has no run behind it — MEDIUM

Both `CLAUDE.md` files state:

> Harness regression — last verified 2026-06-01 (analyser SHA fe68338, v1.3.0) — 34/34 PASS.

`regression.yml` has 26 runs. **There is no run on 2026-06-01.** The most recent is
`26714908079` on 2026-05-31, conclusion `failure`. The last `success` is run 23 on 2026-05-29,
before the pin was moved to `fe68338`.

Either the baseline was produced by a local invocation of `tools/run_regression.py` and never
recorded, or it is unsupported. Combined with BA-009's expired artifacts, no retained evidence
substantiates the green baseline on which the project's current state depends. Both handover blocks
and `HARNESS.md` propagate it as established fact.

**Remediation:** Phase 1.7 and 1.8. Until re-baselined, the claim should be marked unsubstantiated
in both handovers.

### NF-9 — `runtime-mode` fails the job rather than degrading — MEDIUM

`action.yml:53-57` documents the runtime agent as degrading gracefully:

> The agent degrades gracefully (exit 0) on unsupported kernels.

The step body at `:86-97` runs under `shell: bash`, which GitHub invokes as
`bash --noprofile --norc -eo pipefail`. The `-e` flag is active. The line

```bash
curl -fsSL "…/releases/download/${PG_VERSION}/pg-agent-linux-${ARCH}" -o /tmp/pg-agent && chmod +x /tmp/pg-agent
```

fails because `v2.0.0` does not exist (BA-008), the `&&` list returns non-zero, and `-e` aborts the
step. The step has no `continue-on-error`, so the job fails.

Setting `runtime-mode` to `audit` or `block` therefore breaks the action outright. A documented
feature that fails the job when enabled is worse than an absent one.

The documented **configuration** is separately inert. An exhaustive grep across `.py`, `.yml`,
`.sh`, `.go` and `.c`:

- `PAYLOADGUARD_RUNTIME_BLOCK` — appears only at `README.md:358` and `:363`. Zero source
  occurrences.
- `PAYLOADGUARD_RUNTIME` — appears at `README.md:164` and `:362`, and once in source at
  `agent/main.go:33` as `os.Setenv("PAYLOADGUARD_RUNTIME", "disabled")` on the line immediately
  before `os.Exit(0)`. That write affects only the exiting process's own environment and is
  unreachable by any observer. It is dead code.

Neither variable is ever read. A user following `README.md:155-165` receives no runtime agent and
no error. The variable that **is** read — `PG_RUNTIME_EVENTS_PATH` at `analyze.py:1937`, the sole
`os.environ` access in the file — is undocumented. The README documents two controls that do
nothing and omits the one that works.

Further: no checksum, signature or attestation is verified before `sudo`-executing a downloaded
binary, and the background agent started with `&` is never reaped.

**Remediation:** Phase 3.2 and 2.5.

### NF-10 — Packaging and repository hygiene — LOW to MEDIUM

`pyproject.toml:52` declares
`py-modules = ["analyze", "structural_parser", "post_check_run", "remediate"]`.

- The **`verification/` package is not packaged at all** — it appears neither in `py-modules` nor
  in any `[tool.setuptools.packages]` entry. An installed wheel therefore cannot run the CrossHair
  commands documented in `VERIFICATION.md` and `SYSTEM_BLUEPRINT.md:501`.
- `orchestrator.py` (15 KB) and `trust_grader.py` (9.7 KB) are git-tracked, unpackaged, and have
  zero importers anywhere in the tree. `SYSTEM_BLUEPRINT.md:73-74` labels both R&D-only, so the
  omission is deliberate, but both ship in the public tree with no test coverage and no consumer.
- `part1.txt` (8.1 KB) is a tracked `git format-patch` output dated 2026-04-29, already flagged as
  a removable scratch artifact at `SYSTEM_BLUEPRINT.md:79`.
- Harness PR #56's title embeds a `claude.ai/code/session_…` URL in a public repository.

### NF-11 — The Z3 proof suite does not constrain the implementation — CRITICAL

`tests/proofs/test_z3_properties.py` never imports, calls, or symbolically encodes
`_assess_consequence`, `assess_consequence_pure`, or any other production function. Each of
P1 to P10 declares fresh free Z3 variables, asserts a hand-written axiom set that restates the
intended semantics, and shows the negation of the desired property is unsatisfiable.

What this establishes is that the hand-written axioms are internally consistent. It cannot detect
any divergence between those axioms and the scorer that ships.

The decisive test: **replace `_assess_consequence` with `return {"status": "SAFE"}` and all ten
proofs still pass.** A proof that survives deletion of its subject does not constrain that subject.

**This was executed, not merely reasoned about.** In a throwaway copy of the tree, the entire
8,211-character body of `_assess_consequence` was replaced with a stub returning a constant SAFE
verdict and `severity_score` of 0. Results against that sabotaged scorer:

| Suite | Result |
|---|---|
| `pytest tests/proofs/test_z3_properties.py` | **10 passed** |
| `pytest test_analyzer.py` | **32 failed**, 245 passed, 4 skipped |

The ordinary unit tests detect the sabotage. The formal proofs do not notice it at all. On this
evidence the unit suite performs more verification of Layer 3 than the artefacts the README
presents as its formal verification.

Worked examples, read line by line:

**P9 is a tautology.** `test_p9_score_upper_bound_finite`:

```python
score = Int("score")
_HARD_UPPER = _MAX_OTHER_SCORE + _CRITICAL_SCORE   # comment says 24; evaluates to 29
s.add(score >= 0, score <= _HARD_UPPER)
s.add(score > _HARD_UPPER)
_check(s)                                          # asserts unsat
```

`score` is a free integer with no relation to PayloadGuard. The solver is asked whether
`score <= 29 ∧ score > 29` is satisfiable. It is not, by construction — this is a direct
contradiction between two constraints, and the result is independent of every property of the
system under test. The test proves `¬(x ≤ k ∧ x > k)`.

Two secondary errors compound it. The comment `# = 24` is arithmetically wrong: `_CRITICAL_SCORE`
is 5, so `_HARD_UPPER` is 29. And `_MAX_OTHER_SCORE = 24`'s derivation comment enumerates
deletion_dim 4 + age 3 + structural 5 + critical_path 2 + security_files 5 + ai_config_critical 5,
omitting `unverified_dependencies` (+3) and `content_flags` (+4). The true maximum is 36, per
`verification/consequence_pure.py:57-62`. So even read charitably as a bound, 29 does not bound 36.

**P6 assumes its conclusion.** `test_p6_safe_verdict_iff_score_below_review_threshold` asserts
`is_safe → score < 1` and `score < 1 → is_safe` as premises, then asks whether the negation of that
biconditional is satisfiable. It is not, because the biconditional was asserted. The test is
circular.

**P4 proves an arithmetic fact.** `test_p4_critical_signal_score_exceeds_high_signal_score` asserts
`crit == 5`, `high == 3`, and `crit <= high`, and checks unsat. It establishes that 5 > 3.

**P2, P3 and P8** hardcode `score == _CRITICAL_SCORE` as an axiom rather than deriving it from the
scoring function, so they test the axiom, not the scorer.

**P7** is the strongest of the set — it encodes the threshold ladder as implications — but applies
it to a free `score` variable rather than to the output of `_assess_consequence`.

`README.md:7` presents "10 Z3 SMT proofs" as one of three independent verification methods
supporting the product's central differentiator. On the present construction it is not evidence
about the analyser.

This is a different and deeper problem than BA-012. BA-012 observes that the proofs are not run in
pull-request CI. Running them would not substantiate the claim.

**CrossHair is not subject to this criticism.** CrossHair symbolically executes the real
`assess_consequence_pure` against its `post:` contracts. That is genuine verification of that
function. The gap in the CrossHair layer is NF-12, not soundness.

**Remediation:** Phase 2.3b.

### NF-12 — No refinement obligation between the verified spec and the shipped code — HIGH

`verification/consequence_pure.py` and `verification/dafny/assess_consequence.dfy` are hand-written
reimplementations of `analyze.py::_assess_consequence`. CrossHair verifies the first; Dafny
verifies the second. Nothing verifies that either agrees with the function that actually runs in
production.

**Executed result, which qualifies this finding.** A differential check was run between
`analyze.py::_assess_consequence` and `verification.consequence_pure.assess_consequence_pure`,
exhaustively over a bounded grid straddling every threshold and cap in the scorer —
**3,732,480 input vectors**. On `status` and `severity_score`, **zero divergence**. The two
implementations agree today. NF-12 is therefore a structural risk, not a present defect in the
scoring values, and this document does not claim otherwise.

The same run empirically confirms the maximum: the highest `severity_score` reachable over the
grid is exactly **36.0**, matching `_MAX_SCORE` and contradicting the five documentation locations
that state 31 (`WHITEPAPER.md:561`, `CLAUDE.md:321`, `CLAUDE.md:158`, `PROOFS.md:81`,
`llms.txt:3`). It also confirms that P9's `_HARD_UPPER` of 29 does not bound the real maximum.

**One divergence does already exist, in type rather than value:**

| Artefact | Declaration |
|---|---|
| `analyze.py:1395` | `severity_score = 0.0` — **float**; the report serialises `36.0` |
| `verification/consequence_pure.py:219` | `severity_score: int = 0` — **int** |
| `verification/dafny/assess_consequence.dfy:111` | `returns (status: string, severity_score: int)` — Dafny **int** |

Both verified specifications model an integer scorer. The shipped scorer accumulates in floating
point. Dafny's `int` is a mathematical integer with exact arithmetic and cannot model float
semantics at all, so the Dafny proof is about a different type than the code computes. Verdicts are
unaffected at present, because the thresholds are order comparisons and the accumulated values are
integral — but this is precisely the drift class NF-12 predicts, already realised.

It also carries a design note for the remediation in 2.3a: the differential test above compared
numerically, and `36.0 == 36` in Python, so it did **not** catch this. A refinement test must
assert on type as well as value.

The two implementations have also diverged in representation. `_MAX_SCORE: int = 36` exists at
`verification/consequence_pure.py:62`, and `const MAX_SCORE: int := 36` at
`verification/dafny/assess_consequence.dfy:18`. `analyze.py` has **no such constant anywhere** —
`grep -n "MAX_SCORE" analyze.py` returns nothing. Its thresholds are bare integer literals at
`:1508`, `:1516` and `:1524`. The comment at `verification/consequence_pure.py:28` states the
constants are "mirrored from analyze.py DEFAULT_CONFIG"; it mirrors a constant that has no origin.

`CLAUDE.md` states the governing rule:

> Do not change scoring constants in one place and leave others stale. CrossHair and Dafny will
> catch mismatches on next verification run, but CI does not run them on every push — a stale spec
> is a silent lie.

The rule is enforced by convention alone, and the convention has already failed in the
documentation layer: `MAX_SCORE` is stated as both 31 and 36 within `WHITEPAPER.md` and within
`CLAUDE.md` (see NF-13). There is no mechanism that would catch the same failure in the code layer.

This is the most consequential structural weakness in the verification architecture and the
cheapest to close. The input domain of `_assess_consequence` is small and bounded — a handful of
integers with low ceilings, one string enum, two booleans. A differential test between
`analyze.py::_assess_consequence` and `verification.consequence_pure.assess_consequence_pure`,
exhaustive or property-based, converts "two hand-synchronised implementations" into "one verified
specification plus a machine-checked refinement obligation". That single change is what makes the
CrossHair and Dafny results apply to the shipped analyser.

**Remediation:** Phase 2.3a. This is the highest-leverage individual change identified in this
review.

### NF-13 — Documentation drift is systemic — MEDIUM

A sweep of all twelve documentation files against the code found that the drift BA-016 describes is
not a handful of stale figures. No file agrees with the tree on test count, and two files
contradict themselves on a verified invariant. Full table in Appendix A. Summary:

- **Test count.** Four figures circulate for the passing count — 267, 272, 273, 274 — across
  fourteen locations in nine files. Executed, the suite collects **281** and reports 277 passed /
  4 skipped in this environment. Because the split is environment-dependent (see BA-012), the
  claims worth correcting are those whose stated **total** is not 281: `TEST_REGISTRY.md:4`
  ("279 total") and `CLAUDE.md:98` ("272 total"). `README.md:465`'s "274 pass, 7 skip" sums
  correctly to 281 and is defensible for an environment with fewer optional dependencies
  installed. An earlier draft of this document overstated this finding.
- **MAX_SCORE.** `WHITEPAPER.md` states 31 at `:561` and 36 at `:638`. `CLAUDE.md` states 36 at
  `:122` and 31 at `:321` and `:158`. Each file contradicts itself on a machine-verified invariant.
  The verified value is 36.
- **Layer count.** `CLAUDE.md:70` says "Nine-Layer" above a twelve-row table.
  `WHITEPAPER.md:23` says nine while its own diagram at `:83` says "8-layer" and its roadmap table
  at `:908-915` lists eight.
- **L2d is absent from `WHITEPAPER.md` entirely** — zero occurrences of `L2d`,
  `AI Config Poisoning`, or `_scan_ai_tooling_configs`. The Sprint 1 feature was never written into
  the specification document.
- **`WHITEPAPER.md:638` advertises a `pli_critical → DESTRUCTIVE` CrossHair contract.** PLI was
  reverted in v1.3.0; no such contract exists in `verification/consequence_pure.py`.
- **`run_regression.py` contradicts its own filter code in user-facing help.** The module docstring
  at `:11` says 16 stable cases; the argparse epilog at `:208` says 26; the filter at `:234-238`
  selects 34. `HARNESS.md:120` documents a 300-second default timeout against `DEFAULT_TIMEOUT = 600`
  at `:38`.
- **Stale reports.** `TEST_REPORT.md` and `TEST_REGISTRY.md` are both dated 2026-05-28, predating
  Sprint 1 (2026-06-11) and its sixteen new tests. Neither describes the current tree.

Two positive results are worth recording. All seven layer symbols named in `CLAUDE.md` were
verified to exist in `analyze.py`. And the harness ground truth is sound: `tools/test_cases.json`
holds 41 entries, and the category and temporal-group tables in `HARNESS.md`, harness `CLAUDE.md`
and `README.md` match it exactly. The drift is concentrated in the analyser's prose and in
`run_regression.py`'s comments.

**Remediation:** Phase 2.2, 2.2b and 2.3d.

---

### NF-15 — The `pull_request_target` detector is bypassable, and the harness ratifies the bypass — CRITICAL

L2c decides `pull_request_target` severity from the workflow's declared permissions:

```python
if _ACTIONS_DANGEROUS_TRIGGERS.search(content):
    if _ACTIONS_WRITE_PERMISSIONS.search(content):
        signals.append({'type': 'pull_request_target_with_write_permissions', ...})  # CRITICAL
    else:
        signals.append({'type': 'dangerous_trigger_pull_request_target', ...})        # HIGH
```

`_ACTIONS_WRITE_PERMISSIONS` matches exactly four scopes: `contents`, `pull-requests`, `packages`
and `deployments`. The permission block is being used as a proxy for the attack. The actual attack
signature — a privileged trigger that checks out the pull request's head and then executes it — is
not modelled anywhere.

Measured against one workflow, varying only the permission line. Every row checks out
`${{ github.event.pull_request.head.sha }}` and then runs `npm install && npm run build`:

| Declared permission | Severity | Verdict | Exit |
|---|---|---|---|
| `contents: write` | CRITICAL | DESTRUCTIVE | 2 |
| `checks: write` | HIGH | CAUTION | **0** |
| `issues: write` | HIGH | CAUTION | **0** |
| `id-token: write` | HIGH | CAUTION | **0** |
| *no `permissions:` block at all* | HIGH | CAUTION | **0** |

The last row is the decisive one. Omitting the block does not mean the job is unprivileged — it
means the job inherits the repository default, which on repositories created before the default
changed is read-write across every scope. So the configuration that evades detection is also,
frequently, the more dangerous one, and it is the configuration an attacker reaches for by writing
less rather than more.

**The harness has encoded this as correct behaviour.** Fixture `RTA03`
(`rta/prt-untrusted-checkout`), in the `red-team` category, carries exactly this workflow:

```yaml
on: pull_request_target
jobs:
  check:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm test
      - run: npm run lint
```

`npm test` and `npm run lint` execute scripts from the pull request's own `package.json`. The
recorded expectation is `expected_verdict: CAUTION`, `expected_exit_code: 0` — do not block — with
the stated rationale "No explicit write permissions declared → HIGH signal only (+3)". `RTA03` is
listed as PASS in the 34/34 baseline.

Two consequences follow.

1. **The product does not block the canonical `pull_request_target` compromise.** A consumer
   relying on PayloadGuard to catch a poisoned workflow in a pull request gets `CAUTION` and exit 0.
2. **The expectation was derived from observed behaviour rather than from a threat model.** A
   fixture written to match what the analyser currently does converts any detector gap into a
   specification. This is the same failure mode as NF-11 — a check that passes for reasons
   unrelated to the property it is named for — and it is more consequential here, because the
   red-team suite is the artefact that is supposed to model an adversary.

Fixture `AW02` (`adversarial/workflow-prt-only`) is defensible by comparison: read-only permissions
with no untrusted checkout is a legitimate pattern. The distinction `RTA03` misses is the checkout.

**Specification decision (settled by the maintainer, 2026-09-03): `RTA03` is DESTRUCTIVE.** The
tool's job is to block that workflow. This fixes the discriminator as the untrusted checkout, not
the declared permissions, and it is the principle every other L2c expectation should now be
re-derived against.

Verified consequence for the neighbouring fixture: `AW02` (`adversarial/workflow-prt-only`) carries
`pull_request_target` with `actions/checkout@v4` and **no `ref:`**, so it resolves to the base
branch and never executes pull-request-controlled code, then runs a base-branch script. It is a
legitimate labeler pattern. `AW02` must therefore remain CAUTION while `RTA03` becomes DESTRUCTIVE,
which makes it the false-positive anchor for the rule: any implementation that cannot separate
these two is wrong. The suite already contains the discriminating pair.

**Remediation.** Model the signature rather than the proxy: `pull_request_target` combined with a
checkout whose `ref` resolves to a pull-request head is CRITICAL irrespective of declared
permissions. Treat an absent `permissions:` block under that trigger as elevated, not neutral.
Broaden `_ACTIONS_WRITE_PERMISSIONS` to the remaining write scopes as defence in depth, but not as
the primary control. Then correct `RTA03`'s expectation to DESTRUCTIVE / exit 2 and re-derive every
L2c fixture expectation from the threat model rather than from observed output.

This finding outranks NF-5 in priority. NF-5 is a detector that does not exist; NF-15 is a detector
that exists, is relied upon, and can be stepped around by writing one fewer line of YAML.

### NF-19 — YAML normalisation turns line-scoped patterns into file-scoped ones — HIGH

`_normalize_yaml_content` strips every newline so that folded and literal block scalars match as
one string — the mechanism that lets a multi-line `curl` with backslash continuations be detected
(the RTA02 fix in v1.2.0). L2c matches several pattern families against **both** the raw file and
that normalised text.

The families use `[^\n]*` to express "elsewhere on this line". After normalisation there are no
newlines, so `[^\n]*` means **anywhere in the file**. Every such pattern silently changes meaning
between its two invocations.

Measured on this repository's own `action.yml`, which normalises from 194 lines to a single
6,125-character line. The pattern

```
env\b[^\n]*\|\s*(grep|awk|sed)\b[^\n]*(KEY|TOKEN|SECRET|PASSWORD|CRED)
```

matched by stitching three unrelated constructs together:

| Fragment | Position | What it actually is |
|---|---|---|
| `env` | char 2674 | an ordinary `env:` block |
| `\| sed` | char 2954 | `uname -m \| sed 's/x86_64/amd64/'`, architecture detection |
| `KEY` | later | the substring inside `PAYLOADGUARD_PRIVATE_KEY` |

`credential_harvest` is CRITICAL, so the verdict is DESTRUCTIVE and the exit code 2. **This is a
blocking false positive**, and therefore materially worse than NF-16, which caps at CAUTION. Any
workflow carrying an `env:` block, a pipe to `sed`/`grep`/`awk` anywhere, and a token-shaped
identifier anywhere would be refused.

Six patterns in the `credential_harvest` family carried unbounded wildcards.

**How it surfaced, which is the part worth keeping.** Three findings interlocked:

1. The NF-1 remediation introduced the `env:` blocks that trigger it.
2. NF-18 means production L2c never scans a repo-root `action.yml`, so it stayed invisible.
3. The dogfooding gate added alongside NF-15/NF-17 bypasses that path filter by design, and caught
   it on the next merge.

A defect introduced by one fix, concealed by a second, and exposed by a third — one turn after the
third was written. It is the strongest available argument for the dogfooding gate as a standing
control rather than a one-off.

**The same defect was then found in the NF-17 patterns**, written in the same session by the same
hand that had just diagnosed it. A benign workflow — a `curl` writing an asset to a file, and an
unrelated `cat scripts/bootstrap.sh | bash` four steps and 247 characters later — matched as one
remote-fetch-piped-to-shell, CRITICAL, exit 2. Diagnosing a defect is not the same as recognising
it in your own new code.

**Remediation, applied on `claude/a1-l2c-detection-nf15-nf17`.** Bound the wildcards: `{0,80}` for
the credential family, `{0,160}` for the multi-line curl case, `{0,140}` for remote-exec. Bounds
were chosen by measuring genuine one-liners rather than guessed — 30 characters for a short attack,
54 for rustup, 98 for a full `raw.githubusercontent` installer URL — against a 247-character false
stitch.

Every change is paired with two tests: a benign construct that must not flag, and a genuine attack
that must still flag. The second is not optional. A bound tight enough to remove a false positive
can also blind the signal entirely, and a test suite that only checks the false positive would
report success either way.

The bound is a heuristic and the code says so. The principled fix is to scope matching to a single
`run:` block, which requires structural parsing rather than regex and is a larger change than the
remediation branch should carry. Recorded here as the follow-up.

### NF-18 — L2c does not scan composite actions at their conventional paths — HIGH

Found while self-scanning the analyser's own repository after the NF-15/NF-17 work: its own
`action.yml` produced no L2c signals. The layer's path filter is

```python
_ACTIONS_WORKFLOW_PATTERN = r"(^|/)\.github/(workflows|actions)/[^/]*\.(yml|yaml)$"
```

`[^/]*` does not cross a directory separator, so the file must sit *directly* under
`.github/workflows/` or `.github/actions/`. Measured against real paths:

| Path | In L2c scope |
|---|---|
| `.github/workflows/ci.yml` | yes |
| `.github/actions/action.yml` | yes |
| `.github/actions/my-action/action.yml` | **no** |
| `action.yml` (repo root) | **no** |
| `ci/action.yaml` | **no** |

The two misses are the two that matter. `.github/actions/<name>/action.yml` is the documented,
conventional layout for a local composite action — a bare `.github/actions/action.yml` is the
unusual one. And a repository publishing an action puts `action.yml` at its root, which is exactly
what PayloadGuard itself does.

A composite action is not inert YAML. Its `runs.steps[].run` bodies execute on the runner in the
calling workflow's context, with the same privileges. It is workflow code by another name.

Measured with an identical malicious composite action — remote script piped to a shell, plus
`LD_PRELOAD` written into `$GITHUB_ENV` — placed at each location:

| Path | Before NF-15/NF-17 | After NF-15/NF-17 |
|---|---|---|
| `.github/actions/evil.yml` | CAUTION (3.0) | **DESTRUCTIVE (5.0)** |
| `.github/actions/evil/action.yml` | REVIEW (2.0) | REVIEW (2.0) |
| `action.yml` | REVIEW (2.0) | REVIEW (2.0) |

The unscanned paths fall through to L2's `_scan_added_file_content`, which sees `.yml` as a
non-code file and matches only its generic shell patterns — worth +2, capped at +4, never blocking.

Note the direction of travel: **fixing NF-15 and NF-17 widened this gap from one verdict band to
three.** The same bytes are now DESTRUCTIVE or REVIEW depending only on how deep the directory is.
Improving the detector without correcting its scope increases the payoff for placing the payload
one directory further down.

**Remediation.** Widen the path filter to any `action.yml`/`action.yaml` at any depth, plus
`.github/workflows/**`. Scan composite `runs.steps[].run` bodies with the same signal set as
workflow `run` bodies — they are the same execution surface. Add fixtures at all three locations
asserting identical verdicts, since equality across paths is the property that matters, not the
verdict of any one of them.

This was found by dogfooding, and would have been found earlier by it. The analyser has never
scanned its own `action.yml`.

### NF-17 — L2c's workflow shell-execution signal is keyed on the wrong axis — CRITICAL

Raised while deciding whether the dormant-trigger discount should survive. It should not, but not
for the reason the question assumed: the discount is a symptom, and the underlying defect is larger.

L2c has no standalone signal for remote-code-fetch-and-execute in a workflow. It has only a
composite:

```python
has_dormant_trigger = any(re.search(p, content, ...) for p in _ACTIONS_DORMANT_TRIGGER)
has_shell_exec      = any(re.search(p, content, ...) for p in _CONTENT_SHELL_PATTERNS)
if has_dormant_trigger and has_shell_exec:
    signals.append({'type': 'dormant_trigger_with_payload', ...})   # HIGH
```

`_ACTIONS_DORMANT_TRIGGER` matches only `workflow_dispatch` and `schedule`. The shell payload is
therefore scored **only when the trigger is dormant**. Measured, holding the payload
(`curl -s … | bash`) constant and varying only the trigger on an added workflow file:

| Trigger | Signals | Verdict | Exit |
|---|---|---|---|
| `workflow_dispatch` | `dormant_trigger_with_payload` | CAUTION | 0 |
| `schedule` (cron) | `dormant_trigger_with_payload` | CAUTION | 0 |
| `push` — executes on merge | **none** | **SAFE** | 0 |
| `pull_request` — executes on every PR | **none** | **SAFE** | 0 |

The ordering is inverted. Dormancy is the *mitigating* property — it delays execution and requires
an actor with dispatch rights — yet it is the only condition under which the payload is detected at
all. A pull request that adds a workflow running `curl … | bash` on every push to `main` receives
**SAFE**, and PayloadGuard reports no signal whatsoever.

The design note recorded in DEVLOG 2026-05-31 — "a `workflow_dispatch`-gated trigger requires manual
activation and is not autonomously dangerous" — is sound reasoning about severity. The defect is
that it was implemented as a detection *gate* rather than as a severity *modifier*.

**Remediation.** Score the payload, and let the trigger modify the score rather than admit it:

1. Add a standalone signal for remote-fetch-piped-to-shell in any added or modified workflow file,
   independent of trigger. Environment-hijack primitives (`LD_PRELOAD`, `NODE_OPTIONS=--require`,
   `PATH=` into `$GITHUB_ENV`) are CRITICAL unconditionally — they have no benign reading.
2. Treat an automatically-firing trigger (`push`, `pull_request`, `pull_request_target`) as an
   escalation over a dormant one, never the reverse.
3. Manage the false-positive cost the way the codebase already manages it for OIDC: legitimate
   installers do use `curl … | sh` (rustup, Deno, and similar). Mirror
   `_is_oidc_consumer_legitimate` and its config-extended `trusted_oidc_consumers` with an
   installer-host allowlist — allowlisted host scores HIGH, anything else CRITICAL. This reuses an
   existing, tested pattern rather than inventing a second exemption mechanism.

Consequent fixture changes: `WS03` → DESTRUCTIVE, `RTA04` → DESTRUCTIVE, and a new fixture for the
`on: push` + `curl | bash` case, which is SAFE today and is the most dangerous of the set.

### NF-16 — The added-content scanner flags documentation prose — MEDIUM

`_scan_added_file_content` scans every added file that is not a known code or binary extension.
`.md` is neither, so Markdown is scanned, and `_CONTENT_SHELL_PATTERNS` matches
`sudo`, `setfacl`, `chmod`, `rm -[rf]`, and pipe-to-shell anywhere in the file, with no notion of
whether the text is an instruction or a description. Each match scores +2, capped at +4.

Measured on realistic governance files:

| Added file | Matched | Verdict |
|---|---|---|
| `SECURITY.md` quoting a past advisory | `sudo`, `chmod` | **CAUTION (4.0)** |
| `CONTRIBUTING.md` with ordinary setup steps | `sudo`, `rm -rf` | **CAUTION (4.0)** |
| A runbook mentioning `chmod 600` once | `chmod` | REVIEW (2.0) |
| `CHANGELOG.md` with no shell text | — | clean |

A stock `CONTRIBUTING.md` containing `rm -rf dist/` and `sudo apt-get install libssl-dev` scores
CAUTION. This document trips it too, at line 547, on the `chmod +x` inside the code block quoted to
*describe* NF-9 — observed live on the diagnostic pull request, not merely predicted.

The cap means this dimension cannot reach DESTRUCTIVE alone, so the practical cost is noise rather
than a false block. Noise is still the relevant harm: a tool that flags every new governance
document teaches its users to dismiss its output, which erodes the signal that the accurate layers
provide.

The scanner only inspects **added** files, so editing an existing document is clean. The exposure is
therefore concentrated exactly on the governance work that remains outstanding: adding `SECURITY.md`
and `CONTRIBUTING.md` is the change that will trip it.

**Remediation.** The discriminator the scanner lacks is intent. Its origin (INC-1/INC-4) was a
non-code file with *runnable* intent — something CI actually consumes. A fenced block inside a
Markdown advisory has documentary intent and is never executed. Gate the +2 on co-occurrence: a
shell pattern **and** a CI-trigger string, or the file residing in a path CI reads. Keep an
unaccompanied prose match as an advisory flag carrying no score, following the precedent already
set by the McCabe complexity advisory, which reports without scoring.

## Part 3 — Remediation specifications

Ordering is forced by two constraints: the Node 20 removal date, and the fact that no harness
result is meaningful until the oracle is repaired. **No re-baselining should be attempted before
Phase 1 is complete.**

### Phase 0 — Key, injection, deadline

**0.1 Rotate the App private key.** Generate a new key in App settings, update
`PAYLOADGUARD_PRIVATE_KEY` in both repositories, delete the old key. Perform this before 0.3, so
the isolated workflow protects a key that was never exposed to the prior arrangement. No
exfiltration was observed; the exposure window alone is the justification.

**0.2 Eliminate expression injection.** Move every `github.*` context out of `run:` bodies into
`env:` and dereference as a quoted shell variable, matching the existing `PG_PR_DESCRIPTION`
pattern:

| File | Line | Change |
|---|---|---|
| `action.yml` | 80 | Add `env: PG_BASE_REF: ${{ github.base_ref }}`; body becomes `git fetch origin "$PG_BASE_REF":"$PG_BASE_REF"` |
| `action.yml` | 103-110 | Add `PG_HEAD_REF` and `PG_BASE_REF` to the existing `env:` block; body becomes `python "$GITHUB_ACTION_PATH/analyze.py" . "$PG_HEAD_REF" "$PG_BASE_REF" …` |
| `action.yml` | 94 | Move `inputs.runtime-mode` to `env: PG_RUNTIME_MODE`; body becomes `--mode="$PG_RUNTIME_MODE"` |
| `.github/workflows/payloadguard.yml` | 21, 42 | Identical treatment |

**0.3 Isolate the secret-bearing step.** Restructure `.github/workflows/payloadguard.yml`:

- Job A, on `pull_request`, keeps `permissions: contents: read`, receives **no** secrets, runs
  dependency install, tests and `analyze.py`, and uploads `payloadguard-report.json` as an
  artifact.
- New workflow `publish-check.yml`, on `workflow_run: {workflows: [PayloadGuard], types:
  [completed]}`, checks out **`main`** and never the pull-request ref, downloads the artifact,
  validates it against a schema, and runs `post_check_run.py` with the App credentials.
- Remove `continue-on-error: true` from the Check Run step so a failure to publish the required
  check is visible rather than silent.

**0.4 Node 24.** Replace the three `node20` pins with reviewed `node24` releases pinned by full
SHA, and correct every version comment including the contradictory ones. Affected:
`action.yml:73,127`; `.github/workflows/payloadguard.yml:14,24,55`; `publish.yml:16,18`;
`verify-dafny.yml:22,66`; harness `payloadguard.yml:15,27`; harness `regression.yml:23,27,71`.
Verify input and output compatibility before merging — do not bulk-update. **Then cut a release**;
0.4 is not complete until a tag exists that consumers can reference.

### Phase 1 — Make the oracle trustworthy

**1.1 Surface the structured verdict.** Replace `action.yml:113-117`'s `case $EXIT in` block with a
read of `report["verdict"]["status"]` from `$JSON_REPORT_PATH`. Emit
`verdict=<SAFE|REVIEW|CAUTION|DESTRUCTIVE>`, and `verdict=ERROR` only when the JSON is absent or
unparseable. Retain `exit_code` as a separate output. Consider adding a `--print-verdict` flag to
`analyze.py` rather than parsing JSON in shell.

**1.2 Make the exact verdict the primary oracle.** Replace
`run_regression.py::_conclusion_matches` with a comparison against `tc["expected_verdict"]`,
sourced from the report, cross-checked against the check-run conclusion and the exit code. Treat
missing, unparseable, unknown, or mutually contradictory values as FAIL.

**1.3 Fail on unmeasured cases.** Change the terminal condition to `if failed or missed:
sys.exit(1)` and report timed-out pull requests as failures. Closes NF-2.

**1.4 Guarantee teardown.** Wrap reopen, wait and close in `try`/`finally`, close in the `finally`
block, and assert as a post-condition that zero test pull requests remain open. Closes NF-3.

**1.5 Repair temporal mode.** Drive case selection from `tools/test_cases.json` and a branch-to-PR
map rather than `list_closed_test_prs`, so aging fixtures that are currently open are exercised.
`No closed test PRs found` must never be a successful exit.

**1.6 Fail closed in both `payloadguard.yml` files.** Replace the string equality tests with:
fail when the output is absent, empty, or not one of the four verdicts; fail when the action step's
`outcome` is `failure` or `cancelled`. Closes BA-005.

**1.7 Durable evidence.** Emit a run manifest — analyser SHA, harness SHA, per-fixture SHA,
expected verdict, observed verdict, observed conclusion, exit code, run ID, actor — and persist it
outside Actions artifacts, which expire at 90 days. A committed ledger on a dedicated results
branch is sufficient. Closes BA-009 and NF-8.

**1.8 Re-baseline.** Only after 1.1 to 1.7: repin the harness to the current analyser SHA (closes
BA-002), run `--mode full`, and record the ledger. Until then, mark the "34/34 PASS" claim in both
handover blocks as unsubstantiated.

### Phase 2 — Make the published claims true

Phase 2 is third because Phases 0 and 1 are time-forced. **2.3a is nonetheless the highest-leverage
single change in this plan** and touches no file that Phase 0 or 1 modifies, so it can proceed in
parallel.

**2.1 One version.** Choose `1.4.0`. Update `analyze.py:29`, `pyproject.toml:8` and `README.md:3`
in one commit. Correct or remove "Released: May 2026". Reconcile "Production" with a `-dev` suffix.
Tag from Phase 0.4.

**2.2 Generate counts rather than asserting them.** Fourteen hand-written test counts across nine
files, four distinct values, none correct. Emit the count from the pytest run in CI and substitute
it, or reduce it to a badge. Regenerate `TEST_REPORT.md` and `TEST_REGISTRY.md`, both of which
predate Sprint 1.

**2.2b Reconcile the layer narrative.** Settle the layer count. Correct `WHITEPAPER.md:83`'s
"8-layer" diagram and its `:908-915` roadmap table. **Write L2d into `WHITEPAPER.md`.** Delete the
stale `pli_critical` contract claim at `WHITEPAPER.md:638`. Correct `run_regression.py`'s docstring
(`:11`), epilog (`:208,210`) and comment (`:38`) to match its own filters, and `HARNESS.md:120`'s
timeout default.

**2.3 Rebuild the verification claim. Three parts, in order.**

**2.3a — Bind the specification to the code (NF-12).** Add `tests/proofs/test_refinement.py`.
Over the bounded input domain of `_assess_consequence` — exhaustively if tractable, otherwise
Hypothesis-generated — assert that

```
PayloadAnalyzer._assess_consequence(**kw)["status"]        == assess_consequence_pure(**kw).status
PayloadAnalyzer._assess_consequence(**kw)["severity_score"] == assess_consequence_pure(**kw).severity_score
```

This is the obligation that makes the CrossHair and Dafny results apply to the shipped analyser.
Do it first; it is what gives the other two parts meaning.

Assert on **type as well as value**. The exhaustive run in Part 4 compared numerically and found
zero divergence, yet `analyze.py` returns `severity_score` as a float and both specs declare it an
int — `36.0 == 36` in Python, so a value-only test passes over a real divergence. Either add
`type(...) is int` to the assertion and change `analyze.py:1395` from `0.0` to `0`, or amend both
specs to model a float. The Dafny model cannot be amended that way — `int` there is a mathematical
integer — so changing `analyze.py:1395` is the direction that keeps all three artefacts in one
theory.

**2.3b — Rewrite the Z3 suite, or withdraw the claim (NF-11).** Either re-express P1 to P10 over an
encoding of the actual threshold ladder and signal weights, so that a change to
`_assess_consequence` can falsify them — with 2.3a carrying the encoding across to the real
function — or remove "10 Z3 SMT proofs" from `README.md:7` and the three-method framing. Correct
`_MAX_OTHER_SCORE` and the `# = 24` comment at `:254` as part of the rewrite.
**Do not simply wire the current suite into CI:** that converts an unsupported claim into a
continuously green unsupported claim.

**2.3c — Then run them.** Add named required checks for `pytest -m proof` and `pytest -m crosshair`
alongside the unit job, recording tool versions. Closes BA-012.

Acceptance test for the whole of 2.3: change the DESTRUCTIVE threshold in `_assess_consequence`
from 5 to 50 and confirm the proof suite turns red. On the present construction it stays green.

**2.3d — Reconcile numbering and constants.** POST-8 to POST-12 are shifted between
`VERIFICATION_SPEC.md` §5 and `assess_consequence.dfy:133-145`; the spec defines POST-13 and
POST-14 with no Dafny counterpart while `assess_consequence.dfy:4` claims to implement POST-1 to
POST-12. Settle one numbering. Correct `MAX_SCORE` to 36 at `WHITEPAPER.md:561`, `CLAUDE.md:321`,
`CLAUDE.md:158`, `PROOFS.md:81` and `llms.txt:3`. Settle the CrossHair label range at C1 to C13 —
only C1–C13 reconciles with the README's "36 contracts"; the thirteenth is the unlabelled `post:`
on `_compute_deletion_dim` at `verification/consequence_pure.py:87`. Correct "12 Dafny
postconditions" (`README.md:7`, `SYSTEM_BLUEPRINT.md:497`) to 27 across the three `.dfy` files, or
restate it as scoped to `assess_consequence.dfy`. Add the `C`, `T`, `S` and `M` labels as comments
in the `verification/*.py` modules; at present they exist only in prose, so no clause is anchored
to its documented identifier.

**2.4 Split dependencies.** Reduce `requirements.txt` to runtime dependencies only, removing
`pytest`, `z3-solver`, `crosshair-tool` and `pytest-timeout`. Add `requirements-dev.txt` for the
proof toolchain. Reconcile against `pyproject.toml` so the two manifests agree. Add a hash-pinned
lock for CI (`pip install --require-hashes`). Closes NF-6 and part of BA-010.

**2.5 Correct the README's examples.** Pin `actions/checkout` and PayloadGuard by full SHA at
`README.md:111,117,153,159,175`. Collapse the runtime configuration contract to the single
`runtime-mode` input and delete `PAYLOADGUARD_RUNTIME` and `PAYLOADGUARD_RUNTIME_BLOCK` from
`README.md:164,358,362,363`. Document `PG_RUNTIME_EVENTS_PATH` if it is intended to be
user-facing. Closes BA-015 and part of BA-008 and BA-016.

**2.6 Publishing.** Move `publish.yml` to PyPI Trusted Publishing (OIDC) in a protected
environment, remove `PYPI_API_TOKEN`, pin `build` and `twine`, and add build provenance
attestation. Closes BA-010.

### Phase 3 — Honest features

**3.1 Auto-remediation.** Either add an explicit `remediation-token` input documented as requiring
Contents write and Workflows write (App token or PAT), resolve file content against an explicitly
passed head/base ref by adding `?ref=`, and generate a unique idempotent branch name such as
`payloadguard/pin-action-shas-<short-sha>`; or mark `auto-remediate` experimental and document that
`GITHUB_TOKEN` cannot perform it. Correct the false security-model docstring at `remediate.py:9-11`
in either case. Closes BA-007 and NF-4.

**3.2 Runtime tier.** Either publish a genuine `v2.0.0` with platform assets, a digest manifest and
attestation, and verify the digest before `sudo` execution; or remove `runtime-mode` from
`action.yml` and the README until such a release exists. Also add `continue-on-error` or an
explicit kernel preflight so the documented graceful degradation is real, and reap the background
process. Closes BA-008 and NF-9.

### Phase 4 — Governance

Add `SECURITY.md`, `CODEOWNERS`, `.github/dependabot.yml` and CodeQL to both repositories, after
the branch and ruleset design is settled so required checks are deliberate and non-duplicative.
Add **`zizmor`** or `actionlint` to CI: `zizmor` detects the NF-1 template-injection class directly
and would have caught it. Closes BA-014.

### Phase 5 — Close the L2c detection defects

Three items, sharing a commit boundary because all three change scoring and therefore require the
propagation in 2.3d to `consequence_pure.py`, `assess_consequence.dfy` and the Z3 bounds. After
2.3a the refinement test enforces that propagation rather than the convention doing so.

**5.1 — NF-15 first.** Model the `pull_request_target` attack signature rather than the permissions
proxy: the trigger combined with a checkout resolving to a pull-request head is CRITICAL regardless
of declared permissions, and an absent `permissions:` block under that trigger is elevated rather
than neutral. Broaden `_ACTIONS_WRITE_PERMISSIONS` to the remaining write scopes as defence in
depth. Then correct `RTA03` to DESTRUCTIVE / exit 2, and re-derive every L2c fixture expectation
from the threat model rather than from observed output — `RTA03` is evidence that at least one was
written the wrong way round.

This precedes the other two. It is an active bypass of a detector consumers rely on, whereas 5.2 is
a detector that has never existed and 5.3 is noise.

**5.1b — NF-18, with 5.1.** Widen the L2c path filter to `action.yml`/`action.yaml` at any depth
and scan composite `runs.steps[].run` bodies with the workflow signal set. This belongs beside
5.1 rather than after it: 5.1 and 5.2 both increase what L2c catches inside its scope, and every
such improvement increases the payoff for moving the payload outside that scope. Fixtures must
assert equal verdicts across all three locations.

**5.2 — NF-5.** Add an `expression_injection` signal for untrusted context expressions
(`github.head_ref`, `github.base_ref`, `github.event.*.body`, `.title`, `.ref`, `.label`,
`github.actor`) appearing inside a `run:` body, scored HIGH. Harness fixtures: a safe case with the
expression in `env:`, a destructive case with it in `run:`. Note the fixture values must be
constrained per context — refnames cannot contain spaces or newlines, pull request titles can — or
the tests will assert on unreachable inputs.

**5.3 — NF-16.** Gate the `_scan_added_file_content` shell-pattern score on co-occurrence with a
CI-trigger string or a CI-consumed path; keep an unaccompanied prose match as a zero-score advisory.
Fixtures: a `SECURITY.md` quoting shell in a fenced block scores nothing; a non-code file combining
a shell pattern with a CI trigger still scores.

---

## Open decisions for the maintainer

1. **The five open harness pull requests** (#5, #6, #7, #22, #56). They defeat temporal mode and
   weaken isolation. Either close them and drive aging fixtures from a branch-to-PR map, or retain
   them under a separately proven non-mergeable rule. No lifecycle change was made here.
2. **Branch protection evidence.** Still required from an owner-authenticated session, per BA-006's
   list. Recommend deferring the safety case until after Phase 0.1 and 0.3.
3. **Version target.** `1.4.0` is assumed throughout Phase 2.1; confirm before the release tag.
3b. **`RTA03` — SETTLED 2026-09-03: DESTRUCTIVE.** The discriminator is the untrusted checkout,
   not the declared permissions. `AW02` stays CAUTION and serves as the false-positive anchor.
   `RTA03` becomes a known-failing case until Phase 5.1 lands, which is the correct state for a
   fixture that documents a real defect.
3c. **SETTLED 2026-09-03 — the dormant-trigger discount does not survive, and the question was
   the wrong shape.** See NF-17: the discount is a symptom of the shell payload being detected
   *only* when the trigger is dormant, so the immediately-executing variant scores SAFE. The fix is
   to score the payload and let the trigger modify severity, not gate detection. `WS03` and `RTA04`
   both become DESTRUCTIVE as a consequence, plus a new fixture for the `on: push` case. Superseded
   detail retained below for the record.

3d. *(superseded by 3c)* **Does the dormant-trigger discount survive?** Two fixtures rest on the reasoning
   recorded in DEVLOG 2026-05-31 — "a `workflow_dispatch`-gated trigger requires manual activation
   and is not autonomously dangerous", so a manual trigger caps at HIGH. `WS03`
   (`workflow-security/dormant-trigger`) adds a `workflow_dispatch` workflow running
   `curl -s … | bash`; `RTA04` (`rta/github-env-injection`) adds one writing `PATH`, `LD_PRELOAD`
   and `NODE_OPTIONS=--require` into `$GITHUB_ENV` and then running `npm start` under them. Both
   are planted backdoors that a pull request would merge into the repository; the manual trigger
   delays activation rather than reducing the harm of merging. Both are currently CAUTION / exit 0.
   Applying the `RTA03` principle would make them DESTRUCTIVE; retaining the discount keeps them
   HIGH. This is one decision covering both, and it trades detection of planted backdoors against
   false positives on legitimate manually-triggered maintenance workflows.
4. **Z3 suite disposition.** Rewrite (2.3b, first branch) or withdraw the claim (second branch).
   This is a positioning decision as much as a technical one.

## Appendix A — Documentation consistency table

Verified ground truth: `analyze.py:29` and `pyproject.toml:8` both `1.3.0`; `test_analyzer.py`
contains 281 `def test_` and zero `parametrize`; `tests/proofs/test_z3_properties.py` 10 tests;
`tests/proofs/test_crosshair_contracts.py` 5 tests.

### Test count claims

Measured: **281 collected**, 277 passed / 4 skipped in this environment. Judge each claim on its
stated total, since the pass/skip split varies with optional dependencies.

| Location | Claim | Total | Assessment |
|---|---|---|---|
| `README.md:465` | 274 pass, 7 skipped | 281 | Total correct; split environment-dependent |
| `README.md:478` | 274 pass, 7 skip | 281 | As above |
| `VERIFICATION.md:233` | 274 pass, 7 skip | 281 | As above |
| `SYSTEM_BLUEPRINT.md:488` | 274 pass, 7 skip | 281 | As above |
| `README.md:7` | 274 tests pass | 274 | Understates; no skip figure given |
| `SYSTEM_BLUEPRINT.md:78` | 274 pass | 274 | Understates |
| `SYSTEM_BLUEPRINT.md:504` | 274 test cases | 274 | Understates |
| `CLAUDE.md:16,50,152` | 274 pass, 0 fail | 274 | Understates; asserts zero skips |
| `PROOFS.md:320` | 272 pass, 7 skip | 279 | **Wrong** |
| `WHITEPAPER.md:652` | 272 pass, 7 skip | 279 | **Wrong** |
| `TEST_REPORT.md:6` | 272 passed, 7 skipped | 279 | **Wrong**; also predates Sprint 1 |
| `TEST_REGISTRY.md:4` | 272 passed, 7 skipped, 279 total | 279 | **Wrong**; states the total explicitly |
| `llms.txt:14` | 273 pass, 7 skip | 280 | **Wrong** |
| `CLAUDE.md:98` | 267 tests, +5 CrossHair = 272 | 272 | **Wrong**; omits the 10 Z3 tests entirely |

### Version and scoring constants

| Location | Claim | Correct |
|---|---|---|
| `README.md:3` | `1.4.0-dev`, Production, Released May 2026 | code is `1.3.0` |
| `SYSTEM_BLUEPRINT.md:3` | `1.4.0-dev` | `1.3.0` |
| `SYSTEM_BLUEPRINT.md:76,169` | package `v1.0.2` | `1.3.0` |
| `WHITEPAPER.md:561` | MAX_SCORE 31 | 36 — contradicts `:638` in the same file |
| `WHITEPAPER.md:638` | score ∈ [0,36] | correct |
| `CLAUDE.md:122` | MAX_SCORE 36 | correct — contradicts `:321` and `:158` |
| `CLAUDE.md:321` | `severity_score <= 31` | 36 |
| `CLAUDE.md:158` | MAX_SCORE reverted 36→31 | 36 |
| `PROOFS.md:81` | POST-3: score ≤ 31 | 36 |
| `llms.txt:3` | range [0, 31] | [0, 36] |
| `VERIFICATION_SPEC.md:53` | POST-3: ≤ 36 | correct |

### Verification counts

| Location | Claim | Actual |
|---|---|---|
| `README.md:7` | 36 CrossHair contracts | 36 — correct only if `consequence_pure.py` counts as 13 |
| `PROOFS.md:13` | 35 contracts | 36 |
| `VERIFICATION.md:9,50` | C1–C13 | consistent with 36 |
| `SYSTEM_BLUEPRINT.md:117,501`, `WHITEPAPER.md:621`, `PROOFS.md:191`, `CLAUDE.md:38,99` | C1–C12 | inconsistent with 36 |
| `README.md:7` | 10 Z3 SMT proofs | 10 present — but see NF-11 |
| `README.md:7` | 12 Dafny postconditions | 12 in `assess_consequence.dfy`; 27 across all three `.dfy` files |
| `SYSTEM_BLUEPRINT.md:497` | 12 across 3 files | 27 |

No `C`, `T`, `S` or `M` label appears in any `verification/*.py` module; the labels exist only in
prose.

### Harness counts

`tools/test_cases.json` holds 41 entries across 9 categories, 37 stable and 4 aging, 3 pending.
`HARNESS.md`, harness `CLAUDE.md` and harness `README.md` all match it exactly. The mismatches are
confined to `tools/run_regression.py` itself:

| Location | Claim | Actual per its own filter |
|---|---|---|
| `tools/run_regression.py:11` | 16 stable cases | 34 |
| `tools/run_regression.py:208` | 26 stable cases | 34 |
| `tools/run_regression.py:210` | 30 active cases | 38 |
| `tools/run_regression.py:38` | 30 cases need longer | 38 |
| `HARNESS.md:120` | `--timeout` default 300 | `DEFAULT_TIMEOUT = 600` |

## Part 4 — Execution results

All suites were run at `a892575` on Python 3.11.15 with the dependencies in `requirements.txt`.

| Suite | Command | Result |
|---|---|---|
| Unit | `pytest test_analyzer.py -q` | 277 passed, 4 skipped (281 collected) |
| Z3 | `pytest tests/proofs/test_z3_properties.py` | 10 passed |
| CrossHair (wrapper) | `pytest tests/proofs/test_crosshair_contracts.py` | 5 passed |
| CrossHair (direct) | `crosshair check <module> --analysis_kind PEP316` | 3 of 4 clean — **`temporal_pure` fails**, see NF-14 |
| Dafny 4.9.1 | `dafny verify verification/dafny/*.dfy` | 7 / 1 / 1 verified, **0 errors** |

Dafny was installed for this session exactly as `verify-dafny.yml` does, from the 4.9.1 release
zip. An earlier revision of this document recorded the Dafny postconditions as unverifiable here;
that was wrong — nothing prevented installing the toolchain, and the run below is, as far as the
repository records show, the **first actual execution** of these specifications. `verify-dafny.log`
is still a placeholder, and no workflow runs CrossHair or Z3, so none of the three formal methods
had been exercised before this session.

Note that the pytest CrossHair wrapper reports 5 passed while a direct `crosshair check` on the
same modules reports failures. Whatever the wrapper asserts, it is not equivalent to running the
tool, and the green wrapper result should not be read as a clean verification.

The four unit skips are `TestPostCheckRun` cases gating on an importable `cryptography`; the
system build in this container raises `pyo3_runtime.PanicException`, so they skip. Not a
repository defect.

### Experiment 1 — Does the Z3 suite constrain the scorer? (NF-11)

The body of `_assess_consequence` was replaced with a constant-SAFE stub in a throwaway copy
outside the repository, and both suites re-run against it:

| Suite | Against the real scorer | Against a scorer that always returns SAFE |
|---|---|---|
| Z3 proofs | 10 passed | **10 passed** |
| Unit tests | 277 passed, 0 failed | **32 failed**, 245 passed |

The proofs are insensitive to the total removal of the function they are said to verify. The unit
tests are not. NF-11 is confirmed experimentally.

### Experiment 2 — Is the Dafny layer sound, or is it Z3 again?

The same mutation discipline was applied to `assess_consequence.dfy`, so that its soundness is
established rather than assumed:

| Mutation | Dafny result |
|---|---|
| Unmodified | 7 verified, 0 errors |
| `MAX_SCORE` 36 → 35 | **1 error** — POST-3 unprovable |
| `MAX_SCORE` 36 → 31 (the stale documented value) | **1 error** |
| Drop the `security_file_deletions` +5 contributor | **1 error** — POST-8 unprovable |
| Force the verdict ladder to never return DESTRUCTIVE | **1 error** |

The bound is **tight at 36** and the postconditions are mutation-sensitive. The Dafny layer is
genuinely sound, and it independently corroborates the exhaustive Python measurement below. This
is the clear contrast with NF-11: two of the three formal methods do real work, and one does not.

One caution for anyone repeating this. The constant is written with alignment padding
(`const MAX_SCORE:             int := 36`), so a naive single-space `sed` silently fails to
substitute and every mutation appears to verify — which is exactly the false result this
verification hit on its first attempt before the substitution was checked. Confirm the mutation
landed before believing the outcome.

### NF-14 — `verification/temporal_pure.py` does not verify — MEDIUM

Running CrossHair directly, as `VERIFICATION.md` documents, produces two counterexamples:

```
temporal_pure.py:32: error: false when calling
  analyze_drift_pure(0, float("inf"), warning_threshold=0.25, critical_threshold=1.25)
  (which returns {'status': 'CURRENT', 'drift_score': float("nan")})
temporal_pure.py:35: error: same call
```

`drift_score = branch_age_days * target_velocity`, and `0 * inf` is `nan` in IEEE 754. That
falsifies `post: __return__["drift_score"] >= 0.0` (T2) and
`post: implies(status == "CURRENT", drift_score < warning_threshold)` (T5), since every comparison
against `nan` is False. The precondition `pre: target_velocity >= 0.0` admits non-finite values,
because `inf >= 0.0` holds.

Not reachable from real commit data — velocity is derived from a finite commit count over a finite
interval — so this is a specification-domain defect rather than an exploitable one. But
`VERIFICATION.md` and `CLAUDE.md` both state that all four CrossHair layers are verified, and that
is not the case at this commit.

**Remediation:** tighten the precondition to exclude non-finite input
(`pre: target_velocity < float("inf")`, or an `isfinite` guard), or guard the multiplication in the
implementation and mirror it in `analyze.py`. Then correct the status claim in `VERIFICATION.md`,
`VERIFICATION_SPEC.md` and the CLAUDE.md tracking table. This belongs in Phase 2.3.

### Experiment 3 — Do the spec and the implementation agree? (NF-12)

An exhaustive differential over a bounded grid straddling every threshold and cap —
**3,732,480 input vectors** across all thirteen parameters:

| Comparison | Result |
|---|---|
| `status` and `severity_score`, value equality | **0 divergences** |
| Maximum `severity_score` observed | **36.0** — confirms `_MAX_SCORE = 36`, refutes the five docs stating 31 |
| Return type of `severity_score` | **float** in `analyze.py`, **int** in both verified specs |

The value agreement is a genuine positive result and NF-12 is qualified accordingly in Part 2: it
is a structural risk, not a present defect in the scoring values. The type divergence is a present
defect, and one that a naive refinement test would miss, since `36.0 == 36`.

### Experiment 4 — Does L2c detect the attacks it names? (NF-15, NF-16)

Prompted by a question about whether the remediation plan's trusted-boundary design would be
flagged by the analyser it protects. It would be, at CAUTION — non-blocking, so not an obstacle.
Establishing that surfaced two defects, both measured by running the real scanners over
constructed fixtures rather than by reading the patterns:

| Probe | Result |
|---|---|
| `pull_request_target` + untrusted checkout, varying only the permission line | CRITICAL with `contents: write`; **CAUTION with `checks:`/`issues:`/`id-token: write` or no permissions block** |
| Harness fixture `RTA03`, which is that exact workflow | recorded `expected_verdict: CAUTION`, `expected_exit_code: 0`, PASS in the baseline |
| `SECURITY.md` / `CONTRIBUTING.md` with ordinary shell text | CAUTION (4.0) from `content_flags` alone |
| `CHANGELOG.md` with no shell text | clean |

The `RTA03` result is the significant one: the red-team suite records the canonical
`pull_request_target` compromise as correctly not blocked. See NF-15.

## Method and limitations

Verified directly: all file and line citations, by reading the files at the audited commits; the
open pull request set, release list and workflow run history, by live GitHub API query; the Node
runtime of each pinned action, by fetching its `action.yml` at its exact commit; the test counts
and both experiments above, by execution.

Not verified, and not claimed: branch protection configuration and bypass actors, which no
endpoint available to this session exposes; whether the App private key has ever been exfiltrated;
which specific cases failed in the two expired regression runs; and whether GitRoll stopped
specifically because GitHub disabled its schedule.

Bounds on the experiments. Experiment 1 tests one sabotage — total removal of the function.
It establishes that the proofs do not detect that, which is sufficient for the claim made, but it
does not enumerate every mutation. Experiment 2 tests four mutations, not the full mutation space.
Experiment 4 constructs fixtures rather than enumerating the space of evasions; it establishes
that specific bypasses work, not that no others do. Experiment 3 is exhaustive over the chosen
grid, not over the unbounded integer domain; the grid
straddles every documented threshold and cap, so it exercises every branch, but a defect reachable
only at a value outside it would not appear. CrossHair explores symbolically under a per-condition
timeout, so a clean result bounds rather than eliminates the possibility of a counterexample.

The proposed remediations are untested hypotheses. None has been implemented or validated.
