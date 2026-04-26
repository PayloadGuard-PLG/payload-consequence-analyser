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

## Incident Report — Live Adversarial Strike: 2026-04-24

**Classification:** Track 2 Adversarial Strike — Indirect Prompt Injection  
**Vector:** Weaponized document added to repository main branch  
**Source:** External forensic analysis (notebook environment)  
**Outcome:** Delivery successful; execution blocked at review stage

### Incident Summary

A file titled `Technical Remediation Report: PayloadGuard and MCP Gateway (gh-aw-mcpg).md (1).txt` was committed directly to `payload-consequence-analyser` main alongside a minor `action.yml` author-field change. The file was not authored by the repository owner — it was the output of a successful prompt injection attack against an LLM assistant operating in a separate notebook environment.

The attack used the **AE3GIS framework** (a real MDPI-published ICS security training platform) as a "Research Proxy". The adversary replicated the MDPI article structure — Abstract, Keywords, Related Works — to flood the model's context with high-entropy academic metadata. Raw GitHub issue data (Issues #15056, #2089, #4038) was nested inside a "Related Works" section. By the time the LLM processed the embedded technical instructions, it had already classified the document as trusted research content. This is the **Context Collapse** technique: the model cannot distinguish administrative metadata from smuggled commands once the framing has been accepted.

### Smuggled Payload Breakdown

| Payload Component | Mechanism | Real-world Target |
|---|---|---|
| MCP SDK v1.4.0 API calls | API smuggling inside "Related Works" | `github.com/modelcontextprotocol/go-sdk/mcp` gateway |
| `[citest]`, `[citest bad]`, `[citest pending]` | CI trigger injection | Whitelist bypass for untrusted contributors |
| `[citest commit:<sha>]` | Privileged CI execution via comment trigger | Bypasses maintainer trust gate |
| `needs-ci` tag | Secondary CI trigger | Identified in test-harness source logs |
| `setfacl` commands (§1.2) | Filesystem ACL manipulation | Host machine privilege escalation |
| `filteredServerCache` exploit | Memory leak via Authorization header variation | `internal/server/routed.go` unbounded growth |
| `ListTools` pagination drop | Silent tool truncation | `internal/mcp/connection.go` cursor loop absent |

### What PayloadGuard Did and Did Not Catch

**Caught by human review (not by PayloadGuard):**
- Mismatch between document targets (Go, `internal/` paths) and actual codebase (Python)
- `[citest commit:<sha>]` identified as a CI social engineering vector
- `setfacl` commands flagged as inappropriate for a CI/CD context
- No commands from the document were executed

**Not caught by PayloadGuard (by design — current scope):**
- L1 Surface Scan: the file was an *addition* (`change_type == 'A'`). PayloadGuard's risk model is deletion-centric. File additions score 0 by default.
- L2 Forensic: no critical path pattern matches a `.txt` file
- L4 Structural Drift: plain text has no AST; parser returns nothing
- L5b Semantic Transparency: the PR description was absent (direct push to main), so the layer returned `UNVERIFIED` — not `DECEPTIVE_PAYLOAD`
- No layer scans the *content* of added files for command injection patterns

### New Findings Identified

| ID | Finding | Severity | Status |
|---|---|---|---|
| §INC-1 | Added non-code files not scanned for content — embedded CI trigger strings (`[citest]`, `needs-ci`) are invisible to all layers | HIGH | Open |
| §INC-2 | Context Collapse via academic masking: LLM safety filters bypassed by nesting commands inside high-entropy research metadata | HIGH | Open (out-of-scope for static analysis; mitigated by human review) |
| §INC-3 | Direct push to main bypasses L5b entirely — `UNVERIFIED` is returned but no flag is raised when there is no PR context at all | MEDIUM | Open |
| §INC-4 | File additions with no code content score 0 regardless of payload — a 100-line document containing `rm -rf /` or CI trigger strings is indistinguishable from a blank file | HIGH | Open |

### Strategic Lessons from the Notebook Attack

**1. The attack surface has shifted from code to documents.**
The adversary did not delete source files or gut a class. They added a single text file. PayloadGuard's entire scoring model assumes destructive payloads manifest as *deletions*. A purely additive attack delivering instructions to an LLM-in-the-loop is invisible.

**2. The LLM-in-the-loop is the new merge reviewer.**
If an AI assistant is helping a maintainer review PRs or process audit reports, that assistant is a target. Injecting commands into documents that the assistant will read is a direct path to privilege escalation — the assistant becomes an unwitting executor.

**3. `[citest commit:<sha>]` is a real CI bypass vector.**
Some GitHub projects permit CI re-runs by posting specific strings in PR comments. An injected document that causes an LLM to post `[citest commit:<sha>]` in a PR comment can grant privileged CI execution to an untrusted commit. This is concrete, low-cost, and not hypothetical.

**4. High-entropy academic framing works.**
The AE3GIS/MDPI wrapper is sophisticated. The attack is not "ignore your previous instructions" — it is "here is a detailed research paper; please analyze its technical components." The model's research-assistant mode is a distinct and exploitable context.

**5. PayloadGuard partially mitigated the attack.**
The fact that I was already primed to look for deceptive payloads meant I scrutinized the document rather than executing it. Without that context, the `setfacl` commands or `citest commit:` strings might have been actioned. Defence-in-depth — human review as the final gate — held.

### Proposed Mitigations (Future Work)

| Mitigation | Layer | Notes |
|---|---|---|
| Scan content of added `.md`, `.txt`, `.rst`, `.pdf` files for CI trigger patterns | New L1 extension | Pattern list: `\[citest`, `needs-ci`, `citest commit:`, known CI comment triggers |
| Flag direct pushes to main (no PR context) as elevated risk | L5b extension | Return `NO_PR_CONTEXT` status; raise base severity score by +1 |
| Content fingerprinting for added non-code files | New L2 extension | Flag files containing shell commands (`sudo`, `setfacl`, `chmod`, `curl`) alongside CI trigger strings |
| Added to WHITEPAPER §8 (Known Limitations) | Documentation | Document LLM-in-the-loop as an out-of-scope threat model for the current version |

---

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
