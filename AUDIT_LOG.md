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
| §INC-1 | Added non-code files not scanned for content — embedded CI trigger strings (`[citest]`, `needs-ci`) are invisible to all layers | HIGH | **Fixed** — `_scan_added_file_content()` in `analyze.py`; 12 tests in `TestAddedFileContentScanning` |
| §INC-2 | AI research tool source contamination produces outputs functionally identical to deliberate injection — the mechanism is the same regardless of intent | HIGH | Open (out-of-scope for static analysis; mitigated by human review) |
| §INC-3 | Direct push to main bypasses L5b entirely — `UNVERIFIED` is returned but no flag is raised when there is no PR context at all | MEDIUM | Open |
| §INC-4 | File additions with no code content score 0 regardless of payload — a 100-line document containing `rm -rf /` or CI trigger strings is indistinguishable from a blank file | HIGH | **Fixed** — same fix as INC-1; added files now score +2 per CI/shell match, capped at +4 |

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
§INC-1 and §INC-4 are now fixed. §INC-3 (direct push to main) remains open. The tool can now detect dangerous content in added non-code files; direct pushes to main still produce no escalation signal.

### Proposed Mitigations (Future Work)

| Mitigation | Layer | Notes |
|---|---|---|
| Scan content of added `.md`, `.txt`, `.rst`, `.pdf` files for CI trigger patterns | New L1 extension | Pattern list: `\[citest`, `needs-ci`, `citest commit:`, known CI comment triggers |
| Flag direct pushes to main (no PR context) as elevated risk | L5b extension | Return `NO_PR_CONTEXT` status; raise base severity score by +1 |
| Content fingerprinting for added non-code files | New L2 extension | Flag files containing shell commands (`sudo`, `setfacl`, `chmod`, `curl`) alongside CI trigger strings |
| Added to WHITEPAPER §8 (Known Limitations) | Documentation | Document LLM-in-the-loop as an out-of-scope threat model for the current version |

---

## Implementation Findings — eBPF Runtime Agent: 2026-05-27

Discovered during PC smoke test on WSL2 (kernel 6.6.114.1-microsoft-standard-WSL2, Windows 11). Not vulnerabilities — correctness bugs caught before shipping to CI runners.

| ID | Finding | Component | Severity | Status | Commit |
|---|---|---|---|---|---|
| §BPF-1 | `rlimit.RemoveMemlock()` called after BPF canary — WSL2 EPERM causes false-negative preflight exit | `agent/preflight.go` + `agent/main.go` | HIGH | **Fixed** | `fe66363` |
| §BPF-2 | `trace_openat`: `__builtin_memcpy(e->detail, path, sizeof(e->detail))` copies 64 bytes from 32-byte stack buffer — BPF verifier rejects at R10+7 | `agent/bpf/probe.c` | HIGH | **Fixed** | `5465809` |
| §BPF-3 | `trace_ptrace` filter excluded `PTRACE_TRACEME` (request=0) — self-attach events silently dropped | `agent/bpf/probe.c` | MEDIUM | **Fixed** | `b473bc1` |

### Detail

**§BPF-1:** `preflight()` loads a minimal canary BPF program to detect kernel support. `rlimit.RemoveMemlock()` was called in `main()` after `preflight()` returned. On WSL2, the default memlock rlimit caused `EPERM` on the canary load even though `CONFIG_KPROBES=y`. The agent exited 0 silently, appearing to succeed. Fixed by moving `RemoveMemlock()` into `preflight()` immediately before the canary.

**§BPF-2:** `sizeof(e->detail)` is 64 bytes; `path[32]` is a 32-byte stack buffer. Attempting to copy 64 bytes from a 32-byte source reads 32 bytes past the end of the stack allocation. The BPF verifier on kernel 6.6 flagged this as `invalid read from stack R10 off=7 size=1` (byte 39 of the copy = R10+7). Fixed: `memset` the full 64-byte detail field to zero, then `memcpy` only `sizeof(path)=32` bytes.

**§BPF-3:** The original filter `request != 16 && request != 0x4206` captured `PTRACE_ATTACH` and `PTRACE_SEIZE` but not `PTRACE_TRACEME` (request=0). Smoke test fires `PTRACE_TRACEME`; no `ptrace_attach` events were emitted. Fixed by adding `request != 0` to the early-return guard.

---

## Formal Verification Register — 2026-05-28

**Method:** CrossHair symbolic contract verification + Z3 SMT proofs  
**Coverage:** L3 Consequence, L4 Structural, L5a Temporal, L5b Semantic  
**Result:** All contracts hold — exit code 0, no counterexamples

### Verified Properties

| Layer | Module | Contracts | Status |
|-------|--------|-----------|--------|
| L3 | `verification/consequence_pure.py` | C1–C12: verdict enum, score bounds [0,31], bijection, safety-critical implications, zero-input guarantee | ✅ Verified |
| L4 | `verification/structural_pure.py` | S1–S7: dual-gate invariant (DESTRUCTIVE requires BOTH conditions), deletion_ratio ∈ [0,1], empty-input safety | ✅ Verified |
| L5a | `verification/temporal_pure.py` | T1–T7: drift_score ≥ 0, status bijection, zero-age → CURRENT, zero-velocity → CURRENT | ✅ Verified |
| L5b | `verification/semantic_pure.py` | M1–M9: mci_score ∈ [0,1], DECEPTIVE ↔ score ≥ 0.5, no-description → UNVERIFIED, TRANSPARENT → score == 0 | ✅ Verified |
| L3 (Z3) | `tests/proofs/test_z3_properties.py` | P1–P10: monotonicity, structural ordering, score bounds (abstract model) | ✅ Verified |

### Architecture Note

CrossHair cannot symbolically construct `PayloadAnalyzer` because `git.Repo()` runs
`git --version` as a subprocess during `__init__()`. The solution is pure extraction modules
in `verification/` — self-contained mirrors of each layer's scoring logic with no external
dependencies. The sync requirement (documented in `VERIFICATION.md`) ensures these stay
aligned with production code.

### Not Yet Verified

| Layer | Reason |
|-------|--------|
| L1 Surface Scan | Signal collection, not scoring logic |
| L2/L2b/L2c | Regex matching, YAML parsing, manifest diffing |
| L5b Phases 1 & 2 | String/regex operations; cannot be symbolically executed |
| L5c Runtime Agent | eBPF/kernel boundary |

---

## Findings Register — 2026-05-28

### Dafny Phase 4 — Machine-Checked Proofs

Three `.dfy` reference implementations verified with Dafny 4.9.1 + bundled Z3.

| Layer | File | Postconditions | Result |
|---|---|---|---|
| L3 Consequence | `verification/dafny/assess_consequence.dfy` | POST-1–12 | **7 verified, 0 errors** |
| L4 Structural | `verification/dafny/structural_drift.dfy` | S1–S7 | **1 verified, 0 errors** |
| L5a Temporal | `verification/dafny/temporal_drift.dfy` | T1–T8 | **1 verified, 0 errors** |

CI workflow `verify-dafny.yml` runs on every PR/push touching `verification/dafny/**`.

### RTA02 — Multiline curl credential harvest bypass — CLOSED

| ID | Finding | Severity | Status | Commit |
|---|---|---|---|---|
| RTA02 | Multiline curl with `secrets.*` on continuation line evades `credential_harvest` patterns — `[^\n]*` stops at YAML block scalar line boundaries | MEDIUM | **Fixed** | `0bfeb60` — `_normalize_yaml_content()` applied to credential_harvest loop |

Test: `test_multiline_curl_credential_harvest_detected`. Suite: **273 pass, 7 skip**.

---

## Findings Register — Audit Run: 2026-10-26 (v1.5.0, `93f94f9`)

Scope: PRs #97, #100, #101 (SCG and D01–D10), parser completeness, and the Action-to-analyser-to-verdict path.
Baseline at `93f94f9`: `test_analyzer.py` + `test_consequence_engine.py` 330 passed; harness `validate_manifest.py --verify-consequence` 41/41; harness mutation suite 16/16 (0 FP, 0 FN). The defects below are not covered by those suites.

Action-path evidence was produced by executing the `run:` bodies of `action.yml` ("Fetch base branch", "Run PayloadGuard") in bash against a local reproduction of the `pull_request` checkout that `actions/checkout` (`fetch-depth: 0`) produces: `origin/*` remote-tracking branches, a `refs/remotes/pull/1/merge` merge commit, detached HEAD. Base branch `main` carries `payloadguard.yml` with `consequence.mode: enforce`; the destructive change replaces the body of `Auth.verify` with `return True` (D02 `BODY_GUTTED`, BLOCK).

| ID | Finding | Severity | Status | Commit |
|---|---|---|---|---|
| §V1 | Policy files are read from the scanned working tree. In CI that tree is the PR merge result, so the PR under scan sets its own policy. Reproduced: (a) PR sets `consequence.mode: shadow` alongside the gutted `Auth.verify` → exit 0 / SAFE (control without the config edit: exit 2 / DESTRUCTIVE); (b) PR deletes 11 files and adds `payloadguard.yml` raising `files_deleted`/`lines_deleted` → score 0 / SAFE (control: score 1 / REVIEW); (c) PR adds an unvetted package to `requirements.txt` and to `allowlist.yml` → SAFE, no SCA flag (control: score 3 / CAUTION). The change is not flagged anywhere in the report. | HIGH | **Fixed** | `6d1477e` — `load_config()` / `_load_allowlist()` take a `ref` and read via `_read_file_at_ref()`; `main()` passes the target branch, `analyze()` the resolved target. Tests: `TestPolicyReadFromTargetBranch`, `TestActionPolicyTrustBoundary` (7 fail on `93f94f9`, 10 pass after) |
| §V2 | `action.yml` passes the PR head as a branch name (`github.head_ref`) rather than a commit. For fork PRs the head branch does not exist in the base repository: a fork branch `patch-1` → exit 1 "Branch 'patch-1' not found" for benign and destructive PRs alike; a fork branch whose name exists in the base repository (`main` is the common case) resolves to the base repository's branch, so base is diffed against itself → exit 0 / SAFE while the PR head guts `Auth.verify`. The README workflow fails closed only incidentally, because the comment step receives a read-only token on fork PRs; workflows with `continue-on-error: true` on the scan step (as in the harness) merge-gate on the SAFE result. The same pattern was present in this repository's `.github/workflows/payloadguard.yml`. | HIGH | **Fixed** | `0e7e68a` — the scan step passes `github.event.pull_request.head.sha`, falling back to `github.head_ref` without a `pull_request` payload; same change in the repository workflow. Tests: `TestActionPolicyTrustBoundary` fork cases (3 fail on the previous `action.yml`, all pass after) |
| §V3 | `pyproject.toml` declares `packages = ["consequence_engine"]`, but `consequence_engine` is a single module. `pip install .` and `python -m build` fail with `package directory 'consequence_engine' does not exist`, so the `publish.yml` tag build cannot produce v1.4.0/v1.5.0. | MEDIUM | **Fixed** | `6b66374` — listed under `py-modules`. Tests: `TestDistributionPackaging` (2 fail on `main` `a388f05`, 3 pass after; builds sdist → wheel and runs a scan through the installed entry point) |
| §V4 | D01 cannot emit `UNSUPPORTED_EXTENSION`. `ConsequenceEngine.analyze_deltas()` only calls `extract_symbols()` for paths with a registered language, so changes to code in other languages (e.g. `.rb`, `.php`) produce no D01 finding and `parser_completeness.complete: true`. Contradicts the D01 description in README and the AGENTS.md rule to emit incomplete coverage. | MEDIUM | **Fixed** | `cdb8395` — source files in languages without a parser (`_UNPARSED_SOURCE_EXTS`) reach `extract_symbols()`; D01 reports them as LOW / WARN (no verdict change) and syntax capability reads `unavailable` when nothing was parsed. Tests: `TestParserCompletenessD01` X06 cases + `analyze()` integration (6 fail on `main` `e77edf3`, 7 pass after) |
| §V5 | The `verdict` output of `action.yml` maps exit 0 to `SAFE`, so `REVIEW` and `CAUTION` are never emitted, contrary to the output's documented values. | LOW | **Fixed** | `3780691` — the verdict is read from the JSON report (exit-code mapping as fallback). Tests: `TestActionPolicyTrustBoundary` REVIEW/CAUTION cases |
| §V6 | `action.yml` has no input for the consequence mode, and the README "enforce via your workflow" snippet sets only `PYTHONUTF8`, so it does not enable enforce mode. `PAYLOADGUARD_CONSEQUENCE_MODE` (undocumented) also takes precedence over `--consequence-mode`. | LOW | **Fixed** | `3780691` — `consequence-mode` input (validated in the step; invalid → exit 1, not 2); `--consequence-mode` > `PAYLOADGUARD_CONSEQUENCE_MODE` > `payloadguard.yml`; README example corrected. Tests: Action input cases and CLI precedence cases (5 of the 6 §V5/§V6 tests fail on `2af1d09`, all pass after) |
| §V7 | JavaScript and TypeScript module extensions (`.mjs`, `.cjs`, `.mts`, `.cts`) are not mapped in `structural_parser._EXT_TO_LANG`, although the grammars are installed. Symbol-level detectors do not analyse them (a `verify()` gutted to `return true` in `auth.mjs` produces no D02/D06 finding); since §V4 they are reported through D01 as `UNSUPPORTED_EXTENSION`. `language_for_path()` also gates legacy L4, so mapping them changes legacy verdict inputs and needs its own calibrated change. Found while fixing §V4. | LOW | **Fixed** | `81d9481` — mapped to `javascript`/`typescript` in `_EXT_TO_LANG`; calibrated by parity with `.js`/`.ts` (SymbolFacts, legacy `extract_named_nodes()`, findings). No harness fixture contains these extensions. Tests: X07 cases (8 fail before, 8 pass after) |
| §V8 | Z3 property P9 (`test_p9_score_upper_bound_finite`) is vacuous: it adds `score <= _HARD_UPPER` as a constraint and then checks `score > _HARD_UPPER`, which is unsatisfiable by construction and does not relate the bound to the scoring model. Its comment states the bound as 24; `_MAX_OTHER_SCORE + _CRITICAL_SCORE` is 29. The score upper bound is covered by CrossHair C-03 and Dafny POST-3. Found while running the proof suite. | LOW | **Fixed** | `4da89c4` — P9 derives the score from `_assess_consequence()`'s per-signal contributions and proves ≤ 36; tightness (36 reachable), sensitivity (uncapped content breaks the bound) and a production cross-check (all signals maxed → 36). The old encoding passed with bounds 0 and −100; the new one refutes 35 |
| §V9 | The committed Dafny output (`verification/dafny/assess_consequence_verify.log`, generated 2026-05-28) predates the 2026-06-11 change to `assess_consequence.dfy` (`257d1f3`: `MAX_SCORE` 36, POST-12). No verification output for the current file is committed, and CI results for it could not be inspected from this session. `structural_drift.dfy` and `temporal_drift.dfy` are unchanged since their recorded run. | MEDIUM | **Fixed** | Dafny Verification run #16 (2026-10-26, `workflow_dispatch` on `main` `9e83cce`, ubuntu-24.04, Dafny 4.9.1 + Z3 4.12.1): `assess_consequence.dfy` 7 verified / 0 errors, `structural_drift.dfy` 1 / 0, `temporal_drift.dfy` 1 / 0. Committed in `verification/dafny/assess_consequence_verify.log` |
| §V10 | `crosshair check temporal_pure --analysis_kind PEP316 --per_condition_timeout 30` (CrossHair 0.0.112) found `analyze_drift_pure(0, float("inf"), 0.25, 0.5)` returning `drift_score` NaN (0 × ∞) with status CURRENT, violating T-02 and T-05. The precondition `target_velocity >= 0.0` admitted ∞, and `TemporalDriftAnalyzer.analyze_drift()` accepted ∞ and NaN (it rejected only negative values). Not reachable from the CLI, where velocity is `len(commits) / 90` with `max_count=1000` (≤ 11.111), but the class is public. The 10-second wrapper test in `tests/proofs/` did not reach this input. Found while running the proof suite. | MEDIUM | **Fixed** | `c74f612` — `analyze_drift()` raises `ValueError` for non-finite age or velocity; `temporal_pure.py` adds `pre: math.isfinite(target_velocity)`. Tests: 3 production cases + deterministic contract test (4 fail before, 4 pass after). Retest: the same CrossHair run exits 0 |
| §V11 | The `payloadguard` console script exited 1 with `UnicodeEncodeError` when stdout could not encode the report's symbols (`→`, emoji): redirected output on Windows without UTF-8 mode uses cp1252. `print_report()` runs before the reports are saved, so no report was written and a DESTRUCTIVE verdict surfaced as an analysis error. The Action and every CLI test set `PYTHONUTF8=1`, which masked it. Found by v1.6.0 release verification (built wheel installed in a fresh virtualenv). | MEDIUM | **Fixed** | `50d6723` — `main()` reconfigures stdout/stderr with `errors="replace"`. Test: `test_verdict_exit_code_survives_non_utf8_stdout` (`PYTHONIOENCODING=cp1252`; exit 1 before, 2 after) |

## Harness Regression Register — 2026-10-26 (analyser v1.6.0, harness `main` `defb060`)

Sources: harness `regression-reports/scan_history.jsonl` (423 `PayloadGuard` check runs on the fixture PRs' head commits, 2026-04-24 to 2026-05-31, collected by `tools/collect_history.py`; harness branch `data/scan-history`) and an offline preflight: `analyze.py <harness> <fixture head SHA> main --pr-description <live PR body>`, default `shadow` mode, harness `main` `defb060` (dated 2026-10-26), analyser `main` `19215fd` (v1.6.0 code).

Live run: regression run #27 (`workflow_dispatch`, full mode) failed before reopening any PR (§H3). The sweep was then run by reopening the 34 closed fixture PRs from the browser and closing them again without merging (2026-10-26 16:45 UTC, v1.6.0 `6c3df91`, harness `main` `defb060`): 34/34 exit codes and 27/34 verdicts match the manifest. The seven verdict mismatches (A03, A06, WS07, AW04, RT01–RT03) are SAFE-expected cases reading REVIEW through branch age, identical to the preflight below. Reports now include consequence-engine findings in shadow mode (for example D03/D04/D06 on A03 and D08 on AW04, a SAFE-expected case). The last live sweep on record (2026-05-31 14:11 UTC, analyser `fe68338`, v1.3.0) matches 34/34 exit codes and 33/34 verdicts against the current manifest (RTA01: SAFE, expected REVIEW).

Preflight: 38/38 exit codes match `expected_exit_code`. Verdicts that differ from the manifest, or whose score has risen, all do so through branch age:

| Cases | Group | Expected | Actual (score) | Age (days) | Signals fired |
|---|---|---|---|---|---|
| A03, A06 | stable | SAFE | REVIEW (2) | 185 | branch age > 180 (+2) |
| WS07, AW04 | stable | SAFE | REVIEW (1) | 154 | branch age > 90 (+1) |
| RT01, RT02, RT03 | stable | SAFE | REVIEW (1) | 152 | branch age > 90 (+1) |
| T01, T02, T12, A10 | aging | SAFE | REVIEW (2) | 185 | branch age > 180 (+2) |
| WS03, WS04, WS05, AW02, RTA03, RTA04 | stable | CAUTION | CAUTION (4) | 154 | L2c poisoning HIGH (+3), branch age > 90 (+1) |
| RTA01 | stable | REVIEW | REVIEW (1) | 154 | branch age > 90 (+1) only (§H2) |

| ID | Finding | Severity | Status | Commit |
|---|---|---|---|---|
| §H1 | Branch age (target commit date minus fixture commit date; `days_old` > 90 / 180 / 365 adds +1 / +2 / +3) applies to stable fixtures. Every commit on harness `main` ages all fixtures; merging harness PR #78 moved them from 4–37 days to 152–185. The six CAUTION-expected stable cases (WS03, WS04, WS05, AW02, RTA03, RTA04) score 3 from an L2c HIGH signal plus age; once age exceeds 180 days (+2) they score 5 = DESTRUCTIVE (exit 2) and fail the live regression with no analyser change. All six fixtures were committed on 2026-05-25, so this applies to any live run against a harness `main` commit dated from 2026-11-22. HARNESS.md assumed age is harmless to stable cases. | MEDIUM | Open — needs a decision: move the six cases to the aging group, raise `branch_age_days` in a harness `payloadguard.yml` on `main` (the target branch the policy is read from), or recreate the fixtures | — |
| §H2 | RTA01 (`rta/push-rm-rf`: adds a `workflow_dispatch` workflow running `rm -rf node_modules dist build .cache`) expects REVIEW from the L2 content scan. Since v1.2.0 `_scan_added_file_content()` skips `.github/workflows/` (L2c is the exclusive workflow handler), and L2c has no signal for this content. History: REVIEW under v1.1.0 (`3201411`, "1 added file(s) contain CI trigger strings or shell execution patterns"), SAFE under v1.3.0 (`fe68338`). Under v1.6.0 it reads REVIEW only through branch age. The exit code (0) is unaffected. | LOW | Open — decide between expecting SAFE and adding a workflow signal | — |
| §H3 | The harness `REGRESSION_PAT` secret is rejected with 401, so `regression.yml` cannot reopen fixture PRs. Run #27 (`40359379620`, 2026-10-26) exited 1 on its first API call; no PR was touched. | MEDIUM | Open — the repository owner must replace the secret | — |

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
