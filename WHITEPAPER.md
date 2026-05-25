# PayloadGuard — Technical Whitepaper

**Version:** 1.1.0 — May 2026
**Repository:** `PayloadGuard-PLG/payload-consequence-analyser`
**Status:** Live on main (`4ea66e9`)

---

## Contents

1. [Abstract](#1-abstract)
2. [The Problem](#2-the-problem)
3. [System Architecture](#3-system-architecture)
4. [Layer Engineering](#4-layer-engineering)
5. [Scoring Model](#5-scoring-model)
6. [Regression Validation](#6-regression-validation)
7. [Configuration Reference](#7-configuration-reference)
8. [Known Limitations](#8-known-limitations)

---

PayloadGuard is an eight-layer static analysis system that runs on every pull request before merge. It detects destructive code payloads — mass deletions, structural gutting, CI pipeline poisoning, deceptive descriptions — that bypass normal code review because they are either too large for a human reviewer to fully parse or deliberately disguised as low-impact changes.

The system assigns a severity score across independent signal dimensions and produces one of four verdicts: **SAFE**, **REVIEW**, **CAUTION**, or **DESTRUCTIVE**. A DESTRUCTIVE verdict sets exit code 2; wired to a GitHub branch protection rule, this blocks the merge button automatically.

**v1.1.0 production release** includes:
- All AIntegrity audit fixes (5 logic defects resolved)
- SCA dependency hallucination defense — Layer 2b (opt-in via allowlist.yml)
- McCabe complexity advisory for new functions (informational, no score impact)
- GitHub Actions workflow poisoning detection — Layer 2c (7 signal types, 3 hardening fixes)
- GitHub Actions infrastructure hardening (all actions SHA-pinned)

Against a 30-case active test suite covering safe baselines, canonical destructive payloads, boundary conditions, purpose-built evasion techniques, and CI pipeline poisoning, PayloadGuard achieves **29/30 detection (97%)** at default thresholds with zero false positives on safe baselines.

---

## 2. The Problem

### 2.1 The April 2026 Incident

In April 2026 a developer accepted a Codex-generated suggestion described as a *"minor syntax fix"*. The branch had been open for 312 days. The actual diff would have deleted 61 files, 11,967 lines, 217 tests, and the complete application authentication architecture in a single merge. The PR was merged. The damage was caught in production.

The attack has three components: deceptive framing, volume shock, and structural erasure. The description claims low impact. The diff is too large to read carefully. Named components disappear — but line diffs show only that lines changed, not that `AuthManager` and `SessionStore` no longer exist.

### 2.2 Why Existing Tools Miss This

Static linters check for correctness, style, and known vulnerability patterns within files. They evaluate the new version of code in isolation. They cannot reason about what was present before and is now gone. Deletion is not a syntax error. It passes every check.

### 2.3 The Evasion Surface

| Technique | Mechanism |
|---|---|
| Addition camouflage | Large additions dilute deletion ratio below threshold |
| Rename smuggling | File renamed while contents gutted — appears as R not D |
| Distributed deletion | One function removed from each of N files — per-file ratio stays low |
| Threshold gaming | Every metric tuned just below its individual threshold |
| Nested gutting | Class shell preserved; all methods inside removed |
| Deceptive description | Benign PR language contradicts catastrophic diff |
| Config-only deletion | Low line-count infrastructure files with high operational impact |

---

## 3. System Architecture

### 3.1 Data Flow

```
PR opened / synchronised
        │
        ▼
actions/checkout@v4  (fetch-depth: 0)
        │
        ▼
payload-consequence-analyser@main  (composite action)
        │
        ├──► python analyze.py <workspace> <head_ref> <base_ref>
        │         --pr-description  --save-json  --save-markdown
        │                   │
        │         ┌─────────┴──────────┐
        │         │   8-layer engine   │
        │         └─────────┬──────────┘
        │                   │
        │         payloadguard-report.json
        │         payloadguard-report.md
        │                   │
        ├──► post_check_run.py
        │         JWT (App private key)
        │         → GitHub Check Run API
        │         → named badge + full markdown body
        │
        ├──► actions/upload-artifact@v4
        │         payloadguard-results / .json
        │
        └──► Enforce verdict step
                  exit 0 → SAFE/REVIEW/CAUTION
                  exit 1 → analysis error
                  exit 2 → DESTRUCTIVE → branch protection blocks merge
```

### 3.2 Analysis Pipeline

```
git.Repo(workspace)
  │
  ├── merge_base(target, branch)  →  diff objects
  │
  ├─[L1] Surface Scan
  │       file counts per change_type (A/D/M/R/C/T)
  │       git --numstat  →  lines_added / lines_deleted
  │       permission changes  (a_mode → b_mode, executable gain)
  │       symlink / submodule detection  (mode & 0o120000 / 0o160000)
  │
  ├─[L4] Structural Drift  (runs before L2/L3 — feeds severity flag)
  │       for d in diffs where change_type in ('M','R'):
  │         if language_for_path(d.b_path):
  │           original = d.a_blob  →  extract_named_nodes()
  │           modified = d.b_blob  →  extract_named_nodes()
  │           deleted  = original_nodes − modified_nodes
  │           ratio    = len(deleted) / len(original)
  │           CRITICAL if ratio > thresh AND len(deleted) >= min_count
  │       cross-file aggregation:
  │         if len(flagged_files) >= 2
  │            AND sum(deleted_nodes) >= min_deleted_nodes:
  │           overall_severity = CRITICAL
  │
  ├─[L2] Forensic Analysis
  │       deleted_files   = [d.a_path  for D-type diffs]
  │       critical_files  = match(CRITICAL_PATH_PATTERNS)
  │       security_files  = match(_SECURITY_CRITICAL_PATTERNS)
  │       added_file_flags = _scan_added_file_content(diffs)
  │
  ├─[L2b] SCA — Dependency Scanning (opt-in)
  │        manifest_diffs = added/modified requirements*.txt|package.json|go.mod|Cargo.toml|Gemfile
  │        unverified     = packages not in allowlist.yml
  │        score          = +3 per unique unverified package
  │
  ├─[L2c] Actions Poisoning Detection
  │        workflow_diffs = added/modified .github/workflows/**/*.yml
  │        signals        = base64_payload | credential_harvest | prt_with_write |
  │                         dormant_trigger | forged_bot_author | oidc_elevation |
  │                         dangerous_prt
  │        CRITICAL signals → +5; HIGH signals → +3
  │
  ├─[L3] Consequence Model  →  verdict
  │       _assess_consequence(files_del, lines_del, days_old,
  │                           del_ratio, struct_sev,
  │                           crit_file_del, sec_file_del)
  │
  ├─[L5a] Temporal Drift
  │        drift = branch_age_days × target_commits_per_day
  │        CURRENT / STALE / DANGEROUS
  │
  └─[L5b] Semantic Transparency
           Phase 1: _extract_claim(pr_description) → scope, dominant_op, raw_tokens
           Phase 2: _profile_diff(diffs) → churn, insertion_ratio, ext_count,
                                           structural_alterations, sensitive_paths
           Phase 3: cross-correlate → mci_score ∈ [0,1]
           mci_score ≥ 0.5 → DECEPTIVE_PAYLOAD (escalates verdict)
           mci_score > 0   → CAUTION_MISMATCH (escalates SAFE→REVIEW)
           mci_score = 0   → TRANSPARENT
           no description  → UNVERIFIED (escalates SAFE→REVIEW)
```

### 3.3 Component Map

| File | Role |
|---|---|
| `analyze.py` | All eight layers, CLI entry point, report generation |
| `structural_parser.py` | Multi-language AST node extraction |
| `post_check_run.py` | GitHub Check Run posting via App JWT |
| `action.yml` | Composite GitHub Action definition |
| `test_analyzer.py` | 236-test unit suite |

---

## 4. Layer Engineering

### 4.1 Layer 1 — Surface Scan

**Purpose:** Extract raw change metrics from the diff. Provides the numerical inputs to L3 scoring.

**Implementation:**
GitPython's `merge_base[0].diff(branch_ref)` produces `Diff` objects. Change type codes: `A` (added), `D` (deleted), `M` (modified), `R` (renamed), `C` (copied), `T` (type changed).

Line counts use `git --numstat` rather than blob reading. This correctly handles binary files (reported as `-/-` by git, treated as 1 line each) and avoids loading large blobs into memory.

Permission changes are detected by comparing `a_mode` and `b_mode` on each diff object. Files gaining executable bits (`b_mode & 0o111 and not a_mode & 0o111`) are surfaced as advisory signals.

Symlinks (`mode & 0o120000`) and submodules (`mode & 0o160000`) are detected from the effective mode and surfaced in `special_files`.

**Outputs:** `files_added`, `files_deleted`, `files_modified`, `files_renamed`, `lines_added`, `lines_deleted`, `deletion_ratio_percent`, `permission_changes`, `special_files`.

---

### 4.2 Layer 2 — Forensic Analysis

**Purpose:** Identify which specific files were deleted and whether they are high-value targets.

**Critical path detection** uses regex patterns against `d.a_path` for all `D`-type diffs:

```
Test infrastructure   (^|/)tests?(/|$)  |  (^|/)test_[^/]+$
CI/CD                 (^|/)\.github/  |  Dockerfile  |  Makefile
Dependency manifests  requirements*.txt  |  setup.py  |  pyproject.toml
                      package.json  |  Cargo.toml  |  go.mod
Package init          (^|/)__init__\.py$
Architecture dirs     (^|/)core(/|$)  |  modules  |  config
Security files        auth*.(py|js|ts)  |  security*  |  permission*
Database/schema       database*.(py|js|ts)  |  migrations/  |  schema*  |  models*
Entry points          (main|app|server|index).(py|js|ts)
Config files          *.yml  |  *.yaml
```

**Security-critical detection** uses a tighter subset for the +5 scoring bonus:

```
auth[^/]*\.(py|js|ts)
security[^/]*\.(py|js|ts)
permission[^/]*\.(py|js|ts)
authorization[^/]*\.(py|js|ts)
```

**Outputs:** `critical_deletions` (list), `security_deletions` (list), `added_file_flags` (list), counts passed to L3.

---

### 4.2b Layer 2b — SCA: Dependency Scanning (opt-in)

**Purpose:** Detect unverified dependency additions in package manifest files. A PR that adds an unrecognised package — whether a dependency confusion attack, a typosquatted package, or an AI hallucination — produces no structural or deletion signal. L2b provides a dedicated check.

**Activation:** Requires `allowlist.yml` in the scanned repository root. Without this file, L2b is a no-op.

**Manifest types scanned:** `requirements*.txt`, `package.json`, `go.mod`, `Cargo.toml`, `Gemfile`.

**Algorithm:**
```python
for diff in diffs where change_type in ('A', 'M'):
    if path matches _MANIFEST_PATTERNS:
        added_packages = _parse_added_packages(diff)
        for pkg in added_packages:
            if pkg not in allowlist['packages']:
                unverified_packages.add(pkg)

score += 3 * len(unverified_packages)
```

Each unique unverified package adds +3 points. Multiple packages in a single manifest can push a PR to CAUTION or DESTRUCTIVE regardless of diff volume.

**Interaction with L2c:** Added `.yml` workflow files are also processed by L2b's content scanner (`_scan_added_file_content`), which checks for CI trigger strings and shell execution patterns. This means a dormant-trigger workflow that contains `curl | bash` will be flagged by both L2c (`dormant_trigger_with_payload`, +3) and L2b shell pattern scanning (+2 per match). This is defense-in-depth, not double-counting — the signals represent independent detection dimensions.

**Outputs:** `sca_flags` dict with `unverified_packages` list and count; count passed to L3.

---

### 4.2c Layer 2c — GitHub Actions Poisoning Detection

**Purpose:** Detect CI pipeline poisoning in added or modified workflow files. This layer targets the specific techniques used to poison GitHub Actions pipelines — base64 payload delivery, credential exfiltration, privilege escalation — which are invisible to structural drift analysis (which operates on source code ASTs, not YAML) and to L2 forensic analysis (which operates on file deletions, not content of added files).

**Scope:** All added (`A`) and modified (`M`) files matching `.github/workflows/**/*.yml`, `.github/workflows/**/*.yaml`, `.github/actions/**/*.yml`, `.github/actions/**/*.yaml`.

**Signal types:**

| Signal | Severity | Score | Mechanism |
|---|---|---|---|
| `base64_payload` | CRITICAL | +5 | Base64 string piped to a shell interpreter |
| `credential_harvest` | CRITICAL | +5 | AWS/GCP metadata endpoint, secret grep, env dump to curl |
| `pull_request_target_with_write_permissions` | CRITICAL | +5 | `pull_request_target` trigger + any write permission declared |
| `dormant_trigger_with_payload` | HIGH | +3 | `workflow_dispatch` or `schedule` + shell execution in same file |
| `forged_bot_author` | HIGH | +3 | `git config user.name/email` set to a known bot identity |
| `oidc_elevation_no_consumer` | HIGH | +3 | `id-token: write` with no legitimate OIDC consumer in the same file |
| `dangerous_trigger_pull_request_target` | HIGH | +3 | `pull_request_target` trigger alone (no write permissions declared) |

A single CRITICAL signal is sufficient to reach DESTRUCTIVE (score ≥ 5). A single HIGH signal reaches CAUTION (score ≥ 3).

**Three hardening fixes:**

*H1 — YAML block scalar normalisation.* Base64 payloads split across YAML folded (`>`) or literal (`|`) block scalar lines evade single-line regex matching. `_normalize_yaml_content()` collapses block continuation lines before any pattern is applied.

*H2 — Exact-match OIDC consumer allowlist.* The check for legitimate OIDC consumers (`aws-actions/configure-aws-credentials`, `google-github-actions/auth`, `azure/login`, and others) uses exact full-path matching. Prefix matching (`aws-actions/` anywhere in the string) would accept typosquatted names like `aws-actions-unofficial/configure-aws-credentials`. The allowlist is checked against the full `uses:` value only.

*H3 — `pull_request_target` two-tier scoring.* `pull_request_target` alone without any write permission scores HIGH (+3 → CAUTION). Combined with any write permission (`contents: write`, `pull-requests: write`, `id-token: write`, etc.) it scores CRITICAL (+5 → DESTRUCTIVE). This prevents false positives on repos that legitimately use `pull_request_target` in read-only mode while still catching the pwn-request attack surface.

**Outputs:** `actions_poisoning` dict with `flagged_workflows` list (file, signals, severity, change_type), `total`; counts and severity passed to L3.

---

### 4.3 Layer 4 — Structural Drift

**Purpose:** AST-level detection of which named code entities disappeared. Catches gutting that is invisible to line diffs.

**Supported languages:**

| Language | Parser | Node types tracked |
|---|---|---|
| Python | stdlib `ast` | FunctionDef, AsyncFunctionDef, ClassDef, module-level Assign, AnnAssign |
| JavaScript / TypeScript | tree-sitter | function_declaration, class_declaration, method_definition, arrow_function, lexical_declaration |
| Go | tree-sitter | function_declaration, method_declaration, type_spec, const_spec |
| Rust | tree-sitter | function_item, struct_item, enum_item, trait_item, const_item, static_item |
| Java | tree-sitter | method_declaration, class_declaration, interface_declaration, field_declaration |

Files with no installed grammar are silently skipped.

**Per-file algorithm:**

```python
original_nodes = extract_named_nodes(a_blob, file_path)
modified_nodes = extract_named_nodes(b_blob, file_path)
deleted_nodes  = original_nodes - modified_nodes
deletion_ratio = len(deleted_nodes) / len(original_nodes)

CRITICAL if deletion_ratio > threshold AND len(deleted_nodes) >= min_count
```

Both gates must be met. The ratio gate prevents false positives on large codebases where a single deletion is meaningful. The count gate prevents false positives on tiny files (a 2-function helper losing 1 function is 50% ratio but probably not catastrophic).

**Cross-file aggregation** (added to close the distributed-deletion evasion gap):

```python
if overall_severity != 'CRITICAL' and len(flagged_files) >= 2:
    total_deleted = sum(f['metrics']['deleted_node_count'] for f in flagged_files)
    if total_deleted >= min_deleted_nodes:
        overall_severity = 'CRITICAL'
```

This catches A03-class attacks where one function is removed from each of N files — below the per-file ratio threshold but collectively significant.

**Rename coverage:** The structural loop processes both `change_type == 'M'` and `change_type == 'R'`. A file renamed while having its contents gutted (A02 pattern) goes through full AST diffing using the original blob (`a_blob`) vs the replacement blob (`b_blob`).

**Outputs:** `overall_structural_severity`, `max_deletion_ratio_pct`, `flagged_files` (list with per-file metrics and deleted component names).

---

### 4.4 Layer 3 — Consequence Model

The scoring model and its full logic are detailed in [Section 5](#5-scoring-model).

---

### 4.5 Layer 5a — Temporal Drift

**Purpose:** Measure how out-of-date the branch is relative to the target, accounting for repo velocity.

**Formula:**
```
drift_score = branch_age_days × target_commits_per_day
```

`target_velocity` is computed from `iter_commits(target_ref, since=90_days_ago, max_count=1000)`. A slow repo with a 90-day branch has low drift. A fast-moving repo (10 commits/day) with the same branch has a drift score of 900 — approaching the DANGEROUS threshold.

| Status | Drift Score | Signal |
|---|---|---|
| CURRENT | < 250 | Context is valid |
| STALE | 250–999 | Manual diff review required |
| DANGEROUS | ≥ 1000 | Mandatory rebase before merge |

Branch age is clamped to `max(0, days)` — a branch newer than the target commit is treated as age 0.

**Output:** `temporal_drift` dict with status, severity, drift score, velocity, and recommendation string.

---

### 4.6 Layer 5b — Semantic Transparency (v2 — PR-MCI Heuristic Engine)

**Purpose:** Detect the *deceptive description* pattern — language in the PR description that misrepresents the actual scope, operation type, or affected components of the diff.

**Algorithm:** Three-phase heuristic engine derived from the PR-MCI academic framework (CodeFuse-CommitEval + 23,247-PR agent study). Pure Python stdlib, no external dependencies, sub-second.

**Phase 1 — Linguistic Lexer** (`_extract_claim`):

Sanitises markdown (strips code fences, inline code, link syntax, formatting characters), tokenises to lowercase alphanumeric tokens, applies a Lovins-inspired suffix stemmer (longest-first, minimum 3-character candidate). Classifies two dimensions:

- **Scope:** `micro` if any token matches `_SEMANTIC_MICRO_SCOPE` (minor, typo, cleanup, whitespace, cosmetic, etc.); `macro` if any matches `_SEMANTIC_MACRO_SCOPE` (overhaul, architectural, rewrite, comprehensive, etc.); `unspecified` otherwise.
- **Dominant operation:** checked in priority order — `remedial` (fix, patch, resolve, revert), `destructive` (remove, delete, drop, deprecate), `additive` (add, implement, create, build), `mutative` (update, refactor, migrate, replace).

**Phase 2 — Diff Profiler** (`_profile_diff`):

Walks GitPython diff objects. For each diff: extracts file extension; checks path against `_SEMANTIC_SENSITIVE_PATHS` (`.github/workflows/`, auth files, package manifests, Dockerfiles, schema/migration files, secrets); counts added and deleted lines from the unified diff bytes; detects structural additions (lines matching `+def `, `+class `, `+async def `, `+function `, `+interface `, `+struct `).

Computes: `total_churn = lines_added + lines_deleted`, `insertion_ratio = lines_added / total_churn`.

**Phase 3 — Cross-Correlation** (`analyze_transparency`):

Five independent signals, each contributing to `mci_score`:

| Signal | Condition | MCI |
|---|---|---|
| `scope_understated` | scope == micro AND total_churn > churn_limit (default 50) | +0.4 |
| `operation_mutation` | scope == micro AND structural_alterations > 0 | +0.3 |
| `hidden_component_modification` | scope == micro AND sensitive file in diff not named in description | +0.3 |
| `phantom_additions` | dominant_op == remedial AND insertion_ratio > ir_threshold (default 0.9) | +0.4 |
| `cross_stack_micro_claim` | scope == micro AND distinct_file_extensions >= 3 | +0.2 |
| `macro_scope_manual_review` | scope == macro | advisory only — no MCI contribution |

`mci_score` is capped at 1.0.

**Status thresholds:**

| mci_score | Status | Verdict effect |
|---|---|---|
| ≥ 0.5 | `DECEPTIVE_PAYLOAD` | Escalates verdict one step (SAFE→CAUTION, REVIEW→CAUTION, CAUTION→DESTRUCTIVE) |
| > 0.0 or macro advisory | `CAUTION_MISMATCH` | Escalates SAFE→REVIEW only |
| 0.0 | `TRANSPARENT` | No change |
| (no description) | `UNVERIFIED` | Escalates SAFE→REVIEW |

Unlike L1–L4, L5b verdict escalation operates on the pre-existing verdict rather than contributing to the numerical `severity_score`. This allows it to upgrade a SAFE verdict on a low-volume deceptive PR without interfering with the scoring model's calibration.

**Output:** `semantic` dict with `status`, `is_deceptive`, `mci_score`, `signals` list, `semantic_claim` (scope, dominant_op, raw_tokens), `diff_reality` (churn, insertion_ratio, ext_count, structural_alterations, sensitive_paths), `matched_keyword` (first signal, for backwards compatibility), `directive` string.

---

## 5. Scoring Model

Layer 3 accumulates a `severity_score` across independent dimensions. No single signal can produce a false positive at default thresholds. DESTRUCTIVE requires either a combination of signals or a single high-confidence signal (security file deletion or structural CRITICAL).

### 5.1 Signal Dimensions

**Branch age**

| Condition | Points |
|---|---|
| days_old > 365 | +3 |
| days_old > 180 | +2 |
| days_old > 90 | +1 |

**Deletion dimensions (files, ratio, lines)**

Three correlated signals scored independently, then capped to prevent double-counting:

```
files_score  = 3 if files_deleted > 50  else 2 if > 20  else 1 if > 10  else 0
ratio_score  = 3 if deletion_ratio > 90 else 2 if > 70  else 1 if > 50  else 0
lines_score  = 3 if lines_deleted > 50k else 2 if > 10k else 1 if > 5k  else 0

_RATIO_MIN_LINES = 0 if critical_file_deletions > 0 else 100
(ratio_score only evaluated when lines_deleted >= _RATIO_MIN_LINES)

nonzero = count of {files_score, ratio_score, lines_score} > 0
deletion_dim = min(4, max(files_score, ratio_score, lines_score) + (1 if nonzero >= 2 else 0))
```

The cap at 4 means deletion volume alone cannot reach DESTRUCTIVE (≥5). This prevents a legitimate large cleanup from being blocked on numbers alone.

**Structural severity**

| Condition | Points |
|---|---|
| overall_structural_severity == CRITICAL | +5 |

Structural CRITICAL requires both: deletion ratio > threshold (default 20%) AND deleted node count ≥ minimum (default 3) — either per-file or via cross-file aggregation.

**Critical path file deletions**

| Condition | Points |
|---|---|
| critical_file_deletions > 0 | +2 |
| critical_file_deletions > 5 | +2 (same) |

The `_RATIO_MIN_LINES` floor is also set to 0 when critical files are deleted, enabling ratio scoring even for low-volume critical deletions (e.g. a 45-line config file at 90% ratio).

**Security-critical file deletions**

| Condition | Points |
|---|---|
| security_file_deletions > 0 | +5 |

Auth, security, permission, or authorization files (`.py/.js/.ts`) deleted outright. This single signal alone is sufficient to reach DESTRUCTIVE. These are the highest-value targets for a destructive payload.

**Added file content flags (L2 extension)**

| Condition | Points |
|---|---|
| CI trigger string or shell execution pattern in added non-code file | +2 per match |

Patterns scanned include `curl | bash`, `wget | sh`, `chmod +x`, `setfacl`, CI trigger strings. Fires on added `.txt`, `.md`, `.yml`, and similar non-code files.

**Unverified SCA dependencies (L2b)**

| Condition | Points |
|---|---|
| Package in manifest diff not in allowlist.yml | +3 per unique package |

Requires `allowlist.yml` to be present in the target repo root. No-op otherwise.

**GitHub Actions poisoning signals (L2c)**

| Condition | Points |
|---|---|
| Any CRITICAL signal (`base64_payload`, `credential_harvest`, `prt_with_write`) | +5 |
| Any HIGH signal (`dormant_trigger`, `forged_bot_author`, `oidc_elevation`, `dangerous_prt`) | +3 |

A single CRITICAL poisoning signal scores identically to a security file deletion — immediate DESTRUCTIVE. A single HIGH signal alone reaches CAUTION. Multiple flagged workflows accumulate at the single highest-severity level (one CRITICAL outweighs any number of HIGH signals for scoring purposes).

### 5.2 Verdict Thresholds

| Score | Verdict | Severity | Exit Code |
|---|---|---|---|
| 0 | SAFE | LOW | 0 |
| 1–2 | REVIEW | MEDIUM | 0 |
| 3–4 | CAUTION | HIGH | 0 |
| ≥ 5 | DESTRUCTIVE | CRITICAL | 2 |

### 5.3 Scoring Schematic

```
                    SIGNAL INPUTS
                         │
        ┌────────────────┼────────────────────────────┐
        │                │                            │
        ▼                ▼                            ▼
   [Age score]   [Deletion dimensions]        [File quality]
   0–3 pts        files / ratio / lines        security files
                  independently scored         +5 if any deleted
                  cap at 4, bonus if 2+ fire
                        │                      critical files
                        │                      +2 if any deleted
                        │                      (also drops ratio floor)
        ┌───────────────┘                            │
        │                                            │
        ▼                                            │
   [Structural severity]                             │
   +5 if CRITICAL                                    │
   (per-file ratio+count                             │
    OR cross-file total)                             │
        │                                            │
        └────────────────┬───────────────────────────┘
                         │
                         ▼
                  severity_score
                         │
               ┌─────────┴──────────┐
               │                    │
           score ≥ 5          score 3–4
               │                    │
          DESTRUCTIVE           CAUTION
          exit 2               exit 0
```

---

## 6. Regression Validation

### 6.1 Test Harness Architecture

The test harness (`payloadguard-plg/payloadguard-test-harness`) maintains 35 active permanent branches (plus 3 pending for future GitHub APIs), each representing a specific adversarial scenario. Each branch has a closed PR against main. Running a regression:

1. `run_regression.py` reopens all active PRs
2. GitHub Actions triggers a PayloadGuard scan on each
3. The script polls GitHub Check Runs until all scans complete
4. PRs are closed
5. `ingest.py` pulls the `payloadguard-results` artifact from each workflow run and writes to SQLite
6. `dashboard.py` visualises results with a threshold simulator; the **Last Run** summary card shows a full `YYYY-MM-DD HH:MM` timestamp linked directly to the GitHub Actions workflow run that produced the data

The harness CI is pinned to the analyser at SHA `32014117afeb5c99f51045b3df0d7ba27e0a187a` (post INC-3 fix). Temporal grouping controls which cases run: `--mode stable` (default, excludes aging/temporal cases), `--mode temporal` (aging cases only), `--mode full` (all cases).

### 6.2 Test Case Matrix

**Track 1 — Core detection (Layers 1–5)**

| ID | Branch | Category | Expected | Description |
|---|---|---|---|---|
| T01 | safe/small-additive | safe | SAFE | Add health_check() — zero-noise baseline |
| T02 | safe/docs-only | safe | SAFE | README additions only |
| T12 | safe/large-rename | safe | SAFE | Three class renames — L4 false positive check |
| T03 | destructive/mass-deletion | destructive | DESTRUCTIVE | Delete auth.py + database.py |
| T04 | destructive/april-2026-replica | destructive | DESTRUCTIVE | April 2026 incident replica |
| T05 | boundary/structural-threshold | boundary | DESTRUCTIVE | 4 methods removed from auth.py (~23.5% ratio) |
| T09 | semantic/no-description | semantic | DESTRUCTIVE | No PR description, database.py deleted |
| T10 | semantic/honest-critical | semantic | DESTRUCTIVE | Honest BREAKING CHANGE description, auth deleted |
| T11 | multilang/structural-js-ts-go | multilang | DESTRUCTIVE | Structural deletions across JS/TS/Go |
| A01 | adversarial/keyword-evasion | adversarial | DESTRUCTIVE | Destructive diff without benign trigger keywords |
| A02 | adversarial/rename-smuggling | adversarial | DESTRUCTIVE | auth.py renamed to identity.py, contents gutted |
| A03 | adversarial/slow-deletion | adversarial | DESTRUCTIVE | 1 function removed from each of 5 files |
| A04 | adversarial/addition-camouflage | adversarial | DESTRUCTIVE | 300-line api.js addition + auth.py deleted |
| A05 | adversarial/nested-gutting | adversarial | DESTRUCTIVE | Auth class shell preserved, all methods deleted |
| A06 | adversarial/threshold-gaming | adversarial | DESTRUCTIVE | Every metric just below individual threshold |
| A07 | adversarial/new-file-replacement | adversarial | DESTRUCTIVE | auth.py deleted + auth_v2.py stub added |
| A09 | adversarial/config-only-deletion | adversarial | DESTRUCTIVE | settings.yml + requirements.txt deleted |
| A10 | adversarial/unicode-payload | adversarial | SAFE | Hostile Unicode in comments, +4/-1 lines |

**Track 3 — Layer 2c validation**

| ID | Branch | Category | Expected | Signal |
|---|---|---|---|---|
| WS01 | workflow-security/base64-payload | workflow-security | DESTRUCTIVE | `base64_payload` CRITICAL |
| WS02 | workflow-security/credential-harvest | workflow-security | DESTRUCTIVE | `credential_harvest` CRITICAL |
| WS03 | workflow-security/dormant-trigger | workflow-security | DESTRUCTIVE | `dormant_trigger_with_payload` HIGH + L2b shell pattern |
| WS04 | workflow-security/forged-bot-author | workflow-security | CAUTION | `forged_bot_author` HIGH |
| WS05 | workflow-security/oidc-elevation | workflow-security | CAUTION | `oidc_elevation_no_consumer` HIGH |
| WS06 | workflow-security/prt-write-permissions | workflow-security | DESTRUCTIVE | `pull_request_target_with_write_permissions` CRITICAL |
| WS07 | workflow-security/safe-clean-workflow | workflow-security | SAFE | No signals — L2c false positive baseline |

**Track 4 — Layer 2c adversarial (hardening tests)**

| ID | Branch | Category | Expected | Signal |
|---|---|---|---|---|
| AW01 | adversarial/workflow-yaml-folded-block | adversarial | DESTRUCTIVE | Folded block base64 → `base64_payload` CRITICAL |
| AW02 | adversarial/workflow-prt-only | adversarial | CAUTION | `dangerous_trigger_pull_request_target` HIGH only |
| AW03 | adversarial/workflow-typosquatted-oidc | adversarial | CAUTION | Typosquat rejected; `oidc_elevation_no_consumer` HIGH |
| AW04 | adversarial/workflow-legitimate-oidc | adversarial | SAFE | Exact-match allowlist passes — no false positive |
| AW05 | adversarial/workflow-modified-poison | adversarial | DESTRUCTIVE | M-type diff scanned; `credential_harvest` CRITICAL |

**Track 5 — Red-team simulation (bypass probing)**

| ID | Branch | Category | Expected | Signal / Notes |
|---|---|---|---|---|
| RTA01 | rta/push-rm-rf | red-team | REVIEW | `rm -rf` in workflow — caught by L2 content scanner |
| RTA02 | rta/schedule-curl-exfil | red-team | SAFE | **Documented bypass** — curl POST body with `secrets.*`, URL on continuation line; multiline curl body evades all `credential_harvest` patterns |
| RTA03 | rta/prt-untrusted-checkout | red-team | CAUTION | `pull_request_target` + untrusted `head.sha` checkout — caught by L2c `dangerous_trigger_pull_request_target` HIGH |
| RTA04 | rta/github-env-injection | red-team | CAUTION | PATH/LD_PRELOAD/NODE_OPTIONS poisoning via `$GITHUB_ENV` — caught by L2c Signal 7 (`github_env_injection`) HIGH |
| RTA05 | rta/variable-obfuscated-b64 | red-team | DESTRUCTIVE | Variable-indirected base64: `PAYLOAD=$(echo '...')` then `echo $PAYLOAD \| base64 -d \| bash` — `base64 -d \| bash` literal still fires L2c CRITICAL |

RTA02 is a registered bypass: the regression passes when the analyser returns SAFE (confirming the bypass still exists) and fails if a future fix starts catching it (signalling the detection improvement). Fix requires multiline-aware curl body pattern matching.

**Pending (blocked on GitHub 2026 APIs)**

| ID | Description |
|---|---|
| T23 | Dependency lock file tampering — immutable workflow dependency locking |
| T24 | Workflow redefines GITHUB_TOKEN scopes — centralised policy controls API |
| T25 | Curl command to exfiltrate $SECRETS — native egress firewall complement |

### 6.3 Results at Default Thresholds

```
structural deletion_ratio    : 0.20 (20%)
min_deleted_nodes            : 3
DESTRUCTIVE threshold        : 5
CAUTION threshold            : 3
temporal stale               : 250
temporal dangerous           : 1000
actions critical_signal_score: 5
actions high_signal_score    : 3
```

**Core detection (Track 1):**

| Result | Count | Cases |
|---|---|---|
| True DESTRUCTIVE | 14 | T03 T04 T05 T09 T10 T11 A01 A02 A03 A04 A05 A07 A09 |
| True SAFE | 4 | T01 T02 T12 A10 |
| False SAFE (missed) | 1 | A06 |
| False DESTRUCTIVE | 0 | — |

**Layer 2c validation (Tracks 3 + 4):**

| Result | Count | Cases |
|---|---|---|
| True DESTRUCTIVE | 5 | WS01 WS02 WS03 WS06 AW01 AW05 |
| True CAUTION | 4 | WS04 WS05 AW02 AW03 |
| True SAFE | 2 | WS07 AW04 |
| False positive | 0 | — |
| False negative | 0 | — |

**Combined pass rate: 34/35 active cases (97%)**

The one persistent miss is A06 (threshold-gaming), a known limitation of purely additive scoring with no compound detection. All Layer 2c and red-team simulation cases pass. RTA02 is counted as a pass — the regression expects SAFE (documented bypass) and receives it.

### 6.4 Scoring Trace for Key Cases

**T04 — April 2026 replica (DESTRUCTIVE, score ≈ 9)**
```
branch_age 312 days (>180)         +2
files_deleted 61 (>50)         → files_score=3
deletion_ratio 98% (>90%)      → ratio_score=3
lines_deleted 11,967 (>10k)    → lines_score=2
nonzero=3 → bonus=1 → deletion_dim = min(4, 3+1) = 4
structural CRITICAL (auth.py gutted)   +5
critical_file_deletions > 5            +2
                               total = 13 → DESTRUCTIVE
```

**A04 — Addition camouflage (DESTRUCTIVE, score ≈ 7)**
```
auth.py deleted → security_file_deletions=1    +5
auth.py in CRITICAL_PATH_PATTERNS              +2
                                       total = 7 → DESTRUCTIVE
```

**A03 — Slow deletion (DESTRUCTIVE, score ≈ 5)**
```
5 files × 1 function deleted
per-file ratio ~10% each → no per-file CRITICAL
cross-file: 5 total nodes ≥ 3 min_deleted_nodes
→ overall_structural_severity = CRITICAL         +5
                                         total = 5 → DESTRUCTIVE
```

**A06 — Threshold gaming (SAFE, score = 0)**
```
files_deleted < 10   → files_score=0
lines_deleted < 100  → ratio not evaluated
deletion_ratio < 50% → ratio_score=0
lines_deleted < 5000 → lines_score=0
structural < 20% per file, 1 file → no CRITICAL
no critical/security file deletions
branch_age < 90 days
                             total = 0 → SAFE (known miss)
```

---

## 7. Configuration Reference

Drop `payloadguard.yml` in the repo root. All keys are optional.

```yaml
thresholds:
  branch_age_days: [90, 180, 365]      # tier breakpoints, must be ascending
  files_deleted:   [10, 20, 50]
  lines_deleted:   [5000, 10000, 50000]
  temporal:
    stale:     250.0                   # drift_score = age × velocity
    dangerous: 1000.0
  structural:
    deletion_ratio:    0.20            # fraction of AST nodes deleted per file
    min_deleted_nodes: 3               # both must exceed their threshold

semantic:
  micro_scope_churn_limit: 50          # V_s: churn threshold for scope_understated signal
  insertion_ratio_fix_threshold: 0.9   # V_r: insertion ratio threshold for phantom_additions
```

Out-of-order threshold lists are auto-sorted after load. Deep-merge semantics — only keys present in your file override the defaults.

---

## 8. Known Limitations

### 8.1 Compound Threshold Gaming (A06)

An adversary who tunes every metric to sit just below its individual threshold scores 0 points. The scoring model has no compound detection — there is no rule of the form "three signals at 60% of their threshold = flag". This is a deliberate design choice to avoid false positives on legitimate PRs that happen to touch many areas of the codebase, but it is a real gap.

Possible mitigations: a compound bonus when N dimensions are all non-zero but below threshold; a learned baseline model that flags statistical outliers relative to repo history.

### 8.2 Generated Code Volume

A PR that adds 50,000 lines of generated code (e.g. a vendored library, a protobuf output, a lock file) and also deletes meaningful source files may have its deletion ratio diluted below detection thresholds. The deletion dimensions cap at 4 regardless of additions, but ratio scoring depends on the additions-to-deletions balance.

### 8.3 Grammar Coverage

Structural drift analysis requires a tree-sitter grammar for non-Python languages. Languages without an installed grammar are silently skipped. A PR that guts a Ruby or PHP codebase will have no L4 signal.

### 8.4 Merge Base Ambiguity

For repositories with complex merge histories, `merge_base()` may return multiple candidates. The implementation uses `[0]` — the first candidate returned by git. In pathological cases this may not be the optimal merge base.

### 8.5 Semantic Layer Signal Coverage

Layer 5b v2 uses structural heuristics rather than keyword lists, but coverage remains bounded by what can be inferred from description text and diff structure alone.

*Unspecified scope descriptions* ("updates config", "changes handler behaviour") produce no micro or macro scope classification. None of the five MCI signals fire without a scope classification (V_s, V_o, V_f, V_e all require micro scope; V_r requires a remedial operation claim). A sufficiently vague description yields TRANSPARENT regardless of diff severity — the layer cannot penalise what it cannot classify.

*V_r false positives on greenfield additions* — a PR claiming "fix" that adds a new module from scratch will have a high insertion ratio and trigger `phantom_additions`. This may be a valid description ("fix the gap by adding X") rather than deception. The signal is advisory at mci_score 0.4 (CAUTION_MISMATCH) unless combined with another signal.

*V_f acknowledgement check* uses the last two path components (e.g. `auth_handler.py` for `src/auth_handler.py`). The full filename including extension must appear in the description to suppress the signal — stem-only references ("auth_handler" without ".py") are not recognised as acknowledgement.

### 8.6 AI Research Tool Context Pollution is an Out-of-Scope Threat

PayloadGuard's threat model is a human submitting a destructive PR. It does not model the case where an AI assistant — an LLM research tool, notebook, or deep-research agent — is processing repository documents on a maintainer's behalf. In that scenario, a document *added* to the repository (not deleted from it) can contain plausible-looking but hallucinated content that lands in version control, bypassing all five layers because the problem is the LLM's context window, not the git diff.

A live incident (2026-04-24) demonstrated this vector — not through deliberate attack, but through accidental AI source contamination. NotebookLM was conducting legitimate research on this repository. During that session it pulled in external web sources — including the real AE3GIS framework (an MDPI-published ICS security testbed paper), GitHub issue threads, and unrelated MCP gateway documentation. Unable to segregate these sources, it suffered **context collapse**: it attributed AE3GIS's architecture (Purdue Model, GNS3, SCADA, OpenPLC) to PayloadGuard and produced a "Technical Remediation Report" describing this system as if it were an industrial control system testbed. The repository owner committed this output to main unintentionally — it was authoritative in tone and plausible in structure. The report contained embedded CI trigger strings (`[citest commit:<sha>]`), filesystem privilege escalation commands (`setfacl`), and plausible-looking Go remediation code. PayloadGuard scored the commit as low-risk (pure file addition, no deletions). Human code review caught the mismatch.

There was no external attacker. NotebookLM's own post-incident analysis framed the contamination as a "Track 2 Adversarial Strike" — which was itself a secondary hallucination: the model rationalised its source-segregation failure as an external threat.

**The operationally relevant point:** whether a corrupted document enters a repo because a deliberate adversary crafted it or because an AI research tool mixed sources, the outcome is identical — plausible-looking content that doesn't describe reality lands in version control. The mechanism (high-entropy external sources overwhelming source segregation) is functionally equivalent to a deliberate injection attack. Defence must treat both cases the same.

Proposed future mitigations are documented in `AUDIT_LOG.md §INC-1 through §INC-4`.

---

## 9. GitHub 2026 Roadmap Alignment

PayloadGuard complements GitHub's 2026 security roadmap without overlapping it. GitHub is building the execution-security layer — dependency locking, policy controls, egress firewalls, real-time monitoring. PayloadGuard is the **semantic consequence layer** that sits upstream: it analyzes what a change *means* before it merges, where execution-level controls cannot yet reach.

### 9.1 Layer-to-Roadmap Mapping

| PayloadGuard Layer | What it detects | 2026 Roadmap Pillar |
|---|---|---|
| L1 — Surface Scan | File deletions, binary files, permission changes, symlink replacements | Hardened CI/CD infrastructure |
| L2 — Forensic | Critical path files, security file deletions, added file content (shell/CI patterns) | Hardened CI/CD infrastructure |
| L2b — SCA | Unverified dependency additions in package manifests | Supply chain security |
| L2c — Actions Poisoning | Base64 payload delivery, credential harvesting, OIDC privilege escalation, dormant triggers, forged bot identity, unsafe pull_request_target usage | Hardened CI/CD infrastructure — workflow actor permissions |
| L3 — Consequence Model | Compound severity score across all dimensions | Policy controls — "PR must be SAFE or REVIEW to merge" |
| L4 — Structural Drift | Named classes/functions that disappeared | Observability — "what actually changed" (not just what lines moved) |
| L5a — Temporal | Branch staleness, semantic gap relative to target velocity | Observability — stale-context risk surfaced before execution |
| L5b — Semantic Transparency | Deceptive descriptions, commit red-flag keywords | Policy controls — description must align with verified impact |

### 9.2 Complementary, Not Overlapping

```
GitHub 2026 secures:                      PayloadGuard secures:
┌────────────────────────────────┐         ┌────────────────────────────────┐
│  What runs                     │         │  What changed                  │
│  Dependency integrity          │   +     │  Structural consequence         │
│  Runtime egress boundaries     │         │  Deceptive intent detection    │
│  Workflow actor permissions    │         │  Cross-language drift analysis  │
│  Policy enforcement at merge   │         │  Semantic mismatch flagging    │
└────────────────────────────────┘         └────────────────────────────────┘
         Execution-centric                          Change-centric
```

GitHub ensures the merge pipeline is secure. PayloadGuard ensures the thing being merged is safe. Both are required; neither replaces the other.

### 9.3 Pending Integration Points (2026)

Three test cases (T23–T25) are reserved in the regression harness for GitHub 2026 APIs that are not yet available:

| Test | Trigger | GitHub 2026 Feature |
|---|---|---|
| T23 | Dependency lock file tampered in PR | Immutable workflow dependency locking |
| T24 | Workflow redefines GITHUB_TOKEN scopes | Centralized policy controls API |
| T25 | PR adds secret exfiltration command | Native egress firewall (upstream complement) |

When these APIs land, the test branches will be created and T23–T25 will enter the active regression suite.

---

*PayloadGuard is maintained by [PayloadGuard-PLG](https://github.com/PayloadGuard-PLG).*
