# PayloadGuard — Technical Whitepaper

**Version:** 1.1 — April 2026
**Repository:** `darkvader-plg/payload-consequence-analyser`

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

## 1. Abstract

PayloadGuard is a five-layer static analysis system that runs on every pull request before merge. It detects destructive code payloads — mass deletions, structural gutting, deceptive descriptions — that bypass normal code review because they are either too large for a human reviewer to fully parse or deliberately disguised as low-impact changes.

The system assigns a severity score across independent signal dimensions and produces one of four verdicts: **SAFE**, **REVIEW**, **CAUTION**, or **DESTRUCTIVE**. A DESTRUCTIVE verdict sets exit code 2; wired to a GitHub branch protection rule, this blocks the merge button automatically.

Against an 18-case adversarial test suite covering safe baselines, canonical destructive payloads, boundary conditions, and purpose-built evasion techniques, PayloadGuard achieves **17/18 detection (94%)** at default thresholds with zero false positives on safe baselines.

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
        │         │   5-layer engine   │
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
           benign_keyword(pr_description) AND severity==CRITICAL
           → TRANSPARENT / UNVERIFIED / DECEPTIVE_PAYLOAD
```

### 3.3 Component Map

| File | Role |
|---|---|
| `analyze.py` | All five layers, CLI entry point, report generation |
| `structural_parser.py` | Multi-language AST node extraction |
| `post_check_run.py` | GitHub Check Run posting via App JWT |
| `action.yml` | Composite GitHub Action definition |
| `test_analyzer.py` | 124-test unit suite |

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

**Outputs:** `critical_deletions` (list), `security_deletions` (list), counts passed to L3.

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

### 4.6 Layer 5b — Semantic Transparency

**Purpose:** Detect the *deceptive description* pattern — benign language in the PR description contradicting a destructive diff.

**Algorithm:**
```python
claims_benign = any(keyword in pr_description.lower() for keyword in benign_keywords)
is_deceptive  = claims_benign AND actual_severity == "CRITICAL"
```

Default benign keywords: `minor fix`, `minor syntax fix`, `typo`, `formatting`, `cleanup`, `docs`, `refactor whitespace`, `small tweak`, `cosmetic`, `minor update`.

No PR description → `UNVERIFIED` (advisory only, no score impact). The layer is purely semantic — it does not change the numerical score; it adds a high-visibility flag in the report.

**Output:** `semantic` dict with `status` (TRANSPARENT / UNVERIFIED / DECEPTIVE_PAYLOAD), `is_deceptive`, `matched_keyword`, directive string.

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

The test harness (`darkvader-plg/payloadguard-test-harness`) maintains 18 permanent branches, each representing a specific adversarial scenario. Each branch has a closed PR against main. Running a regression:

1. `run_regression.py` reopens all 18 PRs
2. GitHub Actions triggers a PayloadGuard scan on each
3. The script polls GitHub Check Runs until all 18 complete
4. PRs are closed
5. `ingest.py` pulls the `payloadguard-results` artifact from each workflow run and writes to SQLite
6. `dashboard.py` visualises results with a threshold simulator; the **Last Run** summary card shows a full `YYYY-MM-DD HH:MM` timestamp linked directly to the GitHub Actions workflow run that produced the data

### 6.2 Test Case Matrix

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

### 6.3 Results at Default Thresholds

```
structural deletion_ratio : 0.20 (20%)
min_deleted_nodes          : 3
DESTRUCTIVE threshold      : 5
CAUTION threshold          : 3
temporal stale             : 250
temporal dangerous         : 1000
```

| Result | Count | Cases |
|---|---|---|
| True DESTRUCTIVE | 14 | T03 T04 T05 T09 T10 T11 A01 A02 A03 A04 A05 A07 A09 |
| True SAFE | 3 | T01 T02 T12 A10 |
| False SAFE (missed) | 1 | A06 |
| False DESTRUCTIVE | 0 | — |

**Pass rate: 17/18 (94%)**

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
  benign_keywords:                     # phrases that claim low impact
    - minor fix
    - typo
    - formatting
    - cleanup
    - small tweak
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

### 8.5 Semantic Layer Keyword Coverage

Layer 5b fires only when the PR description contains one of the configured benign keywords. A sufficiently vague description ("updates") that doesn't match any keyword produces `UNVERIFIED` rather than `DECEPTIVE_PAYLOAD`. The layer is a high-precision supplement, not a comprehensive intent classifier.

---

## 9. GitHub 2026 Roadmap Alignment

PayloadGuard complements GitHub's 2026 security roadmap without overlapping it. GitHub is building the execution-security layer — dependency locking, policy controls, egress firewalls, real-time monitoring. PayloadGuard is the **semantic consequence layer** that sits upstream: it analyzes what a change *means* before it merges, where execution-level controls cannot yet reach.

### 9.1 Layer-to-Roadmap Mapping

| PayloadGuard Layer | What it detects | 2026 Roadmap Pillar |
|---|---|---|
| L1 — Surface Scan | File deletions, binary files, permission changes, symlink replacements | Hardened CI/CD infrastructure |
| L2 — Forensic | Critical path files, deletion ratios, config-only destruction | Hardened CI/CD infrastructure |
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

*PayloadGuard — because AI doesn't feel bad about what it breaks.*
