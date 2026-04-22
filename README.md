# PayloadGuard

Scans a branch before merge and tells you exactly how badly it's going to hurt.

> **dev:** [Dark^Vader](https://github.com/DarkVader-PLG)

---

## Install

```bash
pip install -r requirements.txt
```

Python 3.8+, GitPython, PyYAML. That's it.

---

## Run

```bash
python analyze.py <repo_path> <branch> [target]
```

```bash
# Basic scan
python analyze.py . feature-branch main

# Feed it the PR description — catches deceptive payloads
python analyze.py . feature-branch main --pr-description "minor syntax fix"

# Save a JSON report
python analyze.py . feature-branch main --save-json

# Save to a specific path
python analyze.py . feature-branch main --save-json reports/scan.json
```

`python analyze.py --help` if you need it.

---

## The forensic report

Every scan produces the same structured report. Here's what each section tells you and what to look for.

---

### 📅 Temporal

How old the branch is relative to the target, and which commits are being compared. A branch that's been sitting open for months while the target keeps moving is already a problem before you look at a single line.

```
📅 TEMPORAL
   Branch age: 14 days
   Branch: a1b2c3d (2026-04-08)
   Target:  e4f5g6h (2026-04-22)
```

---

### 📁 File changes

Raw scope of the changeset — files added, deleted, modified. Deletions are the number to watch. A PR that adds 2 files and deletes 40 is not a normal PR.

```
📁 FILE CHANGES
   Added:      3
   Deleted:    1
   Modified:   5
   Total:      9
```

---

### 📝 Line changes

Volume and direction of change. Deletion ratio is the derived signal — what fraction of total churn is removal. Above 50% starts raising flags; above 90% means almost everything this PR touches is being taken away.

```
📝 LINE CHANGES
   Added:        420 lines
   Deleted:       18 lines
   Net:          402 lines
   Deletion ratio: 4.1%
```

---

### 🧬 Structural drift — Layer 4

Parses every modified Python file into an AST and computes exactly which named classes and functions disappeared. This is the layer that catches a file being "modified" when it's actually been gutted — line diffs alone won't tell you that `AuthManager` and `SessionStore` no longer exist.

Flags `CRITICAL` only when both conditions are met: deletion ratio exceeds the threshold **and** enough nodes were deleted. The dual gate prevents noise from small utility files.

```
🧬 STRUCTURAL DRIFT (Layer 4)
   Overall severity: LOW
   Max deletion ratio: 0.0%
```

If something is actually being removed at scale:

```
🧬 STRUCTURAL DRIFT (Layer 4)
   Overall severity: CRITICAL
   src/core/auth.py: 8 nodes deleted (80.0%) [CRITICAL]
      - AuthManager
      - SessionStore
      - TokenValidator
```

---

### ⏱ Temporal drift — Layer 5a

Compound score: `branch_age_days × target_commits_per_day`. Raw age alone is a weak signal — a 90-day branch on a slow repo is nothing; on a fast repo it's a serious semantic gap. The drift score accounts for both.

| Status | Drift Score | Meaning |
|---|---|---|
| `CURRENT` | < 250 | Branch context is valid |
| `STALE` | 250 – 999 | Moderate drift — manual diff review |
| `DANGEROUS` | ≥ 1000 | Rebase required before this goes anywhere near main |

```
⏱  TEMPORAL DRIFT (Layer 5a)
   Status: CURRENT [LOW]
   Drift Score: 14.0
   Target velocity: 1.0 commits/day
   ✓ SAFE. Branch context is synchronized with target.
```

---

### 🔎 Semantic transparency — Layer 5b

Compares the PR description against the verified severity. If the description uses low-impact language ("minor fix", "typo", "cleanup") but the structural verdict is `CRITICAL`, that's a `DECEPTIVE_PAYLOAD`. Advisory signal — doesn't override the main verdict, but it shows up clearly.

| Status | Meaning |
|---|---|
| `TRANSPARENT` | Description matches what the diff actually does |
| `UNVERIFIED` | No description provided |
| `DECEPTIVE_PAYLOAD` | Description claims low impact, diff says otherwise |

```
🔎 SEMANTIC TRANSPARENCY (Layer 5b)
   Status: TRANSPARENT
   ✓ SAFE. PR description aligns with verified structural impact.
```

---

### 🔍 Verdict

The final call. Produced by the consequence model (Layer 3) which accumulates a weighted score across all signals. No single threshold triggers it — it's the combination that matters.

| Verdict | Severity | Score | Meaning |
|---|---|---|---|
| `SAFE` | LOW | 0 | Nothing notable. Proceed. |
| `REVIEW` | MEDIUM | 1–2 | Minor flags. Worth a look but not alarming. |
| `CAUTION` | HIGH | 3–4 | Real signals. Needs proper review before merge. |
| `DESTRUCTIVE` | CRITICAL | ≥ 5 | Stop. Do not merge. |

```
🔍 VERDICT: SAFE [LOW]
   ⚠️  No major red flags detected

✉️  RECOMMENDATION:
   ✓ Proceed with normal review process
```

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Fine |
| `1` | Analysis broke |
| `2` | Do not merge — wire this to block CI |

---

## CI

```yaml
- name: PayloadGuard
  run: |
    python analyze.py . ${{ github.head_ref }} main \
      --pr-description "${{ github.event.pull_request.body }}"
```

Exit `2` fails the job. Merge blocked. Done.

---

## Configuration

Drop a `payloadguard.yml` in your repo root. Everything is optional — omit what you don't care about and the defaults hold.

```yaml
# payloadguard.yml
thresholds:
  branch_age_days: [90, 180, 365]      # score goes up at each
  files_deleted:   [10, 20, 50]
  lines_deleted:   [5000, 10000, 50000]
  temporal:
    stale:     250                      # drift score = age × commits/day
    dangerous: 1000
  structural:
    deletion_ratio:    0.20             # fraction of AST nodes deleted
    min_deleted_nodes: 3               # both must be hit to flag CRITICAL

semantic:
  benign_keywords:
    - minor fix
    - minor syntax fix
    - typo
    - formatting
    - cleanup
    - small tweak
```

Tighten it for anything that matters:

```yaml
thresholds:
  structural:
    deletion_ratio: 0.10
    min_deleted_nodes: 2
semantic:
  benign_keywords:
    - minor fix
    - typo
    - trivial
    - nit
```

---

## How it works

Five layers. Every scan, every time.

| Layer | What it checks |
|---|---|
| 1 — Surface Scan | Files and lines changed |
| 2 — Forensic Analysis | Deletion ratio, critical path detection |
| 3 — Consequence Model | Weighted score → final verdict |
| 4 — Structural Drift | AST diff — which classes and functions actually disappeared |
| 5a — Temporal Drift | Branch age × repo velocity |
| 5b — Semantic Transparency | Does the PR description match what the diff actually does |

### Scoring (Layer 3)

Points accumulate across signals. No single threshold kills you — it's the pile-up that matters.

| Signal | Thresholds | Points |
|---|---|---|
| Branch age | > 90 / 180 / 365 days | 1 / 2 / 3 |
| Files deleted | > 10 / 20 / 50 | 1 / 2 / 3 |
| Deletion ratio | > 50% / 70% / 90% | 1 / 2 / 3 |
| Structural severity | CRITICAL | 3 |
| Lines deleted | > 5k / 10k / 50k | 1 / 2 / 3 |

`≥ 5` → DESTRUCTIVE. `3–4` → CAUTION. `1–2` → REVIEW. `0` → SAFE.

---

## The incident

In April 2026, a developer received a Codex suggestion described as a *"minor syntax fix"*. The branch had been open for 10 months. Nobody looked closely enough. It would have deleted 60 files, 11,967 lines, 217 tests, and the entire application architecture in a single merge. That's what this tool was built to stop.

Below is the forensic report PayloadGuard would have produced on that branch.

```
======================================================================
PAYLOADGUARD ANALYSIS: codex-suggestion → main
======================================================================

📅 TEMPORAL
   Branch age: 312 days
   Branch: fa3c21d (2025-06-04)
   Target:  b87e90a (2026-04-22)

📁 FILE CHANGES
   Added:      2
   Deleted:   61
   Modified:   4
   Total:     67

📝 LINE CHANGES
   Added:        214 lines
   Deleted:   11,967 lines
   Net:       -11,753 lines
   Deletion ratio: 98.2%

🧬 STRUCTURAL DRIFT (Layer 4)
   Overall severity: CRITICAL
   Max deletion ratio: 94.0%
   src/core/auth.py: 12 nodes deleted (94.0%) [CRITICAL]
      - AuthManager
      - SessionStore
      - TokenValidator
      - PermissionGate
      - RoleRegistry

⏱  TEMPORAL DRIFT (Layer 5a)
   Status: DANGEROUS [CRITICAL]
   Drift Score: 3120.0
   Target velocity: 10.0 commits/day
   ❌ DO NOT MERGE. Extreme semantic drift detected. Mandatory rebase
      and manual architectural review required.

🔎 SEMANTIC TRANSPARENCY (Layer 5b)
   Status: DECEPTIVE_PAYLOAD
   Matched keyword: "minor syntax fix"
   ❌ DO NOT MERGE. PR description deliberately contradicts catastrophic
      architectural changes.

🔍 VERDICT: DESTRUCTIVE [CRITICAL]
   ⚠️  Branch is 312 days old (6+ months)
   ⚠️  61 files would be deleted (massive scope)
   ⚠️  Deletion ratio: 98.2% (almost entire changeset is deletions)
   ⚠️  Structural drift CRITICAL — significant Python class/function
       deletions detected
   ⚠️  11,967 lines would be deleted (large codebase change)

✉️  RECOMMENDATION:
   ❌ DO NOT MERGE — This would catastrophically alter the codebase

🗑️  DELETED FILES (61 total)

   CRITICAL DELETIONS:
      - tests/test_auth.py
      - tests/test_core.py
      - tests/test_integration.py
      - .github/workflows/ci.yml
      - src/core/auth.py
      - src/core/engine.py
      - requirements.txt

   OTHER DELETIONS:
      - src/modules/session.py
      - src/modules/permissions.py
      - src/modules/roles.py
      ... and 51 more files

======================================================================
```

Every signal was there. The age. The deletion ratio. The structural wipeout. The gap between what the description said and what the diff actually did. Nobody saw it. Now you will.

---

*PayloadGuard — because AI doesn't feel bad about what it breaks.*
