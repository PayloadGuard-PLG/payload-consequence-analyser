# PayloadGuard

Scans a branch before merge and tells you exactly how badly it's going to hurt.

Built after watching an AI suggest a *"minor syntax fix"* that would have deleted 60 files, 11,967 lines, and an entire test suite. No one noticed. That's the problem.

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

## What you get

```
======================================================================
PAYLOADGUARD ANALYSIS: feature-branch → main
======================================================================

📅 TEMPORAL
   Branch age: 312 days

📁 FILE CHANGES
   Added:      2
   Deleted:   61
   Modified:   4

📝 LINE CHANGES
   Added:        214 lines
   Deleted:   11,967 lines
   Deletion ratio: 98.2%

🧬 STRUCTURAL DRIFT (Layer 4)
   Overall severity: CRITICAL
   src/core/auth.py: 12 nodes deleted (94.0%) [CRITICAL]

⏱  TEMPORAL DRIFT (Layer 5a)
   Status: DANGEROUS  |  Drift Score: 3120.0

🔎 SEMANTIC TRANSPARENCY (Layer 5b)
   Status: DECEPTIVE_PAYLOAD
   Matched keyword: "minor syntax fix"

🔍 VERDICT: DESTRUCTIVE [CRITICAL]

✉️  RECOMMENDATION:
   ❌ DO NOT MERGE — This would catastrophically alter the codebase
```

---

## Verdicts

| Verdict | Meaning |
|---|---|
| `SAFE` | Clean |
| `REVIEW` | Worth a look |
| `CAUTION` | Something's off |
| `DESTRUCTIVE` | Walk away |

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
| 5a — Temporal Drift | Branch age × repo velocity. Old branch on a fast-moving repo is a different animal than old branch on a slow one |
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

### Structural drift (Layer 4)

Parses modified Python files into ASTs and diffs the named nodes — classes, functions, async functions. Flags CRITICAL only when both conditions land:

- Deletion ratio exceeds threshold (default 20%)
- Deleted node count hits minimum (default 3)

The dual gate stops it crying wolf over small utility files losing one helper.

### Temporal drift (Layer 5a)

`Drift Score = branch_age_days × target_commits_per_day`

Raw age is a bad metric on its own. 90 days on a repo with 1 commit/week is nothing. 90 days on a repo shipping 20 commits/day is a different problem entirely.

### Semantic transparency (Layer 5b)

Checks whether the PR description matches the actual severity. If someone calls a `CRITICAL`-severity change a "minor fix" or a "typo", that's flagged `DECEPTIVE_PAYLOAD`. Layer 5 verdicts are advisory — they show up in the report but don't override the main verdict.

---

## The incident

April 2026. A developer got a Codex suggestion: *"minor syntax fix"*. The branch was 10 months old. Nobody looked closely. It would have deleted 60 files, 11,967 lines, 217 tests, and the entire application architecture in one merge.

PayloadGuard catches every signal that produced: the age, the deletion ratio, the structural wipeout, and the gap between what the description claimed and what the diff actually did.

---

*PayloadGuard — because AI doesn't feel bad about what it breaks.*
