# PayloadGuard

**Scans a branch before merge and tells you if it's going to destroy your codebase.**

Designed for AI-assisted workflows where a suggestion described as a "minor syntax fix" can silently delete 60 files, 11,967 lines, and your entire test suite.

---

## Install

```bash
pip install -r requirements.txt
```

Requirements: Python 3.8+, GitPython, PyYAML.

---

## Run

```bash
python analyze.py <repo_path> <branch> [target]
```

**Examples:**

```bash
# Basic scan
python analyze.py . feature-branch main

# Include PR description check (detects deceptive descriptions)
python analyze.py . feature-branch main --pr-description "minor syntax fix"

# Save a JSON report as well
python analyze.py . feature-branch main --pr-description "minor syntax fix" --save-json

# Save to a specific file
python analyze.py . feature-branch main --save-json reports/scan.json
```

Run `python analyze.py --help` for full usage.

---

## Output

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
| `SAFE` | No significant red flags |
| `REVIEW` | Minor flags — normal review applies |
| `CAUTION` | Significant destructive signals |
| `DESTRUCTIVE` | Do not merge |

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Safe or review |
| `1` | Analysis error |
| `2` | Destructive — use this to block CI |

---

## CI Integration

Add this step to your GitHub Actions workflow to block destructive merges automatically:

```yaml
- name: PayloadGuard
  run: |
    python analyze.py . ${{ github.head_ref }} main \
      --pr-description "${{ github.event.pull_request.body }}"
```

The job fails (exit code `2`) when the verdict is `DESTRUCTIVE`, blocking the merge.

---

## Configuration

Drop a `payloadguard.yml` in your repository root to tune thresholds for your team's risk tolerance. All keys are optional — unspecified values fall back to defaults.

```yaml
# payloadguard.yml
thresholds:
  branch_age_days: [90, 180, 365]     # days at which score increases
  files_deleted:   [10, 20, 50]       # file counts at which score increases
  lines_deleted:   [5000, 10000, 50000]
  temporal:
    stale:     250    # drift score for STALE warning
    dangerous: 1000   # drift score for DANGEROUS warning
  structural:
    deletion_ratio:    0.20   # fraction of AST nodes deleted to flag CRITICAL
    min_deleted_nodes: 3      # minimum deletion count before ratio check fires

semantic:
  benign_keywords:
    - minor fix
    - minor syntax fix
    - typo
    - formatting
    - cleanup
    - small tweak
```

**Example — stricter settings for a security-critical repo:**

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

## How It Works

PayloadGuard runs five layers of analysis on every scan:

| Layer | Name | Question answered |
|---|---|---|
| 1 | Surface Scan | How many files and lines change? |
| 2 | Forensic Analysis | What fraction of the changeset is deletions? |
| 3 | Consequence Model | What is the combined severity score? |
| 4 | Structural Drift | Are classes and functions being silently deleted? |
| 5a | Temporal Drift | Is this branch dangerously out of date? |
| 5b | Semantic Transparency | Does the PR description match the actual diff? |

### Layer 3 — Consequence Model

Produces the final verdict by accumulating a weighted severity score across all signals:

| Signal | Thresholds | Points |
|---|---|---|
| Branch age | > 90 / 180 / 365 days | 1 / 2 / 3 |
| Files deleted | > 10 / 20 / 50 | 1 / 2 / 3 |
| Deletion ratio | > 50% / 70% / 90% | 1 / 2 / 3 |
| Structural severity | CRITICAL | 3 |
| Lines deleted | > 5k / 10k / 50k | 1 / 2 / 3 |

Score ≥ 5 → `DESTRUCTIVE`. Score 3–4 → `CAUTION`. Score 1–2 → `REVIEW`. Score 0 → `SAFE`.

### Layer 4 — Structural Drift

Parses every modified Python file into an Abstract Syntax Tree and computes the exact set of deleted class and function definitions. Flags `CRITICAL` only when **both** conditions are met — preventing false positives on small utility files:

- Deletion ratio exceeds `deletion_ratio_threshold` (default 20%)
- Number of deleted nodes meets `min_deleted_nodes` (default 3)

### Layer 5a — Temporal Drift

Computes a compound **Drift Score** = `branch_age_days × target_commits_per_day`. Raw age alone is misleading — a 90-day branch on a slow repo (score 90) is very different from the same branch on a fast-moving repo (score 1800). Verdicts: `CURRENT`, `STALE`, `DANGEROUS`.

### Layer 5b — Semantic Transparency

Compares the PR description against the verified severity verdict. Flags `DECEPTIVE_PAYLOAD` when the description claims low impact ("minor fix", "typo") but the structural verdict is `CRITICAL`. Directly models the April 2026 incident pattern.

Layer 5 verdicts are advisory — they appear in the report but do not override the main verdict.

---

## Background

In April 2026 a developer received an AI (Codex) suggestion described as a *"minor syntax fix"*. The branch was 10 months old. Had it merged, it would have deleted 60 files, 11,967 lines, 217 tests, and the entire application architecture. PayloadGuard detects every signal that incident produced: the branch age, the deletion ratio, the structural wipeout, and the contradiction between the description and the diff.
