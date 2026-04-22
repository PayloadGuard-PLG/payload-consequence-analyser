# PayloadGuard: Destructive Merge Detection

Detect catastrophic code payloads before they're merged.

## The Problem

41% of shipped code is AI-generated. Dependency automation merges PRs without review. Supply chain attacks hide destructive payloads in legitimate-looking suggestions.

**April 2026 Real Incident:** A user received a Codex suggestion described as a "minor syntax fix." The branch was 10 months old and would have deleted 60 files, 11,967 lines, 217 tests, and the entire architecture.

## The Solution

PayloadGuard runs five layers of analysis before any merge and answers five critical questions:

1. **Scope** — How many files and lines change?
2. **Impact** — What gets removed?
3. **Temporal** — Is this branch current with the target?
4. **Structural** — Are classes and functions being silently deleted?
5. **Transparency** — Does the PR description match the actual diff?

## Quick Start

```bash
pip install -r requirements.txt
python analyze.py /path/to/repo feature-branch main
```

With PR description check:

```bash
python analyze.py . feature-branch main --pr-description "minor syntax fix"
```

Save a JSON report:

```bash
python analyze.py . feature-branch main --pr-description "minor syntax fix" --save-json
```

## Five-Layer Architecture

### Layer 1 — Surface Scan
Extracts the raw file and line delta: files added, deleted, modified, renamed. Establishes the scope of the change.

### Layer 2 — Forensic Analysis
Computes deletion ratios, net line change, and codebase reduction percentage. Flags changesets where deletions dominate additions.

### Layer 3 — Consequence Model
Combines all signals into a weighted severity score and produces a final verdict: `SAFE`, `REVIEW`, `CAUTION`, or `DESTRUCTIVE`.

### Layer 4 — Structural Drift (`StructuralPayloadAnalyzer`)
Parses every modified Python file into an Abstract Syntax Tree and computes the exact set of deleted class and function definitions. Flags `CRITICAL` when both a deletion ratio threshold and a minimum deletion count are exceeded — preventing false positives on small utility files.

**Configurable thresholds** (set per-repo or per-team):

```python
StructuralPayloadAnalyzer(
    original, modified,
    deletion_ratio_threshold=0.10,  # default 0.20 (20%)
    min_deletion_count=5            # default 3
)
```

### Layer 5a — Temporal Drift (`TemporalDriftAnalyzer`)
Computes a compound **Drift Score** = `branch_age_days × target_velocity_commits_per_day`. Raw age alone is misleading: a 90-day-old branch on a slow repo (score 90) is very different from one on a fast-moving repo (score 1800). Verdicts: `CURRENT`, `STALE`, `DANGEROUS`.

**Configurable thresholds:**

```python
TemporalDriftAnalyzer(
    branch_age_days=90,
    target_velocity_commits_per_day=5.0,
    warning_threshold=250.0,    # default
    critical_threshold=1000.0   # default
)
```

### Layer 5b — Semantic Transparency (`SemanticTransparencyAnalyzer`)
Compares the PR description against the verified severity verdict. Detects the `DECEPTIVE_PAYLOAD` pattern: a description claiming low impact ("minor syntax fix", "typo", "cleanup") combined with a `CRITICAL` structural verdict. Directly models the April 2026 incident.

**Configurable keyword list:**

```python
SemanticTransparencyAnalyzer(
    pr_description, actual_severity,
    benign_keywords=["minor fix", "typo", "small tweak", "cosmetic", "nit"]
)
```

The default keyword list covers common low-impact phrases. Extend it with vocabulary specific to your team's PR culture.

## Verdict Reference

| Status | Severity | Meaning |
|---|---|---|
| `SAFE` | LOW | No significant red flags |
| `REVIEW` | MEDIUM | Minor flags — normal review applies |
| `CAUTION` | HIGH | Significant destructive signals |
| `DESTRUCTIVE` | CRITICAL | Do not merge without full architectural review |

Layer 5 verdicts (`temporal_drift`, `semantic`) are reported independently and feed into the console output but do not override the main verdict — they are advisory signals alongside it.

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Safe or review — no block |
| `1` | Analysis error |
| `2` | Destructive — CI should block merge |

Use exit code `2` to gate merges in CI:

```yaml
- name: PayloadGuard
  run: python analyze.py . ${{ github.head_ref }} main --pr-description "${{ github.event.pull_request.body }}"
```

## Requirements

- Python 3.8+
- GitPython >= 3.1.41
