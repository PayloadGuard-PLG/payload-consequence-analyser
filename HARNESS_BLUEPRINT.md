# PayloadGuard — Harness Integration Blueprint

**Version:** 1.3.0 | **Updated:** 2026-06-01

This document describes the complete interaction between the test harness and PayloadGuard: how
test cases are structured, how scans are triggered, how results flow through the system, and how
regressions are evaluated. Read `SYSTEM_BLUEPRINT.md` first for the analyser's internal pipeline.

---

## Repository Relationship

```
┌────────────────────────────────────────────────────────────────────────┐
│  PayloadGuard-PLG/payload-consequence-analyser  (the analyser)         │
│                                                                         │
│  analyze.py + action.yml                                                │
│  Published as: payloadguard-plg/payload-consequence-analyser@<sha>     │
│                                                                         │
│  trigger-regression.yml                                                 │
│  └─ workflow_dispatch only                                              │
│     └─ POSTs repository_dispatch "analyser-updated" →                  │
└───────────────────────────────┬────────────────────────────────────────┘
                                │  repository_dispatch (REGRESSION_PAT)
                                ▼
┌────────────────────────────────────────────────────────────────────────┐
│  PayloadGuard-PLG/payloadguard-test-harness  (the harness)             │
│                                                                         │
│  38 permanent fixture branches  (one scenario per branch)              │
│  3 reserved pending-API branches (T23–T25)                             │
│                                                                         │
│  .github/workflows/payloadguard.yml  ← fires on every PR open/sync    │
│  .github/workflows/regression.yml   ← workflow_dispatch or dispatch   │
│                                                                         │
│  tools/run_regression.py   — orchestrator (open PRs → wait → close)   │
│  tools/ingest.py           — pulls JSON artifacts → SQLite             │
│  tools/dashboard.py        — Dash app: matrix, history, simulator      │
│  tools/test_cases.json     — ground truth: IDs, categories, verdicts  │
└────────────────────────────────────────────────────────────────────────┘
```

The analyser and harness are completely independent repositories. The harness contains no production
code; every source file exists solely as a diff target for PayloadGuard to scan. Triggering flows
in one direction only: analyser → harness (dispatch), never the reverse.

---

## Harness Repository Layout

```
payloadguard-test-harness/
│
├── .github/
│   └── workflows/
│       ├── payloadguard.yml      # Fires on every PR — calls analyser action
│       └── regression.yml        # Orchestrates a full regression cycle
│
├── tools/
│   ├── test_cases.json           # Ground truth: 41 registered test cases
│   ├── run_regression.py         # Regression orchestrator (CLI)
│   ├── ingest.py                 # JSON artifact → SQLite importer
│   ├── dashboard.py              # Dash results dashboard
│   └── db/
│       └── results.db            # SQLite database (generated, not committed)
│
├── auth.py                       # Fixture source file (auth layer target)
├── database.py                   # Fixture source file (database layer target)
├── settings.yml                  # Fixture config file
├── test_auth.py                  # Fixture test file
├── test_database.py              # Fixture test file
│
├── HARNESS.md                    # Full test case matrix + runner docs
├── TEST_SPEC.md                  # Per-branch specification: change, layers, verdict
└── CLAUDE.md                     # Session context
```

The fixture source files (`auth.py`, `database.py`, etc.) on `main` are the baseline. Each test
branch diverges from `main` with a specific change — typically deleting, modifying, or adding one or
more of these files, or adding a workflow file to `.github/workflows/`.

---

## Test Case Taxonomy

### Ground truth: `tools/test_cases.json`

Every registered test case has an entry keyed by branch name:

```json
"adversarial/slow-deletion": {
  "id": "A03",
  "category": "adversarial",
  "temporal_group": "stable",
  "expected_verdict": "SAFE",
  "expected_exit_code": 0,
  "description": "1 function removed from each of 5 files — distributed deletion evasion. Known bypass: cross-file ratio (~8%) is below the 20% aggregation threshold."
}
```

`test_cases.json` is the canonical source of truth. `HARNESS.md` and `TEST_SPEC.md` are human-
readable projections of it; when they conflict, `test_cases.json` wins.

### Categories (9)

| Category | Count | Purpose |
|---|---|---|
| `safe` | 3 | Zero-noise baselines — any DESTRUCTIVE result is a false positive |
| `destructive` | 2 | Canonical payloads — any non-DESTRUCTIVE is a missed detection |
| `boundary` | 1 | Metrics tuned just above a scoring threshold — confirms boundary crossing |
| `semantic` | 2 | PR description vs diff alignment tests (L5b) |
| `multilang` | 1 | Parser stress across JS, TS, Go (L4) |
| `adversarial` | 14 | Static evasion: deletion obfuscation, threshold gaming, workflow poisoning bypasses |
| `red-team` | 5 | Live red-team findings from 2026-05-25 — confirmed detections and known bypasses |
| `runtime` | 3 | L5c eBPF agent event coverage (advisory — no score impact, verdict always SAFE) |
| `workflow-security` | 10 | L2c signal coverage (7 active) + 3 pending GitHub 2026 API |

### Temporal groups

| Group | Regression treatment |
|---|---|
| `stable` | Strict pass/fail — result must match `expected_verdict` on every run |
| `aging` | Observational only — verdict drifts as branch age accumulates; no pass/fail assertion |

Aging cases (T01, T02, T12, A10) were created on new branches and are expected to eventually drift
from SAFE to REVIEW/CAUTION as `branch_age_days` grows and L5a temporal drift accumulates.

### Pending cases

T23–T25 are registered in `test_cases.json` with `"status": "pending-2026-api"` but have no
fixture branches. They depend on GitHub 2026 API features not yet available. The regression runner
filters them out in all modes.

---

## The PayloadGuard Workflow File (harness)

```yaml
# .github/workflows/payloadguard.yml
on:
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write

    steps:
      - uses: actions/checkout@<sha>  # v6, SHA-pinned
        with:
          fetch-depth: 0              # full history required for merge-base computation

      - name: PayloadGuard Scan
        id: payloadguard
        continue-on-error: true       # prevents scan errors from blocking close
        uses: payloadguard-plg/payload-consequence-analyser@<sha>  # pinned to main SHA
        with:
          repo-token:       ${{ secrets.GITHUB_TOKEN }}
          pr-description:   ${{ github.event.pull_request.body }}
          app-id:           ${{ secrets.PAYLOADGUARD_APP_ID }}
          private-key:      ${{ secrets.PAYLOADGUARD_PRIVATE_KEY }}
          installation-id:  ${{ secrets.PAYLOADGUARD_INSTALLATION_ID }}

      - name: Upload JSON report
        if: always()
        uses: actions/upload-artifact@<sha>  # v7, SHA-pinned
        with:
          name: payloadguard-results
          path: payloadguard-report.json    # emitted by analyze.py --save-json
          retention-days: 90

      - name: Enforce verdict
        if: always()
        env:
          EXIT_CODE: ${{ steps.payloadguard.outputs.exit-code }}
        run: |
          if [ "$EXIT_CODE" = "1" ]; then exit 1; fi   # analysis error
          if [ "$EXIT_CODE" = "2" ]; then exit 2; fi   # DESTRUCTIVE
```

Key design decisions:
- **SHA-pinned actions** — all `uses:` references point to exact commit SHAs, not floating tags. This makes the harness itself immune to the supply-chain attacks it is designed to detect.
- **`continue-on-error: true`** on the scan step — allows the PR to be closed by the regression runner even if the scan step errors.
- **Artifact upload** — `payloadguard-report.json` is always uploaded, even on failure. `ingest.py` retrieves it by artifact name (`payloadguard-results`).
- **`fetch-depth: 0`** — full clone is mandatory; PayloadGuard needs the complete commit history to compute `merge_base` and `branch_age_days`.

---

## Full Automated Scan Cycle

### Step-by-step for a single test case

```
Test branch: adversarial/slow-deletion (A03)
Expected verdict: SAFE (known bypass — cross-file structural ratio below threshold)

1. PR is opened (or reopened)
   └── GitHub fires pull_request.reopened event
       └── payloadguard.yml workflow is triggered

2. Runner: actions/checkout@<sha>
   └── Full clone with fetch-depth: 0
   └── Working directory contains the test branch at HEAD

3. Runner: payloadguard-plg/payload-consequence-analyser@<sha>
   └── action.yml composite steps execute:
       a. Set up Python 3.x
       b. pip install -r requirements.txt
       c. python analyze.py . <branch> main \
              --pr-description "$PR_DESCRIPTION" \
              --save-json
          → runs 9-layer analysis (see SYSTEM_BLUEPRINT.md)
          → emits payloadguard-report.json
          → writes outputs: exit-code, verdict, severity-score
       d. python post_check_run.py
          → reads PAYLOADGUARD_APP_ID / PRIVATE_KEY / INSTALLATION_ID
          → signs JWT (RS256), gets installation token
          → posts named Check Run to GitHub ("PayloadGuard")
            with verdict summary in the checks tab

4. Runner: Upload JSON report
   └── payloadguard-report.json → GitHub Actions artifact "payloadguard-results"
       (retained 90 days)

5. Runner: Enforce verdict
   └── EXIT_CODE=2 → step exits 2 → check run conclusion = "failure"
   └── EXIT_CODE=0 → step exits 0 → check run conclusion = "success"
   └── EXIT_CODE=1 → step exits 1 → check run conclusion = "failure" (analysis error)

6. Regression runner receives check run conclusion
   └── conclusion="success" → A03 result = SAFE → PASS (expected SAFE)
```

---

## Regression Cycle: Full Orchestration

The regression runner (`tools/run_regression.py`) drives an entire test cycle through the GitHub
API. It requires a PAT (`REGRESSION_PAT`) with `repo` and `pull_requests` scope — `GITHUB_TOKEN`
cannot be used because it does not trigger `pull_request` events when used to open/reopen PRs
(GitHub blocks self-triggering to prevent infinite loops).

### Phase 1 — Discovery

```
run_regression.py --mode stable
  └── Read test_cases.json → build set of active_branches (mode filter)
  └── GET /repos/payloadguard-plg/payloadguard-test-harness/pulls?state=closed
      └── Filter: head.ref ∈ active_branches
      └── Returns: list of closed PRs, one per test branch
```

The harness maintains exactly one closed PR per test branch at all times. The regression runner
finds them by listing closed PRs and matching the head branch name.

### Phase 2 — Reopen (trigger scans)

```
  └── For each closed PR:
      PATCH /repos/.../pulls/<number> {"state": "open"}
      └── GitHub emits pull_request.reopened
          └── payloadguard.yml fires on the harness runner
              └── Full scan cycle executes (Steps 1–6 above)
      └── Record reopen_time (ISO 8601, UTC)
      └── Record pr_sha_map: {pr_number → head_sha}
```

### Phase 3 — Poll for completion

```
  └── Every 15 seconds, for each pending PR:
      GET /repos/.../commits/<sha>/check-runs?check_name=PayloadGuard
      └── Filter: status == "completed"
                  AND started_at > reopen_time  (ignore stale runs from previous cycles)
      └── Record conclusion per PR
  └── Timeout: 600s default (--timeout flag)
  └── Timed-out PRs are logged as warnings; regression continues
```

The `started_at > reopen_time` filter is critical: without it, a stale check run from a previous
regression cycle would be accepted as the current result.

### Phase 4 — Close PRs

```
  └── For each PR in pr_sha_map:
      PATCH /repos/.../pulls/<number> {"state": "closed"}
```

Closing happens regardless of scan outcome. If close fails, the PR is left open — this is logged
and does not abort the cycle.

### Phase 5 — Evaluate

```
  └── For each (pr_number, conclusion) in scan_results:
      branch = pr_branch_map[pr_number]
      tc = test_cases[branch]
      group = tc.temporal_group

      if group == "aging":
          → print as OBSERVING, increment observed count
      elif conclusion matches expected_exit_code:
          → PASS, increment passed count
      else:
          → FAIL, print expected vs actual, increment failed count
```

Mapping: `conclusion="failure"` ↔ `expected_exit_code=2` (DESTRUCTIVE);
`conclusion="success"` ↔ `expected_exit_code=0` (SAFE / REVIEW / CAUTION).

### Phase 6 — Optional ingest

```
  if --ingest:
      subprocess: python tools/ingest.py
      └── pulls all completed workflow runs for payloadguard.yml
      └── downloads payloadguard-results artifact per run
      └── hydrates SQLite at tools/db/results.db
```

---

## CI Trigger Chains

### Chain 1: Manual regression via harness workflow_dispatch

```
User → GitHub UI: "Run workflow" on regression.yml (harness)
  └── regression.yml fires
      └── pip install requests
      └── python tools/run_regression.py --mode <mode> --ingest --timeout 900
          └── Full orchestration cycle (Steps 1–6)
      └── Write job summary to $GITHUB_STEP_SUMMARY
      └── Upload results.db as artifact
      └── Exit 1 if any stable case FAIL
```

### Chain 2: Manual trigger from analyser side

```
User → GitHub UI: "Run workflow" on trigger-regression.yml (analyser)
  └── trigger-regression.yml fires
      └── POST https://api.github.com/repos/PayloadGuard-PLG/payloadguard-test-harness/dispatches
          {event_type: "analyser-updated", client_payload: {sha, ref, actor}}
          (requires REGRESSION_PAT secret in analyser repo)
  └── GitHub delivers repository_dispatch to harness
      └── regression.yml receives it (if configured — currently workflow_dispatch only)
      └── Full cycle runs
```

Note: `regression.yml` in the harness is currently `workflow_dispatch` only. `repository_dispatch`
support was removed when the 3× daily schedule was eliminated. To re-enable cross-repo triggering,
add `repository_dispatch` as a trigger to `regression.yml`.

### Chain 3: Per-PR automatic scan (always on)

```
Any PR opened/synchronised/reopened against main on the harness
  └── payloadguard.yml always fires (no manual step required)
  └── Single-scan cycle (Steps 1–6 above)
  └── Result: check run posted to the PR
```

This chain is the primary mechanism during regression runs (Phase 2–3 above) and also fires on any
manual PR opened during development — including PRs from the `claude/oidc-typosquat-detection-UBCOJ`
dev branch, which are scanned by PayloadGuard before being merged.

---

## Result Storage

### JSON artifact (`payloadguard-report.json`)

PayloadGuard emits a full JSON report when `--save-json` is passed (or via `action.yml`). Structure:

```json
{
  "branch":      "adversarial/nested-gutting",
  "target":      "main",
  "base_commit": "abc123",
  "branch_commit": "def456",
  "days_old":    12,

  "file_counts":  {"added": 0, "deleted": 0, "modified": 5, "total": 5},
  "line_counts":  {"added": 5, "deleted": 47, "net": -42},
  "deletion_ratio": 90.4,

  "permission_changes": [],
  "special_files": [],

  "critical_file_deletions": 0,
  "security_file_deletions": 0,
  "deleted_critical_files": [],

  "content_flags": 0,
  "content_flag_matches": [],

  "sca": {"unverified_dependencies": 0, "packages": []},

  "structural_flags": [
    {
      "file": "auth.py",
      "status": "STRUCTURAL_DRIFT",
      "severity": "CRITICAL",
      "metrics": {
        "deleted_node_count": 4,
        "total_node_count": 17,
        "structural_deletion_ratio": 23.5
      },
      "deleted_components": ["verify_token", "refresh_session", "validate_role", "check_scope"]
    }
  ],
  "overall_structural_severity": "CRITICAL",
  "complexity_advisory": [],

  "temporal_drift": {
    "status": "CURRENT",
    "drift_score": 24.0,
    "branch_age_days": 12,
    "target_commits_per_day": 2.0
  },

  "semantic_transparency": {
    "result": "DECEPTIVE_PAYLOAD",
    "mci_score": 0.7,
    "signals": ["scope_understated", "operation_mutation"],
    "label": "DECEPTIVE_PAYLOAD"
  },

  "actions_poisoning": {
    "signals": [],
    "has_critical": false,
    "has_high": false,
    "mutable_action_refs": []
  },

  "runtime_events": [],

  "severity_score": 12,
  "status": "DESTRUCTIVE",
  "verdict": {"status": "DESTRUCTIVE", "severity": "CRITICAL", "severity_score": 12},
  "flags": [
    "Structural drift CRITICAL — core authentication layer removed",
    "Description contradicts actual severity"
  ]
}
```

### SQLite schema (`tools/db/results.db`)

`ingest.py` populates two tables:

**`scan_runs`** — one row per workflow run:

| Column | Type | Content |
|---|---|---|
| `workflow_run_id` | TEXT UNIQUE | GitHub Actions run ID |
| `pr_number` | INTEGER | PR that triggered the run |
| `branch` | TEXT | Test fixture branch name |
| `test_case_id` | TEXT | e.g. "A03" |
| `category` | TEXT | e.g. "adversarial" |
| `temporal_group` | TEXT | "stable" or "aging" |
| `run_at` | TEXT | ISO 8601 timestamp |
| `verdict_status` | TEXT | SAFE / REVIEW / CAUTION / DESTRUCTIVE |
| `verdict_score` | REAL | Raw severity score |
| `exit_code` | INTEGER | 0 or 2 |
| `files_deleted` | INTEGER | |
| `lines_deleted` | INTEGER | |
| `deletion_ratio_pct` | REAL | |
| `structural_severity` | TEXT | LOW / MEDIUM / HIGH / CRITICAL |
| `branch_age_days` | INTEGER | |
| `temporal_status` | TEXT | CURRENT / STALE / DANGEROUS |
| `semantic_status` | TEXT | TRANSPARENT / DECEPTIVE_PAYLOAD / etc. |
| `raw_json` | TEXT | Full JSON report blob |

**`structural_flags`** — one row per flagged file per run:

| Column | Type | Content |
|---|---|---|
| `run_id` | INTEGER | FK → scan_runs.id |
| `file_path` | TEXT | |
| `severity` | TEXT | |
| `deleted_node_count` | INTEGER | |
| `deletion_ratio_pct` | REAL | |
| `deleted_components` | TEXT | JSON array of symbol names |

**`expected_verdicts`** — seeded from `test_cases.json` on each ingest run:

| Column | Type | Content |
|---|---|---|
| `test_case_id` | TEXT PK | |
| `expected_verdict` | TEXT | |
| `expected_exit_code` | INTEGER | |

---

## Dashboard (`tools/dashboard.py`)

Plotly Dash application at `http://127.0.0.1:8050`. Three tabs:

**Regression Matrix** — cross-tabulates test case × run date. Each cell shows ✅/❌ + verdict.
Cells are colour-coded green (pass) / red (fail). Reads from `scan_runs` JOIN `expected_verdicts`.

**Test History** — per-case score-over-time chart. Dropdown selects the test case; a threshold
line marks where the expected verdict boundary is. Panel shows layer-level detail for the most
recent run (files deleted, lines deleted, deletion ratio, structural severity, semantic status,
verdict score).

**Threshold Simulator** — re-scores all historical results with adjustable parameters (structural
ratio threshold, min deleted nodes, temporal stale/dangerous thresholds, DESTRUCTIVE/CAUTION score
thresholds). Highlights which verdicts would flip and whether each case would still pass. Useful for
evaluating whether a threshold change would cause regressions before touching `analyze.py`.

---

## Adding a Test Case

```
1. Create branch off main with the scenario changes.

2. Open a PR against main.
   └── payloadguard.yml fires automatically.
   └── Confirm the verdict is what you expect.
   └── If not: diagnose via the JSON report artifact.

3. Close the PR (do not merge).

4. Add entry to tools/test_cases.json:
   {
     "<category>/<name>": {
       "id": "<next sequential ID>",
       "category": "<category>",
       "temporal_group": "stable",
       "expected_verdict": "<SAFE|REVIEW|CAUTION|DESTRUCTIVE>",
       "expected_exit_code": <0|2>,
       "description": "<one sentence, factual>"
     }
   }

5. Add row to HARNESS.md matrix table.

6. Add specification to TEST_SPEC.md under the appropriate track.

7. Update CLAUDE.md (harness) Handover block.
```

Do NOT merge the test branch. The fixture branches are permanent and stay closed-but-unmerged.
Merging them would apply the scenario changes to `main` and corrupt the baseline.

---

## Branch Protection and Self-Scanning

The analyser scans its own PRs via `.github/workflows/payloadguard.yml` in the analyser repo. This
means any PR to the analyser — including PRs from `claude/oidc-typosquat-detection-UBCOJ` — is
analysed by the current production version of PayloadGuard. If a change to `analyze.py` introduces
a scoring bug that would make PayloadGuard flag its own legitimate changes as DESTRUCTIVE, that scan
would fail on the PR and block the merge.

This creates a mild self-referential constraint: drastic refactors of `analyze.py` (mass deletions,
structural gutting) must score below DESTRUCTIVE or the PR cannot be merged. The harness tests do
not cover this scenario — it is tested by the analyser's self-scan only.

---

## Secrets Required

| Secret | Repo | Purpose |
|---|---|---|
| `GITHUB_TOKEN` | Both (automatic) | PR comment, check run read access (scoped to the repo) |
| `PAYLOADGUARD_APP_ID` | Harness | Posts named Check Run in the PR checks tab |
| `PAYLOADGUARD_PRIVATE_KEY` | Harness | RS256 JWT for GitHub App authentication |
| `PAYLOADGUARD_INSTALLATION_ID` | Harness | Installation scope for the GitHub App |
| `REGRESSION_PAT` | Both | Cross-repo PR reopen/close; must have `repo` + `pull_requests` scope on harness |

Without `PAYLOADGUARD_APP_*` the check run tab shows nothing but the `payloadguard.yml` step still
runs and the verdict is enforced via exit code. Without `REGRESSION_PAT` the regression workflow
can still be triggered manually — `--token $GITHUB_TOKEN` is replaced with the PAT at runtime.

---

## Operational Notes

### Why REGRESSION_PAT and not GITHUB_TOKEN?

GitHub prevents `GITHUB_TOKEN` from triggering new workflow runs when used to open or reopen PRs.
This is an intentional anti-loop safeguard. The regression runner requires a PAT because reopening
a PR must fire `payloadguard.yml` — and that requires a token that is not the built-in workflow
identity.

### Stale check run guard

The poller checks `started_at > reopen_time`. If a previous scan ran but was never ingested (e.g.
the runner timed out in an earlier cycle), its check run would satisfy `status == "completed"` but
would have `started_at` before the current reopen. Without this guard, the regression would silently
accept a stale result from a previous cycle.

### Artifact retention

`payloadguard-results` artifacts are retained for 90 days. `ingest.py` idempotently skips already-
ingested runs (`INSERT OR IGNORE` on `workflow_run_id`). Running `ingest.py` multiple times is safe.

### `continue-on-error: true` on the scan step

If `analyze.py` crashes (bad YAML, unexpected git state, import error), the step would exit 1.
Without `continue-on-error`, the entire job would stop and the artifact would not be uploaded.
With it, the upload and enforce steps still run. The `Enforce verdict` step maps exit code 1 to
a job failure — so analysis errors are still caught, but the PR can be closed by the regression
runner and the (empty) artifact is still uploaded.

### SHA pinning in the harness

All `uses:` references in harness workflows are pinned to exact SHAs. This is deliberate:
- The harness self-tests PayloadGuard's ability to detect mutable action references (`AW01`–`AW05`).
- A harness that uses mutable tags would be internally inconsistent.
- SHA pinning also prevents the harness from being compromised by a tag-hijacking attack against
  the actions it depends on.

The analyser SHA in `payloadguard.yml` must be updated manually when a new version is deployed to
`main`. The current pin points to the analyser commit that removed PLI and restored the test suite.
