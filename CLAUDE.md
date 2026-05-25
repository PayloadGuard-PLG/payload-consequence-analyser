# PayloadGuard — Claude Code Context

## Handover (update this block at the end of every session)

- **Branch for next work:** new branch off main
- **Status:** v1.1.0 live on main. All INC findings closed. Red-team complete — RTA-02/05/07 fixes merged (PR #41). INC-3 fixed (PR #42). 5 RTA branches registered in harness test_cases.json (38 total cases).
- **Next priority:** L5b semantic analysis v2 — Steve researching with Gemini/NotebookLM. Bring findings back to implement a credible `SemanticTransparencyAnalyzer` (pure Python, no network, no ML, <2s). Current implementation is hardcoded keyword list — too simple.
- **Open findings:** None (INC-1, INC-3, INC-4 all closed). One documented bypass: RTA02 (`rta/schedule-curl-exfil`) — schedule + curl POST body with secret, URL on continuation line evades all credential_harvest patterns. Needs multiline-aware curl body pattern.
- **Deferred:** RTA-01 (multi-step env var, requires YAML-aware parsing), RTA-03 (unpinned action advisory), refactoring sprint (split `analyze.py` into focused modules).
- **Post red-team fixes:** RTA-02 ✓, RTA-05 ✓, RTA-07 ✓ (PR #41, merged). RTA-01, RTA-03 deferred.
- **Test suite:** `python -m pytest test_analyzer.py -v` → 206 pass, 7 skip (crypto/tree-sitter env)
- **GitHub App credentials:** STALE after org migration. `post_check_run.py` will fail until App is re-installed under `PayloadGuard-PLG`. Workaround: `continue-on-error: true` on both "Post Check Run" (analyser) and "PayloadGuard Scan" (harness) steps.
- **Harness CI:** Operational. SHA pinned to `32014117afeb5c99f51045b3df0d7ba27e0a187a` (post INC-3 fix). Regression runner: `workflow_dispatch` + schedule (02:00/10:00/18:00 UTC daily, full mode). Results in `tools/db/results.db` artifact per run. `REGRESSION_PAT` secret set.
- **Harness branches:** 38 test cases (main + session + 36 test/rta branches). All stale session branches removed.
- **Blockers:** None.

---

## What PayloadGuard Is

A GitHub Action + Python CLI that analyses pull requests for destructive payloads before merge. It does not look for bugs — it looks for PRs that would catastrophically gut the codebase (mass deletions, structural wipeouts, deceptive descriptions). Org: **PayloadGuard-PLG** (formerly DarkVader-PLG, migrated after account suspension).

**Repos:**
- `PayloadGuard-PLG/payload-consequence-analyser` — the analyser (this repo)
- `PayloadGuard-PLG/payloadguard-test-harness` — integration test harness

---

## Architecture

### Five-Layer Analysis (`analyze.py`)

| Layer | What it does | Key class/function |
|---|---|---|
| L1 Surface | File/line counts, permission changes, symlinks | `PayloadAnalyzer.analyze()` |
| L2 Forensic | Critical path regex matching on deleted files | `CRITICAL_PATH_PATTERNS`, `_SECURITY_CRITICAL_PATTERNS` |
| L2b SCA | Manifest diff scanning vs `allowlist.yml` (opt-in) | `_parse_added_packages()`, `_load_allowlist()` |
| L3 Consequence | Severity scoring → SAFE/REVIEW/CAUTION/DESTRUCTIVE | `_assess_consequence()` |
| L4 Structural | AST diff — named class/function/constant deletions | `StructuralPayloadAnalyzer` |
| L4b Complexity | McCabe V(G) advisory for newly added Python fns | inside `analyze_structural_drift()` |
| L5a Temporal | Branch age × target velocity drift score | `TemporalDriftAnalyzer` |
| L5b Semantic | PR description vs actual severity (deceptive payload) | `SemanticTransparencyAnalyzer` |

### Key Files

```
analyze.py           — core analyser, all layers, CLI entry point
structural_parser.py — tree-sitter AST node extraction (Python/JS/TS/Go/Rust/Ruby)
post_check_run.py    — posts GitHub Check Run via App JWT (RS256)
action.yml           — GitHub Action composite wrapper
test_analyzer.py     — pytest suite (151 tests)
allowlist.yml        — SCA package allowlist (user-created, not in repo by default)
payloadguard.yml     — per-repo threshold config (user-created, not in repo by default)
AUDIT_LOG.md         — architectural review findings + incident reports
WHITEPAPER.md        — full technical specification
DEVLOG.md            — chronological session log
```

### Scoring

- Structural CRITICAL: +5
- Security file deleted: +5
- Unverified dependency (SCA): +3 per unique package
- Critical path deleted: +2
- Line/file/ratio flags: up to +4 (capped, correlated dims)
- Branch age: +1/+2/+3
- Thresholds: score >=5 -> DESTRUCTIVE, >=3 -> CAUTION, >=1 -> REVIEW

### Config (`payloadguard.yml` in target repo, optional)

```yaml
thresholds:
  branch_age_days: [90, 180, 365]
  files_deleted: [10, 20, 50]
  lines_deleted: [5000, 10000, 50000]
  structural:
    deletion_ratio: 0.20
    min_deleted_nodes: 3
    complexity_threshold: 15
sca:
  fail_on_unknown: true
```

---

## Current Version

`__version__ = "1.1.0"` (analyze.py:29)

### v1.1.0 changes (branch `claude/initial-setup-WO53R`)
- Fix 1.1: Cross-file structural aggregation requires BOTH count AND ratio (was count-only)
- Fix 1.3: YAML parse errors emit WARNING to stderr instead of swallowing silently
- Fix 2.1: JS/TS parser now tracks all `variable_declarator` names (const/let/var, not just arrow fns)
- Fix 3.1: GitHub Check Run summary uses `_safe_truncate()` — cuts at newline, closes open fences
- Fix 3.2: `cryptography` import guard at module load in `post_check_run.py`
- Feature A: SCA dependency scan (L2b) — opt-in via `allowlist.yml`
- Feature B: McCabe complexity advisory for newly added Python functions (no score impact)

---

## Open Findings (from AUDIT_LOG.md)

| ID | Description | Severity | Priority |
|---|---|---|---|
| INC-1 | Added non-code files (.txt, .md) not scanned for content -- CI trigger strings invisible | HIGH | Next sprint |
| INC-3 | Direct push to main -> L5b returns UNVERIFIED but raises no flag | MEDIUM | Backlog |
| INC-4 | File additions score 0 regardless of content -- rm -rf / indistinguishable from blank | HIGH | Next sprint |

### INC-1/INC-4 Implementation sketch (not started)
- New function `_scan_added_file_content(blob, path)` in `analyze.py`
- Patterns: `[citest`, `needs-ci`, `citest commit:`, `setfacl`, `chmod`, `curl | bash`, `sudo`
- Only fires on A-type diffs for non-code extensions
- Adds to `content_flags` list in report, +2 score per match

---

## Development Rules

- **Push:** `git push -u origin <branch>` — MCP push works now but PC push is equally fine
- **Branch:** Next sprint work on `claude/check-mcp-connection-OUqlz` (INC-1/INC-4)
- **Tests:** Run `python -m pytest test_analyzer.py -v` before every commit -- must stay green
- **No MCP push_files:** Confirmed broken in multiple sessions. Don't retry.
- **Commit style:** Imperative, specific, with test count in body. See git log for examples.
- **NotebookLM:** Do not use for active code sessions -- use only for reading stable documents.

---

## Environment

- Python 3.11+
- Dependencies: `gitpython`, `pyyaml`, `tree-sitter` (optional)
- Test: `pip install pytest` then `python -m pytest test_analyzer.py -v`
- CI: GitHub Actions via `action.yml` -- runs on every PR in consumer repos

---

## How to Start a New Session

1. Read this file (`CLAUDE.md`) -- you now have full context
2. Check the **Handover** block at the top for what's in flight
3. Run `git log --oneline -5` to confirm branch state
4. Run `python -m pytest test_analyzer.py -v` to confirm green baseline
5. Begin work

**Update the Handover block before ending every session.**
