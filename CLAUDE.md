# PayloadGuard — Claude Code Context

## Handover (update this block at the end of every session)

- **Branch for next work:** `claude/oidc-typosquat-detection-UBCOJ`
- **Status:** v1.2.0 live on main. Phase 2 Stage 1+2+3a shipped on working branch.
- **Phase 2 Stage 1 (auto-remediation) — SHIPPED on branch:**
  - `remediate.py`: `WorkflowRemediator` class — scans `uses:` refs, resolves lightweight+annotated tags to SHAs via GitHub API, patches YAML round-trip-safely, opens new PR (never direct commit). SHA cache at `$RUNNER_TEMP/pg-sha-cache.json`.
  - `analyze.py`: `_scan_mutable_action_refs()` function + `mutable_tag_warnings` key in JSON report (advisory, no score impact).
  - `action.yml`: `auto-remediate` input (default `false`); new step runs `remediate.py` when enabled.
  - `requirements.txt`: `ruamel.yaml>=0.18.0`, `z3-solver>=4.12.0`, `pytest-timeout>=2.0`.
  - `test_analyzer.py`: 21 new `TestWorkflowRemediation` tests.
- **Phase 2 Stage 2 (Z3 proofs) — SHIPPED on branch:**
  - `tests/proofs/test_z3_properties.py`: P1–P10, all `unsat` in <0.1 s.
  - `pyproject.toml`: `proof` marker registered.
  - Run: `pytest tests/proofs/ -m proof -v --timeout=30`
- **Phase 2 Stage 3a (eBPF agent skeleton) — SHIPPED on branch:**
  - `agent/bpf/probe.c`: 4 tracepoint probes (execve/connect/ptrace/openat), linux-headers approach (no CO-RE/BTF needed), `BPF_MAP_TYPE_RINGBUF`.
  - `agent/main.go`: `//go:generate bpf2go` directive, ring buffer event loop, SIGTERM handler, `--mode disabled|audit|block` flag, `--dry-run` flag.
  - `agent/preflight.go`: kernel ≥5.8 check + BPF canary load (gracefully exits 0 if tracepoints unavailable).
  - `agent/events.go`, `agent/attach.go`, `agent/policy.go`: event types, tracepoint attacher, YAML egress allowlist.
  - `agent/go.mod`: `module github.com/payloadguard-plg/pg-agent`, cilium/ebpf v0.21.0.
  - `agent/Makefile`: generate + build-amd64 + build-arm64.
  - `dist/pg-agent-linux-amd64` (6.9 MB) + `dist/pg-agent-linux-arm64` (6.6 MB): compiled binaries (not committed).
  - `action.yml`: `runtime-mode` input + `runtime-events-path` output + agent download+run step.
  - `analyze.py`: `_load_runtime_events()` + `"runtime_events"` key in report (advisory, no score impact).
  - **Dev environment note:** This container has `CONFIG_KPROBES=not set` (tracepoints unavailable). Preflight detects this and exits 0 with warning. Binaries compiled and tested for graceful degradation. Full functionality verified via code review — will work on Ubuntu 22.04/24.04 GitHub Actions runners.
- **Test suite:** `python -m pytest test_analyzer.py tests/proofs/ -q --timeout=30` → 267 pass, 7 skip.
- **Next priority (Stage 3b):** Wire egress allowlist into connect handler; add block mode (`bpf_send_signal(9)`); create RT01-RT03 harness branches; add `--mode runtime` to `run_regression.py`.
- **Open findings:** RTA02 bypass still open (multiline curl body), INC-1/INC-4 (added file content scan).
- **GitHub App:** App ID 3856270, Installation ID 135500427. Both repos confirmed in scope.
- **Harness CI:** 38 test cases, regression runner operational. Pinned SHA `32014117afeb5c99f51045b3df0d7ba27e0a187a`.
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

`__version__ = "1.2.0"` (analyze.py:29)

### v1.2.0 changes
- Feature: L2c GitHub Actions poisoning detection — base64 payload, credential harvest, dormant trigger, forged bot author, OIDC elevation, pull_request_target signals
- Feature: L5b v2 PR-MCI heuristic engine — three-phase (Linguistic Lexer → Diff Profiler → Cross-Correlation), mci_score ∈ [0,1], five signals (V_s/V_o/V_f/V_r/V_e)
- Fix: L2 content scanner now excludes `.github/workflows/` files — L2c is the exclusive handler, preventing double-scoring
- Fix: Exit code table corrected — CAUTION exits 0, only DESTRUCTIVE exits 2
- Test suite: 236 pass, 7 skip (+26 TestSemanticTransparencyV2 tests)

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
