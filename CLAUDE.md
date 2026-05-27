# PayloadGuard — Claude Code Context

## Handover (update this block at the end of every session)

- **Branch for next work:** `claude/oidc-typosquat-detection-UBCOJ`
- **Status:** v1.2.0 live on main. Phase 2 Stage 1+2+3a+3b FULLY VERIFIED on real hardware (WSL2, kernel 6.6.114.1-microsoft-standard-WSL2, Windows 11).
- **Phase 2 Stage 3b (block mode + egress allowlist) — VERIFIED on real hardware:**
  - Smoke test PASSED: all 4 event types captured (execve, egress_connect, ptrace_attach, procmem_open).
  - Three PC-specific fixes applied:
    1. `agent/preflight.go`: `rlimit.RemoveMemlock()` moved before canary load — WSL2 fails canary with EPERM if memlock still in effect.
    2. `agent/bpf/probe.c` `trace_openat`: `__builtin_memcpy` size corrected from `sizeof(e->detail)=64` to `sizeof(path)=32` — BPF verifier caught out-of-bounds read at R10+7.
    3. `agent/bpf/probe.c` `trace_ptrace`: `PTRACE_TRACEME` (request=0) added to the filter alongside `PTRACE_ATTACH` (16) and `PTRACE_SEIZE` (0x4206).
  - `agent/bpf/probe.c`: two BPF maps (`pg_config`, `egress_allow_ipv4`) + block logic via `bpf_send_signal(9)`. Event struct has `blocked` field.
  - `agent/main.go`: populates maps at startup, reports `blocked` in JSON events.
  - `agent/events.go`: `Blocked uint8` + `Pad [3]uint8` fields.
  - `scripts/pc-smoke-test.sh`: one-command build+run+verify. Run with `sudo bash scripts/pc-smoke-test.sh`.
- **Phase 2 Stage 3a (eBPF agent skeleton) — SHIPPED:**
  - `agent/bpf/probe.c`: 4 tracepoint probes (execve/connect/ptrace/openat).
  - `agent/main.go`: ring buffer event loop, SIGTERM handler, `--mode disabled|audit|block` flag.
  - `agent/preflight.go`: kernel ≥5.8 check + memlock removal + BPF canary load (graceful exit 0 if unavailable).
  - `action.yml`: `runtime-mode` input + `runtime-events-path` output + agent download+run step.
  - `analyze.py`: `_load_runtime_events()` + `"runtime_events"` key in report (advisory, no score impact).
  - **Dev environment note:** This container has `CONFIG_KPROBES=not set` — preflight exits 0 with warning. WSL2 on Windows 11 has `CONFIG_KPROBES=y` and runs the agent fully.
- **Phase 2 Stage 2 (Z3 proofs) — SHIPPED:**
  - `tests/proofs/test_z3_properties.py`: P1–P10, all `unsat` in <0.1 s.
  - Run: `pytest tests/proofs/ -m proof -v --timeout=30`
- **Phase 2 Stage 1 (auto-remediation) — SHIPPED:**
  - `remediate.py`: `WorkflowRemediator` — resolves `uses:` tags to SHAs, patches YAML, opens PR.
  - `action.yml`: `auto-remediate` input (default `false`).
- **Test suite:** `python -m pytest test_analyzer.py tests/proofs/ -q --timeout=30` → 267 pass, 7 skip.
- **Next priority:** RTA02 bypass (multiline curl body evades credential harvest pattern). INC-3 (direct push to main, no flag).
- **Open findings:** RTA02 bypass (multiline curl body), INC-3 (direct push to main).
- **GitHub App:** App ID 3856270, Installation ID 135500427. Both repos confirmed in scope.
- **Harness CI:** 41 test cases (38 original + RT01/RT02/RT03), regression runner operational with `--mode runtime`.
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

## PC Setup — eBPF Agent (Stage 3b)

When moving to a PC (Ubuntu 22.04/24.04 or WSL2 with kernel ≥5.15):

```bash
# 1. Pull latest
git pull origin claude/oidc-typosquat-detection-UBCOJ

# 2. One-shot smoke test (builds, runs, fires all 4 event types, checks results)
sudo bash scripts/pc-smoke-test.sh

# 3. Manual run
cd agent
go generate ./...                          # recompile BPF (only needed after probe.c edits)
go build -o ../dist/pg-agent-linux-amd64 .
sudo ../dist/pg-agent-linux-amd64 --mode=audit --dry-run

# 4. Block mode with policy
cat > /tmp/policy.yaml << 'EOF'
egress:
  allow:
    - github.com
    - api.github.com
    - 127.0.0.1
EOF
sudo ../dist/pg-agent-linux-amd64 --mode=block --policy=/tmp/policy.yaml
```

Kernel requirement check: `zcat /proc/config.gz | grep CONFIG_KPROBES` — must be `=y`.
The agent preflight canary will warn and exit 0 gracefully if tracepoints are unavailable.

---

## Development Rules

- **Push:** `git push -u origin <branch>` — MCP push works now but PC push is equally fine
- **CLAUDE.md is updated on every change, no exceptions.** Every code change, fix, finding, doc update, or architectural decision goes into the Handover block before the session ends. Stale handovers cause real work loss.
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
