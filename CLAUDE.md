# PayloadGuard — Claude Code Context

## Handover (update this block at the end of every session)

- **Branch for next work:** create a new branch from main
- **Status:** v1.3.0. PLI L4b integration evaluated and reverted. Regression (2026-05-29, 34 stable cases): 30/34 pass. PLI fixed 2 bypasses (A03, A06) but introduced 3 false positives (WS07, RT02, RTA03) via format mismatch — PLI's L2 LLM treats code diff summaries as blank AI responses. PLI code preserved on branch `claude/oidc-typosquat-detection-UBCOJ` and in repo (`pli_analyzer.py`, `pli_engine.py`, `PLI_INTEGRATION_SPEC.md`). Scoring path reverted: MAX_SCORE 36→31, pli_critical/pli_high removed from `_assess_consequence()`. Harness workflow updated to reverted SHA. Auto-regression trigger disabled (was flooding General conversation session with ~200 GitHub events per push).
- **Next action:** Investigate WS03 (workflow-security/dormant-trigger): expected DESTRUCTIVE, consistently getting CAUTION (score=3). L2c dormant_trigger signal fires but score caps at 3 (CAUTION). Determine why second signal not firing.
- **CI:** `trigger-regression.yml` now manual-only (`workflow_dispatch`). Removed push-to-main auto-trigger. Run regression explicitly when needed.
- **Vericoding Phase 4 — Dafny MERGED (PR #70, main `b44a116`):**
  - `verification/dafny/assess_consequence.dfy`: L3 — POST-1–11a (score bounds, verdict bijection, safety implications, empty-input guarantee). POST-12 (PLI) removed in revert.
  - `verification/dafny/structural_drift.dfy`: L4 — S1–S7 dual-gate biconditional
  - `verification/dafny/temporal_drift.dfy`: L5a — T1–T8 linear drift, zero-input guarantees
  - `.github/workflows/verify-dafny.yml`: CI — Dafny 4.9.1 release zip (bundles Z3 4.12.1); runs on PR/push touching `verification/dafny/**`
  - `verify-dafny.log` placeholder in place — replace with actual `dafny verify` output after local run
- **Vericoding Phase 2 — CrossHair SHIPPED, all 4 layers verified (272 pass, 7 skip):**
  - `verification/consequence_pure.py`: Layer 3 — C1–C12 contracts (verdict bijection, score bounds, safety implications). C13 (PLI) removed in revert.
  - `verification/temporal_pure.py`: Layer 5a — T1–T7 contracts (drift_score ≥ 0, status bijection, zero-input → CURRENT)
  - `verification/structural_pure.py`: Layer 4 — S1–S7 contracts (dual-gate: DESTRUCTIVE requires BOTH ratio > threshold AND count ≥ min)
  - `verification/semantic_pure.py`: Layer 5b — M1–M9 contracts (mci_score ∈ [0,1], DECEPTIVE ↔ score ≥ 0.5, no-description → UNVERIFIED)
  - `tests/proofs/test_crosshair_contracts.py`: 5 pytest tests (`@pytest.mark.crosshair`) — all pass in ~8s.
  - `VERIFICATION.md`: public-facing doc — what is proven, how, what is not, sync requirement.
  - `VERIFICATION_SPEC.md`: formal specification for external verifiers — pinned to `d0541f6`.
  - Run CrossHair: `cd verification && crosshair check <module> --analysis_kind PEP316 --per_condition_timeout 30`
  - Run via pytest: `pytest tests/proofs/ -m crosshair -v`
  - **Constraint:** Verification is external. Claude produces specs/implementation modules only.
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
- **Phase 2 Stage 2 (Z3 proofs) — SHIPPED:**
  - `tests/proofs/test_z3_properties.py`: P1–P10, all `unsat` in <0.1 s.
  - Run: `pytest tests/proofs/ -m proof -v --timeout=30`
- **Phase 2 Stage 1 (auto-remediation) — SHIPPED:**
  - `remediate.py`: `WorkflowRemediator` — resolves `uses:` tags to SHAs, patches YAML, opens PR.
  - `action.yml`: `auto-remediate` input (default `false`).
- **Test suite:** `python -m pytest test_analyzer.py tests/proofs/ -q --timeout=30` → 272 pass, 7 skip.
- **Open findings:** INC-3 (direct push to main). WS03 (dormant-trigger) CAUTION not DESTRUCTIVE.
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

### Nine-Layer Analysis (`analyze.py`)

| Layer | What it does | Key class/function |
|---|---|---|
| L1 Surface | File/line counts, permission changes, symlinks | `PayloadAnalyzer.analyze()` |
| L2 Forensic | Critical path regex matching on deleted files + added file content scan | `CRITICAL_PATH_PATTERNS`, `_scan_added_file_content()` |
| L2b SCA | Manifest diff scanning vs `allowlist.yml` (opt-in) | `_parse_added_packages()`, `_load_allowlist()` |
| L2c Actions Poisoning | Added/modified workflow files: base64, credential harvest, OIDC elevation, typosquatted consumers | `_scan_github_actions_poisoning()` |
| L3 Consequence | Severity scoring → SAFE/REVIEW/CAUTION/DESTRUCTIVE | `_assess_consequence()` |
| L4 Structural | AST diff — named class/function/constant deletions | `StructuralPayloadAnalyzer` |
| L4b PLI | Semantic consistency — PR description vs diff, commit vs content, old vs new function | NOT ACTIVE — reverted; code on branch `claude/oidc-typosquat-detection-UBCOJ` |
| L4b Complexity | McCabe V(G) advisory for newly added Python fns | inside `analyze_structural_drift()` |
| L5a Temporal | Branch age × target velocity drift score | `TemporalDriftAnalyzer` |
| L5b Semantic | PR-MCI three-phase heuristic — deceptive description detection | `SemanticTransparencyAnalyzer` |
| L5c Runtime | eBPF tracepoint agent — execve/connect/ptrace/procmem, audit+block | `agent/`, `_load_runtime_events()` |

### Key Files

```
analyze.py               — core analyser, all layers, CLI entry point
pli_analyzer.py          — PLIAnalyzer: R&D only, not wired into scoring path
PLI_INTEGRATION_SPEC.md  — L4b integration reference (future use)
structural_parser.py — tree-sitter AST node extraction (Python/JS/TS/Go/Rust/Ruby)
post_check_run.py    — posts GitHub Check Run via App JWT (RS256)
remediate.py         — auto-remediation: resolves action tags to SHAs, opens PR
action.yml           — GitHub Action composite wrapper
agent/               — eBPF runtime defence agent (Go + cilium/ebpf)
agent/bpf/probe.c    — 4 tracepoint probes + pg_config/egress_allow_ipv4 BPF maps
scripts/pc-smoke-test.sh — one-command build+verify on real kernel
test_analyzer.py     — pytest suite (267 tests, + 5 CrossHair = 272 total)
tests/proofs/        — Z3 formal property proofs (P1–P10) + CrossHair pytest wrapper
verification/        — CrossHair verification targets: consequence_pure (C1-C12), temporal_pure (T1-T7), structural_pure (S1-S7), semantic_pure (M1-M9)
allowlist.yml        — SCA package allowlist (user-created, not in repo by default)
payloadguard.yml     — per-repo threshold config (user-created, not in repo by default)
AUDIT_LOG.md         — architectural review findings + incident reports
WHITEPAPER.md        — full technical specification
DEVLOG.md           — chronological session log
```

### Scoring

- Structural CRITICAL: +5
- Security file deleted: +5
- Actions poisoning CRITICAL signal: +5
- Unverified dependency (SCA): +3 per unique package
- Actions poisoning HIGH signal: +3
- Critical path deleted: +2
- Added file content flags (CI triggers/shell): +2 per match, capped at +4
- Line/file/ratio flags: up to +4 (capped, correlated dims)
- Branch age: +1/+2/+3
- Thresholds: score >=5 -> DESTRUCTIVE, >=3 -> CAUTION, >=1 -> REVIEW
- MAX_SCORE: 31

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

`__version__ = "1.3.0"` (analyze.py:29) — PLI reverted, architecture stable at v1.2.0 level + RTA02 fix

### v1.3.0 changes
- PLI L4b evaluated and reverted. PLI integration (PR #73) was implemented and regression-tested (34 stable cases, 2026-05-29). Result: 2 true positives (A03 adversarial/slow-deletion, A06 adversarial/threshold-gaming — both previously bypassing), 3 false positives (WS07 safe-clean-workflow, RT02 postinstall-curl, RTA03 prt-untrusted-checkout). Root cause: PLI's L2 LLM analysis interprets code diff summaries as blank AI responses, generating critical findings on legitimate safe PRs. Reverted from scoring path. PLI files remain in repo for future reintegration if input pairs are redesigned. MAX_SCORE reverted 36→31.
- Fix (RTA02): `_scan_github_actions_poisoning()` credential_harvest loop now checks normalized content — multiline curl with continuation lines detected. Expected verdict DESTRUCTIVE confirmed.
- CI: `trigger-regression.yml` changed to manual-only — removed push-to-main auto-trigger that was flooding Claude Code General conversation session with ~200 GitHub events per push.
- Docs: `PLI_INTEGRATION_SPEC.md` on main — complete L4b integration reference if reintegration pursued

### v1.2.0 changes
- Feature: L2c GitHub Actions poisoning detection — base64 payload, credential harvest, dormant trigger, forged bot author, OIDC elevation (incl. `oidc_elevation_typosquatted` CRITICAL), pull_request_target signals
- Feature: L5b v2 PR-MCI heuristic engine — three-phase (Linguistic Lexer → Diff Profiler → Cross-Correlation), mci_score ∈ [0,1], five signals (V_s/V_o/V_f/V_r/V_e)
- Feature: L5c eBPF runtime defence agent — 4 tracepoints, audit+block mode, egress allowlist, kernel-side `bpf_send_signal(9)`. Verified on WSL2 + GitHub Actions runners.
- Feature: INC-1/INC-4 fix — `_scan_added_file_content()` scans added non-code files for CI triggers and shell execution patterns (+2/match, capped +4)
- Fix: L2 content scanner now excludes `.github/workflows/` files — L2c is the exclusive handler, preventing double-scoring
- Fix: Exit code table corrected — CAUTION exits 0, only DESTRUCTIVE exits 2
- Test suite: 267 pass, 7 skip

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
| INC-3 | Direct push to main -> L5b returns UNVERIFIED but raises no flag | MEDIUM | Backlog |
| §2.3 | Single-branch clone / detached HEAD raises BadName exception | MEDIUM | Backlog |
| WS03 | workflow-security/dormant-trigger: expected DESTRUCTIVE, getting CAUTION (score=3) | MEDIUM | Next |

## Vericoding Plan (from `payloadguard-vericoding-plan.md` on main)

| Phase | Tool | Target | Status |
|---|---|---|---|
| 1 | Z3 SMT | L3 scoring — 10 properties (P1–P10) | Done — `tests/proofs/test_z3_properties.py` |
| 2 | CrossHair | All 4 layers — C1–C12, T1–T7, S1–S7, M1–M9 | Done — `verification/consequence_pure.py`, `temporal_pure.py`, `structural_pure.py`, `semantic_pure.py` |
| 3 | Nagini | `_assess_consequence()` — heap/null safety | **SKIPPED** — pure integer scorer; no heap or concurrency; toolchain cost (Java, Viper JAR, Python ≤3.12) adds no theorem beyond CrossHair |
| 4 | Dafny | L3/L4/L5a reference implementation vs spec | Done — `verification/dafny/assess_consequence.dfy`, `structural_drift.dfy`, `temporal_drift.dfy`; CI: `verify-dafny.yml`; run log pending |
| 5 | Publication | `VERIFICATION.md` public summary | Done — three-method summary, Dafny row added |

**Constraint:** Verification is always external. Claude writes specs and implementation modules; external parties run the tools and commit logs.

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
- **CLAUDE.md is updated on every change, no exceptions.** Every code change, fix, finding, doc update, or architectural decision goes into the Handover block before the session ends. Stale handovers cause real work loss. This includes architecture table, key files, scoring, open findings, and version changelog — not just the Handover block.
- **Read CLAUDE.md at session start and verify every section is current before touching code.**
- **Tests:** Run `python -m pytest test_analyzer.py -v` before every commit -- must stay green
- **Commit style:** Imperative, specific, with test count in body. See git log for examples.
- **Documentation style:** Professional and concise throughout. No informal, casual, or whimsical language in any documentation, commit messages, comments, or README content. State facts directly. Every sentence must earn its place.

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
