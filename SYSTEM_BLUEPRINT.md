# PayloadGuard — System Blueprint

**Version:** 1.3.0 | **Generated:** 2026-05-31

This document is the authoritative reference for the repository structure, module roles, production
dependencies, and the end-to-end analysis pipeline. Keep it in sync with the codebase; the code
always takes precedence when they conflict.

---

## Repository Layout

```
payload-consequence-analyser/
│
├── .github/
│   └── workflows/
│       ├── payloadguard.yml          # Self-scan: PayloadGuard runs on its own PRs
│       ├── publish.yml               # PyPI publish on release tag push
│       ├── trigger-regression.yml    # Manual-only: triggers harness regression suite
│       └── verify-dafny.yml          # CI: verifies Dafny proofs on verification/dafny/**
│
├── agent/                            # L5c eBPF runtime defence agent (Go)
│   ├── bpf/
│   │   └── probe.c                   # 4 tracepoint probes + BPF maps (pg_config, egress_allow_ipv4)
│   ├── attach.go                     # attaches eBPF programs to kernel tracepoints
│   ├── events.go                     # event struct (EventType, Pid, Comm, Detail, Blocked)
│   ├── main.go                       # entry point: parses flags, populates maps, runs event loop
│   ├── policy.go                     # YAML policy loader (egress allowlist)
│   ├── preflight.go                  # kernel capability checks + canary load
│   ├── probe_bpfeb.go / probe_bpfel.go  # generated: big/little-endian BPF object wrappers
│   ├── probe_bpfeb.o / probe_bpfel.o    # compiled BPF object files
│   ├── go.mod                        # module: github.com/payloadguard-plg/pg-agent
│   ├── go.sum
│   └── Makefile                      # `go generate ./...` → recompiles probe.c via bpf2go
│
├── dist/
│   ├── pg-agent-linux-amd64          # pre-built agent binary (x86_64)
│   └── pg-agent-linux-arm64          # pre-built agent binary (AArch64)
│
├── examples/
│   └── payloadguard.yml              # sample per-repo configuration file
│
├── scripts/
│   └── pc-smoke-test.sh              # one-command: build agent + run + fire all 4 event types + verify
│
├── tests/
│   ├── __init__.py
│   └── proofs/
│       ├── __init__.py
│       ├── test_crosshair_contracts.py   # pytest wrapper: runs CrossHair on all 4 pure modules
│       └── test_z3_properties.py         # Z3 SMT proofs: P1–P10 over L3 scoring
│
├── tools/
│   └── gen_test_registry.py          # generates TEST_REGISTRY.md from harness test metadata
│
├── verification/
│   ├── __init__.py
│   ├── consequence_pure.py           # L3: CrossHair contracts C1–C12 (score bounds, verdict bijection)
│   ├── temporal_pure.py              # L5a: CrossHair contracts T1–T7 (drift score, status bijection)
│   ├── structural_pure.py            # L4: CrossHair contracts S1–S7 (dual-gate biconditional)
│   ├── semantic_pure.py              # L5b: CrossHair contracts M1–M9 (mci_score bounds, DECEPTIVE ↔ ≥0.5)
│   └── dafny/
│       ├── assess_consequence.dfy    # L3: Dafny POST-1–11a (machine-checked over entire input domain)
│       ├── assess_consequence_verify.log  # dafny verify output (placeholder; replace after local run)
│       ├── structural_drift.dfy      # L4: Dafny S1–S7 dual-gate biconditional
│       └── temporal_drift.dfy        # L5a: Dafny T1–T8 linear drift, zero-input guarantees
│
├── analyze.py                        # Core: all 9 layers, scoring, CLI entry point (2,150 lines)
├── structural_parser.py              # L4 helper: tree-sitter AST extraction for 6 languages
├── post_check_run.py                 # GitHub Check Run poster (App JWT / RS256)
├── remediate.py                      # L2c auto-remediation: pin action tags to SHAs, open PR
├── orchestrator.py                   # R&D only — AIntegrity integration, not in production path
├── trust_grader.py                   # R&D only — TrustDecayModel / TrustGradingEngineV4, not wired in
├── action.yml                        # GitHub Action composite wrapper (inputs, outputs, steps)
├── pyproject.toml                    # package: payloadguard-plg v1.0.2; entry payloadguard=analyze:main
├── requirements.txt                  # Python runtime + test dependencies
├── test_analyzer.py                  # pytest suite: 273 pass, 7 skip (258 unit + 15 proof)
├── part1.txt                         # stale scratch artifact — candidate for removal
│
├── AUDIT_LOG.md                      # architectural findings + incident reports (source of truth)
├── CLAUDE.md                         # session context + architecture rules (this project's CLAUDE.md)
├── DEVLOG.md                         # chronological session log
├── LICENSE
├── README.md                         # user-facing documentation
├── TEST_REGISTRY.md                  # generated: harness test case registry
├── TEST_REPORT.md                    # generated: last harness run results
├── VERIFICATION.md                   # public-facing verification summary
├── VERIFICATION_SPEC.md              # formal spec for external auditors (pinned to d0541f6)
└── WHITEPAPER.md                     # full technical specification
```

---

## Module Map

### Production path (invoked on every PR scan)

| Module | Role | Key symbols |
|---|---|---|
| `analyze.py` | Core analyser — all 9 layers, scoring, report generation, CLI | `PayloadAnalyzer`, `PayloadGuardConfig`, `DEFAULT_CONFIG`, `load_config()`, `StructuralPayloadAnalyzer`, `TemporalDriftAnalyzer`, `SemanticTransparencyAnalyzer`, `_assess_consequence()`, `_scan_added_file_content()`, `_scan_github_actions_poisoning()`, `_iter_workflow_file_diffs()`, `_scan_mutable_action_refs()`, `_load_runtime_events()`, `print_report()`, `format_markdown_report()`, `save_json_report()`, `save_markdown_report()`, `main()` |
| `structural_parser.py` | L4 tree-sitter AST extraction for Python/JS/JSX/TS/TSX/Go/Rust/Java | `language_for_path()`, `_load_language()`, `extract_named_nodes()` |
| `post_check_run.py` | Posts named Check Run to GitHub via App JWT (RS256) | `_safe_truncate()`, `main()` |
| `remediate.py` | L2c auto-remediation: resolves `uses:` action tags to SHAs, opens PR | `RemediationTarget`, `WorkflowRemediator` |

### Supporting modules (not in scoring path)

| Module | Role |
|---|---|
| `orchestrator.py` | R&D — `AIntegrityCoreV4`: AIntegrity integration stub, not wired into scoring |
| `trust_grader.py` | R&D — `TrustDecayModel`, `TrustGradingEngineV4`: experimental trust scoring, not wired in |

### Verification modules (external — not imported by production code)

| Module | Layer | Method | Contracts |
|---|---|---|---|
| `verification/consequence_pure.py` | L3 Consequence | CrossHair PEP316 | C1–C12 |
| `verification/temporal_pure.py` | L5a Temporal | CrossHair PEP316 | T1–T7 |
| `verification/structural_pure.py` | L4 Structural | CrossHair PEP316 | S1–S7 |
| `verification/semantic_pure.py` | L5b Semantic | CrossHair PEP316 | M1–M9 |
| `verification/dafny/assess_consequence.dfy` | L3 Consequence | Dafny 4.x / Boogie + Z3 | POST-1–11a |
| `verification/dafny/structural_drift.dfy` | L4 Structural | Dafny 4.x | S1–S7 |
| `verification/dafny/temporal_drift.dfy` | L5a Temporal | Dafny 4.x | T1–T8 |
| `tests/proofs/test_crosshair_contracts.py` | All 4 layers | pytest wrapper | invokes CrossHair |
| `tests/proofs/test_z3_properties.py` | L3 Consequence | Z3 SMT | P1–P10 |

### eBPF agent (Go — L5c runtime)

| File | Role |
|---|---|
| `agent/main.go` | Entry point: flags, policy loading, map population, event loop |
| `agent/attach.go` | Attaches eBPF programs to kernel tracepoints via cilium/ebpf |
| `agent/events.go` | Event struct: `EventType`, `Pid`, `Comm`, `Detail`, `Blocked` |
| `agent/policy.go` | YAML egress allowlist loader |
| `agent/preflight.go` | Kernel cap check + canary load; graceful exit if tracepoints unavailable |
| `agent/bpf/probe.c` | 4 tracepoints: `trace_execve`, `trace_connect`, `trace_ptrace`, `trace_openat`; BPF maps: `pg_config` (block mode flag), `egress_allow_ipv4` (IPv4 allowlist) |

---

## Production Dependencies

### Python (`requirements.txt`)

| Package | Role |
|---|---|
| `GitPython >= 3.1.41` | Git repository access, diff extraction, merge-base resolution |
| `PyYAML >= 6.0` | Config file and workflow YAML parsing |
| `ruamel.yaml >= 0.18.0` | Round-trip YAML for auto-remediation (preserves comments) |
| `PyJWT[crypto] >= 2.8.0` | RS256 JWT signing for GitHub App authentication |
| `requests >= 2.31.0` | HTTP calls to GitHub API (Check Runs, remediation PRs) |
| `pytest >= 7.0` | Test runner |
| `z3-solver >= 4.12.0` | Z3 SMT solver for P1–P10 proof tests |
| `crosshair-tool >= 0.0.104` | CrossHair symbolic execution for C1–C12, T1–T7, S1–S7, M1–M9 |
| `pytest-timeout >= 2.0` | Per-test timeout enforcement in proof suite |
| `tree-sitter >= 0.21.0` | Core tree-sitter library (L4 structural parser) |
| `tree-sitter-python >= 0.21.0` | Python grammar |
| `tree-sitter-javascript >= 0.21.0` | JavaScript / JSX grammar |
| `tree-sitter-typescript >= 0.21.0` | TypeScript / TSX grammar |
| `tree-sitter-go >= 0.21.0` | Go grammar |
| `tree-sitter-rust >= 0.21.0` | Rust grammar |
| `tree-sitter-java >= 0.21.0` | Java grammar |

`anthropic` is commented out in `requirements.txt` — it was the PLI L4b dependency, reverted in v1.3.0.

### Python package metadata (`pyproject.toml`)

```
name: payloadguard-plg
version: 1.0.2
entry_point: payloadguard = "analyze:main"
py_modules: [analyze, structural_parser, post_check_run, remediate]
```

### Go (`agent/go.mod`)

```
module: github.com/payloadguard-plg/pg-agent
go: 1.24.0
```

| Dependency | Version | Role |
|---|---|---|
| `cilium/ebpf` | v0.21.0 | eBPF program loading, map access, perf reader |
| `golang.org/x/sys` | v0.37.0 | Low-level syscall bindings (memlock rlimit, netlink) |
| `gopkg.in/yaml.v3` | v3.0.1 | Policy YAML parsing |

---

## Full Pipeline Flow

### Entry points

**GitHub Action:** `action.yml` → `analyze.py main()` (Python) + `post_check_run.py main()` (Python)

**CLI:** `python analyze.py <repo_path> <branch> [target_branch] [--pr-description ...] [--save-json] [--save-markdown]`

**PyPI CLI:** `payloadguard <repo_path> <branch> [target_branch]`

---

### Step 0 — Configuration

```
load_config(repo_path)
  └── reads payloadguard.yml from repo root (optional)
  └── merges with DEFAULT_CONFIG
  └── returns PayloadGuardConfig dataclass
      ├── thresholds   (branch_age_days, files_deleted, lines_deleted, structural, temporal)
      ├── sca          (fail_on_unknown)
      ├── actions      (enabled, critical_signal_score, high_signal_score, trusted_oidc_consumers)
      └── semantic     (micro_scope_churn_limit, insertion_ratio_fix_threshold)
```

---

### Step 1 — Diff extraction

```
PayloadAnalyzer.analyze()
  ├── resolve branch ref + target ref via GitPython
  ├── compute merge_base (common ancestor)
  └── diffs = merge_base[0].diff(branch_ref)
      └── change_type ∈ {A=Added, D=Deleted, M=Modified, R=Renamed, C=Copied, T=TypeChanged}
```

---

### Step 2 — Layer 1: Surface analysis

```
  ├── files_added / files_deleted / files_modified / files_renamed / files_copied
  ├── lines_added / lines_deleted (via git diff --numstat; handles binary files correctly)
  ├── permission_changes  (mode changes on regular files)
  └── special_files       (symlinks, submodules detected by file mode bits)
```

---

### Step 3 — Layer 2: Forensic analysis

```
  ├── L2 Critical path
  │   ├── CRITICAL_PATH_PATTERNS regex matching on deleted file paths
  │   │     (auth, security, config, credentials, migrations, secrets)
  │   └── critical_file_deletions, security_file_deletions counts
  │
  ├── L2 Added file content scan  →  _scan_added_file_content(diffs)
  │   ├── non-workflow added/modified files only (workflows handled by L2c)
  │   ├── reads blob content, scans for CI trigger patterns + shell execution patterns
  │   └── content_flags count (+2/match, capped +4 in scoring)
  │
  ├── L2b SCA  →  _parse_added_packages(diff_text, manifest_type)
  │   ├── parses requirements.txt / package.json / go.mod diffs
  │   ├── loads allowlist.yml via _load_allowlist(repo_path)
  │   └── unverified_dependencies = packages in diff not in allowlist
  │
  └── L2c Actions poisoning  →  _scan_github_actions_poisoning(diffs)
      ├── iterates workflow files via _iter_workflow_file_diffs(diffs)
      │     (yields path, content, diff for A/M files matching .github/workflows/*)
      ├── normalizes content via _normalize_yaml_content(content)
      │     (collapses multiline YAML block scalars to single lines)
      └── signals detected:
          ├── base64_payload          CRITICAL  base64+shell pipe pattern
          ├── credential_harvest      CRITICAL  env exfil, cloud metadata, secret grep
          ├── pull_request_target_with_write_permissions  CRITICAL  pwn-request vector
          ├── oidc_elevation_typosquatted  CRITICAL  id-token:write + typosquatted consumer
          │     via _is_oidc_consumer_typosquatted()  (known-bad prefix list)
          ├── dormant_trigger_with_payload  HIGH  workflow_dispatch/schedule + shell exec
          ├── forged_bot_author       HIGH      git identity impersonating known bot
          ├── oidc_elevation_no_consumer  HIGH  id-token:write with no known OIDC consumer
          └── dangerous_trigger_pull_request_target  HIGH  pull_request_target alone
```

---

### Step 4 — Layer 4: Structural drift

```
  StructuralPayloadAnalyzer (per modified/renamed file)
  ├── structural_parser.language_for_path(path)     → language key or None (skip)
  ├── extract_named_nodes(original_source, path)    → set of named symbols (before)
  ├── extract_named_nodes(modified_source, path)    → set of named symbols (after)
  │     tree-sitter grammar per language:
  │     Python:     function_def, class_def, async_function_def, assignment, annotated_assignment
  │     JS/JSX:     function_declaration, class_declaration, arrow_function, variable_declarator
  │     TS/TSX:     + interface_declaration, type_alias_declaration, enum_declaration
  │     Go:         function_declaration, method_declaration, type_spec, const_spec
  │     Rust:       function_item, struct_item, enum_item, trait_item, const_item, static_item
  │     Java:       method_declaration, class_declaration, interface_declaration, enum_declaration
  ├── deleted_components = before_symbols − after_symbols
  ├── structural_deletion_ratio = deleted / before  (0.0–1.0)
  ├── severity gate: ratio > deletion_ratio_threshold AND count ≥ min_deletion_count → CRITICAL
  └── aggregate: overall_structural_severity = CRITICAL if any file is CRITICAL

  L4b Complexity advisory (informational, no score impact)
  └── McCabe V(G) for newly added Python functions: flags V(G) > complexity_threshold
```

---

### Step 5 — Layer 5a: Temporal drift

```
  TemporalDriftAnalyzer.analyze_drift()
  ├── branch_age_days = (now − branch_commit_datetime).days
  ├── target_commits_per_day = commits on target in last 90d / 90
  ├── drift_score = branch_age_days × target_commits_per_day
  └── status:
        CURRENT   drift_score < 250
        STALE     250 ≤ drift_score < 1000
        DANGEROUS drift_score ≥ 1000
```

---

### Step 6 — Layer 5b: Semantic transparency

```
  SemanticTransparencyAnalyzer.analyze_transparency()
  ├── Phase 1 — Linguistic Lexer
  │   └── classifies PR description: micro-scope language (fix/patch/update/minor/cleanup/typo…)
  ├── Phase 2 — Diff Profiler
  │   └── computes: churn, insertion_ratio, structural_additions, sensitive_files_touched, file_type_count
  └── Phase 3 — Cross-Correlation → mci_score ∈ [0,1]
        V_s: scope_understated       +0.4  micro-scope language + churn > 50 lines
        V_o: operation_mutation      +0.3  micro-scope language + structural additions in diff
        V_f: phantom_additions       +0.4  remedial claim + insertion ratio > 90%
        V_r: hidden_component_modification  +0.3  sensitive file not named in description
        V_e: cross_stack_micro_claim +0.2  micro-scope language + ≥3 distinct file types
      mci_score ≥ 0.5 → DECEPTIVE_PAYLOAD (escalates verdict)
      mci_score > 0   → CAUTION_MISMATCH
      no description  → UNVERIFIED
```

---

### Step 7 — Layer 5c: Runtime events (optional)

```
  _load_runtime_events()
  ├── reads $PG_RUNTIME_EVENTS env var (JSON lines from pg-agent)
  ├── each event: {event_type, pid, comm, detail, blocked}
  │     event_type ∈ {execve, egress_connect, ptrace_attach, procmem_open}
  └── injected into report as runtime_events[] (informational; no L3 score impact)

  Agent pipeline (L5c, separate process):
    pg-agent --mode=audit|block [--policy=policy.yaml]
    ├── preflight: checks CAP_SYS_ADMIN, loads canary BPF program
    ├── attach: loads probe.c object, attaches 4 tracepoints
    ├── main loop: reads perf ring buffer → JSON events to stdout
    └── block mode: bpf_send_signal(9) to block process on policy violation
```

---

### Step 8 — Layer 3: Consequence scoring

```
  PayloadAnalyzer._assess_consequence(
      files_deleted, lines_deleted, days_old, deletion_ratio,
      structural_severity, critical_file_deletions, security_file_deletions,
      unverified_dependencies, content_flags,
      actions_poisoning_flags, actions_poisoning_critical
  ) → {status, severity_score}

  Scoring (MAX_SCORE = 31):
  ┌─────────────────────────────────────────────────────┬────────┐
  │ Signal                                              │ Points │
  ├─────────────────────────────────────────────────────┼────────┤
  │ Branch age > 90 / 180 / 365 days                   │ +1/2/3 │
  │ Deletion dimension (files/ratio/lines — correlated) │ 0–4    │
  │   files deleted > 10 / 20 / 50                     │ +1/2/3 │
  │   deletion ratio > 50% / 70% / 90% (≥100 lines)   │ +1/2/3 │
  │   lines deleted > 5k / 10k / 50k                   │ +1/2/3 │
  │   cap: min(4, max + 1 if ≥2 non-zero)              │        │
  │ Structural severity CRITICAL                        │    +5  │
  │ Critical-path files deleted                         │    +2  │
  │ Security files deleted                              │    +5  │
  │ Unverified dependencies (SCA, per package)          │    +3  │
  │ Added file content flags (CI/shell, capped)         │  0–4   │
  │ Actions poisoning CRITICAL signal                   │    +5  │
  │ Actions poisoning HIGH signal                       │    +3  │
  └─────────────────────────────────────────────────────┴────────┘

  Verdict thresholds:
    score = 0        → SAFE        exit 0
    score 1–2        → REVIEW      exit 0
    score 3–4        → CAUTION     exit 0
    score ≥ 5        → DESTRUCTIVE exit 2

  Safety-critical floor (verified by Dafny POST-8/9/10):
    security_file_deletions > 0     → always DESTRUCTIVE
    structural_severity == CRITICAL → always DESTRUCTIVE
    actions_poisoning_critical      → always DESTRUCTIVE
```

---

### Step 9 — Report assembly and output

```
  PayloadAnalyzer.analyze() → report dict
  ├── branch, target, base_commit, branch_commit, days_old
  ├── file_counts: {added, deleted, modified, renamed, copied, total}
  ├── line_counts: {added, deleted, net}
  ├── deletion_ratio (float, 0–100)
  ├── permission_changes[], special_files[]
  ├── critical_file_deletions, security_file_deletions, deleted_critical_files[]
  ├── content_flags, content_flag_matches[]
  ├── sca: {unverified_dependencies, packages[]}
  ├── structural_flags[] (per-file: file, status, severity, metrics, deleted_components)
  ├── overall_structural_severity
  ├── complexity_advisory[]
  ├── temporal_drift: {status, drift_score, branch_age_days, target_commits_per_day}
  ├── semantic_transparency: {result, mci_score, signals[], label}
  ├── actions_poisoning: {signals[], has_critical, has_high, mutable_action_refs[]}
  ├── runtime_events[]
  ├── severity_score (int)
  ├── status (SAFE|REVIEW|CAUTION|DESTRUCTIVE)
  └── flags[] (human-readable signal strings)

  Output routing:
  ├── print_report(report)          → ANSI terminal report (stdout)
  ├── format_markdown_report(report) → Markdown string
  ├── save_json_report(report)      → consequence_report.json
  ├── save_markdown_report(report)  → payloadguard-report.md (or custom path)
  └── post_check_run.py main()      → GitHub Check Run via App JWT (RS256)
                                       PAYLOADGUARD_APP_ID + PAYLOADGUARD_PRIVATE_KEY
                                       + PAYLOADGUARD_INSTALLATION_ID
```

---

### AUDIT_LOG.md generation path

`AUDIT_LOG.md` is a **manually maintained** document — it is not generated by the analysis pipeline. It is the authoritative record of:

- Architectural review findings (INC-N series)
- Open defect findings (§N.N series)
- Per-harness test case status entries (WS-N, RT-N, RTA-N series)

**Who writes to it:** The developer or Claude Code session, after any of:
1. A new finding is identified during analysis or testing
2. A harness regression run reveals a verdict mismatch
3. A fix is applied to a known finding (status updated to RESOLVED)
4. A new test case is added to the harness (new entry appended)

**When a verdict mismatch is found** (e.g., expected DESTRUCTIVE, got CAUTION):
```
  Observed in: test run output or harness regression report
       ↓
  Root cause: trace which signals fired vs expected in _assess_consequence()
       ↓
  Record in: AUDIT_LOG.md  (finding ID, branch, expected, actual, score breakdown, root cause)
       ↓
  Add to: Open Findings table in CLAUDE.md
       ↓
  Fix in: analyze.py (the relevant layer or signal)
       ↓
  Verify: python -m pytest test_analyzer.py tests/proofs/ -q  (273 pass, 7 skip)
       ↓
  Update: AUDIT_LOG.md (RESOLVED), CLAUDE.md (remove from Open Findings), DEVLOG.md (session entry)
```

---

## Formal Verification Summary

273 tests pass, 7 skipped. 11 Dafny postconditions verified across 3 files.

| Method | Coverage | Run command |
|---|---|---|
| CrossHair | C1–C12 (L3), S1–S7 (L4), T1–T7 (L5a), M1–M9 (L5b) | `cd verification && crosshair check <module> --analysis_kind PEP316 --per_condition_timeout 30` |
| Z3 SMT | P1–P10 (L3) | `pytest tests/proofs/ -m proof -v --timeout=30` |
| Dafny | POST-1–11a (L3), S1–S7 (L4), T1–T8 (L5a) | `dafny verify verification/dafny/assess_consequence.dfy` |
| pytest (unit) | 258 test cases across all layers | `python -m pytest test_analyzer.py -v` |
| pytest (proofs) | 15 proof-wrapper tests | `python -m pytest tests/proofs/ -v` |

Skipped tests (7): 4× `TestPostCheckRun` (requires App secrets), 3× `TestStructuralParserJSTS` (requires tree-sitter grammar packages).
