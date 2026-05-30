# PayloadGuard — Public Brief

**A pre-merge security gate for GitHub Pull Requests.**

---

## Problem

A branch held dormant for months lands as a "minor fix" and wipes critical infrastructure in a single merge. Existing CI checks validate *functionality* — they do not validate *intent*. PayloadGuard closes this gap by detecting destructive, deceptive, and malicious changesets before they reach the default branch.

Specific threat classes addressed:
- Mass deletion disguised as refactoring
- GitHub Actions workflow poisoning (credential harvesting, OIDC elevation, dormant triggers)
- Semantic mismatch between PR descriptions and actual diff content
- Structural gutting where function shells remain but implementations are removed
- Stale-branch attacks where branch age correlates with attacker dwell time

---

## Architecture

Nine independent analysis layers, each examining a different dimension of risk. A payload that evades one layer is exposed by the others.

```
PR Diff
  │
  ├─ L1  Surface Scan          — File/line delta, deletion ratios, binary files
  ├─ L2  Forensic Analysis     — Critical-path deletions, security-sensitive files
  ├─ L2b SCA                   — Dependency manifest scanning against allowlists
  ├─ L2c Actions Poisoning     — Workflow content: 6 signal classes, YAML normalisation
  ├─ L3  Consequence Model     — Weighted severity scoring → verdict
  ├─ L4  Structural Drift      — AST-level class/function/constant deletion detection
  ├─ L5a Temporal Drift        — Branch age × target velocity → staleness score
  ├─ L5b Semantic Transparency — PR description vs actual diff content (MCI heuristic)
  └─ L5c Runtime Agent         — eBPF tracepoints: execve, egress, ptrace, /proc/mem
```

Verdicts: **SAFE** · **REVIEW** · **CAUTION** · **DESTRUCTIVE**

Wire DESTRUCTIVE to branch protection rules. The merge button is disabled automatically.

---

## Formal Verification

The scoring logic is verified by three independent methods. A bug would have to produce a consistent false result across all three simultaneously.

| Method | Tool | Coverage |
|--------|------|----------|
| Dynamic symbolic execution | CrossHair (Z3-backed) | L3 (C1–C12), L4 (S1–S7), L5a (T1–T7), L5b (M1–M9) — 35 contracts |
| SMT proof | Z3 Solver | L3 scoring — 10 properties (P1–P10): monotonicity, ordering, bijection |
| Machine-checked proof | Dafny 4.9.1 + Boogie + Z3 | L3 (POST-1–12), L4 (S1–S7), L5a (T1–T8) — full input domain |

**Results:** 278 tests pass. 12 Dafny postconditions verified, 0 errors. Verification covers the entire input domain, not a bounded sample.

Key proven properties:
- Score is always bounded [0, 31] and non-negative
- Verdict-to-score mapping is a strict bijection (each verdict corresponds to exactly one score range)
- Empty inputs always produce SAFE (no false positives on empty PRs)
- Structural DESTRUCTIVE requires both deletion ratio AND count thresholds (dual-gate prevents false positives on tiny files)
- Zero-age branches never trigger temporal staleness
- Missing PR descriptions produce UNVERIFIED, never a false deception score

---

## Technology Stack

- **Core:** Python 3.11+, GitPython, PyYAML
- **AST parsing:** Tree-sitter (Python, JavaScript, TypeScript, Go, Rust, Ruby)
- **Formal verification:** CrossHair, Z3 Solver, Dafny 4.9.1
- **Runtime defence:** Go, cilium/ebpf, eBPF C (4 tracepoint probes)
- **Integration:** GitHub Actions composite action, GitHub App (Check Runs API)

---

## Test Coverage

- 278 functional and proof tests (pytest)
- 41 adversarial test cases across 9 categories in a dedicated test harness
- 5 red-team findings from live adversarial sessions — all addressed
- Automated regression runner with SQLite result ingestion and drift tracking

---

## Development Context

- **Timeline:** 3 months (March–May 2026)
- **Developer:** Solo — Steven Dark (Aberdeen, Scotland)
- **Method:** AI-directed development from a mobile device. Human designs, architects, documents, and researches. AI implements under direction.
- **Quality scores:** GitRoll 4.99/5.00 reliability, 4.99/5.00 security, 4.99/5.00 maintainability

---

## What This Demonstrates

1. **Security engineering depth** — nine independent detection layers covering supply-chain, structural, temporal, and semantic attack surfaces
2. **Formal methods competence** — three verification tools (CrossHair, Z3, Dafny) applied to security-critical scoring logic with full input-domain coverage
3. **Adversarial thinking** — 41 test cases including 14 evasion techniques and 5 red-team findings, all documented and addressed
4. **Architecture discipline** — layered, independently verifiable components with pure-function extraction for symbolic execution
5. **Responsible development** — detection patterns treated as sensitive material with controlled-disclosure methodology

---

## Contact

For private demonstration, collaboration, or employment enquiries: see the portfolio page or contact Steven Dark directly.
