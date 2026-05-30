# PayloadGuard — Public Brief

A PR analysis tool that catches destructive, deceptive, and malicious changesets before they reach main.

**Author:** Steven Dark | Systems Architect & Security Researcher | Aberdeen, Scotland

---

## Problem

Pull request-based supply chain attacks against CI/CD infrastructure are a growing and under-addressed threat class. A malicious contributor opens a PR described as a "minor fix" — but the diff deletes critical files, injects credential-harvesting workflows, escalates OIDC permissions, or guts the codebase through targeted structural removal.

Current CI tooling focuses on linting, testing, and dependency scanning. None of it answers the question: **does this PR do what it claims to do, and is the change itself safe to merge?**

Specific attack vectors PayloadGuard addresses:

- **GitHub Actions poisoning** — base64 payload delivery, credential harvesting via metadata endpoints, dormant triggers (workflow_dispatch + schedule), forged bot commit identity, OIDC token escalation, unsafe `pull_request_target` usage.
- **Mass codebase deletion** — PRs that remove entire application architectures while the description says "syntax fix."
- **Semantic mismatch** — PR descriptions that claim additive work (adding features) while the diff is purely destructive (removing code).
- **Structural gutting** — targeted removal of named classes, functions, and constants detected via AST-level diffing.
- **Stale branch exploitation** — branches held open for months, accumulating drift from the target branch, then merged as a "quick update."

---

## Approach — Nine-Layer Analysis Pipeline

Each layer examines an independent dimension of risk. A payload that evades one layer is still exposed by the others.

| Layer | Name | What It Examines |
|---|---|---|
| **L1** | Surface Scan | File and line counts, deletion ratios, binary files, permission changes, symlinks |
| **L2** | Forensic Analysis | Critical-path deletions (auth, config, CI files), security-sensitive file removal, added file content scanning |
| **L2b** | SCA | Package manifest diffs against an allowlist for unverified dependencies |
| **L2c** | Actions Poisoning | Added/modified workflow files scanned for poisoning signals |
| **L3** | Consequence Model | Weighted scoring across all signals — produces single verdict: SAFE / REVIEW / CAUTION / DESTRUCTIVE |
| **L4** | Structural Drift | AST-level diff — which named classes, functions, and constants were actually deleted |
| **L5a** | Temporal Drift | Branch age relative to target repo velocity — a quantified staleness score |
| **L5b** | Semantic Transparency | Whether the PR description matches what the diff actually does (PR-MCI heuristic engine) |
| **L5c** | Runtime Agent | eBPF tracepoints on the CI runner: execve, egress connect, ptrace, /proc/mem — audit or block mode |

The analyser runs as a GitHub Action on every PR. DESTRUCTIVE verdicts fail the check and block the merge button via branch protection rules.

---

## Verification — Three Orthogonal Proof Systems

The scoring logic (L3, L4, L5a, L5b) is verified by three independent methods. A bug would have to produce a consistent false result across all three simultaneously to go undetected.

| Method | Tool | What It Proves |
|---|---|---|
| **Symbolic Execution** | CrossHair (Python, Z3-backed) | Dynamic symbolic execution of the actual Python source — explores all inputs satisfying pre-conditions and verifies all post-conditions hold. 35 contracts across 4 layers (C1-C12, S1-S7, T1-T7, M1-M9). |
| **SMT Proofs** | Z3 Solver | 10 properties (P1-P10) on an abstract model of the scoring logic — monotonicity, ordering, verdict bijection. All `unsat` (proven) in <0.1s. |
| **Machine-Checked Proofs** | Dafny 4.9.1 (with Z3 4.12.1) | Reference implementation verified over the entire input domain. 12 postconditions across L3 (POST-1-12), L4 (S1-S7), L5a (T1-T8). Zero errors. |

**Total:** 278 tests pass. 12 Dafny postconditions verified. 0 errors.

Verification targets are pure-Python mirrors of the production code — no GitPython, no AST parsing, no file I/O. This isolates the mathematical scoring logic from external dependencies.

Full specification: [`VERIFICATION.md`](VERIFICATION.md) | [`VERIFICATION_SPEC.md`](VERIFICATION_SPEC.md)

---

## Audit Methodology

Systematic 6-category architectural audit with a public findings register.

| Category | What Is Checked |
|---|---|
| Detection gaps | Missing signal collection — cases where a destructive changeset would not register |
| Brittle logic | Edge cases that crash or misbehave rather than degrading gracefully |
| Scoring model | Whether the score accurately reflects risk, without double-counting or blindspots |
| Available-but-unused | Capabilities in the dependency graph that could improve signal quality |
| Security issues | Input validation, filesystem access, credential handling, injection paths |
| Test coverage | Which code paths have no automated coverage |

Severity framework: **HIGH** (exploitable or produces wrong verdicts), **MEDIUM** (degrades reliability with unusual input), **LOW** (cosmetic or advisory).

All findings, their severity, fix status, and resolving commits are recorded in the public [`AUDIT_LOG.md`](AUDIT_LOG.md). The methodology is documented step-by-step so a new reviewer can reproduce the same coverage without reading the entire codebase.

---

## What This Demonstrates

| Capability | Evidence |
|---|---|
| **Systems architecture** | Nine-layer pipeline with independent signal extraction, weighted scoring, and formal verdict boundaries |
| **Threat modeling from first principles** | Attack vectors derived from analysis of real CI/CD supply chain incidents, not copied from existing tools |
| **Formal verification** | Three orthogonal proof systems applied to production security logic — not academic exercises |
| **Empirical rigor** | 278 automated tests, 41-case adversarial test harness with regression runner, live red-team exercises |
| **Security engineering** | eBPF kernel-level runtime agent, AST-aware structural analysis, semantic mismatch detection |
| **Documentation discipline** | Architecture whitepaper, verification spec, audit log, calibration records — all maintained and current |

---

## Classification

This brief contains **Tier 1 (Fully Public)** content only. Specific detection patterns, red team bypass details, and open findings are classified under Tier 2 (Selective) and Tier 3 (Private). See [`DISCLOSURE_STRATEGY.md`](DISCLOSURE_STRATEGY.md) for the full classification framework.

---

*Built solo, from a phone, using AI-directed development. Three months. No team, no IDE, no desktop.*
