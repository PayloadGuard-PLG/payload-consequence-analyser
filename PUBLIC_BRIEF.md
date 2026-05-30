# PayloadGuard — Public Brief

**Author:** Steven Dark | Systems Architect & Security Researcher | Aberdeen, Scotland

---

## Problem

Pull request-based supply chain attacks against CI/CD infrastructure represent a growing and under-addressed threat category. Attack vectors include:

- **GitHub Actions poisoning** — injecting malicious workflow modifications that execute during CI
- **Credential harvesting** — exfiltrating secrets via encoded payloads in workflow steps
- **OIDC elevation** — escalating permissions through `id-token: write` grants to untrusted actions
- **Semantic mismatch** — PR descriptions that claim "minor fix" while the diff performs mass deletion or structural gutting

These attacks exploit the trust boundary at the merge gate: the moment a reviewer approves and merges is the moment malicious payloads execute with full CI/CD permissions.

---

## Approach

PayloadGuard implements a nine-layer analysis pipeline that inspects every pull request before merge:

| Layer | Function |
|-------|----------|
| L1 Surface Scan | File counts, line counts, permission changes, symlink detection |
| L2 Forensic Analysis | Critical path regex matching on deleted files, added file content scanning |
| L2b SCA | Dependency manifest scanning against allowlists |
| L2c Actions Poisoning | Workflow file analysis: base64 payloads, credential harvest, OIDC elevation, dormant triggers, typosquatted action consumers |
| L3 Consequence Model | Severity scoring and verdict classification (SAFE → DESTRUCTIVE) |
| L4 Structural Drift | AST-level detection of deleted classes, functions, and constants across Python, JavaScript, TypeScript, Go, Rust, Ruby |
| L5a Temporal Drift | Branch age and target branch velocity risk scoring |
| L5b Semantic Transparency | PR description vs. diff consistency analysis (MCI heuristic engine) |
| L5c Runtime Agent | eBPF tracepoint monitoring — execve, connect, ptrace, procmem — with audit and block modes |

Each layer operates independently. The Consequence Model (L3) aggregates signals into a final verdict: **SAFE**, **REVIEW**, **CAUTION**, or **DESTRUCTIVE**. A DESTRUCTIVE verdict blocks the merge via GitHub Check Run.

---

## Verification

PayloadGuard's scoring and classification logic is verified by three orthogonal proof systems:

### CrossHair Symbolic Execution
Symbolic execution over the Python source code. Contracts verify properties of the actual implementation — not a model or abstraction.
- **L3 Consequence Model:** C1–C12 (verdict bijection, score bounds, safety implications)
- **L4 Structural Drift:** S1–S7 (dual-gate biconditional — DESTRUCTIVE requires both ratio AND count)
- **L5a Temporal Drift:** T1–T7 (drift score non-negativity, status bijection, zero-input guarantees)
- **L5b Semantic Transparency:** M1–M9 (MCI score ∈ [0,1], deceptive classification threshold, no-description handling)

### Z3 SMT Proofs
Abstract model of the scoring logic verified via satisfiability checking. Ten properties (P1–P10) proven unsatisfiable (no counterexample exists).

### Dafny Machine-Checked Proofs
Reference implementation with postconditions verified over the entire input domain by the Dafny verifier (backed by Z3 4.12.1).
- **L3:** POST-1–11a (score bounds, verdict bijection, safety implications, empty-input guarantee)
- **L4:** S1–S7 (dual-gate biconditional)
- **L5a:** T1–T8 (linear drift, zero-input guarantees)

**Result:** 278 tests, 12 Dafny postconditions, 0 errors.

---

## Audit Methodology

Systematic six-category architectural audit:

1. **Detection gaps** — attack vectors not covered by any layer
2. **Brittle logic** — correct behaviour that depends on fragile assumptions
3. **Scoring model** — threshold calibration, signal weighting, cap interactions
4. **Available-but-unused** — data accessible to the analyser but not leveraged
5. **Security issues** — vulnerabilities in PayloadGuard itself
6. **Test coverage** — untested paths and edge cases

Each finding is classified by severity (HIGH / MEDIUM / LOW) and tracked in a public findings register (`AUDIT_LOG.md`). Findings are addressed through code changes with regression tests, or documented as accepted risks with rationale.

---

## What This Project Demonstrates

- **Systems architecture:** Nine independent analysis layers with clean separation of concerns, aggregated through a formally verified scoring model
- **Threat modelling from first principles:** Attack surface analysis of the GitHub PR merge gate, identifying vectors that existing tools do not address
- **Formal verification:** Three orthogonal proof systems (symbolic execution, SMT, machine-checked proofs) applied to a real security tool — not a toy example
- **Empirical rigour:** 278 tests, systematic adversarial testing (41 test cases across 5 tracks), public audit log with severity classification
- **Responsible disclosure:** Three-tier content classification ensuring detection patterns are shared appropriately
