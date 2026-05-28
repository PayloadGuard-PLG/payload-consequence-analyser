# PayloadGuard: Formal Verification Research Plan
**Objective:** Mathematically prove the correctness of PayloadGuard's core logic using SMT solvers and formal verification tools — producing proof artifacts that are independently auditable, citable, and bulletproof.

---

## Why This Matters

Test suites demonstrate the *presence* of correct behaviour. Formal verification proves the *absence* of incorrect behaviour. For a security gate tool, only the latter is sufficient. A formally verified PayloadGuard is a different category of claim entirely.

---

## Phase 1 — Foundations

**Goal:** Understand SMT solving and formal contracts. No code changes yet.

### 1.1 Learn Z3 Basics
Z3 is the SMT solver underpinning most Python verification tools. Start here before touching CrossHair or Nagini.

Resources:
- [Z3 Python API tutorial](https://microsoft.github.io/z3guide/programming/Z3%20Python%20-%20Axioms%20and%20Proofs/) — Microsoft's own guide
- [Z3Py by example](https://ericpony.github.io/z3py-tutorial/guide-examples.htm) — practical examples
- `pip install z3-solver`

First exercise: encode PayloadGuard's verdict thresholds directly in Z3 and prove they are exhaustive and non-overlapping.

```python
from z3 import *

score = Int('score')
s = Solver()

# Prove: every score maps to exactly one verdict
safe       = score == 0
review     = And(score >= 1, score <= 2)
caution    = And(score >= 3, score <= 4)
destructive = score >= 5

# Prove exhaustive: no score falls through
s.add(Not(Or(safe, review, caution, destructive)))
print(s.check())  # unsat = proven exhaustive
```

This is your first proof. Write it, run it, understand what `unsat` means.

### 1.2 Understand What You're Proving
Before annotating code, define the properties you want to hold. For PayloadGuard Layer 3:

- **Boundedness:** deletion_score is always in [0, 4]
- **Monotonicity:** higher deletion ratios never produce lower scores
- **Exhaustiveness:** every possible input maps to exactly one verdict
- **No silent failures:** no code path produces an undefined or null verdict

Write these as English statements first. They become your formal spec.

---

## Phase 2 — CrossHair on Layer 3

**Goal:** Add SMT-backed contracts to `analyze.py` and get CrossHair to verify them.

### 2.1 Install and run CrossHair

```bash
pip install crosshair-tool
crosshair check analyze.py
```

### 2.2 Add contracts to the scoring functions

CrossHair reads standard Python assertions and PEP 316-style docstring contracts. Add pre/post conditions to the consequence model functions:

```python
def compute_deletion_score(files_deleted: int, deletion_ratio: float, lines_deleted: int) -> int:
    """
    post: 0 <= __return__ <= 4
    post: __return__ >= 0
    """
    ...
```

Start with the simplest provable claim: the deletion score cap. Prove it holds for all inputs before moving to more complex properties.

### 2.3 Iterate until CrossHair finds no counterexamples

CrossHair will either:
- Find a counterexample (a bug — fix it)
- Exhaust the search space (proof)

Document every counterexample found. Each one is a finding.

### 2.4 Target functions in order

| Function | Property to prove |
|---|---|
| `compute_deletion_score` | Output always in [0, 4] |
| `compute_verdict` | Every score maps to exactly one verdict |
| `compute_temporal_score` | Branch age tiers are exhaustive |
| Full scoring pipeline | DESTRUCTIVE verdict is never suppressed by a single flag |

---

## Phase 3 — Nagini for Stronger Guarantees

**Goal:** Full pre/post condition verification with loop invariants using Nagini.

Nagini uses the Viper verification infrastructure (ETH Zürich) with Z3 as the backend. It produces formal proofs, not just counterexample searches.

### 3.1 Install Nagini

```bash
pip install nagini
```

Nagini requires Java 11+ and the Viper backend. Installation is more involved than CrossHair — follow the [Nagini README](https://github.com/marcoeilers/nagini) carefully.

### 3.2 Annotate the scoring module

Nagini uses Python type annotations extended with verification contracts:

```python
from nagini_contracts.contracts import *

def compute_verdict(score: int) -> str:
    Requires(score >= 0)
    Ensures(Result() in ['SAFE', 'REVIEW', 'CAUTION', 'DESTRUCTIVE'])
    ...
```

### 3.3 Prove loop termination in structural drift (Layer 4)

The AST traversal in structural drift analysis contains loops over file nodes. Nagini can prove these terminate and don't silently skip nodes. This is a stronger claim than test coverage.

---

## Phase 4 — Dafny Reference Specification

**Goal:** A formally verified reference implementation of the PayloadGuard scoring model that the Python code is provably consistent with.

Dafny is a verification-aware language that compiles to verified code. You write the spec and the implementation together; the compiler proves they match.

### 4.1 Why Dafny

- 82% vericoding success rate with LLMs (from the benchmark paper) — you can use LLM assistance on Dafny code without circular trust issues, because the *verifier* is the proof, not the LLM
- Produces a formal proof artifact that is language-independent
- Citable in a paper

### 4.2 Scope

Implement only the consequence model (Layer 3) in Dafny. Not the full tool — just the scoring logic. This is ~100 lines of Python translated into a formally verified spec.

```dafny
method ComputeVerdict(score: int) returns (verdict: string)
  requires score >= 0
  ensures verdict == "SAFE" || verdict == "REVIEW" || 
          verdict == "CAUTION" || verdict == "DESTRUCTIVE"
  ensures score == 0 ==> verdict == "SAFE"
  ensures score >= 5 ==> verdict == "DESTRUCTIVE"
{
  ...
}
```

### 4.3 The proof artifact

The Dafny verifier producing `Verification successful` on this file is a machine-checkable proof. It can be committed to the repo, linked from the README, and cited in a paper.

---

## Phase 5 — Documentation and Publication

**Goal:** Turn the verification work into a citable public artifact.

### 5.1 Repo structure

```
/verification/
  z3_proofs/          — Phase 1 Z3 scripts, documented
  crosshair/          — Annotated analyze.py with contracts
  nagini/             — Nagini-annotated scoring module
  dafny/              — Reference specification
  VERIFICATION.md     — What was proven, how, and what it means
```

### 5.2 VERIFICATION.md

A plain-English document explaining:
- What properties are proven
- What tool proved them and why that tool is trustworthy
- What is *not* proven (honest scope)
- How to reproduce the proofs

This is what a hiring manager, researcher, or peer reviewer reads. The proof files are the evidence behind it.

### 5.3 Alignment Forum post

The combination of:
- PLI methodology (behavioral auditing)
- Deterministic detection (PayloadGuard)
- Formally verified scoring model

...is a coherent, novel research program. The verification work completes the argument that this is not vibe-coded tooling but a rigorous safety infrastructure.

---

## Toolchain Summary

| Tool | Role | Backend | Difficulty |
|---|---|---|---|
| Z3 (z3-solver) | Direct SMT proofs | Z3 | Low — start here |
| CrossHair | Contract verification on existing Python | Z3 | Medium |
| Nagini | Full formal verification with invariants | Viper + Z3 | High |
| Dafny | Verified reference specification | Z3 | Medium (good LLM support) |

---

## What You Can Claim When This Is Done

> "PayloadGuard's scoring model is formally verified. The verdict logic is proven exhaustive and non-overlapping across all possible inputs using Z3. The deletion score cap is proven to hold for all inputs. These are machine-checkable proofs, not test results. The verification artifacts are publicly available and reproducible."

That is a different beast altogether.

---


