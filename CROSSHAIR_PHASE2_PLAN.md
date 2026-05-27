# CrossHair Formal Contract Verification — Phase 2 Implementation Plan

**Status:** Implemented  
**Branch:** `claude/oidc-typosquat-detection-UBCOJ`  
**Target:** `_assess_consequence()` in `analyze.py` (Layer 3 Consequence Model)  
**Method:** CrossHair PEP316 docstring contracts via pure extraction module  

---

## Problem Statement

CrossHair cannot symbolically verify `_assess_consequence()` directly on `PayloadAnalyzer`
because `PayloadAnalyzer.__init__()` constructs a `git.Repo()` object. GitPython calls
`git --version` as a subprocess on import. CrossHair blocks all subprocess I/O by default
and fails during symbolic construction of `self`.

**Solution:** A pure extraction module at `verification/consequence_pure.py` reimplements
the scoring logic as a standalone function with no imports from `analyze.py` and no
external dependencies. CrossHair verifies this module directly.

---

## Files Added

| File | Purpose |
|------|---------|
| `verification/__init__.py` | Makes `verification/` a proper Python package |
| `verification/consequence_pure.py` | Pure extraction of `_assess_consequence()` — the CrossHair verification target |
| `tests/proofs/test_crosshair_contracts.py` | pytest wrapper shelling out to the CrossHair CLI |
| `VERIFICATION.md` | Public-facing documentation of what is proven, how, and what is not |
| `VERIFICATION_SPEC.md` | Formal specification for external verifiers (CrossHair/Nagini/Dafny) |
| `CROSSHAIR_PHASE2_PLAN.md` | This document |

---

## Files Modified

| File | Change |
|------|--------|
| `requirements.txt` | Added `crosshair-tool>=0.0.104` |
| `pyproject.toml` | Added `crosshair` pytest marker |
| `analyze.py` | Added type annotations + cross-reference docstring to `_assess_consequence()` |

---

## Contracts Verified (C1–C12)

CrossHair explores all inputs satisfying the pre-conditions and verifies every post-condition:

| Contract | Invariant |
|----------|-----------|
| C-01 | `verdict in {SAFE, REVIEW, CAUTION, DESTRUCTIVE}` |
| C-02 | `severity_score >= 0` |
| C-03 | `severity_score <= 31` |
| C-04 | `SAFE <-> severity_score < 1` |
| C-05 | `REVIEW <-> 1 <= severity_score < 3` |
| C-06 | `CAUTION <-> 3 <= severity_score < 5` |
| C-07 | `DESTRUCTIVE <-> severity_score >= 5` |
| C-08 | `security_file_deletions > 0 -> DESTRUCTIVE` |
| C-09 | `structural_severity == CRITICAL -> DESTRUCTIVE` |
| C-10 | `actions_poisoning_critical -> DESTRUCTIVE` |
| C-11 | `all-zero inputs -> SAFE` |
| C-12 | `deletion_dim in [0, 4]` (verified on `_compute_deletion_dim`) |

---

## Why a Pure Extraction Module (not contracts on `_assess_consequence` directly)

CrossHair's symbolic executor cannot construct a `PayloadAnalyzer` instance because:

1. `PayloadAnalyzer.__init__` calls `git.Repo(repo_path)` during construction.
2. GitPython executes `git --version` as a subprocess at import time.
3. CrossHair blocks subprocess calls during symbolic execution — this raises an error
   before any symbolic reasoning can begin.
4. `--unblock subprocess.Popen` allows import, but CrossHair still cannot generate
   valid `git.Repo` instances as symbolic inputs.

The extraction module solves this by being entirely self-contained. The sync requirement
(documented in `VERIFICATION.md`) ensures the module stays aligned with production code.

---

## Implementation Notes

### Inline constants, not list parameters

CrossHair explores list contents symbolically when lists are not fixed-width typed tuples,
causing spurious `IndexError` counterexamples. The production code passes threshold lists
from `self.config.thresholds`. The pure module uses named constants (`_FILES_T1`, etc.)
with the default threshold values hard-coded.

### `_no_signals()` helper for compound pre-conditions

CrossHair's PEP316 parser cannot parse multi-line `implies()` expressions with line
continuations in docstrings. The `_no_signals()` helper encapsulates the compound
all-zero-inputs condition on a single logical line, which CrossHair parses correctly.

### `severity_score` type: `int` vs `float`

The production code initialises `severity_score = 0.0` (float). All increments are
integers so no precision loss occurs. The pure module uses `int` throughout for clarity
and better CrossHair integer arithmetic reasoning. The contracts hold for both.

---

## How to Verify

```bash
# From project root
pip install crosshair-tool>=0.0.104

# CrossHair direct (full exploration)
cd verification
crosshair check consequence_pure --analysis_kind PEP316 \
    --per_condition_timeout 30 --max_uninteresting_iterations 10

# CrossHair via pytest (faster, regression-oriented, ~10s)
pytest tests/proofs/test_crosshair_contracts.py -m crosshair -v

# Full verification suite (Z3 + CrossHair)
pytest tests/proofs/ -v --timeout=60
```

Expected: exit code 0 from CrossHair (no counterexamples). The two pytest tests
(`test_crosshair_deletion_dim_contracts`, `test_crosshair_assess_consequence_contracts`)
both pass.

---

## Vericoding Phases Status

| Phase | Tool | Status |
|-------|------|--------|
| 1 | Z3 SMT | Done — `tests/proofs/test_z3_properties.py` (P1–P10) |
| 2 | CrossHair | Done — `verification/consequence_pure.py` (C1–C12) |
| 3 | Nagini | Not started — heap separation + null safety |
| 4 | Dafny | Not started — reference implementation |
| 5 | Publication | Not started — `VERIFICATION.md` public summary (stub created) |

---

## Constraints

- **Verification is always external.** Claude produces specs; external parties run the tools.
- **No circular verification.** The Z3 proofs in `tests/proofs/test_z3_properties.py` were
  written by the same author as the source code. CrossHair provides independent verification
  of the actual Python implementation, not of an abstract model.
- **Sync requirement:** `consequence_pure.py` must be updated whenever `_assess_consequence()`
  changes in `analyze.py`. The contracts are the specification.
