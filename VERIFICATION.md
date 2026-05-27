# PayloadGuard — Formal Verification

PayloadGuard's Layer 3 scoring model (`_assess_consequence()`) is verified using two
orthogonal formal methods:

| Method    | Tool       | File                                    | What it proves |
|-----------|------------|-----------------------------------------|----------------|
| SMT proof | Z3 Solver  | `tests/proofs/test_z3_properties.py`   | P1–P10: symbolic properties of the signal→score→verdict mapping |
| Contracts | CrossHair  | `verification/consequence_pure.py`     | C1–C12: pre/post conditions on the scoring function implementation |

Both tools are run externally against the published source. Neither is run by the same
author as the production code during the same session — see `VERIFICATION_SPEC.md` for
the formal specification that external tools consume.

---

## CrossHair Contracts (C1–C12)

CrossHair uses its own Z3-backed engine to explore all inputs satisfying the
pre-conditions and verify that every post-condition holds on every execution path.
This is **dynamic symbolic execution** of the actual Python code, not an abstract model.

The verification target is `verification/consequence_pure.py` — a pure extraction of
`_assess_consequence()` with no `git.Repo` dependency (required because CrossHair cannot
symbolically construct `PayloadAnalyzer.__init__()` through GitPython subprocess calls).

### Pre-conditions (input domain)

| Pre  | Condition |
|------|-----------|
| P-01 | `files_deleted >= 0` |
| P-02 | `lines_deleted >= 0` |
| P-03 | `0.0 <= deletion_ratio <= 100.0` |
| P-04 | `critical_file_deletions >= 0` |
| P-05 | `security_file_deletions >= 0` |
| P-06 | `unverified_dependencies >= 0` |
| P-07 | `content_flags >= 0` |
| P-08 | `actions_poisoning_flags >= 0` |

### Post-conditions (invariants proven)

| Contract | Invariant | Security significance |
|----------|-----------|----------------------|
| C-01 | `verdict in {SAFE, REVIEW, CAUTION, DESTRUCTIVE}` | Verdict is always a valid enum value; no undefined state |
| C-02 | `severity_score >= 0` | Score never goes negative; no signal acts as a reducer |
| C-03 | `severity_score <= 31` | Score is bounded; no integer overflow or runaway accumulation |
| C-04 | `SAFE <-> severity_score < 1` | SAFE verdict is exact; cannot be produced by a non-zero score |
| C-05 | `REVIEW <-> 1 <= severity_score < 3` | REVIEW is a closed interval |
| C-06 | `CAUTION <-> 3 <= severity_score < 5` | CAUTION is a closed interval |
| C-07 | `DESTRUCTIVE <-> severity_score >= 5` | DESTRUCTIVE verdict is exact |
| C-08 | `security_file_deletions > 0 -> DESTRUCTIVE` | Deleting any auth/security file always triggers DESTRUCTIVE |
| C-09 | `structural_severity == CRITICAL -> DESTRUCTIVE` | Structural CRITICAL always triggers DESTRUCTIVE |
| C-10 | `actions_poisoning_critical -> DESTRUCTIVE` | Critical workflow poisoning always triggers DESTRUCTIVE |
| C-11 | `all-zero inputs -> SAFE` | Empty PRs never produce a false positive |
| C-12 | `deletion_dim in [0, 4]` | The aggregated deletion dimension is always capped at 4 |

---

## How to Run Verification

### CrossHair (contract verification)

```bash
# From the project root:
cd verification

# Full module check (all contracts)
crosshair check consequence_pure --analysis_kind PEP316 \
    --per_condition_timeout 30 --max_uninteresting_iterations 10

# Target specific functions
crosshair check consequence_pure._compute_deletion_dim
crosshair check consequence_pure.assess_consequence_pure

# Via pytest (faster, regression-oriented, ~10s)
pytest tests/proofs/test_crosshair_contracts.py -m crosshair -v
```

Expected output: exit code 0, no stdout. Counterexamples are reported on stdout with
the specific input values and the violated contract.

### Z3 SMT Proofs

```bash
pytest tests/proofs/test_z3_properties.py -m proof -v --timeout=30
```

### Full verification suite

```bash
pytest tests/proofs/ -v --timeout=60
```

---

## Architecture: Why Two Verification Layers?

**Z3 proofs (`tests/proofs/test_z3_properties.py`)** work on an *abstract model* of the
scoring function — they encode the scoring logic as Z3 integer constraints and prove
properties about the constraint system. They are fast (< 0.1 s per proof) and prove
properties that are hard to express as function contracts (e.g., monotonicity across all
signal combinations, structural ordering of severity levels).

**CrossHair contracts (`verification/consequence_pure.py`)** work on the *actual Python
implementation*. CrossHair symbolically executes the code itself, not a model of it.
This catches a class of bugs that Z3 proofs miss: implementation divergence from the
model (e.g., an off-by-one in a threshold, a missing `elif`, a wrong operator).

The two layers are **orthogonal**:

- Z3 can prove a property about the model even if the Python code is wrong.
- CrossHair can verify the Python code even if no Z3 model exists for that property.

Together they provide defence-in-depth: a scoring change would have to simultaneously
fool both the abstract Z3 model and the concrete CrossHair analysis to pass undetected.

---

## Sync Requirement

`verification/consequence_pure.py` is an intentional mirror of
`analyze.py::PayloadAnalyzer._assess_consequence()`. When the scoring logic changes:

1. Update `consequence_pure.py` to match.
2. Run `cd verification && crosshair check consequence_pure` to verify contracts still hold.
3. If a contract is violated by the new logic, either fix the implementation or update
   the contract (with explicit justification in the PR description).

The contracts are the specification. If the code violates a contract, that is a bug,
not a contract update.

---

## What Is NOT Verified

- **Config-driven threshold overrides:** `consequence_pure.py` uses default thresholds.
  If a user configures `branch_age_days: [30, 60, 90]`, the contracts do not cover that
  scenario.
- **L4 structural analysis:** `structural_severity` is a string input; the logic for
  computing that string (AST analysis) is not verified here.
- **L5 temporal/semantic layers:** These modify the verdict post-hoc; their own logic
  is not formally verified.
- **Runtime behaviour under concurrent access:** CrossHair does not model threads.
- **`actions_cfg` config override for signal scores:** The production code reads
  `critical_signal_score` and `high_signal_score` from `self.config.actions`.
  `consequence_pure.py` uses the hardcoded defaults (5 and 3). If overridden, the
  contracts do not apply to those paths.

Full scope boundaries are documented in `VERIFICATION_SPEC.md`, Section 6.
