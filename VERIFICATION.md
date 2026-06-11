# PayloadGuard — Formal Verification

Three orthogonal verification methods cover the pure scoring logic across four analysis layers.

### CrossHair Symbolic Execution (Phase 2)

| Layer | Function | Module | Contracts |
|-------|----------|--------|-----------|
| L3 Consequence | `_assess_consequence()` | `verification/consequence_pure.py` | C1–C13 |
| L4 Structural | `analyze_structural_drift()` | `verification/structural_pure.py` | S1–S7 |
| L5a Temporal | `analyze_drift()` | `verification/temporal_pure.py` | T1–T7 |
| L5b Semantic | `analyze_transparency()` phase 3 | `verification/semantic_pure.py` | M1–M9 |

### Z3 SMT Proofs (Phase 1)

| Method | Tool | File | What it proves |
|--------|------|------|----------------|
| SMT proof | Z3 Solver | `tests/proofs/test_z3_properties.py` | P1–P10: signal→score→verdict properties (monotonicity, ordering, bijection) |

### Dafny Machine-Checked Proofs (Phase 4)

| Layer | Dafny method | File | Postconditions |
|-------|-------------|------|----------------|
| L3 Consequence | `AssessConsequence` | `verification/dafny/assess_consequence.dfy` | POST-1–12 (score bounds, verdict bijection, safety implications, empty-input guarantee) |
| L4 Structural | `AssessStructuralDrift` | `verification/dafny/structural_drift.dfy` | S1–S7 (dual-gate biconditional) |
| L5a Temporal | `AnalyzeTemporalDrift` | `verification/dafny/temporal_drift.dfy` | T1–T8 (linear drift, zero-input guarantees) |

Dafny translates each annotated method into Boogie verification conditions and discharges
them with Z3. Verification covers the entire input domain, not a bounded sample.
The `.dfy` files plus committed verifier logs are the citable proof artifacts.

All verification tools are run externally against the published source. See `VERIFICATION_SPEC.md`
for the formal specification that external tools consume.

---

## CrossHair Contracts

CrossHair uses its own Z3-backed engine to explore all inputs satisfying the pre-conditions
and verify that every post-condition holds on every execution path. This is **dynamic
symbolic execution** of the actual Python code, not an abstract model.

**Why pure extraction modules?** CrossHair cannot symbolically construct `PayloadAnalyzer`
because `__init__()` calls `git.Repo()` which runs `git --version` as a subprocess.
Each `verification/*.py` module is a self-contained pure-Python mirror of its target —
no GitPython, no AST parsing, no file I/O.

---

### Layer 3 — Consequence Scoring (C1–C13)

**Target:** `PayloadAnalyzer._assess_consequence()` → `verification/consequence_pure.py`

**Pre-conditions:**

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
| P-09 | `ai_config_poisoning_flags >= 0` |

**Contracts:**

| Contract | Invariant | Security significance |
|----------|-----------|----------------------|
| C-01 | `verdict in {SAFE, REVIEW, CAUTION, DESTRUCTIVE}` | Verdict is always a valid enum value |
| C-02 | `severity_score >= 0` | Score never goes negative |
| C-03 | `severity_score <= 36` | Score is bounded; no runaway accumulation |
| C-04 | `SAFE <-> severity_score < 1` | SAFE is exact; cannot be produced by a non-zero score |
| C-05 | `REVIEW <-> 1 <= severity_score < 3` | REVIEW is a closed interval |
| C-06 | `CAUTION <-> 3 <= severity_score < 5` | CAUTION is a closed interval |
| C-07 | `DESTRUCTIVE <-> severity_score >= 5` | DESTRUCTIVE is exact |
| C-08 | `security_file_deletions > 0 -> DESTRUCTIVE` | Any auth/security file deletion → DESTRUCTIVE |
| C-09 | `structural_severity == CRITICAL -> DESTRUCTIVE` | Structural CRITICAL → DESTRUCTIVE |
| C-10 | `actions_poisoning_critical -> DESTRUCTIVE` | Critical workflow poisoning → DESTRUCTIVE |
| C-11 | `all-zero inputs -> SAFE` | Empty PRs never produce a false positive |
| C-12 | `deletion_dim in [0, 4]` | Aggregated deletion dimension always capped at 4 |
| C-13 | `ai_config_poisoning_critical -> DESTRUCTIVE` | Critical AI config poisoning → DESTRUCTIVE |

---

### Layer 4 — Structural Dual-Gate (S1–S7)

**Target:** `StructuralPayloadAnalyzer.analyze_structural_drift()` → `verification/structural_pure.py`

AST parsing (`structural_parser.extract_named_nodes`) is external I/O. The module receives
pre-computed node counts and verifies the classification logic only.

**Pre-conditions:**

| Pre | Condition |
|-----|-----------|
| P-01 | `original_count >= 0` |
| P-02 | `0 <= deleted_count <= original_count` |
| P-03 | `0.0 < deletion_ratio_threshold < 1.0` |
| P-04 | `min_deletion_count >= 1` |

**Contracts:**

| Contract | Invariant | Security significance |
|----------|-----------|----------------------|
| S-01 | `status in {DESTRUCTIVE, SAFE}` | No undefined structural verdict |
| S-02 | `0.0 <= deletion_ratio <= 1.0` | Ratio is always a valid proportion |
| S-03 | `DESTRUCTIVE -> deletion_ratio > threshold` | Ratio gate is always required |
| S-04 | `DESTRUCTIVE -> deleted_count >= min_deletion_count` | Count gate is always required |
| S-05 | `deleted_count == 0 -> SAFE` | No deletions → never DESTRUCTIVE |
| S-06 | `original_count == 0 -> SAFE` | Empty file → never DESTRUCTIVE |
| S-07 | `SAFE -> NOT (ratio > threshold AND count >= min)` | SAFE and DESTRUCTIVE are mutually exclusive |

The dual-gate invariant (S-03 + S-04 together) prevents false positives on tiny files
where a single deletion produces a high ratio.

---

### Layer 5a — Temporal Drift (T1–T7)

**Target:** `TemporalDriftAnalyzer.analyze_drift()` → `verification/temporal_pure.py`

**Pre-conditions:**

| Pre | Condition |
|-----|-----------|
| P-01 | `branch_age_days >= 0` |
| P-02 | `target_velocity >= 0.0` |
| P-03 | `warning_threshold > 0.0` |
| P-04 | `critical_threshold > warning_threshold` |

**Contracts:**

| Contract | Invariant | Security significance |
|----------|-----------|----------------------|
| T-01 | `status in {CURRENT, STALE, DANGEROUS}` | No undefined temporal verdict |
| T-02 | `drift_score >= 0.0` | Score is non-negative (product of two non-negative values) |
| T-03 | `DANGEROUS -> drift_score >= critical_threshold` | DANGEROUS verdict is always earned |
| T-04 | `STALE -> warning_threshold <= drift_score < critical_threshold` | STALE is a closed interval |
| T-05 | `CURRENT -> drift_score < warning_threshold` | CURRENT is the safe band |
| T-06 | `branch_age_days == 0 -> CURRENT` | New branches never trigger STALE or DANGEROUS |
| T-07 | `target_velocity == 0.0 -> CURRENT` | Zero-velocity repos never trigger staleness signals |

---

### Layer 5b — Semantic MCI Cross-Correlation (M1–M9)

**Target:** `SemanticTransparencyAnalyzer.analyze_transparency()` Phase 3 → `verification/semantic_pure.py`

Phases 1 (Linguistic Lexer) and 2 (Diff Profiler) involve regex, string operations, and
GitPython diff objects. This module takes their pre-computed outputs as flat boolean/integer
parameters and verifies the MCI aggregation and status classification logic.

The V_f signal (hidden_component_modification) involves path string matching against the PR
description — abstracted as `has_unacknowledged_sensitive: bool`.

**Pre-conditions:**

| Pre | Condition |
|-----|-----------|
| P-01 | `total_churn >= 0` |
| P-02 | `structural_alterations >= 0` |
| P-03 | `ext_count >= 0` |
| P-04 | `0.0 <= insertion_ratio <= 1.0` |
| P-05 | `churn_limit >= 0` |
| P-06 | `0.0 <= fix_ir_thresh <= 1.0` |
| P-07 | `not (is_micro and is_macro)` |

**Contracts:**

| Contract | Invariant | Security significance |
|----------|-----------|----------------------|
| M-01 | `status in {UNVERIFIED, TRANSPARENT, CAUTION_MISMATCH, DECEPTIVE_PAYLOAD}` | No undefined semantic verdict |
| M-02 | `0.0 <= mci_score <= 1.0` | Score is always a valid [0,1] value |
| M-03 | `not has_description -> status == UNVERIFIED` | Missing description always returns UNVERIFIED |
| M-04 | `not has_description -> mci_score == 0.0` | UNVERIFIED never carries a false MCI score |
| M-05 | `UNVERIFIED -> not has_description` | UNVERIFIED is only ever produced by missing description |
| M-06 | `mci_score >= 0.5 -> DECEPTIVE_PAYLOAD` | High deception score always escalates |
| M-07 | `DECEPTIVE_PAYLOAD -> mci_score >= 0.5` | DECEPTIVE_PAYLOAD is only produced by score ≥ 0.5 |
| M-08 | `TRANSPARENT -> mci_score == 0.0` | TRANSPARENT verdict always has zero MCI |
| M-09 | `TRANSPARENT -> not is_macro` | Macro-scope claims are never fully transparent |

---

## How to Run Verification

### CrossHair (all layers)

```bash
cd verification

crosshair check consequence_pure --analysis_kind PEP316 --per_condition_timeout 30
crosshair check structural_pure  --analysis_kind PEP316 --per_condition_timeout 30
crosshair check temporal_pure    --analysis_kind PEP316 --per_condition_timeout 30
crosshair check semantic_pure    --analysis_kind PEP316 --per_condition_timeout 30

# Via pytest (all 5 tests, ~8s)
pytest tests/proofs/test_crosshair_contracts.py -m crosshair -v
```

Expected: exit code 0, no stdout. Counterexamples are reported on stdout with the specific
input values and the violated contract.

### Z3 SMT Proofs (Layer 3)

```bash
pytest tests/proofs/test_z3_properties.py -m proof -v --timeout=30
```

### Dafny (Layers 3, 4, 5a)

```bash
# Install once
dotnet tool install --global dafny

# Verify each file
dafny verify verification/dafny/assess_consequence.dfy
dafny verify verification/dafny/structural_drift.dfy
dafny verify verification/dafny/temporal_drift.dfy
```

Expected: `Dafny program verifier finished with N verified, 0 errors` and exit code 0.
Also grep for `"0 errors"` to guard against the known dafny-lang/dafny#21 false-zero issue.

CI runs Dafny automatically on any PR touching `verification/dafny/**` via `.github/workflows/verify-dafny.yml`.

### Full Python verification suite

```bash
pytest tests/proofs/ -v --timeout=60
# Expected: 274 pass, 7 skip
```

---

## Architecture: Three Orthogonal Verification Layers

**Z3 proofs** operate on an *abstract model* — encoding the scoring logic as Z3 integer
constraints. Fast (< 0.1 s per proof), they prove properties hard to express as function
contracts: monotonicity, structural ordering across severity levels.

**CrossHair contracts** operate on the *actual Python implementation*. CrossHair symbolically
executes the code itself, not a model. This catches implementation divergence from the
model — off-by-one thresholds, missing `elif` branches, wrong operators.

**Dafny proofs** operate on a *Dafny reference implementation* of the scoring logic.
Dafny translates the annotated method into Boogie verification conditions and discharges
them with Z3 over the entire input domain. The resulting `.dfy` file and verifier output
are the peer-reviewable proof artifacts.

The three layers are **independent**: each uses a different representation of the scoring
function (abstract model, Python source, Dafny spec). A scoring change would have to
produce a consistent error across all three simultaneously to pass undetected.

---

## Sync Requirement

Each `verification/*.py` module is an intentional mirror of its production counterpart.
When scoring logic changes in `analyze.py`:

1. Update the corresponding `verification/*.py` module to match.
2. Run `crosshair check <module>` from `verification/` to confirm contracts still hold.
3. If a contract is violated, either fix the implementation or update the contract with
   explicit justification in the PR description.

**The contracts are the specification.** A contract violation is a bug, not a contract update.

| Module | Mirrors |
|--------|---------|
| `consequence_pure.py` | `PayloadAnalyzer._assess_consequence()` |
| `structural_pure.py` | `StructuralPayloadAnalyzer.analyze_structural_drift()` |
| `temporal_pure.py` | `TemporalDriftAnalyzer.analyze_drift()` |
| `semantic_pure.py` | `SemanticTransparencyAnalyzer.analyze_transparency()` Phase 3 |

---

## What Is NOT Verified

- **Config-driven threshold overrides:** verification modules use default thresholds.
  User-configured overrides (e.g. `branch_age_days: [30, 60, 90]`) are not covered.
- **L1 Surface Scan:** raw metric collection from GitPython diff objects — no pure scoring logic.
- **L2/L2b/L2c/L2d:** regex matching, YAML/JSON parsing, manifest diffing, config content scanning — separate specs needed.
- **L5b Phases 1 & 2:** `_stem()`, `_sanitize()`, `_extract_claim()`, `_profile_diff()` —
  string/regex operations; V_f abstracted as a boolean pre-computed input.
- **L5c Runtime Agent:** eBPF/kernel boundary — separate formal model needed.
- **Concurrent access:** CrossHair does not model threads.
- **Actions config overrides:** `critical_signal_score`/`high_signal_score` from
  `self.config.actions`; verification modules use hardcoded defaults (5 and 3).

Full scope boundaries are documented in `VERIFICATION_SPEC.md`, Section 6.
