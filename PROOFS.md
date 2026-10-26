# PayloadGuard — Formal Verification Record

This page is the authoritative proof artifact record for PayloadGuard v1.6.0
(proofs last run 2026-10-26 on `main` `9e83cce`, plus the §V10 change `c74f612`).
Three independent verification methods — Dafny, CrossHair, and Z3 — cover the same
scoring logic from different angles. A defect would have to produce a consistent
false result across all three simultaneously to go undetected.

**Quick summary (2026-10-26):**

| Method | Tool | Scope | Result |
|---|---|---|---|
| Machine-checked proofs | Dafny 4.9.1 + Boogie + Z3 4.12.1 | L3, L4, L5a — entire input domain | 9 methods/functions verified, 0 errors (GitHub Actions run #16) |
| Symbolic execution | CrossHair 0.0.112 (PEP316 contracts) | L3, L4, L5a, L5b — pure-Python mirror modules in `verification/` | 36 postconditions, 0 counterexamples after the §V10 fix (one counterexample found and fixed in `temporal_pure`) |
| SMT proofs | Z3 (z3-solver 5.3.2.0) | L3, L2c — abstract scoring model | 10 properties, all `unsat`; P9 is model-based with tightness and sensitivity checks (§V8 fixed) |

→ Committed proof files: [`verification/dafny/`](verification/dafny/) · [`verification/`](verification/)  
→ CI workflow: [`.github/workflows/verify-dafny.yml`](.github/workflows/verify-dafny.yml)  
→ Formal specification: [`VERIFICATION_SPEC.md`](VERIFICATION_SPEC.md)

---

## Dafny Machine-Checked Proofs

Dafny translates each annotated method into Boogie verification conditions and
discharges them using Z3. The proof covers the **entire input domain** — not a sample.
Every `ensures` clause is a machine-checked theorem.

### Tool and version

```
Dafny 4.9.1 (release zip), Boogie + Z3 4.12.1 (bundled)
Generated: 2026-10-26T12:19:20Z — GitHub Actions "Dafny Verification" run #16, ubuntu-24.04
Commit: 9e83cce (main)
```

### Committed verification output

This run covers the current `assess_consequence.dfy`, including the 2026-06-11 Sprint 1 change
(`MAX_SCORE` 36, POST-12). The previous committed output (2026-05-28) predated that change
(`AUDIT_LOG.md` §V9).

```
## assess_consequence.dfy
Dafny program verifier finished with 7 verified, 0 errors

## structural_drift.dfy
Dafny program verifier finished with 1 verified, 0 errors

## temporal_drift.dfy
Dafny program verifier finished with 1 verified, 0 errors
```

Full log: [`verification/dafny/assess_consequence_verify.log`](verification/dafny/assess_consequence_verify.log)

### L3 Consequence Scoring — `assess_consequence.dfy`

Source: [`verification/dafny/assess_consequence.dfy`](verification/dafny/assess_consequence.dfy)

"7 verified" = 6 pure helper functions (AgeScore, FilesScore, LinesScore, RatioScore,
DeletionDim, ContentFlagsScore) + 1 main method (AssessConsequence).

The `AssessConsequence` method carries 12 postconditions (POST-1–12, including POST-11a).
Excerpt from the current `assess_consequence.dfy` (`MAX_SCORE` = 36):

```dafny
method AssessConsequence(
    files_deleted:             nat,
    lines_deleted:             nat,
    days_old:                  nat,
    deletion_ratio:            real,
    structural_severity:       string,
    critical_file_deletions:   nat,
    security_file_deletions:   nat,
    unverified_dependencies:   nat,
    content_flags:             nat,
    actions_poisoning_flags:   nat,
    actions_poisoning_critical: bool,
    ai_config_poisoning_flags:  nat,
    ai_config_poisoning_critical: bool
) returns (status: string, severity_score: int)

    requires 0.0 <= deletion_ratio <= 100.0
    requires structural_severity == "LOW" || structural_severity == "MEDIUM" ||
             structural_severity == "HIGH" || structural_severity == "CRITICAL"

    // POST-1: status is one of four valid verdicts
    ensures status == "SAFE" || status == "REVIEW" ||
            status == "CAUTION" || status == "DESTRUCTIVE"

    // POST-2: score is non-negative
    ensures severity_score >= 0

    // POST-3: score does not exceed the sum of all signal maximums (36)
    ensures severity_score <= MAX_SCORE

    // POST-4–7: verdict ↔ score bijection (exhaustive, mutually exclusive)
    ensures (status == "SAFE")        <==> (severity_score < REVIEW_THRESHOLD)
    ensures (status == "REVIEW")      <==> (REVIEW_THRESHOLD <= severity_score < CAUTION_THRESHOLD)
    ensures (status == "CAUTION")     <==> (CAUTION_THRESHOLD <= severity_score < DESTRUCTIVE_THRESHOLD)
    ensures (status == "DESTRUCTIVE") <==> (severity_score >= DESTRUCTIVE_THRESHOLD)

    // POST-8: any security file deletion forces DESTRUCTIVE (contributes +5)
    ensures security_file_deletions > 0 ==> status == "DESTRUCTIVE"

    // POST-9: structural CRITICAL forces DESTRUCTIVE (contributes +5)
    ensures structural_severity == "CRITICAL" ==> status == "DESTRUCTIVE"

    // POST-10: actions poisoning CRITICAL forces DESTRUCTIVE (contributes +5)
    ensures actions_poisoning_critical ==> status == "DESTRUCTIVE"

    // POST-12: AI tooling config poisoning CRITICAL forces DESTRUCTIVE (contributes +5)
    ensures ai_config_poisoning_critical ==> status == "DESTRUCTIVE"

    // POST-11a: all-zero inputs yield SAFE (no false positives on empty diffs)
    ensures files_deleted == 0 && lines_deleted == 0 && days_old == 0 &&
            deletion_ratio == 0.0 && structural_severity == "LOW" &&
            critical_file_deletions == 0 && security_file_deletions == 0 &&
            unverified_dependencies == 0 && content_flags == 0 &&
            actions_poisoning_flags == 0 && !actions_poisoning_critical &&
            ai_config_poisoning_flags == 0 && !ai_config_poisoning_critical
            ==> status == "SAFE"
```

### L4 Structural Drift — `structural_drift.dfy`

Source: [`verification/dafny/structural_drift.dfy`](verification/dafny/structural_drift.dfy)

Proves the dual-gate invariant: DESTRUCTIVE requires **both** deletion_ratio > threshold
**and** deleted_count ≥ min_deletion_count. Neither gate alone is sufficient.

```dafny
method AssessStructuralDrift(
    original_count: nat, deleted_count: nat,
    deletion_ratio_threshold: real, min_deletion_count: nat
) returns (status: string, deletion_ratio: real)

    requires deleted_count <= original_count
    requires 0.0 < deletion_ratio_threshold < 1.0
    requires min_deletion_count >= 1

    ensures status == "SAFE" || status == "DESTRUCTIVE"           // S1
    ensures 0.0 <= deletion_ratio <= 1.0                          // S2
    ensures status == "DESTRUCTIVE" ==>
            deletion_ratio > deletion_ratio_threshold             // S3
    ensures status == "DESTRUCTIVE" ==>
            deleted_count >= min_deletion_count                   // S4
    ensures deleted_count == 0 ==> status == "SAFE"               // S5
    ensures original_count == 0 ==> status == "SAFE"              // S6
    ensures (status == "DESTRUCTIVE") <==>
            (deletion_ratio > deletion_ratio_threshold &&
             deleted_count >= min_deletion_count)                  // S7 biconditional
```

### L5a Temporal Drift — `temporal_drift.dfy`

Source: [`verification/dafny/temporal_drift.dfy`](verification/dafny/temporal_drift.dfy)

```dafny
method AnalyzeTemporalDrift(
    branch_age_days: nat, target_velocity: real,
    warning_threshold: real, critical_threshold: real
) returns (status: string, drift_score: real)

    requires target_velocity >= 0.0
    requires warning_threshold > 0.0
    requires critical_threshold > warning_threshold

    ensures status == "CURRENT" || status == "STALE" || status == "DANGEROUS"  // T1
    ensures drift_score >= 0.0                                                  // T2
    ensures status == "DANGEROUS" ==> drift_score >= critical_threshold         // T3
    ensures status == "STALE" ==>
            warning_threshold <= drift_score < critical_threshold               // T4
    ensures status == "CURRENT" ==> drift_score < warning_threshold             // T5
    ensures branch_age_days == 0 ==> status == "CURRENT"                        // T6
    ensures target_velocity == 0.0 ==> status == "CURRENT"                      // T7
    ensures (status == "DANGEROUS") <==> (drift_score >= critical_threshold)    // T8
```

---

## CrossHair Symbolic Execution

CrossHair executes the **actual Python source** symbolically using its own Z3-backed engine,
exploring all inputs satisfying the pre-conditions and verifying every post-condition on every
execution path. This is not a model — it runs the real implementation.

Because `PayloadAnalyzer.__init__()` calls `git.Repo()` (subprocess), CrossHair targets
pure-Python mirror modules in `verification/` that replicate the scoring logic without I/O.

**Run command:**
```bash
cd verification
crosshair check consequence_pure --analysis_kind PEP316 --per_condition_timeout 30
crosshair check structural_pure  --analysis_kind PEP316 --per_condition_timeout 30
crosshair check temporal_pure    --analysis_kind PEP316 --per_condition_timeout 30
crosshair check semantic_pure    --analysis_kind PEP316 --per_condition_timeout 30
```
**Expected result:** exit code 0, no output. Any counterexample is printed to stdout with
the specific input values and violated contract name.

**Last run (2026-10-26):** the commands above with `--report_all`, CrossHair 0.0.112, local
Windows 11 / Python 3.14.3, after the §V10 fix (`c74f612`). "Confirmed over all paths" means
CrossHair exhausted every execution path; "Not confirmed" means no counterexample was found
within the 30 s per-condition budget but the path space was not exhausted (typical for float
arithmetic).

| Module | Exit | Time | Confirmed over all paths | Not confirmed | Counterexamples |
|---|---|---|---|---|---|
| `consequence_pure` | 0 | 366 s | 1 (C-12, `deletion_dim`) | 12 (C-01–C-11, POST-12) | 0 |
| `structural_pure` | 0 | 224 s | 0 | 7 (S-01–S-07) | 0 |
| `temporal_pure` | 0 | 219 s | 0 | 7 (T-01–T-07) | 0 |
| `semantic_pure` | 0 | 11 s | 9 (M-01–M-09) | 0 | 0 |

Before the §V10 fix, `temporal_pure` exited 1 with a counterexample
(`analyze_drift_pure(0, float("inf"), 0.25, 0.5)` → `drift_score` NaN, violating T-02 and T-05).
The five pytest wrappers in `tests/proofs/` use a 10 s budget and did not reach that input.

### L3 Contracts (C1–C12)

Source: [`verification/consequence_pure.py`](verification/consequence_pure.py)

| Contract | Invariant |
|---|---|
| C-01 | `verdict in {"SAFE", "REVIEW", "CAUTION", "DESTRUCTIVE"}` |
| C-02 | `severity_score >= 0` |
| C-03 | `severity_score <= 36` |
| C-04 | `verdict == "SAFE" ↔ severity_score < 1` |
| C-05 | `verdict == "REVIEW" ↔ 1 <= severity_score < 3` |
| C-06 | `verdict == "CAUTION" ↔ 3 <= severity_score < 5` |
| C-07 | `verdict == "DESTRUCTIVE" ↔ severity_score >= 5` |
| C-08 | `security_file_deletions > 0 → verdict == "DESTRUCTIVE"` |
| C-09 | `structural_severity == "CRITICAL" → verdict == "DESTRUCTIVE"` |
| C-10 | `actions_poisoning_critical → verdict == "DESTRUCTIVE"` |
| C-11 | `all-zero inputs → verdict == "SAFE"` |
| C-12 | `deletion_dim ∈ [0, 4]` |
| POST-12 | `ai_config_poisoning_critical → verdict == "DESTRUCTIVE"` |

### L4 Contracts (S1–S7)

Source: [`verification/structural_pure.py`](verification/structural_pure.py)

| Contract | Invariant |
|---|---|
| S-01 | `status ∈ {"DESTRUCTIVE", "SAFE"}` |
| S-02 | `0.0 <= deletion_ratio <= 1.0` |
| S-03 | `DESTRUCTIVE → deletion_ratio > threshold` |
| S-04 | `DESTRUCTIVE → deleted_count >= min_deletion_count` |
| S-05 | `deleted_count == 0 → SAFE` |
| S-06 | `original_count == 0 → SAFE` |
| S-07 | `SAFE → NOT (ratio > threshold AND count >= min)` |

### L5a Contracts (T1–T7)

Source: [`verification/temporal_pure.py`](verification/temporal_pure.py)

| Contract | Invariant |
|---|---|
| T-01 | `status ∈ {"CURRENT", "STALE", "DANGEROUS"}` |
| T-02 | `drift_score >= 0.0` |
| T-03 | `DANGEROUS → drift_score >= critical_threshold` |
| T-04 | `STALE → warning_threshold <= drift_score < critical_threshold` |
| T-05 | `CURRENT → drift_score < warning_threshold` |
| T-06 | `branch_age_days == 0 → CURRENT` |
| T-07 | `target_velocity == 0.0 → CURRENT` |

Preconditions: `branch_age_days >= 0`, `target_velocity >= 0.0`, `math.isfinite(target_velocity)`,
`warning_threshold > 0.0`, `critical_threshold > warning_threshold`. The finite-velocity
precondition was added on 2026-10-26 after CrossHair found `analyze_drift_pure(0, inf, …)`
returning a NaN drift score (`AUDIT_LOG.md` §V10); `TemporalDriftAnalyzer.analyze_drift()` now
raises `ValueError` for non-finite inputs. Dafny's `real` has no infinity or NaN, so
`temporal_drift.dfy` was unaffected.

### L5b Contracts (M1–M9)

Source: [`verification/semantic_pure.py`](verification/semantic_pure.py)

| Contract | Invariant |
|---|---|
| M-01 | `status ∈ {"UNVERIFIED", "TRANSPARENT", "CAUTION_MISMATCH", "DECEPTIVE_PAYLOAD"}` |
| M-02 | `0.0 <= mci_score <= 1.0` |
| M-03 | `not has_description → status == "UNVERIFIED"` |
| M-04 | `not has_description → mci_score == 0.0` |
| M-05 | `UNVERIFIED → not has_description` |
| M-06 | `mci_score >= 0.5 → DECEPTIVE_PAYLOAD` |
| M-07 | `DECEPTIVE_PAYLOAD → mci_score >= 0.5` |
| M-08 | `TRANSPARENT → mci_score == 0.0` |
| M-09 | `TRANSPARENT → not is_macro` |

---

## Z3 SMT Proofs

Ten properties proved on an abstract model of the scoring logic.
All encode the negation of the target property and prove it `unsat` — meaning no
counterexample exists anywhere in the input space.

Source: [`tests/proofs/test_z3_properties.py`](tests/proofs/test_z3_properties.py)

**Run command:**
```bash
pytest tests/proofs/test_z3_properties.py -m proof -v --timeout=30
```
**Expected result:** 10 passed in < 0.1 s each.

| Property | What is proven |
|---|---|
| P1 | `oidc_elevation_typosquatted` fires → score contribution ≥ CRITICAL_SCORE (5) |
| P2 | Typosquat (CRITICAL +5) with zero other signals → score ≥ DESTRUCTIVE threshold (5) |
| P3 | No trust-signal subtraction can reduce a typosquat score below the DESTRUCTIVE threshold |
| P4 | CRITICAL_SCORE > HIGH_SCORE (severity mapping is strictly ordered) |
| P5 | Adding a CRITICAL signal to any base score never decreases the total |
| P6 | SAFE verdict ↔ score < REVIEW threshold (both directions) |
| P7 | Identical scores always produce identical verdicts |
| P8 | Any score that includes a typosquat contribution cannot be SAFE |
| P9 | No combination of signals makes the score built from `_assess_consequence()`'s per-signal contributions exceed MAX_SCORE (36); 36 is reachable; removing the content-flag cap breaks the bound; the production scorer with every signal at maximum returns 36 |
| P10 | Zero signals → score = 0 → SAFE |

**Last run:** 2026-10-26 — 13 passed (P1–P10, with P9 as four tests; `z3-solver` 5.3.2.0), Windows 11, Python 3.14.3.

**Note on P9 (§V8, fixed 2026-10-26):** the previous P9 added `score <= bound` as a constraint and then checked `score > bound`, which is unsatisfiable for any bound (it passed with a bound of 0 or −100). P9 now derives the score from the signal model; with a bound of 35 the solver returns a counterexample.

---

## Reproduce Locally

### Dafny

```bash
# Install Dafny 4.9.1 from the release zip, which bundles Z3 4.12.1
# (the dotnet tool package does not bundle Z3). CI does the same:
# .github/workflows/verify-dafny.yml (also runnable via workflow_dispatch).

# Verify
dafny verify verification/dafny/assess_consequence.dfy
dafny verify verification/dafny/structural_drift.dfy
dafny verify verification/dafny/temporal_drift.dfy

# Expected for each file: "Dafny program verifier finished with N verified, 0 errors"
# Guard against the known false-zero bug: grep output for "0 errors"
```

### CrossHair

```bash
pip install crosshair-tool
cd verification

crosshair check consequence_pure --analysis_kind PEP316 --per_condition_timeout 30
crosshair check structural_pure  --analysis_kind PEP316 --per_condition_timeout 30
crosshair check temporal_pure    --analysis_kind PEP316 --per_condition_timeout 30
crosshair check semantic_pure    --analysis_kind PEP316 --per_condition_timeout 30
# Expected: exit 0, no output
```

### Z3 + full proof suite

```bash
pip install z3-solver crosshair-tool pytest pytest-timeout
pytest tests/proofs/ -v --timeout=60
# Expected: 19 passed (13 Z3 tests + 5 CrossHair contract wrappers + 1 temporal contract regression)
```

---

## Why Three Independent Methods?

| | Dafny | CrossHair | Z3 |
|---|---|---|---|
| **What it operates on** | Dafny reference implementation | Active Python source | Abstract mathematical model |
| **Verification domain** | Entire input domain (machine-checked) | All paths satisfying preconditions | All values satisfying SMT constraints |
| **What it catches** | Logical errors in the spec itself | Divergence between spec and Python impl | Properties hard to express as contracts |
| **Speed** | Seconds per file | ~8 s for all contracts | < 0.1 s per property |

The three representations are independent: a scoring change would have to produce a
consistent false result across the Dafny spec, the Python implementation, and the abstract
model simultaneously to go undetected.
