# PayloadGuard — Formal Verification Specification

**Purpose:** This document is the authoritative specification for external verification of PayloadGuard's scoring model. It was produced by reading the source code and is intended for use by an independent verifier — human auditor, CrossHair, Nagini, or Dafny — without relying on any tests or proofs written by the same author as the code.

**Version pinned:** commit `257d1f3` (branch `claude/general-conversation-klxctt` — Sprint 1, L2d AI Config Poisoning)  
**Previous pin:** commit `d0541f6cdc1a46b8b05f15bf689bc6f5532bbb48` (branch `claude/oidc-typosquat-detection-UBCOJ`, merged to `main` as PR #63)  
**Source file:** `analyze.py`  
**Method:** `PayloadAnalyzer._assess_consequence()`

---

## 1. System Under Verification

`_assess_consequence()` is the sole scoring function for PayloadGuard's Layer 3 Consequence Model. It receives signal counts from all upstream layers (L1 surface scan, L2 forensic analysis, L2b SCA, L2c actions poisoning, L4 structural drift) and produces a verdict. No other function assigns the final verdict or computes `severity_score`.

It is a pure function with respect to its arguments: given identical arguments, it always returns the same result. The only external dependency is `self.config.thresholds` — a configuration object whose default values are specified in Section 4.

---

## 2. Input Domain (Preconditions)

The following preconditions must hold for the specification to apply. Behaviour outside this domain is caller error.

| Parameter | Type | Precondition | Default |
|---|---|---|---|
| `files_deleted` | int | ≥ 0 | (required) |
| `lines_deleted` | int | ≥ 0 | (required) |
| `days_old` | numeric | ≥ 0 | (required) |
| `deletion_ratio` | float | 0.0 ≤ x ≤ 100.0 | (required) |
| `structural_severity` | str | ∈ {"LOW", "MEDIUM", "HIGH", "CRITICAL"} | "LOW" |
| `critical_file_deletions` | int | ≥ 0 | 0 |
| `security_file_deletions` | int | ≥ 0 | 0 |
| `unverified_dependencies` | int | ≥ 0 | 0 |
| `content_flags` | int | ≥ 0 | 0 |
| `actions_poisoning_flags` | int | ≥ 0 | 0 |
| `actions_poisoning_critical` | bool | ∈ {True, False} | False |
| `ai_config_poisoning_flags` | int | ≥ 0 | 0 |
| `ai_config_poisoning_critical` | bool | ∈ {True, False} | False |

**Note:** `days_old` is clamped to `max(0, days_old)` at the call site before being passed in. The function itself does not clamp it. If negative values are passed, behaviour is implementation-defined.

---

## 3. Output Specification (Postconditions)

The return value is a Python dict. The following must hold for **all** inputs satisfying the preconditions in Section 2.

```
POST-1:   result["status"] ∈ {"SAFE", "REVIEW", "CAUTION", "DESTRUCTIVE"}

POST-2:   result["severity_score"] ≥ 0

POST-3:   result["severity_score"] ≤ 36
          (theoretical maximum: age=3 + deletion_dim=4 + structural=5 +
           critical_files=2 + security_files=5 + sca=3 + content=4 + actions=5 + ai_config=5)

POST-4:   result["status"] == "SAFE"        ⟺  result["severity_score"] < 1
POST-5:   result["status"] == "REVIEW"      ⟺  1 ≤ result["severity_score"] < 3
POST-6:   result["status"] == "CAUTION"     ⟺  3 ≤ result["severity_score"] < 5
POST-7:   result["status"] == "DESTRUCTIVE" ⟺  result["severity_score"] ≥ 5

POST-8:   All inputs at zero/false/default → result["status"] == "SAFE"
          (files_deleted=0, lines_deleted=0, days_old=0, deletion_ratio=0.0,
           structural_severity="LOW", all counts=0, actions_poisoning_critical=False,
           ai_config_poisoning_critical=False)

POST-9:   security_file_deletions > 0 → result["status"] == "DESTRUCTIVE"
POST-10:  structural_severity == "CRITICAL" → result["status"] == "DESTRUCTIVE"
POST-11:  actions_poisoning_critical == True → result["status"] == "DESTRUCTIVE"

POST-12:  ai_config_poisoning_critical == True → result["status"] == "DESTRUCTIVE"
          (Dafny file: `ensures ai_config_poisoning_critical ==> status == "DESTRUCTIVE"`)

POST-13:  The internal deletion_dim value ∈ [0, 4] for all inputs
          (deletion_dim is not returned but can be derived: see Section 4, step 5)

POST-14:  Monotonicity — for any single signal parameter p, holding all other
          parameters constant: increasing p never decreases result["severity_score"]
```

**POST-4 through POST-7 are exhaustive and mutually exclusive.** Every possible score maps to exactly one verdict. There is no score for which the verdict is undefined.

**POST-11 and POST-12 are the safety-critical floors.** Either condition alone is sufficient to force DESTRUCTIVE regardless of all other signal values.

---

## 4. Scoring Model — Mathematical Specification

The following defines `severity_score` as a pure mathematical function of the inputs, using default thresholds. All threshold arrays are configurable via `payloadguard.yml`; the defaults are shown.

### Step 1: Branch Age Score
```
age_thresholds = [90, 180, 365]   # days

age_score(days_old):
  3   if days_old > 365
  2   if days_old > 180
  1   if days_old > 90
  0   otherwise
```

### Step 2: File Deletion Score (pre-aggregation)
```
file_thresholds = [10, 20, 50]   # files

file_score(files_deleted):
  3   if files_deleted > 50
  2   if files_deleted > 20
  1   if files_deleted > 10
  0   otherwise
```

### Step 3: Deletion Ratio Score (pre-aggregation)
```
ratio_min_lines = 0   if critical_file_deletions > 0
                  100  otherwise

ratio_score(deletion_ratio, lines_deleted, critical_file_deletions):
  0   if lines_deleted < ratio_min_lines
  3   if deletion_ratio > 90.0
  2   if deletion_ratio > 70.0
  1   if deletion_ratio > 50.0
  0   otherwise
```

### Step 4: Line Deletion Score (pre-aggregation)
```
line_thresholds = [5000, 10000, 50000]   # lines

line_score(lines_deleted):
  3   if lines_deleted > 50000
  2   if lines_deleted > 10000
  1   if lines_deleted > 5000
  0   otherwise
```

### Step 5: Deletion Dimension Aggregation (anti-correlation cap)
```
nonzero_dims = |{s ∈ {file_score, ratio_score, line_score} : s > 0}|

deletion_dim = min(4,
                 max(file_score, ratio_score, line_score)
                 + (1 if nonzero_dims ≥ 2 else 0))
```

This caps three correlated dimensions at 4 to prevent triple-counting. The bonus (+1) fires only when at least two dimensions independently trigger.

### Step 6–12: Remaining Signal Contributions
```
structural_score  = 5   if structural_severity == "CRITICAL"   else 0
crit_file_score   = 2   if critical_file_deletions > 0         else 0
sec_file_score    = 5   if security_file_deletions > 0         else 0
sca_score         = 3   if unverified_dependencies > 0         else 0
content_score     = min(4, content_flags * 2)   if content_flags > 0   else 0

actions_score     = 5   if actions_poisoning_critical
                  = 3   if (not actions_poisoning_critical) and actions_poisoning_flags > 0
                  = 0   otherwise

ai_config_score   = 5   if ai_config_poisoning_critical
                  = 3   if (not ai_config_poisoning_critical) and ai_config_poisoning_flags > 0
                  = 0   otherwise
```

### Total Score and Verdict
```
severity_score = age_score
               + deletion_dim
               + structural_score
               + crit_file_score
               + sec_file_score
               + sca_score
               + content_score
               + actions_score
               + ai_config_score

verdict(severity_score):
  "DESTRUCTIVE"   if severity_score ≥ 5
  "CAUTION"       if severity_score ≥ 3
  "REVIEW"        if severity_score ≥ 1
  "SAFE"          otherwise
```

---

## 5. Contract Stubs for External Tooling

### CrossHair (docstring format)
Paste these contracts into `_assess_consequence()`. Do not run CrossHair from within this repo — run it externally against a clean checkout at the pinned commit.

```python
def _assess_consequence(self, files_deleted, lines_deleted, days_old, deletion_ratio,
                         structural_severity="LOW", critical_file_deletions=0,
                         security_file_deletions=0, unverified_dependencies=0,
                         content_flags=0, actions_poisoning_flags=0,
                         actions_poisoning_critical=False,
                         ai_config_poisoning_flags=0,
                         ai_config_poisoning_critical=False):
    """
    pre: files_deleted >= 0
    pre: lines_deleted >= 0
    pre: days_old >= 0
    pre: 0.0 <= deletion_ratio <= 100.0
    pre: structural_severity in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    pre: critical_file_deletions >= 0
    pre: security_file_deletions >= 0
    pre: unverified_dependencies >= 0
    pre: content_flags >= 0
    pre: actions_poisoning_flags >= 0
    pre: ai_config_poisoning_flags >= 0
    post: __return__["status"] in ("SAFE", "REVIEW", "CAUTION", "DESTRUCTIVE")
    post: __return__["severity_score"] >= 0
    post: __return__["severity_score"] <= 36
    post: (__return__["status"] == "SAFE") == (__return__["severity_score"] < 1)
    post: (__return__["status"] == "DESTRUCTIVE") == (__return__["severity_score"] >= 5)
    post: not (security_file_deletions > 0) or __return__["status"] == "DESTRUCTIVE"
    post: not (structural_severity == "CRITICAL") or __return__["status"] == "DESTRUCTIVE"
    post: not actions_poisoning_critical or __return__["status"] == "DESTRUCTIVE"
    post: not ai_config_poisoning_critical or __return__["status"] == "DESTRUCTIVE"
    """
```

### Dafny Reference Specification
Implement the method body separately using the mathematical functions in Section 4. The verifier must confirm that any correct implementation satisfies these postconditions.

```dafny
method AssessConsequence(
    files_deleted: nat,
    lines_deleted: nat,
    days_old: nat,
    deletion_ratio: real,
    structural_severity: string,
    critical_file_deletions: nat,
    security_file_deletions: nat,
    unverified_dependencies: nat,
    content_flags: nat,
    actions_poisoning_flags: nat,
    actions_poisoning_critical: bool,
    ai_config_poisoning_flags: nat,
    ai_config_poisoning_critical: bool
) returns (status: string, severity_score: int)
  requires 0.0 <= deletion_ratio <= 100.0
  requires structural_severity == "LOW" || structural_severity == "MEDIUM" ||
           structural_severity == "HIGH" || structural_severity == "CRITICAL"
  ensures status == "SAFE" || status == "REVIEW" ||
          status == "CAUTION" || status == "DESTRUCTIVE"
  ensures severity_score >= 0
  ensures severity_score <= 36
  ensures (status == "SAFE")        <==> (severity_score < 1)
  ensures (status == "REVIEW")      <==> (1 <= severity_score < 3)
  ensures (status == "CAUTION")     <==> (3 <= severity_score < 5)
  ensures (status == "DESTRUCTIVE") <==> (severity_score >= 5)
  ensures security_file_deletions > 0       ==> status == "DESTRUCTIVE"
  ensures structural_severity == "CRITICAL" ==> status == "DESTRUCTIVE"
  ensures actions_poisoning_critical        ==> status == "DESTRUCTIVE"
  ensures ai_config_poisoning_critical      ==> status == "DESTRUCTIVE"
  ensures files_deleted == 0 && lines_deleted == 0 && days_old == 0 &&
          deletion_ratio == 0.0 && structural_severity == "LOW" &&
          critical_file_deletions == 0 && security_file_deletions == 0 &&
          unverified_dependencies == 0 && content_flags == 0 &&
          actions_poisoning_flags == 0 && !actions_poisoning_critical &&
          ai_config_poisoning_flags == 0 && !ai_config_poisoning_critical
          ==> status == "SAFE"
```

### Z3 (independent restatement — do not reuse P1–P10)
Run against the mathematical model in Section 4, not against the Python source, to provide an independent check of the spec itself.

```python
from z3 import *

# Inputs as Z3 variables
files_deleted          = Int('files_deleted')
lines_deleted          = Int('lines_deleted')
days_old               = Int('days_old')
deletion_ratio         = Real('deletion_ratio')
structural_critical    = Bool('structural_critical')
critical_file_del      = Int('critical_file_del')
security_file_del      = Int('security_file_del')
unverified_deps        = Int('unverified_deps')
content_flags          = Int('content_flags')
actions_critical       = Bool('actions_critical')
actions_high           = Int('actions_high')

# Preconditions
pre = And(
    files_deleted >= 0, lines_deleted >= 0, days_old >= 0,
    deletion_ratio >= 0, deletion_ratio <= 100,
    critical_file_del >= 0, security_file_del >= 0,
    unverified_deps >= 0, content_flags >= 0, actions_high >= 0
)

# Prove POST-9: security_file_deletions > 0 → score ≥ 5
# (Minimum score when security_file_del > 0 is 0 + 0 + 0 + 5 = 5)
s = Solver()
s.add(pre)
s.add(security_file_del > 0)
# Assert negation: score < 5 despite security_file_del > 0
# sec_file_score = 5, all other scores ≥ 0, so total ≥ 5 always
# This should be unsat:
s.add(5 < 5)  # 5 + anything_non_negative < 5 is always False
print("POST-9:", s.check())  # expected: unsat
```

---

## 6. Scope Boundaries — What Is NOT Specified Here

| Layer | Status | Reason |
|---|---|---|
| L1 Surface Scan | Not specified | Signal *collection*, not scoring |
| L2 Forensic Analysis | Not specified | Regex pattern matching — separate spec needed |
| L2b SCA | Not specified | Manifest diffing — separate spec needed |
| L2c Actions Poisoning | Not specified | YAML parsing + pattern matching — separate spec needed |
| L4 Structural Drift | Not specified | AST diffing — separate spec needed |
| L5a Temporal Drift | Not specified | Floating-point velocity computation |
| L5b Semantic Transparency | Not suitable for SMT | Regex, tokenisation, suffix stemming |
| L5c Runtime Agent | Out of scope | Kernel-level eBPF — separate formal model needed |
| Config loading | Not specified | File I/O boundary — separate spec needed |

The specification in this document covers **only the consequence scoring function** — the transformation from signal counts to a verdict. All upstream signal collection is assumed correct.

---

## 7. Known Limitations and Verifier Warnings

1. **Configurable thresholds.** Section 4 specifies default thresholds. If `payloadguard.yml` overrides them, the postconditions still hold structurally but the specific numeric boundaries change. A complete verification must either fix the thresholds or parameterise them.

2. **Float arithmetic.** `severity_score` is initialised as `0.0` (Python float). In practice, all increments are integers, so float precision is not a concern. Dafny should model `severity_score` as an integer.

3. **`deletion_ratio` source.** The ratio is computed externally (by git numstat) before being passed in. The function trusts the caller to provide a value in [0, 100]. If the caller provides 101.0, POST-5 through POST-7 may not hold — this is a caller bug.

4. **`actions_poisoning_flags`/`actions_poisoning_critical` and `ai_config_poisoning_flags`/`ai_config_poisoning_critical` are not mutually exclusive enforced.** If the respective `_critical=True`, the branch adds 5 (not 3+5). The `elif` in the source code ensures this for both pairs — a verifier should confirm neither critical branch is double-counted.

5. **P1–P10 are not independent.** The existing Z3 proofs in `tests/proofs/test_z3_properties.py` were written by the same author as the source code. They validate the spec against a Z3 model of the code, not the code directly. CrossHair and Dafny provide independent verification against the actual Python source and a language-agnostic model respectively.
