// verification/dafny/assess_consequence.dfy
//
// Machine-checked verification of PayloadGuard L3 consequence scoring.
// Postconditions POST-1 through POST-12 from VERIFICATION_SPEC.md §5.
//
// Tool:    Dafny 4.x — discharges verification conditions via Boogie + Z3
// Install: dotnet tool install --global dafny
// Verify:  dafny verify verification/dafny/assess_consequence.dfy
//
// Citation: K.R.M. Leino. Dafny: An Automatic Program Verifier for Functional
//           Correctness. LPAR-16, LNCS 6355, pp. 348–370. Springer, 2010.

// ── Verdict thresholds ────────────────────────────────────────────────────────

const DESTRUCTIVE_THRESHOLD: int := 5
const CAUTION_THRESHOLD:     int := 3
const REVIEW_THRESHOLD:      int := 1
const MAX_SCORE:             int := 36

// ── Per-component scoring functions ──────────────────────────────────────────
// Pure functions with explicit bounds. The method body uses these postconditions
// to discharge severity_score <= MAX_SCORE without an explicit arithmetic lemma.

function AgeScore(days_old: nat): (r: int)
    ensures 0 <= r <= 3
{
    if days_old > 365 then 3
    else if days_old > 180 then 2
    else if days_old > 90 then 1
    else 0
}

function FilesScore(files_deleted: nat): (r: int)
    ensures 0 <= r <= 3
{
    if files_deleted > 50 then 3
    else if files_deleted > 20 then 2
    else if files_deleted > 10 then 1
    else 0
}

function LinesScore(lines_deleted: nat): (r: int)
    ensures 0 <= r <= 3
{
    if lines_deleted > 50000 then 3
    else if lines_deleted > 10000 then 2
    else if lines_deleted > 5000 then 1
    else 0
}

// Ratio score applies only when enough lines are deleted to make the ratio
// meaningful (≥100 lines), unless critical files were also deleted.
function RatioScore(deletion_ratio: real, lines_deleted: nat,
                    critical_file_deletions: nat): (r: int)
    requires 0.0 <= deletion_ratio <= 100.0
    ensures 0 <= r <= 3
{
    if !(lines_deleted >= 100 || critical_file_deletions > 0) then 0
    else if deletion_ratio > 90.0 then 3
    else if deletion_ratio > 70.0 then 2
    else if deletion_ratio > 50.0 then 1
    else 0
}

// Deletion dimension: max of the three correlated deletion signals with a +1
// bonus when two or more fire simultaneously. Capped at 4 to prevent
// triple-counting of inherently correlated file/ratio/lines dimensions.
function DeletionDim(fs: int, rs: int, ls: int): (r: int)
    requires 0 <= fs <= 3
    requires 0 <= rs <= 3
    requires 0 <= ls <= 3
    ensures 0 <= r <= 4
{
    var max_dim :=
        if fs >= rs && fs >= ls then fs
        else if rs >= ls then rs
        else ls;
    var active :=
        (if fs > 0 then 1 else 0) +
        (if rs > 0 then 1 else 0) +
        (if ls > 0 then 1 else 0);
    var raw := max_dim + (if active >= 2 then 1 else 0);
    if raw > 4 then 4 else raw
}

// Content flags (CI trigger / shell execution patterns): +2 per flag, capped at 4.
function ContentFlagsScore(content_flags: nat): (r: int)
    ensures 0 <= r <= 4
{
    if content_flags == 0 then 0
    else if content_flags * 2 >= 4 then 4
    else content_flags * 2
}

// ── Main consequence assessment ───────────────────────────────────────────────

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
{
    var s: int := 0;

    // Branch age: 0–3 points
    var age_s := AgeScore(days_old);
    s := s + age_s;

    // Deletion dimension: three correlated signals collapsed to 0–4 points
    var fs  := FilesScore(files_deleted);
    var rs  := RatioScore(deletion_ratio, lines_deleted, critical_file_deletions);
    var ls  := LinesScore(lines_deleted);
    var dim := DeletionDim(fs, rs, ls);
    s := s + dim;

    // Structural CRITICAL (AST-level gutting): 0 or +5
    if structural_severity == "CRITICAL" { s := s + 5; }

    // Critical file deletions (security/auth/config paths): 0 or +2
    if critical_file_deletions > 0 { s := s + 2; }

    // Security file deletions: 0 or +5 (forces DESTRUCTIVE alone)
    if security_file_deletions > 0 { s := s + 5; }

    // Unverified dependencies (SCA): 0 or +3
    if unverified_dependencies > 0 { s := s + 3; }

    // Content flags (CI triggers / shell execution): 0–4 points
    var cf_s := ContentFlagsScore(content_flags);
    s := s + cf_s;

    // Actions poisoning: CRITICAL = +5, HIGH = +3, none = 0
    if actions_poisoning_critical {
        s := s + 5;
    } else if actions_poisoning_flags > 0 {
        s := s + 3;
    }

    // AI tooling config poisoning: CRITICAL = +5, HIGH = +3, none = 0
    if ai_config_poisoning_critical {
        s := s + 5;
    } else if ai_config_poisoning_flags > 0 {
        s := s + 3;
    }

    // Explicit bound assertion: sum of all component maximums = 36.
    // Each addend is bounded by its helper function's postcondition.
    // This assists the verifier in discharging POST-3.
    assert s <= 3 + 4 + 5 + 2 + 5 + 3 + 4 + 5 + 5;

    severity_score := s;

    // Verdict assignment by threshold
    if      severity_score >= DESTRUCTIVE_THRESHOLD { status := "DESTRUCTIVE"; }
    else if severity_score >= CAUTION_THRESHOLD     { status := "CAUTION";     }
    else if severity_score >= REVIEW_THRESHOLD      { status := "REVIEW";      }
    else                                            { status := "SAFE";        }
}
