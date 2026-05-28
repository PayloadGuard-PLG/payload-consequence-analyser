// verification/dafny/temporal_drift.dfy
//
// Machine-checked verification of PayloadGuard L5a temporal drift analysis.
// Verifies the linear drift model: drift_score = branch_age_days × target_velocity,
// classified against warning and critical thresholds.
//
// Tool:    Dafny 4.x — Boogie + Z3 backend
// Verify:  dafny verify verification/dafny/temporal_drift.dfy

method AnalyzeTemporalDrift(
    branch_age_days:   nat,
    target_velocity:   real,
    warning_threshold:  real,
    critical_threshold: real
) returns (status: string, drift_score: real)

    requires target_velocity >= 0.0
    requires warning_threshold > 0.0
    requires critical_threshold > warning_threshold

    // T1: status is one of three valid values
    ensures status == "CURRENT" || status == "STALE" || status == "DANGEROUS"

    // T2: drift score is non-negative
    ensures drift_score >= 0.0

    // T3–T5: status ↔ score classification bijection
    ensures status == "DANGEROUS" ==> drift_score >= critical_threshold
    ensures status == "STALE"     ==> warning_threshold <= drift_score < critical_threshold
    ensures status == "CURRENT"   ==> drift_score < warning_threshold

    // T6: zero-age branch is always CURRENT (no drift possible)
    ensures branch_age_days == 0 ==> status == "CURRENT"

    // T7: zero-velocity target is always CURRENT (score = 0 < warning_threshold)
    ensures target_velocity == 0.0 ==> status == "CURRENT"

    // T8: DANGEROUS ↔ score ≥ critical_threshold (biconditional)
    ensures (status == "DANGEROUS") <==> (drift_score >= critical_threshold)
{
    drift_score := branch_age_days as real * target_velocity;

    // Intermediate assertions assist the verifier for the zero-input postconditions.
    assert branch_age_days == 0   ==> drift_score == 0.0;
    assert target_velocity == 0.0 ==> drift_score == 0.0;

    if drift_score >= critical_threshold {
        status := "DANGEROUS";
    } else if drift_score >= warning_threshold {
        status := "STALE";
    } else {
        status := "CURRENT";
    }
}
