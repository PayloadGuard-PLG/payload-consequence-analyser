"""
verification/temporal_pure.py
=============================
Pure-Python extraction of TemporalDriftAnalyzer.analyze_drift() (Layer 5a)
for CrossHair formal contract verification.

This module is NOT imported by production code. It is the verification target.

Verification command (run from this directory):
    crosshair check temporal_pure --analysis_kind PEP316 \\
        --per_condition_timeout 30 --max_uninteresting_iterations 10
"""


def analyze_drift_pure(
    branch_age_days: int,
    target_velocity: float,
    warning_threshold: float = 250.0,
    critical_threshold: float = 1000.0,
) -> dict:
    """
    Pure mirror of TemporalDriftAnalyzer.analyze_drift().

    Drift Score = branch_age_days * target_velocity_commits_per_day.
    Two thresholds classify the score into three risk bands.

    pre: branch_age_days >= 0
    pre: target_velocity >= 0.0
    pre: warning_threshold > 0.0
    pre: critical_threshold > warning_threshold
    post: __return__["status"] in ("CURRENT", "STALE", "DANGEROUS")
    post: __return__["drift_score"] >= 0.0
    post: implies(__return__["status"] == "DANGEROUS",  __return__["drift_score"] >= critical_threshold)
    post: implies(__return__["status"] == "STALE",      warning_threshold <= __return__["drift_score"] < critical_threshold)
    post: implies(__return__["status"] == "CURRENT",    __return__["drift_score"] < warning_threshold)
    post: implies(branch_age_days == 0, __return__["status"] == "CURRENT")
    post: implies(target_velocity == 0.0, __return__["status"] == "CURRENT")
    """
    drift_score = branch_age_days * target_velocity

    if drift_score >= critical_threshold:
        status = "DANGEROUS"
    elif drift_score >= warning_threshold:
        status = "STALE"
    else:
        status = "CURRENT"

    return {"status": status, "drift_score": float(drift_score)}
