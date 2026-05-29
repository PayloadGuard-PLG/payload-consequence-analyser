"""
verification/consequence_pure.py
================================
Pure-Python extraction of PayloadAnalyzer._assess_consequence() (Layer 3)
for CrossHair formal contract verification.

This module is NOT imported by production code. It is the verification target.
All contracts here are formally checked by CrossHair's Z3-backed engine.

Sync requirement: when scoring logic in analyze.py _assess_consequence changes,
this module must be updated to match. The contracts are the specification;
the implementation here must satisfy them.

Verification command (run from this directory):
    crosshair check consequence_pure --analysis_kind PEP316 \
        --per_condition_timeout 30 --max_uninteresting_iterations 10

Or targeting specific functions:
    crosshair check consequence_pure._compute_deletion_dim
    crosshair check consequence_pure.assess_consequence_pure

Expected result: exit code 0, no output (all contracts hold).
"""

from typing import Any, Dict

# ---------------------------------------------------------------------------
# Scoring constants — mirror of DEFAULT_CONFIG in analyze.py
# Using module-level constants (not list parameters) so CrossHair does not
# explore symbolic list contents.
# ---------------------------------------------------------------------------

# Branch age tier thresholds in days
_AGE_T1: int = 90
_AGE_T2: int = 180
_AGE_T3: int = 365

# File deletion tier thresholds
_FILES_T1: int = 10
_FILES_T2: int = 20
_FILES_T3: int = 50

# Line deletion tier thresholds
_LINES_T1: int = 5_000
_LINES_T2: int = 10_000
_LINES_T3: int = 50_000

# Actions poisoning signal scores
_CRITICAL_SIGNAL_SCORE: int = 5
_HIGH_SIGNAL_SCORE: int = 3

# Verdict thresholds
_DESTRUCTIVE_THRESHOLD: int = 5
_CAUTION_THRESHOLD: int = 3
_REVIEW_THRESHOLD: int = 1

# PLI semantic analysis signal scores
_PLI_CRITICAL_SCORE: int = 5
_PLI_HIGH_SCORE: int = 3

# Maximum possible severity_score (all signals at maximum simultaneously):
#   branch age +3, deletion_dim +4, structural CRITICAL +5,
#   critical_file_deletions +2, security_file_deletions +5,
#   unverified_dependencies +3, content_flags +4, actions_poisoning_critical +5,
#   pli_critical +5
_MAX_SCORE: int = 36


# ---------------------------------------------------------------------------
# Helper: deletion dimension aggregation
# ---------------------------------------------------------------------------


def _compute_deletion_dim(
    files_deleted: int,
    lines_deleted: int,
    deletion_ratio: float,
    critical_file_deletions: int,
) -> int:
    """
    Compute the deletion dimension score (0-4) from three correlated sub-scores.

    The three dimensions (files, ratio, lines) are highly correlated, so they
    are aggregated with a cap: max of the three, plus 1 bonus point if at least
    two fire, capped at 4. This prevents triple-counting a single large deletion.

    pre: files_deleted >= 0
    pre: lines_deleted >= 0
    pre: 0.0 <= deletion_ratio <= 100.0
    pre: critical_file_deletions >= 0
    post: 0 <= __return__ <= 4
    """
    files_score = 0
    if files_deleted > _FILES_T3:
        files_score = 3
    elif files_deleted > _FILES_T2:
        files_score = 2
    elif files_deleted > _FILES_T1:
        files_score = 1

    # Ratio only fires when absolute deletions reach meaningful scale (100 lines),
    # UNLESS critical-path files are deleted (config deletion at 90% ratio IS significant).
    _ratio_min_lines = 0 if critical_file_deletions > 0 else 100
    ratio_score = 0
    if lines_deleted >= _ratio_min_lines:
        if deletion_ratio > 90:
            ratio_score = 3
        elif deletion_ratio > 70:
            ratio_score = 2
        elif deletion_ratio > 50:
            ratio_score = 1

    lines_score = 0
    if lines_deleted > _LINES_T3:
        lines_score = 3
    elif lines_deleted > _LINES_T2:
        lines_score = 2
    elif lines_deleted > _LINES_T1:
        lines_score = 1

    nonzero_dims = sum(1 for s in (files_score, ratio_score, lines_score) if s > 0)
    return min(4, max(files_score, ratio_score, lines_score) + (1 if nonzero_dims >= 2 else 0))


# ---------------------------------------------------------------------------
# Helper: zero-input sentinel (used in empty-inputs contract)
# ---------------------------------------------------------------------------


def _no_signals(
    files_deleted: int,
    lines_deleted: int,
    days_old: float,
    deletion_ratio: float,
    structural_severity: str,
    critical_file_deletions: int,
    security_file_deletions: int,
    unverified_dependencies: int,
    content_flags: int,
    actions_poisoning_flags: int,
    actions_poisoning_critical: bool,
    pli_critical: bool,
    pli_high: bool,
) -> bool:
    """True when all inputs are at their zero/neutral values."""
    return (
        files_deleted == 0
        and lines_deleted == 0
        and days_old <= 0
        and deletion_ratio <= 0
        and structural_severity != "CRITICAL"
        and critical_file_deletions == 0
        and security_file_deletions == 0
        and unverified_dependencies == 0
        and content_flags == 0
        and actions_poisoning_flags == 0
        and not actions_poisoning_critical
        and not pli_critical
        and not pli_high
    )


# ---------------------------------------------------------------------------
# Primary verification target
# ---------------------------------------------------------------------------


def assess_consequence_pure(
    files_deleted: int,
    lines_deleted: int,
    days_old: float,
    deletion_ratio: float,
    structural_severity: str = "LOW",
    critical_file_deletions: int = 0,
    security_file_deletions: int = 0,
    unverified_dependencies: int = 0,
    content_flags: int = 0,
    actions_poisoning_flags: int = 0,
    actions_poisoning_critical: bool = False,
    pli_critical: bool = False,
    pli_high: bool = False,
) -> Dict[str, Any]:
    """
    Pure-Python mirror of PayloadAnalyzer._assess_consequence() with CrossHair contracts.

    This function is the formal specification of Layer 3's scoring model.
    CrossHair explores all possible inputs satisfying the pre-conditions and
    verifies that every post-condition holds on every execution path.

    CONTRACTS (PEP316 format -- checked by CrossHair):

    Input domain contracts (pre-conditions):
    pre: files_deleted >= 0
    pre: lines_deleted >= 0
    pre: 0.0 <= deletion_ratio <= 100.0
    pre: critical_file_deletions >= 0
    pre: security_file_deletions >= 0
    pre: unverified_dependencies >= 0
    pre: content_flags >= 0
    pre: actions_poisoning_flags >= 0

    Output invariants (post-conditions):
    post: __return__["status"] in ("SAFE", "REVIEW", "CAUTION", "DESTRUCTIVE")
    post: __return__["severity_score"] >= 0
    post: __return__["severity_score"] <= 36

    Verdict-score bijection (both directions):
    post: implies(__return__["status"] == "SAFE",        __return__["severity_score"] < 1)
    post: implies(__return__["status"] == "REVIEW",      1 <= __return__["severity_score"] < 3)
    post: implies(__return__["status"] == "CAUTION",     3 <= __return__["severity_score"] < 5)
    post: implies(__return__["status"] == "DESTRUCTIVE", __return__["severity_score"] >= 5)

    Safety-critical signal implications:
    post: implies(security_file_deletions > 0,      __return__["status"] == "DESTRUCTIVE")
    post: implies(structural_severity == "CRITICAL", __return__["status"] == "DESTRUCTIVE")
    post: implies(actions_poisoning_critical,        __return__["status"] == "DESTRUCTIVE")
    post: implies(pli_critical,                      __return__["status"] == "DESTRUCTIVE")

    Empty-input guarantee:
    post: implies(_no_signals(files_deleted, lines_deleted, days_old, deletion_ratio, structural_severity, critical_file_deletions, security_file_deletions, unverified_dependencies, content_flags, actions_poisoning_flags, actions_poisoning_critical, pli_critical, pli_high), __return__["status"] == "SAFE")
    """
    severity_score: int = 0

    # Step 1: Branch age (tiered)
    if days_old > _AGE_T3:
        severity_score += 3
    elif days_old > _AGE_T2:
        severity_score += 2
    elif days_old > _AGE_T1:
        severity_score += 1

    # Step 2: Deletion dimension (correlated sub-scores, capped at 4)
    deletion_dim = _compute_deletion_dim(
        files_deleted, lines_deleted, deletion_ratio, critical_file_deletions
    )
    severity_score += deletion_dim

    # Step 3: Structural severity
    if structural_severity == "CRITICAL":
        severity_score += 5

    # Step 4: Critical file deletions
    if critical_file_deletions > 0:
        severity_score += 2

    # Step 5: Security file deletions
    if security_file_deletions > 0:
        severity_score += 5

    # Step 6: Unverified dependencies (SCA)
    if unverified_dependencies > 0:
        severity_score += 3

    # Step 7: Added-file content flags (CI triggers / shell patterns)
    if content_flags > 0:
        severity_score += min(4, content_flags * 2)

    # Step 8: Actions poisoning (CRITICAL takes priority over HIGH)
    if actions_poisoning_critical:
        severity_score += _CRITICAL_SIGNAL_SCORE
    elif actions_poisoning_flags > 0:
        severity_score += _HIGH_SIGNAL_SCORE

    # Step 9: PLI semantic consistency (L4b)
    if pli_critical:
        severity_score += _PLI_CRITICAL_SCORE
    elif pli_high:
        severity_score += _PLI_HIGH_SCORE

    # Step 10: Verdict
    if severity_score >= _DESTRUCTIVE_THRESHOLD:
        status = "DESTRUCTIVE"
    elif severity_score >= _CAUTION_THRESHOLD:
        status = "CAUTION"
    elif severity_score >= _REVIEW_THRESHOLD:
        status = "REVIEW"
    else:
        status = "SAFE"

    return {"status": status, "severity_score": severity_score}
