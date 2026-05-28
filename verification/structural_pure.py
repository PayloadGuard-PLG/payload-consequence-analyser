"""
verification/structural_pure.py
================================
Pure-Python extraction of the dual-gate scoring logic in
StructuralPayloadAnalyzer.analyze_structural_drift() (Layer 4)
for CrossHair formal contract verification.

The AST parsing (structural_parser.extract_named_nodes) is external I/O and
cannot be symbolically executed by CrossHair. This module receives pre-computed
node counts as inputs and verifies the classification logic only.

This module is NOT imported by production code. It is the verification target.

Verification command (run from this directory):
    crosshair check structural_pure --analysis_kind PEP316 \\
        --per_condition_timeout 30 --max_uninteresting_iterations 10
"""


def assess_structural_drift_pure(
    original_count: int,
    deleted_count: int,
    deletion_ratio_threshold: float = 0.20,
    min_deletion_count: int = 3,
) -> dict:
    """
    Pure mirror of StructuralPayloadAnalyzer.analyze_structural_drift() verdict logic.

    DESTRUCTIVE requires BOTH conditions simultaneously (dual-gate):
      1. deletion_ratio > deletion_ratio_threshold
      2. deleted_count >= min_deletion_count

    This prevents false positives on tiny files where removing 1 of 2 functions
    is a 50% ratio but clearly not catastrophic.

    pre: original_count >= 0
    pre: 0 <= deleted_count <= original_count
    pre: 0.0 < deletion_ratio_threshold < 1.0
    pre: min_deletion_count >= 1
    post: __return__["status"] in ("DESTRUCTIVE", "SAFE")
    post: 0.0 <= __return__["deletion_ratio"] <= 1.0
    post: implies(__return__["status"] == "DESTRUCTIVE", __return__["deletion_ratio"] > deletion_ratio_threshold)
    post: implies(__return__["status"] == "DESTRUCTIVE", deleted_count >= min_deletion_count)
    post: implies(deleted_count == 0, __return__["status"] == "SAFE")
    post: implies(original_count == 0, __return__["status"] == "SAFE")
    post: implies(__return__["status"] == "SAFE", not (deleted_count >= min_deletion_count and __return__["deletion_ratio"] > deletion_ratio_threshold))
    """
    deletion_ratio = deleted_count / original_count if original_count > 0 else 0.0

    is_destructive = (
        deletion_ratio > deletion_ratio_threshold
        and deleted_count >= min_deletion_count
    )

    return {
        "status": "DESTRUCTIVE" if is_destructive else "SAFE",
        "deletion_ratio": deletion_ratio,
    }
