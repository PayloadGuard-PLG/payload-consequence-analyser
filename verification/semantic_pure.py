"""
verification/semantic_pure.py
==============================
Pure-Python extraction of SemanticTransparencyAnalyzer.analyze_transparency()
Phase 3 (Cross-Correlation Matrix) (Layer 5b) for CrossHair formal contract
verification.

Phase 1 (Linguistic Lexer) and Phase 2 (Diff Profiler) involve string operations,
regex matching, and external diff objects that CrossHair cannot symbolically
execute. This module receives their pre-computed outputs as flat parameters and
verifies the MCI aggregation and status classification logic.

Abstraction decisions:
  - V_f signal (hidden_component_modification) requires matching path fragments
    against the PR description — abstracted as `has_unacknowledged_sensitive: bool`
  - Macro-scope advisory produces CAUTION_MISMATCH with mci_score == 0.0 — a
    special case captured by the `is_macro` parameter

This module is NOT imported by production code. It is the verification target.

Verification command (run from this directory):
    crosshair check semantic_pure --analysis_kind PEP316 \\
        --per_condition_timeout 30 --max_uninteresting_iterations 10
"""


def _no_description_case() -> dict:
    """Sentinel return for empty PR description (UNVERIFIED)."""
    return {"status": "UNVERIFIED", "mci_score": 0.0}


def compute_mci_pure(
    has_description: bool,
    is_micro: bool,
    is_macro: bool,
    is_remedial_op: bool,
    total_churn: int,
    structural_alterations: int,
    ext_count: int,
    insertion_ratio: float,
    has_unacknowledged_sensitive: bool,
    churn_limit: int = 50,
    fix_ir_thresh: float = 0.9,
) -> dict:
    """
    Pure mirror of SemanticTransparencyAnalyzer.analyze_transparency() Phase 3.

    Five independent signals accumulate into mci_score, which maps to a verdict.

    Signal weights:
      V_s (scope_understated):          +0.4  if micro AND churn > churn_limit
      V_o (operation_mutation):         +0.3  if micro AND structural_alterations > 0
      V_f (hidden_component_modification): +0.3  if micro AND unacknowledged sensitive path
      V_r (phantom_additions):          +0.4  if remedial op AND insertion_ratio > fix_ir_thresh
      V_e (cross_stack_micro_claim):    +0.2  if micro AND ext_count >= 3

    Macro scope adds an advisory signal (no mci_score increase).

    pre: total_churn >= 0
    pre: structural_alterations >= 0
    pre: ext_count >= 0
    pre: 0.0 <= insertion_ratio <= 1.0
    pre: churn_limit >= 0
    pre: 0.0 <= fix_ir_thresh <= 1.0
    pre: not (is_micro and is_macro)
    post: __return__["status"] in ("UNVERIFIED", "TRANSPARENT", "CAUTION_MISMATCH", "DECEPTIVE_PAYLOAD")
    post: 0.0 <= __return__["mci_score"] <= 1.0
    post: implies(not has_description, __return__["status"] == "UNVERIFIED")
    post: implies(not has_description, __return__["mci_score"] == 0.0)
    post: implies(__return__["status"] == "UNVERIFIED", not has_description)
    post: implies(__return__["mci_score"] >= 0.5, __return__["status"] == "DECEPTIVE_PAYLOAD")
    post: implies(__return__["status"] == "DECEPTIVE_PAYLOAD", __return__["mci_score"] >= 0.5)
    post: implies(__return__["status"] == "TRANSPARENT", __return__["mci_score"] == 0.0)
    post: implies(__return__["status"] == "TRANSPARENT", not is_macro)
    """
    if not has_description:
        return _no_description_case()

    mci_score = 0.0

    # V_s — Scope Adequacy
    if is_micro and total_churn > churn_limit:
        mci_score += 0.4

    # V_o — Operation Mutation
    if is_micro and structural_alterations > 0:
        mci_score += 0.3

    # V_f — Hidden Component (pre-computed boolean: path match vs description)
    if is_micro and has_unacknowledged_sensitive:
        mci_score += 0.3

    # V_r — Phantom Additions
    if is_remedial_op and insertion_ratio > fix_ir_thresh:
        mci_score += 0.4

    # V_e — Cross-stack micro claim
    if is_micro and ext_count >= 3:
        mci_score += 0.2

    mci_score = min(round(mci_score, 3), 1.0)

    if mci_score >= 0.5:
        status = "DECEPTIVE_PAYLOAD"
    elif mci_score > 0.0 or is_macro:
        status = "CAUTION_MISMATCH"
    else:
        status = "TRANSPARENT"

    return {"status": status, "mci_score": mci_score}
