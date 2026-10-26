"""
PayloadGuard -- CrossHair formal contract verification tests.

CrossHair is a CLI tool (not a pytest plugin). These tests shell out to the
crosshair CLI and translate exit codes to pytest outcomes:
    0  -> pass (no counterexamples found, all contracts hold)
    1  -> fail (counterexample found -- a contract was violated)
    2  -> skip (import error or environment problem)

Run specifically with:
    pytest tests/proofs/test_crosshair_contracts.py -m crosshair -v

Run the CLI directly for deeper analysis (longer timeouts):
    cd verification && crosshair check <module> \\
        --analysis_kind PEP316 --per_condition_timeout 30 \\
        --max_uninteresting_iterations 10

Modules covered:
    consequence_pure  -- Layer 3 consequence scoring (C1-C12)
    temporal_pure     -- Layer 5a temporal drift (T1-T7)
    structural_pure   -- Layer 4 structural dual-gate (S1-S7)
    semantic_pure     -- Layer 5b MCI cross-correlation (M1-M9)
"""

import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.crosshair

# Path to the verification/ directory (project root / verification)
_VERIFICATION_DIR = Path(__file__).parent.parent.parent / "verification"

_CROSSHAIR_AVAILABLE = True
try:
    result = subprocess.run(
        [sys.executable, "-m", "crosshair", "--help"],
        capture_output=True,
        timeout=10,
    )
    if result.returncode != 0:
        _CROSSHAIR_AVAILABLE = False
except (FileNotFoundError, subprocess.TimeoutExpired):
    _CROSSHAIR_AVAILABLE = False

_skip_no_crosshair = pytest.mark.skipif(
    not _CROSSHAIR_AVAILABLE,
    reason="crosshair-tool not installed (pip install crosshair-tool)",
)
_skip_no_verification = pytest.mark.skipif(
    not _VERIFICATION_DIR.exists(),
    reason="verification/ directory not found",
)


def _run_crosshair(
    target: str, per_condition_timeout: int = 10, max_iterations: int = 5
) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            sys.executable, "-m", "crosshair", "check",
            target,
            "--analysis_kind", "PEP316",
            "--per_condition_timeout", str(per_condition_timeout),
            "--max_uninteresting_iterations", str(max_iterations),
        ],
        capture_output=True,
        text=True,
        cwd=str(_VERIFICATION_DIR),
        timeout=120,
    )


def _assert_crosshair(result: subprocess.CompletedProcess, target: str) -> None:
    if result.returncode == 1:
        pytest.fail(
            f"CrossHair found a contract violation in {target}:\n{result.stdout}"
        )
    elif result.returncode == 2:
        pytest.skip(
            f"CrossHair could not import {target} (environment issue):\n{result.stderr[:400]}"
        )


# ---------------------------------------------------------------------------
# Layer 3 — Consequence scoring (consequence_pure.py)
# ---------------------------------------------------------------------------

@_skip_no_crosshair
@_skip_no_verification
def test_crosshair_deletion_dim_contracts():
    """
    _compute_deletion_dim(): result always in [0, 4].
    Three correlated deletion dimensions can never produce a score outside [0, 4].
    """
    _assert_crosshair(
        _run_crosshair("consequence_pure._compute_deletion_dim"),
        "consequence_pure._compute_deletion_dim",
    )


@_skip_no_crosshair
@_skip_no_verification
def test_crosshair_assess_consequence_contracts():
    """
    assess_consequence_pure(): C1-C12 all hold.
    verdict in {SAFE,REVIEW,CAUTION,DESTRUCTIVE}, score in [0,31],
    bijection, safety-critical implications, empty-input guarantee.
    """
    _assert_crosshair(
        _run_crosshair("consequence_pure.assess_consequence_pure", per_condition_timeout=10),
        "consequence_pure.assess_consequence_pure",
    )


# ---------------------------------------------------------------------------
# Layer 5a — Temporal drift (temporal_pure.py)
# ---------------------------------------------------------------------------

@_skip_no_crosshair
@_skip_no_verification
def test_crosshair_temporal_drift_contracts():
    """
    analyze_drift_pure(): T1-T7 all hold.
    status in {CURRENT,STALE,DANGEROUS}, drift_score >= 0,
    status-score bijection, zero-age and zero-velocity -> CURRENT.
    """
    _assert_crosshair(
        _run_crosshair("temporal_pure.analyze_drift_pure"),
        "temporal_pure.analyze_drift_pure",
    )


def _pep316_holds(func, module, kind, args, ret=None):
    """Evaluate each `pre:` or `post:` clause of func's PEP316 docstring for args."""
    env = dict(vars(module), **args, __return__=ret, implies=lambda a, b: (not a) or b)
    clauses = [
        line.strip()[len(kind) + 1:].strip()
        for line in (func.__doc__ or "").splitlines()
        if line.strip().startswith(kind + ":")
    ]
    assert clauses, f"no {kind}: clauses found"
    return [bool(eval(clause, env)) for clause in clauses]  # trusted repository source


@_skip_no_verification
def test_temporal_contract_excludes_non_finite_velocity():
    """
    AUDIT_LOG §V10: `crosshair check temporal_pure --per_condition_timeout 30` found
    analyze_drift_pure(0, inf, 0.25, 0.5) returning drift_score nan (0 * inf) with
    status CURRENT, violating T-02 and T-05. The contract domain must exclude the input
    (production raises ValueError for it), and every postcondition must hold at
    finite inputs around it. Deterministic: does not need crosshair-tool.
    """
    sys.path.insert(0, str(_VERIFICATION_DIR))
    try:
        import temporal_pure
    finally:
        sys.path.remove(str(_VERIFICATION_DIR))
    func = temporal_pure.analyze_drift_pure

    counterexample = dict(branch_age_days=0, target_velocity=float("inf"),
                          warning_threshold=0.25, critical_threshold=0.5)
    assert not all(_pep316_holds(func, temporal_pure, "pre", counterexample))

    for age, velocity in [(0, 1e308), (1, 0.25), (2, 0.25), (1, 0.5), (10**6, 1e300), (0, 0.0)]:
        args = dict(branch_age_days=age, target_velocity=velocity,
                    warning_threshold=0.25, critical_threshold=0.5)
        assert all(_pep316_holds(func, temporal_pure, "pre", args)), args
        assert all(_pep316_holds(func, temporal_pure, "post", args, func(**args))), args


# ---------------------------------------------------------------------------
# Layer 4 — Structural dual-gate (structural_pure.py)
# ---------------------------------------------------------------------------

@_skip_no_crosshair
@_skip_no_verification
def test_crosshair_structural_drift_contracts():
    """
    assess_structural_drift_pure(): S1-S7 all hold.
    DESTRUCTIVE requires BOTH ratio > threshold AND deleted >= min_count.
    No deletions and empty file always -> SAFE.
    """
    _assert_crosshair(
        _run_crosshair("structural_pure.assess_structural_drift_pure"),
        "structural_pure.assess_structural_drift_pure",
    )


# ---------------------------------------------------------------------------
# Layer 5b — Semantic MCI cross-correlation (semantic_pure.py)
# ---------------------------------------------------------------------------

@_skip_no_crosshair
@_skip_no_verification
def test_crosshair_semantic_mci_contracts():
    """
    compute_mci_pure(): M1-M9 all hold.
    status in {UNVERIFIED,TRANSPARENT,CAUTION_MISMATCH,DECEPTIVE_PAYLOAD},
    mci_score in [0,1], DECEPTIVE <-> score >= 0.5,
    no description -> UNVERIFIED, TRANSPARENT -> score == 0.0.
    """
    _assert_crosshair(
        _run_crosshair("semantic_pure.compute_mci_pure"),
        "semantic_pure.compute_mci_pure",
    )

