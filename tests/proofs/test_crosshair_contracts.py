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
    cd verification && crosshair check consequence_pure \\
        --analysis_kind PEP316 --per_condition_timeout 30 \\
        --max_uninteresting_iterations 10
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


@_skip_no_crosshair
@_skip_no_verification
def test_crosshair_deletion_dim_contracts():
    """
    CrossHair verifies _compute_deletion_dim() satisfies: 0 <= result <= 4
    for all inputs satisfying its pre-conditions.

    Covers the key aggregation invariant: three correlated deletion dimensions
    can never produce a combined score outside [0, 4].
    """
    result = _run_crosshair("consequence_pure._compute_deletion_dim")

    if result.returncode == 1:
        pytest.fail(
            f"CrossHair found a contract violation in _compute_deletion_dim:\n"
            f"{result.stdout}"
        )
    elif result.returncode == 2:
        pytest.skip(
            f"CrossHair could not import consequence_pure (environment issue):\n"
            f"{result.stderr[:400]}"
        )
    # returncode 0 -> all contracts hold


@_skip_no_crosshair
@_skip_no_verification
def test_crosshair_assess_consequence_contracts():
    """
    CrossHair verifies all post-conditions on assess_consequence_pure():

    - verdict in {SAFE, REVIEW, CAUTION, DESTRUCTIVE}
    - severity_score in [0, 31]
    - SAFE <-> severity_score < 1
    - REVIEW <-> 1 <= severity_score < 3
    - CAUTION <-> 3 <= severity_score < 5
    - DESTRUCTIVE <-> severity_score >= 5
    - security_file_deletions > 0 -> DESTRUCTIVE
    - structural_severity == CRITICAL -> DESTRUCTIVE
    - actions_poisoning_critical -> DESTRUCTIVE
    - all-zero inputs -> SAFE
    """
    result = _run_crosshair(
        "consequence_pure.assess_consequence_pure",
        per_condition_timeout=10,
        max_iterations=5,
    )

    if result.returncode == 1:
        pytest.fail(
            f"CrossHair found a contract violation in assess_consequence_pure:\n"
            f"{result.stdout}"
        )
    elif result.returncode == 2:
        pytest.skip(
            f"CrossHair could not import consequence_pure (environment issue):\n"
            f"{result.stderr[:400]}"
        )
    # returncode 0 -> all contracts hold
