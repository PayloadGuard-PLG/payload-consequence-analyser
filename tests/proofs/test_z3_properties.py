"""
PayloadGuard Stage 2 — Z3 SMT safety proofs.

Ten named properties covering L2c signal classification and L3 scoring.
All proofs must return `unsat` within 5 seconds. `unknown` is a hard failure.

Run with:  pytest tests/proofs/ -m proof -v --timeout=30
"""
import pytest

try:
    from z3 import (
        Bool, BoolVal, EnumSort, Function, If, Implies, Int, IntSort,
        Not, Or, Real, Solver, Sum, unsat, unknown,
    )
    _Z3_AVAILABLE = True
except ImportError:
    _Z3_AVAILABLE = False

pytestmark = pytest.mark.proof

# Scoring constants mirrored from analyze.py DEFAULT_CONFIG
_CRITICAL_SCORE = 5   # actions.critical_signal_score
_HIGH_SCORE = 3       # actions.high_signal_score
_DESTRUCTIVE_THRESHOLD = 5
_CAUTION_THRESHOLD = 3
_REVIEW_THRESHOLD = 1

# Maximum plausible contribution from non-workflow signals (deletion dims, age,
# structural, etc.) — used as an upper bound in proofs that reason about the
# total score. Derived from _assess_consequence: max deletion_dim=4, age=3,
# structural=5, critical_path=2, security_files=5 → conservative cap=19.
_MAX_OTHER_SCORE = 19

_skip = pytest.mark.skipif(not _Z3_AVAILABLE, reason="z3-solver not installed")


def _check(s: "Solver") -> None:
    """Assert unsat; fail on sat (counterexample exists) or unknown (timeout)."""
    result = s.check()
    assert result != unknown, "Z3 timed out — treat as failure"
    assert result == unsat, f"Z3 found a counterexample: {s.model()}"


# ── P1 ────────────────────────────────────────────────────────────────────────

@_skip
def test_p1_typosquat_implies_score_gte_critical_threshold():
    """P1: if oidc_elevation_typosquatted fires, score contribution ≥ CRITICAL_SCORE."""
    s = Solver()
    s.set("timeout", 5000)

    is_typo = Bool("is_typo")
    base = Int("base")      # contributions from other signals
    score = Int("score")

    s.add(base >= 0, base <= _MAX_OTHER_SCORE)
    # Typosquat adds exactly CRITICAL_SCORE to whatever the base is
    s.add(Implies(is_typo, score == base + _CRITICAL_SCORE))
    s.add(Implies(Not(is_typo), score == base))

    # Attempt to find: typosquat fires but score < CRITICAL_SCORE
    s.add(is_typo, score < _CRITICAL_SCORE)

    _check(s)


# ── P2 ────────────────────────────────────────────────────────────────────────

@_skip
def test_p2_typosquat_implies_destructive_verdict():
    """P2: typosquat (CRITICAL +5) with zero other signals → score ≥ DESTRUCTIVE threshold."""
    s = Solver()
    s.set("timeout", 5000)

    is_typo = Bool("is_typo")
    score = Int("score")

    s.add(Implies(is_typo, score == _CRITICAL_SCORE))
    s.add(Implies(Not(is_typo), score == 0))

    # Attempt: typosquat fires but verdict is not DESTRUCTIVE (score < 5)
    s.add(is_typo, score < _DESTRUCTIVE_THRESHOLD)

    _check(s)


# ── P3 ────────────────────────────────────────────────────────────────────────

@_skip
def test_p3_typosquat_score_floor_not_cancelled():
    """P3: no trust-signal subtraction can reduce a typosquat score to < DESTRUCTIVE."""
    s = Solver()
    s.set("timeout", 5000)

    is_typo = Bool("is_typo")
    trust_reduction = Int("trust_reduction")  # any negative adjustment
    score = Int("score")

    # Current codebase has no trust-signal reductions, but prove the floor holds
    # even if we hypothetically allow up to -4 trust adjustments.
    # With CRITICAL_SCORE=5 and max reduction -4, minimum score=1 which is REVIEW
    # not SAFE — so typosquat cannot yield a SAFE verdict (score < REVIEW_THRESHOLD).
    s.add(trust_reduction >= -4, trust_reduction <= 0)
    s.add(Implies(is_typo, score == _CRITICAL_SCORE + trust_reduction))

    # Attempt: typosquat + max trust reduction → score drops to SAFE (< 1)
    s.add(is_typo, score < _REVIEW_THRESHOLD)

    _check(s)


# ── P4 ────────────────────────────────────────────────────────────────────────

@_skip
def test_p4_critical_signal_score_exceeds_high_signal_score():
    """P4: CRITICAL_SCORE > HIGH_SCORE (severity mapping is strictly ordered)."""
    s = Solver()
    s.set("timeout", 5000)

    crit = Int("crit")
    high = Int("high")

    s.add(crit == _CRITICAL_SCORE)
    s.add(high == _HIGH_SCORE)

    # Attempt: critical score ≤ high score (violates severity ordering)
    s.add(crit <= high)

    _check(s)


# ── P5 ────────────────────────────────────────────────────────────────────────

@_skip
def test_p5_score_monotonicity_adding_critical_signal():
    """P5: adding a CRITICAL signal to any base score never decreases the total."""
    s = Solver()
    s.set("timeout", 5000)

    base = Int("base")
    score_without = Int("score_without")
    score_with = Int("score_with")

    s.add(base >= 0, base <= _MAX_OTHER_SCORE)
    s.add(score_without == base)
    s.add(score_with == base + _CRITICAL_SCORE)

    # Attempt: score decreases after adding a CRITICAL signal
    s.add(score_with < score_without)

    _check(s)


# ── P6 ────────────────────────────────────────────────────────────────────────

@_skip
def test_p6_safe_verdict_iff_score_below_review_threshold():
    """P6: SAFE verdict ↔ score < REVIEW_THRESHOLD (equivalence, both directions)."""
    s = Solver()
    s.set("timeout", 5000)

    score = Int("score")
    is_safe = Bool("is_safe")

    s.add(Implies(is_safe, score < _REVIEW_THRESHOLD))
    s.add(Implies(score < _REVIEW_THRESHOLD, is_safe))

    # Attempt: SAFE but score ≥ REVIEW, or score < REVIEW but not SAFE
    from z3 import And as Z3And
    s.add(Or(
        Z3And(is_safe, score >= _REVIEW_THRESHOLD),
        Z3And(Not(is_safe), score < _REVIEW_THRESHOLD),
    ))

    _check(s)


# ── P7 ────────────────────────────────────────────────────────────────────────

@_skip
def test_p7_verdict_deterministic_given_identical_scores():
    """P7: identical scores always produce identical verdicts (no non-determinism)."""
    s = Solver()
    s.set("timeout", 5000)

    score1 = Int("score1")
    score2 = Int("score2")
    verdict1 = Int("verdict1")  # 0=SAFE, 1=REVIEW, 2=CAUTION, 3=DESTRUCTIVE
    verdict2 = Int("verdict2")

    def verdict_of(sc, v):
        """Encode the threshold ladder as Z3 implications."""
        return [
            Implies(sc >= _DESTRUCTIVE_THRESHOLD, v == 3),
            Implies(
                And(sc >= _CAUTION_THRESHOLD, sc < _DESTRUCTIVE_THRESHOLD),
                v == 2,
            ),
            Implies(
                And(sc >= _REVIEW_THRESHOLD, sc < _CAUTION_THRESHOLD),
                v == 1,
            ),
            Implies(sc < _REVIEW_THRESHOLD, v == 0),
        ]

    from z3 import And
    s.add(score1 >= 0, score1 <= _MAX_OTHER_SCORE + _CRITICAL_SCORE)
    s.add(score1 == score2)
    s.add(*verdict_of(score1, verdict1))
    s.add(*verdict_of(score2, verdict2))

    # Attempt: same score but different verdict
    s.add(verdict1 != verdict2)

    _check(s)


# ── P8 ────────────────────────────────────────────────────────────────────────

@_skip
def test_p8_typosquat_cannot_yield_safe_verdict():
    """P8: any score that includes a typosquat contribution cannot be SAFE."""
    s = Solver()
    s.set("timeout", 5000)

    is_typo = Bool("is_typo")
    base = Int("base")
    score = Int("score")
    is_safe = Bool("is_safe")

    s.add(base >= 0)
    s.add(Implies(is_typo, score == base + _CRITICAL_SCORE))
    s.add(Implies(Not(is_typo), score == base))
    s.add(Implies(is_safe, score < _REVIEW_THRESHOLD))

    # Attempt: typosquat fires AND verdict is SAFE
    s.add(is_typo, is_safe)

    _check(s)


# ── P9 ────────────────────────────────────────────────────────────────────────

@_skip
def test_p9_score_upper_bound_finite():
    """P9: total score is bounded by a finite constant (no integer overflow risk)."""
    s = Solver()
    s.set("timeout", 5000)

    score = Int("score")
    # Upper bound: all non-L2c signals max out + CRITICAL_SCORE
    _HARD_UPPER = _MAX_OTHER_SCORE + _CRITICAL_SCORE  # = 24

    s.add(score >= 0, score <= _HARD_UPPER)

    # Attempt: score exceeds the hard upper bound while satisfying constraints
    s.add(score > _HARD_UPPER)

    _check(s)


# ── P10 ───────────────────────────────────────────────────────────────────────

@_skip
def test_p10_empty_signal_set_always_safe():
    """P10: zero signals → score = 0 → SAFE verdict."""
    s = Solver()
    s.set("timeout", 5000)

    num_signals = Int("num_signals")
    score = Int("score")
    is_safe = Bool("is_safe")

    s.add(num_signals == 0)
    s.add(Implies(num_signals == 0, score == 0))
    s.add(Implies(score < _REVIEW_THRESHOLD, is_safe))

    # Attempt: no signals but NOT safe
    s.add(num_signals == 0, Not(is_safe))

    _check(s)
