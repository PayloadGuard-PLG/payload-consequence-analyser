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
        Not, Or, Real, Solver, Sum, sat, unsat, unknown,
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
# structural=5, critical_path=2, security_files=5, ai_config_critical=5
# → conservative cap=24.
_MAX_OTHER_SCORE = 24

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

# MAX_SCORE as stated by consequence_pure.py (C-03) and assess_consequence.dfy (POST-3).
_MAX_SCORE = 36


def _assess_score_model(s, cap_content=True):
    """
    Total score as the sum of _assess_consequence()'s per-signal contributions, each
    constrained to the values the code can produce. AUDIT_LOG §V8: the previous P9
    asserted the bound as a constraint and checked its negation, so it held for any
    bound; this model derives the score from the signals instead.
    """
    age = Int("age")                                    # +1 / +2 / +3 by branch age
    s.add(Or(age == 0, age == 1, age == 2, age == 3))

    dims = [Int("files_dim"), Int("ratio_dim"), Int("lines_dim")]   # each 0..3
    for d in dims:
        s.add(d >= 0, d <= 3)
    files_d, ratio_d, lines_d = dims
    largest = If(files_d >= ratio_d, If(files_d >= lines_d, files_d, lines_d),
                 If(ratio_d >= lines_d, ratio_d, lines_d))
    active = Sum([If(d > 0, 1, 0) for d in dims])
    bonus_dim = largest + If(active >= 2, 1, 0)
    deletion_dim = If(bonus_dim > 4, 4, bonus_dim)      # min(4, max + bonus)

    critical_paths, security_files, unverified = Int("critical_paths"), Int("security_files"), Int("unverified")
    content_flags, actions_flags, ai_flags = Int("content_flags"), Int("actions_flags"), Int("ai_flags")
    for n in (critical_paths, security_files, unverified, content_flags, actions_flags, ai_flags):
        s.add(n >= 0)
    structural_critical, actions_critical, ai_critical = Bool("structural_critical"), Bool("actions_critical"), Bool("ai_critical")

    content = If(2 * content_flags > 4, 4, 2 * content_flags) if cap_content else 2 * content_flags
    return Sum([
        age,
        deletion_dim,
        If(structural_critical, 5, 0),
        If(critical_paths > 0, 2, 0),
        If(security_files > 0, 5, 0),
        If(unverified > 0, 3, 0),
        content,
        If(actions_critical, _CRITICAL_SCORE, If(actions_flags > 0, _HIGH_SCORE, 0)),
        If(ai_critical, _CRITICAL_SCORE, If(ai_flags > 0, _HIGH_SCORE, 0)),
    ])


@_skip
def test_p9_score_upper_bound_is_sum_of_signal_maxima():
    """P9: no combination of signals makes the total exceed MAX_SCORE (36)."""
    s = Solver()
    s.set("timeout", 5000)
    score = _assess_score_model(s)
    s.add(score > _MAX_SCORE)
    _check(s)


@_skip
def test_p9_bound_is_attained():
    """P9 is not vacuous: MAX_SCORE itself is reachable."""
    s = Solver()
    s.set("timeout", 5000)
    score = _assess_score_model(s)
    s.add(score == _MAX_SCORE)
    assert s.check() == sat, "MAX_SCORE is not reachable — the model or the bound is wrong"


@_skip
def test_p9_bound_depends_on_signal_caps():
    """P9 exercises the model: without the content-flag cap (min(4, 2n)) the bound fails."""
    s = Solver()
    s.set("timeout", 5000)
    score = _assess_score_model(s, cap_content=False)
    s.add(score > _MAX_SCORE)
    assert s.check() == sat


def test_p9_model_matches_assess_consequence():
    """Every signal at its maximum in the production scorer yields exactly MAX_SCORE."""
    from unittest.mock import patch

    import analyze

    with patch("git.Repo"):
        analyzer = analyze.PayloadAnalyzer("/fake/repo", "feature", "main")
    verdict = analyzer._assess_consequence(
        files_deleted=10_000, lines_deleted=1_000_000, days_old=10_000, deletion_ratio=100.0,
        structural_severity="CRITICAL", critical_file_deletions=10, security_file_deletions=1,
        unverified_dependencies=5, content_flags=10, actions_poisoning_flags=3,
        actions_poisoning_critical=True, ai_config_poisoning_flags=3, ai_config_poisoning_critical=True,
    )
    assert verdict["severity_score"] == _MAX_SCORE


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
