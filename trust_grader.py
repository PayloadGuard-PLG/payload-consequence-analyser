"""
Dynamic Trust Scoring Engine v4.0

Calculates a dynamic, multi-dimensional trust score with temporal decay.
Extracted from AIntegrity v4.0 Technical Specification.
"""

import math
import time
import datetime
from typing import Dict, Any, Optional


class TrustDecayModel:
    """
    Models the temporal decay of a trust score.

    Trust is not a permanent state; it decays over time in the absence
    of reinforcing evidence. Uses a logistic function for smooth,
    S-shaped decay that levels off at a baseline.

    Mathematical formulation:
        T(t) = T_min + (T_max - T_min) / (1 + e^(k(t - t_mid)))

    Where:
        T(t)   = trust score at time t
        T_max  = maximum trust score (from last successful interaction)
        T_min  = asymptotic minimum trust score (baseline distrust)
        k      = decay rate constant
        t      = time elapsed since last interaction
        t_mid  = midpoint of decay (time of most rapid decay)
    """

    def __init__(
        self,
        decay_rate: float = 0.01,
        min_score: float = 0.2,
        midpoint_days: float = 30.0
    ):
        """
        Initialize the trust decay model.

        Args:
            decay_rate: How quickly trust erodes (k parameter)
            min_score: Baseline minimum trust level (0-1)
            midpoint_days: Days until trust decay is most rapid
        """
        self.k = decay_rate
        self.t_mid = midpoint_days * 86400  # Convert days to seconds
        self.t_min = min_score
        self.t_max = 1.0
        self.last_update_timestamp = time.time()

    def update_score(self, new_score: float):
        """
        Reset the decay model with a new score.

        Called after a positive interaction to reset the clock.

        Args:
            new_score: The new trust score (0-1)
        """
        self.t_max = max(0.0, min(1.0, new_score))
        self.last_update_timestamp = time.time()

    def apply_penalty(self, penalty_factor: float = 0.1):
        """
        Apply an immediate penalty to the trust score.

        Called after a negative event (contradiction, violation).

        Args:
            penalty_factor: How much to reduce t_max (0-1)
        """
        self.t_max = max(self.t_min, self.t_max - penalty_factor)

    def increase_decay_rate(self, multiplier: float = 1.5):
        """
        Increase the decay rate after a trust breach.

        Trust is harder to maintain after a breach.

        Args:
            multiplier: Factor to multiply decay rate by
        """
        self.k *= multiplier

    def get_current_score(self) -> float:
        """
        Calculate the decayed score based on elapsed time.

        Returns:
            Current trust score after applying temporal decay (0-1)
        """
        elapsed_time = time.time() - self.last_update_timestamp

        # Logistic decay function
        try:
            exponent = self.k * (elapsed_time - self.t_mid)
            # Clamp exponent to avoid overflow
            exponent = max(-700, min(700, exponent))
            denominator = 1 + math.exp(exponent)
            decayed_score = self.t_min + (self.t_max - self.t_min) / denominator
        except (OverflowError, ValueError):
            decayed_score = self.t_min

        return max(self.t_min, decayed_score)

    def get_state(self) -> Dict[str, Any]:
        """Returns the current state of the decay model."""
        return {
            "t_max": self.t_max,
            "t_min": self.t_min,
            "decay_rate": self.k,
            "midpoint_seconds": self.t_mid,
            "last_update": self.last_update_timestamp,
            "current_score": self.get_current_score()
        }


class TrustGradingEngineV4:
    """
    Calculates a dynamic, multi-dimensional trust score for an AI agent or session.

    Version: 4.0

    Components:
        - logical_consistency: From PLI/contradiction analysis
        - factual_accuracy: From citation verification
        - visual_consistency: From CLIP-based image-text verification
        - behavioral_stability: From session drift detection
        - adversarial_resistance: From threat monitoring
    """

    DEFAULT_WEIGHTS = {
        "logical_consistency": 0.25,
        "factual_accuracy": 0.20,
        "visual_consistency": 0.15,
        "behavioral_stability": 0.20,
        "adversarial_resistance": 0.20
    }

    def __init__(
        self,
        agent_id: str,
        initial_weights: Optional[Dict[str, float]] = None
    ):
        """
        Initialize the trust grading engine.

        Args:
            agent_id: Identifier for the AI agent being scored
            initial_weights: Custom component weights (must sum to 1.0)
        """
        self.agent_id = agent_id
        self.decay_model = TrustDecayModel()
        self.weights = initial_weights or self.DEFAULT_WEIGHTS.copy()
        self.history: list = []

    def calculate_trust_score(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculates a comprehensive trust score from various analysis module outputs.

        Args:
            analysis_results: Dictionary containing outputs from analysis modules
                Expected keys:
                    - logical_analysis: {"consistency_score": 0-1}
                    - citation_analysis: {"verifiability_score": 0-1}
                    - visual_consistency: {"consistency_score": 0-1}
                    - session_drift: {"max_severity": 0-1}
                    - adversarial_threat: {"threat_level": 0-1}

        Returns:
            Dictionary with trust score breakdown and metadata
        """
        # Extract component scores (default to 1.0 if not provided)
        components = {
            "logical_consistency": analysis_results.get(
                "logical_analysis", {}
            ).get("consistency_score", 1.0),

            "factual_accuracy": analysis_results.get(
                "citation_analysis", {}
            ).get("verifiability_score", 1.0),

            "visual_consistency": analysis_results.get(
                "visual_consistency", {}
            ).get("consistency_score", 1.0),

            "behavioral_stability": 1.0 - analysis_results.get(
                "session_drift", {}
            ).get("max_severity", 0.0),

            "adversarial_resistance": 1.0 - analysis_results.get(
                "adversarial_threat", {}
            ).get("threat_level", 0.0)
        }

        # Ensure all values are in valid range
        components = {k: max(0.0, min(1.0, v)) for k, v in components.items()}

        # Calculate weighted overall score
        weighted_sum = sum(
            self.weights.get(k, 0) * v
            for k, v in components.items()
            if v is not None
        )
        total_weight = sum(
            self.weights.get(k, 0)
            for k, v in components.items()
            if v is not None
        )

        overall_score = weighted_sum / total_weight if total_weight > 0 else 0.0

        # Update the decay model with this new score
        self.decay_model.update_score(overall_score)

        result = {
            "agent_id": self.agent_id,
            "overall_score_instantaneous": overall_score,
            "overall_score_decayed": self.decay_model.get_current_score(),
            "components": components,
            "weights": self.weights,
            "calculation_timestamp_utc": datetime.datetime.utcnow().isoformat() + "Z"
        }

        # Track history
        self.history.append(result)

        return result

    def apply_event_penalty(self, event_type: str, severity: float = 0.1):
        """
        Apply a penalty based on a negative event.

        Args:
            event_type: Type of negative event (e.g., "contradiction", "violation")
            severity: Severity of the penalty (0-1)
        """
        self.decay_model.apply_penalty(severity)
        if event_type in ["deception_proven", "source_disproven"]:
            self.decay_model.increase_decay_rate(1.5)

    def get_current_trust_score(self) -> float:
        """Returns the current, time-decayed trust score."""
        return self.decay_model.get_current_score()

    def get_grade(self, score: Optional[float] = None) -> str:
        """
        Convert a numeric score to a letter grade.

        Args:
            score: Score to grade (0-100), uses current score if not provided

        Returns:
            Letter grade (A, B, C, D, or E)
        """
        if score is None:
            score = self.get_current_trust_score() * 100

        if score >= 80:
            return "A"
        elif score >= 60:
            return "B"
        elif score >= 40:
            return "C"
        elif score >= 20:
            return "D"
        else:
            return "E"

    def get_risk_level(
        self,
        score: Optional[float] = None,
        critical_count: int = 0,
        high_count: int = 0,
        medium_count: int = 0,
        deception_count: int = 0,
        disproven_count: int = 0
    ) -> str:
        """
        Calculate risk level based on score and finding counts.

        Returns:
            Risk level: "minimal", "low", "medium", "high", or "critical"
        """
        if score is None:
            score = self.get_current_trust_score() * 100

        if disproven_count > 0 or deception_count >= 2 or critical_count >= 3:
            return "critical"
        elif deception_count >= 1 or critical_count >= 2:
            return "high"
        elif score < 50 or high_count >= 2 or medium_count >= 3:
            return "medium"
        elif score < 70 or medium_count > 0:
            return "low"
        else:
            return "minimal"
