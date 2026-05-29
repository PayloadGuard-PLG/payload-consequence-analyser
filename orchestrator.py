"""
AIntegrity Core Orchestrator v4.0

Main orchestrator that coordinates all analysis modules and the
Verifiable Interaction Ledger.

Extracted from AIntegrity v4.0 Technical Specification.
"""

import uuid
import json
from typing import List, Dict, Any, Optional
from dataclasses import asdict

from .core.data_structures import (
    AuditEvent,
    EventType,
    ContentBlock,
    ModalityType,
    SessionSummary
)
from .core.vil import VerifiableInteractionLedger
from .modules.trust_grader import TrustGradingEngineV4
from .modules.threat_monitor import AdversarialThreatMonitor
from .modules.multimodal_verifier import VisualConsistencyVerifier, MediaIntegrityAssessor
from .modules.pli_analyzer import PLIAnalyzer
from .modules.llm_adapter import LLMAdapter


class AIntegrityCoreV4:
    """
    Main orchestrator for the AIntegrity v4.0 framework.

    This class coordinates:
    - Verifiable Interaction Ledger (VIL) for audit trail
    - PLI Engine for logical analysis
    - Trust Grading Engine for scoring
    - Adversarial Threat Monitor for security
    - Multimodal Verifiers for image/media verification
    """

    def __init__(
        self,
        session_id: Optional[str] = None,
        agent_id: str = "default_agent",
        baseline_data: Optional[List[str]] = None,
        enable_multimodal: bool = True,
        llm_adapter: Optional[LLMAdapter] = None,
    ):
        """
        Initialize the AIntegrity Core.

        Args:
            session_id: Unique session identifier (generated if not provided)
            agent_id: Identifier for the AI agent being audited
            baseline_data: Baseline text samples for drift detection
            enable_multimodal: Whether to enable multimodal verification
            llm_adapter: Optional LLM adapter for live model interrogation
        """
        self.session_id = session_id or str(uuid.uuid4())
        self.agent_id = agent_id

        # Initialize Verifiable Interaction Ledger
        self.vil = VerifiableInteractionLedger(self.session_id)

        # Initialize analysis modules
        self.trust_grader = TrustGradingEngineV4(agent_id=agent_id)
        self.threat_monitor = AdversarialThreatMonitor(baseline_data=baseline_data or [])
        # Optional LLM adapter for live interrogation
        self.llm_adapter = llm_adapter

        self.pli_analyzer = PLIAnalyzer(llm_adapter=llm_adapter)

        # Multimodal verifiers (optional)
        self.enable_multimodal = enable_multimodal
        if enable_multimodal:
            self.visual_verifier = VisualConsistencyVerifier()
            self.media_assessor = MediaIntegrityAssessor()
        else:
            self.visual_verifier = None
            self.media_assessor = None

        # Session state
        self.turn_count = 0
        self.session_active = True

        print(f"AIntegrity Core v4.0 initialized. Session: {self.session_id[:8]}...")

    def _create_content_block(self, text: str) -> ContentBlock:
        """Create a text content block."""
        return ContentBlock(
            modality=ModalityType.TEXT,
            data=text,
            metadata={"length": len(text)}
        )

    def _analyze_text(self, text: str, is_input: bool = True) -> Dict[str, Any]:
        """
        Run text analysis including threat monitoring and basic NLP.

        Args:
            text: Text to analyze
            is_input: Whether this is user input (vs model output)

        Returns:
            Analysis results
        """
        results: Dict[str, Any] = {}

        # Threat monitoring
        threat_result = self.threat_monitor.monitor_single(text, is_input=is_input)
        results["threat_analysis"] = threat_result

        # Basic text metrics
        results["text_metrics"] = {
            "length": len(text),
            "word_count": len(text.split()),
            "sentence_count": text.count('.') + text.count('!') + text.count('?')
        }

        return results

    def log_user_input(
        self,
        text: str,
        parent_event_id: Optional[str] = None,
        actor_id: str = "user"
    ) -> AuditEvent:
        """
        Log a user input event.

        Args:
            text: User input text
            parent_event_id: ID of parent event (for threading)
            actor_id: User identifier

        Returns:
            The logged AuditEvent
        """
        if not self.session_active:
            raise RuntimeError("Session has been sealed. Cannot log new events.")

        # Analyze input
        analysis = self._analyze_text(text, is_input=True)

        # Create and log event
        event = AuditEvent(
            event_type=EventType.USER_INPUT,
            actor_id=actor_id,
            content_blocks=[self._create_content_block(text)],
            analysis_payload=analysis,
            parent_event_id=parent_event_id
        )

        logged_event = self.vil.log_event(event)
        self.turn_count += 1

        # Alert on threats
        if analysis["threat_analysis"].get("is_alert"):
            print(f"ALERT: Potential threat detected in user input!")

        return logged_event

    def log_model_output(
        self,
        text: str,
        parent_event_id: Optional[str] = None,
        model_id: str = "ai_model"
    ) -> AuditEvent:
        """
        Log a model output event.

        Args:
            text: Model output text
            parent_event_id: ID of parent event (user input)
            model_id: Model identifier

        Returns:
            The logged AuditEvent
        """
        if not self.session_active:
            raise RuntimeError("Session has been sealed. Cannot log new events.")

        # Analyze output
        analysis = self._analyze_text(text, is_input=False)

        # Create and log event
        event = AuditEvent(
            event_type=EventType.MODEL_OUTPUT,
            actor_id=model_id,
            content_blocks=[self._create_content_block(text)],
            analysis_payload=analysis,
            parent_event_id=parent_event_id
        )

        logged_event = self.vil.log_event(event)

        # Alert on evasion
        if analysis["threat_analysis"].get("is_alert"):
            print(f"ALERT: Potential evasion detected in model output!")

        return logged_event

    def process_turn(
        self,
        user_text: str,
        model_text: str,
        parent_event_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Process a complete conversation turn (user input + model response).

        Args:
            user_text: User input
            model_text: Model response
            parent_event_id: ID of previous turn's model output

        Returns:
            Turn analysis including events and trust score
        """
        # Log user input
        user_event = self.log_user_input(user_text, parent_event_id)

        # Log model output
        model_event = self.log_model_output(model_text, user_event.event_id)

        # Run PLI logical consistency analysis
        pli_result = self.pli_analyzer.analyze_turn(user_text, model_text)

        # Log PLI analysis event
        pli_event = AuditEvent(
            event_type=EventType.LOGICAL_ANALYSIS,
            actor_id="aintegrity",
            analysis_payload=pli_result,
            parent_event_id=model_event.event_id
        )
        self.vil.log_event(pli_event)

        # Calculate trust score using real PLI consistency score
        analysis_results = {
            "logical_analysis": {"consistency_score": pli_result["consistency_score"]},
            "adversarial_threat": model_event.analysis_payload.get("threat_analysis", {})
        }
        trust_result = self.trust_grader.calculate_trust_score(analysis_results)

        # Log trust grading event
        trust_event = AuditEvent(
            event_type=EventType.TRUST_GRADING,
            actor_id="aintegrity",
            analysis_payload=trust_result,
            parent_event_id=model_event.event_id
        )
        self.vil.log_event(trust_event)

        return {
            "turn_number": self.turn_count,
            "user_event_id": user_event.event_id,
            "model_event_id": model_event.event_id,
            "trust_score": trust_result["overall_score_instantaneous"],
            "trust_grade": self.trust_grader.get_grade(trust_result["overall_score_instantaneous"] * 100),
            "alerts": {
                "user_input": user_event.analysis_payload["threat_analysis"].get("is_alert", False),
                "model_output": model_event.analysis_payload["threat_analysis"].get("is_alert", False)
            }
        }

    def verify_image_text(
        self,
        image_data: bytes,
        text: str,
        parent_event_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Verify consistency between an image and text description.

        Args:
            image_data: Image bytes
            text: Text description
            parent_event_id: Parent event ID

        Returns:
            Verification results
        """
        if not self.visual_verifier:
            return {"status": "DISABLED", "reason": "Multimodal verification disabled"}

        result = self.visual_verifier.verify(image_data, text)

        # Log the verification event
        event = AuditEvent(
            event_type=EventType.VISUAL_CONSISTENCY_ANALYSIS,
            actor_id="aintegrity",
            analysis_payload=result,
            parent_event_id=parent_event_id
        )
        self.vil.log_event(event)

        return result

    def assess_media_integrity(
        self,
        media_data: bytes,
        media_type: str = "image",
        parent_event_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Assess the integrity of media content.

        Args:
            media_data: Media bytes
            media_type: Type of media
            parent_event_id: Parent event ID

        Returns:
            Integrity assessment results
        """
        if not self.media_assessor:
            return {"status": "DISABLED", "reason": "Multimodal verification disabled"}

        result = self.media_assessor.assess(media_data, media_type)

        # Log the assessment event
        event = AuditEvent(
            event_type=EventType.MEDIA_INTEGRITY_ANALYSIS,
            actor_id="aintegrity",
            analysis_payload=result,
            parent_event_id=parent_event_id
        )
        self.vil.log_event(event)

        return result

    def interrogate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        parent_event_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Send a prompt to the attached LLM and audit the response.

        Requires an ``llm_adapter`` to have been provided at init time.

        Args:
            prompt: The interrogation prompt
            system_prompt: Optional system-level instruction
            parent_event_id: Parent event ID for threading

        Returns:
            Turn result (same shape as process_turn) plus llm_response metadata
        """
        if self.llm_adapter is None:
            raise RuntimeError(
                "No LLM adapter configured. Pass llm_adapter= to __init__ "
                "or use LLMAdapter.create() to build one."
            )

        response = self.llm_adapter.query(
            prompt, system_prompt=system_prompt
        )

        turn_result = self.process_turn(
            user_text=prompt,
            model_text=response.text,
            parent_event_id=parent_event_id,
        )
        turn_result["llm_response"] = {
            "model": response.model,
            "provider": response.provider,
            "latency_ms": response.latency_ms,
            "usage": response.usage,
        }
        return turn_result

    def get_session_status(self) -> Dict[str, Any]:
        """Get current session status."""
        return {
            "session_id": self.session_id,
            "turn_count": self.turn_count,
            "event_count": len(self.vil.events),
            "current_trust_score": self.trust_grader.get_current_trust_score(),
            "session_active": self.session_active
        }

    def seal_session(self) -> SessionSummary:
        """
        Seal the session and anchor it.

        Returns:
            Session summary with cryptographic proofs
        """
        if not self.session_active:
            raise RuntimeError("Session already sealed.")

        self.session_active = False
        summary = self.vil.seal_and_anchor_session()

        print("\n--- SESSION SEALED ---")
        print(f"Session ID: {summary.session_id}")
        print(f"Events: {summary.event_count}")
        print(f"Merkle Root: {summary.merkle_root[:16]}...")

        return summary

    def verify_integrity(self) -> Dict[str, Any]:
        """Verify the integrity of the audit trail."""
        return self.vil.verify_chain_integrity()

    def export_audit_log(self, format: str = "json") -> str:
        """
        Export the audit log.

        Args:
            format: Export format ("json" or "pretty")

        Returns:
            Serialized audit log
        """
        log = self.vil.export_log()

        if format == "pretty":
            return json.dumps(log, indent=2)
        return json.dumps(log)

    def generate_report(self) -> Dict[str, Any]:
        """
        Generate a comprehensive audit report.

        Returns:
            Audit report dictionary
        """
        integrity = self.verify_integrity()
        trust_history = self.trust_grader.history

        # Count findings
        threat_count = 0
        evasion_count = 0
        for event in self.vil.events:
            threat_info = event.analysis_payload.get("threat_analysis", {})
            if threat_info.get("is_alert"):
                if event.event_type == EventType.USER_INPUT:
                    threat_count += 1
                else:
                    evasion_count += 1

        pli_summary = self.pli_analyzer.get_summary()

        return {
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "summary": {
                "total_turns": self.turn_count,
                "total_events": len(self.vil.events),
                "threat_alerts": threat_count,
                "evasion_alerts": evasion_count,
                "logical_contradictions": pli_summary["total_contradictions"],
                "logical_evasions": pli_summary["total_evasions"],
                "consistency_score": pli_summary["final_consistency_score"],
                "final_trust_score": self.trust_grader.get_current_trust_score(),
                "final_grade": self.trust_grader.get_grade(),
                "chain_integrity": integrity["valid"]
            },
            "trust_history": [
                {
                    "timestamp": h["calculation_timestamp_utc"],
                    "score": h["overall_score_instantaneous"]
                }
                for h in trust_history
            ],
            "pli_findings": pli_summary,
            "integrity_check": integrity
        }
