"""
consequence_engine.py — Semantic Change Graph (SCG) & Differential Consequence Engine
=====================================================================================

Advances PayloadGuard from flat lexical/count heuristics to an evidence-driven,
multi-language code consequence analysis system (`consequence.v1`).

Core Capabilities & Detectors:
  - D01_PARSER_INCOMPLETE: Explicit epistemic tracking when syntax errors, missing
    grammars, or unsupported extensions prevent complete structural analysis.
  - D02_STRUCTURAL_DELTA & D02_BODY_WEAKENING: 5-stage container-aware symbol
    matching across files (distinguishing pure renames and cross-file moves from
    true deletions and body gutting/stubbing).
  - D03_COMPOUND_LOSS: Cross-file distributed symbol deletion (A03) and
    sub-threshold padding/dilution gaming (A06) corroborated by public/security
    symbol loss, guard removal, or broken callers.
  - D04_PUBLIC_API_BREAK: Exported/public symbol removal, visibility reduction,
    incompatible signature tightening, and bounded repository-wide unresolved
    caller verification in head.
  - D05_BUILD_DEPENDENCY_DELTA: Manifest changes without corresponding lockfile
    updates and suspicious build/lifecycle script mutations.
  - D06_GUARD_REGRESSION: Removal of authentication, authorization, validation,
    rate-limit, or transaction-rollback guards from surviving functions/methods.
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from structural_parser import (
    PARSER_STATUS_AVAILABLE,
    PARSER_STATUS_GRAMMAR_UNAVAILABLE,
    PARSER_STATUS_PARSE_ERROR,
    PARSER_STATUS_UNSUPPORTED_EXTENSION,
    CallSiteFact,
    ParseResult,
    SymbolFact,
    build_capability_vector,
    extract_symbols,
    language_for_path,
)

CAPABILITY_AVAILABLE = "available"
CAPABILITY_PARTIAL = "partial"
CAPABILITY_UNAVAILABLE = "unavailable"
CAPABILITY_FAILED = "failed"

CONSEQUENCE_SCHEMA_VERSION = "consequence.v1"

# Epistemic tiers
TIER_VERIFIED = "VERIFIED_CONSEQUENCE"
TIER_LIKELY = "LIKELY_CONSEQUENCE"
TIER_INCOMPLETE = "INCOMPLETE_ANALYSIS"
TIER_INFORMATIONAL = "INFORMATIONAL"

# Confidence levels
CONFIDENCE_HIGH = "HIGH"
CONFIDENCE_MEDIUM = "MEDIUM"
CONFIDENCE_LOW = "LOW"
CONFIDENCE_UNKNOWN = "UNKNOWN"

# Severities
SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"
SEVERITY_INFO = "INFORMATIONAL"

# Policy recommendations
POLICY_BLOCK = "BLOCK"
POLICY_REVIEW = "REVIEW"
POLICY_WARN = "WARN"
POLICY_PASS = "PASS"

# Detector IDs
DETECTOR_D01_PARSER = "D01_PARSER_INCOMPLETE"
DETECTOR_D02_WEAKENING = "D02_BODY_WEAKENING"
DETECTOR_D02_DELTA = "D02_STRUCTURAL_DELTA"
DETECTOR_D02_AMBIGUOUS = "D02_AMBIGUOUS_REFACTOR"
DETECTOR_D03_COMPOUND = "D03_COMPOUND_LOSS"
DETECTOR_D04_API = "D04_PUBLIC_API_BREAK"
DETECTOR_D05_BUILD = "D05_BUILD_DEPENDENCY_DELTA"
DETECTOR_D06_GUARD = "D06_GUARD_REGRESSION"

# Security & Integrity Guard / Critical Symbol Vocabulary
_SECURITY_SYMBOL_TOKENS = frozenset({
    "auth", "authenticate", "authorize", "login", "logout", "logout_all",
    "revoke", "revoke_all", "deactivate", "validate", "verify", "verify_password",
    "hash_password", "check_rate_limit", "rate_limit", "permission", "permissions",
    "csrf", "sanitize", "escape", "encrypt", "decrypt", "rollback", "_rollback",
    "audit", "send_alert", "sendalert", "write_error", "writeerror", "token",
    "session", "guard", "policy", "signature", "acl", "rbac",
})

_GUARD_CALL_PATTERNS = frozenset({
    "validate", "verify", "verify_password", "authenticate", "authorize",
    "check_permission", "check_permissions", "require_auth", "require_role",
    "check_rate_limit", "_check_rate_limit", "rollback", "_rollback",
    "sanitize", "escape", "check_csrf", "verify_token", "verify_signature",
    "assert_authorized", "enforce_policy",
})

_GUARD_DECORATOR_PATTERNS = frozenset({
    "login_required", "permission_required", "requires_auth", "require_auth",
    "authenticated", "authorize", "roles_allowed", "preauthorize", "secured",
    "csrf_protect", "rate_limit", "ratelimit", "validate_input", "transactional",
})

# Manifest -> Expected Lockfiles mapping for D05
_MANIFEST_LOCKFILE_PAIRS: Dict[str, Tuple[str, ...]] = {
    "package.json": ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", "npm-shrinkwrap.json"),
    "Cargo.toml": ("Cargo.lock",),
    "go.mod": ("go.sum",),
    "pyproject.toml": ("poetry.lock", "uv.lock", "pdm.lock", "Pipfile.lock", "requirements.lock"),
    "Pipfile": ("Pipfile.lock",),
    "Gemfile": ("Gemfile.lock",),
    "composer.json": ("composer.lock",),
}

_SUSPICIOUS_LIFECYCLE_HOOKS = frozenset({
    "preinstall", "install", "postinstall", "prepublish", "prepare",
})

_SUSPICIOUS_SCRIPT_PATTERNS = re.compile(
    r"(?:curl\s+[^\n|]*\|\s*(?:ba)?sh|wget\s+[^\n|]*\|\s*(?:ba)?sh|"
    r"rm\s+-rf\s+(?:/|\$|--no-preserve-root)|chmod\s+\+x\s+/tmp/|"
    r"nc\s+-e\s+|bash\s+-i\s+>&\s*/dev/tcp/|python[23]?\s+-c\s+['\"].*socket|"
    r"node\s+-e\s+['\"].*child_process|base64\s+-d\s*\|)",
    re.IGNORECASE,
)


def _is_security_relevant_name(name: str) -> bool:
    """Return True if a symbol or method name matches security/integrity domains."""
    lowered = name.lower()
    parts = [p for p in re.split(r"[._/:\-]+", lowered) if p]
    for p in parts:
        if p in _SECURITY_SYMBOL_TOKENS:
            return True
        # CamelCase split
        camel_tokens = [t.lower() for t in re.findall(r"[A-Z]?[a-z0-9]+|[A-Z]+(?=[A-Z]|$)", p)]
        if any(t in _SECURITY_SYMBOL_TOKENS for t in camel_tokens):
            return True
    return False


def _is_guard_call(call_expr: str) -> bool:
    """Return True if a call expression invokes a security, validation, or rollback guard."""
    base = call_expr.rsplit(".", 1)[-1].rsplit("::", 1)[-1].lower()
    if base in _GUARD_CALL_PATTERNS:
        return True
    return any(tok in base for tok in ("validate", "verify", "authorize", "authenticate", "rollback", "rate_limit", "sanitize", "csrf"))


def _is_guard_decorator(deco: str) -> bool:
    """Return True if a decorator represents an auth/security/validation guard."""
    cleaned = deco.lstrip("@#[").split("(")[0].split(".")[-1].lower().strip()
    if cleaned in _GUARD_DECORATOR_PATTERNS:
        return True
    return any(tok in cleaned for tok in ("auth", "login", "permission", "role", "csrf", "rate_limit", "secure"))


@dataclass(frozen=True)
class FileDeltaInput:
    """Input representation of a changed file between base and head."""
    file_path: str
    old_path: Optional[str] = None
    change_type: str = "M"  # 'A', 'D', 'M', 'R'
    base_source: Optional[str] = None
    head_source: Optional[str] = None
    lines_added: int = 0
    lines_deleted: int = 0


@dataclass(frozen=True)
class SymbolTransition:
    """Represents a matched or unmatched symbol transition in the SCG."""
    transition_kind: str  # UNCHANGED, MODIFIED, RENAMED, MOVED, GUTTED, RENAMED_AND_GUTTED, MOVED_AND_GUTTED, REMOVED, ADDED, AMBIGUOUS
    base_symbol: Optional[SymbolFact] = None
    head_symbol: Optional[SymbolFact] = None
    match_stage: int = 0
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "transition_kind": self.transition_kind,
            "match_stage": self.match_stage,
            "reason": self.reason,
            "base_symbol_id": self.base_symbol.symbol_id if self.base_symbol else None,
            "head_symbol_id": self.head_symbol.symbol_id if self.head_symbol else None,
            "base_qualified_name": self.base_symbol.qualified_name if self.base_symbol else None,
            "head_qualified_name": self.head_symbol.qualified_name if self.head_symbol else None,
            "kind": (self.head_symbol or self.base_symbol).kind if (self.head_symbol or self.base_symbol) else None,
        }


@dataclass(frozen=True)
class EvidenceItem:
    """Deterministic, auditable evidence item attached to a ConsequenceFinding."""
    kind: str
    file: str
    line: Optional[int] = None
    symbol: Optional[str] = None
    detail: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "file": self.file,
            "line": self.line,
            "symbol": self.symbol,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class ConsequenceFinding:
    """Standardized consequence finding produced by the SCG differential engine."""
    finding_id: str
    detector_id: str
    consequence_class: str
    tier: str
    confidence: str
    severity: str
    policy_recommendation: str
    summary: str
    affected_files: Tuple[str, ...]
    affected_symbols: Tuple[str, ...]
    evidence: Tuple[EvidenceItem, ...]
    remediation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "detector_id": self.detector_id,
            "consequence_class": self.consequence_class,
            "tier": self.tier,
            "confidence": self.confidence,
            "severity": self.severity,
            "policy_recommendation": self.policy_recommendation,
            "summary": self.summary,
            "affected_files": list(self.affected_files),
            "affected_symbols": list(self.affected_symbols),
            "evidence": [e.to_dict() for e in self.evidence],
            "remediation": self.remediation,
        }


@dataclass
class ConsequenceReport:
    """Top-level consequence analysis report (`consequence.v1`)."""
    schema_version: str = CONSEQUENCE_SCHEMA_VERSION
    mode: str = "shadow"
    recommended_verdict: str = "SAFE"
    recommended_score: float = 0.0
    capabilities: Dict[str, Dict[str, str]] = field(default_factory=dict)
    parser_completeness: Dict[str, Any] = field(default_factory=dict)
    graph_summary: Dict[str, Any] = field(default_factory=dict)
    findings: List[ConsequenceFinding] = field(default_factory=list)
    stage_timing_ms: Dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "mode": self.mode,
            "recommended_verdict": self.recommended_verdict,
            "recommended_score": round(self.recommended_score, 4),
            "capabilities": self.capabilities,
            "parser_completeness": self.parser_completeness,
            "graph_summary": self.graph_summary,
            "findings": [f.to_dict() for f in self.findings],
            "stage_timing_ms": {k: round(v, 3) for k, v in self.stage_timing_ms.items()},
        }


# ==============================================================================
# 5-STAGE SYMBOL MATCHING PIPELINE
# ==============================================================================

def _is_body_weakened(base: SymbolFact, head: SymbolFact) -> Tuple[bool, str]:
    """
    Determine whether a matched symbol's implementation was gutted or weakened.
    """
    if base.kind not in ("function", "method", "class", "struct"):
        return False, ""
    if not base.is_stub and head.is_stub:
        return True, (
            f"Non-stub {base.kind} '{base.qualified_name}' ({base.statement_count} stmts) "
            f"was replaced with a no-op stub in '{head.qualified_name}'"
        )
    # Severe statement & call collapse (e.g. multi-statement logic with calls replaced by 1-line constant return)
    if (
        base.statement_count >= 3
        and head.statement_count <= 1
        and base.body_hash != head.body_hash
        and len(base.calls) >= 1
        and len(head.calls) == 0
    ):
        return True, (
            f"{base.kind.capitalize()} '{base.qualified_name}' collapsed from "
            f"{base.statement_count} statements ({len(base.calls)} calls) to "
            f"{head.statement_count} statement with 0 calls"
        )
    return False, ""


def match_symbols_5_stage(
    base_symbols: List[SymbolFact],
    head_symbols: List[SymbolFact],
    renamed_file_map: Optional[Dict[str, str]] = None,
) -> Tuple[List[SymbolTransition], Dict[str, str]]:
    """
    Execute the deterministic 5-stage symbol matching pipeline across base and head symbols.

    Stages:
      1. Exact symbol_id & kind match (same file path, same qualified_name, same kind).
      2. Git-renamed file exact qualified_name & kind match.
      3. Cross-file moved symbol match (same language, kind, name/qualified_name, signature/body).
      4. Container-aware & body-hash rename match:
         4a. Container (class/struct/interface/trait) rename corroborated by body_hash or >=50% child method match,
             cascading to member methods.
         4b. Same-scope function/method/constant rename with identical body_hash and normalized_signature.
         4c. Same-scope or cross-file replacement where signature matches or single replacement is stubbed.
      5. Residual unmatched REMOVED and ADDED classification.

    Returns (transitions, container_rename_map).
    """
    renamed_file_map = renamed_file_map or {}
    matched_base: Set[int] = set()
    matched_head: Set[int] = set()
    transitions: List[SymbolTransition] = []
    container_rename_map: Dict[str, str] = {}  # base_file::base_qual -> head_file::head_qual

    # Index helpers
    head_by_id_kind: Dict[Tuple[str, str], List[int]] = {}
    for hi, hs in enumerate(head_symbols):
        head_by_id_kind.setdefault((hs.symbol_id, hs.kind), []).append(hi)

    # ------------------------------------------------------------------
    # STAGE 1: Exact (symbol_id, kind) match
    # ------------------------------------------------------------------
    for bi, bs in enumerate(base_symbols):
        candidates = [
            hi for hi in head_by_id_kind.get((bs.symbol_id, bs.kind), [])
            if hi not in matched_head
        ]
        if candidates:
            hi = candidates[0]
            hs = head_symbols[hi]
            matched_base.add(bi)
            matched_head.add(hi)
            weakened, weak_reason = _is_body_weakened(bs, hs)
            if weakened:
                transitions.append(SymbolTransition("GUTTED", bs, hs, 1, weak_reason))
            elif (
                bs.body_hash == hs.body_hash
                and bs.normalized_signature == hs.normalized_signature
                and bs.visibility == hs.visibility
                and bs.is_exported == hs.is_exported
                and bs.decorators == hs.decorators
            ):
                transitions.append(SymbolTransition("UNCHANGED", bs, hs, 1, "Identical symbol fact"))
            else:
                transitions.append(SymbolTransition("MODIFIED", bs, hs, 1, "Modified in place"))

    # ------------------------------------------------------------------
    # STAGE 2: Git-renamed file exact (qualified_name, kind) match
    # ------------------------------------------------------------------
    if renamed_file_map:
        for bi, bs in enumerate(base_symbols):
            if bi in matched_base:
                continue
            target_file = renamed_file_map.get(bs.file_path)
            if not target_file:
                continue
            for hi, hs in enumerate(head_symbols):
                if hi in matched_head:
                    continue
                if hs.file_path == target_file and hs.qualified_name == bs.qualified_name and hs.kind == bs.kind:
                    matched_base.add(bi)
                    matched_head.add(hi)
                    weakened, weak_reason = _is_body_weakened(bs, hs)
                    kind_str = "MOVED_AND_GUTTED" if weakened else "MOVED"
                    reason = weak_reason if weakened else f"Moved via file rename {bs.file_path} -> {hs.file_path}"
                    transitions.append(SymbolTransition(kind_str, bs, hs, 2, reason))
                    break

    # ------------------------------------------------------------------
    # STAGE 3: Cross-file moved symbol match (exact qualified_name & kind, or exact name+sig+body_hash)
    # ------------------------------------------------------------------
    for bi, bs in enumerate(base_symbols):
        if bi in matched_base:
            continue
        # 3a: Exact qualified_name + kind + language across different changed files
        qual_candidates = [
            hi for hi, hs in enumerate(head_symbols)
            if hi not in matched_head
            and hs.language == bs.language
            and hs.kind == bs.kind
            and hs.file_path != bs.file_path
            and hs.qualified_name == bs.qualified_name
        ]
        if len(qual_candidates) == 1:
            hi = qual_candidates[0]
            hs = head_symbols[hi]
            matched_base.add(bi)
            matched_head.add(hi)
            weakened, weak_reason = _is_body_weakened(bs, hs)
            if weakened:
                transitions.append(
                    SymbolTransition(
                        "MOVED_AND_GUTTED",
                        bs,
                        hs,
                        3,
                        f"Moved {bs.file_path} -> {hs.file_path} and gutted: {weak_reason}",
                    )
                )
            else:
                transitions.append(
                    SymbolTransition(
                        "MOVED",
                        bs,
                        hs,
                        3,
                        f"Moved {bs.file_path} -> {hs.file_path} with matching qualified name '{bs.qualified_name}'",
                    )
                )
            continue

        # 3b: Top-level symbol moved across files with same name, signature, and non-stub body_hash
        if bs.parent_symbol is None and not bs.is_stub:
            move_candidates = [
                hi for hi, hs in enumerate(head_symbols)
                if hi not in matched_head
                and hs.language == bs.language
                and hs.kind == bs.kind
                and hs.file_path != bs.file_path
                and hs.parent_symbol is None
                and hs.name == bs.name
                and (hs.body_hash == bs.body_hash or hs.normalized_signature == bs.normalized_signature)
            ]
            if len(move_candidates) == 1:
                hi = move_candidates[0]
                hs = head_symbols[hi]
                matched_base.add(bi)
                matched_head.add(hi)
                weakened, weak_reason = _is_body_weakened(bs, hs)
                t_kind = "MOVED_AND_GUTTED" if weakened else "MOVED"
                reason = (
                    f"Moved {bs.file_path} -> {hs.file_path} and gutted: {weak_reason}"
                    if weakened
                    else f"Moved {bs.file_path} -> {hs.file_path}"
                )
                transitions.append(SymbolTransition(t_kind, bs, hs, 3, reason))

    # ------------------------------------------------------------------
    # STAGE 4: Container-aware & Body-hash Rename Match
    # ------------------------------------------------------------------
    # Stage 4a: Match renamed containers (class, struct, interface, trait, enum)
    container_kinds = {"class", "struct", "interface", "trait", "enum"}
    unmatched_base_containers = [
        bi for bi, bs in enumerate(base_symbols)
        if bi not in matched_base and bs.kind in container_kinds
    ]
    unmatched_head_containers = [
        hi for hi, hs in enumerate(head_symbols)
        if hi not in matched_head and hs.kind in container_kinds
    ]

    # Collect member methods per (file_path, container_qual)
    base_members_by_container: Dict[Tuple[str, str], List[int]] = {}
    for bi, bs in enumerate(base_symbols):
        if bs.parent_symbol:
            base_members_by_container.setdefault((bs.file_path, bs.parent_symbol), []).append(bi)

    head_members_by_container: Dict[Tuple[str, str], List[int]] = {}
    for hi, hs in enumerate(head_symbols):
        if hs.parent_symbol:
            head_members_by_container.setdefault((hs.file_path, hs.parent_symbol), []).append(hi)

    for bi in unmatched_base_containers:
        if bi in matched_base:
            continue
        bs = base_symbols[bi]
        b_members = [base_symbols[m] for m in base_members_by_container.get((bs.file_path, bs.qualified_name), [])]
        b_member_sigs = {(m.name, m.normalized_signature) for m in b_members}
        b_member_names = {m.name for m in b_members}

        best_hi: Optional[int] = None
        best_score: float = 0.0
        ambiguous = False

        for hi in unmatched_head_containers:
            if hi in matched_head:
                continue
            hs = head_symbols[hi]
            if hs.language != bs.language or hs.kind != bs.kind:
                continue

            h_members = [head_symbols[m] for m in head_members_by_container.get((hs.file_path, hs.qualified_name), [])]
            h_member_sigs = {(m.name, m.normalized_signature) for m in h_members}
            h_member_names = {m.name for m in h_members}

            score = 0.0
            if not bs.is_stub and bs.body_hash == hs.body_hash:
                score = 1.0
            elif b_member_sigs and h_member_sigs:
                overlap = len(b_member_sigs & h_member_sigs)
                denom = max(len(b_member_sigs), len(h_member_sigs))
                score = overlap / denom if denom else 0.0
            elif b_member_names and h_member_names:
                overlap = len(b_member_names & h_member_names)
                denom = max(len(b_member_names), len(h_member_names))
                score = (overlap / denom) * 0.8 if denom else 0.0

            if score >= 0.5:
                if score > best_score:
                    best_score = score
                    best_hi = hi
                    ambiguous = False
                elif score == best_score and best_hi is not None:
                    ambiguous = True

        if best_hi is not None and not ambiguous:
            hs = head_symbols[best_hi]
            matched_base.add(bi)
            matched_head.add(best_hi)
            container_rename_map[f"{bs.file_path}::{bs.qualified_name}"] = f"{hs.file_path}::{hs.qualified_name}"
            is_move = bs.file_path != hs.file_path
            t_kind = "MOVED" if is_move else "RENAMED"
            transitions.append(
                SymbolTransition(
                    t_kind,
                    bs,
                    hs,
                    4,
                    f"Container '{bs.qualified_name}' -> '{hs.qualified_name}' matched with {best_score:.0%} member similarity",
                )
            )

            # Cascade match to member methods of this paired container
            b_mem_indices = base_members_by_container.get((bs.file_path, bs.qualified_name), [])
            h_mem_indices = head_members_by_container.get((hs.file_path, hs.qualified_name), [])
            for m_bi in b_mem_indices:
                if m_bi in matched_base:
                    continue
                m_bs = base_symbols[m_bi]
                for m_hi in h_mem_indices:
                    if m_hi in matched_head:
                        continue
                    m_hs = head_symbols[m_hi]
                    if m_hs.kind == m_bs.kind and m_hs.name == m_bs.name:
                        matched_base.add(m_bi)
                        matched_head.add(m_hi)
                        weakened, weak_reason = _is_body_weakened(m_bs, m_hs)
                        if weakened:
                            m_kind = "MOVED_AND_GUTTED" if is_move else "RENAMED_AND_GUTTED"
                            reason = f"Member of renamed container '{bs.qualified_name}' -> '{hs.qualified_name}' gutted: {weak_reason}"
                        else:
                            m_kind = "MOVED" if is_move else "RENAMED"
                            reason = f"Member of renamed container '{bs.qualified_name}' -> '{hs.qualified_name}'"
                        transitions.append(SymbolTransition(m_kind, m_bs, m_hs, 4, reason))
                        break

    # Stage 4b: Function / method / constant rename with identical non-stub body_hash & signature
    for bi, bs in enumerate(base_symbols):
        if bi in matched_base or bs.is_stub:
            continue
        candidates = []
        for hi, hs in enumerate(head_symbols):
            if hi in matched_head or hs.is_stub:
                continue
            if hs.language != bs.language or hs.kind != bs.kind:
                continue
            # Check container compatibility
            same_or_mapped_container = (
                bs.parent_symbol == hs.parent_symbol
                or container_rename_map.get(f"{bs.file_path}::{bs.parent_symbol}") == f"{hs.file_path}::{hs.parent_symbol}"
            )
            if not same_or_mapped_container:
                continue
            if hs.body_hash == bs.body_hash and hs.normalized_signature == bs.normalized_signature:
                candidates.append(hi)

        if len(candidates) == 1:
            hi = candidates[0]
            hs = head_symbols[hi]
            matched_base.add(bi)
            matched_head.add(hi)
            is_move = bs.file_path != hs.file_path
            t_kind = "MOVED" if is_move else "RENAMED"
            transitions.append(
                SymbolTransition(
                    t_kind,
                    bs,
                    hs,
                    4,
                    f"Renamed '{bs.qualified_name}' -> '{hs.qualified_name}' with identical normalized body hash and signature",
                )
            )
        elif len(candidates) > 1:
            # Ambiguous refactor: multiple new symbols share the exact body hash & signature
            matched_base.add(bi)
            transitions.append(
                SymbolTransition(
                    "AMBIGUOUS",
                    bs,
                    head_symbols[candidates[0]],
                    4,
                    f"Ambiguous match for '{bs.qualified_name}': {len(candidates)} candidate symbols share body hash",
                )
            )

    # Stage 4c: Symbol rename/move in same container/file (or renamed file) where body was gutted to a stub
    for bi, bs in enumerate(base_symbols):
        if bi in matched_base or bs.kind not in ("function", "method", "class", "struct") or bs.is_stub:
            continue
        stub_candidates = []
        for hi, hs in enumerate(head_symbols):
            if hi in matched_head or hs.kind != bs.kind or not hs.is_stub:
                continue
            if hs.language != bs.language:
                continue
            same_file_or_mapped = (
                hs.file_path == bs.file_path
                or renamed_file_map.get(bs.file_path) == hs.file_path
            )
            same_container = (
                bs.parent_symbol == hs.parent_symbol
                or container_rename_map.get(f"{bs.file_path}::{bs.parent_symbol}") == f"{hs.file_path}::{hs.parent_symbol}"
            )
            if same_file_or_mapped and same_container and hs.normalized_signature == bs.normalized_signature:
                stub_candidates.append(hi)

        if stub_candidates:
            hi = stub_candidates[0]
            hs = head_symbols[hi]
            matched_base.add(bi)
            matched_head.add(hi)
            t_kind = "MOVED_AND_GUTTED" if hs.file_path != bs.file_path else "RENAMED_AND_GUTTED"
            transitions.append(
                SymbolTransition(
                    t_kind,
                    bs,
                    hs,
                    4,
                    f"Replaced '{bs.qualified_name}' ({bs.file_path}) -> '{hs.qualified_name}' ({hs.file_path}) with a no-op stub",
                )
            )

    # ------------------------------------------------------------------
    # STAGE 5: Residual Unmatched REMOVED and ADDED symbols
    # ------------------------------------------------------------------
    for bi, bs in enumerate(base_symbols):
        if bi not in matched_base:
            transitions.append(
                SymbolTransition(
                    "REMOVED",
                    bs,
                    None,
                    5,
                    f"Symbol '{bs.qualified_name}' ({bs.kind}) removed with no matching replacement",
                )
            )

    for hi, hs in enumerate(head_symbols):
        if hi not in matched_head:
            transitions.append(
                SymbolTransition(
                    "ADDED",
                    None,
                    hs,
                    5,
                    f"Symbol '{hs.qualified_name}' ({hs.kind}) added",
                )
            )

    return transitions, container_rename_map


# ==============================================================================
# DIFFERENTIAL CONSEQUENCE ENGINE (D01 - D06)
# ==============================================================================

class ConsequenceEngine:
    """
    Evaluates a commit delta and repository state to produce deterministic,
    evidence-backed ConsequenceFindings (`consequence.v1`).
    """

    def __init__(self, mode: str = "shadow", max_repo_files: int = 200):
        self.mode = mode if mode in ("shadow", "advisory", "enforce") else "shadow"
        self.max_repo_files = max_repo_files

    def analyze_deltas(
        self,
        file_deltas: List[FileDeltaInput],
        repo_head_files: Optional[Dict[str, str]] = None,
    ) -> ConsequenceReport:
        """
        Run the full SCG differential consequence pipeline over a list of FileDeltaInputs
        and an optional dictionary of `{file_path: source_text}` representing the
        repository's `head` tree (for cross-file caller verification).
        """
        t_start = time.perf_counter()
        stage_timing: Dict[str, float] = {}
        repo_head_files = repo_head_files or {}

        # ------------------------------------------------------------------
        # Stage A: Parse changed files & evaluate D01 Parser Completeness
        # ------------------------------------------------------------------
        t0 = time.perf_counter()
        base_parse_results: Dict[str, ParseResult] = {}
        head_parse_results: Dict[str, ParseResult] = {}
        base_symbols: List[SymbolFact] = []
        head_symbols: List[SymbolFact] = []
        renamed_file_map: Dict[str, str] = {}

        # Detect git file renames and deleted+added file pairs in same language
        deleted_files_by_lang: Dict[str, List[str]] = {}
        added_files_by_lang: Dict[str, List[str]] = {}

        for fd in file_deltas:
            if fd.change_type == "R" and fd.old_path:
                renamed_file_map[fd.old_path] = fd.file_path
            lang = language_for_path(fd.file_path)
            if fd.change_type == "D" and lang:
                deleted_files_by_lang.setdefault(lang, []).append(fd.file_path)
            elif fd.change_type == "A" and lang:
                added_files_by_lang.setdefault(lang, []).append(fd.file_path)

            if fd.base_source is not None and language_for_path(fd.old_path or fd.file_path) is not None:
                b_path = fd.old_path or fd.file_path
                pr_base = extract_symbols(fd.base_source, b_path)
                base_parse_results[b_path] = pr_base
                base_symbols.extend(pr_base.symbols)

            if fd.head_source is not None and language_for_path(fd.file_path) is not None:
                pr_head = extract_symbols(fd.head_source, fd.file_path)
                head_parse_results[fd.file_path] = pr_head
                head_symbols.extend(pr_head.symbols)

        # Pair single deleted + single added file of the same language as candidate move/rename
        for lang, del_paths in deleted_files_by_lang.items():
            add_paths = added_files_by_lang.get(lang, [])
            if len(del_paths) == 1 and len(add_paths) == 1:
                renamed_file_map.setdefault(del_paths[0], add_paths[0])

        stage_timing["parse_changed_files"] = (time.perf_counter() - t0) * 1000.0

        # ------------------------------------------------------------------
        # Stage B: Parse repository head files for cross-file call graph
        # ------------------------------------------------------------------
        t1 = time.perf_counter()
        repo_call_sites: List[CallSiteFact] = []
        repo_head_symbols: List[SymbolFact] = []

        # Include already-parsed head files
        parsed_head_paths: Set[str] = set()
        for fpath, pr in head_parse_results.items():
            parsed_head_paths.add(fpath)
            repo_call_sites.extend(pr.call_sites)
            repo_head_symbols.extend(pr.symbols)

        # Parse remaining unmodified head files up to max_repo_files
        count_extra = 0
        for fpath in sorted(repo_head_files.keys()):
            if fpath in parsed_head_paths:
                continue
            if language_for_path(fpath) is None:
                continue
            if count_extra >= self.max_repo_files:
                break
            src = repo_head_files[fpath]
            if src:
                pr = extract_symbols(src, fpath)
                repo_call_sites.extend(pr.call_sites)
                repo_head_symbols.extend(pr.symbols)
                count_extra += 1

        stage_timing["index_repo_call_sites"] = (time.perf_counter() - t1) * 1000.0

        # ------------------------------------------------------------------
        # Stage C: 5-Stage Symbol Matching Pipeline
        # ------------------------------------------------------------------
        t2 = time.perf_counter()
        transitions, container_rename_map = match_symbols_5_stage(
            base_symbols, head_symbols, renamed_file_map
        )
        stage_timing["symbol_matching"] = (time.perf_counter() - t2) * 1000.0

        # ------------------------------------------------------------------
        # Stage D: Run Detectors D01 - D06
        # ------------------------------------------------------------------
        t3 = time.perf_counter()
        findings: List[ConsequenceFinding] = []

        findings.extend(self._detect_d01_parser_incomplete(base_parse_results, head_parse_results))
        findings.extend(self._detect_d02_structural_and_weakening(transitions, file_deltas))
        findings.extend(self._detect_d06_guard_regressions(transitions))
        d04_findings, unresolved_by_symbol = self._detect_d04_public_api_and_callers(
            transitions, repo_head_symbols, repo_call_sites
        )
        findings.extend(d04_findings)
        findings.extend(
            self._detect_d03_compound_and_threshold_gaming(
                transitions, file_deltas, findings, unresolved_by_symbol
            )
        )
        findings.extend(self._detect_d05_build_dependency_delta(file_deltas))

        # Sort findings deterministically by severity rank then finding_id
        sev_rank = {
            SEVERITY_CRITICAL: 0,
            SEVERITY_HIGH: 1,
            SEVERITY_MEDIUM: 2,
            SEVERITY_LOW: 3,
            SEVERITY_INFO: 4,
        }
        findings.sort(key=lambda f: (sev_rank.get(f.severity, 9), f.detector_id, f.finding_id))
        stage_timing["detectors"] = (time.perf_counter() - t3) * 1000.0
        stage_timing["total"] = (time.perf_counter() - t_start) * 1000.0

        # ------------------------------------------------------------------
        # Stage E: Build Capability Vector, Summary & Recommended Verdict
        # ------------------------------------------------------------------
        all_prs = list(base_parse_results.values()) + list(head_parse_results.values())
        incomplete_prs = [pr for pr in all_prs if not pr.complete]
        if not all_prs:
            syntax_state = CAPABILITY_AVAILABLE
            syntax_reason = "No supported code files modified in delta"
        elif not incomplete_prs:
            syntax_state = CAPABILITY_AVAILABLE
            syntax_reason = f"All {len(all_prs)} parsed file snapshot(s) succeeded without syntax errors"
        elif len(incomplete_prs) < len(all_prs):
            syntax_state = CAPABILITY_PARTIAL
            syntax_reason = f"{len(incomplete_prs)} of {len(all_prs)} file snapshot(s) had incomplete parsing"
        else:
            syntax_state = CAPABILITY_FAILED
            syntax_reason = f"All {len(incomplete_prs)} file snapshot(s) failed structural parsing"

        capabilities = build_capability_vector(
            syntax_state=syntax_state,
            syntax_provenance="python-ast+tree-sitter",
            syntax_reason=syntax_reason,
            symbolic_state=CAPABILITY_AVAILABLE if all_prs else CAPABILITY_PARTIAL,
            symbolic_reason="5-stage SCG symbol matching across changed files",
            reachability_state=CAPABILITY_AVAILABLE if repo_head_files else CAPABILITY_PARTIAL,
            reachability_reason=(
                f"Cross-file call index over {len(repo_call_sites)} call sites in head"
                if repo_head_files
                else "Changed-file call sites indexed"
            ),
            flow_state=CAPABILITY_PARTIAL,
            flow_reason="Intra-function guard calls, exception rollback calls, and decorator deltas analyzed",
            runtime_state=CAPABILITY_UNAVAILABLE,
            runtime_reason="Static analysis mode (no test runner execution invoked)",
        )

        counts_by_kind: Dict[str, int] = {}
        for tr in transitions:
            counts_by_kind[tr.transition_kind] = counts_by_kind.get(tr.transition_kind, 0) + 1

        graph_summary = {
            "base_symbol_count": len(base_symbols),
            "head_symbol_count": len(head_symbols),
            "repo_indexed_call_sites": len(repo_call_sites),
            "transition_counts": counts_by_kind,
            "container_renames": container_rename_map,
            "renamed_files": renamed_file_map,
        }

        parser_completeness = {
            "complete": len(incomplete_prs) == 0,
            "total_snapshots_parsed": len(all_prs),
            "incomplete_snapshots": [
                {
                    "file_path": pr.file_path,
                    "status": pr.status,
                    "reason": pr.incomplete_reason,
                    "error_detail": pr.error_detail,
                }
                for pr in incomplete_prs
            ],
        }

        rec_verdict, rec_score = self._compute_recommendation(findings)

        return ConsequenceReport(
            schema_version=CONSEQUENCE_SCHEMA_VERSION,
            mode=self.mode,
            recommended_verdict=rec_verdict,
            recommended_score=rec_score,
            capabilities=capabilities,
            parser_completeness=parser_completeness,
            graph_summary=graph_summary,
            findings=findings,
            stage_timing_ms=stage_timing,
        )

    # ------------------------------------------------------------------
    # D01: Parser / Analysis Completeness Detector
    # ------------------------------------------------------------------
    def _detect_d01_parser_incomplete(
        self,
        base_prs: Dict[str, ParseResult],
        head_prs: Dict[str, ParseResult],
    ) -> List[ConsequenceFinding]:
        findings: List[ConsequenceFinding] = []
        seen: Set[Tuple[str, str]] = set()

        for side, prs in (("base", base_prs), ("head", head_prs)):
            for fpath, pr in sorted(prs.items()):
                if pr.complete:
                    continue
                key = (fpath, pr.status)
                if key in seen:
                    continue
                seen.add(key)

                is_head_error = side == "head" and pr.status == PARSER_STATUS_PARSE_ERROR
                sev = SEVERITY_MEDIUM if is_head_error else SEVERITY_LOW
                pol = POLICY_REVIEW if is_head_error else POLICY_WARN

                findings.append(
                    ConsequenceFinding(
                        finding_id=f"PG-D01-{fpath}-{pr.status}",
                        detector_id=DETECTOR_D01_PARSER,
                        consequence_class="ANALYSIS_INCOMPLETE",
                        tier=TIER_INCOMPLETE,
                        confidence=CONFIDENCE_UNKNOWN,
                        severity=sev,
                        policy_recommendation=pol,
                        summary=(
                            f"Structural analysis of '{fpath}' ({side}) is incomplete "
                            f"({pr.status}): {pr.incomplete_reason}"
                        ),
                        affected_files=(fpath,),
                        affected_symbols=(),
                        evidence=(
                            EvidenceItem(
                                kind=pr.status,
                                file=fpath,
                                line=1,
                                symbol=None,
                                detail=f"{pr.incomplete_reason} ({pr.error_detail or 'no detail'})",
                            ),
                        ),
                        remediation=(
                            f"Fix syntax errors in '{fpath}' or ensure the '{pr.language}' Tree-sitter grammar "
                            "is installed before relying on structural safety guarantees."
                        ),
                    )
                )
        return findings

    # ------------------------------------------------------------------
    # D02: Structural Delta, Rename+Weakening & Ambiguous Refactor
    # ------------------------------------------------------------------
    def _detect_d02_structural_and_weakening(
        self,
        transitions: List[SymbolTransition],
        file_deltas: List[FileDeltaInput],
    ) -> List[ConsequenceFinding]:
        findings: List[ConsequenceFinding] = []

        gutted_transitions = [
            tr for tr in transitions
            if tr.transition_kind in ("GUTTED", "RENAMED_AND_GUTTED", "MOVED_AND_GUTTED")
            and tr.base_symbol is not None
            and tr.head_symbol is not None
        ]

        if gutted_transitions:
            files = sorted({
                tr.head_symbol.file_path for tr in gutted_transitions if tr.head_symbol
            } | {
                tr.base_symbol.file_path for tr in gutted_transitions if tr.base_symbol
            })
            syms = tuple(
                f"{tr.base_symbol.qualified_name}->{tr.head_symbol.qualified_name}"
                if tr.base_symbol.qualified_name != tr.head_symbol.qualified_name
                else tr.base_symbol.qualified_name
                for tr in gutted_transitions
                if tr.base_symbol and tr.head_symbol
            )
            ev = tuple(
                EvidenceItem(
                    kind=tr.transition_kind,
                    file=tr.head_symbol.file_path,
                    line=tr.head_symbol.start_line,
                    symbol=tr.head_symbol.qualified_name,
                    detail=tr.reason,
                )
                for tr in gutted_transitions
                if tr.head_symbol
            )
            has_rename_or_move = any(
                tr.transition_kind in ("RENAMED_AND_GUTTED", "MOVED_AND_GUTTED")
                for tr in gutted_transitions
            )
            is_critical_gutting = (
                len(gutted_transitions) >= 2
                or has_rename_or_move
                or any(
                    tr.base_symbol.kind in ("class", "struct")
                    or tr.base_symbol.statement_count >= 5
                    or _is_security_relevant_name(tr.base_symbol.qualified_name)
                    for tr in gutted_transitions
                    if tr.base_symbol
                )
            )
            c_class = "RENAME_WITH_BODY_WEAKENING" if has_rename_or_move else "BODY_GUTTED"
            sev = SEVERITY_CRITICAL if is_critical_gutting else SEVERITY_HIGH
            pol = POLICY_BLOCK if is_critical_gutting else POLICY_REVIEW

            findings.append(
                ConsequenceFinding(
                    finding_id=f"PG-D02-WEAKENING-{files[0]}",
                    detector_id=DETECTOR_D02_WEAKENING,
                    consequence_class=c_class,
                    tier=TIER_VERIFIED,
                    confidence=CONFIDENCE_HIGH,
                    severity=sev,
                    policy_recommendation=pol,
                    summary=(
                        f"{len(gutted_transitions)} symbol implementation(s) were gutted or replaced with "
                        f"no-op stubs ({', '.join(syms[:4])}{'...' if len(syms) > 4 else ''})."
                    ),
                    affected_files=tuple(files),
                    affected_symbols=syms,
                    evidence=ev,
                    remediation=(
                        "Restore the functional implementation of the gutted symbol(s) or remove callers "
                        "explicitly instead of leaving silent no-op stubs."
                    ),
                )
            )

        # Ambiguous refactors
        ambiguous_transitions = [
            tr for tr in transitions
            if tr.transition_kind == "AMBIGUOUS" and tr.base_symbol is not None
        ]
        if ambiguous_transitions:
            files = sorted({tr.base_symbol.file_path for tr in ambiguous_transitions if tr.base_symbol})
            syms = tuple(tr.base_symbol.qualified_name for tr in ambiguous_transitions if tr.base_symbol)
            ev = tuple(
                EvidenceItem(
                    kind="AMBIGUOUS_SYMBOL_MATCH",
                    file=tr.base_symbol.file_path,
                    line=tr.base_symbol.start_line,
                    symbol=tr.base_symbol.qualified_name,
                    detail=tr.reason,
                )
                for tr in ambiguous_transitions
                if tr.base_symbol
            )
            findings.append(
                ConsequenceFinding(
                    finding_id=f"PG-D02-AMBIGUOUS-{files[0]}",
                    detector_id=DETECTOR_D02_AMBIGUOUS,
                    consequence_class="AMBIGUOUS_REFACTOR",
                    tier=TIER_INCOMPLETE,
                    confidence=CONFIDENCE_LOW,
                    severity=SEVERITY_LOW,
                    policy_recommendation=POLICY_WARN,
                    summary=(
                        f"Ambiguous symbol replacement for {len(ambiguous_transitions)} symbol(s): "
                        f"multiple candidate targets share identical body hashes."
                    ),
                    affected_files=tuple(files),
                    affected_symbols=syms,
                    evidence=ev,
                    remediation="Verify that all callers were updated to target the intended replacement symbol.",
                )
            )

        return findings

    # ------------------------------------------------------------------
    # D06: Security / Validation / Rollback Guard Regression Detector
    # ------------------------------------------------------------------
    def _detect_d06_guard_regressions(
        self,
        transitions: List[SymbolTransition],
    ) -> List[ConsequenceFinding]:
        findings: List[ConsequenceFinding] = []

        for tr in transitions:
            bs = tr.base_symbol
            hs = tr.head_symbol
            if bs is None or hs is None:
                continue
            if bs.kind not in ("function", "method", "class"):
                continue

            # 1. Check removed security decorators
            base_guard_decos = {d for d in bs.decorators if _is_guard_decorator(d)}
            head_guard_decos = {d for d in hs.decorators if _is_guard_decorator(d)}
            removed_decos = sorted(base_guard_decos - head_guard_decos)

            # 2. Check removed guard calls inside surviving non-stub functions/methods
            base_guard_calls = {c for c in bs.calls if _is_guard_call(c)}
            head_guard_calls = {c for c in hs.calls if _is_guard_call(c)}
            removed_calls = sorted(base_guard_calls - head_guard_calls)

            if not removed_decos and not removed_calls:
                continue

            ev_items: List[EvidenceItem] = []
            for d in removed_decos:
                ev_items.append(
                    EvidenceItem(
                        kind="GUARD_DECORATOR_REMOVED",
                        file=hs.file_path,
                        line=hs.start_line,
                        symbol=hs.qualified_name,
                        detail=f"Removed security decorator '@{d}' from '{hs.qualified_name}'",
                    )
                )
            for c in removed_calls:
                ev_items.append(
                    EvidenceItem(
                        kind="GUARD_CALL_REMOVED",
                        file=hs.file_path,
                        line=hs.start_line,
                        symbol=hs.qualified_name,
                        detail=f"Removed guard/rollback call '{c}()' from '{hs.qualified_name}'",
                    )
                )

            findings.append(
                ConsequenceFinding(
                    finding_id=f"PG-D06-{hs.file_path}-{hs.qualified_name}",
                    detector_id=DETECTOR_D06_GUARD,
                    consequence_class="SECURITY_GUARD_REMOVED",
                    tier=TIER_VERIFIED,
                    confidence=CONFIDENCE_HIGH,
                    severity=SEVERITY_HIGH,
                    policy_recommendation=POLICY_BLOCK,
                    summary=(
                        f"Surviving {hs.kind} '{hs.qualified_name}' in '{hs.file_path}' removed "
                        f"security/integrity guard(s): {', '.join(removed_decos + removed_calls)}"
                    ),
                    affected_files=(hs.file_path,),
                    affected_symbols=(hs.qualified_name,),
                    evidence=tuple(ev_items),
                    remediation=(
                        f"Restore the removed guard ({', '.join(removed_decos + removed_calls)}) in "
                        f"'{hs.qualified_name}' or verify an equivalent upstream protection."
                    ),
                )
            )

        return findings

    # ------------------------------------------------------------------
    # D04: Public API Contract Break & Cross-File Unresolved Caller Detector
    # ------------------------------------------------------------------
    def _detect_d04_public_api_and_callers(
        self,
        transitions: List[SymbolTransition],
        repo_head_symbols: List[SymbolFact],
        repo_call_sites: List[CallSiteFact],
    ) -> Tuple[List[ConsequenceFinding], Dict[str, List[CallSiteFact]]]:
        findings: List[ConsequenceFinding] = []
        unresolved_by_symbol: Dict[str, List[CallSiteFact]] = {}

        # Build set of all surviving symbol names and qualified names in head
        surviving_names: Set[str] = {s.name for s in repo_head_symbols}
        surviving_quals: Set[str] = {s.qualified_name for s in repo_head_symbols}

        # Map (container_name, method_name) in head
        surviving_class_methods: Set[Tuple[str, str]] = set()
        for s in repo_head_symbols:
            if s.parent_symbol:
                surviving_class_methods.add((s.parent_symbol, s.name))

        # 1. Check unmatched REMOVED symbols for unresolved call sites in head & public API removal
        removed_transitions = [
            tr for tr in transitions
            if tr.transition_kind == "REMOVED" and tr.base_symbol is not None
        ]

        for tr in removed_transitions:
            bs = tr.base_symbol
            assert bs is not None

            # Find call sites in head that still invoke this removed symbol
            matching_callers: List[CallSiteFact] = []
            for cs in repo_call_sites:
                if cs.callee_name != bs.name:
                    continue
                if bs.parent_symbol:
                    # Method on a class/container: check if another class in head still defines it
                    # and whether the call site qualifier matches the class or an instance variable name
                    class_lower = bs.parent_symbol.lower()
                    qual_lower = cs.qualifier.lower()
                    initials = "".join(
                        t[0].lower()
                        for t in re.findall(r"[A-Z][a-z0-9]*", bs.parent_symbol)
                    )
                    qualifier_matches_class = (
                        qual_lower in (class_lower, initials, "self", "this")
                        or class_lower in qual_lower
                        or bs.name not in surviving_names
                    )
                    if qualifier_matches_class:
                        matching_callers.append(cs)
                else:
                    # Top-level function/class: if no symbol with this name exists in head
                    if bs.name not in surviving_names:
                        matching_callers.append(cs)

            if matching_callers:
                unresolved_by_symbol[bs.symbol_id] = matching_callers
                caller_files = sorted({bs.file_path} | {cs.file_path for cs in matching_callers})
                ev = [
                    EvidenceItem(
                        kind="REMOVED_SYMBOL",
                        file=bs.file_path,
                        line=bs.start_line,
                        symbol=bs.qualified_name,
                        detail=f"Removed {bs.visibility} {bs.kind} '{bs.qualified_name}{bs.normalized_signature}'",
                    )
                ]
                for cs in matching_callers[:5]:
                    ev.append(
                        EvidenceItem(
                            kind="UNRESOLVED_CALL_SITE",
                            file=cs.file_path,
                            line=cs.line,
                            symbol=cs.caller_qualified_name,
                            detail=(
                                f"Caller '{cs.caller_qualified_name}' at {cs.file_path}:{cs.line} still invokes "
                                f"removed symbol '{cs.qualifier + '.' if cs.qualifier else ''}{cs.callee_name}()'"
                            ),
                        )
                    )
                findings.append(
                    ConsequenceFinding(
                        finding_id=f"PG-D04-CALLER-{bs.file_path}-{bs.qualified_name}",
                        detector_id=DETECTOR_D04_API,
                        consequence_class="UNRESOLVED_CALLER",
                        tier=TIER_VERIFIED,
                        confidence=CONFIDENCE_HIGH,
                        severity=SEVERITY_CRITICAL,
                        policy_recommendation=POLICY_BLOCK,
                        summary=(
                            f"Removed {bs.kind} '{bs.qualified_name}' ({bs.file_path}) leaves "
                            f"{len(matching_callers)} unresolved call site(s) in head "
                            f"(e.g. {matching_callers[0].file_path}:{matching_callers[0].line})."
                        ),
                        affected_files=tuple(caller_files),
                        affected_symbols=(bs.qualified_name,),
                        evidence=tuple(ev),
                        remediation=(
                            f"Update or remove all callers of '{bs.qualified_name}' "
                            f"(including {matching_callers[0].file_path}:{matching_callers[0].line}) "
                            "or restore the removed symbol."
                        ),
                    )
                )
            elif bs.is_exported and bs.visibility == "public" and bs.kind in ("function", "method", "class", "interface", "struct", "trait"):
                # Public exported API removed without internal caller match
                sec_rel = _is_security_relevant_name(bs.qualified_name)
                sev = SEVERITY_HIGH if sec_rel else SEVERITY_MEDIUM
                pol = POLICY_REVIEW if sec_rel else POLICY_WARN
                findings.append(
                    ConsequenceFinding(
                        finding_id=f"PG-D04-API-{bs.file_path}-{bs.qualified_name}",
                        detector_id=DETECTOR_D04_API,
                        consequence_class="PUBLIC_API_REMOVAL",
                        tier=TIER_LIKELY,
                        confidence=CONFIDENCE_MEDIUM,
                        severity=sev,
                        policy_recommendation=pol,
                        summary=(
                            f"Exported public {bs.kind} '{bs.qualified_name}' was removed from '{bs.file_path}' "
                            "with no rename or move counterpart."
                        ),
                        affected_files=(bs.file_path,),
                        affected_symbols=(bs.qualified_name,),
                        evidence=(
                            EvidenceItem(
                                kind="PUBLIC_EXPORT_REMOVED",
                                file=bs.file_path,
                                line=bs.start_line,
                                symbol=bs.qualified_name,
                                detail=f"Exported {bs.kind} '{bs.qualified_name}{bs.normalized_signature}' deleted",
                            ),
                        ),
                        remediation=(
                            f"Verify whether external consumers depend on '{bs.qualified_name}' "
                            "or provide a deprecation alias."
                        ),
                    )
                )

        # 2. Check MODIFIED symbols for incompatible signature tightening or export/visibility drop
        for tr in transitions:
            if tr.transition_kind != "MODIFIED" or tr.base_symbol is None or tr.head_symbol is None:
                continue
            bs, hs = tr.base_symbol, tr.head_symbol
            if not bs.is_exported or bs.visibility != "public":
                continue

            # Visibility reduced (public -> private)
            if not hs.is_exported or hs.visibility == "private":
                findings.append(
                    ConsequenceFinding(
                        finding_id=f"PG-D04-VIS-{hs.file_path}-{hs.qualified_name}",
                        detector_id=DETECTOR_D04_API,
                        consequence_class="PUBLIC_API_VISIBILITY_REDUCED",
                        tier=TIER_VERIFIED,
                        confidence=CONFIDENCE_HIGH,
                        severity=SEVERITY_MEDIUM,
                        policy_recommendation=POLICY_REVIEW,
                        summary=(
                            f"Public exported {bs.kind} '{bs.qualified_name}' in '{hs.file_path}' "
                            f"reduced visibility from '{bs.visibility}' (exported={bs.is_exported}) "
                            f"to '{hs.visibility}' (exported={hs.is_exported})."
                        ),
                        affected_files=(hs.file_path,),
                        affected_symbols=(hs.qualified_name,),
                        evidence=(
                            EvidenceItem(
                                kind="VISIBILITY_REDUCED",
                                file=hs.file_path,
                                line=hs.start_line,
                                symbol=hs.qualified_name,
                                detail=f"Visibility changed {bs.visibility}->'{hs.visibility}', exported {bs.is_exported}->{hs.is_exported}",
                            ),
                        ),
                        remediation=f"Restore export/public visibility on '{hs.qualified_name}' or update downstream consumers.",
                    )
                )

            # Required parameter count increased or max parameters decreased breaking callers
            if bs.kind in ("function", "method") and hs.required_parameter_count > bs.required_parameter_count:
                broken_cs = [
                    cs for cs in repo_call_sites
                    if cs.callee_name == hs.name and cs.arg_count < hs.required_parameter_count
                ]
                tier = TIER_VERIFIED if broken_cs else TIER_LIKELY
                conf = CONFIDENCE_HIGH if broken_cs else CONFIDENCE_MEDIUM
                sev = SEVERITY_HIGH if broken_cs else SEVERITY_MEDIUM
                pol = POLICY_BLOCK if broken_cs else POLICY_REVIEW
                ev = [
                    EvidenceItem(
                        kind="REQUIRED_PARAMS_INCREASED",
                        file=hs.file_path,
                        line=hs.start_line,
                        symbol=hs.qualified_name,
                        detail=(
                            f"Required parameters increased from {bs.required_parameter_count} "
                            f"({bs.normalized_signature}) to {hs.required_parameter_count} ({hs.normalized_signature})"
                        ),
                    )
                ]
                for cs in broken_cs[:5]:
                    ev.append(
                        EvidenceItem(
                            kind="INSUFFICIENT_CALLER_ARGS",
                            file=cs.file_path,
                            line=cs.line,
                            symbol=cs.caller_qualified_name,
                            detail=f"Call at {cs.file_path}:{cs.line} passes {cs.arg_count} arg(s), fewer than required {hs.required_parameter_count}",
                        )
                    )
                findings.append(
                    ConsequenceFinding(
                        finding_id=f"PG-D04-SIG-{hs.file_path}-{hs.qualified_name}",
                        detector_id=DETECTOR_D04_API,
                        consequence_class="PUBLIC_API_SIGNATURE_BREAK",
                        tier=tier,
                        confidence=conf,
                        severity=sev,
                        policy_recommendation=pol,
                        summary=(
                            f"Signature change on '{hs.qualified_name}' increased required parameters "
                            f"from {bs.required_parameter_count} to {hs.required_parameter_count}"
                            + (f", breaking {len(broken_cs)} call site(s)." if broken_cs else ".")
                        ),
                        affected_files=tuple(sorted({hs.file_path} | {cs.file_path for cs in broken_cs})),
                        affected_symbols=(hs.qualified_name,),
                        evidence=tuple(ev),
                        remediation=f"Provide a default value for the new parameter in '{hs.qualified_name}' or update all call sites.",
                    )
                )

        return findings, unresolved_by_symbol

    # ------------------------------------------------------------------
    # D03: Cross-File Compound Loss (A03) & Threshold-Gaming Evasion (A06)
    # ------------------------------------------------------------------
    def _detect_d03_compound_and_threshold_gaming(
        self,
        transitions: List[SymbolTransition],
        file_deltas: List[FileDeltaInput],
        existing_findings: List[ConsequenceFinding],
        unresolved_by_symbol: Dict[str, List[CallSiteFact]],
    ) -> List[ConsequenceFinding]:
        findings: List[ConsequenceFinding] = []

        # Collect genuinely unmatched non-stub REMOVED symbols (excludes all matched renames/moves!)
        unmatched_removed = [
            tr.base_symbol for tr in transitions
            if tr.transition_kind == "REMOVED"
            and tr.base_symbol is not None
            and not tr.base_symbol.is_stub
            and tr.base_symbol.kind in ("function", "method", "class", "struct", "interface", "trait")
        ]

        if len(unmatched_removed) < 3:
            return findings

        files_with_removals = sorted({s.file_path for s in unmatched_removed})
        public_removed = [s for s in unmatched_removed if s.is_exported or s.visibility == "public"]
        security_removed = [s for s in unmatched_removed if _is_security_relevant_name(s.qualified_name)]
        has_guard_regression = any(f.detector_id == DETECTOR_D06_GUARD for f in existing_findings)
        has_unresolved_callers = bool(unresolved_by_symbol)

        # ------------------------------------------------------------------
        # Case 1: Cross-File Distributed Symbol Loss (A03 pattern)
        #   >= 3 unmatched non-stub symbols removed across >= 3 distinct files
        # ------------------------------------------------------------------
        if len(files_with_removals) >= 3 and len(unmatched_removed) >= 3:
            # Distinguish benign dead-code cleanup of private unreferenced helpers from
            # destructive distributed capability loss:
            is_corroborated = (
                len(public_removed) >= 2
                or len(security_removed) >= 1
                or has_guard_regression
                or has_unresolved_callers
            )
            if is_corroborated:
                verified = (
                    has_guard_regression
                    or has_unresolved_callers
                    or (len(security_removed) >= 2 and len(public_removed) >= 2)
                    or len(public_removed) >= 5
                )
                tier = TIER_VERIFIED if verified else TIER_LIKELY
                conf = CONFIDENCE_HIGH if verified else CONFIDENCE_MEDIUM
                sev = SEVERITY_CRITICAL if verified else SEVERITY_HIGH
                pol = POLICY_BLOCK if verified else POLICY_REVIEW

                ev = [
                    EvidenceItem(
                        kind="DISTRIBUTED_UNMATCHED_REMOVAL",
                        file=s.file_path,
                        line=s.start_line,
                        symbol=s.qualified_name,
                        detail=(
                            f"Unmatched removal of {s.visibility} {s.kind} '{s.qualified_name}{s.normalized_signature}' "
                            f"({s.statement_count} stmts, exported={s.is_exported})"
                        ),
                    )
                    for s in unmatched_removed
                ]
                findings.append(
                    ConsequenceFinding(
                        finding_id="PG-D03-DISTRIBUTED-LOSS",
                        detector_id=DETECTOR_D03_COMPOUND,
                        consequence_class="DISTRIBUTED_SYMBOL_LOSS",
                        tier=tier,
                        confidence=conf,
                        severity=sev,
                        policy_recommendation=pol,
                        summary=(
                            f"Distributed capability loss across {len(files_with_removals)} files: "
                            f"{len(unmatched_removed)} non-stub symbols removed with no rename/move replacement "
                            f"({', '.join(s.qualified_name for s in unmatched_removed[:5])})."
                        ),
                        affected_files=tuple(files_with_removals),
                        affected_symbols=tuple(s.qualified_name for s in unmatched_removed),
                        evidence=tuple(ev),
                        remediation=(
                            "Review the cross-file symbol removals together: each file remained below "
                            "single-file deletion thresholds, but the combined commit removes active capabilities."
                        ),
                    )
                )

        # ------------------------------------------------------------------
        # Case 2: Threshold-Gaming / Dilution Evasion (A06 pattern)
        #   >= 3 unmatched public/security-critical symbols removed in 1-2 files while
        #   trivial 1-statement getters/stubs or line padding keep ratios below legacy thresholds
        # ------------------------------------------------------------------
        elif len(unmatched_removed) >= 3 and (len(security_removed) >= 2 or len(public_removed) >= 3):
            unmatched_added = [
                tr.head_symbol for tr in transitions
                if tr.transition_kind == "ADDED" and tr.head_symbol is not None
            ]
            trivial_added = [
                s for s in unmatched_added
                if s.is_stub or s.statement_count <= 1
            ]
            total_lines_added = sum(fd.lines_added for fd in file_deltas)
            total_lines_deleted = sum(fd.lines_deleted for fd in file_deltas)

            # Check if dilution is present (trivial additions or comment/docstring line padding)
            has_dilution = len(trivial_added) >= 1 or total_lines_added >= total_lines_deleted
            if has_dilution or has_unresolved_callers:
                verified = has_unresolved_callers or (len(security_removed) >= 2 and len(trivial_added) >= 2)
                tier = TIER_VERIFIED if verified else TIER_LIKELY
                conf = CONFIDENCE_HIGH if verified else CONFIDENCE_MEDIUM
                sev = SEVERITY_CRITICAL if verified else SEVERITY_HIGH
                pol = POLICY_BLOCK if verified else POLICY_REVIEW

                ev = [
                    EvidenceItem(
                        kind="CRITICAL_SYMBOL_REMOVED",
                        file=s.file_path,
                        line=s.start_line,
                        symbol=s.qualified_name,
                        detail=(
                            f"Removed {s.visibility} {s.kind} '{s.qualified_name}{s.normalized_signature}' "
                            f"({s.statement_count} stmts)"
                        ),
                    )
                    for s in unmatched_removed
                ]
                for ts in trivial_added[:5]:
                    ev.append(
                        EvidenceItem(
                            kind="DILUTION_TRIVIAL_ADDITION",
                            file=ts.file_path,
                            line=ts.start_line,
                            symbol=ts.qualified_name,
                            detail=f"Added trivial {ts.statement_count}-statement {ts.kind} '{ts.qualified_name}'",
                        )
                    )

                findings.append(
                    ConsequenceFinding(
                        finding_id=f"PG-D03-THRESHOLD-GAMING-{files_with_removals[0]}",
                        detector_id=DETECTOR_D03_COMPOUND,
                        consequence_class="THRESHOLD_GAMING_DELETION",
                        tier=tier,
                        confidence=conf,
                        severity=sev,
                        policy_recommendation=pol,
                        summary=(
                            f"{len(unmatched_removed)} public/security-critical symbols "
                            f"({', '.join(s.qualified_name for s in unmatched_removed[:4])}) were deleted "
                            f"while {len(trivial_added)} trivial symbol(s) and +{total_lines_added} lines "
                            "masked the deletion ratio."
                        ),
                        affected_files=tuple(files_with_removals),
                        affected_symbols=tuple(s.qualified_name for s in unmatched_removed),
                        evidence=tuple(ev),
                        remediation=(
                            "Restore the removed security/public methods or update callers; padding commits "
                            "with trivial getters or docstrings does not offset capability removal."
                        ),
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # D05: Build / Dependency / Lockfile & Script Delta Detector
    # ------------------------------------------------------------------
    def _detect_d05_build_dependency_delta(
        self,
        file_deltas: List[FileDeltaInput],
    ) -> List[ConsequenceFinding]:
        findings: List[ConsequenceFinding] = []
        changed_basenames_by_dir: Dict[str, Set[str]] = {}
        for fd in file_deltas:
            p = Path(fd.file_path)
            parent = str(p.parent).replace("\\", "/")
            changed_basenames_by_dir.setdefault(parent, set()).add(p.name)

        for fd in file_deltas:
            p = Path(fd.file_path)
            parent = str(p.parent).replace("\\", "/")
            bname = p.name

            # 1. Check package.json lifecycle scripts & dependency drift
            if bname == "package.json" and fd.head_source:
                try:
                    head_pkg = json.loads(fd.head_source)
                    base_pkg = json.loads(fd.base_source) if fd.base_source else {}
                except Exception:
                    head_pkg, base_pkg = {}, {}

                if isinstance(head_pkg, dict):
                    head_scripts = head_pkg.get("scripts") or {}
                    base_scripts = (base_pkg.get("scripts") or {}) if isinstance(base_pkg, dict) else {}
                    if isinstance(head_scripts, dict):
                        for hook, cmd in sorted(head_scripts.items()):
                            if not isinstance(cmd, str):
                                continue
                            old_cmd = base_scripts.get(hook) if isinstance(base_scripts, dict) else None
                            if cmd == old_cmd:
                                continue
                            if _SUSPICIOUS_SCRIPT_PATTERNS.search(cmd):
                                findings.append(
                                    ConsequenceFinding(
                                        finding_id=f"PG-D05-SCRIPT-{fd.file_path}-{hook}",
                                        detector_id=DETECTOR_D05_BUILD,
                                        consequence_class="BUILD_SCRIPT_MODIFICATION",
                                        tier=TIER_VERIFIED,
                                        confidence=CONFIDENCE_HIGH,
                                        severity=SEVERITY_CRITICAL,
                                        policy_recommendation=POLICY_BLOCK,
                                        summary=(
                                            f"Suspicious shell command introduced in '{fd.file_path}' "
                                            f"script '{hook}': {cmd[:80]}"
                                        ),
                                        affected_files=(fd.file_path,),
                                        affected_symbols=(f"scripts.{hook}",),
                                        evidence=(
                                            EvidenceItem(
                                                kind="SUSPICIOUS_BUILD_SCRIPT",
                                                file=fd.file_path,
                                                line=1,
                                                symbol=f"scripts.{hook}",
                                                detail=f"Script '{hook}' set to: {cmd}",
                                            ),
                                        ),
                                        remediation=f"Remove the destructive or remote-execution command from 'scripts.{hook}' in '{fd.file_path}'.",
                                    )
                                )
                            elif hook in _SUSPICIOUS_LIFECYCLE_HOOKS:
                                findings.append(
                                    ConsequenceFinding(
                                        finding_id=f"PG-D05-HOOK-{fd.file_path}-{hook}",
                                        detector_id=DETECTOR_D05_BUILD,
                                        consequence_class="BUILD_SCRIPT_MODIFICATION",
                                        tier=TIER_LIKELY,
                                        confidence=CONFIDENCE_HIGH,
                                        severity=SEVERITY_MEDIUM,
                                        policy_recommendation=POLICY_REVIEW,
                                        summary=(
                                            f"Install lifecycle hook 'scripts.{hook}' was added or modified "
                                            f"in '{fd.file_path}'."
                                        ),
                                        affected_files=(fd.file_path,),
                                        affected_symbols=(f"scripts.{hook}",),
                                        evidence=(
                                            EvidenceItem(
                                                kind="LIFECYCLE_HOOK_CHANGED",
                                                file=fd.file_path,
                                                line=1,
                                                symbol=f"scripts.{hook}",
                                                detail=f"Lifecycle hook '{hook}': {cmd}",
                                            ),
                                        ),
                                        remediation=f"Verify that the '{hook}' lifecycle hook in '{fd.file_path}' is intentional and safe.",
                                    )
                                )

            # 2. Check manifest dependency modification without lockfile update
            if bname in _MANIFEST_LOCKFILE_PAIRS and fd.change_type == "M":
                expected_locks = _MANIFEST_LOCKFILE_PAIRS[bname]
                siblings = changed_basenames_by_dir.get(parent, set())
                has_lock_update = any(lk in siblings for lk in expected_locks)

                # For package.json, only flag if dependencies/devDependencies/peerDependencies/overrides changed
                deps_changed = True
                if bname == "package.json" and fd.base_source and fd.head_source:
                    try:
                        bp = json.loads(fd.base_source)
                        hp = json.loads(fd.head_source)
                        dep_keys = ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies", "overrides", "resolutions")
                        deps_changed = any(bp.get(k) != hp.get(k) for k in dep_keys)
                    except Exception:
                        deps_changed = True

                if deps_changed and not has_lock_update:
                    findings.append(
                        ConsequenceFinding(
                            finding_id=f"PG-D05-LOCK-{fd.file_path}",
                            detector_id=DETECTOR_D05_BUILD,
                            consequence_class="DEPENDENCY_LOCKFILE_MISMATCH",
                            tier=TIER_LIKELY,
                            confidence=CONFIDENCE_MEDIUM,
                            severity=SEVERITY_LOW,
                            policy_recommendation=POLICY_WARN,
                            summary=(
                                f"Dependency manifest '{fd.file_path}' was modified without a corresponding "
                                f"lockfile update ({'/'.join(expected_locks[:2])})."
                            ),
                            affected_files=(fd.file_path,),
                            affected_symbols=(),
                            evidence=(
                                EvidenceItem(
                                    kind="MANIFEST_WITHOUT_LOCKFILE",
                                    file=fd.file_path,
                                    line=1,
                                    symbol=None,
                                    detail=f"Modified '{bname}' without updating any of {expected_locks}",
                                ),
                            ),
                            remediation=f"Regenerate and commit the lockfile corresponding to '{fd.file_path}' to ensure reproducible builds.",
                        )
                    )

        return findings

    # ------------------------------------------------------------------
    # Verdict & Score Recommendation
    # ------------------------------------------------------------------
    def _compute_recommendation(
        self,
        findings: List[ConsequenceFinding],
    ) -> Tuple[str, float]:
        if not findings:
            return "SAFE", 0.0

        has_block = any(f.policy_recommendation == POLICY_BLOCK for f in findings)
        has_review = any(f.policy_recommendation == POLICY_REVIEW for f in findings)
        has_warn = any(f.policy_recommendation == POLICY_WARN for f in findings)

        if has_block:
            return "DESTRUCTIVE", 0.90
        if has_review:
            return "REVIEW", 0.55
        if has_warn:
            return "SAFE", 0.25
        return "SAFE", 0.0
