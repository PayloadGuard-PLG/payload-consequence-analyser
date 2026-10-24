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
DETECTOR_D08_WORKFLOW = "D08_WORKFLOW_INTEGRITY"
DETECTOR_D09_TEST = "D09_TEST_EROSION"
DETECTOR_D10_MIGRATION = "D10_MIGRATION_PERSISTENCE_LOSS"

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

# Build Wrapper Basenames for D05
_BUILD_WRAPPER_BASENAMES = frozenset({
    "mvnw", "mvnw.cmd", "gradlew", "gradlew.bat", "makefile", "gnumakefile", "build.sh", "make.bat",
})

# Migration & Persistence Patterns for D10
_MIGRATION_PATH_DIRS = frozenset({
    "migration", "migrations", "migrate", "alembic", "versions",
    "prisma", "schema", "db", "flyway", "liquibase", "sql",
})

_SQL_DROP_TABLE_RE = re.compile(
    r"\bDROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?([A-Za-z0-9_.\"'`]+)",
    re.IGNORECASE,
)
_SQL_DROP_COLUMN_RE = re.compile(
    r"(?:ALTER\s+TABLE\s+[A-Za-z0-9_.\"'`]+\s+)?\bDROP\s+COLUMN\s+(?:IF\s+EXISTS\s+)?([A-Za-z0-9_.\"'`]+)",
    re.IGNORECASE,
)
_SQL_TRUNCATE_RE = re.compile(
    r"\bTRUNCATE\s+(?:TABLE\s+)?([A-Za-z0-9_.\"'`]+)",
    re.IGNORECASE,
)
_SQL_DROP_DATABASE_RE = re.compile(
    r"\bDROP\s+(?:DATABASE|SCHEMA)\s+(?:IF\s+EXISTS\s+)?([A-Za-z0-9_.\"'`]+)",
    re.IGNORECASE,
)
_ALEMBIC_DROP_TABLE_RE = re.compile(
    r"\bop\.drop_table\(\s*['\"]([A-Za-z0-9_]+)['\"]",
    re.IGNORECASE,
)
_ALEMBIC_DROP_COLUMN_RE = re.compile(
    r"\bop\.drop_column\(\s*['\"]([A-Za-z0-9_]+)['\"]\s*,\s*['\"]([A-Za-z0-9_]+)['\"]",
    re.IGNORECASE,
)
_DJANGO_DELETE_MODEL_RE = re.compile(
    r"\bmigrations\.DeleteModel\(\s*name=['\"]([A-Za-z0-9_]+)['\"]",
    re.IGNORECASE,
)
_DJANGO_REMOVE_FIELD_RE = re.compile(
    r"\bmigrations\.RemoveField\(\s*model_name=['\"]([A-Za-z0-9_]+)['\"]\s*,\s*name=['\"]([A-Za-z0-9_]+)['\"]",
    re.IGNORECASE,
)
_JS_TS_DROP_RE = re.compile(
    r"(?:\.dropTable|\.dropColumn|dropTable|dropColumn)\(\s*['\"]([A-Za-z0-9_]+)['\"]",
    re.IGNORECASE,
)

_TEMP_TABLE_PREFIXES = ("temp_", "tmp_", "staging_", "_scratch", "temporary")

# Workflow / Action Integrity Patterns for D08
_WORKFLOW_OR_ACTION_PATH_RE = re.compile(
    r"(?:^|/)(?:\.github/workflows/[^/]+\.ya?ml|(?:\.github/actions/[^/]+/)?action\.ya?ml)$",
    re.IGNORECASE,
)

_UNTRUSTED_GH_EXPR_RE = re.compile(
    r"\$\{\{\s*("
    r"github\.head_ref\b"
    r"|github\.event\.(?:pull_request|issue|discussion)\.(?:title|body)\b"
    r"|github\.event\.pull_request\.head\.(?:ref|label|repo\.default_branch)\b"
    r"|github\.event\.(?:comment|review|review_comment)\.body\b"
    r"|github\.event\.pages\[[^\]]*\]\.page_name\b"
    r"|github\.event\.commits\[[^\]]*\]\.(?:message|author\.(?:name|email))\b"
    r"|github\.event\.head_commit\.(?:message|author\.(?:name|email))\b"
    r"|github\.event\.workflow_run\.(?:head_branch|head_commit\.message)\b"
    r")[^}]*\}\}",
    re.IGNORECASE,
)

_SHA40_RE = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)

_PRT_TRIGGER_RE = re.compile(r"\bpull_request_target\b")
_PRT_UNTRUSTED_REF_RE = re.compile(
    r"ref\s*:\s*['\"]?\$\{\{\s*github\.event\.pull_request\.head\.(?:sha|ref)\b"
    r"|ref\s*:\s*['\"]?refs/pull/",
    re.IGNORECASE,
)
_WORKFLOW_WRITE_OR_SECRETS_RE = re.compile(
    r"(?:permissions\s*:\s*write-all\b"
    r"|(?:contents|pull-requests|packages|deployments|id-token|actions|security-events|statuses|checks)\s*:\s*write\b"
    r"|\$\{\{\s*secrets\.)",
    re.IGNORECASE,
)

# Test Skip Decorators for D09
_TEST_SKIP_DECORATOR_TOKENS = frozenset({
    "skip", "skipif", "xfail", "expectedfailure", "disabled", "ignore",
})


def _is_migration_file(file_path: str) -> bool:
    """Return True if file_path appears to be a database migration or schema migration file."""
    if _is_test_path(file_path):
        return False
    norm = file_path.replace("\\", "/").lower()
    parts = [p for p in norm.split("/") if p]
    if not parts:
        return False
    bname = parts[-1]
    # Check parent directories
    if any(p in _MIGRATION_PATH_DIRS for p in parts[:-1]):
        return True
    # Check filename patterns like 0001_initial.py or 20261021_migration.sql
    if re.match(r"^\d{3,}_", bname) and (bname.endswith(".py") or bname.endswith(".sql") or bname.endswith(".rb") or bname.endswith(".js") or bname.endswith(".ts")):
        return True
    if "migration" in bname and (bname.endswith(".py") or bname.endswith(".sql") or bname.endswith(".rb") or bname.endswith(".js") or bname.endswith(".ts")):
        return True
    return False


def _is_test_path(file_path: str) -> bool:
    """Return True if file_path looks like a unit/integration test file."""
    norm = file_path.replace("\\", "/").lower()
    parts = [p for p in norm.split("/") if p]
    if any(p in ("test", "tests", "__tests__", "spec", "specs") for p in parts[:-1]):
        return True
    bname = parts[-1] if parts else norm
    return (
        bname.startswith("test_")
        or "_test." in bname
        or ".test." in bname
        or ".spec." in bname
        or bname.endswith("test.java")
        or bname.endswith("tests.java")
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
        repo_head_imports: Dict[str, List[str]] = {}

        # Include already-parsed head files
        parsed_head_paths: Set[str] = set()
        for fpath, pr in head_parse_results.items():
            parsed_head_paths.add(fpath)
            repo_call_sites.extend(pr.call_sites)
            repo_head_symbols.extend(pr.symbols)
            repo_head_imports[fpath] = list(pr.imports)

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
                repo_head_imports[fpath] = list(pr.imports)
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
        # Stage D: Run Detectors D01 - D09
        # ------------------------------------------------------------------
        t3 = time.perf_counter()
        findings: List[ConsequenceFinding] = []

        findings.extend(self._detect_d01_parser_incomplete(base_parse_results, head_parse_results))
        findings.extend(self._detect_d02_structural_and_weakening(transitions, file_deltas))
        findings.extend(self._detect_d06_guard_regressions(transitions))
        d04_findings, unresolved_by_symbol = self._detect_d04_public_api_and_callers(
            transitions, repo_head_symbols, repo_call_sites, repo_head_imports
        )
        findings.extend(d04_findings)
        findings.extend(
            self._detect_d03_compound_and_threshold_gaming(
                transitions, file_deltas, findings, unresolved_by_symbol
            )
        )
        findings.extend(self._detect_d05_build_dependency_delta(file_deltas))
        findings.extend(self._detect_d08_workflow_integrity(file_deltas))
        findings.extend(self._detect_d09_test_erosion(transitions))
        findings.extend(self._detect_d10_migration_persistence_loss(file_deltas))

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
            "repo_call_sites": len(repo_call_sites),
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
    # D06: Security / Validation / Rollback Guard Regression Detector (v2)
    # ------------------------------------------------------------------
    def _detect_d06_guard_regressions(
        self,
        transitions: List[SymbolTransition],
    ) -> List[ConsequenceFinding]:
        findings: List[ConsequenceFinding] = []

        def _parse_if_guards(conds: Tuple[str, ...]) -> Dict[str, List[Tuple[str, str]]]:
            parsed: Dict[str, List[Tuple[str, str]]] = {}
            for item in conds:
                if item.startswith("if_guard:"):
                    parts = item.split(":", 3)
                    if len(parts) == 4:
                        _, callee, pol, act = parts
                        parsed.setdefault(callee, []).append((pol, act))
            return parsed

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

            # 3. Check guard condition polarity inversion, enforcement neutralization,
            #    boolean short-circuiting, early-return bypass, and exception-swallowing (D06 v2)
            b_conds = getattr(bs, "guard_conditions", ()) or ()
            h_conds = getattr(hs, "guard_conditions", ()) or ()
            b_if = _parse_if_guards(b_conds)
            h_if = _parse_if_guards(h_conds)

            weakened_notes: List[str] = []
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

            for callee, b_pairs in sorted(b_if.items()):
                if not (_is_guard_call(callee) or _is_security_relevant_name(bs.qualified_name)):
                    continue
                h_pairs = h_if.get(callee, [])
                if not h_pairs:
                    continue
                for b_pol, b_act in b_pairs:
                    if b_act not in ("raise", "return_deny", "rollback"):
                        continue
                    # Check if polarity inverted while keeping enforcement action
                    for h_pol, h_act in h_pairs:
                        if h_pol != b_pol and h_act == b_act and (b_pol, b_act) not in h_pairs:
                            weakened_notes.append(f"{callee} polarity inverted ({b_pol}->{h_pol})")
                            ev_items.append(
                                EvidenceItem(
                                    kind="GUARD_POLARITY_INVERTED",
                                    file=hs.file_path,
                                    line=hs.start_line,
                                    symbol=hs.qualified_name,
                                    detail=(
                                        f"Guard condition on '{callee}()' in '{hs.qualified_name}' inverted "
                                        f"polarity from '{b_pol}' to '{h_pol}' ({b_act})"
                                    ),
                                )
                            )
                        elif h_act in ("noop", "return_allow") and (b_pol, b_act) not in h_pairs:
                            weakened_notes.append(f"{callee} enforcement neutralized ({b_act}->{h_act})")
                            ev_items.append(
                                EvidenceItem(
                                    kind="GUARD_ENFORCEMENT_NEUTRALIZED",
                                    file=hs.file_path,
                                    line=hs.start_line,
                                    symbol=hs.qualified_name,
                                    detail=(
                                        f"Guard failure branch for '{callee}()' in '{hs.qualified_name}' "
                                        f"weakened from '{b_act}' to '{h_act}'"
                                    ),
                                )
                            )

            # Boolean short-circuiting of guard conditions (`and False`, `|| true`, `if False:`)
            b_sc = {c for c in b_conds if c.startswith("if_short_circuit:")}
            h_sc = {c for c in h_conds if c.startswith("if_short_circuit:")}
            new_sc = sorted(h_sc - b_sc)
            for sc in new_sc:
                parts = sc.split(":", 3)
                if len(parts) == 4:
                    _, target, sc_kind, act = parts
                    # Only flag if the short-circuited branch was an enforcing guard or inside a security function
                    is_enforcing = (
                        (sc_kind == "and_false" and act in ("raise", "return_deny", "rollback"))
                        or (sc_kind == "or_true" and act in ("return_allow", "other", "noop"))
                        or _is_guard_call(target)
                        or _is_security_relevant_name(bs.qualified_name)
                    )
                    if is_enforcing and (b_if or b_conds or base_guard_calls or _is_security_relevant_name(bs.qualified_name)):
                        weakened_notes.append(f"{target} short-circuited ({sc_kind})")
                        ev_items.append(
                            EvidenceItem(
                                kind="GUARD_SHORT_CIRCUITED",
                                file=hs.file_path,
                                line=hs.start_line,
                                symbol=hs.qualified_name,
                                detail=(
                                    f"Guard condition on '{target}' in '{hs.qualified_name}' was "
                                    f"short-circuited with '{sc_kind}' ({act})"
                                ),
                            )
                        )

            # Early-return bypass before remaining statements/guards
            b_early = {c for c in b_conds if c.startswith("early_return_bypass:")}
            h_early = {c for c in h_conds if c.startswith("early_return_bypass:")}
            new_early = sorted(h_early - b_early)
            if new_early and (base_guard_calls or base_guard_decos or _is_security_relevant_name(bs.qualified_name)):
                weakened_notes.append("unconditional early return bypass")
                ev_items.append(
                    EvidenceItem(
                        kind="GUARD_BYPASSED_BY_EARLY_RETURN",
                        file=hs.file_path,
                        line=hs.start_line,
                        symbol=hs.qualified_name,
                        detail=(
                            f"Inserted unconditional early return ({new_early[0].split(':', 1)[1]}) "
                            f"before guard statements in '{hs.qualified_name}'"
                        ),
                    )
                )

            # State-guard clauses (`if (!response.ok) throw ...` / `if s.started { return fmt.Errorf(...) }`)
            b_state_guards = {c for c in b_conds if c.startswith("if_state_guard:")}
            h_state_guards = {c for c in h_conds if c.startswith("if_state_guard:")}
            removed_state_guards = sorted(b_state_guards - h_state_guards)
            # Only flag if the function did not replace the state guard with a new call-based guard
            added_if_callees = set(h_if.keys()) - set(b_if.keys())
            if removed_state_guards and not added_if_callees and not new_sc and not hs.is_stub:
                for sg in removed_state_guards:
                    parts = sg.split(":", 3)
                    if len(parts) == 4:
                        _, subj, pol, act = parts
                        removed_calls.append(f"guard({subj})")
                        ev_items.append(
                            EvidenceItem(
                                kind="GUARD_CLAUSE_REMOVED",
                                file=hs.file_path,
                                line=hs.start_line,
                                symbol=hs.qualified_name,
                                detail=(
                                    f"Removed enforcing state guard on '{subj}' ({pol} -> {act}) "
                                    f"from '{hs.qualified_name}'"
                                ),
                            )
                        )

            # Exception handler swallowed (raise/rollback/return_deny -> swallowed_noop/swallowed_allow)
            b_exc = {c.split(":", 1)[1] for c in b_conds if c.startswith("except_handler:")}
            h_exc = {c.split(":", 1)[1] for c in h_conds if c.startswith("except_handler:")}
            enforcing_exc = b_exc & {"raise", "rollback", "return_deny"}
            swallowed_exc = h_exc & {"swallowed_noop", "swallowed_allow"}
            if enforcing_exc and swallowed_exc and not (h_exc & {"raise", "rollback", "return_deny"}):
                weakened_notes.append(
                    f"exception handler weakened ({sorted(enforcing_exc)[0]}->{sorted(swallowed_exc)[0]})"
                )
                ev_items.append(
                    EvidenceItem(
                        kind="EXCEPTION_HANDLER_SWALLOWED",
                        file=hs.file_path,
                        line=hs.start_line,
                        symbol=hs.qualified_name,
                        detail=(
                            f"Exception handler in '{hs.qualified_name}' weakened from "
                            f"'{sorted(enforcing_exc)[0]}' to '{sorted(swallowed_exc)[0]}'"
                        ),
                    )
                )

            if not ev_items:
                continue

            all_labels = removed_decos + removed_calls + weakened_notes
            c_class = "SECURITY_GUARD_REMOVED" if (removed_decos or removed_calls) else "SECURITY_GUARD_WEAKENED"
            action_verb = "removed" if (removed_decos or removed_calls) else "weakened"

            findings.append(
                ConsequenceFinding(
                    finding_id=f"PG-D06-{hs.file_path}-{hs.qualified_name}",
                    detector_id=DETECTOR_D06_GUARD,
                    consequence_class=c_class,
                    tier=TIER_VERIFIED,
                    confidence=CONFIDENCE_HIGH,
                    severity=SEVERITY_HIGH,
                    policy_recommendation=POLICY_BLOCK,
                    summary=(
                        f"Surviving {hs.kind} '{hs.qualified_name}' in '{hs.file_path}' {action_verb} "
                        f"security/integrity guard(s): {', '.join(all_labels)}"
                    ),
                    affected_files=(hs.file_path,),
                    affected_symbols=(hs.qualified_name,),
                    evidence=tuple(ev_items),
                    remediation=(
                        f"Restore the guard enforcement ({', '.join(all_labels)}) in "
                        f"'{hs.qualified_name}' or verify an equivalent upstream protection."
                    ),
                )
            )

        return findings

    # ------------------------------------------------------------------
    # D04: Public API Contract Break & Cross-File Unresolved Caller Detector (v2)
    # ------------------------------------------------------------------
    @staticmethod
    def _parse_file_import_bindings(imports: List[str]) -> Tuple[Dict[str, Tuple[str, str]], Dict[str, str], Set[str]]:
        """
        Parse import entries into:
        - symbol_aliases: {local_name: (module_stem, original_symbol_name)}
        - module_aliases: {local_qualifier: module_stem}
        - imported_modules: {module_stem}
        """
        symbol_aliases: Dict[str, Tuple[str, str]] = {}
        module_aliases: Dict[str, str] = {}
        imported_modules: Set[str] = set()

        for imp in imports:
            s = imp.strip()
            # 1. JS/TS ES import: import { a as b, c } from './mod' or import * as ns from './mod'
            m_from = re.search(r"from\s+['\"]([^'\"]+)['\"]", s)
            if m_from:
                mod_stem = Path(m_from.group(1)).stem
                imported_modules.add(mod_stem)
                m_ns = re.search(r"\*\s+as\s+([A-Za-z0-9_$]+)", s)
                if m_ns:
                    module_aliases[m_ns.group(1)] = mod_stem
                m_braces = re.search(r"\{([^}]+)\}", s)
                if m_braces:
                    for part in m_braces.group(1).split(","):
                        part = part.strip()
                        if not part:
                            continue
                        if " as " in part:
                            orig, loc = [p.strip() for p in part.split(" as ", 1)]
                            symbol_aliases[loc] = (mod_stem, orig)
                        else:
                            symbol_aliases[part] = (mod_stem, part)
                continue

            # 2. CommonJS require: const { a: b } = require('./mod') or const m = require('./mod')
            m_req = re.search(r"require\s*\(\s*['\"]([^'\"]+)['\"]\s*\)", s)
            if m_req and "=" in s:
                mod_stem = Path(m_req.group(1)).stem
                imported_modules.add(mod_stem)
                lhs = s.split("=", 1)[0].strip()
                m_braces = re.search(r"\{([^}]+)\}", lhs)
                if m_braces:
                    for part in m_braces.group(1).split(","):
                        part = part.strip()
                        if not part:
                            continue
                        if ":" in part:
                            orig, loc = [p.strip() for p in part.split(":", 1)]
                            symbol_aliases[loc] = (mod_stem, orig)
                        else:
                            symbol_aliases[part] = (mod_stem, part)
                else:
                    ident = lhs.split()[-1].strip()
                    if ident.isidentifier():
                        module_aliases[ident] = mod_stem
                continue

            # 3. Rust use declaration: use crate::auth::verify as check_auth;
            if s.startswith("use "):
                clean = s[4:].rstrip(";").strip()
                if " as " in clean:
                    target, loc = [p.strip() for p in clean.split(" as ", 1)]
                else:
                    target = clean
                    loc = clean.split("::")[-1].strip()
                parts = [p for p in target.split("::") if p not in ("crate", "self", "super")]
                if len(parts) >= 2:
                    mod_stem, orig = parts[-2], parts[-1]
                    imported_modules.add(mod_stem)
                    symbol_aliases[loc] = (mod_stem, orig)
                continue

            # 4. Python import entries from _extract_python_parse_result:
            #    "pkg.mod.sym as alias", "pkg.mod as alias", "pkg.mod.sym", "pkg.mod"
            if " as " in s:
                target, loc = [p.strip() for p in s.split(" as ", 1)]
                parts = [p for p in target.split(".") if p]
                if len(parts) >= 2:
                    symbol_aliases[loc] = (parts[-2], parts[-1])
                    module_aliases[loc] = parts[-1]
                    imported_modules.add(parts[-2])
                    imported_modules.add(parts[-1])
                elif len(parts) == 1:
                    module_aliases[loc] = parts[0]
                    imported_modules.add(parts[0])
            else:
                parts = [p for p in s.split(".") if p]
                if len(parts) >= 2:
                    symbol_aliases[parts[-1]] = (parts[-2], parts[-1])
                    imported_modules.add(parts[-2])
                    imported_modules.add(parts[-1])
                elif len(parts) == 1:
                    imported_modules.add(parts[0])
                    module_aliases[parts[0]] = parts[0]

        return symbol_aliases, module_aliases, imported_modules

    def _detect_d04_public_api_and_callers(
        self,
        transitions: List[SymbolTransition],
        repo_head_symbols: List[SymbolFact],
        repo_call_sites: List[CallSiteFact],
        repo_head_imports: Optional[Dict[str, List[str]]] = None,
    ) -> Tuple[List[ConsequenceFinding], Dict[str, List[CallSiteFact]]]:
        findings: List[ConsequenceFinding] = []
        unresolved_by_symbol: Dict[str, List[CallSiteFact]] = {}
        repo_head_imports = repo_head_imports or {}

        # Precompute import bindings per head file
        bindings_by_file: Dict[str, Tuple[Dict[str, Tuple[str, str]], Dict[str, str], Set[str]]] = {
            fpath: self._parse_file_import_bindings(imps)
            for fpath, imps in repo_head_imports.items()
        }

        # Build set of all surviving symbol names and per-file surviving names in head
        surviving_names: Set[str] = {s.name for s in repo_head_symbols}
        surviving_names_by_file: Dict[str, Set[str]] = {}
        surviving_names_by_mod: Dict[str, Set[str]] = {}
        for s in repo_head_symbols:
            surviving_names_by_file.setdefault(s.file_path, set()).add(s.name)
            surviving_names_by_mod.setdefault(Path(s.file_path).stem, set()).add(s.name)

        # 1. Check unmatched REMOVED symbols for unresolved call sites in head & public API removal
        removed_transitions = [
            tr for tr in transitions
            if tr.transition_kind == "REMOVED" and tr.base_symbol is not None
        ]

        # Group unresolved callers by (file_path, container_or_symbol_name) and API removals by file_path
        caller_groups: Dict[Tuple[str, str], List[Tuple[SymbolFact, List[CallSiteFact]]]] = {}
        api_removal_groups: Dict[str, List[SymbolFact]] = {}

        for tr in removed_transitions:
            bs = tr.base_symbol
            assert bs is not None
            bs_mod = Path(bs.file_path).stem

            matching_callers: List[CallSiteFact] = []
            for cs in repo_call_sites:
                sym_aliases, mod_aliases, imp_mods = bindings_by_file.get(cs.file_path, ({}, {}, set()))

                # Resolve aliased callee or module qualifier
                effective_callee = cs.callee_name
                effective_mod: Optional[str] = None
                if not cs.qualifier and cs.callee_name in sym_aliases:
                    effective_mod, effective_callee = sym_aliases[cs.callee_name]
                elif cs.qualifier:
                    effective_mod = mod_aliases.get(cs.qualifier, cs.qualifier)

                if effective_callee != bs.name:
                    continue

                if bs.parent_symbol:
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
                    # Top-level function/class:
                    # Match if:
                    # (a) caller explicitly qualifies or aliases from bs_mod (e.g. billing.cancel() or aliased import), OR
                    # (b) no symbol with bs.name survives anywhere in head (unless caller explicitly qualified a different module), OR
                    # (c) another module still defines bs.name, but caller's file explicitly imported bs.name from bs_mod
                    #     and does not define bs.name locally.
                    if effective_mod == bs_mod:
                        matching_callers.append(cs)
                    elif bs.name not in surviving_names:
                        if not effective_mod or effective_mod == bs_mod or cs.file_path == bs.file_path:
                            matching_callers.append(cs)
                    else:
                        # Another module in head still defines a symbol named bs.name:
                        # check if cs.file_path specifically imported bs.name from bs_mod
                        local_defs = surviving_names_by_file.get(cs.file_path, set())
                        if bs.name not in local_defs and sym_aliases.get(cs.callee_name) == (bs_mod, bs.name):
                            matching_callers.append(cs)

            if matching_callers:
                unresolved_by_symbol[bs.symbol_id] = matching_callers
                group_key = (bs.file_path, bs.parent_symbol or bs.qualified_name)
                caller_groups.setdefault(group_key, []).append((bs, matching_callers))
            elif bs.is_exported and bs.visibility == "public" and bs.kind in ("function", "method", "class", "interface", "struct", "trait"):
                api_removal_groups.setdefault(bs.file_path, []).append(bs)

        # Emit consolidated UNRESOLVED_CALLER findings per container/top-level symbol
        for (file_path, group_name), items in sorted(caller_groups.items()):
            if len(items) == 1:
                bs, matching_callers = items[0]
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
            else:
                all_syms = tuple(bs.qualified_name for bs, _ in items)
                all_callers = [cs for _, m_cs in items for cs in m_cs]
                caller_files = sorted({file_path} | {cs.file_path for cs in all_callers})
                ev = [
                    EvidenceItem(
                        kind="REMOVED_SYMBOL",
                        file=bs.file_path,
                        line=bs.start_line,
                        symbol=bs.qualified_name,
                        detail=f"Removed {bs.visibility} {bs.kind} '{bs.qualified_name}{bs.normalized_signature}'",
                    )
                    for bs, _ in items[:5]
                ]
                for cs in all_callers[:5]:
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
                        finding_id=f"PG-D04-CALLER-{file_path}-{group_name}",
                        detector_id=DETECTOR_D04_API,
                        consequence_class="UNRESOLVED_CALLER",
                        tier=TIER_VERIFIED,
                        confidence=CONFIDENCE_HIGH,
                        severity=SEVERITY_CRITICAL,
                        policy_recommendation=POLICY_BLOCK,
                        summary=(
                            f"Removed {len(items)} symbols in '{group_name}' ({file_path}: "
                            f"{', '.join(all_syms[:4])}{'...' if len(all_syms) > 4 else ''}) leaving "
                            f"{len(all_callers)} unresolved call site(s) in head "
                            f"(e.g. {all_callers[0].file_path}:{all_callers[0].line})."
                        ),
                        affected_files=tuple(caller_files),
                        affected_symbols=all_syms,
                        evidence=tuple(ev),
                        remediation=(
                            f"Update or remove all callers of '{group_name}' members "
                            f"(including {all_callers[0].file_path}:{all_callers[0].line}) "
                            "or restore the removed symbols."
                        ),
                    )
                )

        # Emit consolidated PUBLIC_API_REMOVAL findings per file
        for file_path, syms_removed in sorted(api_removal_groups.items()):
            if len(syms_removed) == 1:
                bs = syms_removed[0]
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
            else:
                sec_rel = any(_is_security_relevant_name(s.qualified_name) for s in syms_removed)
                sev = SEVERITY_HIGH if sec_rel else SEVERITY_MEDIUM
                pol = POLICY_REVIEW if sec_rel else POLICY_WARN
                sym_names = tuple(s.qualified_name for s in syms_removed)
                ev = tuple(
                    EvidenceItem(
                        kind="PUBLIC_EXPORT_REMOVED",
                        file=s.file_path,
                        line=s.start_line,
                        symbol=s.qualified_name,
                        detail=f"Exported {s.kind} '{s.qualified_name}{s.normalized_signature}' deleted",
                    )
                    for s in syms_removed[:8]
                )
                findings.append(
                    ConsequenceFinding(
                        finding_id=f"PG-D04-API-{file_path}",
                        detector_id=DETECTOR_D04_API,
                        consequence_class="PUBLIC_API_REMOVAL",
                        tier=TIER_LIKELY,
                        confidence=CONFIDENCE_MEDIUM,
                        severity=sev,
                        policy_recommendation=pol,
                        summary=(
                            f"{len(syms_removed)} exported public symbols were removed from '{file_path}' "
                            f"({', '.join(sym_names[:4])}{'...' if len(sym_names) > 4 else ''}) "
                            "with no rename or move counterpart."
                        ),
                        affected_files=(file_path,),
                        affected_symbols=sym_names,
                        evidence=ev,
                        remediation=(
                            f"Verify whether external consumers depend on the {len(syms_removed)} removed "
                            f"exports in '{file_path}' or provide deprecation aliases."
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


            # 3. Check build wrapper scripts (mvnw, gradlew, Makefile, build.sh)
            if bname.lower() in _BUILD_WRAPPER_BASENAMES and fd.head_source:
                base_s = fd.base_source or ""
                head_s = fd.head_source
                suspicious_matches = []
                for idx, line in enumerate(head_s.splitlines(), start=1):
                    stripped = line.strip()
                    if stripped.startswith("#"):
                        continue
                    if _SUSPICIOUS_SCRIPT_PATTERNS.search(stripped):
                        if stripped not in base_s:
                            suspicious_matches.append((idx, stripped))

                if suspicious_matches:
                    findings.append(
                        ConsequenceFinding(
                            finding_id=f"PG-D05-WRAPPER-{fd.file_path}",
                            detector_id=DETECTOR_D05_BUILD,
                            consequence_class="BUILD_WRAPPER_TAMPERING",
                            tier=TIER_VERIFIED,
                            confidence=CONFIDENCE_HIGH,
                            severity=SEVERITY_CRITICAL,
                            policy_recommendation=POLICY_BLOCK,
                            summary=(
                                f"Build wrapper script '{fd.file_path}' introduces suspicious remote execution "
                                f"or binary payload ({suspicious_matches[0][1][:60]})."
                            ),
                            affected_files=(fd.file_path,),
                            affected_symbols=(bname,),
                            evidence=tuple(
                                EvidenceItem(
                                    kind="SUSPICIOUS_BUILD_WRAPPER",
                                    file=fd.file_path,
                                    line=lno,
                                    symbol=bname,
                                    detail=f"Line {lno}: {ltxt}",
                                )
                                for lno, ltxt in suspicious_matches
                            ),
                            remediation=(
                                f"Ensure build wrapper '{fd.file_path}' is generated by official toolchains and does "
                                "not download or pipe unverified remote code directly to execution shells."
                            ),
                        )
                    )

        return findings

    # ------------------------------------------------------------------
    # D08: Workflow / CI Integrity & Supply-Chain Detector
    # ------------------------------------------------------------------
    @staticmethod
    def _extract_workflow_run_lines(yaml_text: str) -> List[Tuple[int, str]]:
        """Extract (line_number, line_text) pairs belonging to YAML `run:` step blocks."""
        if not yaml_text:
            return []
        run_lines: List[Tuple[int, str]] = []
        in_run_block = False
        run_indent = 0
        run_key_re = re.compile(r"^(\s*)(?:-\s*)?run\s*:\s*(.*)$")
        yaml_key_re = re.compile(r"^(\s*)(?:-\s*)?[A-Za-z0-9_-]+\s*:")

        for idx, raw_line in enumerate(yaml_text.splitlines(), start=1):
            stripped = raw_line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            m_run = run_key_re.match(raw_line)
            if m_run:
                prefix, rest = m_run.group(1), m_run.group(2).strip()
                # Effective indentation of the `run` property itself
                dash_offset = raw_line.find("run")
                run_indent = dash_offset if dash_offset >= 0 else len(prefix)
                if rest in ("|", "|-", "|+", ">", ">-", ">+", ""):
                    in_run_block = True
                else:
                    in_run_block = True
                    run_lines.append((idx, rest))
                continue

            if in_run_block:
                leading_spaces = len(raw_line) - len(raw_line.lstrip(" "))
                m_key = yaml_key_re.match(raw_line)
                if leading_spaces <= run_indent:
                    in_run_block = False
                elif m_key and (len(raw_line) - len(raw_line.lstrip(" -"))) <= run_indent:
                    in_run_block = False
                else:
                    run_lines.append((idx, stripped))
        return run_lines

    def _detect_d08_workflow_integrity(
        self,
        file_deltas: List[FileDeltaInput],
    ) -> List[ConsequenceFinding]:
        findings: List[ConsequenceFinding] = []
        uses_re = re.compile(r"uses\s*:\s*['\"]?([A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+)@([^\s'\"#]+)")
        continue_on_error_re = re.compile(r"^\s*continue-on-error\s*:\s*true\b", re.IGNORECASE | re.MULTILINE)
        write_all_re = re.compile(r"^\s*permissions\s*:\s*write-all\b", re.IGNORECASE | re.MULTILINE)

        for fd in file_deltas:
            norm_path = fd.file_path.replace("\\", "/")
            if not _WORKFLOW_OR_ACTION_PATH_RE.search(norm_path):
                continue
            if not fd.head_source:
                continue
            base_src = fd.base_source or ""
            head_src = fd.head_source

            # 1. Untrusted GitHub expression interpolation inside `run:` shell blocks (W02)
            base_run_exprs = {
                m.group(1).strip()
                for _, line_txt in self._extract_workflow_run_lines(base_src)
                for m in _UNTRUSTED_GH_EXPR_RE.finditer(line_txt)
            }
            head_run_matches: List[Tuple[int, str]] = []
            for line_no, line_txt in self._extract_workflow_run_lines(head_src):
                for m in _UNTRUSTED_GH_EXPR_RE.finditer(line_txt):
                    expr = m.group(1).strip()
                    if expr not in base_run_exprs:
                        head_run_matches.append((line_no, expr))

            if head_run_matches:
                unique_exprs = sorted({expr for _, expr in head_run_matches})
                ev = tuple(
                    EvidenceItem(
                        kind="WORKFLOW_RUN_EXPRESSION_INJECTION",
                        file=fd.file_path,
                        line=line_no,
                        symbol="run",
                        detail=f"Untrusted GitHub context '${{{{ {expr} }}}}' interpolated directly into `run:` shell script",
                    )
                    for line_no, expr in head_run_matches
                )
                findings.append(
                    ConsequenceFinding(
                        finding_id=f"PG-D08-INJECTION-{fd.file_path}",
                        detector_id=DETECTOR_D08_WORKFLOW,
                        consequence_class="UNTRUSTED_WORKFLOW_EXPRESSION_INJECTION",
                        tier=TIER_VERIFIED,
                        confidence=CONFIDENCE_HIGH,
                        severity=SEVERITY_CRITICAL,
                        policy_recommendation=POLICY_BLOCK,
                        summary=(
                            f"Workflow '{fd.file_path}' interpolates untrusted GitHub event context "
                            f"({', '.join(unique_exprs[:3])}) directly inside a `run:` shell block."
                        ),
                        affected_files=(fd.file_path,),
                        affected_symbols=("run",),
                        evidence=ev,
                        remediation=(
                            "Bind the untrusted GitHub expression to an intermediate step `env:` variable "
                            "and reference it as a double-quoted shell variable (`\"$VAR\"`) inside `run:`."
                        ),
                    )
                )

            # 2. pull_request_target + untrusted PR head checkout ("Pwn Request" W01)
            base_has_prt_checkout = bool(
                _PRT_TRIGGER_RE.search(base_src) and _PRT_UNTRUSTED_REF_RE.search(base_src)
            )
            head_has_prt_checkout = bool(
                _PRT_TRIGGER_RE.search(head_src) and _PRT_UNTRUSTED_REF_RE.search(head_src)
            )
            if head_has_prt_checkout and not base_has_prt_checkout:
                m_ref = _PRT_UNTRUSTED_REF_RE.search(head_src)
                ref_line = head_src[: m_ref.start()].count("\n") + 1 if m_ref else 1
                has_priv = bool(_WORKFLOW_WRITE_OR_SECRETS_RE.search(head_src))
                sev = SEVERITY_CRITICAL if has_priv else SEVERITY_HIGH
                pol = POLICY_BLOCK if has_priv else POLICY_REVIEW
                findings.append(
                    ConsequenceFinding(
                        finding_id=f"PG-D08-PRT-{fd.file_path}",
                        detector_id=DETECTOR_D08_WORKFLOW,
                        consequence_class="PULL_REQUEST_TARGET_UNTRUSTED_CHECKOUT",
                        tier=TIER_VERIFIED,
                        confidence=CONFIDENCE_HIGH,
                        severity=sev,
                        policy_recommendation=pol,
                        summary=(
                            f"Workflow '{fd.file_path}' combines `pull_request_target` with an explicit "
                            "checkout of untrusted pull request head code."
                        ),
                        affected_files=(fd.file_path,),
                        affected_symbols=("on.pull_request_target",),
                        evidence=(
                            EvidenceItem(
                                kind="PRT_UNTRUSTED_CHECKOUT",
                                file=fd.file_path,
                                line=ref_line,
                                symbol="on.pull_request_target",
                                detail=(
                                    "Workflow triggers on `pull_request_target` and checks out "
                                    "untrusted PR head ref"
                                    + (" with write permissions or secrets access" if has_priv else "")
                                ),
                            ),
                        ),
                        remediation=(
                            "Do not check out untrusted PR head code inside a `pull_request_target` workflow; "
                            "use an unprivileged `pull_request` workflow and pass artifacts to a separate workflow_run."
                        ),
                    )
                )

            # 3. Action SHA pin downgrade to mutable tag/branch (W03)
            downgraded: List[Tuple[int, str, str, str]] = []
            if base_src:
                base_sha_pins: Dict[str, str] = {}
                for m in uses_re.finditer(base_src):
                    act_name, ref_val = m.group(1), m.group(2)
                    if _SHA40_RE.match(ref_val):
                        base_sha_pins[act_name] = ref_val

                downgraded: List[Tuple[int, str, str, str]] = []
                for m in uses_re.finditer(head_src):
                    act_name, ref_val = m.group(1), m.group(2)
                    if act_name in base_sha_pins and not _SHA40_RE.match(ref_val):
                        line_no = head_src[: m.start()].count("\n") + 1
                        downgraded.append((line_no, act_name, base_sha_pins[act_name], ref_val))

                if downgraded:
                    ev = tuple(
                        EvidenceItem(
                            kind="ACTION_SHA_PIN_DOWNGRADED",
                            file=fd.file_path,
                            line=line_no,
                            symbol=act_name,
                            detail=f"Action '{act_name}' downgraded from immutable SHA '{old_sha[:12]}...' to mutable ref '@{new_ref}'",
                        )
                        for line_no, act_name, old_sha, new_ref in downgraded
                    )
                    findings.append(
                        ConsequenceFinding(
                            finding_id=f"PG-D08-PINDOWN-{fd.file_path}",
                            detector_id=DETECTOR_D08_WORKFLOW,
                            consequence_class="ACTION_PIN_DOWNGRADE",
                            tier=TIER_VERIFIED,
                            confidence=CONFIDENCE_HIGH,
                            severity=SEVERITY_HIGH,
                            policy_recommendation=POLICY_REVIEW,
                            summary=(
                                f"Workflow '{fd.file_path}' downgraded {len(downgraded)} GitHub Action(s) "
                                f"from immutable 40-char commit SHAs to mutable refs ({', '.join(a for _, a, _, _ in downgraded[:3])})."
                            ),
                            affected_files=(fd.file_path,),
                            affected_symbols=tuple(sorted({a for _, a, _, _ in downgraded})),
                            evidence=ev,
                            remediation="Pin third-party GitHub Actions to full 40-character commit SHAs instead of mutable tags or branch names.",
                        )
                    )

            # 4. CI gate weakened (`continue-on-error: true` or `permissions: write-all` added on modified workflow)
            if fd.change_type == "M" and base_src:
                base_coe = len(continue_on_error_re.findall(base_src))
                head_coe = len(continue_on_error_re.findall(head_src))
                base_wa = bool(write_all_re.search(base_src))
                head_wa = bool(write_all_re.search(head_src))

                gate_ev: List[EvidenceItem] = []
                if head_coe > base_coe:
                    m_coe = continue_on_error_re.search(head_src)
                    line_no = head_src[: m_coe.start()].count("\n") + 1 if m_coe else 1
                    gate_ev.append(
                        EvidenceItem(
                            kind="CONTINUE_ON_ERROR_ADDED",
                            file=fd.file_path,
                            line=line_no,
                            symbol="continue-on-error",
                            detail=f"Added `continue-on-error: true` ({base_coe} -> {head_coe}) allowing failing CI steps to pass silently",
                        )
                    )
                if head_wa and not base_wa:
                    m_wa = write_all_re.search(head_src)
                    line_no = head_src[: m_wa.start()].count("\n") + 1 if m_wa else 1
                    gate_ev.append(
                        EvidenceItem(
                            kind="PERMISSIONS_WRITE_ALL_ADDED",
                            file=fd.file_path,
                            line=line_no,
                            symbol="permissions",
                            detail="Added overly broad `permissions: write-all` to workflow",
                        )
                    )

                if gate_ev:
                    findings.append(
                        ConsequenceFinding(
                            finding_id=f"PG-D08-CIGATE-{fd.file_path}",
                            detector_id=DETECTOR_D08_WORKFLOW,
                            consequence_class="CI_GATE_WEAKENED",
                            tier=TIER_VERIFIED,
                            confidence=CONFIDENCE_HIGH,
                            severity=SEVERITY_MEDIUM,
                            policy_recommendation=POLICY_REVIEW,
                            summary=(
                                f"Workflow '{fd.file_path}' weakens CI enforcement gates or permissions "
                                f"({', '.join(e.symbol or e.kind for e in gate_ev)})."
                            ),
                            affected_files=(fd.file_path,),
                            affected_symbols=tuple(e.symbol for e in gate_ev if e.symbol),
                            evidence=tuple(gate_ev),
                            remediation="Remove `continue-on-error: true` from required verification steps and scope `permissions:` to least privilege.",
                        )
                    )


            # 5. Privileged `workflow_run` combining untrusted artifact download with execution
            base_has_wfr = bool(re.search(r"\bworkflow_run\b", base_src))
            head_has_wfr = bool(re.search(r"\bworkflow_run\b", head_src))
            head_has_download = bool(re.search(r"actions/download-artifact@", head_src, re.IGNORECASE))
            base_has_download = bool(re.search(r"actions/download-artifact@", base_src, re.IGNORECASE))
            if head_has_wfr and head_has_download and not (base_has_wfr and base_has_download):
                m_dl = re.search(r"actions/download-artifact@", head_src, re.IGNORECASE)
                lno = head_src[: m_dl.start()].count("\n") + 1 if m_dl else 1
                findings.append(
                    ConsequenceFinding(
                        finding_id=f"PG-D08-WORKFLOWRUN-{fd.file_path}",
                        detector_id=DETECTOR_D08_WORKFLOW,
                        consequence_class="WORKFLOW_RUN_UNTRUSTED_ARTIFACT",
                        tier=TIER_VERIFIED,
                        confidence=CONFIDENCE_HIGH,
                        severity=SEVERITY_HIGH,
                        policy_recommendation=POLICY_REVIEW,
                        summary=(
                            f"Workflow '{fd.file_path}' triggers on privileged `workflow_run` and downloads "
                            "untrusted PR artifacts, introducing artifact poisoning risk."
                        ),
                        affected_files=(fd.file_path,),
                        affected_symbols=("on.workflow_run",),
                        evidence=(
                            EvidenceItem(
                                kind="WORKFLOW_RUN_ARTIFACT_DOWNLOAD",
                                file=fd.file_path,
                                line=lno,
                                symbol="on.workflow_run",
                                detail="Workflow triggers on `workflow_run` and downloads untrusted artifacts",
                            ),
                        ),
                        remediation=(
                            "Do not execute or unpack untrusted pull request artifacts directly in a privileged `workflow_run` "
                            "job that holds repository secrets or write tokens."
                        ),
                    )
                )

            # 6. Unpinned Third-Party Action Introduced (when action is newly introduced in head)
            base_actions = {m.group(1): m.group(2) for m in uses_re.finditer(base_src)}
            unpinned_new = []
            for m in uses_re.finditer(head_src):
                act_name, ref_val = m.group(1), m.group(2)
                if act_name.startswith("./") or act_name.startswith("docker://"):
                    continue
                if not _SHA40_RE.match(ref_val):
                    if act_name not in base_actions:
                        lno = head_src[: m.start()].count("\n") + 1
                        unpinned_new.append((lno, act_name, ref_val))

            if unpinned_new and not downgraded and not head_has_prt_checkout:
                ev_unpinned = tuple(
                    EvidenceItem(
                        kind="ACTION_PIN_UNPINNED",
                        file=fd.file_path,
                        line=lno,
                        symbol=act_name,
                        detail=f"Action '{act_name}' introduced with mutable ref '@{ref_val}' instead of 40-character commit SHA",
                    )
                    for lno, act_name, ref_val in unpinned_new
                )
                findings.append(
                    ConsequenceFinding(
                        finding_id=f"PG-D08-UNPINNED-{fd.file_path}",
                        detector_id=DETECTOR_D08_WORKFLOW,
                        consequence_class="ACTION_PIN_UNPINNED",
                        tier=TIER_VERIFIED,
                        confidence=CONFIDENCE_HIGH,
                        severity=SEVERITY_MEDIUM,
                        policy_recommendation=POLICY_WARN,
                        summary=(
                            f"Workflow '{fd.file_path}' introduces {len(unpinned_new)} unpinned third-party Action(s) "
                            f"({', '.join(a for _, a, _ in unpinned_new[:3])}) using mutable refs."
                        ),
                        affected_files=(fd.file_path,),
                        affected_symbols=tuple(sorted({a for _, a, _ in unpinned_new})),
                        evidence=ev_unpinned,
                        remediation="Pin third-party GitHub Actions to immutable full 40-character commit SHAs (e.g., `uses: actions/checkout@11bd71901ebe5b1630ceea73d27597364c9af683 # v4.2.2`).",
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # D09: Test Erosion & Assertion Removal Detector
    # ------------------------------------------------------------------
    def _detect_d09_test_erosion(
        self,
        transitions: List[SymbolTransition],
    ) -> List[ConsequenceFinding]:
        findings: List[ConsequenceFinding] = []

        def _parse_test_assertions(conds: Tuple[str, ...]) -> Optional[Tuple[int, int]]:
            for c in conds:
                if c.startswith("test_assertions:"):
                    parts = c.split(":")
                    if len(parts) == 3:
                        try:
                            return int(parts[1]), int(parts[2])
                        except ValueError:
                            return None
            return None

        def _is_skip_deco(deco: str) -> bool:
            low = deco.lower().lstrip("@")
            return any(tok in low for tok in _TEST_SKIP_DECORATOR_TOKENS)

        for tr in transitions:
            bs = tr.base_symbol
            hs = tr.head_symbol
            if bs is None or hs is None:
                continue
            if bs.kind not in ("function", "method"):
                continue
            if not (_is_test_path(bs.file_path) or _is_test_path(hs.file_path)):
                continue

            b_conds = getattr(bs, "guard_conditions", ()) or ()
            h_conds = getattr(hs, "guard_conditions", ()) or ()
            b_asserts = _parse_test_assertions(b_conds)
            h_asserts = _parse_test_assertions(h_conds)

            is_test_symbol = (
                bs.name.startswith("test")
                or bs.name.startswith("Test")
                or any("test" in d.lower() for d in bs.decorators)
                or b_asserts is not None
            )
            if not is_test_symbol:
                continue

            # 1. Check newly added skip decorators or skip calls
            base_skip_decos = {d for d in bs.decorators if _is_skip_deco(d)}
            head_skip_decos = {d for d in hs.decorators if _is_skip_deco(d)}
            added_skip_decos = sorted(head_skip_decos - base_skip_decos)
            added_skip_call = ("test_skip_call:true" in h_conds) and ("test_skip_call:true" not in b_conds)

            if added_skip_decos or added_skip_call:
                detail_parts: List[str] = []
                if added_skip_decos:
                    detail_parts.append(f"added skip decorator(s) {', '.join(added_skip_decos)}")
                if added_skip_call:
                    detail_parts.append("inserted runtime skip call")
                findings.append(
                    ConsequenceFinding(
                        finding_id=f"PG-D09-SKIP-{hs.file_path}-{hs.qualified_name}",
                        detector_id=DETECTOR_D09_TEST,
                        consequence_class="TEST_SKIPPED_OR_DISABLED",
                        tier=TIER_VERIFIED,
                        confidence=CONFIDENCE_HIGH,
                        severity=SEVERITY_MEDIUM,
                        policy_recommendation=POLICY_REVIEW,
                        summary=(
                            f"Existing test '{hs.qualified_name}' in '{hs.file_path}' was skipped or disabled "
                            f"({'; '.join(detail_parts)})."
                        ),
                        affected_files=(hs.file_path,),
                        affected_symbols=(hs.qualified_name,),
                        evidence=(
                            EvidenceItem(
                                kind="TEST_NEWLY_SKIPPED",
                                file=hs.file_path,
                                line=hs.start_line,
                                symbol=hs.qualified_name,
                                detail=f"Test '{hs.qualified_name}' disabled via {'; '.join(detail_parts)}",
                            ),
                        ),
                        remediation=f"Fix the underlying failure in '{hs.qualified_name}' instead of skipping the test.",
                    )
                )
                continue

            # 2. Check test assertion erosion (effective assertions dropped from >=1 to 0)
            if b_asserts is not None and not hs.is_stub:
                b_eff, _ = b_asserts
                h_eff, h_triv = h_asserts if h_asserts is not None else (0, 0)
                if b_eff >= 1 and h_eff == 0:
                    detail_msg = (
                        f"Replaced {b_eff} effective assertion(s) with {h_triv} tautological assertion(s) (`assert True`)"
                        if h_triv > 0
                        else f"Removed all {b_eff} assertion(s) from test '{hs.qualified_name}' while leaving body statements"
                    )
                    findings.append(
                        ConsequenceFinding(
                            finding_id=f"PG-D09-EROSION-{hs.file_path}-{hs.qualified_name}",
                            detector_id=DETECTOR_D09_TEST,
                            consequence_class="TEST_ASSERTION_EROSION",
                            tier=TIER_VERIFIED,
                            confidence=CONFIDENCE_HIGH,
                            severity=SEVERITY_HIGH,
                            policy_recommendation=POLICY_BLOCK,
                            summary=(
                                f"Test '{hs.qualified_name}' in '{hs.file_path}' lost all effective assertions "
                                f"({b_eff} -> 0)."
                            ),
                            affected_files=(hs.file_path,),
                            affected_symbols=(hs.qualified_name,),
                            evidence=(
                                EvidenceItem(
                                    kind="TEST_ASSERTIONS_GUTTED",
                                    file=hs.file_path,
                                    line=hs.start_line,
                                    symbol=hs.qualified_name,
                                    detail=detail_msg,
                                ),
                            ),
                            remediation=f"Restore meaningful assertions in test '{hs.qualified_name}' to verify expected behavior.",
                        )
                    )

        return findings

    # ------------------------------------------------------------------
    # D10: Migration & Persistence Loss Detector
    # ------------------------------------------------------------------
    def _detect_d10_migration_persistence_loss(
        self,
        file_deltas: List[FileDeltaInput],
    ) -> List[ConsequenceFinding]:
        findings: List[ConsequenceFinding] = []

        def _is_temp_entity(name: str) -> bool:
            clean = name.strip("'\"` ").lower()
            return any(clean.startswith(p) for p in _TEMP_TABLE_PREFIXES)

        for fd in file_deltas:
            if not _is_migration_file(fd.file_path):
                continue
            if not fd.head_source:
                continue

            head_src = fd.head_source
            base_src = fd.base_source or ""

            def _clean_sql_lines(text: str) -> List[Tuple[int, str]]:
                lines: List[Tuple[int, str]] = []
                in_block_comment = False
                for idx, line in enumerate(text.splitlines(), start=1):
                    stripped = line.strip()
                    if in_block_comment:
                        if "*/" in stripped:
                            in_block_comment = False
                        continue
                    if stripped.startswith("/*"):
                        if "*/" not in stripped:
                            in_block_comment = True
                        continue
                    if stripped.startswith("--") or stripped.startswith("//") or stripped.startswith("#"):
                        continue
                    lines.append((idx, stripped))
                return lines

            head_lines = _clean_sql_lines(head_src)
            base_lines = _clean_sql_lines(base_src)
            base_line_texts = {l for _, l in base_lines}

            # 1. Catastrophic Database / Schema Drops or Truncations
            for line_no, line_txt in head_lines:
                if line_txt in base_line_texts:
                    continue

                m_trunc = _SQL_TRUNCATE_RE.search(line_txt)
                if m_trunc:
                    target = m_trunc.group(1).strip("'\"` ")
                    if not _is_temp_entity(target):
                        findings.append(
                            ConsequenceFinding(
                                finding_id=f"PG-D10-TRUNCATE-{fd.file_path}-{line_no}",
                                detector_id=DETECTOR_D10_MIGRATION,
                                consequence_class="CATASTROPHIC_DATA_WIPEOUT",
                                tier=TIER_VERIFIED,
                                confidence=CONFIDENCE_HIGH,
                                severity=SEVERITY_CRITICAL,
                                policy_recommendation=POLICY_BLOCK,
                                summary=f"Migration '{fd.file_path}' truncates persistent table '{target}', permanently erasing all table data.",
                                affected_files=(fd.file_path,),
                                affected_symbols=(target,),
                                evidence=(
                                    EvidenceItem(
                                        kind="TABLE_TRUNCATE",
                                        file=fd.file_path,
                                        line=line_no,
                                        symbol=target,
                                        detail=f"Line {line_no}: '{line_txt}'",
                                    ),
                                ),
                                remediation="Avoid TRUNCATE in automated production migrations. Use soft archiving, batch deprecation, or explicit manual maintenance procedures.",
                            )
                        )

                m_dropdb = _SQL_DROP_DATABASE_RE.search(line_txt)
                if m_dropdb:
                    target = m_dropdb.group(1).strip("'\"` ")
                    findings.append(
                        ConsequenceFinding(
                            finding_id=f"PG-D10-DROPDB-{fd.file_path}-{line_no}",
                            detector_id=DETECTOR_D10_MIGRATION,
                            consequence_class="CATASTROPHIC_DATA_WIPEOUT",
                            tier=TIER_VERIFIED,
                            confidence=CONFIDENCE_HIGH,
                            severity=SEVERITY_CRITICAL,
                            policy_recommendation=POLICY_BLOCK,
                            summary=f"Migration '{fd.file_path}' drops database or schema '{target}', causing irreversible data loss.",
                            affected_files=(fd.file_path,),
                            affected_symbols=(target,),
                            evidence=(
                                EvidenceItem(
                                    kind="DATABASE_OR_SCHEMA_DROP",
                                    file=fd.file_path,
                                    line=line_no,
                                    symbol=target,
                                    detail=f"Line {line_no}: '{line_txt}'",
                                ),
                            ),
                            remediation="Dropping entire databases or schemas must never occur in automated CI/CD pull requests.",
                        )
                    )

            # 2. Table and Column Drops in Migrations (SQL & ORM)
            dropped_tables: List[Tuple[int, str, str]] = []
            dropped_columns: List[Tuple[int, str, str]] = []

            for line_no, line_txt in head_lines:
                if line_txt in base_line_texts:
                    continue

                m_dt = _SQL_DROP_TABLE_RE.search(line_txt)
                if m_dt:
                    tname = m_dt.group(1).strip("'\"` ")
                    if not _is_temp_entity(tname):
                        dropped_tables.append((line_no, tname, line_txt))

                m_dc = _SQL_DROP_COLUMN_RE.search(line_txt)
                if m_dc:
                    cname = m_dc.group(1).strip("'\"` ")
                    if not _is_temp_entity(cname):
                        dropped_columns.append((line_no, cname, line_txt))

                m_adt = _ALEMBIC_DROP_TABLE_RE.search(line_txt)
                if m_adt:
                    tname = m_adt.group(1)
                    if not _is_temp_entity(tname):
                        dropped_tables.append((line_no, tname, line_txt))

                m_adc = _ALEMBIC_DROP_COLUMN_RE.search(line_txt)
                if m_adc:
                    tname, cname = m_adc.group(1), m_adc.group(2)
                    if not _is_temp_entity(tname) and not _is_temp_entity(cname):
                        dropped_columns.append((line_no, f"{tname}.{cname}", line_txt))

                m_djm = _DJANGO_DELETE_MODEL_RE.search(line_txt)
                if m_djm:
                    mname = m_djm.group(1)
                    dropped_tables.append((line_no, mname, line_txt))

                m_djf = _DJANGO_REMOVE_FIELD_RE.search(line_txt)
                if m_djf:
                    mname, fname = m_djf.group(1), m_djf.group(2)
                    dropped_columns.append((line_no, f"{mname}.{fname}", line_txt))

                m_js = _JS_TS_DROP_RE.search(line_txt)
                if m_js:
                    entity = m_js.group(1)
                    if "table" in line_txt.lower():
                        dropped_tables.append((line_no, entity, line_txt))
                    elif "column" in line_txt.lower():
                        dropped_columns.append((line_no, entity, line_txt))

            if dropped_tables or dropped_columns:
                is_irreversible = False
                if "def downgrade" in head_src:
                    dw_match = re.search(r"def\s+downgrade\s*\([^)]*\)\s*(?:->\s*[^:]+)?\s*:(.*)", head_src, re.DOTALL)
                    if dw_match:
                        dw_body = dw_match.group(1)
                        dw_lines = []
                        for raw_l in dw_body.splitlines():
                            if re.match(r"^(?:def|class)\s+", raw_l):
                                break
                            clean_l = raw_l.strip()
                            if clean_l and not clean_l.startswith("#"):
                                dw_lines.append(clean_l)
                        if not dw_lines or all(l in ("pass", "...", "return", "pass;", "raise NotImplementedError") for l in dw_lines):
                            is_irreversible = True

                ev_items: List[EvidenceItem] = []
                for lno, tname, ltxt in dropped_tables:
                    ev_items.append(
                        EvidenceItem(
                            kind="SCHEMA_TABLE_DROPPED",
                            file=fd.file_path,
                            line=lno,
                            symbol=tname,
                            detail=f"Line {lno}: Dropped table '{tname}' ({ltxt})",
                        )
                    )
                for lno, cname, ltxt in dropped_columns:
                    ev_items.append(
                        EvidenceItem(
                            kind="SCHEMA_COLUMN_DROPPED",
                            file=fd.file_path,
                            line=lno,
                            symbol=cname,
                            detail=f"Line {lno}: Dropped column '{cname}' ({ltxt})",
                        )
                    )

                all_entities = [t for _, t, _ in dropped_tables] + [c for _, c, _ in dropped_columns]
                c_class = "IRREVERSIBLE_PERSISTENCE_DROP" if is_irreversible else "DESTRUCTIVE_PERSISTENCE_MIGRATION"
                sev = SEVERITY_CRITICAL if is_irreversible else SEVERITY_HIGH
                pol = POLICY_BLOCK if is_irreversible else POLICY_REVIEW

                summary_msg = (
                    f"Migration '{fd.file_path}' introduces irreversible schema drop(s) ({', '.join(all_entities[:3])}) with no downgrade rollback procedure."
                    if is_irreversible
                    else f"Migration '{fd.file_path}' drops persistent database schema element(s) ({', '.join(all_entities[:3])})."
                )

                findings.append(
                    ConsequenceFinding(
                        finding_id=f"PG-D10-SCHEMA-{fd.file_path}",
                        detector_id=DETECTOR_D10_MIGRATION,
                        consequence_class=c_class,
                        tier=TIER_VERIFIED,
                        confidence=CONFIDENCE_HIGH,
                        severity=sev,
                        policy_recommendation=pol,
                        summary=summary_msg,
                        affected_files=(fd.file_path,),
                        affected_symbols=tuple(all_entities),
                        evidence=tuple(ev_items),
                        remediation=(
                            "Adhere to the expand-and-contract pattern: avoid dropping columns or tables in the same deployment as application changes. "
                            "Ensure migration downgrade/rollback functions are fully implemented with backward compatibility."
                        ),
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
