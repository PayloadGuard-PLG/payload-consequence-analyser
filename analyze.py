#!/usr/bin/env python3
"""
PayloadGuard - Destructive Merge Detection
Detects catastrophic code payloads hidden in code suggestions before merge

Usage:
    python analyze.py <repo_path> <branch> [target] [--pr-description "..."] [--save-json [FILE]]

Example:
    python analyze.py . feature-branch main
    python analyze.py . feature-branch main --pr-description "minor syntax fix" --save-json
"""

import argparse
import ast
import copy
import git
import re
import sys
import json
import textwrap
import yaml
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, Union
from dataclasses import dataclass, field
import structural_parser

__version__ = "1.2.0"


# ==============================================================================
# CRITICAL PATH PATTERNS (Layer 2)
# Regex patterns used to identify high-value deleted files.
# More precise than substring matching — avoids false positives on paths like
# "protest.py", "latest_deployment.yaml", "reconfiguration_log.py".
# ==============================================================================

CRITICAL_PATH_PATTERNS = [
    # Test infrastructure
    r"(^|/)tests?(/|$)",
    r"(^|/)test_[^/]+$",
    # CI/CD and workflows
    r"(^|/)\.github/",
    r"(^|/)Dockerfile[^/]*$",
    r"(^|/)docker-compose[^/]*\.(yml|yaml)$",
    r"(^|/)Makefile$",
    # Dependency manifests
    r"(^|/)requirements[^/]*\.txt$",
    r"(^|/)setup\.py$",
    r"(^|/)pyproject\.toml$",
    r"(^|/)package\.json$",
    r"(^|/)Cargo\.toml$",
    r"(^|/)go\.mod$",
    r"(^|/)pom\.xml$",
    r"(^|/)build\.gradle(\.kts)?$",
    # Package init
    r"(^|/)__init__\.py$",
    # Architecture directories
    r"(^|/)core(/|$)",
    r"(^|/)modules(/|$)",
    r"(^|/)config(/|$)",
    # Security-sensitive files
    r"(^|/)auth[^/]*\.(py|js|ts)$",
    r"(^|/)security[^/]*\.(py|js|ts)$",
    r"(^|/)permission[^/]*\.(py|js|ts)$",
    # Database / schema
    r"(^|/)database[^/]*\.(py|js|ts)$",
    r"(^|/)migrations?(/|$)",
    r"(^|/)migration[^/]*(\.py|\.sql)?$",
    r"(^|/)schema[^/]*(\.py|\.sql|\.json)?$",
    r"(^|/)models?(/|\.py$|\.js$|\.ts$)",
    # Application entry points
    r"(^|/)(main|app|server|index)\.(py|js|ts)$",
    # Config files
    r"\.(yml|yaml)$",
]

# Security-critical file patterns — a subset of CRITICAL_PATH_PATTERNS that
# warrant an immediate high-confidence DESTRUCTIVE signal when deleted.
_SECURITY_CRITICAL_PATTERNS = [
    r"(^|/)auth[^/]*\.(py|js|ts)$",
    r"(^|/)security[^/]*\.(py|js|ts)$",
    r"(^|/)permission[^/]*\.(py|js|ts)$",
    r"(^|/)authorization[^/]*\.(py|js|ts)$",
]

# Commit message patterns that indicate deliberate destructive intent.
# Conservative set — only phrases with low false-positive risk.
_COMMIT_RED_FLAG_PATTERNS = [
    r"\bremove\s+all\s+tests?\b",
    r"\bdelete\s+everything\b",
    r"\bwipe\s+(out\s+)?(everything|all|codebase)\b",
    r"\berase\s+(all|everything)\b",
    r"\bdisable\s+(auth|security|validation|all\s+tests?|checks?)\b",
    r"\bbypass\s+(auth|security|validation|checks?)\b",
    r"\bdrop\s+(all\s+)?(tables?|schema|database)\b",
    r"\bremove\s+(auth|security|authentication|authorization)\b",
]

# ==============================================================================
# ADDED FILE CONTENT SCANNING (Layer 1 extension — INC-1, INC-4)
# Scans added non-code files for CI trigger strings and shell execution patterns.
# Code extensions are skipped (handled by structural analysis, Layer 4).
# Known binary extensions are skipped (undecodable content).
# ==============================================================================

_CONTENT_SCAN_CODE_EXTENSIONS = frozenset({
    '.py', '.js', '.jsx', '.ts', '.tsx', '.go', '.rs', '.java',
    '.rb', '.c', '.cpp', '.h', '.hpp', '.cs', '.swift', '.kt',
})

_CONTENT_BINARY_EXTENSIONS = frozenset({
    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.zip', '.tar', '.gz', '.bz2', '.7z', '.rar',
    '.exe', '.dll', '.so', '.dylib', '.bin', '.wasm',
    '.mp3', '.mp4', '.avi', '.mov', '.wav',
    '.ttf', '.woff', '.woff2', '.eot',
    '.pyc', '.pyo', '.class', '.o', '.a',
    '.db', '.sqlite', '.sqlite3',
})

# Strings embedded in non-code files (README, docs, config) to force CI reruns.
_CONTENT_CI_TRIGGER_PATTERNS = [
    r'\[citest',
    r'\bneeds-ci\b',
    r'citest\s+commit:',
    r'\[needs-ci\]',
]

# Shell execution patterns — a non-code file containing these has runnable intent.
_CONTENT_SHELL_PATTERNS = [
    r'\bsudo\s+\S',
    r'\bsetfacl\s+',
    r'\bchmod\s+[0-9a-osx+\-]',
    r'curl\b[^\n]*\|\s*(ba)?sh',
    r'wget\b[^\n]*\|\s*(ba)?sh',
    r'\brm\s+-[rf]',
]

# ==============================================================================
# GITHUB ACTIONS POISONING DETECTION (Layer 2c)
# Scans added and modified .github/workflows/ and .github/actions/ YAML files
# for poisoning signals. Complements Layer 2 (which catches deletion of .github/
# files) by inspecting the *content* of new/changed workflow definitions.
# ==============================================================================

_ACTIONS_WORKFLOW_PATTERN = r"(^|/)\.github/(workflows|actions)/[^/]*\.(yml|yaml)$"

# Signal 1: Base64-encoded payload delivery
_ACTIONS_BASE64_PAYLOAD = [
    r"base64\s+-d\s*\|\s*(ba)?sh",
    r"\|\s*base64\s+--decode\s*\|\s*(ba)?sh",
    r"echo\s+['\"]?[A-Za-z0-9+/]{20,}={0,2}['\"]?\s*\|\s*(ba)?sh",
]

# Signal 2: Credential harvesting — env dumps, secret grep, metadata endpoints
_ACTIONS_CREDENTIAL_HARVEST = [
    r"curl\s+http://169\.254\.169\.254",
    r"env\b[^\n]*\|\s*(grep|awk|sed)\b[^\n]*(KEY|TOKEN|SECRET|PASSWORD|CRED)",
    r"printenv\b[^\n]*\|\s*(grep|awk)\b",
    r"grep\s+-r[^\n]*(AWS_|GITHUB_TOKEN|api[_-]?key|ssh-rsa)",
    r"cat\s+~?/\.ssh/(id_rsa|id_ed25519|authorized_keys)",
    # RTA-05 fix: curl with secret in URL (original pattern — http after secret)
    r"curl\b[^\n]*\$\{\{\s*secrets\.[A-Z_]+\s*\}\}[^\n]*http",
    # RTA-05 fix: secret passed as HTTP auth header (-H / --header), works
    # even when curl spans multiple lines with backslash continuation.
    r"(?:-H|--header)\s+[\"'][^\"']*\$\{\{\s*secrets\.[A-Z_]+\s*\}\}",
    # RTA-02 fix: secret exfiltrated via GITHUB_OUTPUT or GITHUB_STEP_SUMMARY
    r"echo\b[^\n]*\$\{\{\s*secrets\.[A-Z_]+\s*\}\}[^\n]*>>\s*\$GITHUB_OUTPUT",
    r"echo\b[^\n]*\$\{\{\s*secrets\.[A-Z_]+\s*\}\}[^\n]*>>\s*\$GITHUB_STEP_SUMMARY",
]

# Signal 7: GitHub environment file injection — poisons PATH, LD_PRELOAD, or
# NODE_OPTIONS for subsequent steps via $GITHUB_ENV. Distinguished from
# legitimate env-var setting by the presence of path-manipulation values.
_ACTIONS_GITHUB_ENV_INJECTION = re.compile(
    r"echo\s+['\"]?(PATH=|LD_PRELOAD=|LD_LIBRARY_PATH=|NODE_OPTIONS=--require)[^\n]*>>\s*\$GITHUB_ENV",
    re.IGNORECASE | re.MULTILINE,
)

# ==============================================================================
# SEMANTIC TRANSPARENCY (Layer 5b v2) — PR-MCI heuristic engine
# Derives mci_score from five signals:
#   V_s  Scope Adequacy        — description verbosity vs diff churn
#   V_o  Operation Mutation    — claimed op type vs structural alterations
#   V_f  File-Type Verify      — sensitive files in diff not acknowledged
#   V_r  Phantom Additions     — remedial claim + high insertion ratio
#   V_e  Cross-stack micro     — micro claim touches ≥3 distinct file types
# ==============================================================================

_SEMANTIC_MICRO_SCOPE = frozenset({
    'typo', 'minor', 'trivial', 'small', 'cosmetic', 'syntax', 'formatting',
    'cleanup', 'whitespace', 'indent', 'comment', 'docs', 'readme', 'changelog',
    'spelling', 'grammar', 'style', 'lint', 'nit', 'docstring',
})
_SEMANTIC_MACRO_SCOPE = frozenset({
    'massive', 'major', 'complete', 'total', 'overhaul', 'rewrite', 'rework',
    'architecture', 'architectural', 'global', 'substantial', 'large',
    'significant', 'comprehensive', 'entire',
})
_SEMANTIC_ADDITIVE_STEMS    = frozenset({'add', 'implement', 'creat', 'introduc', 'integrat', 'build', 'extend', 'new'})
_SEMANTIC_DESTRUCTIVE_STEMS = frozenset({'remov', 'delet', 'drop', 'deprecat', 'destroy', 'clean', 'purg', 'strip'})
_SEMANTIC_MUTATIVE_STEMS    = frozenset({'updat', 'modif', 'refactor', 'rewrit', 'restructur', 'bump', 'chang', 'migrat', 'replac'})
_SEMANTIC_REMEDIAL_STEMS    = frozenset({'fix', 'patch', 'resolv', 'revert', 'correct', 'repair', 'hotfix'})

_SEMANTIC_SUFFIXES = [  # Lovins-inspired, longest-first; guard: stem must remain ≥3 chars
    ('ations', ''), ('ation', ''), ('tions', ''), ('tion', ''),
    ('ments', ''), ('ment', ''), ('ness', ''), ('ings', ''), ('ing', ''),
    ('ized', ''), ('izes', ''), ('ize', ''), ('ified', ''), ('ify', ''),
    ('able', ''), ('ible', ''), ('ed', ''), ('ers', ''), ('er', ''),
    ('ies', 'y'), ('es', ''), ('s', ''),
]

_SEMANTIC_SENSITIVE_PATHS = [
    re.compile(r'\.github/workflows/', re.IGNORECASE),
    re.compile(r'(?:^|/)auth[^/]*\.', re.IGNORECASE),
    re.compile(r'package\.json|requirements\.txt|Pipfile|go\.mod|Cargo\.toml', re.IGNORECASE),
    re.compile(r'Dockerfile|docker-compose', re.IGNORECASE),
    re.compile(r'schema\.|migration', re.IGNORECASE),
    re.compile(r'(?:^|/)secrets?[^/]*\.', re.IGNORECASE),
]

# Signal 3: Dormant trigger — workflow_dispatch or schedule combined with a
# shell execution pattern in the same file constitutes a sleeper payload.
_ACTIONS_DORMANT_TRIGGER = [
    r"on:\s*\n\s+workflow_dispatch",
    r"on:\s*\[?\s*schedule",
]

# Signal 4: Forged bot / impersonator commit identity
_ACTIONS_FORGED_AUTHOR = re.compile(
    r"git\s+config\s+user\.(name|email)\s+['\"]?("
    r"build-bot|auto-ci|ci-bot|github-actions\[bot\]|actions-bot|dependabot"
    r")['\"]?",
    re.IGNORECASE,
)

# Signal 5: Elevated OIDC permissions without a legitimate cloud consumer.
# id-token: write grants ambient cloud credentials — only legitimate alongside
# known cloud-auth actions. Exact-match list prevents typosquatted action names
# (e.g. aws-actions-unofficial/) from bypassing the check.
# Extend via payloadguard.yml: actions.trusted_oidc_consumers list.
_ACTIONS_OIDC_ELEVATION_PATTERN = re.compile(r"id-token:\s*write", re.IGNORECASE)
_SAFE_OIDC_CONSUMERS_DEFAULT = [
    "aws-actions/configure-aws-credentials",
    "google-github-actions/auth",
    "azure/login",
]

# OIDC Consumer Allowlist (Exact Match Only)
_SAFE_OIDC_CONSUMERS = [
    'aws-actions/configure-aws-credentials',
    'google-github-actions/auth',
    'azure/login',
    'azure/login@v1',
]

_SAFE_OIDC_PREFIXES = [
    'aws-actions/',
    'google-github-actions/',
    'azure/',
]


def _is_oidc_consumer_legitimate(action_string):
    """Check if action is in the safe OIDC allowlist."""
    return any(action_string.startswith(safe) for safe in _SAFE_OIDC_CONSUMERS)


def _is_oidc_consumer_typosquatted(action_string):
    """
    Detect if action appears to be a typosquat of a known-safe OIDC consumer.

    Typosquats: aws-actions-unofficial/, aws-action/, google-github-action-fork/, etc.
    """
    if not action_string:
        return False

    # Pattern 1: Uses safe prefix but isn't on allowlist
    for prefix in _SAFE_OIDC_PREFIXES:
        if action_string.startswith(prefix):
            if not _is_oidc_consumer_legitimate(action_string):
                return True

    # Pattern 2: Common typosquat indicators
    typosquat_patterns = [
        'aws-actions-',
        'aws-action/',
        'google-github-actions-',
        'google-github-action-',
        'google-github-action/',
        'azure-login',
    ]
    return any(pattern in action_string for pattern in typosquat_patterns)


# Signal 6: pull_request_target trigger — runs in the base-branch context with
# repository secrets accessible even when triggered by a fork PR. Standalone use
# is HIGH; combined with any write permission it is CRITICAL because an attacker
# can both read secrets and push code/artifacts.
_ACTIONS_DANGEROUS_TRIGGERS = re.compile(r"\bpull_request_target\b", re.IGNORECASE)
_ACTIONS_WRITE_PERMISSIONS = re.compile(
    r"contents:\s*write|pull-requests:\s*write|packages:\s*write|deployments:\s*write",
    re.IGNORECASE,
)

# ==============================================================================
# SCA — DEPENDENCY MANIFEST PATTERNS (Layer 2b)
# Opt-in: only runs when allowlist.yml is present in the repo root.
# ==============================================================================

_MANIFEST_PATTERNS = {
    r"(^|/)requirements[^/]*\.txt$": "pip",
    r"(^|/)package\.json$":          "npm",
    r"(^|/)go\.mod$":                "go",
    r"(^|/)Cargo\.toml$":            "cargo",
    r"(^|/)pyproject\.toml$":        "pyproject",
}

_MANIFEST_ALLOWLIST_KEY = {
    "pip": "python", "pyproject": "python",
    "npm": "npm", "go": "go", "cargo": "rust",
}

_TOML_SKIP_KEYS = {"name", "version", "edition", "authors", "description", "license", "readme", "build"}
_JSON_SKIP_KEYS = {
    "version", "description", "name", "main", "scripts", "keywords",
    "author", "license", "private", "type", "homepage", "repository", "bugs",
}


def _parse_added_packages(diff_text: str, manifest_type: str) -> list:
    """Extract newly added package names from a unified diff of a manifest file."""
    packages = []
    for line in diff_text.splitlines():
        if not line.startswith('+') or line.startswith('+++'):
            continue
        content = line[1:].strip()
        if manifest_type in ("pip",):
            m = re.match(r'^([A-Za-z0-9][A-Za-z0-9._-]*)', content)
            if m:
                packages.append(m.group(1).lower())
        elif manifest_type == "pyproject":
            m = re.match(r'^["\']?([A-Za-z0-9][A-Za-z0-9._-]*)', content)
            if m:
                pkg = m.group(1).lower()
                if pkg not in _TOML_SKIP_KEYS:
                    packages.append(pkg)
        elif manifest_type == "npm":
            m = re.match(r'^"([^"]+)"\s*:', content)
            if m:
                pkg = m.group(1)
                if pkg not in _JSON_SKIP_KEYS:
                    packages.append(pkg)
        elif manifest_type == "go":
            m = re.match(r'^(?:require\s+)?([a-z][a-z0-9./\-]+)\s+v', content)
            if m:
                packages.append(m.group(1))
        elif manifest_type == "cargo":
            m = re.match(r'^([a-zA-Z][a-zA-Z0-9_-]*)\s*[=\[]', content)
            if m:
                pkg = m.group(1).lower()
                if pkg not in _TOML_SKIP_KEYS:
                    packages.append(pkg)
    return packages


def _normalize_yaml_content(content: str) -> str:
    """Collapse YAML folded/literal block scalars to a single line.

    YAML folded blocks (>) and literal blocks (|) split a single logical shell
    command across multiple lines in the raw file, which prevents single-line
    regex patterns from matching. Joining all lines with a space produces the
    same string that the shell would execute, making patterns like
    'base64 -d | bash' visible regardless of how the YAML was formatted.

    Only use this for base64/payload patterns. Do NOT normalise before checks
    that rely on line structure (dormant-trigger composite, forged-author).
    """
    return " ".join(content.split())


def _load_allowlist(repo_path: str):
    """Load allowlist.yml from repo root. Returns None if absent (SCA opt-out)."""
    p = Path(repo_path) / "allowlist.yml"
    if not p.exists():
        return None
    try:
        with open(p) as f:
            data = yaml.safe_load(f) or {}
        return {k: set(str(v).lower() for v in lst) for k, lst in data.items() if isinstance(lst, list)}
    except Exception:
        return None


# ==============================================================================
# LAYER 4: STRUCTURAL DRIFT DETECTION
# ==============================================================================

class StructuralPayloadAnalyzer:
    """
    Parses original and modified source code into Abstract Syntax Trees (AST)
    to detect catastrophic structural deletions.

    Configurable thresholds allow teams to tune sensitivity to their own risk
    tolerance and codebase culture:

        deletion_ratio_threshold (float): Fraction of structural nodes that must
            be deleted before flagging CRITICAL. Default 0.20 (20%).
            Lower = stricter. A security-critical repo might use 0.10.

        min_deletion_count (int): Minimum number of nodes that must be deleted
            before the ratio check can trigger CRITICAL. Prevents false positives
            on tiny files (e.g. a 2-function helper losing 1 function is 50% ratio
            but only 1 deletion — probably not catastrophic).
            Default 3. Increase if your repo has many small utility files.

    Example — custom thresholds:
        analyzer = StructuralPayloadAnalyzer(
            original, modified,
            deletion_ratio_threshold=0.10,
            min_deletion_count=5
        )
    """

    def __init__(
        self,
        original_code: str,
        modified_code: str,
        file_path: str = "",
        deletion_ratio_threshold: float = 0.20,
        min_deletion_count: int = 3,
        complexity_threshold: int = 15,
    ):
        self.original_code = original_code
        self.modified_code = modified_code
        self.file_path = file_path
        self.deletion_ratio_threshold = deletion_ratio_threshold
        self.min_deletion_count = min_deletion_count
        self.complexity_threshold = complexity_threshold

    def _extract_core_nodes(self, source_text: str) -> set:
        return structural_parser.extract_named_nodes(source_text, self.file_path)

    def analyze_structural_drift(self) -> Dict[str, Any]:
        """
        Flags CRITICAL only when BOTH the deletion ratio AND the minimum
        deletion count thresholds are exceeded.
        """
        try:
            original_nodes = self._extract_core_nodes(self.original_code)
            modified_nodes = self._extract_core_nodes(self.modified_code)
        except ValueError as e:
            return {"error": str(e), "status": "PARSE_FAILURE", "severity": "HIGH"}

        deleted_nodes = original_nodes - modified_nodes
        added_nodes = modified_nodes - original_nodes

        deletion_ratio = len(deleted_nodes) / len(original_nodes) if original_nodes else 0

        # Both conditions must be met to avoid false positives on tiny files
        is_destructive = (
            deletion_ratio > self.deletion_ratio_threshold
            and len(deleted_nodes) >= self.min_deletion_count
        )

        # Feature B: McCabe complexity advisory for newly added Python functions
        complexity_advisory = []
        if self.file_path.endswith('.py') and added_nodes:
            try:
                tree = ast.parse(self.modified_code)
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        if node.name in added_nodes:
                            complexity = 1
                            for child in ast.walk(node):
                                if isinstance(child, (ast.If, ast.For, ast.While, ast.ExceptHandler)):
                                    complexity += 1
                                elif isinstance(child, ast.BoolOp):
                                    complexity += len(child.values) - 1
                            if complexity > self.complexity_threshold:
                                complexity_advisory.append({
                                    "name": node.name,
                                    "complexity": complexity,
                                    "threshold": self.complexity_threshold,
                                })
            except SyntaxError:
                pass

        return {
            "status": "DESTRUCTIVE" if is_destructive else "SAFE",
            "severity": "CRITICAL" if is_destructive else "LOW",
            "metrics": {
                "original_node_count": len(original_nodes),
                "deleted_node_count": len(deleted_nodes),
                "structural_deletion_ratio": round(deletion_ratio * 100, 2),
                "deletion_ratio_threshold_pct": round(self.deletion_ratio_threshold * 100, 2),
                "min_deletion_count": self.min_deletion_count,
            },
            "deleted_components": sorted(deleted_nodes),
            "added_components": sorted(added_nodes),
            "complexity_advisory": complexity_advisory,
        }


# ==============================================================================
# LAYER 5a: TEMPORAL DRIFT ANALYSIS
# ==============================================================================

class TemporalDriftAnalyzer:
    """
    Evaluates the temporal divergence between a feature branch and its target.
    Correlates branch age with target branch velocity to compute a Drift Score.

    Drift Score = branch_age_days * target_velocity_commits_per_day

    Configurable thresholds:
        warning_threshold (float): Drift Score at which status becomes STALE.
            Default 250. Example: 50-day branch on a 5-commit/day repo.

        critical_threshold (float): Drift Score at which status becomes DANGEROUS.
            Default 1000. Example: 100-day branch on a 10-commit/day repo.
    """

    def __init__(
        self,
        branch_age_days: int,
        target_velocity_commits_per_day: float,
        warning_threshold: float = 250.0,
        critical_threshold: float = 1000.0,
    ):
        self.branch_age_days = branch_age_days
        self.target_velocity = target_velocity_commits_per_day
        self.WARNING_THRESHOLD = warning_threshold
        self.CRITICAL_THRESHOLD = critical_threshold

    def analyze_drift(self) -> Dict[str, Union[str, float, int]]:
        if self.branch_age_days < 0 or self.target_velocity < 0:
            raise ValueError("Age and velocity metrics must be non-negative.")

        drift_score = self.branch_age_days * self.target_velocity

        if drift_score >= self.CRITICAL_THRESHOLD:
            status = "DANGEROUS"
            severity = "CRITICAL"
        elif drift_score >= self.WARNING_THRESHOLD:
            status = "STALE"
            severity = "WARNING"
        else:
            status = "CURRENT"
            severity = "LOW"

        return {
            "status": status,
            "severity": severity,
            "metrics": {
                "branch_age_days": self.branch_age_days,
                "target_velocity": self.target_velocity,
                "calculated_drift_score": float(drift_score),
                "warning_threshold": self.WARNING_THRESHOLD,
                "critical_threshold": self.CRITICAL_THRESHOLD,
            },
            "recommendation": self._generate_directive(status),
        }

    def _generate_directive(self, status: str) -> str:
        directives = {
            "DANGEROUS": "❌ DO NOT MERGE. Extreme semantic drift detected. Mandatory rebase and manual architectural review required.",
            "STALE": "⚠ CAUTION. Moderate semantic drift. Automated tests insufficient; manual diff review required.",
            "CURRENT": "✓ SAFE. Branch context is synchronized with target.",
        }
        return directives.get(status, "UNKNOWN STATUS")


# ==============================================================================
# LAYER 5b: SEMANTIC TRANSPARENCY ANALYSIS
# ==============================================================================

class SemanticTransparencyAnalyzer:
    """Layer 5b v2 — PR-MCI heuristic semantic transparency engine.

    Three-phase analysis: Linguistic Lexer → Diff Profiler → Cross-Correlation.
    Derives mci_score ∈ [0,1] from five signals (V_s/V_o/V_f/V_r/V_e).
    Zero external dependencies. Sub-second execution.

    Status values:
      UNVERIFIED        No PR description — cannot evaluate
      TRANSPARENT       Description consistent with diff profile
      CAUTION_MISMATCH  Partial inconsistency — manual review advised
      DECEPTIVE_PAYLOAD High-confidence mismatch — escalation triggered
    """

    def __init__(self, pr_description: str, diffs, config: dict = None):
        self.pr_description = pr_description or ''
        self.diffs = list(diffs) if diffs is not None else []
        self.config = config or {}

    # ── Phase 1: Linguistic Lexer ─────────────────────────────────────────────

    @staticmethod
    def _stem(word: str) -> str:
        """Lovins-inspired suffix stripper — stem must remain ≥3 chars."""
        if len(word) <= 3:
            return word
        for suffix, replacement in _SEMANTIC_SUFFIXES:
            if word.endswith(suffix):
                candidate = word[:-len(suffix)] + replacement
                if len(candidate) >= 3:
                    return candidate
        return word

    @staticmethod
    def _sanitize(text: str) -> str:
        """Strip markdown, normalize to lowercase ASCII."""
        text = re.sub(r'```.*?```', ' ', text, flags=re.DOTALL)
        text = re.sub(r'`[^`]+`', ' ', text)
        text = re.sub(r'\[([^\]]+)\]\([^)]*\)', r'\1', text)
        text = re.sub(r'[#*_~>|]', ' ', text)
        return text.encode('ascii', errors='ignore').decode().lower()

    def _extract_claim(self) -> dict:
        """Extract Semantic Claim Object: scope, dominant_op, raw_tokens."""
        clean = self._sanitize(self.pr_description)
        tokens = re.findall(r'[a-z0-9_/.-]+', clean)
        raw = set(tokens)
        stems = {self._stem(t) for t in tokens if len(t) > 2}

        scope = 'unspecified'
        if raw & _SEMANTIC_MICRO_SCOPE:
            scope = 'micro'
        elif raw & _SEMANTIC_MACRO_SCOPE:
            scope = 'macro'

        dominant_op = 'unspecified'
        for op_name, op_set in [
            ('remedial',    _SEMANTIC_REMEDIAL_STEMS),
            ('destructive', _SEMANTIC_DESTRUCTIVE_STEMS),
            ('additive',    _SEMANTIC_ADDITIVE_STEMS),
            ('mutative',    _SEMANTIC_MUTATIVE_STEMS),
        ]:
            if stems & op_set:
                dominant_op = op_name
                break

        return {'scope': scope, 'dominant_op': dominant_op, 'raw_tokens': sorted(raw)}

    # ── Phase 2: Diff Profiler ────────────────────────────────────────────────

    def _profile_diff(self) -> dict:
        """Extract Diff Reality Object: churn, extensions, structural alterations."""
        lines_added = lines_deleted = structural_alterations = 0
        extensions: set = set()
        sensitive_paths: list = []

        struct_pat = re.compile(
            r'^\+[ \t]*(def |class |async def |function |interface |struct )',
        )

        for d in self.diffs:
            path = d.b_path or getattr(d, 'a_path', '') or ''
            if not isinstance(path, str):
                path = ''
            if path:
                ext = Path(path).suffix.lower()
                if ext:
                    extensions.add(ext)
                for pat in _SEMANTIC_SENSITIVE_PATHS:
                    if pat.search(path):
                        sensitive_paths.append(path)
                        break

            try:
                diff_bytes = d.diff if isinstance(d.diff, bytes) else b''
                diff_text = diff_bytes.decode('utf-8', errors='replace')
            except Exception:
                diff_text = ''

            for line in diff_text.splitlines():
                if line.startswith('+') and not line.startswith('+++'):
                    lines_added += 1
                    if struct_pat.match(line):
                        structural_alterations += 1
                elif line.startswith('-') and not line.startswith('---'):
                    lines_deleted += 1

        total_churn = lines_added + lines_deleted
        insertion_ratio = lines_added / total_churn if total_churn else 0.0

        return {
            'lines_added': lines_added,
            'lines_deleted': lines_deleted,
            'total_churn': total_churn,
            'insertion_ratio': insertion_ratio,
            'ext_count': len(extensions),
            'structural_alterations': structural_alterations,
            'sensitive_paths': sensitive_paths,
        }

    # ── Phase 3: Cross-Correlation Matrix ────────────────────────────────────

    def analyze_transparency(self) -> dict:
        if not self.pr_description.strip():
            return {
                'status': 'UNVERIFIED',
                'is_deceptive': False,
                'matched_keyword': None,
                'directive': '⚠ CAUTION. No PR description provided for semantic analysis.',
                'mci_score': 0.0,
                'signals': [],
                'semantic_claim': {},
                'diff_reality': {},
            }

        claim   = self._extract_claim()
        reality = self._profile_diff()
        signals: list = []
        mci_score = 0.0

        churn_limit   = self.config.get('micro_scope_churn_limit', 50)
        fix_ir_thresh = self.config.get('insertion_ratio_fix_threshold', 0.9)

        # V_s — Scope Adequacy: micro claim but large churn
        if claim['scope'] == 'micro' and reality['total_churn'] > churn_limit:
            signals.append('scope_understated')
            mci_score += 0.4

        # V_o — Operation Mutation: micro claim + new structural declarations
        if claim['scope'] == 'micro' and reality['structural_alterations'] > 0:
            signals.append('operation_mutation')
            mci_score += 0.3

        # V_f — Hidden Component: sensitive file modified but not named in description
        if reality['sensitive_paths'] and claim['scope'] == 'micro':
            desc_lower = self.pr_description.lower()
            unacknowledged = [
                p for p in reality['sensitive_paths']
                if not any(part.lower() in desc_lower
                           for part in Path(p).parts[-2:] if len(part) > 2)
            ]
            if unacknowledged:
                signals.append('hidden_component_modification')
                mci_score += 0.3

        # V_r — Phantom Additions: "fix" claim but diff is almost entirely additions
        if claim['dominant_op'] == 'remedial' and reality['insertion_ratio'] > fix_ir_thresh:
            signals.append('phantom_additions')
            mci_score += 0.4

        # V_e — Cross-stack micro claim: touches ≥3 distinct file types
        if claim['scope'] == 'micro' and reality['ext_count'] >= 3:
            signals.append('cross_stack_micro_claim')
            mci_score += 0.2

        # Macro scope → human reviewer advisory; no MCI penalty (attacker who
        # claims a massive change loses the stealth advantage anyway)
        if claim['scope'] == 'macro':
            signals.append('macro_scope_manual_review')

        mci_score = min(round(mci_score, 3), 1.0)

        if mci_score >= 0.5:
            status, is_deceptive = 'DECEPTIVE_PAYLOAD', True
            directive = '❌ DO NOT MERGE. PR description is inconsistent with actual diff scope and structure.'
        elif mci_score > 0.0 or 'macro_scope_manual_review' in signals:
            status, is_deceptive = 'CAUTION_MISMATCH', False
            directive = '⚠ REVIEW ADVISED. Partial mismatch between stated intent and diff profile.'
        else:
            status, is_deceptive = 'TRANSPARENT', False
            directive = '✓ Description aligns with verified diff scope and operation type.'

        return {
            'status': status,
            'is_deceptive': is_deceptive,
            'matched_keyword': signals[0] if signals else None,  # backwards compat
            'directive': directive,
            'mci_score': mci_score,
            'signals': signals,
            'semantic_claim': claim,
            'diff_reality': reality,
        }


# ==============================================================================
# CONFIGURATION
# ==============================================================================

DEFAULT_CONFIG = {
    "thresholds": {
        "branch_age_days": [90, 180, 365],
        "files_deleted":   [10, 20, 50],
        "lines_deleted":   [5000, 10000, 50000],
        "temporal": {
            "stale":     250.0,
            "dangerous": 1000.0,
        },
        "structural": {
            "deletion_ratio":       0.20,
            "min_deleted_nodes":    3,
            "complexity_threshold": 15,
        },
    },
    "semantic": {
        "enabled": True,
        "micro_scope_churn_limit": 50,
        "insertion_ratio_fix_threshold": 0.9,
        "benign_keywords": [],  # legacy — kept for payloadguard.yml compat; unused by v2
    },
    "sca": {
        "fail_on_unknown": True,
    },
    "actions": {
        "enabled": True,
        "critical_signal_score": 5,
        "high_signal_score": 3,
        "trusted_oidc_consumers": [],
    },
}


@dataclass
class PayloadGuardConfig:
    thresholds: dict = field(default_factory=lambda: copy.deepcopy(DEFAULT_CONFIG["thresholds"]))
    semantic: dict   = field(default_factory=lambda: copy.deepcopy(DEFAULT_CONFIG["semantic"]))
    sca: dict        = field(default_factory=lambda: copy.deepcopy(DEFAULT_CONFIG["sca"]))
    actions: dict    = field(default_factory=lambda: copy.deepcopy(DEFAULT_CONFIG["actions"]))


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merges override into a deep copy of base."""
    result = copy.deepcopy(base)
    for k, v in override.items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = v
    return result


def load_config(repo_path: str) -> PayloadGuardConfig:
    """
    Loads payloadguard.yml from the repo root if present, deep-merging it over
    DEFAULT_CONFIG. Falls back to defaults silently if the file is absent.
    """
    config_path = Path(repo_path) / "payloadguard.yml"
    if not config_path.exists():
        return PayloadGuardConfig()
    try:
        with open(config_path) as f:
            user_cfg = yaml.safe_load(f) or {}
    except yaml.YAMLError as e:
        print(f"WARNING: payloadguard.yml is invalid and has been ignored: {e}", file=sys.stderr)
        return PayloadGuardConfig()
    merged = _deep_merge(DEFAULT_CONFIG, user_cfg)
    merged_thresholds = merged.get("thresholds", copy.deepcopy(DEFAULT_CONFIG["thresholds"]))
    for _key in ("branch_age_days", "files_deleted", "lines_deleted"):
        _val = merged_thresholds.get(_key)
        if isinstance(_val, list) and len(_val) == 3:
            merged_thresholds[_key] = sorted(_val)
    return PayloadGuardConfig(
        thresholds=merged_thresholds,
        semantic=merged.get("semantic", copy.deepcopy(DEFAULT_CONFIG["semantic"])),
        sca=merged.get("sca",           copy.deepcopy(DEFAULT_CONFIG["sca"])),
        actions=merged.get("actions",   copy.deepcopy(DEFAULT_CONFIG["actions"])),
    )
    
# ==============================================================================
# CORE ANALYZER
# ==============================================================================

class PayloadAnalyzer:
    """
    Five-layer analysis system for detecting destructive merges.

    Layer 1: Surface Scan        — File/line delta extraction
    Layer 2: Forensic Analysis   — Deletion ratios, critical path detection
    Layer 3: Consequence Model   — Severity scoring and verdict
    Layer 4: Structural Drift    — AST-based class/function deletion detection
    Layer 5: Extended Analysis   — Temporal drift score + semantic transparency
    """

    def __init__(self, repo_path, branch, target_branch="main", config: PayloadGuardConfig = None):
        try:
            self.repo = git.Repo(repo_path)
        except Exception as e:
            print(f"ERROR: Could not open repository at {repo_path}")
            print(f"Details: {e}")
            sys.exit(1)

        self.branch = branch
        self.target = target_branch
        self.repo_path = repo_path
        self.config = config or PayloadGuardConfig()

    def _calculate_target_velocity(self, target_ref: str = None) -> float:
        """
        Calculates commits per day on the target branch over the last 90 days.
        Returns 0.0 safely if the calculation fails for any reason.
        """
        ref = target_ref or self.target
        try:
            target_commit = self.repo.commit(ref)
            since = target_commit.committed_datetime - timedelta(days=90)
            commits = list(
                self.repo.iter_commits(ref, since=since.isoformat(), max_count=1000)
            )
            return round(len(commits) / 90.0, 3)
        except Exception:
            return 0.0

    def _resolve_ref(self, ref: str) -> str:
        """Resolve a ref, falling back to origin/<ref> for CI detached-HEAD checkouts."""
        try:
            self.repo.commit(ref)
            return ref
        except git.exc.BadName:
            origin_ref = f"origin/{ref}"
            self.repo.commit(origin_ref)  # raises BadName if also absent
            return origin_ref

    def analyze(self, pr_description: str = ""):
        try:
            try:
                target_ref = self._resolve_ref(self.target)
            except git.exc.BadName:
                return {
                    "error": f"Target branch '{self.target}' not found",
                    "available_branches": [ref.name for ref in self.repo.heads],
                }

            try:
                branch_ref = self._resolve_ref(self.branch)
            except git.exc.BadName:
                return {
                    "error": f"Branch '{self.branch}' not found",
                    "available_branches": [ref.name for ref in self.repo.heads],
                }

            merge_base = self.repo.merge_base(target_ref, branch_ref)
            if not merge_base:
                return {
                    "error": "No common ancestor found — branches may have unrelated histories",
                    "available_branches": [ref.name for ref in self.repo.heads],
                }
            diffs = merge_base[0].diff(branch_ref)

            # LAYER 1: FILE COUNTS
            files_added    = len([d for d in diffs if d.change_type == 'A'])
            files_deleted  = len([d for d in diffs if d.change_type == 'D'])
            files_modified = len([d for d in diffs if d.change_type == 'M'])
            files_renamed  = len([d for d in diffs if d.change_type == 'R'])
            files_copied   = len([d for d in diffs if d.change_type == 'C'])
            files_typed    = len([d for d in diffs if d.change_type == 'T'])

            # Permission change detection (§1.5) and symlink/submodule detection (§1.3).
            permission_changes = []
            special_files: list[dict] = []
            _SYMLINK_MODE    = 0o120000
            _SUBMODULE_MODE  = 0o160000
            for d in diffs:
                try:
                    a_mode = getattr(d, 'a_mode', None) or 0
                    b_mode = getattr(d, 'b_mode', None) or 0
                    fpath  = d.b_path or d.a_path or ''
                    # Symlinks and submodules — flag regardless of change type.
                    effective_mode = b_mode or a_mode
                    if effective_mode & _SUBMODULE_MODE == _SUBMODULE_MODE:
                        special_files.append({"file": fpath, "type": "submodule", "change_type": d.change_type})
                    elif effective_mode & _SYMLINK_MODE == _SYMLINK_MODE:
                        special_files.append({"file": fpath, "type": "symlink", "change_type": d.change_type})
                    # Mode changes on regular files.
                    elif a_mode and b_mode and a_mode != b_mode:
                        permission_changes.append({
                            "file": fpath,
                            "from_mode": oct(a_mode),
                            "to_mode": oct(b_mode),
                            "made_executable": bool(b_mode & 0o111 and not (a_mode & 0o111)),
                        })
                except Exception:
                    pass

            # Use git's own numstat for line counts: handles binary files correctly
            # ('-' entries) and avoids loading blobs into memory.
            lines_added = 0
            lines_deleted = 0
            try:
                numstat = self.repo.git.diff(
                    '--numstat', merge_base[0].hexsha, branch_ref
                )
                for line in numstat.splitlines():
                    parts = line.split('\t')
                    if len(parts) == 3:
                        added_str, deleted_str = parts[0], parts[1]
                        if added_str != '-':
                            lines_added += int(added_str)
                        if deleted_str != '-':
                            lines_deleted += int(deleted_str)
            except Exception:
                pass

            # LAYER 4: STRUCTURAL DRIFT
            structural_th = self.config.thresholds["structural"]
            structural_score = 0.0
            structural_flags = []
            overall_structural_severity = "LOW"
            complexity_advisory_all: list = []

            for d in diffs:
                if d.change_type not in ('M', 'R'):
                    continue
                path = d.b_path or d.a_path or ''
                if structural_parser.language_for_path(path) is None:
                    continue
                try:
                    original = d.a_blob.data_stream.read().decode('utf-8', errors='ignore')
                    modified = d.b_blob.data_stream.read().decode('utf-8', errors='ignore')
                    result = StructuralPayloadAnalyzer(
                        original, modified,
                        file_path=path,
                        deletion_ratio_threshold=structural_th["deletion_ratio"],
                        min_deletion_count=structural_th["min_deleted_nodes"],
                        complexity_threshold=structural_th.get("complexity_threshold", 15),
                    ).analyze_structural_drift()
                    if 'error' not in result:
                        for ca in result.get('complexity_advisory', []):
                            complexity_advisory_all.append({'file': path, **ca})
                        if result['metrics']['deleted_node_count'] > 0:
                            ratio = result['metrics']['structural_deletion_ratio']
                            structural_score = max(structural_score, ratio)
                            structural_flags.append({
                                'file': path,
                                'status': result['status'],
                                'severity': result['severity'],
                                'metrics': result['metrics'],
                                'deleted_components': result['deleted_components'],
                            })
                            if result['severity'] == 'CRITICAL':
                                overall_structural_severity = 'CRITICAL'
                except Exception:
                    pass

            # Cross-file structural aggregation: distributed deletions across
            # multiple files can collectively constitute a destructive payload
            # even when no single file exceeds the per-file ratio threshold.
            # Both the absolute count AND the cross-file ratio must exceed their
            # thresholds — mirrors the per-file dual-condition gate.
            if overall_structural_severity != 'CRITICAL' and len(structural_flags) >= 2:
                total_deleted_nodes = sum(
                    f['metrics']['deleted_node_count'] for f in structural_flags
                )
                total_original_nodes = sum(
                    f['metrics']['original_node_count'] for f in structural_flags
                )
                cross_file_ratio = (
                    total_deleted_nodes / total_original_nodes
                    if total_original_nodes > 0 else 0
                )
                if (total_deleted_nodes >= structural_th["min_deleted_nodes"]
                        and cross_file_ratio > structural_th["deletion_ratio"]):
                    overall_structural_severity = 'CRITICAL'

            branch_commit = self.repo.commit(branch_ref)
            target_commit = self.repo.commit(target_ref)
            branch_date = branch_commit.committed_datetime
            target_date = target_commit.committed_datetime
            # Clamp to zero: branch newer than target is treated as age 0, not an error.
            days_old = max(0, (target_date - branch_date).days)

            total_lines_changed = lines_added + lines_deleted
            deletion_ratio = (lines_deleted / total_lines_changed * 100) if total_lines_changed > 0 else 0

            # LAYER 2: FORENSIC — critical path detection via regex
            deleted_files = [d.a_path for d in diffs if d.change_type == 'D']
            critical_deletions = [
                f for f in deleted_files
                if any(re.search(p, f) for p in CRITICAL_PATH_PATTERNS)
            ]
            security_deletions = [
                f for f in deleted_files
                if any(re.search(p, f) for p in _SECURITY_CRITICAL_PATTERNS)
            ]

            # LAYER 2b: SCA — dependency manifest scanning (opt-in via allowlist.yml)
            allowlist = _load_allowlist(self.repo_path)
            sca_flags: list = []
            sca_manifests_scanned: list = []
            if allowlist is not None:
                for d in diffs:
                    if d.change_type not in ('A', 'M'):
                        continue
                    path = d.b_path or d.a_path or ''
                    manifest_type = next(
                        (mt for pat, mt in _MANIFEST_PATTERNS.items() if re.search(pat, path)),
                        None,
                    )
                    if manifest_type is None:
                        continue
                    sca_manifests_scanned.append(path)
                    allowlist_key = _MANIFEST_ALLOWLIST_KEY.get(manifest_type, manifest_type)
                    allowed = allowlist.get(allowlist_key, set())
                    try:
                        diff_text = self.repo.git.diff(merge_base[0].hexsha, branch_ref, '--', path)
                        added_pkgs = _parse_added_packages(diff_text, manifest_type)
                        seen = set()
                        for pkg in added_pkgs:
                            if pkg not in allowed and pkg not in seen:
                                seen.add(pkg)
                                sca_flags.append({
                                    "package": pkg,
                                    "manifest": path,
                                    "manifest_type": manifest_type,
                                })
                    except Exception:
                        pass

            sca_result = {
                "status": "FLAGGED" if sca_flags else "CLEAN",
                "unverified_packages": sca_flags[:20],
                "manifest_files_scanned": sca_manifests_scanned,
                "allowlist_active": allowlist is not None,
            }

            # LAYER 1 (extension): Added non-code file content scanning (INC-1, INC-4)
            added_file_flags = self._scan_added_file_content(diffs)

            # LAYER 2c: GitHub Actions poisoning detection
            actions_poison_flags = self._scan_github_actions_poisoning(diffs)

            # LAYER 2d: Mutable action ref advisory (no score impact)
            mutable_tag_warnings = _scan_mutable_action_refs(diffs)

            # LAYER 3: CONSEQUENCE VERDICT
            unverified_dep_count = len(sca_flags) if self.config.sca.get("fail_on_unknown", True) else 0
            verdict = self._assess_consequence(
                files_deleted,
                lines_deleted,
                days_old,
                deletion_ratio,
                overall_structural_severity,
                critical_file_deletions=len(critical_deletions),
                security_file_deletions=len(security_deletions),
                unverified_dependencies=unverified_dep_count,
                content_flags=len(added_file_flags),
                actions_poisoning_flags=len(actions_poison_flags),
                actions_poisoning_critical=any(
                    f['severity'] == 'CRITICAL' for f in actions_poison_flags
                ),
            )

            # LAYER 5a: TEMPORAL DRIFT
            temporal_th = self.config.thresholds["temporal"]
            target_velocity = self._calculate_target_velocity(target_ref)
            temporal_drift = TemporalDriftAnalyzer(
                branch_age_days=max(days_old, 0),
                target_velocity_commits_per_day=target_velocity,
                warning_threshold=temporal_th["stale"],
                critical_threshold=temporal_th["dangerous"],
            ).analyze_drift()

            # LAYER 5b: SEMANTIC TRANSPARENCY (v2 — PR-MCI heuristic engine)
            semantic = SemanticTransparencyAnalyzer(
                pr_description=pr_description,
                diffs=diffs,
                config=self.config.semantic,
            ).analyze_transparency()

            if semantic["status"] == "UNVERIFIED":
                # INC-3: no PR description — cannot validate; SAFE upgrades to REVIEW
                # so the gap is visible to reviewers without blocking the PR.
                verdict["flags"].append("No PR description — semantic transparency unverified")
                if verdict["status"] == "SAFE":
                    verdict["status"] = "REVIEW"
            elif semantic["status"] == "DECEPTIVE_PAYLOAD":
                verdict["flags"].append(
                    f"Semantic mismatch — description contradicts diff profile "
                    f"(signals: {', '.join(semantic['signals'])})"
                )
                _escalate = {"SAFE": "CAUTION", "REVIEW": "CAUTION", "CAUTION": "DESTRUCTIVE"}
                if verdict["status"] in _escalate:
                    verdict["status"] = _escalate[verdict["status"]]
            elif semantic["status"] == "CAUTION_MISMATCH":
                verdict["flags"].append(
                    f"Partial semantic mismatch — manual review advised "
                    f"(signals: {', '.join(semantic['signals'])})"
                )
                if verdict["status"] == "SAFE":
                    verdict["status"] = "REVIEW"

            # COMMIT MESSAGE ANALYSIS (advisory — §4.1)
            commit_flags: list[dict] = []
            try:
                branch_commits = list(self.repo.iter_commits(
                    f"{merge_base[0].hexsha}..{branch_ref}", max_count=50
                ))
                for commit in branch_commits:
                    msg = commit.message.lower()
                    for pattern in _COMMIT_RED_FLAG_PATTERNS:
                        if re.search(pattern, msg):
                            commit_flags.append({
                                "sha": commit.hexsha[:7],
                                "message": commit.message.split('\n')[0][:120],
                                "matched_pattern": pattern,
                            })
                            break
            except Exception:
                pass

            return {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "analysis": {
                    "branch": self.branch,
                    "target": self.target,
                    "repo_path": str(self.repo_path),
                },
                "files": {
                    "added": files_added,
                    "deleted": files_deleted,
                    "modified": files_modified,
                    "renamed": files_renamed,
                    "copied": files_copied,
                    "type_changed": files_typed,
                    "total_changed": files_added + files_deleted + files_modified + files_renamed + files_copied + files_typed,
                },
                "lines": {
                    "added": lines_added,
                    "deleted": lines_deleted,
                    "net_change": lines_added - lines_deleted,
                    "deletion_ratio_percent": round(deletion_ratio, 1),
                    "codebase_reduction_percent": round(deletion_ratio, 1),
                },
                "temporal": {
                    "branch_age_days": days_old,
                    "branch_last_commit": branch_date.isoformat(),
                    "branch_commit_hash": branch_commit.hexsha[:7],
                    "target_last_commit": target_date.isoformat(),
                    "target_commit_hash": target_commit.hexsha[:7],
                },
                "verdict": verdict,
                "structural": {
                    "overall_severity": overall_structural_severity,
                    "max_deletion_ratio_pct": round(structural_score, 2),
                    "flagged_files": structural_flags[:10],
                },
                "complexity_advisory": complexity_advisory_all[:20],
                "sca": sca_result,
                "temporal_drift": temporal_drift,
                "semantic": semantic,
                "commit_flags": commit_flags,
                "content_flags": added_file_flags,
                "actions_poisoning": {
                    "flagged_workflows": actions_poison_flags[:10],
                    "total": len(actions_poison_flags),
                },
                "mutable_tag_warnings": mutable_tag_warnings,
                "permission_changes": permission_changes,
                "special_files": special_files,
                "deleted_files": {
                    "total": len(deleted_files),
                    "critical": critical_deletions[:10],
                    "all": deleted_files[:30],
                },
                "runtime_events": _load_runtime_events(),
            }

        except Exception as e:
            return {
                "error": f"Analysis failed: {str(e)}",
                "error_type": type(e).__name__,
            }

    def _assess_consequence(
        self,
        files_deleted: int,
        lines_deleted: int,
        days_old: float,
        deletion_ratio: float,
        structural_severity: str = "LOW",
        critical_file_deletions: int = 0,
        security_file_deletions: int = 0,
        unverified_dependencies: int = 0,
        content_flags: int = 0,
        actions_poisoning_flags: int = 0,
        actions_poisoning_critical: bool = False,
    ) -> dict:
        """
        Layer 3 consequence scoring -- assigns a severity verdict to the PR's deletion profile.

        Returns a dict with keys: status, severity, severity_score, flags, recommendation.

        Formal contracts are maintained in verification/consequence_pure.py and verified by
        CrossHair. Invariants proven there:
          - verdict in {SAFE, REVIEW, CAUTION, DESTRUCTIVE}
          - severity_score in [0, 31]
          - SAFE <-> severity_score < 1; DESTRUCTIVE <-> severity_score >= 5
          - security_file_deletions > 0 -> DESTRUCTIVE
          - structural_severity == CRITICAL -> DESTRUCTIVE
          - actions_poisoning_critical -> DESTRUCTIVE
          - all-zero inputs -> SAFE

        Run: cd verification && crosshair check consequence_pure
        """
        flags = []
        severity_score = 0.0
        th = self.config.thresholds

        age_th   = th["branch_age_days"]  # [90, 180, 365]
        files_th = th["files_deleted"]     # [10, 20, 50]
        lines_th = th["lines_deleted"]     # [5000, 10000, 50000]

        if days_old > age_th[2]:
            flags.append(f"Branch is {days_old} days old (1+ year)")
            severity_score += 3
        elif days_old > age_th[1]:
            flags.append(f"Branch is {days_old} days old (6+ months)")
            severity_score += 2
        elif days_old > age_th[0]:
            flags.append(f"Branch is {days_old} days old (3+ months)")
            severity_score += 1

        # Three deletion dimensions are highly correlated — score independently
        # then cap to prevent double-counting: max of the three + 1 bonus if ≥2 fire.
        files_score = 0
        if files_deleted > files_th[2]:
            flags.append(f"{files_deleted} files would be deleted (massive scope)")
            files_score = 3
        elif files_deleted > files_th[1]:
            flags.append(f"{files_deleted} files would be deleted (large scope)")
            files_score = 2
        elif files_deleted > files_th[0]:
            flags.append(f"{files_deleted} files would be deleted")
            files_score = 1

        # Ratio scoring only fires when absolute deletions reach a meaningful scale.
        # A 5-deleted / 15-added PR (25% ratio) is not a destructive changeset.
        # When critical-path files are deleted the bar drops to zero — a 45-line
        # config deletion at 90% ratio IS significant regardless of volume.
        _RATIO_MIN_LINES = 0 if critical_file_deletions > 0 else 100
        ratio_score = 0
        if lines_deleted >= _RATIO_MIN_LINES:
            if deletion_ratio > 90:
                flags.append(f"Deletion ratio: {deletion_ratio:.1f}% (almost entire changeset is deletions)")
                ratio_score = 3
            elif deletion_ratio > 70:
                flags.append(f"Deletion ratio: {deletion_ratio:.1f}% (majority of changes are deletions)")
                ratio_score = 2
            elif deletion_ratio > 50:
                flags.append(f"Deletion ratio: {deletion_ratio:.1f}% (more deletions than additions)")
                ratio_score = 1

        lines_score = 0
        if lines_deleted > lines_th[2]:
            flags.append(f"{lines_deleted:,} lines would be deleted (massive codebase change)")
            lines_score = 3
        elif lines_deleted > lines_th[1]:
            flags.append(f"{lines_deleted:,} lines would be deleted (large codebase change)")
            lines_score = 2
        elif lines_deleted > lines_th[0]:
            flags.append(f"{lines_deleted:,} lines would be deleted")
            lines_score = 1

        nonzero_dims = sum(1 for s in (files_score, ratio_score, lines_score) if s > 0)
        deletion_dim = min(4, max(files_score, ratio_score, lines_score) + (1 if nonzero_dims >= 2 else 0))
        severity_score += deletion_dim

        if structural_severity == "CRITICAL":
            flags.append("Structural drift CRITICAL — significant class/function deletions detected")
            severity_score += 5

        if critical_file_deletions > 5:
            flags.append(f"{critical_file_deletions} critical-path files deleted")
            severity_score += 2
        elif critical_file_deletions > 0:
            flags.append(f"{critical_file_deletions} critical-path file(s) deleted")
            severity_score += 2

        if security_file_deletions > 0:
            flags.append(f"{security_file_deletions} security-critical file(s) deleted (auth/security/permission)")
            severity_score += 5

        if unverified_dependencies > 0:
            flags.append(f"{unverified_dependencies} unverified package(s) added — not in allowlist.yml")
            severity_score += 3

        if content_flags > 0:
            flags.append(f"{content_flags} added file(s) contain CI trigger strings or shell execution patterns")
            severity_score += min(4, content_flags * 2)

        actions_cfg = self.config.actions if hasattr(self.config, 'actions') else DEFAULT_CONFIG["actions"]
        if actions_poisoning_critical:
            flags.append(
                f"{actions_poisoning_flags} GitHub Actions workflow(s) contain critical "
                f"poisoning signals (base64 payload / credential harvest)"
            )
            severity_score += actions_cfg.get("critical_signal_score", 5)
        elif actions_poisoning_flags > 0:
            flags.append(
                f"{actions_poisoning_flags} GitHub Actions workflow(s) contain "
                f"poisoning signals (elevated OIDC / dormant trigger / forged author)"
            )
            severity_score += actions_cfg.get("high_signal_score", 3)

        if severity_score >= 5:
            return {
                "status": "DESTRUCTIVE",
                "severity": "CRITICAL",
                "flags": flags,
                "recommendation": "❌ DO NOT MERGE — This would catastrophically alter the codebase",
                "severity_score": severity_score,
            }
        elif severity_score >= 3:
            return {
                "status": "CAUTION",
                "severity": "HIGH",
                "flags": flags,
                "recommendation": "⚠️  REVIEW CAREFULLY — Significant destructive changes detected",
                "severity_score": severity_score,
            }
        elif severity_score >= 1:
            return {
                "status": "REVIEW",
                "severity": "MEDIUM",
                "flags": flags if flags else ["Some changes detected"],
                "recommendation": "→ Proceed with normal review process, but note the flags above",
                "severity_score": severity_score,
            }
        else:
            return {
                "status": "SAFE",
                "severity": "LOW",
                "flags": flags if flags else ["No major red flags detected"],
                "recommendation": "✓ Proceed with normal review process",
                "severity_score": severity_score,
            }

    def _scan_added_file_content(self, diffs):
        """Scan added non-code files for CI trigger strings and shell execution patterns."""
        flags = []
        for d in diffs:
            if d.change_type != 'A':
                continue
            path = d.b_path or ''
            ext = Path(path).suffix.lower()
            if ext in _CONTENT_SCAN_CODE_EXTENSIONS or ext in _CONTENT_BINARY_EXTENSIONS:
                continue
            # Workflow files are handled exclusively by L2c (_scan_github_actions_poisoning)
            # to prevent double-counting scores from the same file.
            if isinstance(path, str) and re.search(_ACTIONS_WORKFLOW_PATTERN, path):
                continue
            try:
                content = d.b_blob.data_stream.read().decode('utf-8', errors='replace')
            except Exception:
                continue
            ci_matches = [p for p in _CONTENT_CI_TRIGGER_PATTERNS
                          if re.search(p, content, re.IGNORECASE | re.MULTILINE)]
            shell_matches = [p for p in _CONTENT_SHELL_PATTERNS
                             if re.search(p, content, re.IGNORECASE | re.MULTILINE)]
            if ci_matches or shell_matches:
                flags.append({
                    'file': path,
                    'ci_triggers': ci_matches,
                    'shell_patterns': shell_matches,
                })
        return flags

    def _scan_github_actions_poisoning(self, diffs) -> list:
        """Scan added and modified GitHub Actions workflow files for poisoning signals."""
        if not self.config.actions.get("enabled", True):
            return []
        flags = []
        for d in diffs:
            if d.change_type not in ('A', 'M'):
                continue
            path = d.b_path or d.a_path or ''
            if not isinstance(path, str) or not re.search(_ACTIONS_WORKFLOW_PATTERN, path):
                continue
            try:
                content = d.b_blob.data_stream.read().decode('utf-8', errors='replace')
            except Exception:
                continue

            signals = []

            # Fix 3: normalise folded/literal YAML block scalars to one line so
            # patterns like 'base64 -d | bash' match even when split across lines.
            # Only used for base64 checks — other checks depend on line structure.
            normalized = _normalize_yaml_content(content)

            # Signal 1: base64 payload — check both raw and normalised content so
            # a payload entirely on one line is still caught without normalisation.
            seen_b64 = False
            for pat in _ACTIONS_BASE64_PAYLOAD:
                if not seen_b64 and (
                    re.search(pat, content, re.IGNORECASE | re.MULTILINE)
                    or re.search(pat, normalized, re.IGNORECASE)
                ):
                    signals.append({'type': 'base64_payload', 'pattern': pat})
                    seen_b64 = True  # one entry per file regardless of how many patterns match

            for pat in _ACTIONS_CREDENTIAL_HARVEST:
                if re.search(pat, content, re.IGNORECASE | re.MULTILINE) or \
                   re.search(pat, normalized, re.IGNORECASE):
                    signals.append({'type': 'credential_harvest', 'pattern': pat})

            has_dormant_trigger = any(
                re.search(p, content, re.IGNORECASE | re.MULTILINE)
                for p in _ACTIONS_DORMANT_TRIGGER
            )
            has_shell_exec = any(
                re.search(p, content, re.IGNORECASE | re.MULTILINE)
                for p in _CONTENT_SHELL_PATTERNS
            )
            if has_dormant_trigger and has_shell_exec:
                signals.append({'type': 'dormant_trigger_with_payload', 'pattern': 'composite'})

            if _ACTIONS_FORGED_AUTHOR.search(content):
                signals.append({'type': 'forged_bot_author', 'pattern': _ACTIONS_FORGED_AUTHOR.pattern})

            if _ACTIONS_OIDC_ELEVATION_PATTERN.search(content):
                # id-token: write detected - verify legitimate OIDC consumer.

                # Extract all action references
                actions_in_workflow = re.findall(
                    r'uses:\s+([^\s@\n]+)',
                    content,
                    re.IGNORECASE
                )

                # Config-extended trusted consumers
                config_trusted = self.config.actions.get("trusted_oidc_consumers", [])

                # Check if any action is legitimate (built-in or config)
                has_legitimate_consumer = any(
                    _is_oidc_consumer_legitimate(action)
                    or any(t in action for t in config_trusted)
                    for action in actions_in_workflow
                )

                if has_legitimate_consumer:
                    # Safe: id-token granted to trusted action
                    pass
                else:
                    # No legitimate consumer - check for typosquat
                    has_typosquat = any(
                        _is_oidc_consumer_typosquatted(action)
                        for action in actions_in_workflow
                    )

                    if has_typosquat:
                        signals.append({
                            'type': 'oidc_elevation_typosquatted',
                            'pattern': 'id-token: write with typosquatted OIDC action',
                            'risk': 'Deliberate impersonation of trusted cloud auth action',
                            'severity': 'CRITICAL'
                        })
                    else:
                        signals.append({
                            'type': 'oidc_elevation_no_consumer',
                            'pattern': 'id-token: write without safe OIDC consumer',
                            'risk': 'Elevated permissions without legitimate use',
                            'severity': 'HIGH'
                        })

            # Fix 1: pull_request_target as a standalone signal.
            # Alone → HIGH: the trigger is sometimes legitimate (e.g. posting a
            # comment from a fork PR). Combined with any write permission → CRITICAL
            # because the workflow can both read secrets and modify the repository.
            if _ACTIONS_DANGEROUS_TRIGGERS.search(content):
                if _ACTIONS_WRITE_PERMISSIONS.search(content):
                    signals.append({
                        'type': 'pull_request_target_with_write_permissions',
                        'pattern': 'pull_request_target + write permissions',
                    })
                else:
                    signals.append({
                        'type': 'dangerous_trigger_pull_request_target',
                        'pattern': 'pull_request_target trigger',
                    })

            # Signal 7: GITHUB_ENV path/loader injection
            if _ACTIONS_GITHUB_ENV_INJECTION.search(content):
                signals.append({
                    'type': 'github_env_injection',
                    'pattern': _ACTIONS_GITHUB_ENV_INJECTION.pattern,
                })

            if signals:
                critical_types = {
                    'base64_payload',
                    'credential_harvest',
                    'pull_request_target_with_write_permissions',
                    'oidc_elevation_typosquatted',
                }
                severity = 'CRITICAL' if any(s['type'] in critical_types for s in signals) else 'HIGH'
                flags.append({
                    'file': path,
                    'signals': signals,
                    'severity': severity,
                    'change_type': d.change_type,
                })
        return flags


def _scan_mutable_action_refs(diffs) -> list:
    """Detect workflow `uses:` values not pinned to a 40-char SHA (advisory, no score impact)."""
    _sha_re = re.compile(r'^[0-9a-f]{40}$', re.IGNORECASE)
    warnings: list = []
    for d in diffs:
        if d.change_type not in ('A', 'M'):
            continue
        path = d.b_path or d.a_path or ''
        if not isinstance(path, str) or not re.search(_ACTIONS_WORKFLOW_PATTERN, path):
            continue
        try:
            content = d.b_blob.data_stream.read().decode('utf-8', errors='replace')
        except Exception:
            continue
        seen: set = set()
        for line in content.splitlines():
            m = re.match(r'\s+(?:-\s+)?uses:\s+([^\s#\n]+)', line)
            if not m:
                continue
            raw = m.group(1).strip()
            if raw.startswith('./') or raw.startswith('/') or '@' not in raw:
                continue
            action, ref = raw.rsplit('@', 1)
            if _sha_re.match(ref) or raw in seen:
                continue
            seen.add(raw)
            warnings.append({'file': path, 'action': action, 'ref': ref})
    return warnings


def _load_runtime_events() -> list:
    """Load runtime events from the eBPF agent output file (advisory, no score impact)."""
    import json as _json
    import os as _os
    path = _os.environ.get("PG_RUNTIME_EVENTS_PATH", "pg-runtime-events.json")
    try:
        with open(path) as f:
            return [_json.loads(line) for line in f if line.strip()]
    except (FileNotFoundError, _json.JSONDecodeError):
        return []


# ==============================================================================
# OUTPUT
# ==============================================================================

def print_report(report):
    if "error" in report:
        print("\n" + "="*70)
        print("❌ ANALYSIS FAILED")
        print("="*70)
        print(f"\nError: {report['error']}")
        if "error_type" in report:
            print(f"Type: {report['error_type']}")
        if "available_branches" in report:
            print(f"\nAvailable branches: {', '.join(report['available_branches'][:5])}")
        print()
        return

    analysis  = report['analysis']
    files     = report['files']
    lines     = report['lines']
    temporal  = report['temporal']
    verdict   = report['verdict']
    deleted   = report['deleted_files']

    print("\n" + "="*70)
    print(f"PAYLOADGUARD ANALYSIS: {analysis['branch']} → {analysis['target']}")
    print("="*70)

    print(f"\n📅 TEMPORAL")
    print(f"   Branch age: {temporal['branch_age_days']} days")
    print(f"   Branch: {temporal['branch_commit_hash']} ({temporal['branch_last_commit'][:10]})")
    print(f"   Target: {temporal['target_commit_hash']} ({temporal['target_last_commit'][:10]})")

    print(f"\n📁 FILE CHANGES")
    print(f"   Added:    {files['added']:3d}")
    print(f"   Deleted:  {files['deleted']:3d}")
    print(f"   Modified: {files['modified']:3d}")
    print(f"   Total:    {files['total_changed']:3d}")

    print(f"\n📝 LINE CHANGES")
    print(f"   Added:    {lines['added']:>7,} lines")
    print(f"   Deleted:  {lines['deleted']:>7,} lines")
    print(f"   Net:      {lines['net_change']:>7,} lines")
    print(f"   Deletion ratio: {lines['deletion_ratio_percent']}%")

    if 'structural' in report:
        s = report['structural']
        print(f"\n🧬 STRUCTURAL DRIFT (Layer 4)")
        print(f"   Overall severity: {s['overall_severity']}")
        print(f"   Max deletion ratio: {s['max_deletion_ratio_pct']}%")
        for f in s['flagged_files']:
            m = f['metrics']
            print(f"   {f['file']}: {m['deleted_node_count']} nodes deleted ({m['structural_deletion_ratio']}%) [{f['severity']}]")
            for comp in f['deleted_components'][:5]:
                print(f"      - {comp}")

    complexity_advisory = report.get('complexity_advisory', [])
    if complexity_advisory:
        print(f"\n📐 COMPLEXITY ADVISORY ({len(complexity_advisory)} function(s) above threshold)")
        for ca in complexity_advisory[:10]:
            print(f"   {ca['file']}: {ca['name']}() — V(G)={ca['complexity']} (threshold: {ca['threshold']})")

    sca = report.get('sca', {})
    if sca.get('allowlist_active'):
        print(f"\n📦 SCA — DEPENDENCY SCAN: {sca['status']}")
        if sca['manifest_files_scanned']:
            print(f"   Manifests scanned: {', '.join(sca['manifest_files_scanned'])}")
        if sca['unverified_packages']:
            print(f"   Unverified packages ({len(sca['unverified_packages'])}):")
            for pkg in sca['unverified_packages'][:10]:
                print(f"      - {pkg['package']} ({pkg['manifest']})")

    if 'temporal_drift' in report:
        td = report['temporal_drift']
        print(f"\n⏱  TEMPORAL DRIFT (Layer 5a)")
        print(f"   Status: {td['status']} [{td['severity']}]")
        print(f"   Drift Score: {td['metrics']['calculated_drift_score']:.1f}")
        print(f"   Target velocity: {td['metrics']['target_velocity']} commits/day")
        print(f"   {td['recommendation']}")

    if 'semantic' in report:
        sem = report['semantic']
        print(f"\n🔎 SEMANTIC TRANSPARENCY (Layer 5b) — {sem['status']}")
        print(f"   MCI score: {sem.get('mci_score', 0.0):.3f}")
        if sem.get('signals'):
            print(f"   Signals:   {', '.join(sem['signals'])}")
        print(f"   {sem['directive']}")

    ap = report.get('actions_poisoning', {})
    if ap.get('total', 0) > 0:
        print(f"\n🎯  GITHUB ACTIONS POISONING (Layer 2c) — {ap['total']} workflow(s) flagged")
        for wf in ap.get('flagged_workflows', [])[:5]:
            sig_types = ', '.join(s['type'] for s in wf['signals'])
            print(f"   [{wf['severity']}] {wf['file']}: {sig_types}")

    commit_flags = report.get('commit_flags', [])
    if commit_flags:
        print(f"\n⚠️  COMMIT MESSAGE FLAGS ({len(commit_flags)} suspicious commit(s))")
        for cf in commit_flags[:5]:
            print(f"   [{cf['sha']}] {cf['message']}")

    print(f"\n🔍 VERDICT: {verdict['status']} [{verdict['severity']}]")
    for flag in verdict['flags']:
        print(f"   ⚠️  {flag}")

    print(f"\n✉️  RECOMMENDATION:")
    print(f"   {verdict['recommendation']}")

    if deleted['total'] > 0:
        print(f"\n🗑️  DELETED FILES ({deleted['total']} total)")
        if deleted['critical']:
            print(f"\n   CRITICAL DELETIONS:")
            for f in deleted['critical']:
                print(f"      - {f}")
        if deleted['all']:
            print(f"\n   OTHER DELETIONS:")
            for f in deleted['all'][:10]:
                print(f"      - {f}")
        if deleted['total'] > 30:
            remaining = deleted['total'] - len(deleted['all'])
            if remaining > 0:
                print(f"      ... and {remaining} more files")

    perm_changes = report.get('permission_changes', [])
    executable_changes = [p for p in perm_changes if p.get('made_executable')]
    if executable_changes:
        print(f"\n🔐 PERMISSION CHANGES ({len(executable_changes)} file(s) made executable)")
        for p in executable_changes[:5]:
            print(f"   {p['file']}  {p['from_mode']} → {p['to_mode']}")

    print("\n" + "="*70 + "\n")


def _md_escape(name: str) -> str:
    return name.replace('\\', '\\\\').replace('`', '\\`').replace('|', '\\|')


def format_markdown_report(report: dict) -> str:
    """Generate GitHub-flavoured markdown from a PayloadGuard report."""
    if "error" in report:
        return (
            "## ❌ PayloadGuard — Analysis Failed\n\n"
            f"`{report['error']}`\n"
        )

    analysis = report['analysis']
    files    = report['files']
    lines    = report['lines']
    temporal = report['temporal']
    verdict  = report['verdict']
    deleted  = report['deleted_files']

    verdict_emoji = {
        "SAFE":        "✅",
        "REVIEW":      "🔵",
        "CAUTION":     "⚠️",
        "DESTRUCTIVE": "🚨",
    }.get(verdict['status'], "❓")

    out = []
    out.append(f"## {verdict_emoji} PayloadGuard — `{verdict['status']}` [{verdict['severity']}]")
    out.append(f"\n> `{analysis['branch']}` → `{analysis['target']}`")
    out.append(f"\n**{verdict['recommendation']}**")
    out.append("")

    if verdict['flags']:
        for flag in verdict['flags']:
            out.append(f"- ⚠️ {flag}")
        out.append("")

    out.append("---")
    out.append("")

    # ── Temporal ──────────────────────────────────────────────────────────────
    age = temporal['branch_age_days']
    if age == 0:
        age_note = "Branch is current — created against this target, no staleness risk."
    elif age < 30:
        age_note = f"Branch is {age} days old — context is fresh."
    elif age < 90:
        age_note = f"Branch is {age} days old — approaching the review threshold (90 days)."
    elif age < 180:
        age_note = f"Branch is {age} days old — past the review threshold. Confirm context is still valid before merging."
    elif age < 365:
        age_note = f"Branch is {age} days old — significantly stale. Rebase strongly recommended."
    else:
        age_note = f"Branch is {age} days old — over a year. Mandatory rebase before merge."

    out.append("### 📅 Temporal")
    out.append("_Branch age and the commits being compared. A long-lived branch may have diverged significantly from what the target codebase now looks like._")
    out.append("")
    out.append("| | |")
    out.append("|---|---|")
    out.append(f"| Branch age | {age} days |")
    out.append(f"| Branch commit | `{temporal['branch_commit_hash']}` ({temporal['branch_last_commit'][:10]}) |")
    out.append(f"| Target commit | `{temporal['target_commit_hash']}` ({temporal['target_last_commit'][:10]}) |")
    out.append("")
    out.append(f"_{age_note}_")
    out.append("")

    # ── File Changes ──────────────────────────────────────────────────────────
    n_deleted = files['deleted']
    n_total   = files['total_changed']
    if n_total == 0:
        file_note = "No file changes detected in this diff."
    elif n_deleted == 0:
        file_note = f"{n_total} file(s) changed — no deletions."
    elif n_deleted > 50:
        file_note = f"**{n_deleted} files deleted** — massive scope (flag thresholds: >10 REVIEW · >20 CAUTION · >50 DESTRUCTIVE)."
    elif n_deleted > 20:
        file_note = f"**{n_deleted} files deleted** — large scope (flag thresholds: >10 REVIEW · >20 CAUTION · >50 DESTRUCTIVE)."
    elif n_deleted > 10:
        file_note = f"{n_deleted} files deleted — moderate removal (flag threshold: >10 REVIEW · >20 CAUTION · >50 DESTRUCTIVE)."
    else:
        file_note = f"{n_deleted} file(s) deleted — within normal range (flag threshold: >10)."

    out.append("### 📁 File Changes")
    out.append("_Raw scope of the change — how many files are being added, removed, or touched. Deletions are the number to watch._")
    out.append("")
    out.append("| Type | Count |")
    out.append("|---|---|")
    out.append(f"| Added | {files['added']} |")
    out.append(f"| Deleted | {n_deleted} |")
    out.append(f"| Modified | {files['modified']} |")
    out.append(f"| Total | {n_total} |")
    out.append("")
    out.append(f"_{file_note}_")
    out.append("")

    # ── Line Changes ──────────────────────────────────────────────────────────
    ratio = lines['deletion_ratio_percent']
    net   = lines['net_change']
    if lines['deleted'] == 0:
        ratio_note = "No lines deleted — no destructive churn detected."
    elif ratio < 50:
        ratio_note = f"{ratio}% of total churn is deletion — within normal range (flag threshold: >50%)."
    elif ratio < 70:
        ratio_note = f"**{ratio}% deletion ratio** — more than half of all churn is removal (threshold: >50% → REVIEW)."
    elif ratio < 90:
        ratio_note = f"**{ratio}% deletion ratio** — majority of changes are deletions (threshold: >70% → CAUTION)."
    else:
        ratio_note = f"**{ratio}% deletion ratio** — almost the entire changeset is deletions (threshold: >90% → DESTRUCTIVE)."

    out.append("### 📝 Line Changes")
    out.append("_Volume and direction of change. Deletion ratio — the fraction of total churn that is removal — is the key derived signal. Above 50% starts raising flags; above 90% means almost everything this PR touches is being taken away._")
    out.append("")
    out.append("| | |")
    out.append("|---|---|")
    out.append(f"| Added | {lines['added']:,} |")
    out.append(f"| Deleted | {lines['deleted']:,} |")
    out.append(f"| Net | {net:+,} |")
    out.append(f"| Deletion ratio | {ratio}% |")
    out.append("")
    out.append(f"_{ratio_note}_")
    out.append("")

    # ── Structural Drift ──────────────────────────────────────────────────────
    if 'structural' in report:
        s = report['structural']
        sev_emoji = "🚨" if s['overall_severity'] == 'CRITICAL' else "✅"
        if s['overall_severity'] == 'CRITICAL':
            struct_note = "Named structural components have been deleted at scale — review the list below carefully before merging."
        elif s['flagged_files']:
            struct_note = "Some structural changes detected but below the critical threshold — worth a manual look."
        else:
            struct_note = "No significant class, function, or constant deletions detected — file content is structurally intact."

        out.append("### 🧬 Structural Drift (Layer 4)")
        out.append("_Parses every modified source file and tracks exactly which named classes, functions, and constants disappeared. This catches a file being \"modified\" when it's actually been gutted — line diffs alone won't tell you that `AuthManager` no longer exists._")
        out.append("")
        out.append(
            f"**Severity:** {sev_emoji} `{s['overall_severity']}`"
            f"  |  **Max deletion ratio:** {s['max_deletion_ratio_pct']}%"
        )
        out.append("")
        if s['flagged_files']:
            out.append("| File | Nodes deleted | Ratio | Severity |")
            out.append("|---|---|---|---|")
            for ff in s['flagged_files']:
                m = ff['metrics']
                out.append(
                    f"| `{_md_escape(ff['file'])}` | {m['deleted_node_count']} |"
                    f" {m['structural_deletion_ratio']}% | {ff['severity']} |"
                )
            for ff in s['flagged_files']:
                if ff['severity'] == 'CRITICAL' and ff['deleted_components']:
                    out.append(f"\n**Deleted from `{_md_escape(ff['file'])}`:**")
                    for comp in ff['deleted_components'][:10]:
                        out.append(f"- `{comp}`")
            out.append("")
        out.append(f"_{struct_note}_")
        out.append("")

    # ── Complexity Advisory ───────────────────────────────────────────────────
    complexity_advisory = report.get('complexity_advisory', [])
    if complexity_advisory:
        out.append("### 📐 Complexity Advisory")
        out.append("_Newly added Python functions with McCabe cyclomatic complexity above the configured threshold (default V(G) > 15). Advisory only — no score impact. High complexity functions are harder to test and maintain._")
        out.append("")
        out.append("| File | Function | V(G) | Threshold |")
        out.append("|---|---|---|---|")
        for ca in complexity_advisory[:10]:
            out.append(f"| `{_md_escape(ca['file'])}` | `{ca['name']}` | {ca['complexity']} | {ca['threshold']} |")
        out.append("")

    # ── SCA ───────────────────────────────────────────────────────────────────
    sca = report.get('sca', {})
    if sca.get('allowlist_active'):
        sca_emoji = "🚨" if sca['status'] == 'FLAGGED' else "✅"
        out.append("### 📦 SCA — Dependency Scan (Layer 2b)")
        out.append("_Scans manifest file changes (requirements.txt, package.json, go.mod, Cargo.toml, pyproject.toml) for packages not in `allowlist.yml`. Only active when `allowlist.yml` is present in the repo root._")
        out.append("")
        out.append(f"**Status:** {sca_emoji} `{sca['status']}`")
        if sca['manifest_files_scanned']:
            out.append(f"  \n**Manifests scanned:** {', '.join(f'`{_md_escape(m)}`' for m in sca['manifest_files_scanned'])}")
        if sca['unverified_packages']:
            out.append("")
            out.append("| Package | Manifest | Type |")
            out.append("|---|---|---|")
            for pkg in sca['unverified_packages'][:20]:
                out.append(f"| `{_md_escape(pkg['package'])}` | `{_md_escape(pkg['manifest'])}` | {pkg['manifest_type']} |")
        out.append("")

    # ── Temporal Drift ────────────────────────────────────────────────────────
    if 'temporal_drift' in report:
        td = report['temporal_drift']
        m  = td['metrics']
        td_emoji = {"CRITICAL": "🚨", "WARNING": "⚠️"}.get(td['severity'], "✅")
        out.append("### ⏱ Temporal Drift (Layer 5a)")
        out.append("_Compound staleness score: `branch_age_days × target_commits/day`. Raw age alone is a weak signal — a 90-day branch on a slow repo is nothing; on a fast-moving repo it represents a serious semantic gap between what the branch was written against and what main looks like today._")
        out.append("")
        out.append(f"**Status:** {td_emoji} `{td['status']}`")
        out.append("")
        out.append("| | |")
        out.append("|---|---|")
        out.append(f"| Drift score | {m['calculated_drift_score']:.1f} _(CURRENT <250 · STALE 250–1,000 · DANGEROUS ≥1,000)_ |")
        out.append(f"| Target velocity | {m['target_velocity']} commits/day |")
        out.append("")
        out.append(f"> {td['recommendation']}")
        out.append("")

    # ── Semantic Transparency ─────────────────────────────────────────────────
    if 'semantic' in report:
        sem = report['semantic']
        sem_emoji = {"DECEPTIVE_PAYLOAD": "🚨", "CAUTION_MISMATCH": "⚠️", "UNVERIFIED": "⚠️"}.get(sem['status'], "✅")
        out.append("### 🔎 Semantic Transparency (Layer 5b)")
        out.append("_Compares the PR description against the verified severity. If the description uses low-impact language but the diff says otherwise, that's a deceptive payload pattern — the pattern at the centre of the April 2026 incident._")
        out.append("")
        out.append(f"**Status:** {sem_emoji} `{sem['status']}` &nbsp; **MCI score:** `{sem.get('mci_score', 0.0):.3f}`")
        if sem.get('signals'):
            out.append(f"  \n**Signals:** {', '.join(f'`{s}`' for s in sem['signals'])}")
        out.append(f"\n> {sem['directive']}")
        out.append("")

    # ── Commit Message Flags ──────────────────────────────────────────────────
    commit_flags = report.get('commit_flags', [])
    if commit_flags:
        out.append("### ⚠️ Commit Message Flags")
        out.append("_Commit messages between the merge base and branch tip were checked for red-flag language (disable auth, remove all tests, bypass security, etc.)._")
        out.append("")
        out.append(f"**{len(commit_flags)} commit(s) matched red-flag patterns:**")
        out.append("")
        out.append("| SHA | Message |")
        out.append("|---|---|")
        for cf in commit_flags[:10]:
            out.append(f"| `{cf['sha']}` | {_md_escape(cf['message'])} |")
        out.append("")

    # ── Added File Content Flags ──────────────────────────────────────────────
    content_flags = report.get('content_flags', [])
    if content_flags:
        out.append("### 🔬 Added File Content Scan")
        out.append("_Added non-code files scanned for CI trigger strings and shell execution patterns._")
        out.append("")
        out.append("| File | CI Triggers | Shell Patterns |")
        out.append("|---|---|---|")
        for cf in content_flags:
            ci_cell = f"{len(cf['ci_triggers'])} match(es)" if cf['ci_triggers'] else "—"
            sh_cell = f"{len(cf['shell_patterns'])} match(es)" if cf['shell_patterns'] else "—"
            out.append(f"| `{_md_escape(cf['file'])}` | {ci_cell} | {sh_cell} |")
        out.append("")

    # ── GitHub Actions Poisoning ──────────────────────────────────────────────
    ap = report.get('actions_poisoning', {})
    if ap.get('total', 0) > 0:
        ap_emoji = "🚨" if any(
            wf['severity'] == 'CRITICAL' for wf in ap.get('flagged_workflows', [])
        ) else "⚠️"
        out.append("### 🎯 GitHub Actions Poisoning (Layer 2c)")
        out.append(
            "_Scans added and modified `.github/workflows/` and `.github/actions/` files for "
            "poisoning signals: base64-encoded payload delivery, credential harvesting "
            "(env dumps, metadata endpoint probing), dormant triggers with embedded shell "
            "execution, forged bot commit identity, and elevated OIDC permissions without "
            "a legitimate cloud consumer._"
        )
        out.append("")
        out.append(f"**{ap_emoji} {ap['total']} workflow(s) flagged**")
        out.append("")
        out.append("| File | Signal types | Severity |")
        out.append("|---|---|---|")
        for wf in ap.get('flagged_workflows', []):
            sig_types = ', '.join(f"`{s['type']}`" for s in wf['signals'])
            sev_emoji = "🚨" if wf['severity'] == 'CRITICAL' else "⚠️"
            out.append(
                f"| `{_md_escape(wf['file'])}` | {sig_types} | {sev_emoji} {wf['severity']} |"
            )
        out.append("")

    # ── Deleted Files ─────────────────────────────────────────────────────────
    if deleted['total'] > 0:
        out.append(f"### 🗑️ Deleted Files ({deleted['total']} total)")
        out.append("")
        if deleted['critical']:
            out.append("**Critical deletions** _(matched high-value path patterns — tests, CI, auth, schema, entry points):_")
            for f in deleted['critical']:
                out.append(f"- `{_md_escape(f)}`")
            out.append("")
        other = [f for f in deleted['all'] if f not in deleted['critical']]
        if other:
            out.append("<details><summary>Other deletions</summary>")
            out.append("")
            for f in other[:20]:
                out.append(f"- `{_md_escape(f)}`")
            if deleted['total'] > 30:
                out.append(f"\n_...and {deleted['total'] - 30} more_")
            out.append("")
            out.append("</details>")
            out.append("")

    out.append("---")
    raw_ts = report.get('timestamp', '')
    ts = raw_ts[:19].replace('T', ' ') + (' UTC' if '+' not in raw_ts and 'Z' not in raw_ts else '')
    out.append(f"_PayloadGuard scan — {ts}_")

    return "\n".join(out)


def save_json_report(report, filename="consequence_report.json"):
    try:
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"✓ Report saved to {filename}")
    except Exception as e:
        print(f"⚠️  Could not save JSON report: {e}")


def save_markdown_report(report, filename="payloadguard-report.md"):
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(format_markdown_report(report))
        print(f"✓ Markdown report saved to {filename}")
    except Exception as e:
        print(f"⚠️  Could not save markdown report: {e}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        prog="payloadguard",
        description="Detect destructive payloads hidden in code suggestions before merge.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            examples:
              python analyze.py . feature-branch main
              python analyze.py . feature-branch main --pr-description "minor syntax fix"
              python analyze.py . feature-branch main --save-json
              python analyze.py . feature-branch main --save-json reports/scan.json

            exit codes:
              0  safe or review
              1  analysis error
              2  destructive — block merge in CI
        """),
    )
    parser.add_argument("repo_path", help="Path to the git repository")
    parser.add_argument("branch",    help="Feature branch to analyse")
    parser.add_argument("target",    nargs="?", default="main",
                        help="Target branch (default: main)")
    parser.add_argument("--pr-description", default="", metavar="TEXT",
                        help="PR description for semantic transparency analysis")
    parser.add_argument("--save-json", nargs="?", const="consequence_report.json",
                        metavar="FILE",
                        help="Save JSON report (default filename: consequence_report.json)")
    parser.add_argument("--save-markdown", nargs="?", const="payloadguard-report.md",
                        metavar="FILE",
                        help="Save GitHub-flavoured markdown report (default: payloadguard-report.md)")

    args = parser.parse_args()

    config   = load_config(args.repo_path)
    analyzer = PayloadAnalyzer(args.repo_path, args.branch, args.target, config=config)
    report   = analyzer.analyze(pr_description=args.pr_description)
    print_report(report)

    if args.save_json:
        save_json_report(report, args.save_json)

    if args.save_markdown:
        save_markdown_report(report, args.save_markdown)

    if "error" in report:
        sys.exit(1)
    elif report.get("verdict", {}).get("status") == "DESTRUCTIVE":
        sys.exit(2)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
    
