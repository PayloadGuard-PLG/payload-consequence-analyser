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

import ast
import bisect
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

# Source-code extensions with no registered structural parser. Changes to these
# files reach D01 as UNSUPPORTED_EXTENSION instead of being skipped, so they are
# never reported as fully analysed. Data, configuration and markup formats are
# excluded; SQL migrations are covered by D10.
_UNPARSED_SOURCE_EXTS = frozenset({
    ".c", ".h", ".cc", ".cpp", ".cxx", ".hh", ".hpp", ".hxx",
    ".cs", ".vb", ".fs", ".fsx",
    ".kt", ".kts", ".scala", ".groovy", ".clj", ".cljs",
    ".swift", ".m", ".mm", ".dart",
    ".rb", ".php", ".pl", ".pm", ".lua", ".r", ".jl",
    ".ex", ".exs", ".erl", ".hs", ".ml", ".nim", ".zig", ".sol",
    ".vue", ".svelte",
    ".pyi", ".pyx",
    ".sh", ".bash", ".zsh", ".ps1",
})


def _needs_structural_parse(file_path: str) -> bool:
    """True for files with a structural parser and for source code that lacks one."""
    return language_for_path(file_path) is not None or Path(file_path).suffix.lower() in _UNPARSED_SOURCE_EXTS

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


# Migration & Persistence Patterns for D10
# ---------------------------------------------------------------------------
# D10 analyses FORWARD migration code only. Rollback code (Alembic downgrade(),
# Knex/TypeORM/Sequelize down(), Rails `def down`, goose/sql-migrate/dbmate Down
# sections, *.down.sql / Flyway undo files) legitimately drops what the forward
# migration created and must never be reported as data loss.
_MIGRATION_DIR_TOKENS = frozenset({"migrations", "migration", "migrate", "flyway", "liquibase"})
_MIGRATION_EXCLUDED_DIRS = frozenset({
    "test", "tests", "__tests__", "spec", "specs", "testdata", "test_data",
    "seed", "seeds", "seeders", "seeding", "fixture", "fixtures",
    "example", "examples", "sample", "samples", "doc", "docs",
    "node_modules", "vendor", "third_party", "site-packages",
})
_MIGRATION_EXTS = (".sql", ".py", ".rb", ".js", ".mjs", ".cjs", ".ts")
_FLYWAY_VERSIONED_RE = re.compile(r"^v\d+(?:[._]\d+)*__.+\.sql$", re.IGNORECASE)
_ROLLBACK_SQL_FILE_RE = re.compile(
    r"(?:^|[._-])(?:down|rollback|undo)\.sql$|^u\d+(?:[._]\d+)*__.+\.sql$",
    re.IGNORECASE,
)
_UP_SQL_FILE_RE = re.compile(r"(?:^|[._-])up\.sql$", re.IGNORECASE)
_TEMP_TABLE_PREFIXES = ("temp_", "tmp_", "staging_", "_scratch", "temporary")

# Comment / string tokenisers per migration language. Comments are blanked
# (replaced by spaces, newlines kept) so offsets and line numbers stay aligned;
# string literals are kept because migrations embed SQL in strings.
_COMMENT_STRING_RES: Dict[str, "re.Pattern[str]"] = {
    "sql": re.compile(
        r"(?P<c>--[^\n]*|/\*.*?(?:\*/|\Z))|(?P<s>'(?:[^']|'')*'|\"[^\"]*\"|`[^`]*`)",
        re.S,
    ),
    "js": re.compile(
        r"(?P<c>//[^\n]*|/\*.*?(?:\*/|\Z))"
        r"|(?P<s>'(?:\\.|[^'\\\n])*'|\"(?:\\.|[^\"\\\n])*\"|`(?:\\.|[^`\\])*`)",
        re.S,
    ),
    "py": re.compile(
        r"(?P<c>#[^\n]*)"
        r"|(?P<s>'''(?:\\.|[^\\])*?'''|\"\"\"(?:\\.|[^\\])*?\"\"\"|'(?:\\.|[^'\\\n])*'|\"(?:\\.|[^\"\\\n])*\")",
        re.S,
    ),
    "rb": re.compile(
        r"(?P<c>^=begin\b.*?^=end\b[^\n]*|#[^\n]*)|(?P<s>'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\")",
        re.S | re.M,
    ),
}

# SQL statement grammar (statement-level, whitespace/newline tolerant)
_SQL_IDENT_PART = r'(?:\\?"[^"\n\\]+\\?"|`[^`\n]+`|\[[^\]\n]+\]|[A-Za-z_][\w$]*)'
_SQL_IDENT = _SQL_IDENT_PART + r"(?:[ \t]*\.[ \t]*" + _SQL_IDENT_PART + r")*"
_SQL_IDENT_RE = re.compile(_SQL_IDENT)
# Non-literal table names: f-strings, ${}, #{}, %s, ?, or string concatenation
_SQL_DYNAMIC_RE = re.compile(
    r"(?:\{[^}\n]*\}|\$\{[^}\n]*\}|#\{[^}\n]*\}|%\(\w+\)s|%s|\?"
    r"|\\?[\"'`][ \t]*(?:\+|\|\||\.\.|%|\.format\b)|\+[ \t]*\w)"
)
_SQL_LIST_SEP_RE = re.compile(r"[ \t]*,[ \t]*")
# A literal target must be followed by a statement/string boundary. This rejects
# English prose such as "truncate long names" inside log strings.
_SQL_TERMINATOR_RE = re.compile(
    r"[ \t]*(?:;|\)|\\?[\"'`]|\r?\n|$|,|(?:CASCADE|RESTRICT|PURGE|RESTART|CONTINUE)\b)",
    re.IGNORECASE,
)
_SQL_DROP_TABLE_HEAD_RE = re.compile(r"\bDROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?", re.IGNORECASE)
_SQL_DROP_COLUMN_HEAD_RE = re.compile(r"\bDROP\s+COLUMN\s+(?:IF\s+EXISTS\s+)?", re.IGNORECASE)
_SQL_TRUNCATE_HEAD_RE = re.compile(r"\bTRUNCATE\s+(?:TABLE\s+)?(?:ONLY\s+)?", re.IGNORECASE)
_SQL_DROP_DB_HEAD_RE = re.compile(r"\bDROP\s+(?:DATABASE|SCHEMA)\s+(?:IF\s+EXISTS\s+)?", re.IGNORECASE)
_SQL_ALTER_TABLE_RE = re.compile(
    r"\bALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?(" + _SQL_IDENT + r")", re.IGNORECASE
)
# `ALTER TABLE t DROP col` (COLUMN keyword omitted; valid in PostgreSQL/MySQL)
_SQL_ALTER_DROP_IMPLICIT_RE = re.compile(
    r"\bALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?(" + _SQL_IDENT + r")\s+DROP\s+"
    r"(?!(?:COLUMN|CONSTRAINT|INDEX|KEY|PRIMARY|FOREIGN|CHECK|DEFAULT|NOT|IDENTITY|EXPRESSION"
    r"|PARTITION|UNIQUE|PERIOD|SYSTEM|FULLTEXT|SPATIAL|IF|TRIGGER|ROW|OIDS)\b)",
    re.IGNORECASE,
)
_SQL_SECTION_MARKER_RE = re.compile(
    r"^[ \t]*--[ \t]*(?:\+goose[ \t]+(up|down)|\+migrate[ \t]+(up|down)|migrate:(up|down))\b",
    re.IGNORECASE | re.MULTILINE,
)

# ORM / DSL drop operations
_ALEMBIC_DROP_TABLE_RE = re.compile(r"\bop\.drop_table\(\s*(?:table_name\s*=\s*)?[\"']([\w.]+)[\"']")
_ALEMBIC_DROP_COLUMN_RE = re.compile(
    r"\bop\.drop_column\(\s*(?:table_name\s*=\s*)?[\"']([\w.]+)[\"']\s*,\s*(?:column_name\s*=\s*)?[\"'](\w+)[\"']"
)
_ALEMBIC_BATCH_TABLE_RE = re.compile(r"\bop\.batch_alter_table\(\s*(?:table_name\s*=\s*)?[\"']([\w.]+)[\"']")
_ALEMBIC_BATCH_DROP_COLUMN_RE = re.compile(
    r"\b(?!op\.)[A-Za-z_]\w*\.drop_column\(\s*(?:column_name\s*=\s*)?[\"'](\w+)[\"']\s*[,)]"
)
_DJANGO_DELETE_MODEL_RE = re.compile(r"\b(?:migrations\.)?DeleteModel\(\s*(?:name\s*=\s*)?[\"'](\w+)[\"']")
_DJANGO_REMOVE_FIELD_RE = re.compile(r"\b(?:migrations\.)?RemoveField\(")
_JS_DROP_TABLE_CALL_RE = re.compile(r"\.dropTable(?:IfExists)?\(\s*[\"'`]([\w.]+)[\"'`]")
_JS_DROP_COLUMN_CALL_RE = re.compile(r"\b([\w$]+)\.(dropColumns?|removeColumn)\(")
_JS_TABLE_CONTEXT_RE = re.compile(r"\.(?:alterTable|table)\(\s*[\"'`]([\w.]+)[\"'`]")
_JS_STR_ARG_RE = re.compile(r"[\"'`]([\w.]+)[\"'`]")
_JS_FN_HEADER_TEMPLATES = (
    r"\b(?:module\.)?exports\.{n}\s*=\s*",
    r"(?<![.\w$]){n}\s*:\s*",
    r"\bexport\s+(?:const|let|var)\s+{n}\b\s*(?::[^=\n]+)?=\s*",
    r"\bexport\s+(?:default\s+)?(?:async\s+)?function\s+{n}\b\s*",
    r"(?<![.\w$])(?:(?:public|private|protected|static|override)\s+)*(?:async\s+)?{n}\s*(?=\()",
)
_RB_DEF_RE = re.compile(r"^([ \t]*)def[ \t]+(?:self\.)?(up|down|change)\b([^\n]*)$", re.MULTILINE)
_RB_DROP_TABLE_RE = re.compile(r"(?<![.\w])drop_table\s*\(?\s*[:\"']?(\w+)[\"']?")
_RB_REMOVE_COLUMN_RE = re.compile(
    r"(?<![.\w])remove_column\s*\(?\s*[:\"']?(\w+)[\"']?\s*,\s*[:\"']?(\w+)[\"']?"
)
_RB_REMOVE_COLUMNS_RE = re.compile(r"(?<![.\w])remove_columns\s*\(?\s*[:\"']?(\w+)[\"']?\s*,([^\n]*)")

# D08: workflow_run as an actual trigger (not merely a `github.event.workflow_run.*` expression)
_WORKFLOW_RUN_TRIGGER_RE = re.compile(
    r"^\s*(?:on\s*:\s*(?:\[[^\]\n]*\bworkflow_run\b|workflow_run\b)|workflow_run\s*:|-\s*workflow_run\s*$)",
    re.MULTILINE,
)
# D08: GitHub-owned action namespaces excluded from ACTION_PIN_UNPINNED (third-party only).
_GITHUB_OWNED_ACTION_OWNERS = frozenset({"actions", "github"})


def _is_migration_file(file_path: str) -> bool:
    """Return True if file_path is a forward database migration.

    Requires a recognised migration directory (migrations/, migration/, migrate/,
    flyway/, liquibase/, alembic/.../versions/) or a Flyway versioned filename
    (V<n>__*.sql). Seed, fixture, sample, docs, vendored and test directories are
    excluded, as are rollback-only SQL files (*.down.sql, *.rollback.sql, Flyway
    U<n>__ undo scripts).
    """
    norm = file_path.replace("\\", "/").lower()
    parts = [p for p in norm.split("/") if p]
    if not parts:
        return False
    bname, dirs = parts[-1], parts[:-1]
    if not bname.endswith(_MIGRATION_EXTS) or bname.endswith(".d.ts"):
        return False
    if any(d in _MIGRATION_EXCLUDED_DIRS for d in dirs) or bname.startswith("seed"):
        return False
    if bname.endswith(".sql") and _ROLLBACK_SQL_FILE_RE.search(bname):
        return False
    if any(d in _MIGRATION_DIR_TOKENS for d in dirs):
        return True
    if "alembic" in dirs and "versions" in dirs:
        return True
    return bool(_FLYWAY_VERSIONED_RE.match(bname))


def _migration_language(file_path: str) -> Optional[str]:
    low = file_path.lower()
    if low.endswith(".sql"):
        return "sql"
    if low.endswith(".py"):
        return "py"
    if low.endswith(".rb"):
        return "rb"
    if low.endswith((".js", ".mjs", ".cjs", ".ts")):
        return "js"
    return None


def _is_temp_table_entity(entity: str, kind: str) -> bool:
    """True when the dropped/truncated TABLE is a temporary/staging table.

    Column names are never treated as temporary (`sensors.temp_celsius` is real data).
    """
    if entity == "<dynamic>":
        return False
    parts = entity.lower().split(".")
    if kind == "column":
        if len(parts) < 2:
            return False
        table = parts[-2]
    else:
        table = parts[-1]
    return table.startswith(_TEMP_TABLE_PREFIXES)


def _blank_spans(text: str, spans: List[Tuple[int, int]]) -> str:
    if not spans:
        return text
    out: List[str] = []
    last = 0
    for s, e in sorted(spans):
        s = max(s, last)
        if s >= e:
            continue
        out.append(text[last:s])
        out.append(re.sub(r"[^\n]", " ", text[s:e]))
        last = e
    out.append(text[last:])
    return "".join(out)


def _blank_comments(text: str, lang: Optional[str]) -> str:
    """Replace comments with spaces (quote-aware, offsets preserved)."""
    rx = _COMMENT_STRING_RES.get(lang or "")
    if rx is None or not text:
        return text
    spans = [m.span() for m in rx.finditer(text) if m.group("c") is not None]
    return _blank_spans(text, spans)


def _line_starts(text: str) -> List[int]:
    return [0] + [m.end() for m in re.finditer("\n", text)]


def _line_of(starts: List[int], offset: int) -> int:
    return bisect.bisect_right(starts, offset)


def _balanced_end(text: str, open_idx: int, limit: int = 200_000) -> int:
    """Index just past the bracket matching text[open_idx] (quote-aware); bounded scan."""
    pairs = {"(": ")", "[": "]", "{": "}"}
    stack = [pairs[text[open_idx]]]
    i, n, quote = open_idx + 1, min(len(text), open_idx + limit), None
    while i < n:
        ch = text[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in "'\"`":
            quote = ch
        elif ch in pairs:
            stack.append(pairs[ch])
        elif ch in ")]}":
            if ch != stack[-1]:
                return i + 1
            stack.pop()
            if not stack:
                return i + 1
        i += 1
    return n


def _mk_mig_event(kind: str, entity: str, offset: int, dynamic: bool = False,
                  irrev: Optional[str] = None, src: str = "orm") -> Dict[str, Any]:
    return {"kind": kind, "entity": entity, "offset": offset, "dynamic": dynamic, "irrev": irrev, "src": src}


def _sql_norm_ident(raw: str) -> str:
    return re.sub(r'[\\"`\[\]\s]', "", raw)


def _sql_parse_targets(text: str, pos: int, allow_list: bool) -> Optional[Tuple[List[str], bool]]:
    """Parse the target identifier(s) of a destructive SQL statement at `pos`.

    Returns (names, is_dynamic) or None when the text is not a well-formed target.
    """
    if _SQL_DYNAMIC_RE.match(text, pos):
        return ["<dynamic>"], True
    names: List[str] = []
    p = pos
    while True:
        m = _SQL_IDENT_RE.match(text, p)
        if not m:
            break
        names.append(_sql_norm_ident(m.group(0)))
        p = m.end()
        if not allow_list:
            break
        sep = _SQL_LIST_SEP_RE.match(text, p)
        if sep and _SQL_IDENT_RE.match(text, sep.end()) and not _SQL_DYNAMIC_RE.match(text, sep.end()):
            p = sep.end()
            continue
        break
    if not names:
        return None
    if _SQL_DYNAMIC_RE.match(text, p):  # e.g. "DROP TABLE prefix_" + name
        return ["<dynamic>"], True
    if not _SQL_TERMINATOR_RE.match(text, p):
        return None
    return names, False


def _sql_alter_table_before(text: str, pos: int) -> Optional[str]:
    seg = text[max(0, pos - 2000):pos]
    semi = seg.rfind(";")
    if semi != -1:
        seg = seg[semi + 1:]
    last = None
    for m in _SQL_ALTER_TABLE_RE.finditer(seg):
        last = m
    return _sql_norm_ident(last.group(1)) if last else None


def _extract_sql_events(text: str) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    heads = (
        (_SQL_DROP_TABLE_HEAD_RE, "table", True),
        (_SQL_TRUNCATE_HEAD_RE, "truncate", True),
        (_SQL_DROP_DB_HEAD_RE, "dropdb", False),
        (_SQL_DROP_COLUMN_HEAD_RE, "column", False),
    )
    for head_re, kind, allow_list in heads:
        for m in head_re.finditer(text):
            parsed = _sql_parse_targets(text, m.end(), allow_list)
            if not parsed:
                continue
            names, dyn = parsed
            for nm in names:
                ent = nm
                if kind == "column" and not dyn:
                    tbl = _sql_alter_table_before(text, m.start())
                    if tbl:
                        ent = f"{tbl}.{nm}"
                events.append(_mk_mig_event(kind, ent, m.start(), dyn, src="sql"))
    for m in _SQL_ALTER_DROP_IMPLICIT_RE.finditer(text):
        parsed = _sql_parse_targets(text, m.end(), False)
        if not parsed:
            continue
        names, dyn = parsed
        tbl = _sql_norm_ident(m.group(1))
        for nm in names:
            events.append(_mk_mig_event("column", nm if dyn else f"{tbl}.{nm}", m.start(), dyn, src="sql"))
    return events


def _py_body_trivial(body: List[Any]) -> bool:
    """True if a Python function body cannot restore anything (pass/.../docstring/return None/raise)."""
    stmts = list(body)
    if stmts and isinstance(stmts[0], ast.Expr) and isinstance(getattr(stmts[0], "value", None), ast.Constant) \
            and isinstance(stmts[0].value.value, str):
        stmts = stmts[1:]
    if any(isinstance(s, ast.Raise) for s in stmts):
        return True
    for s in stmts:
        if isinstance(s, ast.Pass):
            continue
        if isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant):
            continue
        if isinstance(s, ast.Return) and (s.value is None or (isinstance(s.value, ast.Constant) and s.value.value is None)):
            continue
        return False
    return True


def _py_call_name(func: Any) -> str:
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return ""


def _py_is_noop_reverse(node: Any) -> bool:
    if isinstance(node, ast.Attribute) and node.attr == "noop":
        return True
    return isinstance(node, ast.Constant) and node.value in (None, "", [])


def _py_migration_structure(
    src: str, blanked: str
) -> Tuple[str, List[Tuple[int, int]], Optional[str], List[Tuple[int, int, str]]]:
    """Return (blanked_text, rollback_spans, irreversible_reason, irreversible_spans) for Python migrations."""
    starts = _line_starts(src)

    def line_span(first: int, last: int) -> Tuple[int, int]:
        return starts[first - 1], (starts[last] if last < len(starts) else len(src))

    rollback: List[Tuple[int, int]] = []
    irrev_spans: List[Tuple[int, int, str]] = []
    reason: Optional[str] = None
    try:
        tree = ast.parse(src)
    except (SyntaxError, ValueError):
        tree = None

    if tree is None:
        for m in re.finditer(r"^(?:async[ \t]+)?def[ \t]+(?:downgrade|down)[ \t]*\(", blanked, re.MULTILINE):
            nxt = re.compile(r"^\S", re.MULTILINE).search(blanked, m.end())
            rollback.append((m.start(), nxt.start() if nxt else len(blanked)))
        return blanked, rollback, None, irrev_spans

    # Blank bare string statements (docstrings) so prose like "drop table users" is not parsed as SQL.
    doc_spans: List[Tuple[int, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            first_line = src[starts[node.lineno - 1]:].lstrip()
            if re.match(r"(?i)[rbuf]{0,2}[\"']", first_line):
                doc_spans.append(line_span(node.lineno, node.end_lineno or node.lineno))
    blanked = _blank_spans(blanked, doc_spans)

    funcs: Dict[str, Any] = {}
    containers = [tree.body] + [n.body for n in tree.body if isinstance(n, ast.ClassDef)]
    for body in containers:
        for n in body:
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name in ("upgrade", "downgrade", "up", "down"):
                funcs.setdefault(n.name, n)
    for nm in ("downgrade", "down"):
        fn = funcs.get(nm)
        if fn is not None:
            first = min([fn.lineno] + [d.lineno for d in fn.decorator_list])
            rollback.append(line_span(first, fn.end_lineno or fn.lineno))

    module_fns = {n.name for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    if module_fns & {"upgrade", "up"}:
        down_fn = funcs.get("downgrade") or funcs.get("down")
        if down_fn is None:
            reason = "no downgrade() rollback function is defined"
        elif _py_body_trivial(down_fn.body):
            reason = f"{down_fn.name}() is empty or raises instead of restoring the schema"

    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _py_call_name(node.func) == "RunSQL":
            rev = next((kw.value for kw in node.keywords if kw.arg == "reverse_sql"), None)
            if rev is None and len(node.args) >= 2:
                rev = node.args[1]
            if rev is None or _py_is_noop_reverse(rev):
                s, e = line_span(node.lineno, node.end_lineno or node.lineno)
                irrev_spans.append((s, e, "RunSQL has no reverse_sql, so Django cannot roll it back"))
    return blanked, rollback, reason, irrev_spans


def _js_expr_end(text: str, p: int) -> int:
    i, n, depth, quote = p, len(text), 0, None
    while i < n:
        ch = text[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in "'\"`":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                return i
            depth -= 1
        elif depth == 0 and ch in ";,":
            return i
        elif depth == 0 and ch == "\n":
            j = i + 1
            while j < n and text[j] in " \t\r\n":
                j += 1
            if j < n and text[j] in ".?":
                i = j
                continue
            return i
        i += 1
    return n


def _js_parse_function_at(text: str, p: int) -> Optional[Tuple[int, str, bool]]:
    """Parse a function/arrow/method starting at p. Returns (end, body_text, is_expression)."""
    n = len(text)
    m = re.compile(r"\s*(?:async\b\s*)?(?:function\b\s*\*?\s*[\w$]*\s*)?").match(text, p)
    p = m.end() if m else p
    ident_param = False
    if p < n and text[p] == "(":
        p = _balanced_end(text, p)
    else:
        mi = re.compile(r"[\w$]+").match(text, p)
        if not mi:
            return None
        p, ident_param = mi.end(), True
    while p < n and text[p] in " \t\r\n":
        p += 1
    if p < n and text[p] == ":":  # TypeScript return type annotation
        mt = re.compile(r"=>|\{").search(text, p)
        if not mt:
            return None
        p = mt.start()
    if text.startswith("=>", p):
        p += 2
        while p < n and text[p] in " \t\r\n":
            p += 1
        if p < n and text[p] == "{":
            end = _balanced_end(text, p)
            return end, text[p + 1:end - 1], False
        end = _js_expr_end(text, p)
        return end, text[p:end], True
    if ident_param:
        return None
    if p < n and text[p] == "{":
        end = _balanced_end(text, p)
        return end, text[p + 1:end - 1], False
    return None


def _js_function_spans(text: str, name: str) -> List[Tuple[int, int, str, bool]]:
    found: Dict[int, Tuple[int, int, str, bool]] = {}
    for tmpl in _JS_FN_HEADER_TEMPLATES:
        for m in re.finditer(tmpl.replace("{n}", name), text):
            res = _js_parse_function_at(text, m.end())
            if res:
                end, body, is_expr = res
                found.setdefault(end, (m.start(), end, body, is_expr))
    return sorted(found.values())


def _js_body_trivial(body: str, is_expr: bool) -> bool:
    b = body.strip()
    if re.match(r"^(?:return\s+)?(?:Promise\.reject\s*\(|throw\b)", b):
        return True
    if is_expr:
        return bool(re.fullmatch(r"\{\s*\}|null|undefined|Promise\.resolve\(\s*\)|", b))
    b = re.sub(r"\breturn\s*(?:Promise\.resolve\(\s*\)|null|undefined|\{\s*\})?\s*;?", "", b)
    return not re.sub(r"[\s;]", "", b)


def _js_migration_structure(text: str) -> Tuple[List[Tuple[int, int]], Optional[str]]:
    downs = _js_function_spans(text, "down")
    rollback = [(s, e) for s, e, _, _ in downs]
    reason: Optional[str] = None
    if _js_function_spans(text, "up"):
        if not downs:
            reason = "no down() rollback is defined"
        elif all(_js_body_trivial(body, is_expr) for _, _, body, is_expr in downs):
            reason = "down() is empty or throws instead of restoring the schema"
    return rollback, reason


def _rb_migration_structure(text: str) -> Tuple[List[Tuple[int, int]], Optional[str], Optional[Tuple[int, int]]]:
    defs: Dict[str, Tuple[int, int, str]] = {}
    for m in _RB_DEF_RE.finditer(text):
        indent, name, rest = m.group(1), m.group(2), m.group(3)
        if re.search(r";\s*end\s*$", rest):  # one-liner `def down; end`
            defs.setdefault(name, (m.start(), m.end(), rest.rsplit("end", 1)[0]))
            continue
        me = re.compile(r"^" + re.escape(indent) + r"end\b[^\n]*$", re.MULTILINE).search(text, m.end())
        end = me.end() if me else len(text)
        defs.setdefault(name, (m.start(), end, text[m.end():me.start() if me else len(text)]))
    rollback = [defs["down"][:2]] if "down" in defs else []
    reason: Optional[str] = None
    if "down" in defs:
        body = defs["down"][2]
        if "IrreversibleMigration" in body or not re.sub(r"[\s;]", "", body):
            reason = "`down` raises ActiveRecord::IrreversibleMigration or is empty"
    elif "up" in defs and "change" not in defs:
        reason = "only `up` is defined, so the migration cannot be rolled back"
    change_span = defs["change"][:2] if "change" in defs else None
    return rollback, reason, change_span


def _sql_migration_structure(raw: str, blanked: str) -> Tuple[List[Tuple[int, int]], Optional[str]]:
    markers = list(_SQL_SECTION_MARKER_RE.finditer(raw))
    if not markers:
        return [], None
    sections: List[Tuple[str, int, int]] = []
    for i, m in enumerate(markers):
        direction = (m.group(1) or m.group(2) or m.group(3) or "").lower()
        end = markers[i + 1].start() if i + 1 < len(markers) else len(raw)
        sections.append((direction, m.end(), end))
    rollback = [(s, e) for d, s, e in sections if d == "down"]
    downs = [blanked[s:e] for d, s, e in sections if d == "down"]
    reason: Optional[str] = None
    if not downs:
        reason = "the migration has an Up section but no Down section"
    elif all(not re.sub(r"[\s;]", "", d) for d in downs):
        reason = "the Down section is empty"
    return rollback, reason


def _extract_py_orm_events(text: str) -> List[Dict[str, Any]]:
    evs: List[Dict[str, Any]] = []
    for m in _ALEMBIC_DROP_TABLE_RE.finditer(text):
        evs.append(_mk_mig_event("table", m.group(1), m.start()))
    for m in _ALEMBIC_DROP_COLUMN_RE.finditer(text):
        evs.append(_mk_mig_event("column", f"{m.group(1)}.{m.group(2)}", m.start()))
    batch_tables = [(m.start(), m.group(1)) for m in _ALEMBIC_BATCH_TABLE_RE.finditer(text)]
    for m in _ALEMBIC_BATCH_DROP_COLUMN_RE.finditer(text):
        table = next((nm for pos, nm in reversed(batch_tables) if pos < m.start()), None)
        evs.append(_mk_mig_event("column", f"{table}.{m.group(1)}" if table else m.group(1), m.start()))
    for m in _DJANGO_DELETE_MODEL_RE.finditer(text):
        evs.append(_mk_mig_event("table", m.group(1), m.start()))
    for m in _DJANGO_REMOVE_FIELD_RE.finditer(text):
        open_idx = m.end() - 1
        args = text[open_idx + 1:_balanced_end(text, open_idx) - 1]
        m_model = re.search(r"model_name\s*=\s*[\"'](\w+)[\"']", args)
        m_name = re.search(r"(?<!\w)name\s*=\s*[\"'](\w+)[\"']", args)
        positional = re.findall(r"(?:^|,)\s*[\"'](\w+)[\"']", args)
        model = m_model.group(1) if m_model else (positional[0] if positional else None)
        field_name = m_name.group(1) if m_name else (positional[1] if len(positional) > 1 else None)
        if field_name:
            evs.append(_mk_mig_event("column", f"{model}.{field_name}" if model else field_name, m.start()))
    return evs


def _extract_js_orm_events(text: str) -> List[Dict[str, Any]]:
    evs: List[Dict[str, Any]] = []
    for m in _JS_DROP_TABLE_CALL_RE.finditer(text):
        evs.append(_mk_mig_event("table", m.group(1), m.start()))
    contexts = [(m.start(), m.group(1)) for m in _JS_TABLE_CONTEXT_RE.finditer(text)]
    for m in _JS_DROP_COLUMN_CALL_RE.finditer(text):
        obj, meth = m.group(1), m.group(2)
        open_idx = m.end() - 1
        strs = _JS_STR_ARG_RE.findall(text[open_idx + 1:_balanced_end(text, open_idx) - 1])
        if not strs:
            continue
        table: Optional[str] = None
        if obj in ("queryRunner", "queryInterface") or meth == "removeColumn":
            if len(strs) >= 2:
                table, cols = strs[0], (strs[1:] if meth == "dropColumns" else strs[1:2])
            else:
                cols = strs
        else:
            table = next((nm for pos, nm in reversed(contexts) if pos < m.start()), None)
            cols = strs
        for c in cols:
            evs.append(_mk_mig_event("column", f"{table}.{c}" if table else c, m.start()))
    return evs


def _extract_rb_events(text: str, change_span: Optional[Tuple[int, int]]) -> List[Dict[str, Any]]:
    evs: List[Dict[str, Any]] = []

    def in_change(off: int) -> bool:
        return bool(change_span and change_span[0] <= off < change_span[1])

    def rest_of_line(off: int) -> str:
        nl = text.find("\n", off)
        return text[off:nl if nl != -1 else len(text)]

    for m in _RB_DROP_TABLE_RE.finditer(text):
        irrev = None
        if in_change(m.start()) and not re.search(r"\bdo\b|\{", rest_of_line(m.end())):
            irrev = "drop_table inside `change` has no block, so Rails cannot reverse it"
        evs.append(_mk_mig_event("table", m.group(1), m.start(), irrev=irrev))
    for m in _RB_REMOVE_COLUMN_RE.finditer(text):
        irrev = None
        if in_change(m.start()) and not re.match(r"\s*,", rest_of_line(m.end())):
            irrev = "remove_column inside `change` has no column type, so Rails cannot reverse it"
        evs.append(_mk_mig_event("column", f"{m.group(1)}.{m.group(2)}", m.start(), irrev=irrev))
    for m in _RB_REMOVE_COLUMNS_RE.finditer(text):
        rest = m.group(2)
        irrev = None
        if in_change(m.start()) and "type:" not in rest:
            irrev = "remove_columns inside `change` has no type:, so Rails cannot reverse it"
        for piece in rest.split(","):
            piece = piece.strip()
            if not piece or re.match(r"^\w+\s*:", piece):
                continue
            mc = re.match(r"^[:\"']?(\w+)", piece)
            if mc:
                evs.append(_mk_mig_event("column", f"{m.group(1)}.{mc.group(1)}", m.start(), irrev=irrev))
    return evs


@dataclass(frozen=True)
class _MigrationAnalysis:
    lang: Optional[str]
    events: Tuple[Dict[str, Any], ...]
    reason: Optional[str]


def _analyze_migration_source(file_path: str, src: str) -> _MigrationAnalysis:
    """Extract forward-direction destructive persistence events from one migration snapshot."""
    lang = _migration_language(file_path)
    blanked = _blank_comments(src, lang)
    rollback: List[Tuple[int, int]] = []
    irrev_spans: List[Tuple[int, int, str]] = []
    reason: Optional[str] = None
    change_span: Optional[Tuple[int, int]] = None
    if lang == "py":
        blanked, rollback, reason, irrev_spans = _py_migration_structure(src, blanked)
    elif lang == "js":
        rollback, reason = _js_migration_structure(blanked)
    elif lang == "rb":
        rollback, reason, change_span = _rb_migration_structure(blanked)
        if change_span:
            irrev_spans.append((change_span[0], change_span[1], "SQL `execute` inside `change` cannot be reversed by Rails"))
    elif lang == "sql":
        rollback, reason = _sql_migration_structure(src, blanked)

    raw_events = _extract_sql_events(blanked)
    if lang == "py":
        raw_events += _extract_py_orm_events(blanked)
    elif lang == "js":
        raw_events += _extract_js_orm_events(blanked)
    elif lang == "rb":
        raw_events += _extract_rb_events(blanked, change_span)

    starts = _line_starts(src)
    out: List[Dict[str, Any]] = []
    seen: Set[Any] = set()
    for ev in sorted(raw_events, key=lambda e: e["offset"]):
        off = ev["offset"]
        if any(s <= off < e for s, e in rollback):
            continue
        if ev["irrev"] is None and (lang != "rb" or ev["src"] == "sql"):
            for s, e, why in irrev_spans:
                if s <= off < e:
                    ev["irrev"] = why
                    break
        line = _line_of(starts, off)
        line_txt = src[starts[line - 1]:(starts[line] if line < len(starts) else len(src))].strip()
        if ev["dynamic"]:
            key = (ev["kind"], "<dynamic>", re.sub(r"\s+", " ", line_txt))
        else:
            key = (ev["kind"], ev["entity"].lower())
        if (key, line) in seen:
            continue
        seen.add((key, line))
        ev.update(line=line, key=key, snippet=line_txt[:200])
        out.append(ev)
    return _MigrationAnalysis(lang=lang, events=tuple(out), reason=reason)


def _sql_sibling_down_reason(file_path: str, by_path: Dict[str, "FileDeltaInput"]) -> Optional[str]:
    """For `*.up.sql` migrations, inspect a sibling `*.down.sql` changed in the same delta."""
    norm = file_path.replace("\\", "/")
    bname = norm.rsplit("/", 1)[-1]
    if not _UP_SQL_FILE_RE.search(bname):
        return None
    idx = norm.lower().rfind("up.sql")
    sibling = norm[:idx] + "down.sql"
    sfd = by_path.get(sibling) or by_path.get(norm[:idx] + "DOWN.sql")
    if sfd is None:
        return None
    if sfd.change_type == "D" or not sfd.head_source:
        return f"its rollback file '{sibling}' is deleted in this change"
    if not re.sub(r"[\s;]", "", _blank_comments(sfd.head_source, "sql")):
        return f"its rollback file '{sibling}' is empty"
    return None





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

            if fd.base_source is not None and _needs_structural_parse(fd.old_path or fd.file_path):
                b_path = fd.old_path or fd.file_path
                pr_base = extract_symbols(fd.base_source, b_path)
                base_parse_results[b_path] = pr_base
                base_symbols.extend(pr_base.symbols)

            if fd.head_source is not None and _needs_structural_parse(fd.file_path):
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
        elif all(pr.status == PARSER_STATUS_UNSUPPORTED_EXTENSION for pr in incomplete_prs):
            syntax_state = CAPABILITY_UNAVAILABLE
            syntax_reason = f"No structural parser for any of the {len(all_prs)} changed file snapshot(s)"
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
                if pr.status == PARSER_STATUS_UNSUPPORTED_EXTENSION:
                    remediation = (
                        f"No structural parser is registered for '{Path(fpath).suffix}' files, so the "
                        f"symbol-level detectors did not analyse '{fpath}'. Review its changes manually."
                    )
                else:
                    remediation = (
                        f"Fix syntax errors in '{fpath}' or ensure the '{pr.language}' Tree-sitter grammar "
                        "is installed before relying on structural safety guarantees."
                    )

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
                        remediation=remediation,
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
            base_has_wfr = bool(_WORKFLOW_RUN_TRIGGER_RE.search(base_src))
            head_has_wfr = bool(_WORKFLOW_RUN_TRIGGER_RE.search(head_src))
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
                owner = act_name.split("/")[0].lower() if "/" in act_name else ""
                if owner in _GITHUB_OWNED_ACTION_OWNERS:
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
        """Report destructive operations newly introduced in FORWARD migration code.

        Rollback code is excluded, only operations absent from the base snapshot are
        reported, and irreversibility is judged per framework (empty/missing
        downgrade/down, empty Down section or sibling down.sql, RunSQL without
        reverse_sql, Rails `change` operations Rails cannot invert).
        """
        findings: List[ConsequenceFinding] = []
        by_path = {fd.file_path.replace("\\", "/"): fd for fd in file_deltas}

        for fd in file_deltas:
            if not fd.head_source or not _is_migration_file(fd.file_path):
                continue
            head = _analyze_migration_source(fd.file_path, fd.head_source)
            base_keys: Set[Any] = set()
            if fd.base_source:
                base = _analyze_migration_source(fd.old_path or fd.file_path, fd.base_source)
                base_keys = {ev["key"] for ev in base.events}
            new_events = [
                ev for ev in head.events
                if ev["key"] not in base_keys and not _is_temp_table_entity(ev["entity"], ev["kind"])
            ]
            if not new_events:
                continue

            file_reason = head.reason
            if file_reason is None and head.lang == "sql":
                file_reason = _sql_sibling_down_reason(fd.file_path, by_path)

            # 1. Catastrophic wipe-outs: TRUNCATE / DROP DATABASE / DROP SCHEMA
            for ev in new_events:
                if ev["kind"] not in ("truncate", "dropdb"):
                    continue
                dyn = ev["dynamic"]
                is_trunc = ev["kind"] == "truncate"
                what = "truncates table" if is_trunc else "drops database/schema"
                target = "a dynamically built name" if dyn else f"'{ev['entity']}'"
                findings.append(
                    ConsequenceFinding(
                        finding_id=f"PG-D10-{'TRUNCATE' if is_trunc else 'DROPDB'}-{fd.file_path}-{ev['line']}",
                        detector_id=DETECTOR_D10_MIGRATION,
                        consequence_class="CATASTROPHIC_DATA_WIPEOUT",
                        tier=TIER_LIKELY if dyn else TIER_VERIFIED,
                        confidence=CONFIDENCE_MEDIUM if dyn else CONFIDENCE_HIGH,
                        severity=SEVERITY_HIGH if dyn else SEVERITY_CRITICAL,
                        policy_recommendation=POLICY_REVIEW if dyn else POLICY_BLOCK,
                        summary=f"Migration '{fd.file_path}' {what} {target}, permanently erasing its data.",
                        affected_files=(fd.file_path,),
                        affected_symbols=(ev["entity"],),
                        evidence=(
                            EvidenceItem(
                                kind="TABLE_TRUNCATE" if is_trunc else "DATABASE_OR_SCHEMA_DROP",
                                file=fd.file_path,
                                line=ev["line"],
                                symbol=ev["entity"],
                                detail=f"Line {ev['line']}: {ev['snippet']}",
                            ),
                        ),
                        remediation=(
                            "Avoid TRUNCATE in automated production migrations; use soft archiving, batched "
                            "deletion or an explicit, reviewed maintenance procedure."
                            if is_trunc
                            else "Dropping an entire database or schema must never ship in an automated migration."
                        ),
                    )
                )

            # 2. Table / column drops (grouped per migration file)
            schema_events = [ev for ev in new_events if ev["kind"] in ("table", "column")]
            if not schema_events:
                continue
            literal = [ev for ev in schema_events if not ev["dynamic"]]
            reasons: List[str] = [file_reason] if (file_reason and literal) else []
            for r in sorted({ev["irrev"] for ev in literal if ev["irrev"]}):
                reasons.append(r)
            irreversible = bool(literal) and bool(reasons)
            all_dynamic = not literal

            ev_items: List[EvidenceItem] = [
                EvidenceItem(
                    kind="SCHEMA_TABLE_DROPPED" if ev["kind"] == "table" else "SCHEMA_COLUMN_DROPPED",
                    file=fd.file_path,
                    line=ev["line"],
                    symbol=ev["entity"],
                    detail=(
                        f"Line {ev['line']}: dropped {'table' if ev['kind'] == 'table' else 'column'} "
                        f"'{ev['entity']}' ({ev['snippet']})"
                    ),
                )
                for ev in schema_events
            ]
            for r in reasons:
                ev_items.append(
                    EvidenceItem(kind="ROLLBACK_UNAVAILABLE", file=fd.file_path, line=None, symbol=None, detail=r)
                )

            entities = [ev["entity"] for ev in schema_events]
            shown = ", ".join(entities[:3]) + (f" (+{len(entities) - 3} more)" if len(entities) > 3 else "")
            if irreversible:
                summary_msg = f"Migration '{fd.file_path}' drops {shown} and cannot be rolled back: {reasons[0]}."
            elif all_dynamic:
                summary_msg = (
                    f"Migration '{fd.file_path}' drops a table/column whose name is built at runtime; "
                    "the target could not be resolved statically."
                )
            else:
                summary_msg = f"Migration '{fd.file_path}' drops persistent schema element(s): {shown}."

            all_symbols: List[str] = []
            for ev in schema_events:
                if ev["entity"] not in all_symbols:
                    all_symbols.append(ev["entity"])
                if "." in ev["entity"]:
                    col_bare = ev["entity"].split(".")[-1]
                    if col_bare not in all_symbols:
                        all_symbols.append(col_bare)
            findings.append(
                ConsequenceFinding(
                    finding_id=f"PG-D10-SCHEMA-{fd.file_path}",
                    detector_id=DETECTOR_D10_MIGRATION,
                    consequence_class="IRREVERSIBLE_PERSISTENCE_DROP" if irreversible else "DESTRUCTIVE_PERSISTENCE_MIGRATION",
                    tier=TIER_LIKELY if all_dynamic else TIER_VERIFIED,
                    confidence=CONFIDENCE_MEDIUM if all_dynamic else CONFIDENCE_HIGH,
                    severity=SEVERITY_CRITICAL if irreversible else SEVERITY_HIGH,
                    policy_recommendation=POLICY_BLOCK if irreversible else POLICY_REVIEW,
                    summary=summary_msg,
                    affected_files=(fd.file_path,),
                    affected_symbols=tuple(all_symbols),
                    evidence=tuple(ev_items),
                    remediation=(
                        "Follow expand-and-contract: stop reading/writing the column or table in a prior deploy, "
                        "then drop it in a separate migration. Provide a working rollback (downgrade/down) "
                        "or document why the drop is intentionally irreversible."
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
