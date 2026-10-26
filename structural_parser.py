"""
Language-aware structural node and semantic symbol extraction for Layer 4
(Structural Drift) and the Semantic Change Graph (SCG).

Python uses stdlib ast (always available, no extra dep). All other languages
use tree-sitter grammar packages and a recursive node walker — no query-string
API, so it works across tree-sitter versions.

Legacy public API `extract_named_nodes(source, path) -> set[str]` is preserved
unchanged for backwards compatibility.

Structured API `extract_symbols(source, path) -> ParseResult` provides:
- Explicit parser completeness status (AVAILABLE, PARSE_ERROR,
  GRAMMAR_UNAVAILABLE, UNSUPPORTED_EXTENSION, TIMEOUT)
- Per-file capability vectors (universal, syntax, symbolic, typed,
  reachability, flow, runtime)
- Qualified, source-located `SymbolFact` v1 records with normalized signatures,
  parameter counts, visibility, export status, decorators, normalized body
  hashes, statement counts, stub detection, and call-site extraction.

Supported:  .py  .js  .jsx  .ts  .tsx  .go  .rs  .java
"""

import ast
import hashlib
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SYMBOL_FACT_SCHEMA_VERSION = "1.0"

PARSER_STATUS_AVAILABLE = "AVAILABLE"
PARSER_STATUS_PARSE_ERROR = "PARSE_ERROR"
PARSER_STATUS_GRAMMAR_UNAVAILABLE = "GRAMMAR_UNAVAILABLE"
PARSER_STATUS_UNSUPPORTED_EXTENSION = "UNSUPPORTED_EXTENSION"
PARSER_STATUS_TIMEOUT = "TIMEOUT"

_EXT_TO_LANG: dict[str, str] = {
    ".py":   "python",
    ".js":   "javascript",
    ".jsx":  "javascript",
    ".mjs":  "javascript",
    ".cjs":  "javascript",
    ".ts":   "typescript",
    ".mts":  "typescript",
    ".cts":  "typescript",
    ".tsx":  "tsx",
    ".go":   "go",
    ".rs":   "rust",
    ".java": "java",
}

_JS_RULES: dict[str, str] = {
    "function_declaration": "name",
    "class_declaration":    "name",
    "method_definition":    "name",
}
_LANG_RULES: dict[str, dict[str, str]] = {
    "javascript": _JS_RULES,
    "typescript": {
        **_JS_RULES,
        "interface_declaration":  "name",
        "type_alias_declaration": "name",
    },
    "go": {
        "function_declaration": "name",
        "method_declaration":   "name",
        "type_spec":            "name",
        "const_spec":           "name",
    },
    "rust": {
        "function_item": "name",
        "struct_item":   "name",
        "enum_item":     "name",
        "trait_item":    "name",
        "const_item":    "name",
        "static_item":   "name",
    },
    "java": {
        "class_declaration":     "name",
        "interface_declaration": "name",
        "enum_declaration":      "name",
        "method_declaration":    "name",
    },
}
_LANG_RULES["tsx"] = _LANG_RULES["typescript"]


@dataclass(frozen=True)
class SymbolFact:
    """Versioned, source-located structural symbol record (SymbolFact v1)."""
    schema_version: str
    symbol_id: str
    language: str
    kind: str
    name: str
    qualified_name: str
    file_path: str
    start_line: int
    end_line: int
    visibility: str
    is_exported: bool
    normalized_signature: str
    parameter_count: int
    required_parameter_count: int
    decorators: Tuple[str, ...]
    body_hash: str
    statement_count: int
    is_stub: bool
    calls: Tuple[str, ...]
    parent_symbol: Optional[str] = None
    frontend: str = ""
    frontend_version: str = ""
    guard_conditions: Tuple[str, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["decorators"] = list(self.decorators)
        d["calls"] = list(self.calls)
        d["guard_conditions"] = list(self.guard_conditions)
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SymbolFact":
        payload = dict(data)
        payload["decorators"] = tuple(payload.get("decorators", ()))
        payload["calls"] = tuple(payload.get("calls", ()))
        payload["guard_conditions"] = tuple(payload.get("guard_conditions", ()))
        return cls(**payload)


@dataclass(frozen=True)
class CallSiteFact:
    """Source-located function or method invocation site."""
    file_path: str
    line: int
    caller_qualified_name: str
    callee_name: str
    qualifier: str
    arg_count: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CallSiteFact":
        return cls(**data)


@dataclass
class ParseResult:
    """Structured output of parsing a single file, including completeness state."""
    file_path: str
    language: Optional[str]
    status: str
    complete: bool
    incomplete_reason: Optional[str] = None
    error_detail: Optional[str] = None
    frontend: str = "none"
    frontend_version: str = "0"
    symbols: List[SymbolFact] = field(default_factory=list)
    named_nodes: List[str] = field(default_factory=list)
    call_sites: List[CallSiteFact] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    exports: List[str] = field(default_factory=list)
    capabilities: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_path": self.file_path,
            "language": self.language,
            "status": self.status,
            "complete": self.complete,
            "incomplete_reason": self.incomplete_reason,
            "error_detail": self.error_detail,
            "frontend": self.frontend,
            "frontend_version": self.frontend_version,
            "symbols": [s.to_dict() for s in self.symbols],
            "named_nodes": list(self.named_nodes),
            "call_sites": [c.to_dict() for c in self.call_sites],
            "imports": list(self.imports),
            "exports": list(self.exports),
            "capabilities": dict(self.capabilities),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ParseResult":
        return cls(
            file_path=data["file_path"],
            language=data.get("language"),
            status=data["status"],
            complete=bool(data["complete"]),
            incomplete_reason=data.get("incomplete_reason"),
            error_detail=data.get("error_detail"),
            frontend=data.get("frontend", "none"),
            frontend_version=data.get("frontend_version", "0"),
            symbols=[SymbolFact.from_dict(s) for s in data.get("symbols", [])],
            named_nodes=list(data.get("named_nodes", [])),
            call_sites=[CallSiteFact.from_dict(c) for c in data.get("call_sites", [])],
            imports=list(data.get("imports", [])),
            exports=list(data.get("exports", [])),
            capabilities=dict(data.get("capabilities", {})),
        )


def build_capability_vector(
    syntax_state: str,
    syntax_provenance: str,
    syntax_reason: str,
    symbolic_state: str = "unavailable",
    symbolic_reason: str = "No symbolic extraction performed",
    reachability_state: str = "unavailable",
    reachability_reason: str = "Cross-file reachability not computed at single-file stage",
    flow_state: str = "unavailable",
    flow_reason: str = "Intra-procedural guard/call inspection only",
    runtime_state: str = "unavailable",
    runtime_reason: str = "No runtime trace attached",
) -> Dict[str, Dict[str, str]]:
    """Construct the standard 7-dimension capability vector for a file/module."""
    return {
        "universal": {
            "state": "available",
            "provenance": "git-diff",
            "reason": "Git object and path metadata available",
        },
        "syntax": {
            "state": syntax_state,
            "provenance": syntax_provenance,
            "reason": syntax_reason,
        },
        "symbolic": {
            "state": symbolic_state,
            "provenance": syntax_provenance if symbolic_state != "unavailable" else "none",
            "reason": symbolic_reason,
        },
        "typed": {
            "state": "unavailable",
            "provenance": "none",
            "reason": "Compiler/type-checker frontend not invoked in fast static lane",
        },
        "reachability": {
            "state": reachability_state,
            "provenance": syntax_provenance if reachability_state != "unavailable" else "none",
            "reason": reachability_reason,
        },
        "flow": {
            "state": flow_state,
            "provenance": syntax_provenance if flow_state != "unavailable" else "none",
            "reason": flow_reason,
        },
        "runtime": {
            "state": runtime_state,
            "provenance": "ebpf-agent" if runtime_state == "available" else "none",
            "reason": runtime_reason,
        },
    }


def language_for_path(path: str) -> Optional[str]:
    return _EXT_TO_LANG.get(Path(path).suffix.lower())


def _treesitter_version() -> str:
    try:
        import importlib.metadata
        return importlib.metadata.version("tree-sitter")
    except Exception:
        return "unknown"


def _load_language(lang_key: str):
    try:
        from tree_sitter import Language
        if lang_key == "python":
            import tree_sitter_python as m
            return Language(m.language())
        if lang_key in ("javascript",):
            import tree_sitter_javascript as m
            return Language(m.language())
        if lang_key == "typescript":
            import tree_sitter_typescript as m
            return Language(m.language_typescript())
        if lang_key == "tsx":
            import tree_sitter_typescript as m
            return Language(m.language_tsx())
        if lang_key == "go":
            import tree_sitter_go as m
            return Language(m.language())
        if lang_key == "rust":
            import tree_sitter_rust as m
            return Language(m.language())
        if lang_key == "java":
            import tree_sitter_java as m
            return Language(m.language())
    except (ImportError, AttributeError):
        pass
    return None


def get_parser_capabilities() -> Dict[str, Dict[str, Any]]:
    """Return installed parser availability across all supported languages."""
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    caps: Dict[str, Dict[str, Any]] = {
        "python": {
            "available": True,
            "frontend": "python-ast",
            "version": py_ver,
        }
    }
    ts_ver = _treesitter_version()
    for lang_key in ("javascript", "typescript", "tsx", "go", "rust", "java"):
        loaded = _load_language(lang_key) is not None
        caps[lang_key] = {
            "available": loaded,
            "frontend": "tree-sitter",
            "version": ts_ver if loaded else "unavailable",
        }
    return caps


def _collect(node, rules: dict[str, str], names: set[str]) -> None:
    name_field = rules.get(node.type)
    if name_field:
        name_node = node.child_by_field_name(name_field)
        if name_node and name_node.text:
            names.add(name_node.text.decode("utf-8"))
    elif node.type == "variable_declarator" and "function_declaration" in rules:
        # Track all named JS/TS declarations: arrow functions, constants,
        # config objects, auth literals — anything with a name at declarator level.
        name_node = node.child_by_field_name("name")
        if name_node and name_node.text:
            names.add(name_node.text.decode("utf-8"))
    for child in node.children:
        _collect(child, rules, names)


def _extract_via_treesitter(source: str, lang_key: str) -> set[str]:
    ts_lang = _load_language(lang_key)
    if ts_lang is None:
        return set()
    from tree_sitter import Parser
    parser = Parser(ts_lang)
    tree = parser.parse(bytes(source, "utf-8"))
    names: set[str] = set()
    _collect(tree.root_node, _LANG_RULES[lang_key], names)
    return names


def extract_named_nodes(source: str, path: str) -> set[str]:
    """Legacy L4 API: returns a flat set of simple declaration names."""
    lang_key = language_for_path(path)
    if lang_key is None:
        return set()
    if lang_key == "python":
        try:
            tree = ast.parse(source)
        except SyntaxError as e:
            raise ValueError(f"SyntaxError: {e}") from e
        names = {
            node.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
        }
        for node in tree.body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        names.add(target.id)
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                names.add(node.target.id)
        return names
    try:
        return _extract_via_treesitter(source, lang_key)
    except Exception as e:
        raise ValueError(str(e)) from e


# ==============================================================================
# SYMBOL FACT v1 EXTRACTION HELPERS
# ==============================================================================

def _hash_normalized_text(text: str) -> str:
    norm = re.sub(r"\s+", " ", text.strip())
    return hashlib.sha256(norm.encode("utf-8")).hexdigest()[:16]


class _PythonIdentNormalizer(ast.NodeTransformer):
    """Strip docstrings and normalize function/class names for body digesting."""

    def _strip_docstring(self, body: list) -> list:
        if (
            body
            and isinstance(body[0], ast.Expr)
            and isinstance(getattr(body[0], "value", None), ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            return body[1:]
        return body

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self.generic_visit(node)
        node.body = self._strip_docstring(node.body)
        node.decorator_list = []
        return node

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self.generic_visit(node)
        node.body = self._strip_docstring(node.body)
        node.decorator_list = []
        return node

    def visit_ClassDef(self, node: ast.ClassDef):
        self.generic_visit(node)
        node.body = self._strip_docstring(node.body)
        node.decorator_list = []
        return node


def _python_body_metrics(stmts: list) -> Tuple[str, int, bool]:
    """Compute (body_hash, statement_count, is_stub) for a Python AST body."""
    import copy as _copy
    cleaned = []
    for idx, stmt in enumerate(stmts):
        if (
            idx == 0
            and isinstance(stmt, ast.Expr)
            and isinstance(getattr(stmt, "value", None), ast.Constant)
            and isinstance(stmt.value.value, str)
        ):
            continue
        cleaned.append(_PythonIdentNormalizer().visit(_copy.deepcopy(stmt)))

    if not cleaned:
        return _hash_normalized_text("STUB"), 0, True

    # Check if all remaining statements are pass, `...`, or `return None`
    is_stub = all(
        isinstance(s, ast.Pass)
        or (
            isinstance(s, ast.Expr)
            and isinstance(getattr(s, "value", None), ast.Constant)
            and s.value.value is Ellipsis
        )
        or (
            isinstance(s, ast.Return)
            and (
                s.value is None
                or (isinstance(s.value, ast.Constant) and s.value.value is None)
            )
        )
        for s in cleaned
    )

    stmt_count = sum(
        1
        for s in cleaned
        for sub in ast.walk(s)
        if isinstance(sub, ast.stmt) and not isinstance(sub, ast.Pass)
    )
    dumped = "|".join(ast.dump(s, annotate_fields=True, include_attributes=False) for s in cleaned)
    if is_stub:
        return _hash_normalized_text("STUB"), stmt_count, True
    return _hash_normalized_text(dumped), max(stmt_count, 1), False


def _python_signature(node: ast.AST, is_method: bool = False) -> Tuple[str, int, int]:
    """Return (normalized_signature, param_count, required_param_count) for a Python function."""
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return "()", 0, 0
    args = node.args
    all_args = list(args.posonlyargs) + list(args.args)
    if is_method and all_args and all_args[0].arg in ("self", "cls"):
        all_args = all_args[1:]
    num_defaults = len(args.defaults)
    req_positional = max(0, len(all_args) - num_defaults)

    kwonly = list(args.kwonlyargs)
    req_kwonly = sum(1 for d in args.kw_defaults if d is None)

    param_parts = []
    for a in all_args:
        ann = f":{ast.unparse(a.annotation)}" if a.annotation else ""
        param_parts.append(f"{a.arg}{ann}")
    if args.vararg:
        param_parts.append(f"*{args.vararg.arg}")
    for a in kwonly:
        ann = f":{ast.unparse(a.annotation)}" if a.annotation else ""
        param_parts.append(f"{a.arg}{ann}")
    if args.kwarg:
        param_parts.append(f"**{args.kwarg.arg}")

    ret = f"->{ast.unparse(node.returns)}" if node.returns else ""
    sig = f"({','.join(param_parts)}){ret}"
    sig = re.sub(r"\s+", "", sig)
    total_params = len(all_args) + len(kwonly) + (1 if args.vararg else 0) + (1 if args.kwarg else 0)
    required_params = req_positional + req_kwonly
    return sig, total_params, required_params


def _python_extract_calls(
    node: ast.AST,
    caller_qual: str,
    file_path: str,
    stop_at_nested_defs: bool = True,
) -> Tuple[Tuple[str, ...], List[CallSiteFact]]:
    """Extract called symbol names and CallSiteFacts within a Python AST node."""
    calls: List[str] = []
    call_sites: List[CallSiteFact] = []

    def _walk(curr: ast.AST, is_root: bool = False):
        if not is_root and stop_at_nested_defs and isinstance(
            curr, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        ):
            return
        if isinstance(curr, ast.Call):
            callee = ""
            qualifier = ""
            if isinstance(curr.func, ast.Name):
                callee = curr.func.id
            elif isinstance(curr.func, ast.Attribute):
                callee = curr.func.attr
                try:
                    qualifier = ast.unparse(curr.func.value)
                except Exception:
                    qualifier = ""
            if callee:
                full_call = f"{qualifier}.{callee}" if qualifier else callee
                calls.append(full_call)
                call_sites.append(
                    CallSiteFact(
                        file_path=file_path,
                        line=getattr(curr, "lineno", 1),
                        caller_qualified_name=caller_qual,
                        callee_name=callee,
                        qualifier=qualifier,
                        arg_count=len(curr.args) + len(curr.keywords),
                    )
                )
        for ch in ast.iter_child_nodes(curr):
            _walk(ch, False)

    _walk(node, True)
    return tuple(dict.fromkeys(calls)), call_sites


_LOGGING_QUALIFIERS = frozenset({"logger", "logging", "log", "console", "fmt"})
_LOGGING_CALLEES = frozenset({"debug", "info", "warning", "warn", "error", "print", "println", "printf"})
_ABORT_CALLEES = frozenset({"abort", "panic", "exit", "Exit", "Fatal", "Fatalf", "reject", "Error"})


def _python_stmt_action(stmts: list) -> str:
    """Classify the enforcement action of a Python statement block (if-branch or except-handler)."""
    if not stmts:
        return "noop"
    has_raise = False
    has_rollback = False
    return_kinds: List[str] = []
    non_trivial_stmts = 0

    for stmt in stmts:
        if isinstance(stmt, ast.Pass):
            continue
        if (
            isinstance(stmt, ast.Expr)
            and isinstance(getattr(stmt, "value", None), ast.Constant)
            and (stmt.value.value is Ellipsis or isinstance(stmt.value.value, str))
        ):
            continue
        for sub in ast.walk(stmt):
            if isinstance(sub, ast.Raise):
                has_raise = True
            elif isinstance(sub, ast.Call):
                callee = ""
                qual = ""
                if isinstance(sub.func, ast.Name):
                    callee = sub.func.id
                elif isinstance(sub.func, ast.Attribute):
                    callee = sub.func.attr
                    if isinstance(sub.func.value, ast.Name):
                        qual = sub.func.value.id
                if callee in _ABORT_CALLEES:
                    has_raise = True
                if "rollback" in callee.lower() or "abort" in callee.lower():
                    has_rollback = True
            elif isinstance(sub, ast.Return):
                val = sub.value
                if val is None or (isinstance(val, ast.Constant) and val.value in (False, None)):
                    return_kinds.append("return_deny")
                elif isinstance(val, ast.Constant) and val.value is True:
                    return_kinds.append("return_allow")
                else:
                    return_kinds.append("return_val")

        # Check if statement is purely a logging/print expression
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
            c_name = ""
            q_name = ""
            if isinstance(stmt.value.func, ast.Name):
                c_name = stmt.value.func.id
            elif isinstance(stmt.value.func, ast.Attribute):
                c_name = stmt.value.func.attr
                if isinstance(stmt.value.func.value, ast.Name):
                    q_name = stmt.value.func.value.id
            if c_name in _LOGGING_CALLEES or q_name in _LOGGING_QUALIFIERS:
                continue
        non_trivial_stmts += 1

    if has_raise:
        return "raise"
    if has_rollback:
        return "rollback"
    if return_kinds:
        if "return_deny" in return_kinds:
            return "return_deny"
        if "return_allow" in return_kinds:
            return "return_allow"
        return return_kinds[0]
    if non_trivial_stmts == 0:
        return "noop"
    return "branch"


_STATE_GUARD_IDENT_RE = re.compile(
    r"\b(?:auth|authenticated|authorized|admin|is_admin|isadmin|perm|permission|"
    r"role|valid|verified|active|is_active|isactive|token|session|expired|csrf|"
    r"signature|policy|allowed|enabled|ok|started)\b",
    re.IGNORECASE,
)


_CUSTOM_ASSERT_HELPER_RE = re.compile(
    r"^(?:verify|check|ensure|require|expect|should)(?:_[a-z0-9_]+|[A-Z][A-Za-z0-9_]*)$"
)


def _eval_python_const_bool(
    test_node: ast.AST,
    const_bools: Optional[Dict[str, bool]] = None,
) -> Optional[bool]:
    """Evaluate a Python AST expression to a static boolean if it is a constant tautology/contradiction."""
    const_bools = const_bools or {}
    if isinstance(test_node, ast.Constant) and isinstance(test_node.value, (bool, int)):
        return bool(test_node.value)
    if isinstance(test_node, ast.Name) and test_node.id in const_bools:
        return const_bools[test_node.id]
    if isinstance(test_node, ast.UnaryOp) and isinstance(test_node.op, ast.Not):
        inner = _eval_python_const_bool(test_node.operand, const_bools)
        if inner is not None:
            return not inner
    if (
        isinstance(test_node, ast.Compare)
        and len(test_node.ops) == 1
        and len(test_node.comparators) == 1
        and isinstance(test_node.left, ast.Constant)
        and isinstance(test_node.comparators[0], ast.Constant)
    ):
        lv = test_node.left.value
        rv = test_node.comparators[0].value
        op = test_node.ops[0]
        try:
            if isinstance(op, (ast.Eq, ast.Is)):
                return bool(lv == rv)
            if isinstance(op, (ast.NotEq, ast.IsNot)):
                return bool(lv != rv)
            if isinstance(op, ast.Lt):
                return bool(lv < rv)
            if isinstance(op, ast.LtE):
                return bool(lv <= rv)
            if isinstance(op, ast.Gt):
                return bool(lv > rv)
            if isinstance(op, ast.GtE):
                return bool(lv >= rv)
        except TypeError:
            return None
    return None


def _collect_python_const_bools(stmts: list) -> Dict[str, bool]:
    """
    Collect single-assignment boolean/int constants within a statement list.
    Any variable assigned more than once or mutated via AugAssign/Global/Nonlocal is excluded.
    """
    assign_counts: Dict[str, int] = {}
    bool_vals: Dict[str, bool] = {}
    disqualified: set[str] = set()

    class _AssignVisitor(ast.NodeVisitor):
        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            for child in ast.walk(node):
                if isinstance(child, ast.Nonlocal):
                    for n in child.names:
                        disqualified.add(n)
                elif isinstance(child, ast.Assign):
                    for t in child.targets:
                        for sub in ast.walk(t):
                            if isinstance(sub, ast.Name):
                                disqualified.add(sub.id)
                elif isinstance(child, (ast.AugAssign, ast.AnnAssign)):
                    target = getattr(child, "target", None)
                    if target:
                        for sub in ast.walk(target):
                            if isinstance(sub, ast.Name):
                                disqualified.add(sub.id)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self.visit_FunctionDef(node)

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            return

        def visit_Global(self, node: ast.Global) -> None:
            for n in node.names:
                disqualified.add(n)

        def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
            for n in node.names:
                disqualified.add(n)

        def visit_AugAssign(self, node: ast.AugAssign) -> None:
            if isinstance(node.target, ast.Name):
                disqualified.add(node.target.id)

        def visit_Assign(self, node: ast.Assign) -> None:
            for t in node.targets:
                if isinstance(t, ast.Name):
                    assign_counts[t.id] = assign_counts.get(t.id, 0) + 1
                    if (
                        isinstance(node.value, ast.Constant)
                        and isinstance(node.value.value, bool)
                    ):
                        bool_vals[t.id] = bool(node.value.value)
                    else:
                        disqualified.add(t.id)
                else:
                    for sub in ast.walk(t):
                        if isinstance(sub, ast.Name):
                            disqualified.add(sub.id)

        def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
            if isinstance(node.target, ast.Name):
                tid = node.target.id
                assign_counts[tid] = assign_counts.get(tid, 0) + 1
                if (
                    node.value is not None
                    and isinstance(node.value, ast.Constant)
                    and isinstance(node.value.value, bool)
                ):
                    bool_vals[tid] = bool(node.value.value)
                else:
                    disqualified.add(tid)

    visitor = _AssignVisitor()
    for s in stmts:
        visitor.visit(s)

    return {
        k: v
        for k, v in bool_vals.items()
        if assign_counts.get(k, 0) == 1 and k not in disqualified
    }


def _is_python_trivial_assert(
    test_node: ast.AST,
    const_bools: Optional[Dict[str, bool]] = None,
) -> bool:
    """Return True if a Python assert expression is a constant tautology (e.g. `assert True`, `assert 1 == 1`)."""
    return _eval_python_const_bool(test_node, const_bools) is True


def _python_extract_guard_conditions(
    node: ast.AST,
    module_const_bools: Optional[Dict[str, bool]] = None,
) -> Tuple[str, ...]:
    """
    Extract intra-function guard condition and test contract descriptors for D06 & D09:
    - if_guard:<callee>:<polarity>:<action>
    - if_state_guard:<subject>:<polarity>:<action>
    - if_short_circuit:<target>:<and_false|or_true>:<action>
    - early_return_bypass:<action>
    - except_handler:<action>
    - test_assertions:<effective_count>:<trivial_count>
    - test_skip_call:true
    """
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return ()

    conditions: List[str] = []
    # Strip leading docstring
    body = list(node.body)
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(getattr(body[0], "value", None), ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        body = body[1:]

    const_bools: Dict[str, bool] = dict(module_const_bools or {})
    const_bools.update(_collect_python_const_bools(body))

    # 1. Check for early unconditional return followed by unreachable statements
    for idx, stmt in enumerate(body):
        if isinstance(stmt, ast.Return) and idx < len(body) - 1:
            val = stmt.value
            if isinstance(val, ast.Constant) and val.value is True:
                conditions.append("early_return_bypass:return_allow")
            elif isinstance(val, ast.Constant) and val.value in (False, None):
                conditions.append("early_return_bypass:return_deny")
            else:
                conditions.append("early_return_bypass:unconditional")
            break

    def _atomic_clauses(test_node: ast.AST) -> List[ast.AST]:
        if isinstance(test_node, ast.BoolOp):
            clauses: List[ast.AST] = []
            for v in test_node.values:
                clauses.extend(_atomic_clauses(v))
            return clauses
        return [test_node]

    def _clause_polarity_and_callees(clause_node: ast.AST) -> Tuple[str, List[str], ast.AST]:
        polarity = "positive"
        target = clause_node
        if isinstance(clause_node, ast.UnaryOp) and isinstance(clause_node.op, ast.Not):
            polarity = "negated"
            target = clause_node.operand
        elif isinstance(clause_node, ast.Compare) and len(clause_node.ops) == 1 and len(clause_node.comparators) == 1:
            op = clause_node.ops[0]
            comp = clause_node.comparators[0]
            if isinstance(comp, ast.Constant):
                if (isinstance(op, (ast.Eq, ast.Is)) and comp.value in (False, None)) or (
                    isinstance(op, (ast.NotEq, ast.IsNot)) and comp.value is True
                ):
                    polarity = "negated"
                    target = clause_node.left
                elif (isinstance(op, (ast.Eq, ast.Is)) and comp.value is True) or (
                    isinstance(op, (ast.NotEq, ast.IsNot)) and comp.value in (False, None)
                ):
                    polarity = "positive"
                    target = clause_node.left

        callees: List[str] = []
        for sub in ast.walk(target):
            if isinstance(sub, ast.Call):
                c_name = ""
                q_name = ""
                if isinstance(sub.func, ast.Name):
                    c_name = sub.func.id
                elif isinstance(sub.func, ast.Attribute):
                    c_name = sub.func.attr
                    try:
                        q_name = ast.unparse(sub.func.value)
                    except Exception:
                        q_name = ""
                if c_name:
                    callees.append(f"{q_name}.{c_name}" if q_name else c_name)
        return polarity, callees, target

    def _short_circuit_kind(test_node: ast.AST) -> Optional[str]:
        direct_val = _eval_python_const_bool(test_node, const_bools)
        if direct_val is False:
            return "and_false"
        if isinstance(test_node, ast.BoolOp):
            if isinstance(test_node.op, ast.And):
                if any(_eval_python_const_bool(v, const_bools) is False for v in test_node.values):
                    return "and_false"
            elif isinstance(test_node.op, ast.Or):
                if any(_eval_python_const_bool(v, const_bools) is True for v in test_node.values):
                    return "or_true"
        return None

    effective_asserts = 0
    trivial_asserts = 0
    has_skip_call = False

    def _walk_stmt_exprs(curr: ast.AST, is_root: bool = False):
        nonlocal effective_asserts, trivial_asserts, has_skip_call
        if not is_root and isinstance(curr, ast.stmt):
            return
        is_standalone_call = is_root and isinstance(curr, ast.Expr) and isinstance(curr.value, ast.Call)
        if isinstance(curr, ast.Call):
            c_name = ""
            q_name = ""
            if isinstance(curr.func, ast.Name):
                c_name = curr.func.id
            elif isinstance(curr.func, ast.Attribute):
                c_name = curr.func.attr
                if isinstance(curr.func.value, ast.Name):
                    q_name = curr.func.value.id
            if (q_name in ("pytest", "unittest") and c_name in ("skip", "xfail", "SkipTest")) or (
                q_name == "self" and c_name == "skipTest"
            ):
                has_skip_call = True
            elif (
                c_name.lower().startswith("assert")
                or (q_name == "pytest" and c_name in ("raises", "warns", "fail"))
            ):
                if (
                    c_name in ("assertTrue", "assert_", "assert_true")
                    and len(curr.args) >= 1
                    and _eval_python_const_bool(curr.args[0], const_bools) is True
                ):
                    trivial_asserts += 1
                elif (
                    c_name in ("assertFalse", "assert_false")
                    and len(curr.args) >= 1
                    and _eval_python_const_bool(curr.args[0], const_bools) is False
                ):
                    trivial_asserts += 1
                elif (
                    c_name in ("assertEqual", "assert_equal", "assertEquals")
                    and len(curr.args) >= 2
                    and isinstance(curr.args[0], ast.Constant)
                    and isinstance(curr.args[1], ast.Constant)
                    and curr.args[0].value == curr.args[1].value
                ):
                    trivial_asserts += 1
                else:
                    effective_asserts += 1
        if is_standalone_call:
            call_node = curr.value
            c_name = ""
            if isinstance(call_node.func, ast.Name):
                c_name = call_node.func.id
            elif isinstance(call_node.func, ast.Attribute):
                c_name = call_node.func.attr
            if c_name and not c_name.lower().startswith("assert") and _CUSTOM_ASSERT_HELPER_RE.match(c_name):
                effective_asserts += 1
        for ch in ast.iter_child_nodes(curr):
            _walk_stmt_exprs(ch, False)

    def _walk_stmts(stmts: list):
        nonlocal effective_asserts, trivial_asserts, has_skip_call
        for stmt in stmts:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            if isinstance(stmt, ast.Assert):
                if _is_python_trivial_assert(stmt.test, const_bools):
                    trivial_asserts += 1
                else:
                    effective_asserts += 1
            _walk_stmt_exprs(stmt, True)

            if isinstance(stmt, ast.If):
                action = _python_stmt_action(stmt.body)
                sc_kind = _short_circuit_kind(stmt.test)
                if sc_kind is not None:
                    all_callees: List[str] = []
                    for clause in _atomic_clauses(stmt.test):
                        if _eval_python_const_bool(clause, const_bools) is not None:
                            continue
                        _, c_list, _ = _clause_polarity_and_callees(clause)
                        all_callees.extend(c_list)
                    if all_callees:
                        for callee in all_callees:
                            conditions.append(f"if_short_circuit:{callee}:{sc_kind}:{action}")
                    elif action in ("raise", "rollback", "return_deny", "return_allow", "return_val", "branch"):
                        conditions.append(f"if_short_circuit:state_guard:{sc_kind}:{action}")
                else:
                    for clause in _atomic_clauses(stmt.test):
                        polarity, callees, target_node = _clause_polarity_and_callees(clause)
                        if callees:
                            for callee in callees:
                                conditions.append(f"if_guard:{callee}:{polarity}:{action}")
                        elif action in ("raise", "rollback") or (
                            action == "return_deny"
                            and _STATE_GUARD_IDENT_RE.search(ast.unparse(target_node) if hasattr(ast, "unparse") else "")
                        ):
                            try:
                                raw_subj = ast.unparse(target_node)
                            except Exception:
                                raw_subj = ""
                            subj = re.sub(r"\s+", "", raw_subj).replace(":", "_")
                            if subj and not isinstance(target_node, ast.Constant):
                                conditions.append(f"if_state_guard:{subj}:{polarity}:{action}")
                _walk_stmts(stmt.body)
                _walk_stmts(stmt.orelse)
            elif isinstance(stmt, ast.Try):
                for handler in stmt.handlers:
                    h_action = _python_stmt_action(handler.body)
                    if h_action == "noop":
                        conditions.append("except_handler:swallowed_noop")
                    elif h_action == "return_allow":
                        conditions.append("except_handler:swallowed_allow")
                    else:
                        conditions.append(f"except_handler:{h_action}")
                _walk_stmts(stmt.body)
                _walk_stmts(stmt.orelse)
                _walk_stmts(stmt.finalbody)
            elif isinstance(stmt, (ast.With, ast.AsyncWith, ast.For, ast.AsyncFor, ast.While)):
                _walk_stmts(getattr(stmt, "body", []))
                _walk_stmts(getattr(stmt, "orelse", []))

    _walk_stmts(body)
    if effective_asserts > 0 or trivial_asserts > 0:
        conditions.append(f"test_assertions:{effective_asserts}:{trivial_asserts}")
    if has_skip_call:
        conditions.append("test_skip_call:true")
    return tuple(dict.fromkeys(conditions))



def _extract_python_parse_result(source: str, file_path: str) -> ParseResult:
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        caps = build_capability_vector(
            syntax_state="failed",
            syntax_provenance=f"python-ast@{py_ver}",
            syntax_reason=f"SyntaxError at line {e.lineno}: {e.msg}",
        )
        return ParseResult(
            file_path=file_path,
            language="python",
            status=PARSER_STATUS_PARSE_ERROR,
            complete=False,
            incomplete_reason="Python syntax error prevented AST construction",
            error_detail=f"SyntaxError: {e}",
            frontend="python-ast",
            frontend_version=py_ver,
            capabilities=caps,
        )

    symbols: List[SymbolFact] = []
    call_sites: List[CallSiteFact] = []
    imports: List[str] = []
    explicit_all: Optional[set[str]] = None

    # First pass on module body: imports and __all__
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append(alias.name)
                if alias.asname:
                    imports.append(f"{alias.name} as {alias.asname}")
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            for alias in node.names:
                target = f"{mod}.{alias.name}" if mod else alias.name
                imports.append(target)
                if alias.asname:
                    imports.append(f"{target} as {alias.asname}")
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "__all__":
                    if isinstance(node.value, (ast.List, ast.Tuple, ast.Set)):
                        explicit_all = {
                            elt.value
                            for elt in node.value.elts
                            if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
                        }

    # Module-level calls
    _, mod_calls = _python_extract_calls(tree, "<module>", file_path, stop_at_nested_defs=True)
    call_sites.extend(mod_calls)

    def _is_public_name(name: str, parent_public: bool = True) -> Tuple[str, bool]:
        if not parent_public:
            return "private", False
        if explicit_all is not None and "." not in name:
            is_exp = name in explicit_all
            return ("public" if is_exp else "private"), is_exp
        if name.startswith("__") and name.endswith("__"):
            return "public", True
        if name.startswith("_"):
            return "private", False
        return "public", True

    def _visit_container(stmts: list, parent_qual: Optional[str], parent_public: bool):
        for node in stmts:
            if isinstance(node, ast.ClassDef):
                qual = f"{parent_qual}.{node.name}" if parent_qual else node.name
                vis, is_exp = _is_public_name(node.name, parent_public)
                decos = tuple(ast.unparse(d) for d in node.decorator_list)
                bases = ",".join(ast.unparse(b) for b in node.bases)
                sig = f"({bases})"
                body_hash, stmt_count, is_stub = _python_body_metrics(node.body)
                calls, cs = _python_extract_calls(node, qual, file_path, stop_at_nested_defs=True)
                call_sites.extend(cs)
                symbols.append(
                    SymbolFact(
                        schema_version=SYMBOL_FACT_SCHEMA_VERSION,
                        symbol_id=f"{file_path}::{qual}",
                        language="python",
                        kind="class",
                        name=node.name,
                        qualified_name=qual,
                        file_path=file_path,
                        start_line=getattr(node, "lineno", 1),
                        end_line=getattr(node, "end_lineno", getattr(node, "lineno", 1)),
                        visibility=vis,
                        is_exported=is_exp,
                        normalized_signature=sig,
                        parameter_count=len(node.bases),
                        required_parameter_count=len(node.bases),
                        decorators=decos,
                        body_hash=body_hash,
                        statement_count=stmt_count,
                        is_stub=is_stub,
                        calls=calls,
                        parent_symbol=parent_qual,
                        frontend="python-ast",
                        frontend_version=py_ver,
                    )
                )
                _visit_container(node.body, qual, vis == "public")

            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                is_method = parent_qual is not None
                qual = f"{parent_qual}.{node.name}" if parent_qual else node.name
                vis, is_exp = _is_public_name(node.name, parent_public)
                decos = tuple(ast.unparse(d) for d in node.decorator_list)
                sig, p_cnt, req_cnt = _python_signature(node, is_method=is_method)
                body_hash, stmt_count, is_stub = _python_body_metrics(node.body)
                calls, cs = _python_extract_calls(node, qual, file_path, stop_at_nested_defs=True)
                g_conds = _python_extract_guard_conditions(node)
                call_sites.extend(cs)
                symbols.append(
                    SymbolFact(
                        schema_version=SYMBOL_FACT_SCHEMA_VERSION,
                        symbol_id=f"{file_path}::{qual}",
                        language="python",
                        kind="method" if is_method else "function",
                        name=node.name,
                        qualified_name=qual,
                        file_path=file_path,
                        start_line=getattr(node, "lineno", 1),
                        end_line=getattr(node, "end_lineno", getattr(node, "lineno", 1)),
                        visibility=vis,
                        is_exported=is_exp,
                        normalized_signature=sig,
                        parameter_count=p_cnt,
                        required_parameter_count=req_cnt,
                        decorators=decos,
                        body_hash=body_hash,
                        statement_count=stmt_count,
                        is_stub=is_stub,
                        calls=calls,
                        guard_conditions=g_conds,
                        parent_symbol=parent_qual,
                        frontend="python-ast",
                        frontend_version=py_ver,
                    )
                )
                _visit_container(node.body, qual, False)

            elif parent_qual is None and isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                val_node = getattr(node, "value", None)
                val_dump = ast.dump(val_node, include_attributes=False) if val_node else "None"
                b_hash = _hash_normalized_text(val_dump)
                for target in targets:
                    if isinstance(target, ast.Name):
                        vis, is_exp = _is_public_name(target.id, True)
                        kind = "constant" if target.id.isupper() else "variable"
                        symbols.append(
                            SymbolFact(
                                schema_version=SYMBOL_FACT_SCHEMA_VERSION,
                                symbol_id=f"{file_path}::{target.id}",
                                language="python",
                                kind=kind,
                                name=target.id,
                                qualified_name=target.id,
                                file_path=file_path,
                                start_line=getattr(node, "lineno", 1),
                                end_line=getattr(node, "end_lineno", getattr(node, "lineno", 1)),
                                visibility=vis,
                                is_exported=is_exp,
                                normalized_signature="=",
                                parameter_count=0,
                                required_parameter_count=0,
                                decorators=(),
                                body_hash=b_hash,
                                statement_count=1,
                                is_stub=False,
                                calls=(),
                                parent_symbol=None,
                                frontend="python-ast",
                                frontend_version=py_ver,
                            )
                        )

    _visit_container(tree.body, None, True)
    symbols.sort(key=lambda s: (s.start_line, s.end_line, s.qualified_name, s.kind))
    legacy_names = sorted(extract_named_nodes(source, file_path))
    exports = sorted({s.qualified_name for s in symbols if s.is_exported})

    caps = build_capability_vector(
        syntax_state="available",
        syntax_provenance=f"python-ast@{py_ver}",
        syntax_reason="AST parsed cleanly via stdlib ast",
        symbolic_state="partial",
        symbolic_reason="Intra-file declarations, scopes, and call sites extracted via AST",
        flow_state="partial",
        flow_reason="Intra-function guard calls and decorators extracted",
    )

    return ParseResult(
        file_path=file_path,
        language="python",
        status=PARSER_STATUS_AVAILABLE,
        complete=True,
        frontend="python-ast",
        frontend_version=py_ver,
        symbols=symbols,
        named_nodes=legacy_names,
        call_sites=call_sites,
        imports=sorted(set(imports)),
        exports=exports,
        capabilities=caps,
    )


# ==============================================================================
# TREE-SITTER SYMBOL FACT EXTRACTION (JS, TS, TSX, Go, Rust, Java)
# ==============================================================================

_COMMENT_NODE_TYPES = frozenset({
    "comment", "line_comment", "block_comment", "doc_comment",
})


def _ts_node_text(node) -> str:
    if node is None or node.text is None:
        return ""
    return node.text.decode("utf-8", errors="replace")


def _ts_non_comment_tokens(node) -> List[str]:
    """Collect leaf token strings excluding comments."""
    tokens: List[str] = []

    def _walk(n):
        if n.type in _COMMENT_NODE_TYPES:
            return
        if len(n.children) == 0:
            txt = _ts_node_text(n).strip()
            if txt:
                tokens.append(txt)
        else:
            for c in n.children:
                _walk(c)

    if node is not None:
        _walk(node)
    return tokens


def _ts_body_metrics(body_node) -> Tuple[str, int, bool]:
    if body_node is None:
        return _hash_normalized_text("STUB"), 0, True
    tokens = _ts_non_comment_tokens(body_node)
    # Strip enclosing braces { }
    if len(tokens) >= 2 and tokens[0] == "{" and tokens[-1] == "}":
        inner = tokens[1:-1]
    else:
        inner = tokens
    inner_clean = [t for t in inner if t not in (";", ",")]
    if not inner_clean:
        return _hash_normalized_text("STUB"), 0, True
    joined = " ".join(inner_clean)
    if joined in ("return", "return null", "return nil", "todo ! ( )", "unimplemented ! ( )"):
        return _hash_normalized_text("STUB"), 1, True
    # Approximate statement count by counting statement-like child nodes
    stmt_count = sum(
        1
        for ch in body_node.children
        if ch.type not in ("{", "}", ";") and ch.type not in _COMMENT_NODE_TYPES
    )
    return _hash_normalized_text(joined), max(stmt_count, 1), False


def _ts_param_metrics(params_node, lang_key: str) -> Tuple[str, int, int]:
    if params_node is None:
        return "()", 0, 0
    tokens = _ts_non_comment_tokens(params_node)
    sig = "".join(tokens)
    # Count parameters excluding receiver/self
    param_children = [
        c for c in params_node.children
        if c.type not in ("(", ")", ",", "self_parameter") and c.type not in _COMMENT_NODE_TYPES
    ]
    total = len(param_children)
    required = 0
    for c in param_children:
        txt = _ts_node_text(c)
        if c.type in ("optional_parameter", "assignment_pattern", "rest_pattern", "variadic_parameter_declaration"):
            continue
        if "?" in txt or "=" in txt or "..." in txt:
            continue
        required += 1
    return sig, total, required


def _ts_extract_calls(node, caller_qual: str, file_path: str, lang_key: str) -> Tuple[Tuple[str, ...], List[CallSiteFact]]:
    calls: List[str] = []
    call_sites: List[CallSiteFact] = []
    nested_stop = {
        "function_declaration", "method_definition", "arrow_function",
        "function_item", "method_declaration", "class_declaration",
    }

    def _walk(curr, is_root: bool = False):
        if not is_root and curr.type in nested_stop:
            return
        if curr.type in ("call_expression", "method_invocation"):
            callee = ""
            qualifier = ""
            args_node = curr.child_by_field_name("arguments")
            arg_count = 0
            if args_node is not None:
                arg_count = sum(
                    1 for c in args_node.children
                    if c.type not in ("(", ")", ",") and c.type not in _COMMENT_NODE_TYPES
                )
            if curr.type == "method_invocation":
                name_n = curr.child_by_field_name("name")
                obj_n = curr.child_by_field_name("object")
                callee = _ts_node_text(name_n)
                qualifier = _ts_node_text(obj_n)
            else:
                fn_n = curr.child_by_field_name("function")
                if fn_n is not None:
                    if fn_n.type == "identifier":
                        callee = _ts_node_text(fn_n)
                    elif fn_n.type in ("member_expression", "selector_expression", "field_expression", "scoped_identifier"):
                        parts = _ts_node_text(fn_n).rsplit(".", 1)
                        if len(parts) == 2:
                            qualifier, callee = parts[0].strip(), parts[1].strip()
                        elif "::" in _ts_node_text(fn_n):
                            parts = _ts_node_text(fn_n).rsplit("::", 1)
                            qualifier, callee = parts[0].strip(), parts[1].strip()
                        else:
                            callee = _ts_node_text(fn_n)
            if callee:
                full = f"{qualifier}.{callee}" if qualifier else callee
                calls.append(full)
                call_sites.append(
                    CallSiteFact(
                        file_path=file_path,
                        line=curr.start_point[0] + 1,
                        caller_qualified_name=caller_qual,
                        callee_name=callee,
                        qualifier=qualifier,
                        arg_count=arg_count,
                    )
                )
        for ch in curr.children:
            _walk(ch, False)

    if node is not None:
        _walk(node, True)
    return tuple(dict.fromkeys(calls)), call_sites


def _ts_stmt_action(block_node) -> str:
    """Classify the enforcement action of a Tree-sitter block/consequence/catch body."""
    if block_node is None:
        return "noop"
    tokens = _ts_non_comment_tokens(block_node)
    if len(tokens) >= 2 and tokens[0] == "{" and tokens[-1] == "}":
        inner = tokens[1:-1]
    else:
        inner = tokens
    inner_clean = [t for t in inner if t not in (";", ",")]
    if not inner_clean:
        return "noop"

    joined = " ".join(inner_clean)
    if (
        "throw " in joined
        or tokens[0] == "throw"
        or "panic !" in joined
        or "panic (" in joined
        or "os . Exit" in joined
        or "t . Fatal" in joined
        or "http . Error" in joined
        or "fmt . Errorf" in joined
        or "errors . New" in joined
        or "res . status ( 401 )" in joined
        or "res . status ( 403 )" in joined
    ):
        return "raise"
    if "rollback" in joined.lower() or "abort" in joined.lower():
        return "rollback"
    if (
        "return false" in joined
        or "return null" in joined
        or "return nil" in joined
        or "return Err" in joined
        or re.search(r"\breturn\b[^;{}]*\berr\b", joined)
    ):
        return "return_deny"
    if "return true" in joined or "return Ok" in joined:
        return "return_allow"
    if "return" in inner_clean:
        return "return_val"

    # Check if only console.log / logger / fmt.Println
    stmt_children = [
        c for c in block_node.children
        if c.type not in ("{", "}", ";") and c.type not in _COMMENT_NODE_TYPES
    ]
    if stmt_children and all(
        any(q in _ts_node_text(c) for q in ("console.", "logger.", "log.", "fmt.Print", "println!"))
        for c in stmt_children
    ):
        return "noop"
    return "branch"


def _ts_extract_guard_conditions(body_node, lang_key: str) -> Tuple[str, ...]:
    """
    Extract intra-function guard condition and test contract descriptors from a Tree-sitter body:
    - if_guard:<callee>:<polarity>:<action>
    - if_state_guard:<subject>:<polarity>:<action>
    - if_short_circuit:<target>:<and_false|or_true>:<action>
    - early_return_bypass:<action>
    - except_handler:<action>
    - test_assertions:<effective_count>:<trivial_count>
    - test_skip_call:true
    """
    if body_node is None:
        return ()

    conditions: List[str] = []
    nested_stop = {
        "function_declaration", "method_definition", "arrow_function",
        "function_item", "method_declaration", "class_declaration",
    }

    # 1. Early unconditional return followed by unreachable statements in top-level block
    stmt_children = [
        c for c in body_node.children
        if c.type not in ("{", "}", ";") and c.type not in _COMMENT_NODE_TYPES
    ]
    for idx, ch in enumerate(stmt_children):
        if ch.type in ("return_statement", "return_expression") and idx < len(stmt_children) - 1:
            txt = " ".join(_ts_non_comment_tokens(ch))
            if "true" in txt:
                conditions.append("early_return_bypass:return_allow")
            elif any(k in txt for k in ("false", "null", "nil")):
                conditions.append("early_return_bypass:return_deny")
            else:
                conditions.append("early_return_bypass:unconditional")
            break

    effective_asserts = 0
    trivial_asserts = 0
    has_skip_call = False

    def _walk(curr, is_root: bool = False):
        nonlocal effective_asserts, trivial_asserts, has_skip_call
        if not is_root and curr.type in nested_stop:
            return

        # Track test assertions & skip calls across JS/TS/Go/Rust/Java
        if curr.type in ("call_expression", "method_invocation"):
            txt = " ".join(_ts_non_comment_tokens(curr))
            fn_node = curr.child_by_field_name("function") if curr.type == "call_expression" else curr.child_by_field_name("name")
            obj_node = curr.child_by_field_name("object") if curr.type == "method_invocation" else None
            fn_txt = _ts_node_text(fn_node).strip() if fn_node else ""
            obj_txt = _ts_node_text(obj_node).strip() if obj_node else ""
            full_fn = f"{obj_txt}.{fn_txt}" if obj_txt else fn_txt

            if full_fn in ("t.Skip", "t.SkipNow", "t.Skipf", "it.skip", "test.skip", "describe.skip"):
                has_skip_call = True
            elif fn_txt == "expect":
                # Inspect parent chain for trivial `expect(true).toBe(true)` or `expect(1).toBe(1)`
                outer_txt = txt
                if curr.parent is not None and curr.parent.parent is not None and curr.parent.parent.type == "call_expression":
                    outer_txt = " ".join(_ts_non_comment_tokens(curr.parent.parent))
                if re.match(r"^expect\s*\(\s*(?:true|1)\s*\)\s*\.\s*(?:toBe|toEqual|toBeTruthy)\s*\(\s*(?:true|1)?\s*\)$", outer_txt):
                    trivial_asserts += 1
                else:
                    effective_asserts += 1
            elif (
                fn_txt in ("assert", "assertEquals", "assertTrue", "assertFalse", "assertNotNull", "assertNull", "assertThrows", "assertThat")
                or full_fn.startswith(("assert.", "require."))
                or full_fn in ("t.Error", "t.Errorf", "t.Fatal", "t.Fatalf")
            ):
                if re.match(r"^(?:assert|assert\.ok|assertTrue)\s*\(\s*(?:true|1)\s*\)$", txt):
                    trivial_asserts += 1
                else:
                    effective_asserts += 1
        elif curr.type == "macro_invocation":
            m_txt = " ".join(_ts_non_comment_tokens(curr))
            if m_txt.startswith(("assert !", "assert_eq !", "assert_ne !")):
                if re.match(r"^assert\s*!\s*\(\s*true\s*\)$", m_txt) or re.match(
                    r"^assert_eq\s*!\s*\(\s*(?:true\s*,\s*true|1\s*,\s*1)\s*\)$", m_txt
                ):
                    trivial_asserts += 1
                else:
                    effective_asserts += 1

        if curr.type in ("if_statement", "if_expression"):
            cond = curr.child_by_field_name("condition")
            conseq = curr.child_by_field_name("consequence")
            if cond is not None:
                cond_txt = " ".join(_ts_non_comment_tokens(cond)).strip()
                if cond_txt.startswith("(") and cond_txt.endswith(")"):
                    cond_txt = cond_txt[1:-1].strip()
                polarity = "positive"
                if (
                    cond_txt.startswith("!")
                    or cond_txt.startswith("not ")
                    or "== false" in cond_txt
                    or "=== false" in cond_txt
                    or "!= true" in cond_txt
                    or "!== true" in cond_txt
                ):
                    polarity = "negated"
                calls_in_cond, _ = _ts_extract_calls(cond, "<cond>", "", lang_key)
                action = _ts_stmt_action(conseq)

                is_and_false = bool(
                    re.search(r"(?:&&\s*false\b|\bfalse\s*&&)", cond_txt, re.IGNORECASE)
                    or cond_txt.lower() == "false"
                )
                is_or_true = bool(
                    re.search(r"(?:\|\|\s*true\b|\btrue\s*\|\|)", cond_txt, re.IGNORECASE)
                    or cond_txt.lower() == "true"
                )
                if is_and_false or is_or_true:
                    sc_kind = "and_false" if is_and_false else "or_true"
                    if calls_in_cond:
                        for callee in calls_in_cond:
                            conditions.append(f"if_short_circuit:{callee}:{sc_kind}:{action}")
                    elif action in ("raise", "rollback", "return_deny", "return_allow"):
                        conditions.append(f"if_short_circuit:state_guard:{sc_kind}:{action}")
                elif calls_in_cond:
                    for callee in calls_in_cond:
                        conditions.append(f"if_guard:{callee}:{polarity}:{action}")
                elif (
                    action in ("raise", "rollback")
                    or (lang_key == "go" and re.search(r"\berr\s*!=\s*nil\b", cond_txt) and action in ("return_deny", "return_val"))
                    or (action == "return_deny" and _STATE_GUARD_IDENT_RE.search(cond_txt))
                ):
                    subj = cond_txt.lstrip("!").strip()
                    if subj.startswith("not "):
                        subj = subj[4:].strip()
                    subj = re.sub(r"\s+", "", subj).replace(":", "_")
                    if subj:
                        conditions.append(f"if_state_guard:{subj}:{polarity}:{action}")
        elif curr.type == "catch_clause":
            c_body = curr.child_by_field_name("body")
            c_action = _ts_stmt_action(c_body)
            if c_action == "noop":
                conditions.append("except_handler:swallowed_noop")
            elif c_action == "return_allow":
                conditions.append("except_handler:swallowed_allow")
            else:
                conditions.append(f"except_handler:{c_action}")

        for ch in curr.children:
            _walk(ch, False)

    _walk(body_node, True)
    if effective_asserts > 0 or trivial_asserts > 0:
        conditions.append(f"test_assertions:{effective_asserts}:{trivial_asserts}")
    if has_skip_call:
        conditions.append("test_skip_call:true")
    return tuple(dict.fromkeys(conditions))


def _extract_commonjs_exports(root_node) -> set[str]:
    """Detect `module.exports = { a, b }` or `exports.a = ...` in JS/TS."""
    exported: set[str] = set()

    def _walk(n):
        if n.type == "assignment_expression":
            left = n.child_by_field_name("left")
            right = n.child_by_field_name("right")
            left_txt = _ts_node_text(left)
            if left_txt in ("module.exports", "exports") and right is not None:
                if right.type == "object":
                    for ch in right.children:
                        if ch.type == "shorthand_property_identifier":
                            exported.add(_ts_node_text(ch))
                        elif ch.type == "pair":
                            k = ch.child_by_field_name("key")
                            if k:
                                exported.add(_ts_node_text(k))
                elif right.type == "identifier":
                    exported.add(_ts_node_text(right))
            elif left_txt.startswith("exports.") or left_txt.startswith("module.exports."):
                prop = left_txt.split(".")[-1]
                if prop:
                    exported.add(prop)
        for c in n.children:
            _walk(c)

    _walk(root_node)
    return exported


def _extract_treesitter_parse_result(source: str, file_path: str, lang_key: str) -> ParseResult:
    ts_ver = _treesitter_version()
    ts_lang = _load_language(lang_key)
    if ts_lang is None:
        caps = build_capability_vector(
            syntax_state="unavailable",
            syntax_provenance="tree-sitter",
            syntax_reason=f"Tree-sitter grammar for '{lang_key}' is not installed",
        )
        return ParseResult(
            file_path=file_path,
            language=lang_key,
            status=PARSER_STATUS_GRAMMAR_UNAVAILABLE,
            complete=False,
            incomplete_reason=f"Missing Tree-sitter grammar package for '{lang_key}'",
            frontend="tree-sitter",
            frontend_version=ts_ver,
            capabilities=caps,
        )

    from tree_sitter import Parser
    parser = Parser(ts_lang)
    tree = parser.parse(bytes(source, "utf-8"))
    root = tree.root_node

    has_syntax_error = bool(getattr(root, "has_error", False))
    symbols: List[SymbolFact] = []
    call_sites: List[CallSiteFact] = []
    imports: List[str] = []
    commonjs_exports = _extract_commonjs_exports(root) if lang_key in ("javascript", "typescript", "tsx") else set()

    def _has_export_ancestor(n) -> bool:
        curr = n.parent
        while curr is not None:
            if curr.type == "export_statement":
                return True
            curr = curr.parent
        return False

    def _child_modifiers_text(n) -> str:
        parts = []
        for ch in n.children:
            if ch.type in ("modifiers", "visibility_modifier", "accessibility_modifier"):
                parts.append(_ts_node_text(ch))
        return " ".join(parts)

    def _decorators_for_node(n) -> Tuple[str, ...]:
        decos = []
        for ch in n.children:
            if ch.type in ("decorator", "marker_annotation", "annotation", "attribute_item"):
                decos.append(_ts_node_text(ch).strip())
            elif ch.type == "modifiers":
                for sub in ch.children:
                    if sub.type in ("marker_annotation", "annotation"):
                        decos.append(_ts_node_text(sub).strip())
        return tuple(decos)

    def _go_receiver_type(method_node) -> Optional[str]:
        rec = method_node.child_by_field_name("receiver")
        if rec is None:
            return None
        # Look for type_identifier inside receiver parameter_list
        for ch in rec.children:
            if ch.type == "parameter_declaration":
                t_node = ch.child_by_field_name("type")
                if t_node is not None:
                    return _ts_node_text(t_node).lstrip("*").strip()
        txt = _ts_node_text(rec).strip("()")
        parts = txt.split()
        if parts:
            return parts[-1].lstrip("*")
        return None

    def _walk(node, parent_qual: Optional[str], parent_exported: bool):
        ntype = node.type

        # Collect imports
        if ntype in ("import_statement", "import_declaration", "use_declaration"):
            imports.append(_ts_node_text(node).strip())

        # Rust impl blocks qualify their inner function_items
        if lang_key == "rust" and ntype == "impl_item":
            type_node = node.child_by_field_name("type")
            impl_type = _ts_node_text(type_node).split("<")[0].strip() if type_node else "impl"
            body = node.child_by_field_name("body")
            if body:
                for ch in body.children:
                    _walk(ch, impl_type, True)
            return

        rules = _LANG_RULES[lang_key]
        name_field = rules.get(ntype)

        # Also handle Rust trait signature items
        if lang_key == "rust" and ntype == "function_signature_item":
            name_field = "name"

        if name_field:
            name_node = node.child_by_field_name(name_field)
            name = _ts_node_text(name_node).strip() if name_node else ""
            if name:
                container = parent_qual
                if lang_key == "go" and ntype == "method_declaration":
                    rec_type = _go_receiver_type(node)
                    if rec_type:
                        container = rec_type

                qual = f"{container}.{name}" if container else name

                # Kind mapping
                if ntype in ("class_declaration",):
                    kind = "class"
                elif ntype in ("interface_declaration",):
                    kind = "interface"
                elif ntype in ("struct_item",):
                    kind = "struct"
                elif ntype in ("enum_item", "enum_declaration"):
                    kind = "enum"
                elif ntype in ("trait_item",):
                    kind = "trait"
                elif ntype in ("type_alias_declaration", "type_spec"):
                    t_child = node.child_by_field_name("type")
                    if t_child is not None and t_child.type == "struct_type":
                        kind = "struct"
                    elif t_child is not None and t_child.type == "interface_type":
                        kind = "interface"
                    else:
                        kind = "type_alias"
                elif ntype in ("const_spec", "const_item", "static_item"):
                    kind = "constant"
                elif ntype in ("method_definition", "method_declaration") or container is not None:
                    kind = "method"
                else:
                    kind = "function"

                # Visibility & export resolution
                mods = _child_modifiers_text(node)
                if lang_key == "go":
                    is_exp = bool(name and name[0].isupper()) and (parent_exported if container else True)
                    vis = "public" if is_exp else "private"
                elif lang_key == "rust":
                    has_pub = "pub" in mods.split() or mods.startswith("pub(")
                    is_exp = (has_pub or ntype == "function_signature_item") and (parent_exported if container else True)
                    vis = "public" if is_exp else "private"
                elif lang_key == "java":
                    if "private" in mods.split():
                        vis, is_exp = "private", False
                    elif "protected" in mods.split():
                        vis, is_exp = "protected", True
                    elif "public" in mods.split() or ntype == "method_declaration" and parent_exported:
                        vis, is_exp = "public", True
                    else:
                        vis, is_exp = "package", False
                else:
                    # JS / TS / TSX
                    if "private" in mods.split() or name.startswith("_") or name.startswith("#"):
                        vis, is_exp = "private", False
                    elif "protected" in mods.split():
                        vis, is_exp = "protected", False
                    else:
                        vis = "public"
                        if container:
                            is_exp = parent_exported
                        else:
                            is_exp = _has_export_ancestor(node) or (name in commonjs_exports)

                params_node = node.child_by_field_name("parameters")
                sig, p_cnt, req_cnt = _ts_param_metrics(params_node, lang_key)
                ret_node = (
                    node.child_by_field_name("return_type")
                    or node.child_by_field_name("result")
                    or node.child_by_field_name("type")
                )
                if ret_node is not None and ntype not in ("type_spec", "const_item"):
                    ret_txt = "".join(_ts_non_comment_tokens(ret_node)).lstrip(":")
                    if ret_txt:
                        sig = f"{sig}->{ret_txt}"

                body_node = (
                    node.child_by_field_name("body")
                    or node.child_by_field_name("value")
                    or (node.child_by_field_name("type") if ntype == "type_spec" else None)
                )
                b_hash, stmt_cnt, is_stub = _ts_body_metrics(body_node)
                calls, cs = _ts_extract_calls(body_node or node, qual, file_path, lang_key)
                g_conds = _ts_extract_guard_conditions(body_node, lang_key) if kind in ("function", "method") else ()
                call_sites.extend(cs)

                symbols.append(
                    SymbolFact(
                        schema_version=SYMBOL_FACT_SCHEMA_VERSION,
                        symbol_id=f"{file_path}::{qual}",
                        language=lang_key,
                        kind=kind,
                        name=name,
                        qualified_name=qual,
                        file_path=file_path,
                        start_line=node.start_point[0] + 1,
                        end_line=node.end_point[0] + 1,
                        visibility=vis,
                        is_exported=is_exp,
                        normalized_signature=sig,
                        parameter_count=p_cnt,
                        required_parameter_count=req_cnt,
                        decorators=_decorators_for_node(node),
                        body_hash=b_hash,
                        statement_count=stmt_cnt,
                        is_stub=is_stub,
                        calls=calls,
                        guard_conditions=g_conds,
                        parent_symbol=container,
                        frontend="tree-sitter",
                        frontend_version=ts_ver,
                    )
                )

                # Recurse into class/interface/trait/function/method bodies with container context
                if kind in ("class", "interface", "trait", "enum", "struct", "function", "method"):
                    child_exported = is_exp if kind in ("class", "interface", "trait", "enum", "struct") else False
                    for ch in node.children:
                        _walk(ch, qual, child_exported)
                    return

        elif ntype == "variable_declarator" and "function_declaration" in rules and parent_qual is None:
            name_node = node.child_by_field_name("name")
            val_node = node.child_by_field_name("value")
            name = _ts_node_text(name_node).strip() if name_node else ""
            if val_node is not None and "require(" in _ts_node_text(val_node):
                imports.append(_ts_node_text(node).strip())
            if name and not name.startswith("{") and not name.startswith("["):
                is_arrow = val_node is not None and val_node.type in ("arrow_function", "function_expression", "function")
                kind = "function" if is_arrow else ("constant" if name.isupper() else "variable")
                is_exp = _has_export_ancestor(node) or (name in commonjs_exports)
                vis = "private" if name.startswith("_") else ("public" if is_exp else "module")
                if is_arrow:
                    params_node = val_node.child_by_field_name("parameters")
                    sig, p_cnt, req_cnt = _ts_param_metrics(params_node, lang_key)
                    body_node = val_node.child_by_field_name("body")
                    b_hash, stmt_cnt, is_stub = _ts_body_metrics(body_node)
                    calls, cs = _ts_extract_calls(val_node, name, file_path, lang_key)
                    g_conds = _ts_extract_guard_conditions(body_node, lang_key)
                    call_sites.extend(cs)
                else:
                    sig, p_cnt, req_cnt = "=", 0, 0
                    b_hash, stmt_cnt, is_stub = _ts_body_metrics(val_node)
                    calls, cs = _ts_extract_calls(val_node, name, file_path, lang_key)
                    g_conds = ()
                    call_sites.extend(cs)
                symbols.append(
                    SymbolFact(
                        schema_version=SYMBOL_FACT_SCHEMA_VERSION,
                        symbol_id=f"{file_path}::{name}",
                        language=lang_key,
                        kind=kind,
                        name=name,
                        qualified_name=name,
                        file_path=file_path,
                        start_line=node.start_point[0] + 1,
                        end_line=node.end_point[0] + 1,
                        visibility=vis,
                        is_exported=is_exp,
                        normalized_signature=sig,
                        parameter_count=p_cnt,
                        required_parameter_count=req_cnt,
                        decorators=(),
                        body_hash=b_hash,
                        statement_count=stmt_cnt,
                        is_stub=is_stub,
                        calls=calls,
                        guard_conditions=g_conds,
                        parent_symbol=None,
                        frontend="tree-sitter",
                        frontend_version=ts_ver,
                    )
                )
                return

        for ch in node.children:
            _walk(ch, parent_qual, parent_exported)

    _, mod_cs = _ts_extract_calls(root, "<module>", file_path, lang_key)
    call_sites.extend(mod_cs)
    _walk(root, None, True)
    symbols.sort(key=lambda s: (s.start_line, s.end_line, s.qualified_name, s.kind))
    # Deduplicate call sites deterministically (prefer specific caller over <module>)
    dedup_cs: Dict[Tuple[str, int, str, str], CallSiteFact] = {}
    for cs in call_sites:
        key = (cs.file_path, cs.line, cs.callee_name, cs.qualifier)
        if key not in dedup_cs or dedup_cs[key].caller_qualified_name == "<module>":
            dedup_cs[key] = cs
    call_sites = sorted(dedup_cs.values(), key=lambda c: (c.line, c.callee_name, c.caller_qualified_name))
    legacy_names: set[str] = set()
    _collect(root, _LANG_RULES[lang_key], legacy_names)
    exports = sorted({s.qualified_name for s in symbols if s.is_exported})

    if has_syntax_error:
        caps = build_capability_vector(
            syntax_state="partial",
            syntax_provenance=f"tree-sitter@{ts_ver}",
            syntax_reason="Tree-sitter syntax tree contains ERROR/MISSING nodes; partial recovery only",
            symbolic_state="partial",
            symbolic_reason="Symbols extracted from error-recovered syntax tree",
        )
        return ParseResult(
            file_path=file_path,
            language=lang_key,
            status=PARSER_STATUS_PARSE_ERROR,
            complete=False,
            incomplete_reason="Syntax error node(s) detected in Tree-sitter parse tree",
            error_detail="tree.root_node.has_error == True",
            frontend="tree-sitter",
            frontend_version=ts_ver,
            symbols=symbols,
            named_nodes=sorted(legacy_names),
            call_sites=call_sites,
            imports=sorted(set(imports)),
            exports=exports,
            capabilities=caps,
        )

    caps = build_capability_vector(
        syntax_state="available",
        syntax_provenance=f"tree-sitter@{ts_ver}",
        syntax_reason=f"Tree-sitter '{lang_key}' grammar parsed cleanly",
        symbolic_state="partial",
        symbolic_reason="Intra-file declarations, scopes, and call sites extracted via Tree-sitter",
        flow_state="partial",
        flow_reason="Intra-function call sites extracted",
    )

    return ParseResult(
        file_path=file_path,
        language=lang_key,
        status=PARSER_STATUS_AVAILABLE,
        complete=True,
        frontend="tree-sitter",
        frontend_version=ts_ver,
        symbols=symbols,
        named_nodes=sorted(legacy_names),
        call_sites=call_sites,
        imports=sorted(set(imports)),
        exports=exports,
        capabilities=caps,
    )


def extract_symbols(source: str, path: str) -> ParseResult:
    """
    Extract rich SymbolFact records, call sites, and explicit completeness
    status for a source file. Never silently equates missing grammar or
    unsupported extensions with 'nothing removed'.
    """
    lang_key = language_for_path(path)
    if lang_key is None:
        ext = Path(path).suffix.lower() or "<no-extension>"
        caps = build_capability_vector(
            syntax_state="unavailable",
            syntax_provenance="none",
            syntax_reason=f"Extension '{ext}' has no registered structural parser",
        )
        return ParseResult(
            file_path=path,
            language=None,
            status=PARSER_STATUS_UNSUPPORTED_EXTENSION,
            complete=False,
            incomplete_reason=f"Unsupported file extension '{ext}'",
            frontend="none",
            frontend_version="0",
            capabilities=caps,
        )
    if lang_key == "python":
        return _extract_python_parse_result(source, path)
    try:
        return _extract_treesitter_parse_result(source, path, lang_key)
    except Exception as e:
        ts_ver = _treesitter_version()
        caps = build_capability_vector(
            syntax_state="failed",
            syntax_provenance=f"tree-sitter@{ts_ver}",
            syntax_reason=f"Exception during Tree-sitter extraction: {e}",
        )
        return ParseResult(
            file_path=path,
            language=lang_key,
            status=PARSER_STATUS_PARSE_ERROR,
            complete=False,
            incomplete_reason="Parser raised exception during syntax extraction",
            error_detail=str(e),
            frontend="tree-sitter",
            frontend_version=ts_ver,
            capabilities=caps,
        )
