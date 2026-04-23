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

    def test_default_benign_keywords_present(self):
        cfg = PayloadGuardConfig()
        self.assertIn("typo", cfg.semantic["benign_keywords"])


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
        # Unspecified sibling key is preserved
        self.assertEqual(cfg.thresholds["structural"]["min_deleted_nodes"], 3)

    def test_deep_merges_partial_temporal_override(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "payloadguard.yml"), "w") as f:
                f.write("thresholds:\n  temporal:\n    stale: 100\n")
            cfg = load_config(d)
        self.assertEqual(cfg.thresholds["temporal"]["stale"], 100)
        # Unspecified sibling key is preserved
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

    # False-positive checks — the main improvement over substring matching
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
        # 2-function file losing 1: ratio 50% exceeds threshold but count (1) < 3
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
        # Ratio gate requires >= 100 lines deleted to fire
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
        # Ratio gate requires >= 100 lines deleted; combine with file flag for CAUTION
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
        # ratio+lines both fire → deletion_dim capped at 4, no age → CAUTION not DESTRUCTIVE
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
        # 35 days > custom threshold of 30 — would be SAFE with default (90)
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

        # Build numstat output from mock diff blobs so line-count tests work.
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
        d.a_mode = 0o100644  # regular non-executable
        d.b_mode = 0o100755  # executable
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

class TestSemanticTransparencyAnalyzer(unittest.TestCase):
    def test_empty_description_is_unverified(self):
        result = SemanticTransparencyAnalyzer("", "CRITICAL").analyze_transparency()
        self.assertEqual(result["status"], "UNVERIFIED")
        self.assertFalse(result["is_deceptive"])

    def test_benign_desc_with_critical_severity_is_deceptive(self):
        result = SemanticTransparencyAnalyzer("minor syntax fix", "CRITICAL").analyze_transparency()
        self.assertTrue(result["is_deceptive"])
        self.assertEqual(result["status"], "DECEPTIVE_PAYLOAD")

    def test_benign_desc_with_low_severity_is_transparent(self):
        result = SemanticTransparencyAnalyzer("minor syntax fix", "LOW").analyze_transparency()
        self.assertFalse(result["is_deceptive"])
        self.assertEqual(result["status"], "TRANSPARENT")

    def test_non_benign_desc_with_critical_severity_is_transparent(self):
        result = SemanticTransparencyAnalyzer(
            "refactored entire auth system", "CRITICAL"
        ).analyze_transparency()
        self.assertFalse(result["is_deceptive"])
        self.assertEqual(result["status"], "TRANSPARENT")

    def test_matched_keyword_returned(self):
        result = SemanticTransparencyAnalyzer("just a typo fix", "CRITICAL").analyze_transparency()
        self.assertEqual(result["matched_keyword"], "typo")

    def test_description_lowercased_before_matching(self):
        result = SemanticTransparencyAnalyzer("Minor Fix in spacing", "CRITICAL").analyze_transparency()
        self.assertTrue(result["is_deceptive"])

    def test_custom_keywords(self):
        result = SemanticTransparencyAnalyzer(
            "nit pick change", "CRITICAL", benign_keywords=["nit pick"]
        ).analyze_transparency()
        self.assertTrue(result["is_deceptive"])

    def test_directive_present(self):
        result = SemanticTransparencyAnalyzer("minor fix", "LOW").analyze_transparency()
        self.assertIn("directive", result)

    def test_no_match_gives_none_keyword(self):
        result = SemanticTransparencyAnalyzer(
            "overhaul authentication layer", "CRITICAL"
        ).analyze_transparency()
        self.assertIsNone(result["matched_keyword"])


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
        """numstat returns '-' for binary files; those must not be counted."""
        inner = TestAnalyzeSuccess()
        a = inner._setup_repo([])
        # One binary deletion (-/-) plus one normal deletion (0/8)
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

    def test_small_critical_deletions_adds_one_point(self):
        v = self.a._assess_consequence(0, 0, 0, 0, critical_file_deletions=1)
        self.assertEqual(v["severity_score"], 1)
        self.assertEqual(v["status"], "REVIEW")

    def test_many_critical_deletions_adds_two_points(self):
        v = self.a._assess_consequence(0, 0, 0, 0, critical_file_deletions=6)
        self.assertEqual(v["severity_score"], 2)
        self.assertEqual(v["status"], "REVIEW")

    def test_critical_deletions_combined_reach_caution(self):
        # age(1) + critical(2) = 3 → CAUTION
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
        """Import post_check_run, skipping if the crypto stack is unavailable."""
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
        """When PAYLOADGUARD_APP_ID is absent main() prints and returns before touching jwt."""
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


if __name__ == "__main__":
    unittest.main()
