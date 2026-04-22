import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from io import StringIO
from unittest.mock import MagicMock, patch

import git

from analyze import (
    PayloadAnalyzer,
    SemanticTransparencyAnalyzer,
    StructuralPayloadAnalyzer,
    TemporalDriftAnalyzer,
    print_report,
    save_json_report,
)


def _make_analyzer(branch="feature", target="main"):
    with patch("git.Repo"):
        return PayloadAnalyzer("/fake/repo", branch, target)


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
# LAYER 4 — StructuralPayloadAnalyzer
# ==============================================================================

class TestStructuralPayloadAnalyzer(unittest.TestCase):
    def test_no_deletions_status_is_safe(self):
        result = StructuralPayloadAnalyzer(SIMPLE_ORIGINAL, SIMPLE_ORIGINAL).analyze_structural_drift()
        self.assertEqual(result["status"], "SAFE")
        self.assertEqual(result["metrics"]["deleted_node_count"], 0)

    def test_detects_deleted_classes(self):
        result = StructuralPayloadAnalyzer(SIMPLE_ORIGINAL, SIMPLE_MODIFIED).analyze_structural_drift()
        self.assertIn("Database", result["deleted_components"])
        self.assertIn("Cache", result["deleted_components"])

    def test_full_delete_has_higher_deletion_ratio_than_partial(self):
        full = StructuralPayloadAnalyzer(SIMPLE_ORIGINAL, "").analyze_structural_drift()
        partial = StructuralPayloadAnalyzer(SIMPLE_ORIGINAL, SIMPLE_MODIFIED).analyze_structural_drift()
        self.assertGreater(
            full["metrics"]["structural_deletion_ratio"],
            partial["metrics"]["structural_deletion_ratio"],
        )

    def test_below_min_deletion_count_not_flagged(self):
        # 2-function file losing 1 function: ratio 50% exceeds threshold but
        # count (1) is below min_deletion_count default of 3 — should stay SAFE
        tiny_original = "def foo(): pass\ndef bar(): pass"
        tiny_modified = "def foo(): pass"
        result = StructuralPayloadAnalyzer(tiny_original, tiny_modified).analyze_structural_drift()
        self.assertEqual(result["status"], "SAFE")

    def test_both_thresholds_met_is_destructive(self):
        # SIMPLE_ORIGINAL has 10 nodes; deleting all → 100% ratio, 10 deletions
        result = StructuralPayloadAnalyzer(SIMPLE_ORIGINAL, "").analyze_structural_drift()
        self.assertEqual(result["status"], "DESTRUCTIVE")
        self.assertEqual(result["severity"], "CRITICAL")

    def test_syntax_error_returns_error_key(self):
        result = StructuralPayloadAnalyzer("def foo(: pass", "valid = 1").analyze_structural_drift()
        self.assertIn("error", result)

    def test_added_components_tracked(self):
        result = StructuralPayloadAnalyzer(SIMPLE_MODIFIED, SIMPLE_ORIGINAL).analyze_structural_drift()
        self.assertIn("Database", result["added_components"])

    def test_empty_original_no_crash(self):
        result = StructuralPayloadAnalyzer("", SIMPLE_ORIGINAL).analyze_structural_drift()
        self.assertEqual(result["metrics"]["deleted_node_count"], 0)
        self.assertEqual(result["status"], "SAFE")

    def test_deletion_ratio_reported_in_metrics(self):
        result = StructuralPayloadAnalyzer(SIMPLE_ORIGINAL, "").analyze_structural_drift()
        self.assertIn("structural_deletion_ratio", result["metrics"])
        self.assertEqual(result["metrics"]["structural_deletion_ratio"], 100.0)

    def test_high_custom_threshold_suppresses_flag(self):
        # Threshold > 1.0 means it can never be reached — always SAFE
        result = StructuralPayloadAnalyzer(
            SIMPLE_ORIGINAL, "", deletion_ratio_threshold=1.5
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
        v = self.a._assess_consequence(0, 0, 0, 55)
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
        v = self.a._assess_consequence(11, 0, 0, 75)
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
        self.assertEqual(v["status"], "DESTRUCTIVE")

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
        # CRITICAL structural severity adds 3 to score → CAUTION or DESTRUCTIVE
        v = self.a._assess_consequence(0, 0, 0, 0, structural_severity="CRITICAL")
        self.assertIn(v["status"], ("CAUTION", "DESTRUCTIVE"))

    def test_critical_structural_severity_increases_score(self):
        v_low = self.a._assess_consequence(0, 0, 0, 0, structural_severity="LOW")
        v_critical = self.a._assess_consequence(0, 0, 0, 0, structural_severity="CRITICAL")
        self.assertGreater(v_critical["severity_score"], v_low["severity_score"])

    def test_default_structural_severity_is_safe(self):
        v = self.a._assess_consequence(0, 0, 0, 0)
        self.assertEqual(v["status"], "SAFE")


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
        a.repo.merge_base.return_value = [merge_base_commit]

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

    def test_structural_report_has_new_shape(self):
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


# ==============================================================================
# LAYER 5a — TemporalDriftAnalyzer
# ==============================================================================

class TestTemporalDriftAnalyzer(unittest.TestCase):
    def test_zero_drift_is_current(self):
        result = TemporalDriftAnalyzer(0, 0.0).analyze_drift()
        self.assertEqual(result["status"], "CURRENT")
        self.assertEqual(result["severity"], "LOW")

    def test_below_warning_threshold_is_current(self):
        # 10 days * 5 commits/day = score 50 < 250
        result = TemporalDriftAnalyzer(10, 5.0).analyze_drift()
        self.assertEqual(result["status"], "CURRENT")

    def test_at_warning_threshold_is_stale(self):
        # 50 * 5.0 = 250.0 == warning_threshold
        result = TemporalDriftAnalyzer(50, 5.0).analyze_drift()
        self.assertEqual(result["status"], "STALE")
        self.assertEqual(result["severity"], "WARNING")

    def test_above_critical_threshold_is_dangerous(self):
        # 100 * 10.1 = 1010 > 1000
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
        # score=50 >= custom warning=50 → STALE
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
        # "Minor Fix" should still match the "minor fix" keyword
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


if __name__ == "__main__":
    unittest.main()
