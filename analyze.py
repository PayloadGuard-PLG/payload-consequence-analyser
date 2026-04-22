#!/usr/bin/env python3
"""
PayloadGuard - Destructive Merge Detection
Detects catastrophic code payloads hidden in code suggestions before merge

Usage:
    python analyze.py <repo_path> <branch> [target_branch] [--pr-description "..."] [--save-json]

Example:
    python analyze.py . feature-branch main
    python analyze.py . feature-branch main --pr-description "minor syntax fix" --save-json
"""

import ast
import git
import sys
import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, Union


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
        deletion_ratio_threshold: float = 0.20,
        min_deletion_count: int = 3,
    ):
        self.original_code = original_code
        self.modified_code = modified_code
        self.deletion_ratio_threshold = deletion_ratio_threshold
        self.min_deletion_count = min_deletion_count

    def _extract_core_nodes(self, source_text: str) -> set:
        """
        Walks the AST to extract the names of all defined classes and functions.
        """
        try:
            tree = ast.parse(source_text)
        except SyntaxError as e:
            raise ValueError(f"SyntaxError during AST parsing: {e}")

        core_nodes = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                core_nodes.add(node.name)

        return core_nodes

    def analyze_structural_drift(self) -> Dict[str, Any]:
        """
        Calculates the exact set difference between original and modified
        architectural nodes. Flags CRITICAL only when BOTH the deletion ratio
        AND the minimum deletion count thresholds are exceeded.
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
        }


# ==============================================================================
# LAYER 5a: TEMPORAL DRIFT ANALYSIS
# ==============================================================================

class TemporalDriftAnalyzer:
    """
    Evaluates the temporal divergence between a feature branch and its target.
    Correlates branch age with target branch velocity to compute a Drift Score.

    Drift Score = branch_age_days * target_velocity_commits_per_day

    This compound metric is more meaningful than raw age alone: a 90-day-old
    branch on a slow repo (1 commit/day = score 90) is very different from a
    90-day-old branch on a fast repo (20 commits/day = score 1800).

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
        """
        Calculates the compound drift score and assigns a verdict.
        """
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
    """
    Evaluates the integrity of a pull request by comparing the stated intent
    (PR description) against the actual structural impact (severity verdict).

    Detects the 'benign description / catastrophic payload' pattern that was
    central to the April 2026 Codex incident.

    Configurable:
        benign_keywords (list): Phrases that signal a claimed low-impact change.
            Extend this list for your team's common PR vocabulary.

    Example — custom keywords:
        analyzer = SemanticTransparencyAnalyzer(
            pr_description, actual_severity,
            benign_keywords=["minor fix", "typo", "small tweak", "cosmetic"]
        )
    """

    DEFAULT_BENIGN_KEYWORDS = [
        "minor fix",
        "minor syntax fix",
        "typo",
        "formatting",
        "cleanup",
        "docs",
        "refactor whitespace",
        "small tweak",
        "cosmetic",
        "minor update",
    ]

    def __init__(
        self,
        pr_description: str,
        actual_severity: str,
        benign_keywords: list = None,
    ):
        self.pr_description = pr_description.lower().strip()
        self.actual_severity = actual_severity.upper()
        self.benign_keywords = benign_keywords if benign_keywords is not None else self.DEFAULT_BENIGN_KEYWORDS

    def analyze_transparency(self) -> Dict[str, Union[str, bool]]:
        """
        Calculates the divergence between human-readable claims and
        machine-verified structural impact.
        """
        if not self.pr_description:
            return {
                "status": "UNVERIFIED",
                "is_deceptive": False,
                "matched_keyword": None,
                "directive": "⚠ CAUTION. No PR description provided for semantic analysis.",
            }

        matched_keyword = next(
            (kw for kw in self.benign_keywords if kw in self.pr_description), None
        )
        claims_benign = matched_keyword is not None
        is_deceptive = claims_benign and self.actual_severity == "CRITICAL"

        if is_deceptive:
            status = "DECEPTIVE_PAYLOAD"
            directive = "❌ DO NOT MERGE. PR description deliberately contradicts catastrophic architectural changes."
        else:
            status = "TRANSPARENT"
            directive = "✓ SAFE. PR description aligns with verified structural impact."

        return {
            "status": status,
            "is_deceptive": is_deceptive,
            "matched_keyword": matched_keyword,
            "directive": directive,
        }


# ==============================================================================
# CORE ANALYZER
# ==============================================================================

class PayloadAnalyzer:
    """
    Five-layer analysis system for detecting destructive merges.

    Layer 1: Surface Scan        — File/line delta extraction
    Layer 2: Forensic Analysis   — Temporal validation, deletion ratios
    Layer 3: Consequence Model   — Severity scoring and verdict
    Layer 4: Structural Drift    — AST-based class/function deletion detection
    Layer 5: Extended Analysis   — Temporal drift score + semantic transparency
    """

    def __init__(self, repo_path, branch, target_branch="main"):
        try:
            self.repo = git.Repo(repo_path)
        except Exception as e:
            print(f"ERROR: Could not open repository at {repo_path}")
            print(f"Details: {e}")
            sys.exit(1)

        self.branch = branch
        self.target = target_branch
        self.repo_path = repo_path

    def _calculate_target_velocity(self) -> float:
        """
        Calculates commits per day on the target branch over the last 90 days.
        Returns 0.0 safely if the calculation fails for any reason.
        """
        try:
            target_commit = self.repo.commit(self.target)
            since = target_commit.committed_datetime - timedelta(days=90)
            commits = list(
                self.repo.iter_commits(self.target, since=since.isoformat())
            )
            return round(len(commits) / 90.0, 3)
        except Exception:
            return 0.0

    def analyze(self, pr_description: str = ""):
        try:
            try:
                self.repo.commit(self.target)
            except git.exc.BadName:
                return {
                    "error": f"Target branch '{self.target}' not found",
                    "available_branches": [ref.name for ref in self.repo.heads],
                }

            try:
                self.repo.commit(self.branch)
            except git.exc.BadName:
                return {
                    "error": f"Branch '{self.branch}' not found",
                    "available_branches": [ref.name for ref in self.repo.heads],
                }

            merge_base = self.repo.merge_base(self.target, self.branch)
            diffs = merge_base[0].diff(self.branch)

            # LAYER 1: FILE COUNTS
            files_added    = len([d for d in diffs if d.change_type == 'A'])
            files_deleted  = len([d for d in diffs if d.change_type == 'D'])
            files_modified = len([d for d in diffs if d.change_type == 'M'])
            files_renamed  = len([d for d in diffs if d.change_type == 'R'])
            files_copied   = len([d for d in diffs if d.change_type == 'C'])
            files_typed    = len([d for d in diffs if d.change_type == 'T'])

            lines_added = 0
            lines_deleted = 0

            for d in diffs:
                if d.change_type == 'A':
                    try:
                        content = d.b_blob.data_stream.read().decode('utf-8', errors='ignore')
                        lines_added += len(content.split('\n'))
                    except Exception:
                        pass
                elif d.change_type == 'D':
                    try:
                        content = d.a_blob.data_stream.read().decode('utf-8', errors='ignore')
                        lines_deleted += len(content.split('\n'))
                    except Exception:
                        pass

            # LAYER 4: STRUCTURAL DRIFT (Python files only)
            structural_score = 0.0
            structural_flags = []
            overall_structural_severity = "LOW"

            for d in diffs:
                if d.change_type != 'M':
                    continue
                path = d.b_path or d.a_path or ''
                if not path.endswith('.py'):
                    continue
                try:
                    original = d.a_blob.data_stream.read().decode('utf-8', errors='ignore')
                    modified = d.b_blob.data_stream.read().decode('utf-8', errors='ignore')
                    result = StructuralPayloadAnalyzer(original, modified).analyze_structural_drift()
                    if 'error' not in result and result['metrics']['deleted_node_count'] > 0:
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

            branch_commit = self.repo.commit(self.branch)
            target_commit = self.repo.commit(self.target)
            branch_date = branch_commit.committed_datetime
            target_date = target_commit.committed_datetime
            days_old = (target_date - branch_date).days

            total_lines_changed = lines_added + lines_deleted
            deletion_ratio = (lines_deleted / total_lines_changed * 100) if total_lines_changed > 0 else 0

            # LAYER 3: CONSEQUENCE VERDICT
            verdict = self._assess_consequence(
                files_deleted,
                lines_deleted,
                days_old,
                deletion_ratio,
                overall_structural_severity,
            )

            deleted_files = [d.a_path for d in diffs if d.change_type == 'D']
            critical_patterns = [
                'test', 'tests', '.github/workflows', 'requirements', 'setup.py',
                '__init__.py', 'core', 'modules', 'config', '.yml', '.yaml'
            ]
            critical_deletions = [
                f for f in deleted_files
                if any(pattern.lower() in f.lower() for pattern in critical_patterns)
            ]

            # LAYER 5a: TEMPORAL DRIFT
            target_velocity = self._calculate_target_velocity()
            temporal_drift = TemporalDriftAnalyzer(
                branch_age_days=max(days_old, 0),
                target_velocity_commits_per_day=target_velocity,
            ).analyze_drift()

            # LAYER 5b: SEMANTIC TRANSPARENCY
            semantic = SemanticTransparencyAnalyzer(
                pr_description=pr_description,
                actual_severity=verdict['severity'],
            ).analyze_transparency()

            return {
                "timestamp": datetime.now().isoformat(),
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
                "temporal_drift": temporal_drift,
                "semantic": semantic,
                "deleted_files": {
                    "total": len(deleted_files),
                    "critical": critical_deletions[:10],
                    "all": deleted_files[:30],
                },
            }

        except Exception as e:
            return {
                "error": f"Analysis failed: {str(e)}",
                "error_type": type(e).__name__,
            }

    def _assess_consequence(self, files_deleted, lines_deleted, days_old, deletion_ratio, structural_severity="LOW"):
        flags = []
        severity_score = 0.0

        if days_old > 365:
            flags.append(f"Branch is {days_old} days old (1+ year)")
            severity_score += 3
        elif days_old > 180:
            flags.append(f"Branch is {days_old} days old (6+ months)")
            severity_score += 2
        elif days_old > 90:
            flags.append(f"Branch is {days_old} days old (3+ months)")
            severity_score += 1

        if files_deleted > 50:
            flags.append(f"{files_deleted} files would be deleted (massive scope)")
            severity_score += 3
        elif files_deleted > 20:
            flags.append(f"{files_deleted} files would be deleted (large scope)")
            severity_score += 2
        elif files_deleted > 10:
            flags.append(f"{files_deleted} files would be deleted")
            severity_score += 1

        if deletion_ratio > 90:
            flags.append(f"Deletion ratio: {deletion_ratio:.1f}% (almost entire changeset is deletions)")
            severity_score += 3
        elif deletion_ratio > 70:
            flags.append(f"Deletion ratio: {deletion_ratio:.1f}% (majority of changes are deletions)")
            severity_score += 2
        elif deletion_ratio > 50:
            flags.append(f"Deletion ratio: {deletion_ratio:.1f}% (more deletions than additions)")
            severity_score += 1

        if structural_severity == "CRITICAL":
            flags.append("Structural drift CRITICAL — significant Python class/function deletions detected")
            severity_score += 3

        if lines_deleted > 50000:
            flags.append(f"{lines_deleted:,} lines would be deleted (massive codebase change)")
            severity_score += 3
        elif lines_deleted > 10000:
            flags.append(f"{lines_deleted:,} lines would be deleted (large codebase change)")
            severity_score += 2
        elif lines_deleted > 5000:
            flags.append(f"{lines_deleted:,} lines would be deleted")
            severity_score += 1

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

    if 'temporal_drift' in report:
        td = report['temporal_drift']
        print(f"\n⏱  TEMPORAL DRIFT (Layer 5a)")
        print(f"   Status: {td['status']} [{td['severity']}]")
        print(f"   Drift Score: {td['metrics']['calculated_drift_score']:.1f}")
        print(f"   Target velocity: {td['metrics']['target_velocity']} commits/day")
        print(f"   {td['recommendation']}")

    if 'semantic' in report:
        sem = report['semantic']
        print(f"\n🔎 SEMANTIC TRANSPARENCY (Layer 5b)")
        print(f"   Status: {sem['status']}")
        if sem.get('matched_keyword'):
            print(f"   Matched keyword: \"{sem['matched_keyword']}\"")
        print(f"   {sem['directive']}")

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

    print("\n" + "="*70 + "\n")


def save_json_report(report, filename="consequence_report.json"):
    try:
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"✓ Report saved to {filename}")
    except Exception as e:
        print(f"⚠️  Could not save JSON report: {e}")


def main():
    if len(sys.argv) < 3:
        print("\n" + "="*70)
        print("PAYLOADGUARD v0.2")
        print("="*70)
        print("\nDetects destructive payloads hidden in code suggestions before merge")
        print("\nUSAGE:")
        print("  python analyze.py <repo_path> <branch> [target_branch] [--pr-description \"...\"] [--save-json]")
        print("\nEXAMPLES:")
        print("  python analyze.py . feature-branch main")
        print("  python analyze.py . feature-branch main --pr-description \"minor syntax fix\"")
        print("  python analyze.py . feature-branch main --pr-description \"minor syntax fix\" --save-json")
        print("\n" + "="*70 + "\n")
        sys.exit(1)

    repo_path      = sys.argv[1]
    branch         = sys.argv[2]
    target_branch  = "main"
    pr_description = ""
    save_json      = False

    i = 3
    while i < len(sys.argv):
        if sys.argv[i] == "--save-json":
            save_json = True
        elif sys.argv[i] == "--pr-description" and i + 1 < len(sys.argv):
            pr_description = sys.argv[i + 1]
            i += 1
        else:
            target_branch = sys.argv[i]
        i += 1

    analyzer = PayloadAnalyzer(repo_path, branch, target_branch)
    report   = analyzer.analyze(pr_description=pr_description)
    print_report(report)

    if save_json:
        save_json_report(report)

    if "error" in report:
        sys.exit(1)
    elif report.get('verdict', {}).get('status') == 'DESTRUCTIVE':
        sys.exit(2)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
