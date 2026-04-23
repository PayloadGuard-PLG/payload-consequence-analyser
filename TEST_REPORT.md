# PayloadGuard — Test Run Report

**Date:** 2026-04-22
**Environment:** Python 3.11.15, pytest 9.0.3, pluggy 1.6.0
**Platform:** Linux
**Result:** ✅ 100 passed, 0 failed, 0 errors — 0.52s

---

## Test Coverage by Layer

| Class | Tests | Result |
|---|---|---|
| TestDeepMerge | 4 | ✅ All passed |
| TestPayloadGuardConfig | 3 | ✅ All passed |
| TestLoadConfig | 5 | ✅ All passed |
| TestCriticalPathPatterns | 11 | ✅ All passed |
| TestStructuralPayloadAnalyzer | 10 | ✅ All passed |
| TestAssessConsequenceSafe | 2 | ✅ All passed |
| TestAssessConsequenceReview | 4 | ✅ All passed |
| TestAssessConsequenceCaution | 4 | ✅ All passed |
| TestAssessConsequenceDestructive | 4 | ✅ All passed |
| TestAssessConsequenceStructural | 5 | ✅ All passed |
| TestAssessConsequenceCustomThresholds | 2 | ✅ All passed |
| TestPayloadAnalyzerInit | 5 | ✅ All passed |
| TestAnalyzeErrors | 3 | ✅ All passed |
| TestAnalyzeSuccess | 11 | ✅ All passed |
| TestTemporalDriftAnalyzer | 10 | ✅ All passed |
| TestSemanticTransparencyAnalyzer | 9 | ✅ All passed |
| TestPrintReport | 6 | ✅ All passed |
| TestSaveJsonReport | 2 | ✅ All passed |

---

## Issues Found and Fixed

**6 tests were failing prior to this run** in `TestStructuralPayloadAnalyzer`.

**Root cause:** The Layer 4 multi-language refactor added a `file_path` parameter to `StructuralPayloadAnalyzer`. Without it, `language_for_path("")` returns `None` and `extract_named_nodes` returns an empty set — causing all structural analysis to silently score 0 regardless of input.

**Fix:** Added `file_path="test.py"` to all 10 `StructuralPayloadAnalyzer` constructor calls in `TestStructuralPayloadAnalyzer`. All test source code is Python so routing through the stdlib AST path is correct.

**Failing tests restored:**
- `test_detects_deleted_classes` — `deleted_components` was empty, now returns `["Cache", "Database"]`
- `test_full_delete_has_higher_deletion_ratio_than_partial` — both ratios were 0, now correct
- `test_both_thresholds_met_is_destructive` — returned SAFE (0 ratio), now returns DESTRUCTIVE
- `test_added_components_tracked` — `added_components` was empty, now returns `["Database"]`
- `test_deletion_ratio_reported_in_metrics` — ratio was 0, now returns 100.0
- `test_syntax_error_returns_error_key` — returned empty result, now returns error dict

---

## CI Integration

`pytest test_analyzer.py -v` is now wired into `.github/workflows/payloadguard.yml` and runs on every PR before the PayloadGuard scan step. A failing test blocks the scan from running.

`pytest>=7.0` added to `requirements.txt`.

---

*PayloadGuard v1.0.0 — 100/100 tests passing*
