# PayloadGuard — Test Run Report

**Date:** 2026-10-26 16:00 UTC  
**Environment:** Python 3.14.3, pytest 9.1.1, z3-solver 5.3.2.0, crosshair-tool 0.0.112, tree-sitter 0.26.0  
**Platform:** Windows 11 (local)  
**Commit:** `28345bc`  
**Result:** 391 passed · 0 skipped · 0 failed

Run with: `python -m pytest test_analyzer.py test_consequence_engine.py tests/ -v`

---

## test_analyzer.py::TestDeepMerge

- ✓ `test_does_not_mutate_base`
- ✓ `test_nested_merge_preserves_unspecified_keys`
- ✓ `test_new_key_in_override_is_added`
- ✓ `test_shallow_override`

## test_analyzer.py::TestPayloadGuardConfig

- ✓ `test_default_instances_are_independent`
- ✓ `test_default_thresholds`
- ✓ `test_semantic_config_has_v2_keys`

## test_analyzer.py::TestLoadConfig

- ✓ `test_custom_benign_keywords_replace_defaults`
- ✓ `test_deep_merges_partial_structural_override`
- ✓ `test_deep_merges_partial_temporal_override`
- ✓ `test_empty_yaml_returns_defaults`
- ✓ `test_returns_defaults_when_no_file`

## test_analyzer.py::TestCriticalPathPatterns

- ✓ `test_github_workflows_is_critical`
- ✓ `test_latest_deployment_is_not_critical`
- ✓ `test_protest_py_is_not_critical`
- ✓ `test_reconfiguration_log_is_not_critical`
- ✓ `test_requirements_dev_txt_is_critical`
- ✓ `test_requirements_txt_is_critical`
- ✓ `test_setup_py_is_critical`
- ✓ `test_test_directory_singular_is_critical`
- ✓ `test_test_file_prefix_is_critical`
- ✓ `test_tests_directory_is_critical`
- ✓ `test_yaml_file_is_critical`

## test_analyzer.py::TestStructuralPayloadAnalyzer

- ✓ `test_added_components_tracked`
- ✓ `test_below_min_deletion_count_not_flagged`
- ✓ `test_both_thresholds_met_is_destructive`
- ✓ `test_deletion_ratio_reported_in_metrics`
- ✓ `test_detects_deleted_classes`
- ✓ `test_empty_original_no_crash`
- ✓ `test_full_delete_has_higher_deletion_ratio_than_partial`
- ✓ `test_high_custom_threshold_suppresses_flag`
- ✓ `test_no_deletions_status_is_safe`
- ✓ `test_syntax_error_returns_error_key`

## test_analyzer.py::TestAssessConsequenceSafe

- ✓ `test_no_changes_is_safe`
- ✓ `test_safe_has_recommendation`

## test_analyzer.py::TestAssessConsequenceReview

- ✓ `test_11_files_deleted`
- ✓ `test_5001_lines_deleted`
- ✓ `test_branch_over_90_days`
- ✓ `test_deletion_ratio_over_50`

## test_analyzer.py::TestAssessConsequenceCaution

- ✓ `test_branch_over_180_days_plus_minor_flag`
- ✓ `test_deletion_ratio_over_70_plus_minor_flag`
- ✓ `test_over_10000_lines_plus_old_branch`
- ✓ `test_over_20_files_plus_old_branch`

## test_analyzer.py::TestAssessConsequenceDestructive

- ✓ `test_branch_over_365_days_and_many_files`
- ✓ `test_combined_flags_score`
- ✓ `test_high_deletion_ratio_and_line_count`
- ✓ `test_recommendation_says_do_not_merge`

## test_analyzer.py::TestAssessConsequenceStructural

- ✓ `test_critical_structural_severity_adds_flag`
- ✓ `test_critical_structural_severity_elevates_verdict`
- ✓ `test_critical_structural_severity_increases_score`
- ✓ `test_default_structural_severity_is_safe`
- ✓ `test_low_structural_severity_no_flag`

## test_analyzer.py::TestAssessConsequenceCustomThresholds

- ✓ `test_custom_age_threshold_fires_earlier`
- ✓ `test_custom_files_threshold`

## test_analyzer.py::TestPayloadAnalyzerInit

- ✓ `test_accepts_custom_config`
- ✓ `test_bad_repo_path_exits`
- ✓ `test_default_target_is_main`
- ✓ `test_stores_branch_and_target`
- ✓ `test_uses_default_config_when_none_passed`

## test_analyzer.py::TestAnalyzeErrors

- ✓ `test_empty_merge_base_returns_error`
- ✓ `test_error_includes_available_branches`
- ✓ `test_missing_feature_branch_returns_error`
- ✓ `test_missing_target_branch_returns_error`

## test_analyzer.py::TestAnalyzeSuccess

- ✓ `test_commit_flags_key_present`
- ✓ `test_counts_added_lines`
- ✓ `test_counts_deleted_files`
- ✓ `test_counts_deleted_lines`
- ✓ `test_counts_modified_files`
- ✓ `test_critical_deletions_flagged`
- ✓ `test_deleted_files_list`
- ✓ `test_deletion_ratio_zero_when_no_changes`
- ✓ `test_permission_changes_detected`
- ✓ `test_pr_description_flows_to_semantic_result`
- ✓ `test_red_flag_commit_message_detected`
- ✓ `test_report_has_required_keys`
- ✓ `test_structural_report_has_correct_shape`
- ✓ `test_verdict_is_present`

## test_analyzer.py::TestTemporalDriftAnalyzer

- ✓ `test_above_critical_threshold_is_dangerous`
- ✓ `test_at_warning_threshold_is_stale`
- ✓ `test_below_warning_threshold_is_current`
- ✓ `test_custom_thresholds`
- ✓ `test_drift_score_calculated_correctly`
- ✓ `test_infinite_age_raises`
- ✓ `test_infinite_velocity_raises`
- ✓ `test_metrics_block_present`
- ✓ `test_nan_velocity_raises`
- ✓ `test_negative_age_raises`
- ✓ `test_negative_velocity_raises`
- ✓ `test_recommendation_present`
- ✓ `test_zero_drift_is_current`

## test_analyzer.py::TestSemanticTransparencyAnalyzer

- ✓ `test_directive_present`
- ✓ `test_empty_description_is_unverified`
- ✓ `test_is_deceptive_false_on_caution_mismatch`
- ✓ `test_macro_scope_gives_caution_mismatch`
- ✓ `test_matched_keyword_is_first_signal_or_none`
- ✓ `test_matched_keyword_none_when_transparent`
- ✓ `test_mci_score_present`
- ✓ `test_micro_scope_large_churn_and_new_function_is_deceptive`
- ✓ `test_micro_scope_large_churn_is_caution`
- ✓ `test_micro_scope_small_churn_is_transparent`
- ✓ `test_signals_list_present`
- ✓ `test_unspecified_scope_large_diff_is_transparent`
- ✓ `test_whitespace_description_is_unverified`

## test_analyzer.py::TestPrintReport

- ✓ `test_deleted_files_section_shown_when_present`
- ✓ `test_error_report_prints_failed`
- ✓ `test_error_with_available_branches`
- ✓ `test_full_report_shows_branch_names`
- ✓ `test_full_report_shows_verdict`
- ✓ `test_no_deleted_files_section_when_empty`

## test_analyzer.py::TestSaveJsonReport

- ✓ `test_gracefully_handles_write_error`
- ✓ `test_saves_valid_json`

## test_analyzer.py::TestStructuralParserConstants

- ✓ `test_annotated_assignment_tracked`
- ✓ `test_deletion_of_constant_detected_by_structural_analyzer`
- ✓ `test_functions_still_tracked`
- ✓ `test_local_variable_not_tracked`
- ✓ `test_module_level_assignment_tracked`

## test_analyzer.py::TestBinaryFileDeletion

- ✓ `test_binary_files_do_not_inflate_line_counts`

## test_analyzer.py::TestNegativeBranchAge

- ✓ `test_branch_newer_than_target_does_not_crash`
- ✓ `test_zero_age_does_not_trigger_age_flag`

## test_analyzer.py::TestMalformedConfig

- ✓ `test_empty_yaml_falls_back_to_defaults`
- ✓ `test_malformed_yaml_falls_back_to_defaults`

## test_analyzer.py::TestThresholdOrderValidation

- ✓ `test_already_ordered_thresholds_unchanged`
- ✓ `test_out_of_order_age_thresholds_are_sorted`
- ✓ `test_out_of_order_files_thresholds_are_sorted`

## test_analyzer.py::TestCriticalPathScoring

- ✓ `test_critical_deletions_combined_reach_caution`
- ✓ `test_critical_path_flag_text_present`
- ✓ `test_many_critical_deletions_adds_two_points`
- ✓ `test_small_critical_deletions_adds_two_points`
- ✓ `test_zero_critical_deletions_no_bonus`

## test_analyzer.py::TestMarkdownEscaping

- ✓ `test_backtick_in_deleted_filename_escaped`
- ✓ `test_pipe_in_structural_filename_escaped`

## test_analyzer.py::TestPostCheckRun

- ✓ `test_main_skips_without_app_id`
- ✓ `test_malformed_private_key_raises_clear_error`
- ✓ `test_require_env_raises_on_missing_var`
- ✓ `test_require_env_returns_stripped_value`

## test_analyzer.py::TestCrossFileAggregation

- ✓ `test_both_gates_met_triggers_critical`
- ✓ `test_count_met_but_ratio_low_is_not_critical`

## test_analyzer.py::TestMalformedConfigWarning

- ✓ `test_malformed_yaml_emits_warning_to_stderr`

## test_analyzer.py::TestStructuralParserJSTS

- ✓ `test_js_arrow_function_const_still_detected`
- ✓ `test_js_const_deletion_detected`
- ✓ `test_ts_const_deletion_detected`

## test_analyzer.py::TestMarkdownTruncation

- ✓ `test_cuts_at_newline_boundary`
- ✓ `test_even_fence_count_not_doubled`
- ✓ `test_long_content_is_truncated`
- ✓ `test_short_content_returned_unchanged`
- ✓ `test_truncation_notice_appended`
- ✓ `test_unclosed_code_fence_is_closed`

## test_analyzer.py::TestSCAAnalysis

- ✓ `test_load_allowlist_returns_none_when_absent`
- ✓ `test_load_allowlist_returns_sets`
- ✓ `test_parse_cargo_package`
- ✓ `test_parse_go_package`
- ✓ `test_parse_ignores_diff_header_line`
- ✓ `test_parse_npm_package`
- ✓ `test_parse_pip_ignores_removed_lines`
- ✓ `test_parse_pip_packages`
- ✓ `test_sca_inactive_without_allowlist`
- ✓ `test_unverified_package_adds_three_to_score`

## test_analyzer.py::TestComplexityAdvisory

- ✓ `test_advisory_does_not_affect_verdict`
- ✓ `test_advisory_includes_threshold_value`
- ✓ `test_complexity_value_correct`
- ✓ `test_custom_threshold_respected`
- ✓ `test_existing_function_not_in_advisory`
- ✓ `test_high_complexity_function_flagged`
- ✓ `test_non_python_file_no_advisory`
- ✓ `test_simple_function_no_advisory`

## test_analyzer.py::TestAddedFileContentScanning

- ✓ `test_both_ci_and_shell_in_same_file`
- ✓ `test_ci_trigger_in_added_md_detected`
- ✓ `test_clean_markdown_not_flagged`
- ✓ `test_code_file_extension_skipped`
- ✓ `test_content_flag_scores_review`
- ✓ `test_decode_error_does_not_crash`
- ✓ `test_js_extension_skipped`
- ✓ `test_multiple_flagged_files_score_accumulates`
- ✓ `test_needs_ci_trigger_detected`
- ✓ `test_shell_pattern_in_added_txt_detected`
- ✓ `test_sudo_command_detected`
- ✓ `test_yaml_file_scanned`

## test_analyzer.py::TestINC3UnverifiedFlag

- ✓ `test_safe_with_pr_description_stays_safe`
- ✓ `test_unverified_flag_appears_in_full_analyze_no_description`
- ✓ `test_unverified_on_destructive_changeset_adds_flag`
- ✓ `test_unverified_on_safe_changeset_upgrades_to_review`

## test_analyzer.py::TestGitHubActionsPoisoningScanning

- ✓ `test_actions_poisoning_disabled_via_config`
- ✓ `test_actions_poisoning_key_in_report`
- ✓ `test_base64_payload_detected`
- ✓ `test_base64_payload_severity_is_critical`
- ✓ `test_clean_workflow_not_flagged`
- ✓ `test_credential_harvest_env_grep`
- ✓ `test_credential_harvest_metadata_endpoint`
- ✓ `test_credential_harvest_severity_is_critical`
- ✓ `test_critical_signal_scores_destructive`
- ✓ `test_curl_auth_header_with_secret_detected`
- ✓ `test_curl_header_flag_is_critical_severity`
- ✓ `test_curl_without_secret_in_header_not_flagged`
- ✓ `test_custom_trusted_oidc_consumer_via_config`
- ✓ `test_decode_error_does_not_crash`
- ✓ `test_deleted_workflow_not_scanned`
- ✓ `test_dormant_trigger_with_shell_exec`
- ✓ `test_dormant_trigger_without_shell_is_safe`
- ✓ `test_flag_text_appears_in_verdict`
- ✓ `test_forged_bot_author_detected`
- ✓ `test_forged_bot_author_severity_is_high`
- ✓ `test_github_env_innocent_var_not_flagged`
- ✓ `test_github_env_ld_preload_injection_detected`
- ✓ `test_github_env_node_options_injection_detected`
- ✓ `test_github_env_path_injection_detected`
- ✓ `test_github_output_secret_exfil_detected`
- ✓ `test_github_output_without_secret_not_flagged`
- ✓ `test_high_signal_scores_caution`
- ✓ `test_legitimate_oidc_consumer_still_passes`
- ✓ `test_modified_workflow_also_scanned`
- ✓ `test_multiline_curl_credential_harvest_detected`
- ✓ `test_non_workflow_yaml_skipped`
- ✓ `test_oidc_elevation_with_legitimate_consumer_is_safe`
- ✓ `test_oidc_elevation_without_consumer`
- ✓ `test_pull_request_target_alone_is_detected`
- ✓ `test_pull_request_target_with_write_permissions_is_critical`
- ✓ `test_typosquat_detection_patterns`
- ✓ `test_typosquatted_oidc_action_detected_as_critical`
- ✓ `test_typosquatted_oidc_action_fails_legitimacy_check`
- ✓ `test_yaml_folded_block_base64_detected`
- ✓ `test_yaml_literal_block_base64_detected`

## test_analyzer.py::TestSemanticTransparencyV2

- ✓ `test_caution_mismatch_escalates_safe_to_review`
- ✓ `test_deceptive_payload_escalates_safe_to_caution`
- ✓ `test_is_deceptive_true_on_deceptive_payload_status`
- ✓ `test_is_deceptive_true_only_on_deceptive_payload`
- ✓ `test_macro_scope_large_diff_adds_advisory_not_mci_penalty`
- ✓ `test_macro_scope_manual_review_signal_present`
- ✓ `test_matched_keyword_is_first_signal_or_none`
- ✓ `test_matched_keyword_none_when_no_signals`
- ✓ `test_mci_score_clamped_at_1_0`
- ✓ `test_micro_scope_auth_file_acknowledged_in_description_ok`
- ✓ `test_micro_scope_auth_file_unacknowledged_flags`
- ✓ `test_micro_scope_large_churn_flags_scope_understated`
- ✓ `test_micro_scope_no_structural_changes_transparent`
- ✓ `test_micro_scope_small_churn_transparent`
- ✓ `test_micro_scope_three_extensions_flags_cross_stack`
- ✓ `test_micro_scope_with_new_def_flags_operation_mutation`
- ✓ `test_no_description_returns_unverified`
- ✓ `test_remedial_claim_balanced_ratio_transparent`
- ✓ `test_remedial_claim_high_insertion_ratio_flags_phantom`
- ✓ `test_result_contains_required_keys`
- ✓ `test_score_at_0_5_returns_deceptive_payload`
- ✓ `test_score_below_0_5_returns_caution_mismatch`
- ✓ `test_transparent_with_no_signals_returns_transparent`
- ✓ `test_two_signals_accumulate_correctly`
- ✓ `test_unverified_result_contains_required_keys`
- ✓ `test_whitespace_only_description_returns_unverified`

## test_analyzer.py::TestWorkflowRemediation

- ✓ `test_already_pinned_sha_skipped`
- ✓ `test_already_sha_returns_none`
- ✓ `test_branch_ref_warns_and_not_tag`
- ✓ `test_duplicate_refs_deduplicated`
- ✓ `test_first_party_action_flagged_as_first_party`
- ✓ `test_local_path_ref_skipped`
- ✓ `test_multiple_distinct_refs_all_detected`
- ✓ `test_mutable_tag_detected`
- ✓ `test_mutable_tag_warnings_key_present_in_report`
- ✓ `test_mutable_tag_warnings_skips_deleted_diffs`
- ✓ `test_mutable_tag_warnings_skips_sha_pinned`
- ✓ `test_patch_branch_ref_not_substituted`
- ✓ `test_patch_no_op_when_no_subs`
- ✓ `test_patch_preserves_other_lines`
- ✓ `test_ref_without_at_sign_skipped`
- ✓ `test_resolve_annotated_tag_dereferences`
- ✓ `test_resolve_lightweight_tag`
- ✓ `test_sha_cache_prevents_duplicate_api_calls`
- ✓ `test_step_name_tracked`
- ✓ `test_third_party_action_not_first_party`
- ✓ `test_yaml_patch_substitutes_sha`

## test_analyzer.py::TestAIToolingConfigPoisoning

- ✓ `test_ai_config_critical_scores_destructive`
- ✓ `test_ai_config_disabled_via_config`
- ✓ `test_ai_config_flag_text_in_verdict`
- ✓ `test_ai_config_high_scores_caution`
- ✓ `test_ai_config_key_in_report`
- ✓ `test_binding_gyp_safe_require_not_flagged`
- ✓ `test_binding_gyp_shell_chain_critical`
- ✓ `test_claude_settings_legitimate_hook_is_safe`
- ✓ `test_claude_settings_session_hook_critical`
- ✓ `test_cursor_rule_alwaysapply_with_exec_imperative`
- ✓ `test_cursor_rule_alwaysapply_without_exec_is_safe`
- ✓ `test_full_scan_detects_claude_session_hook`
- ✓ `test_gemini_settings_session_hook_critical`
- ✓ `test_vscode_tasks_folder_open_critical`
- ✓ `test_vscode_tasks_no_folder_open_is_safe`
- ✓ `test_zero_ai_config_inputs_still_safe`

## test_analyzer.py::TestOwnWorkflowsNotInjectable

- ✓ `test_no_untrusted_context_in_any_run_body`
- ✓ `test_run_body_iterator_finds_steps`
- ✓ `test_scanner_finds_a_planted_offender`

## test_analyzer.py::TestPolicyReadFromTargetBranch

- ✓ `test_cli_flag_takes_precedence_over_env_mode`
- ✓ `test_control_destructive_change_blocks_under_base_policy`
- ✓ `test_env_mode_still_overrides_policy_file`
- ✓ `test_legitimate_change_passes_under_base_policy`
- ✓ `test_load_config_ref_reads_commit_not_working_tree`
- ✓ `test_policy_ref_falls_back_to_origin`
- ✓ `test_policy_ref_missing_file_or_ref_returns_defaults`
- ✓ `test_pr_cannot_allowlist_its_own_dependency`
- ✓ `test_pr_cannot_downgrade_its_own_consequence_mode`
- ✓ `test_pr_cannot_raise_its_own_thresholds`
- ✓ `test_verdict_exit_code_survives_non_utf8_stdout`

## test_analyzer.py::TestActionPolicyTrustBoundary

- ✓ `test_consequence_mode_input_reaches_the_analyser`
- ✓ `test_fork_pr_from_colliding_branch_name_scans_the_pr_head`
- ✓ `test_fork_pr_from_fork_only_branch_scans_the_pr_head`
- ✓ `test_head_ref_fallback_without_pull_request_payload`
- ✓ `test_invalid_consequence_mode_input_is_an_error_not_destructive`
- ✓ `test_legitimate_fork_pr_passes_through_action`
- ✓ `test_legitimate_pr_passes_through_action`
- ✓ `test_pr_policy_downgrade_still_blocks_through_action`
- ✓ `test_verdict_output_reports_caution`
- ✓ `test_verdict_output_reports_review`

## test_analyzer.py::TestDistributionPackaging

- ✓ `test_built_distribution_runs_a_scan`
- ✓ `test_declared_modules_and_packages_exist`
- ✓ `test_shipped_modules_include_their_first_party_imports`

## test_consequence_engine.py::TestParserCompletenessD01

- ✓ `test_x01_missing_grammar_never_silently_returns_complete`
- ✓ `test_x02_python_syntax_error_reports_parse_error`
- ✓ `test_x02_treesitter_syntax_error_reports_parse_error`
- ✓ `test_x05_unsupported_extension_explicit_status`
- ✓ `test_x06_unsupported_source_change_reports_incomplete_coverage[ruby]`
- ✓ `test_x06_unsupported_source_change_reports_incomplete_coverage[csharp]`
- ✓ `test_x06_unsupported_source_change_reports_incomplete_coverage[kotlin]`
- ✓ `test_x06_added_and_deleted_unsupported_source_reported`
- ✓ `test_x06_non_code_files_stay_out_of_parser_coverage`
- ✓ `test_x06_supported_analysis_unchanged_alongside_unsupported_file`
- ✓ `test_x07_module_extension_parses_like_base_extension[mjs]`
- ✓ `test_x07_module_extension_parses_like_base_extension[cjs]`
- ✓ `test_x07_module_extension_parses_like_base_extension[mts]`
- ✓ `test_x07_module_extension_parses_like_base_extension[cts]`
- ✓ `test_x07_gutting_in_module_extension_matches_base_extension[mjs]`
- ✓ `test_x07_gutting_in_module_extension_matches_base_extension[cjs]`
- ✓ `test_x07_gutting_in_module_extension_matches_base_extension[mts]`
- ✓ `test_x07_gutting_in_module_extension_matches_base_extension[cts]`
- ✓ `test_parser_capabilities_probe`

## test_consequence_engine.py::TestSymbolFactMultiLanguage

- ✓ `test_python_qualified_methods_fix_flat_set_collision`
- ✓ `test_body_hash_invariant_to_comments_and_docstrings`
- ✓ `test_javascript_commonjs_exports_and_no_local_var_leak`
- ✓ `test_typescript_classes_interfaces_and_methods`
- ✓ `test_go_structs_methods_and_export_casing`
- ✓ `test_rust_structs_traits_and_impl_methods`
- ✓ `test_java_classes_annotations_and_visibility`

## test_consequence_engine.py::TestSymbolMatchingD02

- ✓ `test_s01_pure_class_and_method_rename_is_safe`
- ✓ `test_s02_cross_file_move_is_safe`
- ✓ `test_s03_rename_with_body_weakening_blocks`
- ✓ `test_s04_ambiguous_refactor_emits_incomplete_warning`

## test_consequence_engine.py::TestCompoundAndAdversarialDetectors

- ✓ `test_c01_distributed_cross_file_loss_blocks`
- ✓ `test_c02_five_file_pure_move_refactor_is_safe`
- ✓ `test_c03_threshold_gaming_dilution_blocks`
- ✓ `test_c04_benign_private_dead_code_cleanup_is_safe`
- ✓ `test_d04_signature_tightening_breaks_callers_vs_optional_param_safe`
- ✓ `test_d05_manifest_lockfile_and_lifecycle_scripts`
- ✓ `test_d06_guard_decorator_and_rollback_call_removal`

## test_consequence_engine.py::TestPayloadAnalyzerIntegration

- ✓ `test_enforce_mode_suppresses_legacy_l4_false_positive_on_massive_rename`
- ✓ `test_unsupported_source_change_reported_without_changing_verdict`
- ✓ `test_shadow_advisory_and_enforce_modes_on_threshold_gaming_repo`

## test_consequence_engine.py::TestDetectorAccuracyV2AndUsability

- ✓ `test_d06_v2_guard_polarity_inversion_python_and_typescript`
- ✓ `test_d06_v2_guard_enforcement_neutralized_and_early_return_bypass`
- ✓ `test_d06_v2_exception_handler_swallowed`
- ✓ `test_d04_v2_import_alias_and_cross_module_disambiguation`
- ✓ `test_d04_v2_container_consolidation_reduces_finding_noise`
- ✓ `test_usability_cli_print_and_sarif_report`
- ✓ `test_d06_compound_boolop_guard_and_polyglot_state_guards`
- ✓ `test_d06_boolean_short_circuit_and_python_go_state_guards`
- ✓ `test_d08_workflow_expression_injection_and_safe_env_binding`
- ✓ `test_d08_prt_untrusted_checkout_and_action_pin_downgrade_and_ci_gate`
- ✓ `test_d09_test_assertion_erosion_and_skip_addition`

## test_consequence_engine.py::TestDetectorD10AndExtendedIntegrity

- ✓ `test_d10_sql_destructive_table_and_column_drop_and_truncate`
- ✓ `test_d10_alembic_irreversible_drop_without_downgrade`
- ✓ `test_d10_django_and_knex_destructive_migrations`
- ✓ `test_d10_safe_additive_migration_and_temp_table_drops`
- ✓ `test_d05_build_wrapper_script_tampering`
- ✓ `test_d08_unpinned_action_addition_and_workflow_run_artifact`
- ✓ `test_d10_multiline_sql_and_goose_rollback_exclusions`
- ✓ `test_d10_rails_and_django_runsql_irreversibility`
- ✓ `test_d08_first_party_actions_not_flagged_as_unpinned`
- ✓ `test_d06_nonlocal_inner_function_mutation_not_flagged_as_short_circuit`

## tests/proofs/test_crosshair_contracts.py

- ✓ `test_crosshair_deletion_dim_contracts`
- ✓ `test_crosshair_assess_consequence_contracts`
- ✓ `test_crosshair_temporal_drift_contracts`
- ✓ `test_temporal_contract_excludes_non_finite_velocity`
- ✓ `test_crosshair_structural_drift_contracts`
- ✓ `test_crosshair_semantic_mci_contracts`

## tests/proofs/test_z3_properties.py

- ✓ `test_p1_typosquat_implies_score_gte_critical_threshold`
- ✓ `test_p2_typosquat_implies_destructive_verdict`
- ✓ `test_p3_typosquat_score_floor_not_cancelled`
- ✓ `test_p4_critical_signal_score_exceeds_high_signal_score`
- ✓ `test_p5_score_monotonicity_adding_critical_signal`
- ✓ `test_p6_safe_verdict_iff_score_below_review_threshold`
- ✓ `test_p7_verdict_deterministic_given_identical_scores`
- ✓ `test_p8_typosquat_cannot_yield_safe_verdict`
- ✓ `test_p9_score_upper_bound_is_sum_of_signal_maxima`
- ✓ `test_p9_bound_is_attained`
- ✓ `test_p9_bound_depends_on_signal_caps`
- ✓ `test_p9_model_matches_assess_consequence`
- ✓ `test_p10_empty_signal_set_always_safe`
