# PayloadGuard — Test Registry

**Last run:** 2026-05-27 06:06 UTC  
**Result:** 267 passed · 7 skipped · 0 failed · 274 total

Run with: `python -m pytest test_analyzer.py tests/proofs/ --timeout=30 -v`  
Regenerate this file: `python tools/gen_test_registry.py`

## test_analyzer.py — TestDeepMerge

- ✓ `test_does_not_mutate_base`
- ✓ `test_nested_merge_preserves_unspecified_keys`
- ✓ `test_new_key_in_override_is_added`
- ✓ `test_shallow_override`

## test_analyzer.py — TestPayloadGuardConfig

- ✓ `test_default_instances_are_independent`
- ✓ `test_default_thresholds`
- ✓ `test_semantic_config_has_v2_keys`

## test_analyzer.py — TestLoadConfig

- ✓ `test_custom_benign_keywords_replace_defaults`
- ✓ `test_deep_merges_partial_structural_override`
- ✓ `test_deep_merges_partial_temporal_override`
- ✓ `test_empty_yaml_returns_defaults`
- ✓ `test_returns_defaults_when_no_file`

## test_analyzer.py — TestCriticalPathPatterns

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

## test_analyzer.py — TestStructuralPayloadAnalyzer

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

## test_analyzer.py — TestAssessConsequenceSafe

- ✓ `test_no_changes_is_safe`
- ✓ `test_safe_has_recommendation`

## test_analyzer.py — TestAssessConsequenceReview

- ✓ `test_11_files_deleted`
- ✓ `test_5001_lines_deleted`
- ✓ `test_branch_over_90_days`
- ✓ `test_deletion_ratio_over_50`

## test_analyzer.py — TestAssessConsequenceCaution

- ✓ `test_branch_over_180_days_plus_minor_flag`
- ✓ `test_deletion_ratio_over_70_plus_minor_flag`
- ✓ `test_over_10000_lines_plus_old_branch`
- ✓ `test_over_20_files_plus_old_branch`

## test_analyzer.py — TestAssessConsequenceDestructive

- ✓ `test_branch_over_365_days_and_many_files`
- ✓ `test_combined_flags_score`
- ✓ `test_high_deletion_ratio_and_line_count`
- ✓ `test_recommendation_says_do_not_merge`

## test_analyzer.py — TestAssessConsequenceStructural

- ✓ `test_critical_structural_severity_adds_flag`
- ✓ `test_critical_structural_severity_elevates_verdict`
- ✓ `test_critical_structural_severity_increases_score`
- ✓ `test_default_structural_severity_is_safe`
- ✓ `test_low_structural_severity_no_flag`

## test_analyzer.py — TestAssessConsequenceCustomThresholds

- ✓ `test_custom_age_threshold_fires_earlier`
- ✓ `test_custom_files_threshold`

## test_analyzer.py — TestPayloadAnalyzerInit

- ✓ `test_accepts_custom_config`
- ✓ `test_bad_repo_path_exits`
- ✓ `test_default_target_is_main`
- ✓ `test_stores_branch_and_target`
- ✓ `test_uses_default_config_when_none_passed`

## test_analyzer.py — TestAnalyzeErrors

- ✓ `test_empty_merge_base_returns_error`
- ✓ `test_error_includes_available_branches`
- ✓ `test_missing_feature_branch_returns_error`
- ✓ `test_missing_target_branch_returns_error`

## test_analyzer.py — TestAnalyzeSuccess

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

## test_analyzer.py — TestTemporalDriftAnalyzer

- ✓ `test_above_critical_threshold_is_dangerous`
- ✓ `test_at_warning_threshold_is_stale`
- ✓ `test_below_warning_threshold_is_current`
- ✓ `test_custom_thresholds`
- ✓ `test_drift_score_calculated_correctly`
- ✓ `test_metrics_block_present`
- ✓ `test_negative_age_raises`
- ✓ `test_negative_velocity_raises`
- ✓ `test_recommendation_present`
- ✓ `test_zero_drift_is_current`

## test_analyzer.py — TestSemanticTransparencyAnalyzer

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

## test_analyzer.py — TestPrintReport

- ✓ `test_deleted_files_section_shown_when_present`
- ✓ `test_error_report_prints_failed`
- ✓ `test_error_with_available_branches`
- ✓ `test_full_report_shows_branch_names`
- ✓ `test_full_report_shows_verdict`
- ✓ `test_no_deleted_files_section_when_empty`

## test_analyzer.py — TestSaveJsonReport

- ✓ `test_gracefully_handles_write_error`
- ✓ `test_saves_valid_json`

## test_analyzer.py — TestStructuralParserConstants

- ✓ `test_annotated_assignment_tracked`
- ✓ `test_deletion_of_constant_detected_by_structural_analyzer`
- ✓ `test_functions_still_tracked`
- ✓ `test_local_variable_not_tracked`
- ✓ `test_module_level_assignment_tracked`

## test_analyzer.py — TestBinaryFileDeletion

- ✓ `test_binary_files_do_not_inflate_line_counts`

## test_analyzer.py — TestNegativeBranchAge

- ✓ `test_branch_newer_than_target_does_not_crash`
- ✓ `test_zero_age_does_not_trigger_age_flag`

## test_analyzer.py — TestMalformedConfig

- ✓ `test_empty_yaml_falls_back_to_defaults`
- ✓ `test_malformed_yaml_falls_back_to_defaults`

## test_analyzer.py — TestThresholdOrderValidation

- ✓ `test_already_ordered_thresholds_unchanged`
- ✓ `test_out_of_order_age_thresholds_are_sorted`
- ✓ `test_out_of_order_files_thresholds_are_sorted`

## test_analyzer.py — TestCriticalPathScoring

- ✓ `test_critical_deletions_combined_reach_caution`
- ✓ `test_critical_path_flag_text_present`
- ✓ `test_many_critical_deletions_adds_two_points`
- ✓ `test_small_critical_deletions_adds_two_points`
- ✓ `test_zero_critical_deletions_no_bonus`

## test_analyzer.py — TestMarkdownEscaping

- ✓ `test_backtick_in_deleted_filename_escaped`
- ✓ `test_pipe_in_structural_filename_escaped`

## test_analyzer.py — TestPostCheckRun

- ○ `test_main_skips_without_app_id`
- ○ `test_malformed_private_key_raises_clear_error`
- ○ `test_require_env_raises_on_missing_var`
- ○ `test_require_env_returns_stripped_value`

## test_analyzer.py — TestCrossFileAggregation

- ✓ `test_both_gates_met_triggers_critical`
- ✓ `test_count_met_but_ratio_low_is_not_critical`

## test_analyzer.py — TestMalformedConfigWarning

- ✓ `test_malformed_yaml_emits_warning_to_stderr`

## test_analyzer.py — TestStructuralParserJSTS

- ○ `test_js_arrow_function_const_still_detected`
- ○ `test_js_const_deletion_detected`
- ○ `test_ts_const_deletion_detected`

## test_analyzer.py — TestMarkdownTruncation

- ✓ `test_cuts_at_newline_boundary`
- ✓ `test_even_fence_count_not_doubled`
- ✓ `test_long_content_is_truncated`
- ✓ `test_short_content_returned_unchanged`
- ✓ `test_truncation_notice_appended`
- ✓ `test_unclosed_code_fence_is_closed`

## test_analyzer.py — TestSCAAnalysis

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

## test_analyzer.py — TestComplexityAdvisory

- ✓ `test_advisory_does_not_affect_verdict`
- ✓ `test_advisory_includes_threshold_value`
- ✓ `test_complexity_value_correct`
- ✓ `test_custom_threshold_respected`
- ✓ `test_existing_function_not_in_advisory`
- ✓ `test_high_complexity_function_flagged`
- ✓ `test_non_python_file_no_advisory`
- ✓ `test_simple_function_no_advisory`

## test_analyzer.py — TestAddedFileContentScanning

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

## test_analyzer.py — TestINC3UnverifiedFlag

- ✓ `test_safe_with_pr_description_stays_safe`
- ✓ `test_unverified_flag_appears_in_full_analyze_no_description`
- ✓ `test_unverified_on_destructive_changeset_adds_flag`
- ✓ `test_unverified_on_safe_changeset_upgrades_to_review`

## test_analyzer.py — TestGitHubActionsPoisoningScanning

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

## test_analyzer.py — TestSemanticTransparencyV2

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

## test_analyzer.py — TestWorkflowRemediation

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

## tests/proofs/test_z3_properties.py — test_z3_properties

- ✓ `test_p1_typosquat_implies_score_gte_critical_threshold`
- ✓ `test_p2_typosquat_implies_destructive_verdict`
- ✓ `test_p3_typosquat_score_floor_not_cancelled`
- ✓ `test_p4_critical_signal_score_exceeds_high_signal_score`
- ✓ `test_p5_score_monotonicity_adding_critical_signal`
- ✓ `test_p6_safe_verdict_iff_score_below_review_threshold`
- ✓ `test_p7_verdict_deterministic_given_identical_scores`
- ✓ `test_p8_typosquat_cannot_yield_safe_verdict`
- ✓ `test_p9_score_upper_bound_finite`
- ✓ `test_p10_empty_signal_set_always_safe`
