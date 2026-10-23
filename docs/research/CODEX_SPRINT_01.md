# Codex Task Queue - First Engineering Sprint (research handover)
Date: 2026-10-21 | Execution: ONE TASK AT A TIME | Default: no live PR harness runs

## Task 0 - Baseline only
Read research dossier, structural_parser.py, L4 consumers, current test manifest and HARNESS.md. Record exact SHAs, language/toolchain capabilities, current verdict mapping, parser failure paths and source/test contradictions. Produce a markdown evidence ledger. No code edits, no live harness, no credentials.
Acceptance: every inspected file listed, verified facts separate from hypotheses, A03/A06 known misses recorded.

## Task 1 - Parser completeness contract
Design opt-in structured parser status (available / failed / unsupported / timeout), source ranges and error provenance. Preserve extract_named_nodes API and legacy scoring. Prototype parser failures with local isolated unit fixtures only when authorized.
Acceptance: missing Tree-sitter grammar never silently appears as 'nothing removed'; old verdicts unchanged.

## Task 2 - SymbolFact v1
Add richer facts (language, kind, qualified identity, signature, file span, version, body digest) while retaining legacy output. Cover Python, JS/TS, Go, Rust, Java and parser-absent controls.
Acceptance: frozen fixture oracle, stable sort/IDs, deterministic round-trip and no legacy drift.

## Task 3 - Shadow move/rename/body-weakening delta
Match exact identity, qualified signature, moved signature and corroborated AST/body similarity. Emit REMOVED, MOVED, RENAMED, BODY_CHANGED and UNKNOWN independently. Do not change merge decision.
Acceptance: pure rename safe, rename+gutting detected, ambiguous refactor uncertain rather than destructive.

## Task 4 - Compound loss research fixture
Prototype offline semantic-loss aggregate covering A03/A06 with paired benign refactor control. Surface feature contributions and evidence, do not silently change A03/A06 expected verdicts.
Acceptance: experiment ledger describes signal quality, misses, FP tradeoff, effect on PR latency.

## Task 5 - Harness oracle versioning
Schema v2 for expected/forbidden findings, capabilities and immutable fixtures; retain previous case manifest fields, avoid moving live branches. Resolve TEST_SPEC/HARNESS drift by generated tables.
Acceptance: old ingestion remains valid and newly generated docs match canonical machine-readable spec.

## Stop / escalation gates
Stop and request review if: current SHA differs unexpectedly, parser output is suppressed without status, a legacy verdict changes, real untrusted code would execute, network or credentials are required, compiler model is unavailable but result reports full coverage, or review cannot reproduce test evidence.

Each response to the user must cover only the selected task and its measured outcome, not silently advance to the next.
