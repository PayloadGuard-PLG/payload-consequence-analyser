# Agent instructions - PayloadGuard research branch

Applies to all coding/research agents operating in this checkout.

## First-read context
1. Read docs/research/PAYLOADGUARD_CONSEQUENCE_RESEARCH_2026-10-21.md in full.
2. Read docs/research/CODEX_SPRINT_01.md before proposing or writing implementation changes.
3. Inspect actual source and tests; never treat research hypotheses, README claims or test manifest expected results as independently measured outcomes.
4. The separate live PR harness is https://github.com/PayloadGuard-PLG/payloadguard-test-harness . Its current A03 and A06 SAFE expectations are known missed consequence classes, not success criteria.

## Non-negotiable execution policy
- Work only in the authorized branch. Do not mutate main, reset branches, force-push, or merge without explicit permission.
- This branch begins documentation-only. The report is a proposal, not permission to run live regressions.
- Do not trigger the live PR regression harness, issue a credential-based scan, start eBPF, or execute untrusted code without explicit authorization.
- Never equate a missing parser/toolchain with an absence of consequence. Emit incomplete coverage.
- Preserve legacy verdict/exit-code compatibility while new detectors operate in shadow mode.
- New detectors are advisory until calibrated by independent positive and negative examples and approved for policy gating.
- Keep developer friction as a measured release criterion. Findings must show base/head evidence, affected entities, uncertainty and an actionable resolution.
- Do not transmit repository source to a remote LLM/service by default.
- Small sequential changes only: one verifiable task, evidence review, then next task.

## Output for each Codex task
Report current SHA; modified paths; hypothesis; implementation; tests/fixtures invoked and outcomes; false-positive controls; performance; security impact; unfinished limitations; rollback. If any cannot be verified, label it unknown.

## Source of truth
Research dossier: docs/research/PAYLOADGUARD_CONSEQUENCE_RESEARCH_2026-10-21.md
Task queue: docs/research/CODEX_SPRINT_01.md
Do not auto-merge this research branch or promote experimental score changes.
