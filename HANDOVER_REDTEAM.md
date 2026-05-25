# PayloadGuard — Red-Team Handover

**Date:** 2026-05-25  
**For:** Next Claude session with access to PayloadGuard-PLG/AIntegrity-Squad-Optimiser  
**Delete this file after reading.**

---

## What PayloadGuard Is

A GitHub Action and Python CLI that scans pull requests for destructive merge payloads before they land on main. It does not look for bugs — it looks for PRs that would catastrophically gut a codebase, poison CI pipelines, or exfiltrate credentials. Org: PayloadGuard-PLG.

Repos:
- PayloadGuard-PLG/payload-consequence-analyser — the analyser engine
- PayloadGuard-PLG/payloadguard-test-harness — regression test harness
- PayloadGuard-PLG/AIntegrity-Squad-Optimiser — target repo for red-team (Steven's football management app, React Native / Expo)

---

## Current State (as of this handover)

### payload-consequence-analyser

Main is at commit 4ea66e9. Layer 2c (GitHub Actions workflow poisoning detection) is live. All five detection layers are operational:

- L1 Surface: file/line counts, deletion ratio
- L2 Forensic: critical path regex on deleted files
- L2b SCA: manifest diff vs allowlist.yml
- L2c Actions Poisoning: scans added and modified .github/workflows/ files for seven signal types
- L3 Consequence: severity scoring to SAFE/REVIEW/CAUTION/DESTRUCTIVE
- L4 Structural: AST diff for named class/function/constant deletions
- L5a Temporal: branch age x target velocity drift score
- L5b Semantic: PR description vs actual severity

Layer 2c signal types and scoring:
- base64_payload: CRITICAL, score +5
- credential_harvest: CRITICAL, score +5
- pull_request_target_with_write_permissions: CRITICAL, score +5
- dormant_trigger_with_payload: HIGH, score +3
- forged_bot_author: HIGH, score +3
- oidc_elevation_no_consumer: HIGH, score +3
- dangerous_trigger_pull_request_target: HIGH, score +3

Score thresholds: >=5 DESTRUCTIVE, >=3 CAUTION, >=1 REVIEW.

Three hardening fixes are in place: YAML folded/literal block normalisation (prevents multi-line base64 bypass), exact-match OIDC consumer allowlist (prevents typosquatting bypass), pull_request_target two-tier scoring (prt alone = HIGH, prt + any write permission = CRITICAL).

Unit test suite: 194 tests passing, 7 skipped (crypto/tree-sitter env).

### payloadguard-test-harness

Main is at latest merge. 12 Layer 2c test branches exist and have been scanned live. All 12 verdicts confirmed correct against expected outcomes. The harness CI is pinned to analyser SHA 83826a5f3204d74afef5e1a930e7d60bfd1b8cba (Layer 2c enabled).

Confirmed working signals from live run:
- WS01: base64_payload caught correctly (DESTRUCTIVE)
- WS02: credential_harvest caught correctly (DESTRUCTIVE)
- WS03: dormant_trigger caught correctly (DESTRUCTIVE — note L2b also fires on curl|bash in yml files, pushing score higher than L2c alone)
- WS04: forged_bot_author caught correctly (CAUTION)
- WS05: oidc_elevation_no_consumer caught correctly (CAUTION)
- WS06: prt + write permissions caught correctly (DESTRUCTIVE)
- WS07: clean workflow not flagged (SAFE — no false positive)
- AW01: YAML folded block base64 caught correctly (DESTRUCTIVE — normalisation working)
- AW02: prt-only correctly scores HIGH not CRITICAL (CAUTION)
- AW03: typosquatted OIDC consumer correctly rejected (CAUTION — oidc signal is always HIGH regardless)
- AW04: legitimate aws-actions/ consumer not flagged (SAFE — no false positive)
- AW05: modified workflow (M change_type) caught correctly (DESTRUCTIVE)

### AIntegrity-Squad-Optimiser

Steven has PayloadGuard installed on this repo. A fix commit was pushed on branch claude/test-connection-I2s8B adding fetch-depth 0 and pull-requests write permission to the PayloadGuard workflow. The repo is a React Native / Expo football management app. Steven confirmed the setup looks good from his Termux terminal.

---

## The Red-Team Exercise

The purpose is to find Layer 2c bypass gaps that unit tests and the controlled harness cannot catch. The Squad Optimiser is a real consumer repo with a real codebase — running adversarial PRs against it tests PayloadGuard in a more realistic context and may reveal detection gaps caused by interactions with the actual repo structure, workflow configuration, or edge cases in the diff format.

### How to Run

For each scenario:
1. Create a branch from the Squad Optimiser default branch
2. Add or modify a .github/workflows/ file with the adversarial payload
3. Open a PR against the default branch
4. PayloadGuard scans automatically
5. Record the verdict against the expected verdict
6. Do not merge — close the PR when done

### Red-Team Scenarios to Run

These are the bypass attempts that have NOT yet been tested in the live harness because they require a real consumer repo context:

RTA-01: Multi-step payload via environment variable injection
Create a workflow that sets an env var to a base64 string in one step and decodes it in a second step. The two steps individually look clean — the payload only executes when chained. Expected: SAFE (this is a known gap — multi-step detection requires YAML parsing, not regex).

RTA-02: GITHUB_OUTPUT / GITHUB_STEP_SUMMARY exfiltration
Create a workflow with: echo "token=${{ secrets.GITHUB_TOKEN }}" >> $GITHUB_OUTPUT. This exfiltrates the token via GitHub's own step output mechanism, not via curl or env grep. Expected: SAFE (this pattern is not yet in _ACTIONS_CREDENTIAL_HARVEST).

RTA-03: Unpinned third-party action with suspicious name
Create a workflow using: uses: random-user/data-collector@main. No base64, no credential grep, no OIDC. A supply chain risk via unpinned action reference. Expected: SAFE (unpinned action advisory not yet implemented).

RTA-04: Workflow with on: push trigger and rm -rf in run step
A workflow that runs rm -rf node_modules or similar on push. Not a credential harvest or base64 payload — destructive shell execution not covered by current patterns. Expected: depends on whether rm -rf matches _CONTENT_SHELL_PATTERNS.

RTA-05: Schedule trigger (cron) with exfiltration payload
A workflow using on: schedule with a curl exfiltration. The dormant_trigger signal currently checks workflow_dispatch and schedule separately. This tests the schedule path specifically. Expected: DESTRUCTIVE if schedule + shell is caught by dormant_trigger_with_payload composite.

RTA-06: pull_request_target with checkout of untrusted head SHA combined with script execution
Classic pwn-request pattern: uses actions/checkout with ref: ${{ github.event.pull_request.head.sha }} inside a prt workflow. No write permissions declared — tests whether the checkout-of-untrusted-ref is flagged independently of permissions. Expected: CAUTION (prt alone = HIGH +3).

RTA-07: Workflow that only modifies GITHUB_ENV (environment file injection)
echo "PATH=/attacker/bin:$PATH" >> $GITHUB_ENV. Poisons the environment for subsequent steps. Not base64, not metadata endpoint, not env grep. Expected: SAFE (GITHUB_ENV injection not yet a signal).

RTA-08: Clean-looking workflow with obfuscated base64 via variable substitution
A=$(echo "cGF5bG9hZA=="); echo $A | base64 -d | bash. The base64 string is assigned to a variable first — regex looks for the decode pattern, not the assignment. Expected: depends on whether the pattern matches across the variable indirection.

### Recording Results

For each RTA, record:
- Actual verdict
- Which signals fired (from the Layer 2c table in the PR comment)
- Whether the result matches expected
- If SAFE when a flag was expected: this is a confirmed bypass gap — log it as a new finding for the next development sprint

### Known Gaps Already Documented (do not re-test)

- Multi-step payload (RTA-01 above) — requires YAML parsing
- GITHUB_OUTPUT exfiltration (RTA-02 above) — pattern not yet added
- Unpinned uses references advisory (RTA-03 above) — not yet implemented

These three are the post-red-team Session 2 fix targets mentioned in the original handover.

---

## Development Rules

- Branch for analyser work: new branch off main
- Branch for harness work: new branch off main
- Tests: python -m pytest test_analyzer.py -v before every commit — must stay green at 194 pass
- Push: git push -u origin branch-name
- No MCP push_files: confirmed broken, do not retry
- Commit style: imperative, specific, with test count in body

## Open Findings

INC-3 (MEDIUM): direct push to main causes L5b to return UNVERIFIED but raises no flag. Low urgency. Documented in AUDIT_LOG.md.

---

## How to Start

1. Read this file — you now have full context
2. Confirm Squad Optimiser repo access via MCP GitHub tools
3. Check the PayloadGuard workflow on the Squad Optimiser is correctly configured (fetch-depth 0, pull-requests write, triggers on pull_request opened/synchronize/reopened)
4. Begin RTA-01 through RTA-08 in order
5. After all eight, triage the bypass gaps and open issues or begin fixes as appropriate
