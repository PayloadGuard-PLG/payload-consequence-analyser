# PayloadGuard — Controlled Disclosure Strategy

This document defines the content classification, disclosure channels, and visibility rationale for the PayloadGuard project family. These tools detect real attack vectors against CI/CD infrastructure. Disclosure is controlled, not casual.

**Author:** Steven Dark | Systems Architect & Security Researcher | Aberdeen, Scotland

---

## Section 1 — Content Classification

All project content is classified into three tiers. Public briefs (`PUBLIC_BRIEF.md` in each repository) contain only Tier 1 material.

### Tier 1 — Fully Public

Architecture descriptions, methodology, and verification results. No operational detection logic exposed.

| Content | Source |
|---|---|
| Five-layer analysis pipeline architecture (L1 Surface, L2 Forensic, L2b SCA, L2c Actions Poisoning, L3 Consequence, L4 Structural, L5a Temporal, L5b Semantic, L5c Runtime) | `analyze.py` lines 926-940, `PayloadAnalyzer` docstring |
| Formal verification approach and results: CrossHair symbolic execution (C1-C12, S1-S7, T1-T7, M1-M9), Z3 SMT proofs (P1-P10), Dafny machine-checked proofs (POST-1-12, S1-S7, T1-T8). 278 tests, 12 Dafny postconditions, 0 errors | `VERIFICATION.md`, `VERIFICATION_SPEC.md` |
| Audit methodology framework: 6 categories (detection gaps, brittle logic, scoring model, available-but-unused, security issues, test coverage), severity framework (HIGH/MEDIUM/LOW) | `AUDIT_LOG.md` |
| Scoring model structure: signal categories, threshold boundaries (SAFE/REVIEW/CAUTION/DESTRUCTIVE), MAX_SCORE 31 | `analyze.py` `_assess_consequence()` |
| AIntegrity thesis: "alignment presupposes epistemology" — epistemic decay detection framework | `Ai-Integrity/README.md` lines 258-264 |
| PLI 5-state interrogation cycle (CONFRONT, DETECT, COUNTER, ESCALATE, FORCE) with 9 categorised failure modes | `Ai-Integrity/README.md` |
| Squad Optimiser calibration methodology: empirical-only constants, epistemic status labelling (confirmed/assumed/invalidated), zero-trust community data policy | `AIntegrity-Squad-Optimiser/CLAUDE.md`, `CALIBRATION_RECORD.md`, `ASSUMPTIONS.md` |
| engineMath.ts 16-stage pure-function pipeline design: exponential cost curves, geometric decay, compounding multipliers | `AIntegrity-Squad-Optimiser/src/logic/` |
| Test harness structure: 41 test cases, 5 tracks, 9 categories, regression runner architecture | `payloadguard-test-harness/HARNESS.md` |

### Tier 2 — Selective

Available to prospective employers, security teams, and vetted collaborators. Under NDA if requested.

| Content | Rationale |
|---|---|
| Specific regex detection patterns for GitHub Actions poisoning (base64 payload, credential harvesting, dormant trigger, forged bot author, OIDC elevation, pull_request_target) | `analyze.py` lines 149-272. These patterns reveal exactly what PayloadGuard looks for — publishing them enables evasion. |
| Red team findings RTA01-RTA05 from the test harness | Confirmed detections and bypass details from live adversarial testing. |
| Known bypass RTA02 (schedule-curl-exfil) and its fix (`_normalize_yaml_content()` applied to credential_harvest loop) | Specific evasion technique and countermeasure — publishing enables copycat attacks. |
| Adversarial test track evasion techniques (14 cases: deletion obfuscation, threshold gaming, workflow poisoning bypasses) | Specific techniques that probe detection boundaries. |
| PLI L4b integration findings: 2 true positives (A03, A06), 3 false positives (WS07, RT02, RTA03), root cause analysis | Reveals current detection limitations. |

### Tier 3 — Private

Not disclosed. Operational security material.

| Content | Classification Rationale |
|---|---|
| Unpublished detection patterns under development | Premature disclosure enables preemptive evasion. |
| Unfixed bypass techniques and open findings: §2.3 single-branch clone/detached HEAD `BadName` exception, §3.5 structural ratio file size context, §1.4 CRITICAL_PATH_PATTERNS yml matching | Open items in `AUDIT_LOG.md` — publishing unfixed issues creates exploitable windows. |
| WS03 dormant-trigger score cap investigation (expected DESTRUCTIVE, getting CAUTION at score=3) | Active investigation — publishing partial analysis risks misinterpretation. |
| INC-3 direct push to main bypass (L5b returns UNVERIFIED, raises no flag) | Unfixed detection gap. |

---

## Section 2 — Professional Disclosure Channels

Disclosure follows the conventions of security research. Channels are specific, named, and appropriate to the work.

### GitHub Security Team

**Contact:** GitHub Security Bug Bounty programme and GitHub Security Lab.

PayloadGuard detects a specific class of attack against GitHub Actions — PR-based supply chain poisoning. This is directly relevant to GitHub's platform security. Potential outcomes: bug bounty, case study, referral to GitHub's internal detection team.

**What to share:** Tier 1 architecture overview + Tier 2 detection patterns (under coordinated disclosure terms). Demonstrate that PayloadGuard catches attack classes that GitHub's own tooling does not flag.

### NCSC (UK National Cyber Security Centre)

**Contact:** [ncsc.gov.uk](https://www.ncsc.gov.uk/) — Active Cyber Defence programme, Vulnerability Reporting.

The NCSC runs programmes for UK-based security researchers. Supply chain security is an explicitly stated NCSC priority. PayloadGuard's CI/CD poisoning detection work aligns with their published threat assessments.

**What to share:** Tier 1 public brief + formal verification results. The three-method verification approach (CrossHair + Z3 + Dafny) demonstrates rigour appropriate for government-facing security work.

### Conference Submissions

**Target venues:**
- **BSides Scotland** — regional security conference, appropriate for first public presentation.
- **ScotSec** — Scottish cybersecurity conference, industry-focused audience.
- **BSides London / 44CON** — larger UK security conferences for broader visibility.

**Suggested talk titles:**
- *"Formal Verification of Supply Chain Security Scoring Models"* — focuses on the three-method verification approach as applied to security tooling.
- *"Detecting GitHub Actions Poisoning Without Running the Workflow"* — focuses on static analysis of workflow files for credential harvesting, dormant triggers, and OIDC escalation.

**What to share:** Tier 1 content only in public talks. Tier 2 material available in private Q&A or hallway conversations with verified security professionals.

### Private Demonstrations — Security Companies

Direct, private demonstrations to companies whose product space intersects with PayloadGuard's capabilities:

| Company | Relevance |
|---|---|
| **Snyk** | Supply chain security, dependency scanning. PayloadGuard's L2b SCA and L2c Actions Poisoning complement Snyk's focus. |
| **Socket.dev** | Package supply chain analysis. Shared problem space — detecting malicious contributions before merge. |
| **StepSecurity** | GitHub Actions security hardening. Direct overlap — StepSecurity hardens workflows, PayloadGuard detects poisoned ones. |
| **Chainguard** | Supply chain integrity and provenance. PayloadGuard's formal verification approach aligns with Chainguard's provenance model. |
| **GitGuardian** | Secret detection in code. Complementary — GitGuardian finds leaked secrets, PayloadGuard finds the PR that would introduce the leak vector. |

**What to share:** Tier 1 + Tier 2 under NDA. These companies understand controlled disclosure — they practice it themselves.

---

## Section 3 — The 0.00 Influence Score

Steven Dark's public visibility score is zero. This is a deliberate consequence of responsible development, not a career deficiency.

Security researchers do not build visibility by broadcasting detection techniques on social media. They build it by:

1. **Producing working tools** that detect real threats — PayloadGuard, AIntegrity, the test harness.
2. **Formally verifying** their claims — three independent proof systems, 278 tests, 12 Dafny postconditions.
3. **Conducting controlled adversarial testing** — 41 test cases across 5 tracks, including live red-team exercises.
4. **Documenting systematically** — audit logs, calibration records, verification specs, architectural whitepapers.
5. **Disclosing responsibly** — through named channels to appropriate audiences, not public blast.

The zero influence score is the expected state for someone who has been building detection tooling for three months rather than posting about it. The disclosure strategy documented here is how that changes — through professional channels, not social media engagement metrics.

**Development context:** All four repositories were built solo, from a phone, using AI-directed development (Claude). No team, no IDE, no desktop. GitRoll independent code quality scores: 4.99/5.00 Reliability, 4.99/5.00 Security, 4.99/5.00 Maintainability.

---

## Revision History

| Date | Change |
|---|---|
| 2026-05-30 | Initial strategy document created. |
