# PayloadGuard — Controlled Disclosure Strategy

**Author:** Steven Dark  
**Date:** May 2026  
**Context:** Four repositories under PayloadGuard-PLG, developed solo over 3 months via AI-directed development from a mobile device. These tools detect real attack vectors against CI/CD infrastructure. This document defines what can be shared, with whom, and through which channels.

---

## Framing

PayloadGuard detects GitHub Actions poisoning, credential harvesting, OIDC elevation attacks, forged bot identities, and semantic mismatch in pull requests. AIntegrity audits LLM behavioral integrity. The test harness contains documented red-team findings against live detection logic.

Publishing detection patterns carelessly would help attackers understand what is detected and craft bypasses. The same applies to AIntegrity's interrogation methodology and the test harness's adversarial track findings. The 0.00 influence score on GitRoll is a feature of responsible development — not a bug in the career strategy.

This document mirrors how security researchers actually operate: controlled disclosure, trusted channels, professional reputation built through demonstrated competence rather than social media reach.

---

## 1. Classification Tiers

### Tier 1 — Fully Public

Architecture, methodology, and empirical results. Safe to share without restriction because they describe *what* is measured and *how correctness is established*, not *what patterns trigger detection*.

| Item | Source | Why it's safe |
|------|--------|---------------|
| 5-layer analysis pipeline architecture | `analyze.py:926-940` — Surface Scan, Forensic Analysis, Consequence Model, Structural Drift, Extended Analysis | Describes the measurement framework, not specific signatures |
| Formal verification approach and results | `VERIFICATION.md` — CrossHair + Z3 + Dafny, 278 tests, 12 Dafny postconditions verified, 0 errors | Proves correctness properties; reveals no detection rules |
| Audit methodology framework | `AUDIT_LOG.md` — 6-category scope, severity framework, step-by-step methodology | Shows rigor; describes how to audit, not what to detect |
| Dual-gate structural drift invariant | `VERIFICATION.md` S1–S7 — DESTRUCTIVE requires BOTH ratio > threshold AND count >= min | A defensive design property, not an attack surface |
| AIntegrity thesis | `Ai-Integrity/README.md:258-264` — "alignment presupposes epistemology" | Foundational research claim; no operational signatures |
| PLI 5-state interrogation cycle | CONFRONT, DETECT, COUNTER, ESCALATE, FORCE | Methodology description; adversaries cannot bypass a methodology by knowing its names |
| engineMath.ts 16-stage pipeline | `AIntegrity-Squad-Optimiser/src/engine/engineMath.ts:1-30` — pure-function architecture | Game simulation mathematics; no security content |
| Scoring thresholds | score >= 5 → DESTRUCTIVE, >= 3 → CAUTION, >= 1 → REVIEW | Already implied by any user of the Action seeing verdicts |
| Three-method verification stack | CrossHair (dynamic symbolic execution), Z3 (SMT proof), Dafny (machine-checked proof) | Tooling choices are public knowledge |

### Tier 2 — Share Selectively

With prospective employers, security teams, or conference programme committees. Under NDA if the recipient requests it, or in a controlled demonstration environment.

| Item | Source | Why it's sensitive |
|------|--------|-------------------|
| Specific regex detection patterns for Actions poisoning | `analyze.py:149-272` — base64 payload, credential harvest, OIDC elevation, env injection patterns | Knowing exact regex enables crafting payloads that evade them |
| Red-team session findings RTA01–RTA05 | `payloadguard-test-harness/HARNESS.md:66-70` | Documents confirmed detection gaps and bypasses |
| RTA02 known bypass and fix | `_normalize_yaml_content()` applied to credential_harvest loop | Shows exactly what was missed and how to trigger the old gap |
| Adversarial test track specifications | `payloadguard-test-harness/TEST_SPEC.md` Track 2 & 4 | Evasion techniques tested and documented |
| PLI integration findings | 3 false positives via format mismatch — demonstrates limitation understanding | Shows where the detection has known blind spots |

### Tier 3 — Keep Private

Active detection signatures that would directly aid bypass if disclosed. No sharing outside the development context.

| Item | Why it stays private |
|------|---------------------|
| Unpublished detection patterns not yet in the public repo | Premature disclosure creates a window for attackers before the pattern is deployed |
| Bypass techniques marked "Open" in the audit log (WS03, INC-3) | Unfixed gaps — disclosure before fix enables exploitation |
| Internal scoring weights and cap logic beyond what's in README | Fine-grained knowledge enables threshold gaming (as demonstrated by A06) |
| Future detection patterns under development | Operational security for unreleased work |

---

## 2. Professional Disclosure Channels

### 2.1 GitHub Security Team — Responsible Disclosure

**What to share:** The Actions poisoning detection work (Tier 1 architecture + Tier 2 patterns under their responsible disclosure program).

**Why:** GitHub's security team evaluates supply-chain threats to Actions. PayloadGuard detects six distinct poisoning vectors in workflow files. This is directly relevant to their platform security.

**Expected outcome:** Bug bounty consideration, potential case study, professional relationship, possible referral. GitHub's security team is small and accessible.

**Contact:** https://github.com/security/advisories — submit as a research disclosure, not a vulnerability report. Frame as "detection methodology for a class of attacks against GitHub Actions."

### 2.2 NCSC (UK National Cyber Security Centre)

**What to share:** Summary of the supply-chain security detection framework and formal verification approach.

**Why:** NCSC has active interest in software supply chain security. UK-based researchers are eligible for their Cyber Security Research programmes regardless of location within the UK.

**Expected outcome:** Formal recognition, potential research collaboration, access to NCSC's industry network.

**Contact:** https://www.ncsc.gov.uk/section/about-ncsc/contact-us — reference their Active Cyber Defence programme and supply chain security guidance.

### 2.3 Conference Submissions

**Target conferences:**
- **BSides Scotland** — appropriate venue for a talk on CI/CD security detection. Accessible, professional, security-focused audience.
- **ScotSec** — Scottish security community. Local presence, professional credibility.
- **OWASP Scotland** — supply chain security is directly within scope.

**Talk titles (Tier 1 content only):**
- "Formal Verification of Supply Chain Security Scoring Models"
- "Detecting GitHub Actions Poisoning Without Running the Workflow"
- "Nine Layers Deep: Static Analysis for Destructive Merge Prevention"

**Content boundary:** Architecture, verification methodology, and empirical results (Tier 1). Detection patterns (Tier 2) disclosed only in closed-session Q&A with programme committee approval.

### 2.4 Private Demonstration to Target Companies

**Target organisations:**
- **Snyk** — supply chain security is their core product
- **Socket** — npm/PyPI supply chain detection
- **StepSecurity** — GitHub Actions hardening (direct competitor/acquirer)
- **Chainguard** — supply chain provenance and verification
- **Endor Labs** — dependency risk scoring

**Approach:** Direct message to engineering leadership or security research leads. Offer a private walkthrough of the detection methodology and verification stack. Security companies understand controlled disclosure — they operate the same way.

**What to show:** Full Tier 1 + selective Tier 2 under mutual understanding of sensitivity. Demonstrate the formal verification stack, the test harness methodology, and the detection architecture.

### 2.5 Academic Publication

**Target:** Preprint on arXiv (cs.CR or cs.SE) documenting the formal verification methodology applied to security scoring models.

**Content:** Verification approach (CrossHair + Z3 + Dafny), contract specifications, proof methodology. Does not require disclosing detection patterns — the novelty is in applying formal methods to security tooling, not in the patterns themselves.

---

## 3. Public Brief Documents

Each repository gets a `PUBLIC_BRIEF.md` — a document designed for external readers that explains what the project does, how it's verified, and what it demonstrates about the author's capabilities, without revealing operational signatures.

| Repository | Brief focus |
|------------|-------------|
| `payload-consequence-analyser` | 9-layer architecture, formal verification (3 methods, 278 tests), scoring model properties |
| `Ai-Integrity` | Behavioral auditing framework, PLI methodology, VIL cryptographic audit trail, trust grading |
| `AIntegrity-Squad-Optimiser` | Pure-function 16-stage mathematical pipeline, OCR integration, exponential cost modelling |
| `payloadguard-test-harness` | Adversarial validation methodology, 41 test cases across 9 categories, regression automation |

---

## 4. Portfolio Landing Page (GitHub Pages)

A single `index.html` hosted on GitHub Pages that serves as a professional landing page for direct outreach. Not a blog. Not a portfolio to accumulate stars.

**Contains:**
- Project summaries linking to each PUBLIC_BRIEF.md
- GitRoll scores: 4.99 reliability / 4.99 security / 4.99 maintainability
- Development context: 3 months, solo, AI-directed from a mobile device
- Contact method (email or form)
- Links to any published talks, papers, or disclosures

**Does not contain:**
- Detection signatures or pattern details
- Links to raw source code of detection modules
- Social sharing buttons or star counts
- Casual language or self-promotion

---

## 5. Implementation Sequence

1. **Immediate:** Create `PUBLIC_BRIEF.md` in each repository (Tier 1 content only).
2. **Immediate:** Deploy GitHub Pages landing page.
3. **Week 1:** Submit responsible disclosure to GitHub Security team.
4. **Week 2:** Contact NCSC via their researcher engagement programme.
5. **Week 3:** Submit CFP to BSides Scotland or next available ScotSec event.
6. **Week 4:** Direct outreach to 2–3 target companies with a one-paragraph summary and offer of private demonstration.
7. **Ongoing:** Maintain Tier classification as new features are developed. Re-evaluate Tier 2 items for promotion to Tier 1 after fixes are deployed and regression-validated.

---

## 6. What This Strategy Avoids

- **Public dumps of detection patterns** — enables bypass crafting
- **"Star farming" on social media** — attracts noise, not employers
- **Making repos public before classification** — irreversible exposure
- **Conference talks that reveal Tier 2 content** — professional reputation damage if attendees use patterns adversarially
- **Rushing disclosure for attention** — security researchers build reputation through demonstrated restraint and competence, not speed

---

## Document Maintenance

Update this document when:
- A Tier 3 item is fixed and can be promoted to Tier 2
- A Tier 2 item is disclosed through a channel and can be promoted to Tier 1
- New detection patterns are added (classify immediately)
- A disclosure event occurs (record date, channel, content shared, outcome)
