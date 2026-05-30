# PayloadGuard — Controlled Disclosure Strategy

**Author:** Steven Dark | Aberdeen, Scotland
**Date:** 2026-05-30
**Status:** Active

---

## Purpose

This document defines the three-tier content classification framework for responsible disclosure of PayloadGuard's security tooling, research findings, and detection methodologies. All public-facing documentation, conference materials, and employer communications must comply with these tier boundaries.

---

## Tier 1 — Fully Public

Content in this tier may be shared without restriction. It describes *what* PayloadGuard does and *how it was verified*, without revealing specific detection signatures or bypass techniques.

### Architecture
- Nine-layer analysis pipeline (Surface, Forensic, SCA, Actions Poisoning, Consequence Model, Structural Drift, PLI Semantic, Temporal Drift, Semantic Transparency, Runtime Agent)
- Layer responsibilities and interaction model
- Pipeline flow from PR event to verdict

### Formal Verification
- Verification approach and results: CrossHair symbolic execution + Z3 SMT proofs + Dafny machine-checked proofs
- 278 tests, 12 Dafny postconditions, 0 errors
- Three orthogonal proof systems covering the entire scoring and classification logic
- Public verification spec (`VERIFICATION.md`, `VERIFICATION_SPEC.md`)

### Audit Methodology
- Six audit categories: detection gaps, brittle logic, scoring model, available-but-unused, security issues, test coverage
- Severity framework: HIGH / MEDIUM / LOW
- Public findings register (`AUDIT_LOG.md`)

### Calibration Methodology
- Empirical calibration approach: back-calculated constants from observed data
- Epistemic status labelling: confirmed, assumed, invalidated
- Self-correcting methodology with evidence chain

### AIntegrity Thesis
- Epistemic decay in AI systems
- PLI (Persistent Logical Interrogation) methodology
- Behavioral consistency auditing framework

### PLI Methodology
- Five-state interrogation cycle (CONFRONT, DETECT, COUNTER, ESCALATE, FORCE)
- Nine categorised failure modes
- Trust grading and temporal decay model

### engineMath Pipeline Design
- 16-stage pure-function mathematical pipeline
- Exponential cost modelling with geometric decay
- Empirical calibration under uncertainty

---

## Tier 2 — Selective Disclosure

Content in this tier is shared only with vetted parties under appropriate context. It includes specific technical details that could be misused if published broadly but are necessary for security collaboration and employment evaluation.

### Content
- Specific regex detection patterns for GitHub Actions poisoning
- Red team findings RTA01–RTA05 (attack vectors, detection results, bypass attempts)
- Known bypass RTA02 and the fix applied (multiline curl continuation detection)
- Adversarial test track evasion techniques (deletion obfuscation, threshold gaming, workflow poisoning bypasses)

### Approved Recipients
- **Security companies:** Snyk, Socket.dev, StepSecurity, Chainguard, GitGuardian
- **Platform security teams:** GitHub Security team
- **Prospective employers:** Under NDA or mutual confidentiality agreement

### Disclosure Protocol
1. Verify recipient identity and affiliation
2. Confirm appropriate context (security research collaboration, employment evaluation, or responsible disclosure)
3. Share via secure channel (encrypted email, private repository access, or in-person demonstration)
4. Document disclosure date, recipient, and scope in internal log

---

## Tier 3 — Private

Content in this tier is not disclosed externally. It includes unpublished detection capabilities and known gaps that could be exploited if revealed.

### Content
- Unpublished detection patterns not yet in the public codebase
- Unfixed bypass techniques — items marked "Open" in the audit log:
  - §1.4 `CRITICAL_PATH_PATTERNS` YML matching gaps
  - §2.3 Single-branch clone / detached HEAD `BadName` exception
  - §3.5 Structural ratio file-size context limitations
- Experimental detection approaches under development
- Internal red team planning and methodology

### Rationale
These items represent active security gaps. Disclosing them before fixes are implemented would provide a roadmap for circumventing PayloadGuard's protections. They will be reclassified to Tier 2 or Tier 1 once mitigations are in place.

---

## Professional Disclosure Channels

### Security Teams
- **GitHub Security team** — responsible disclosure of findings related to GitHub Actions attack surface
- **NCSC (UK National Cyber Security Centre)** — reporting on CI/CD supply chain threat patterns observed during research

### Conference & Community
- **BSides Scotland / ScotSec** — conference talks on CI/CD supply chain security, formal verification of security tools
- **Private demonstrations** — live demonstrations of detection capabilities to target companies (Tier 2 recipients)

### Publication
- Research papers published under author name with appropriate Tier 1 content only
- Open-source codebase with detection logic visible but Tier 3 patterns excluded

---

## On the GitRoll Influence Score

The 0.00 GitRoll influence score is a deliberate consequence of responsible development practices, not a career deficiency.

PayloadGuard was developed as a solo project over three months, primarily from a mobile device, using AI-directed development. The project prioritised:

- **Correctness over visibility:** Formal verification (CrossHair, Z3, Dafny) rather than social engagement
- **Depth over breadth:** Nine-layer analysis with three orthogonal proof systems rather than multiple shallow projects
- **Responsible disclosure over self-promotion:** Security-sensitive detection patterns classified and protected rather than published for stars
- **Empirical rigour over rapid shipping:** Every constant back-calculated from observed data, every assumption labelled with epistemic status

Influence metrics measure community engagement. They do not measure architectural depth, verification rigour, or responsible handling of security-sensitive material. The GitRoll quality scores (4.99 Reliability, 4.99 Security, 4.99 Maintainability) reflect what the code actually is.
