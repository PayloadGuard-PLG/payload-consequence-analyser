# Layer Restructuring Plan: Core/Feature Model

**Status:** Proposal — planning document only, no code changes  
**Version:** 1.0  
**Date:** 2026-05-30

---

## 1. Current State Analysis

PayloadGuard currently defines nine analysis layers (README.md lines 15–30), numbered sequentially:

| Layer | Name | Verified |
|---|---|---|
| L1 | Surface Scan | — |
| L2 | Forensic Analysis | — |
| L2b | SCA (Dependency Scanning) | — |
| L2c | Actions Poisoning | — |
| L3 | Consequence Model | CrossHair C1–C12 · Z3 P1–P10 · Dafny POST-1–12 |
| L4 | Structural Drift | CrossHair S1–S7 · Dafny S1–S7 |
| L4b | PLI Semantic (R&D, not active) | — |
| L5a | Temporal Drift | CrossHair T1–T7 · Dafny T1–T8 |
| L5b | Semantic Transparency | CrossHair M1–M9 |
| L5c | Runtime Agent (eBPF) | — |

### Problem

The layers are numbered sequentially (L1, L2, L2b, L2c, L3, L4, L4b, L5a, L5b, L5c) but not grouped by function, deployment complexity, or dependency footprint. This creates friction:

- **New users** must install tree-sitter, understand eBPF kernel requirements, and parse ten layers before running a basic scan.
- **The README** presents all layers as co-equal, obscuring the fact that L1–L3 work with GitPython alone while L5c requires kernel ≥5.8 and root privileges.
- **Dependency confusion**: `requirements.txt` bundles core and optional dependencies without distinguishing what is needed for basic operation versus advanced features.

---

## 2. Proposed Restructuring

### Core Analysis (L1–L3) — Open Structural Analysis

The minimum viable deployment. A single-script invocation that answers the primary question: *"Is this PR destructive?"*

- **Invocation:** `analyze.py --core`
- **Contains:** L1 Surface Scan, L2 Forensic Analysis, L3 Consequence Model
- **Dependencies:** GitPython, PyYAML only (no tree-sitter, no LLM, no eBPF)
- **Use case:** Basic destructive merge detection for any repository
- **Verification status:** L3 fully verified (CrossHair C1–C12, Z3 P1–P10, Dafny POST-1–12)
- **Score range:** 0–31 (existing `MAX_SCORE`); verdicts SAFE / REVIEW / CAUTION / DESTRUCTIVE
- **Output:** File/line metrics, deletion ratios, critical-path flags, forensic content scan, weighted verdict

### Enhanced Features (by importance/impact)

Features beyond core, grouped into tiers by production readiness, impact, and dependency cost.

#### Tier 1 — High Impact (Recommended for production)

| Feature | Layer | What it detects | Verified | Extra dependencies |
|---|---|---|---|---|
| Structural Drift | L4 | AST-level deletion of named classes, functions, constants | CrossHair S1–S7 · Dafny S1–S7 | tree-sitter + grammar packages |
| Semantic Transparency | L5b | PR description vs diff inconsistency (MCI score) | CrossHair M1–M9 | None (heuristic, no LLM) |
| Actions Poisoning | L2c | CI/CD workflow security: base64 payload, credential harvest, dormant triggers, OIDC elevation, typosquatting | — | None |

#### Tier 2 — Medium Impact (Contextual)

| Feature | Layer | What it detects | Verified | Extra dependencies |
|---|---|---|---|---|
| Temporal Drift | L5a | Branch staleness relative to target velocity | CrossHair T1–T7 · Dafny T1–T8 | None |
| SCA | L2b | Unverified dependencies in package manifests | — | None (opt-in via `allowlist.yml`) |

#### Tier 3 — Advanced/Experimental

| Feature | Layer | What it detects | Verified | Extra dependencies |
|---|---|---|---|---|
| PLI Semantic | L4b | LLM dual-pass: PR description vs diff, commit vs content, old vs new function | — (R&D, not active) | LLM API access (opt-in) |
| Runtime Agent | L5c | eBPF kernel-level monitoring: execve, egress connect, ptrace, /proc/mem | — | Go toolchain, kernel ≥5.8, root privileges |

---

## 3. Proposed README Structure

### Section 1: Quick Start (Core)

Focused onboarding path covering core dependencies only.

- **Installation:** `pip install gitpython pyyaml` (or `pip install payloadguard-plg`)
- **Basic usage:** `python analyze.py <repo> <branch> [target] --core`
- **Example report:** L1–L3 output only — file metrics, forensic flags, verdict
- **GitHub Action snippet:** Minimal workflow using `--core` flag

### Section 2: Enhanced Features

Each tier documented with enablement flags and dependency requirements.

- **Tier 1 features:** Enablement flags, what they add to the report, recommended for production
- **Tier 2 features:** Enablement flags, contextual use cases
- **Tier 3 features:** Enablement flags, system requirements, R&D status disclaimers

### Section 3: Feature Reference

Each feature documented with a consistent template:

- **What it detects** — one-line description
- **Dependencies required** — exact packages or system requirements
- **Verification status** — CrossHair/Z3/Dafny proof references
- **Configuration options** — `payloadguard.yml` keys, CLI flags
- **Performance impact** — approximate overhead relative to core-only execution
- **Score contributions** — points added to the consequence model

---

## 4. Implementation Considerations

### CLI Flag Changes

```
python analyze.py <repo> <branch> [target]
  --core                Run L1–L3 only (default for new users)
  --enhanced            Run all enabled enhanced features
  --enable-structural   Enable L4 Structural Drift
  --enable-semantic     Enable L5b Semantic Transparency
  --enable-actions      Enable L2c Actions Poisoning
  --enable-temporal     Enable L5a Temporal Drift
  --enable-sca          Enable L2b SCA
  --enable-pli          Enable L4b PLI Semantic (experimental)
  --enable-runtime      Enable L5c Runtime Agent (advanced)
  --full                Run all layers (backward-compatible default)
```

### Configuration Changes

`payloadguard.yml` feature toggles section:

```yaml
features:
  core: true           # L1–L3 (always enabled)
  structural: true     # L4 — default: enabled in standard preset
  semantic: true       # L5b — default: enabled in standard preset
  actions: true        # L2c — default: enabled in standard preset
  temporal: false      # L5a — default: disabled (opt-in)
  sca: false           # L2b — default: disabled (requires allowlist.yml)
  pli: false           # L4b — default: disabled (experimental)
  runtime: false       # L5c — default: disabled (requires kernel ≥5.8)
```

Default behavior: core only. Enhanced features opt-in via config or CLI flags.

### Backward Compatibility

- **Current behavior** (all layers) preserved with `--full` flag
- **No flags specified:** runs `--full` for backward compatibility during transition period; deprecation warning printed recommending explicit `--core` or `--full`
- **Existing `action.yml` consumers:** unaffected — `--full` is implicit default
- **Score semantics unchanged:** MAX_SCORE remains 31; verdict thresholds unchanged

---

## 5. Migration Path

### Phase 1: Documentation

- Update README with the core/feature structure proposed in Section 3
- Add migration guide for existing users explaining the new flag system
- Document feature dependencies clearly — which packages are needed for which tier
- Update `WHITEPAPER.md` to reflect the tiered architecture

### Phase 2: CLI Implementation

- Add feature flags to `analyze.py` argument parser
- Implement conditional layer execution in `PayloadAnalyzer.analyze()`
- Gate `StructuralPayloadAnalyzer`, `TemporalDriftAnalyzer`, `SemanticTransparencyAnalyzer` behind feature checks
- Update `--help` text to describe core vs enhanced
- Add deprecation warning when running without explicit mode flag

### Phase 3: Configuration

- Add `features:` section to `payloadguard.yml` schema
- Update config loading logic in `analyze.py` to read feature toggles
- Add validation for feature dependencies (e.g., `sca: true` requires `allowlist.yml`)
- Implement presets: `--minimal` (core only), `--standard` (core + Tier 1), `--full` (all)

---

## 6. Benefits

### For New Users

- **Clearer onboarding path:** Start with core (GitPython only), add features as needed
- **Reduced dependency confusion:** tree-sitter not required for basic destructive merge detection
- **Faster initial setup:** `pip install gitpython pyyaml` is sufficient for a working scanner
- **Lower cognitive load:** three core layers instead of ten to understand before first use

### For Existing Users

- **No breaking changes:** backward compatible via `--full` flag
- **Selective execution:** disable unused features for faster scans (skip tree-sitter parsing when structural drift is not needed)
- **Clearer feature understanding:** tier grouping makes it obvious what each layer provides and what it costs

### For Maintenance

- **Independent testability:** core logic (L1–L3) can be tested without tree-sitter, LLM APIs, or eBPF infrastructure
- **Clearer separation of concerns:** each tier has a defined dependency boundary
- **Better documentation organization:** README sections map directly to deployment tiers
- **Simpler CI:** core tests run fast without optional dependencies; enhanced tests run in separate CI jobs

---

## 7. Risks and Mitigations

### Risk: Users may not enable critical features

Users running `--core` only may miss structural drift (L4) or actions poisoning (L2c) signals that would catch sophisticated attacks.

**Mitigations:**
- README documents Tier 1 as "Recommended for production" with clear justification
- Core-only output includes a footer: *"Enhanced features (structural drift, semantic transparency, actions poisoning) are available — run with `--standard` for recommended coverage"*
- Warning in output when core-only mode detects borderline cases (score 3–4) that enhanced layers might escalate

### Risk: Increased CLI complexity

Ten new flags increase the surface area for misconfiguration.

**Mitigations:**
- Presets reduce flag combinations to three common profiles: `--minimal` (core only), `--standard` (core + Tier 1), `--full` (all)
- Sensible defaults: `--standard` preset enables Tier 1 by default in `payloadguard.yml`
- Invalid combinations produce clear error messages (e.g., `--enable-sca` without `allowlist.yml` present)

### Risk: Backward compatibility issues

Existing `action.yml` consumers expect all layers to run.

**Mitigations:**
- No flags = `--full` during transition period (existing behavior preserved exactly)
- `action.yml` updated to pass `--full` explicitly, locking current behavior
- Migration guide documents the transition timeline
- Comprehensive testing of all flag combinations added to test suite before any CLI changes ship
