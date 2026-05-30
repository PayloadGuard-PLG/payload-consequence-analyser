# PayloadGuard — Layer Restructuring Plan

**Author:** Steven Dark | Aberdeen, Scotland
**Date:** 2026-05-30
**Status:** Planning document — no code changes proposed

---

## Purpose

This document proposes restructuring PayloadGuard's nine analysis layers from a flat, numbered sequence into a core/feature model. The goal is to make the tool accessible to users who need basic destructive merge detection without requiring them to understand or configure nine layers, while preserving full capability for advanced deployments.

---

## Current State

Nine layers numbered L1–L5c, all run by default, documented sequentially:

| Layer | Name | Dependencies |
|-------|------|-------------|
| L1 | Surface Scan | GitPython |
| L2 | Forensic Analysis | GitPython |
| L2b | SCA | GitPython, PyYAML |
| L2c | Actions Poisoning | GitPython |
| L3 | Consequence Model | (pure logic) |
| L4 | Structural Drift | tree-sitter (optional) |
| L4b | PLI Semantic | LLM API (R&D status) |
| L5a | Temporal Drift | GitPython |
| L5b | Semantic Transparency | (pure logic) |
| L5c | Runtime Agent | Go, eBPF, kernel ≥5.8 |

All layers run unless explicitly disabled. Users must read the full documentation to understand which layers apply to their use case.

---

## Proposed Structure

### Core (L1–L3)

Single-script deployment for basic destructive merge detection.

**Layers:** Surface Scan + Forensic Analysis + Consequence Model
**Dependencies:** GitPython only
**Use case:** Basic destructive merge detection for any repository
**Verification status:** L3 verified — CrossHair C1–C12, Z3 P1–P10, Dafny POST-1–12

The core provides the fundamental capability: detecting PRs that would catastrophically gut a codebase through mass deletions, critical path modifications, or deceptive descriptions. This covers the most common and most damaging attack vectors.

### Enhanced Tier 1 — High Impact (Recommended)

**Layers:**
- **L4 Structural Drift** — AST-level detection of deleted classes/functions/constants. Verified: CrossHair S1–S7.
- **L5b Semantic Transparency** — PR description vs. diff consistency (MCI heuristic). Verified: CrossHair M1–M9.
- **L2c Actions Poisoning** — Workflow file analysis for CI/CD attack patterns.

**Rationale:** These layers address the most sophisticated attack vectors (structural gutting disguised as refactoring, deceptive PR descriptions, workflow poisoning) with minimal additional dependencies.

### Enhanced Tier 2 — Contextual

**Layers:**
- **L5a Temporal Drift** — Branch age and target velocity risk scoring. Verified: CrossHair T1–T8.
- **L2b SCA** — Dependency manifest scanning (opt-in via allowlist).

**Rationale:** Useful in specific contexts (long-lived branches, dependency management) but not universally required.

### Enhanced Tier 3 — Advanced / Experimental

**Layers:**
- **L4b PLI Semantic** — LLM-based semantic consistency analysis. R&D status — not currently active in scoring path.
- **L5c Runtime Agent** — eBPF tracepoint monitoring. Requires kernel ≥5.8 and root access.

**Rationale:** These layers require significant infrastructure (LLM API access, kernel support) and are not suitable for default deployment.

---

## Proposed CLI Flags

### Presets
```
--core          L1–L3 only (Surface + Forensic + Consequence)
--standard      Core + Tier 1 (+ Structural, Semantic, Actions Poisoning)
--full          All layers
```

### Individual Feature Flags
```
--enable-structural     L4 Structural Drift
--enable-semantic       L5b Semantic Transparency
--enable-actions        L2c Actions Poisoning
--enable-temporal       L5a Temporal Drift
--enable-sca            L2b SCA (requires allowlist.yml)
--enable-pli            L4b PLI Semantic (requires LLM API)
--enable-runtime        L5c Runtime Agent (requires kernel ≥5.8)
```

Individual flags can be combined with presets: `--core --enable-temporal` runs L1–L3 + L5a.

---

## Proposed README Restructure

### Quick Start
Core deployment (L1–L3). One command, one dependency (GitPython). Covers the most common and most dangerous attack vectors.

### Enhanced Features
Organised by tier, not by layer number. Each tier explains what additional threats it addresses and what dependencies it requires.

### Feature Reference
Per-feature documentation with:
- What it detects
- How it works (at Tier 1 disclosure level)
- Configuration options
- Verification status

---

## Migration Path

### Phase 1 — Documentation (This Document)
Define the tier structure, CLI interface, and README organisation. No code changes.

### Phase 2 — CLI Implementation
Add `--core`, `--standard`, `--full`, and `--enable-*` flags to `analyze.py`. Default behaviour (no flags) matches current behaviour (all available layers run) for backward compatibility.

### Phase 3 — Configuration
Add tier presets to `payloadguard.yml`:
```yaml
mode: standard  # or: core, full, custom
layers:
  structural: true
  semantic: true
  actions: true
  temporal: false
  sca: false
  pli: false
  runtime: false
```

---

## Risks and Mitigations

| Risk | Mitigation |
|------|-----------|
| Users run `--core` and miss critical features | Emit warning on borderline verdicts: "Consider running with `--standard` for structural and semantic analysis" |
| CLI complexity from too many flags | Presets cover 90% of use cases; individual flags are opt-in for advanced users |
| Backward compatibility broken | Default behaviour (no flags) is identical to current behaviour — all available layers run |
| Configuration drift between CLI and config file | Config file is the source of truth; CLI flags override config for single runs |
| Users confused by tier numbering vs. layer numbering | Documentation uses tier names (Core, Enhanced 1/2/3) in user-facing content; layer numbers (L1–L5c) only in technical reference |

---

## Non-Goals

This document does not propose:
- Removing any layer
- Changing any layer's detection logic
- Modifying the scoring model
- Altering verification contracts
- Any code changes whatsoever

This is a planning document. Implementation will be tracked separately.
