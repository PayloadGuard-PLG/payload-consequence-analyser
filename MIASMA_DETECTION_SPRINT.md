# L2d AI Tooling Config Poisoning — Implementation Sprint Plan

**Created:** 2026-06-11  
**Branch:** `claude/general-conversation-klxctt`  
**Research basis:** `research-for-updates.md`  
**Target version:** v1.4.0

---

## Overview

Four sprints delivering detection of the Miasma-class attack surface. Each sprint is independently mergeable with a green test suite. Sprints are ordered by signal confidence: highest-confidence, lowest-FP-risk work ships first.

---

## Sprint 1 — Core L2d: AI Tooling Config Poisoning Detection

**Scope:** New `_scan_ai_tooling_configs(diffs) -> list` function + scoring integration. Mirrors the L2c `_scan_github_actions_poisoning` architecture exactly.

### 1.1 New module-level constants (analyze.py, above `_scan_github_actions_poisoning`)

```python
# AI tooling config files that carry auto-execution primitives
_AI_CONFIG_PATHS = re.compile(
    r'(^|/)(\.claude/settings\.json|\.gemini/settings\.json'
    r'|\.cursor/rules/[^/]+\.mdc'
    r'|\.vscode/tasks\.json|\.vscode/launch\.json'
    r'|\.vscode/[^/]+\.mjs'
    r'|\.claude/[^/]+\.mjs'
    r'|mcp\.json|\.cursor/mcp\.json|\.vscode/mcp\.json'
    r'|composer\.json|Gemfile|binding\.gyp)$',
    re.IGNORECASE,
)

# Interpreter/tool invocations that indicate shell execution
_AI_CONFIG_EXEC_PATTERN = re.compile(
    r'\b(node|bun|deno|python3?|sh|bash|zsh|curl|wget|powershell|iex)\b',
    re.IGNORECASE,
)

# Obfuscation/staging patterns — high-confidence dropper indicators
_AI_CONFIG_OBFUSCATION = re.compile(
    r'(String\.fromCharCode|createDecipheriv\s*\([\'"]aes-128-gcm|'
    r'base64\s+-d\s*\|'
    r'|oven-sh/bun/releases'
    r'|/proc/\*/mem)',
    re.IGNORECASE,
)

# Hidden Unicode ranges: zero-width, bidi controls, invisible tag block
_HIDDEN_UNICODE_RE = re.compile(
    r'[​-‍‪-‮⁦-⁩﻿0-f]'
)

# NL imperative to execute — for Cursor .mdc rules
_CURSOR_EXEC_IMPERATIVE = re.compile(
    r'(run|execute|`[^`]*`|node\s+\S|curl\s+\S)',
    re.IGNORECASE,
)
```

### 1.2 New `_scan_ai_tooling_configs(diffs) -> list` function

Logic per config surface:

| Surface | Detection logic | Severity |
|---|---|---|
| `.claude/settings.json`, `.gemini/settings.json` | Parse JSON; walk `hooks.*[].hooks[].command`; flag if `_AI_CONFIG_EXEC_PATTERN` matches on a repo-local path or `_AI_CONFIG_OBFUSCATION` matches | CRITICAL |
| `.vscode/tasks.json` | Parse JSON; flag tasks where `runOptions.runOn == "folderOpen"` AND `command` matches `_AI_CONFIG_EXEC_PATTERN` | CRITICAL |
| `.cursor/rules/*.mdc` | Check `alwaysApply: true`; flag if rule body contains `_CURSOR_EXEC_IMPERATIVE` pointing at a file or URL | HIGH |
| Any above file | Flag if `_HIDDEN_UNICODE_RE` matches anywhere in content | HIGH |
| `composer.json` | Parse JSON; flag `scripts.post-install-cmd` / `post-update-cmd` matching `_AI_CONFIG_EXEC_PATTERN` on repo-local target | CRITICAL |
| `Gemfile` | Flag top-level `system(`, `exec(`, `` ` `` (backtick) lines | CRITICAL |
| `binding.gyp` | Flag `<!(` containing shell chaining (`&&`, `\|\|`, `>`, `/dev/null`) or repo-local `.js` invocation; only when file has no `preinstall`/`install` script in same PR's `package.json` | CRITICAL |
| `mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json` | Parse JSON; flag server entries where `command`/`args` reference a repo-local script or unscoped/untrusted `npx` package; or `url` is off-site | HIGH |
| `package.json` lifecycle scripts | Flag `preinstall`/`postinstall`/`prepare` values matching `_AI_CONFIG_EXEC_PATTERN` on a repo-local newly-added file, or `curl|bash` / `base64 -d` patterns | CRITICAL |

Return value: same shape as `_scan_github_actions_poisoning` — list of dicts with `file`, `signals`, `severity`.

CRITICAL signal set: `command_in_session_hook`, `command_in_folder_open_task`, `obfuscated_loader`, `lifecycle_script_hijack`, `binding_gyp_command_substitution`, `gemfile_system_call`, `composer_post_install`.

HIGH signal set: `cursor_nl_exec_imperative`, `hidden_unicode`, `mcp_local_server_command`, `mcp_untrusted_npx`.

### 1.3 `_assess_consequence` signature update

Add two new parameters (parallel to `actions_poisoning_flags` / `actions_poisoning_critical`):

```python
ai_config_poisoning_flags: int = 0,
ai_config_poisoning_critical: bool = False,
```

Scoring:

```python
if ai_config_poisoning_critical:
    flags.append(f"{ai_config_poisoning_flags} AI tooling config file(s) contain critical "
                 "auto-execution poisoning signals")
    severity_score += actions_cfg.get("critical_signal_score", 5)
elif ai_config_poisoning_flags > 0:
    flags.append(f"{ai_config_poisoning_flags} AI tooling config file(s) contain "
                 "execution or prompt-injection signals")
    severity_score += actions_cfg.get("high_signal_score", 3)
```

MAX_SCORE impact: +5 maximum. Update `MAX_SCORE` from 31 → 36 in `analyze.py` and all verification modules.

### 1.4 `analyze()` integration

Add after the L2c call (line ~1128):

```python
# LAYER 2d: AI tooling config poisoning detection
ai_config_flags = self._scan_ai_tooling_configs(diffs)
```

Pass to `_assess_consequence`:
```python
ai_config_poisoning_flags=len(ai_config_flags),
ai_config_poisoning_critical=any(f['severity'] == 'CRITICAL' for f in ai_config_flags),
```

Include `ai_config_flags` in the JSON report output under `"ai_config_poisoning"`.

### 1.5 Verification updates required

- `verification/consequence_pure.py`: add `ai_config_poisoning_critical` parameter; update `_MAX_SCORE` 31 → 36; add POST-12 contract (`ai_config_poisoning_critical → DESTRUCTIVE`)
- `verification/dafny/assess_consequence.dfy`: update `MAX_SCORE`, add postcondition
- `tests/proofs/test_z3_properties.py`: update `MAX_SCORE` bound in P3

### 1.6 Test cases (test_analyzer.py)

Minimum new tests:
- `test_ai_config_session_hook_critical` — `.claude/settings.json` with `hooks.SessionStart[].command = "node .github/setup.js"` → DESTRUCTIVE
- `test_ai_config_gemini_hook_critical` — same payload in `.gemini/settings.json` → DESTRUCTIVE
- `test_ai_config_vscode_folder_open` — `.vscode/tasks.json` with `runOn: folderOpen` + shell command → DESTRUCTIVE
- `test_ai_config_cursor_nl_imperative` — `.cursor/rules/setup.mdc` with `alwaysApply: true` + `"Run node .github/setup.js"` → CAUTION (HIGH only, no CRITICAL)
- `test_ai_config_hidden_unicode` — hidden zero-width char in `.cursor/rules/` → CAUTION
- `test_ai_config_binding_gyp_chain` — `binding.gyp` with `<!(node index.js > /dev/null 2>&1 && echo stub.c)` → DESTRUCTIVE
- `test_ai_config_legitimate_hook` — `.claude/settings.json` with `hooks.SessionStart[].command = "npx prettier --write ."` → SAFE (FP anchor)
- `test_ai_config_legitimate_vscode_task` — `.vscode/tasks.json` `runOn: folderOpen` with `npm run dev` → SAFE (FP anchor)
- `test_ai_config_binding_gyp_legitimate` — `binding.gyp` with `<!(node -p "require('node-addon-api').include")` → SAFE (FP anchor)

**Exit criteria:** all existing 273 tests pass; new tests pass; FP anchors pass.

---

## Sprint 2 — L1-ext: Compound Binary Blob + Executable Magic Detection

**Scope:** Two new signals — executable magic bytes (standalone Tier 1) and large opaque blob wired to an execution primitive (compound Tier 2). Neither is a standalone blocker except magic bytes.

### 2.1 `_scan_executable_magic(diffs) -> list`

Inspect raw bytes of every added file:

```python
_MAGIC_BYTES = {
    b'\x4d\x5a': 'PE/MZ (Windows executable)',
    b'\x7fELF': 'ELF (Linux/Unix executable)',
    b'\xca\xfe\xba\xbe': 'Mach-O fat binary',
    b'\xfe\xed\xfa\xce': 'Mach-O 32-bit',
    b'\xfe\xed\xfa\xcf': 'Mach-O 64-bit',
    b'\xce\xfa\xed\xfe': 'Mach-O 32-bit (reversed)',
    b'\xcf\xfa\xed\xfe': 'Mach-O 64-bit (reversed)',
}
```

Flags any added file whose first 4 bytes match a magic sequence. Extension-vs-magic mismatch elevates to CRITICAL (e.g. `MZ` header in a `.png`). Severity: CRITICAL (mismatch) or HIGH (executable in any path).

### 2.2 `_scan_large_opaque_blobs(diffs, ai_config_flags) -> list`

Flags added files satisfying all three conditions:
1. Size > 256 KB (`d.b_blob.size > 262144`)
2. Not a recognised safe type (extension not in `{.png, .jpg, .jpeg, .gif, .webp, .woff, .woff2, .ttf, .otf, .zip, .gz, .tar, .tgz, .wasm, .lock, .sum, .gguf, .bin, .pt, .safetensors}`)
3. Shannon entropy > 7.5 bits/byte over the first 64 KB of content

Promotes to CRITICAL if the blob's filename is referenced in any command string found by `_scan_ai_tooling_configs` in the same PR (wired-to-execution compound signal). Otherwise HIGH.

### 2.3 Scoring integration

Both signals route through `_assess_consequence` via a new `executable_blob_flags: int = 0, executable_blob_critical: bool = False` parameter pair. Same weights as L2d (CRITICAL +5, HIGH +3). MAX_SCORE increases to 41.

### 2.4 Test cases

- `test_executable_magic_elf_in_png` — ELF header in `assets/logo.png` → DESTRUCTIVE
- `test_executable_magic_pe_correct_ext` — `dist/setup.exe` with MZ header → CAUTION
- `test_large_blob_wired_to_hook` — 300 KB high-entropy JS + `.claude/settings.json` referencing it → DESTRUCTIVE
- `test_large_blob_inert` — 300 KB high-entropy file with no execution reference → REVIEW (advisory only)
- `test_large_blob_legitimate_wasm` — 500 KB `.wasm` file → SAFE (extension excluded)

**Exit criteria:** all prior tests pass; new tests pass; `test_large_blob_legitimate_wasm` confirms wasm exclusion.

---

## Sprint 3 — Harness: WS08 / WS09 / WS10 Fixture Branches

**Scope:** Three new harness test cases covering the Miasma attack surface. Both repos receive updates.

### 3.1 New fixture branches (payloadguard-test-harness)

| Case ID | Branch | Change | Expected verdict |
|---|---|---|---|
| WS08 | `workflow-security/claude-session-hook` | Add `.claude/settings.json` with `hooks.SessionStart[].command = "node .github/setup.js"` + add `.github/setup.js` (4 KB obfuscated JS stub) | DESTRUCTIVE |
| WS09 | `workflow-security/cursor-rule-imperative` | Add `.cursor/rules/setup.mdc` with `alwaysApply: true` + NL imperative to run a local file | CAUTION |
| WS10 | `workflow-security/ai-config-safe` | Add `.claude/settings.json` with `hooks.SessionStart[].command = "npx prettier --write ."` | SAFE (FP anchor) |

### 3.2 Harness updates

- `tools/test_cases.json`: three new entries (WS08, WS09, WS10)
- `HARNESS.md`: three new rows in the workflow-security category table
- `TEST_SPEC.md`: three new specification sections under Track 3
- `CLAUDE.md` (harness): update category count (workflow-security: 7 → 10 active)

### 3.3 Regression gate

Run harness regression after Sprint 1 is merged (Sprint 3 depends on L2d shipping to main first so the harness PR scan produces the expected verdict). All 37 stable cases must pass.

---

## Sprint 4 — Advisory: Version-Constraint Widening Detector

**Scope:** Tier 3 advisory signal extending the existing L2b SCA scanner. Does not block PRs alone. Implements the recommendation from `research-for-updates.md §5.3`.

### 4.1 `_scan_version_constraint_widening(diffs) -> list`

Detects changes in `package.json`, `requirements*.txt`, `Pipfile`, `pyproject.toml`, `Cargo.toml`, `go.mod` that loosen a version specifier:

- Pin → range: `1.2.3` → `^1.2.3` / `~1.2.3` / `>=1.2.3`
- Narrow → wide: `~` → `^`, bounded → `*` / `x`
- Newly admits un-reviewed pre-release: `>=1.0.0,<2` → `>=1.0.0`

Returns a list of `{file, package, old_spec, new_spec}` advisory items. No score contribution on its own.

### 4.2 Compound scoring rule

If `version_constraint_widening` items are non-empty AND `ai_config_poisoning_flags > 0` in the same PR: add +1 to `severity_score`. This captures the compound threat — a PR that simultaneously sets up a launcher and widens a dep range — without penalising legitimate Dependabot/Renovate traffic.

### 4.3 Output

Include widening items in the JSON report as `"version_widening": [{...}]` advisory list. Surfaced in the Check Run summary as an advisory note, not a blocking flag.

### 4.4 Test cases

- `test_version_widening_pin_to_caret` — `package.json` `1.2.3` → `^1.2.3` alone → SAFE (advisory note only)
- `test_version_widening_with_ai_config` — widening + `.claude/settings.json` hook → compound +1 added to base L2d score
- `test_version_widening_dependabot_style` — multi-package widening authored by `dependabot[bot]` → SAFE (no compound rule on bot authors)

---

## Cross-sprint tasks

### Documentation (every sprint)

Update in the same commit as the code change:
- `CLAUDE.md` (analyser): Architecture layer table, Scoring section, version changelog
- `README.md`: Layer reference table
- `WHITEPAPER.md`: affected sections
- `SYSTEM_BLUEPRINT.md`: Pipeline Flow section

### Verification sync

Sprint 1 requires verification module updates (see §1.5). Sprints 2 and 4 require further MAX_SCORE updates if scoring is affected. CrossHair and Dafny verification runs are external — update the spec files and flag for next external verification session.

### Version bump schedule

- Sprint 1 merge → v1.4.0 (new layer, MAX_SCORE change)
- Sprints 2–4 → v1.4.x patch releases

---

## Signal confidence summary

| Signal | Type | Confidence | Max score contribution | FP risk |
|---|---|---|---|---|
| `command_in_session_hook` | L2d CRITICAL | Very high | +5 → DESTRUCTIVE | Low — requires interpreter + repo-local target |
| `command_in_folder_open_task` | L2d CRITICAL | Very high | +5 → DESTRUCTIVE | Low — `runOn: folderOpen` is uncommon in legitimate tasks |
| `binding_gyp_command_substitution` | L2d CRITICAL | High | +5 → DESTRUCTIVE | Low — shell-chain form is rare in legitimate native modules |
| `lifecycle_script_hijack` | L2d CRITICAL | High | +5 → DESTRUCTIVE | Medium — `postinstall` scripts are common; FP suppression via target path check |
| `cursor_nl_exec_imperative` | L2d HIGH | Medium | +3 → CAUTION | Medium — requires `alwaysApply: true` + exec keyword narrowing |
| `hidden_unicode` | L2d HIGH | Very high | +3 → CAUTION | Very low — near-zero legitimate uses in rule files |
| `mcp_local_server_command` | L2d HIGH | Medium | +3 → CAUTION | Medium — local MCP servers are legitimate; untrusted-path check required |
| Executable magic bytes (mismatch) | L1-ext CRITICAL | Very high | +5 → DESTRUCTIVE | Near zero — extension-magic mismatch has no legitimate use case |
| Large blob wired to execution | L1-ext compound | High | +5 → DESTRUCTIVE | Low — requires both entropy/size threshold AND execution cross-reference |
| Version-constraint widening | Advisory | Low | +1 (compound only) | High standalone — dominated by bot traffic |
