# PLI Integration Specification — PayloadGuard v1.3.0

**Layer:** L4b — Semantic Consistency  
**Shipped:** v1.3.0 (`analyze.py`, commit `6a37d8f`)  
**Engine source:** `pli_analyzer.py` (AIntegrity PLIEngineV4 — `PLIAnalyzer` class)

---

## 1. What the PLI Engine Is

`PLIAnalyzer` is a three-layer logical consistency engine from the AIntegrity project.
It takes a `(user_text, model_text)` pair and determines whether the two texts are
semantically consistent with each other.

**Three analysis layers inside `PLIAnalyzer`:**

| Layer | Method | What it does |
|---|---|---|
| L1 | Regex | Pattern matching — contradiction, evasion, hedging, circular reasoning, deflection, false authority, self-contradiction |
| L2 | LLM dual-pass | OBSERVE pass (factual accuracy, logical consistency, relevance) + VERIFY pass (adversarial challenge). Requires `llm_adapter`. |
| L3 | Dynamic prompt | Adjusts interrogation depth and focus areas based on L1 findings (`LogicProfile`) |

**Return value of `analyze_turn(user_text, model_text)`:**

```python
{
    "consistency_score": float,      # 0.0–1.0. Lower = more suspicious.
                                     # L1-only: 1.0 - (contradictions×0.15) - (evasions×0.08)
                                     # Full: weighted blend of L1 score and LLM pass scores
    "contradiction_detected": bool,
    "evasion_detected": bool,
    "total_contradictions": int,
    "total_evasions": int,
    "total_fallacies": int,
    "l1_enhanced": dict,             # hedging, circular_reasoning, false_authority, deflection, etc.
    "findings": {
        "contradiction": dict | None,
        "evasion": dict | None,
    },
    # Present only when llm_adapter is provided:
    "l2_findings": {
        "pass_1_score": int,         # OBSERVE pass score (0–100)
        "pass_2_score": int,         # VERIFY pass score (0–100)
        "variance": int,             # |pass_1 - pass_2|
        "fallacies": [               # merged from both passes, deduplicated
            {
                "type": str,
                "severity": str,     # "critical" | "high" | "moderate" | "low"
                "evidence": str,     # exact quote from model_text
                "explanation": str,
                "turn": int,
                "source": str,       # "observe" | "verify"
            }
        ],
    },
    "behavioral_metrics": {...},     # CFR, RR, AD rates (full mode only)
}
```

**Important:** `PLIAnalyzer` is stateful — it accumulates history across calls to
`analyze_turn()`. PayloadGuard creates a **fresh instance per analysis pair** to keep
each pair's score independent.

---

## 2. How PayloadGuard Uses It (Layer L4b)

### 2.1 Activation

PLI is **opt-in and disabled by default**. It activates when:

```yaml
# In the PayloadGuard GitHub Action step:
- uses: PayloadGuard-PLG/payload-consequence-analyser@main
  with:
    pli-analysis: 'true'
```

Or via CLI:
```bash
python analyze.py --repo . --pli-analysis
```

The `pli-analysis` flag sets `config.pli["enabled"] = True` at runtime.

### 2.2 Mode Selection

On each analysis run, PayloadGuard reads the `PLI_API_KEY` environment variable:

```
PLI_API_KEY set → full mode (L1 + L2 LLM dual-pass + L3 dynamic)
PLI_API_KEY absent → l1_only mode (L1 regex only)
pli_analyzer.py absent → unavailable (score unchanged)
```

**L1-only mode note:** The L1 patterns in `PLIAnalyzer` were designed for AI conversation
auditing (detecting AI evasion and contradiction). For code diff inputs (PR descriptions,
commit messages, function code), L1 patterns will rarely fire and `consistency_score` will
remain 1.0. L1-only mode adds negligible signal for PLG's use case. **Full mode with
`PLI_API_KEY` is required for effective semantic analysis.**

### 2.3 LLM Adapter Shim

`pli_analyzer.py` requires an `llm_adapter` object with a `.query()` method. PayloadGuard
provides `_build_pli_llm_adapter(api_key)` — a minimal inline shim:

```python
# analyze.py lines 392–418
def _build_pli_llm_adapter(api_key: str):
    """Minimal shim satisfying PLIAnalyzer's llm_adapter.query() interface."""
    # Uses: anthropic SDK, model claude-haiku-4-5-20251001
    # Returns: None if anthropic package is not installed
```

**Model:** `claude-haiku-4-5-20251001` — lowest cost, fastest latency.  
**Dependency:** `anthropic` package. Not in default `requirements.txt`; add manually if
using full mode (see `requirements.txt` comment block).

### 2.4 Analysis Pairs

For each PR, PayloadGuard runs up to `1 + max_commit_pairs + N` analysis pairs:

| Pair | `user_text` | `model_text` | What it catches |
|---|---|---|---|
| **Pair 1** | PR title + body (`pr_description`) | Diff summary (file counts, deleted paths, structural component names) | Deceptive PR description — "fix typo" when diff rewrites auth middleware |
| **Pair 2** | Commit message subject (first 500 chars, up to 3 commits) | Raw unified diff (first 2000 chars) | Misleading commit message — commit claims to add tests but removes security checks |
| **Pair 3** | Full file content before change (up to 3000 chars) | Full file content after change (up to 3000 chars) | Semantic attack in modified function — one-line change that inverts auth logic |

Pair 3 only runs for files where L4 Structural analysis already detected deleted components
(`structurally_flagged_paths`). This avoids analyzing every modified file.

### 2.5 Configuration (`config.pli`)

```python
DEFAULT_CONFIG["pli"] = {
    "enabled": False,             # must be set True via --pli-analysis flag
    "api_key_env": "PLI_API_KEY", # env var name for the Anthropic API key
    "max_file_chars": 3000,       # truncation limit per blob in Pair 3
    "max_commit_pairs": 3,        # max commit messages to analyze in Pair 2
}
```

### 2.6 Findings Normalisation

`_extract_pli_findings(result)` normalises both L1 and L2 findings into a unified list:

```python
# L2 fallacies: severity already lowercase ("critical", "high", etc.)
# L1 contradiction/evasion: severity is capitalized ("High", "Moderate") — normalised to lowercase
# Output: [{"severity": str (lowercase), "type": str, "evidence": str, ...}]
```

---

## 3. Scoring Impact

### 3.1 Signal Classification

```
critical_count = count of findings where severity == "critical"
high_count     = count of findings where severity == "high"

pli_critical = critical_count > 0   → bool passed to _assess_consequence()
pli_high     = high_count > 0       → bool passed to _assess_consequence()
```

The minimum `consistency_score` across all pairs is tracked but does not directly affect
the verdict — only the finding severity counts feed into scoring.

### 3.2 Score Contribution

```python
# analyze.py _assess_consequence() — after actions_poisoning block
if pli_critical:
    severity_score += 5   # forces DESTRUCTIVE alone (threshold is 5)
elif pli_high:
    severity_score += 3   # forces CAUTION alone (threshold is 3)
```

**PLI critical is equivalent to:** security file deletion, structural CRITICAL, or
actions_poisoning CRITICAL — all contribute +5 and each forces DESTRUCTIVE in isolation.

### 3.3 MAX_SCORE

Updated from 31 → **36** in v1.3.0 to account for the maximum PLI contribution (+5).

---

## 4. Report Output

The analysis report includes a top-level `"pli"` key:

```json
{
    "pli": {
        "mode": "full",
        "pairs_analyzed": 3,
        "consistency_score": 0.72,
        "critical_count": 0,
        "high_count": 1,
        "findings": [
            {
                "type": "Logical Contradiction",
                "severity": "high",
                "evidence": "...",
                "explanation": "PR description claims minor refactor; diff removes entire authentication module"
            }
        ]
    }
}
```

When PLI is disabled or unavailable, `"pli"` is:
```json
{
    "pli": {
        "mode": "unavailable",
        "pairs_analyzed": 0,
        "consistency_score": 1.0,
        "critical_count": 0,
        "high_count": 0,
        "findings": []
    }
}
```

---

## 5. Formal Verification

The two PLI parameters propagate into both verification targets:

### 5.1 CrossHair (`verification/consequence_pure.py`)

```python
_MAX_SCORE: int = 36  # updated from 31

# Contract C13 — added in v1.3.0
post: implies(pli_critical, __return__["status"] == "DESTRUCTIVE")
```

### 5.2 Dafny (`verification/dafny/assess_consequence.dfy`)

```dafny
const MAX_SCORE: int := 36  // updated from 31

// POST-12: PLI critical finding forces DESTRUCTIVE (+5)
ensures pli_critical ==> status == "DESTRUCTIVE"
```

Both targets were updated in the same commit as the `analyze.py` changes to maintain
the invariant that the verified reference implementation stays in sync with production code.

---

## 6. Test Coverage (`test_analyzer.py`)

| Test | What it verifies |
|---|---|
| `TestPLIAnalysis::test_assess_consequence_pli_critical_forces_destructive` | `pli_critical=True` → verdict DESTRUCTIVE regardless of other signals |
| `TestPLIAnalysis::test_assess_consequence_pli_high_produces_caution` | `pli_high=True`, no other signals → verdict CAUTION |
| `TestPLIAnalysis::test_assess_consequence_pli_both_false_no_impact` | Both false → no PLI contribution to score |
| `TestPLIAnalysis::test_pli_disabled_by_default` | `config.pli["enabled"]` defaults False; `_run_pli_analysis` not called |
| `TestPLIAnalysis::test_pli_unavailable_returns_zero_signals` | `_PLI_AVAILABLE=False` → empty result, verdict unaffected |
| `TestPLIAnalysis::test_pli_l1_mode_when_no_api_key` | SKIPPED (requires live API key) |

---

## 7. Degradation Behaviour

| Condition | Behaviour |
|---|---|
| `pli_analyzer.py` absent | `_PLI_AVAILABLE = False`; `_run_pli_analysis()` returns empty; score unchanged |
| `PLI_API_KEY` not set | `llm_adapter = None`; PLIAnalyzer runs L1-only; score unlikely to change for code diff inputs |
| `anthropic` package not installed | `_build_pli_llm_adapter()` returns `None`; falls back to L1-only |
| `pli-analysis` flag not set | Layer L4b skipped entirely; zero API calls; zero cost |
| LLM API error | `PLIAnalyzer._llm_query()` returns a neutral JSON (`score: 100`, empty fallacies); analysis continues |

---

## 8. Cost

Full mode (per PR analysis):
- Up to `1 + max_commit_pairs + N_structural_flagged_files` API calls
- Default maximum: 1 + 3 + varies = ~4–6 calls per PR
- Model: `claude-haiku-4-5-20251001` at ~$0.00025 per 1K input tokens, ~$0.00125 per 1K output tokens
- Typical cost per PR: **< $0.005**

---

## 9. File Index

| File | Role |
|---|---|
| `analyze.py:31–34` | Import guard — `_PLI_AVAILABLE` flag |
| `analyze.py:392–418` | `_build_pli_llm_adapter()` — Anthropic SDK shim |
| `analyze.py:421–432` | `_extract_pli_findings()` — severity normalisation |
| `analyze.py:869–874` | `DEFAULT_CONFIG["pli"]` — default configuration |
| `analyze.py:1191–1213` | L4b call site inside `analyze()` — runs after L4 Structural |
| `analyze.py:1231–1232` | `_assess_consequence()` invocation — passes `pli_critical`, `pli_high` |
| `analyze.py:1370–1371` | `_assess_consequence()` signature — new parameters |
| `analyze.py:1492–1497` | `_assess_consequence()` scoring block — +5 / +3 |
| `analyze.py:1536–1552` | `_build_pli_diff_summary()` — Pair 1 model_text builder |
| `analyze.py:1554–1568` | `_build_pli_diff_content()` — Pair 2 model_text builder |
| `analyze.py:1570–1644` | `_run_pli_analysis()` — main L4b method |
| `analyze.py:2342–2344` | `--pli-analysis` CLI argument |
| `action.yml` | `pli-analysis` input (default `false`) |
| `pli_analyzer.py` | `PLIAnalyzer` source — three-layer engine |
| `verification/consequence_pure.py` | CrossHair contracts — C13, updated `_MAX_SCORE=36` |
| `verification/dafny/assess_consequence.dfy` | Dafny spec — POST-12, `MAX_SCORE=36` |
| `test_analyzer.py` | `TestPLIAnalysis` — 5 pass, 1 skip |
| `requirements.txt` | Optional `anthropic>=0.40.0` (commented) |
