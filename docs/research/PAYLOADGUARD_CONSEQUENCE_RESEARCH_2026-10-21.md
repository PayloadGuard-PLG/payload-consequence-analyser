# PayloadGuard: Multi-Language Consequence Analysis
## Research findings, reference architecture and Codex implementation plan
Research date: 2026-10-21 | Status: research / design baseline, not implementation authorization
Repository: https://github.com/PayloadGuard-PLG/payload-consequence-analyser
Harness: https://github.com/PayloadGuard-PLG/payloadguard-test-harness

## 1. Executive decision

PayloadGuard should become a differential, evidence-backed consequence analyzer, rather than expand into hundreds of lexical alerts. Its differentiator is explaining what a proposed pull request removes, exposes, breaks or makes reachable, with a specific path to remediation. A consequence requires stronger evidence than the presence of a suspicious token.

Recommended investment order:
1. Preserve and measure the current baseline; make parser and analysis incompleteness explicit.
2. Introduce versioned finding/evidence contracts and one machine-readable harness oracle.
3. Replace L4 bare name sets with qualified, source-located semantic symbols and move/rename-aware delta matching.
4. Detect cross-file compound losses and threshold gaming without flooding legitimate refactors.
5. Add public API and build/dependency contract analysis, then bounded reverse dependency/call reachability.
6. Research deeper differential dataflow, authorization invariants and optional runtime corroboration only after the foundations are measurable.

Product contract: no default network upload of source code; no execution of untrusted repository code in fast analysis; no low-confidence blocking; explicit incomplete-analysis state; safe-by-default permissions; policy-owned blocking; low-noise evidence-first PR output.

## 2. Evidence examined and epistemic limits

Verified from the GitHub connector on 2026-10-21:
- Core README.md currently labels Version 1.4.0-dev and Status Production; both labels appear together, requiring release-status clarification.
- structural_parser.py uses Python ast for .py and Tree-sitter grammars for .js/.jsx/.ts/.tsx/.go/.rs/.java. The extracted representation is a set of simple names. It omits qualified identity, kind, signature, calls, references, visibility, types, body changes and structural relations.
- In structural_parser.py, an unavailable Tree-sitter grammar returns an empty set via _extract_via_treesitter; unsupported extension also returns empty. This is not evidence of absence of destructive changes.
- Harness HARNESS.md reports 41 registered cases, 38 active PR branches, SQLite result ingestion and stable versus aging temporal groups.
- tools/test_cases.json records A03 distributed deletion and A06 threshold gaming as expected SAFE. HARNESS.md describes these as known bypasses. T05 and A02 currently expect DESTRUCTIVE.
- T11 exercises JavaScript, TypeScript and Go, even though syntactic parsers also cover Rust and Java.
- README describes Core, Standard, Full; L1, L2, L2b/c/d, L3, L4, L5a/b/c; and SAFE/REVIEW/CAUTION/DESTRUCTIVE outcomes.

These are SOURCE/TEST-SPEC OBSERVATIONS, not independently replayed runtime results. We did not run regression, audit test outcome data, confirm exact real-world precision, or validate every detector. All new performance and precision figures below are PROPOSED GATES, not measured current performance.

Primary repository evidence:
- https://github.com/PayloadGuard-PLG/payload-consequence-analyser/blob/main/structural_parser.py
- https://github.com/PayloadGuard-PLG/payload-consequence-analyser/blob/main/README.md
- https://github.com/PayloadGuard-PLG/payloadguard-test-harness/blob/main/HARNESS.md
- https://github.com/PayloadGuard-PLG/payloadguard-test-harness/blob/main/tools/test_cases.json
- https://github.com/PayloadGuard-PLG/payloadguard-test-harness/blob/main/TEST_SPEC.md
- https://github.com/PayloadGuard-PLG/payload-consequence-analyser/blob/main/PROOFS.md

Existing formal verification/proof counts in README should not be conflated with proof of semantic consequence detection or real-world detector accuracy.

## 3. What can actually be known

A Git diff alone establishes changed bytes and Git objects, not executed behaviour. An AST establishes parsed syntax but not resolved binding. Compiler semantics can establish missing symbols, inconsistent types, visibility breaks and broken references under a specified compilation context. A build graph establishes known dependency relationships. Static call graphs and dataflow can establish feasible or approximate reachability under their model assumptions. Differential sandboxed execution establishes only the effects actually observed for that workload.

Never claim a universal proof of arbitrary before/after program equivalence or all runtime consequences. Where models are incomplete (reflection, dynamic imports, code generation, macros, native extensions, build flags), report coverage and uncertainty rather than silently outputting SAFE.

Adopt a capability vector per file/module:
- universal: Git, file metadata, manifest/workflow schemas;
- syntax: parser available and parse completed;
- symbolic: declaration and reference binding resolved;
- typed: compiler or type checker evidence;
- reachability: bounded caller/dependency graph;
- flow: modelled CFG/taint analysis;
- runtime: observed sandbox execution.
Every capability reports available, unavailable, partial or failed, together with provenance and reason.

## 4. Architecture: the Semantic Change Graph (SCG)

Data flow:
PR base/head immutable commits -> Git and manifest envelope -> language-specific adapters -> normalized before/after facts -> graph delta -> consequence detectors -> evidence grouping and severity/confidence -> policy decision -> PR check/SARIF/JSON.

Do not build a lowest-common-denominator universal AST. Keep language-native facts in adapters, and normalize the narrow ontology needed for cross-language reporting.

Versioned entity types:
File, Symbol, Type, Package, BuildTarget, TestTarget, Endpoint, DataSource, DataSink, Sanitizer, WorkflowJob, Permission, RuntimeEffect.

Versioned edge types:
CONTAINS, DECLARES, CALLS, REFERENCES, IMPORTS, IMPLEMENTS, OVERRIDES, READS, WRITES, FLOWS_TO, GUARDED_BY, DEPENDS_ON, BUILDS, TESTED_BY, EXPOSES, SPAWNS, CONNECTS_TO.

Versioned change events:
ADDED, REMOVED, MOVED, RENAMED, SIGNATURE_CHANGED, VISIBILITY_CHANGED, BODY_CHANGED, GUARD_REMOVED, DEPENDENCY_ADDED, DEPENDENCY_REBOUND, FLOW_INTRODUCED, FLOW_REMOVED, UNKNOWN.

Suggested entity fields:
id, language, package, module, qualified_name, symbol_kind, visibility, normalized_signature, source_path, start/end range, stable_ast_fingerprint, body_hash, frontend, frontend_version, compilation_context, evidence_refs, completeness.

Suggested consequence finding fields:
schema_version, detector_id, consequence_type, subject, before_ref, after_ref, changed_edge_ids, affected_entities, source_evidence, confidence_class, severity, analysis_capabilities, incomplete_reasons, is_introduced, remediation_options, grouping_fingerprint, policy_recommendation.

Example: PUBLIC_API_REMOVED for auth.Authenticator.verify(Token) with 7 bound callers and 3 affected build targets. Evidence requires base symbol, absent unmatched head symbol, verified public visibility, and unresolved references in head. This is materially different from a name absent from a text set.

Matching pipeline:
(1) exact compiler symbol identity when stable, (2) exact qualified signature, (3) same normalized signature in moved file/parent, (4) compatible kind and strongly corroborated body/AST similarity, (5) otherwise unmatched. Preserve a distinct RENAME_WITH_BODY_WEAKENING event: a superficially similar replacement must not hide real destruction.

All graph records must be tied to content SHA and analyzer/front-end versions. Never cache under mutable branch names alone.

## 5. Language strategy

Current syntactic coverage: Python, JavaScript/JSX, TypeScript/TSX, Go, Rust, Java. This is not yet compiler-semantic support.

Wave 1, instrumentation + syntax normalization: existing six language families and missing-grammar/parse-failure paths.
Wave 2, native type/API sources: TypeScript compiler API and tsc; Go go/types and go/packages; Java javac Tree API or compatible index; Rust rustdoc JSON / cargo metadata / compiler tooling evaluated for stability; Python ast plus optional type checker information; JS via resolver/type-aware project context where feasible.
Wave 3, based on adoption: C/C++ through Clang, C# through Roslyn, then Kotlin, Ruby and Swift.
Avoid linking every language adapter directly into the critical PR lane. Discover toolchains and provide capability fallback.

Examples of ecosystem-specific consequences:
- TypeScript: removed exported method, changed required parameter, widened unsafe any at security boundary.
- Go: removed exported function/interface implementation, changed module imports.
- Java: public method signature change, inheritance or interface break.
- Rust: removed pub item, trait implementation or feature-gated export, Cargo resolver/feature change.
- Python: removed decorator, importable function or route guard, dynamic dispatch uncertainty.
- JS: changed exports, changed bundler/build script, prototype/dynamic property uncertainty.
- All ecosystems: dependencies, lockfiles, CI privileges, secrets plumbing, migration files and test removals.

## 6. Detector specification and precedence

Detector catalog below gives priority, evidence requirement, likely false-positive control and recommended initial policy. Severity reflects potential harm; confidence reflects epistemic strength; the two must never be collapsed.

D01 Parser/completeness failure — P0.
Trigger: expected grammar missing, parse error, compilation context absent, timeout or stage crash. Evidence: path, stage, exception category, capability gap. Policy: ANALYSIS_INCOMPLETE + review based on protected surface; never return implied clean result. Negative control: unsupported file should not be falsely called destructive.

D02 Rename/move-aware structural delta — P0.
Trigger: declarations apparently removed across base/head. Evidence: typed node IDs, ranges, signatures, move/rename matching, body-delta fraction. Detect true removal and renamed gutted contents; cancel pure moves only when evidence agrees. Initially report only; do not block by similarity alone. Cases T05/T12/A02/A05/A07 plus new pure-move/rename controls.

D03 Cross-file compound loss — P0.
Trigger: semantically unmatched removals spread across files/packages; cumulative removal of related auth/test/validation surface. Evidence: affected package, counts, separate corroborators, negative controls. Pure refactors are discounted after matching. Cases A03, A04, A06 plus 3/5/10-file curves. Start in shadow/advisory.

D04 Public API contract break — P0/P1.
Trigger: public export removed, visibility reduced, required parameter/signature change, interface/trait implementation break. Evidence: compiler binding and affected reference sites, compilation diagnostics when available. Policy: advisory initially; optional block only if authoritative type check proves broken dependents and explicit policy opts in.

D05 Build/dependency delta — P0/P1.
Trigger: executable install script added, resolved package changed, lock-manifest mismatch, critical build target disabled, dependency graph fanout shifts. Evidence: parsed manifests + lock metadata, resolver/toolchain versions and affected targets. Do not execute package lifecycle hooks in the fast lane. Policy: review/critical gating only when supported evidence is decisive.

D06 Authorization/validation guard regression — P1.
Trigger: guard, decorator, middleware, sanitizer or error-handling barrier removed without equivalent relocation. Evidence: protected entry point, base/head control or dataflow, guard relation and path. False-positive control: equivalent moved guard and framework-specific models. No speculative block.

D07 Differential source-to-sink flow — P1 research.
Trigger: newly introduced user-controlled input to command, SQL, file or outbound network sink, or removed sanitizer. Evidence: base/head path with source, transformation, barrier and sink. Legacy pre-existing paths are not new findings. Policy: only high-confidence reviewed rules become block candidates.

D08 Workflow / permissions / AI-tooling poisoning — P0 refinement.
Trigger: untrusted event/workflow input to shell, unexpected id-token/write permissions, dangerous checkout on pull_request_target, action pin/identity downgrade, AI tool hooks with execution surface. Evidence: parsed workflow graph and trust boundaries. Keep legitimate OIDC workflows as negative controls (AW04). Preserve existing L2c/L2d detections; improve semantics before score reweighting.

D09 Test contract erosion — P1.
Trigger: meaningful tests removed/disabled, coverage gate softened, assertion replaced with trivial success, CI checks bypassed. Evidence: named test targets and CI configuration before/after; distinguish intentional test replacement. Advisory unless combined with independently proven breaking consequence.

D10 Migration / persistence loss — P1.
Trigger: destructive schema drop, irreversible migration, changed data retention or access policy. Evidence: SQL/ORM schema operations, rollback/forward compatibility plan, protected data classes. A raw string 'DROP' is not sufficient proof. Critical review, not blanket block.

D11 Transparency mismatch — P1.
Trigger: PR description omits materially established destructive or security boundary change. Evidence: established SCG consequences + exact claim spans. Phrase as 'description does not account for X', not a claim of malicious developer intent. NLP/LLM advisory only, never sole merge blocker.

D12 Runtime effect differential — P2 opt-in.
Trigger: base/head identical sandbox workload shows newly observed network/process/filesystem/privilege effects. Evidence: reproducible trace, workload coverage, kernel/agent versions. Non-observation never lowers static risk. Isolate eBPF capability in disposable worker pool.

Policy classes are independent of existing user-facing verdict labels:
- Block-eligible: critical, reproducible, corroborated consequence meeting calibrated empirical precision and explicit repository policy.
- Review: credible significant consequence or protected-surface incomplete analysis.
- Informational: low severity, confirmed intentional change, or uncertain noncritical heuristic.
- Abstain: missing required capability or conflicting evidence; do not manufacture a SAFE statement.

Never introduce a new default blocking detector in the first sprint.

## 7. Harness transformation

Existing harness is a valuable end-to-end integration fixture but verdict-only pass counts conceal both lucky scoring and wrong explanations. Keep existing branches; do not mutate them to add every language permutation.

Three tiers:
1. Unit fixture tests: parser and single-detector semantics, milliseconds, deterministic.
2. Repository pair fixtures: complete base/head tree, expected graph events and forbidden events, seconds.
3. Live PR integration: 38 existing active branches and a small expansion, minutes; verifies GitHub checks, metadata, isolation and policy.

Canonical machine-readable oracle (extend tools/test_cases.json with schema version without deleting current fields):
case ID, immutable base/head fixture refs, language, temporal group, consequence class, expected and forbidden findings, symbol IDs, min expected evidence, allowed verdict set, required analysis capabilities, expected incomplete state, performance budget, source label and oracle reviewer.

Proposed new case groups:
- S01 pure Python/TS/Go/Rust/Java rename, no behavioral loss;
- S02 moved symbol with every caller updated, no loss;
- S03 moved symbol with guard body gutted, real loss;
- S04 extract/inline refactor, safe; plus ambiguous matching that must abstain;
- C01 3-file auth guard removal; C02 5-file distributed loss; C03 10-file control; C04 below-threshold compound effect;
- A01 public export removed with unchanged callers; A02 signature break; A03 private unused helper removed; A04 equivalent API replacement;
- B01 npm manifest/lock mismatch; B02 safe lock churn; B03 Cargo feature or transitive dependency rebound; B04 build script activation;
- F01 removed sanitizer; F02 relocated sanitizer; F03 legacy vulnerable path unchanged; F04 new cross-file source-to-sink;
- W01 untrusted expression to shell; W02 legitimate OIDC; W03 action pin downgrade; W04 permission narrowing;
- X01 missing grammar; X02 malformed head; X03 missing compiler; X04 timeout; X05 unsupported language.
Every positive receives matched nearby negative controls, metamorphic transformations and evidence assertions.

Permanent existing regression obligations: T03/T04 canonical destructive; T05 boundary; T11 multilang; T12 pure rename; A02 rename smuggling; A03 distributed deletion; A06 threshold gaming; WS01-WS07, AW01-AW05 and RTA cases. A03/A06's existing expected SAFE records describe CURRENT KNOWN MISSES; do not silently recode the oracle as success. Introduce explicit legacy_expected_verdict and security_desired_outcome until fix is evidenced.

Spec drift between TEST_SPEC.md and machine manifest should be reconciled by manifest schema validation and generated human-readable tables. Do not manually maintain two incompatible oracles.

Harness telemetry: analyzer SHA/version, harness SHA, report schema, language/front-end capabilities, detector ID, consequence, evidence quality, false-positive disposition, stage time, p50/p95 PR time, peak RSS, cache-hit rate, timeout/fallback counts, branching temporal drift, suppressed/overturned findings.

## 8. Developer utility and PR friction

Fast lane (default): immutable diff + manifest/workflow scan + changed-file parsing + basic qualified structural delta + bounded local reference impact. No project code execution; local/on-runner processing, no source upload. Proposed objective: p50 under 10 seconds; p95 under 30 seconds for ordinary PR cohorts, to be measured on representative hardware.

Deep lane (opt-in/risk-triggered): compiler-aware API, reverse call graph, dependency target graph, bounded taint, later differential runtime. Proposed deep lane p95 under 5 minutes on explicitly selected cohorts. Every timeout surfaces incomplete analysis and unchanged policy semantics.

Output one primary root-cause finding per consequence with evidence, affected symbols/build targets/tests, source locations, confidence, alternatives (restore, migrate caller, approve intentional breaking change), and coverage limitations. No alert storm for 70 references caused by one removed API. Keep PR check summary authoritative for deletion-centric findings: SARIF inline annotations cannot reliably anchor removed lines.

Policy-as-code: path scopes and protected components; detector enablement; shadow/advisory/gating modes; risk/timeout budgets; explicit suppressions with detector/scope/owner/rationale/expiry and audit record; approved-breaking-change mechanism; pinned toolchains and analyzers; per-repo defaults. No secret or API keys in output.

Metrics: per-class precision, recall and false-positive PR rate; critical miss rate; evidence accuracy; blast radius precision/recall; confidence calibration; block overturn rate; extra minutes to merge; dismissal/suppression rate and opt-outs. A large pass total or overall accuracy is not product validation.

Proposed promotion gates, not measured:
Shadow: deterministic structured evidence, explicit incompleteness, negative controls, no crashes.
Advisory: >=95% reviewed precision on meaningful stratified corpus and useful remediation.
Optional blocking: >=99% precision and >=95% critical recall on held-out relevant cases, plus measured low overturn rate.
Default critical blocking: >=99.5% empirical precision, high coverage on clean control PRs, no unresolved known bypass in the gated class, p95 within budget, security review and documented rollback. Report sample sizes and confidence intervals; zero false positives in a tiny sample is not evidence of 99.5% precision.
All incomplete analysis surfaced: 100%. All blocking decisions traceable to machine-readable evidence: 100%.

## 9. Operational hardening

Threat model includes untrusted PRs, YAML expression injection, malicious compilers/build hooks, parser resource exhaustion, symlinks/path traversal, cache poisoning, poisoned dependency manifests, workflow privilege escalation, compromise of action supply chain and optional external LLM exfiltration.

Least-privilege PR analysis: read-only token and repository content by default. Separate write-authorized reporting step from untrusted checkout if needed. Never run untrusted PR code inside a privileged pull_request_target or workflow_run context. Pin third-party Actions by immutable commit SHA when practical. Do not automatically grant secrets or elevated eBPF privileges to standard workers.

Version/report schema discipline: release manifest separates dev from production, records parser versions, immutable Git SHA and breaking schema changes. Test parser availability and fail-closed-to-review for protected surfaces without treating analysis errors as DESTRUCTIVE proof.

CI delivery: tests (unit, property/metamorphic, integration), static code hygiene, SBOM, dependency pins, artifact attestations, reproducible build/version labels, structured logging without source exfiltration, runbook for erroneous block, rollback of detector policy, explicit threat-model review.

## 10. Phased engineering backlog

Milestone 0 (0-2 weeks): freeze baseline; introduce capability/completeness event in report; compile a canonical harness metadata schema; prototype typed structural facts in shadow; prepare adversarial/benign paired fixtures. No verdict change.
Milestone 1 (2-6 weeks): rename/move-aware structural diff and body weakening; multi-language fixtures for Python/JS/TS/Go/Rust/Java; root-cause grouping; A03/A06 compound experimental signal with evidence.
Milestone 2 (6-12 weeks): dependency/build graph adapters, public API contract adapters (begin TS and Go), build-target and caller impact.
Milestone 3 (12-20+ weeks): additional native semantic frontends, differential authorization/taint path detection, framework model registry, protected path policy.
Milestone 4 (research-heavy): deterministic differential runtime and security sandbox; adoption trials; release qualification and tier-specific SLOs.

Effort ranges are hypotheses dependent on engineering staffing, code quality and test harness reliability, not promised calendars. Use PR-sized work items, benchmark them, and reprioritize on measured evidence.

## 11. First two-week Codex sprint, sequential gates

Day 0: snapshot main/harness immutable SHAs and read code, harness and report contracts. Create baseline inventory without invoking live PR cycles. Preserve existing verdict expectations. Output: baseline evidence ledger and current/unknown capability table. Stop if repository snapshots differ from research.

Task 1: inspect structural_parser.py and all its consumers; map every empty-set path and error propagation. Implement no changes yet. Output: precise call graph and minimal compatibility-safe design. Review gate: existing L4 consumers and CLI output identified.

Task 2: add explicit parser_status/capabilities sidecar or result field behind an opt-in flag, preserving legacy L4 verdict and schema compatibility. Add missing-grammar/invalid-syntax tests. Review gate: no silent grammar success; no changed existing verdict.

Task 3: add richer SymbolFact extraction, source range, language, kind, qualified path and normalized signature, without replacing extract_named_nodes public behaviour. Golden fixtures: Python, JS/TS, Go, Rust, Java. Review gate: side-by-side unchanged legacy results; test valid/no grammar/invalid code.

Task 4: implement shadow rename/move matching with separate BODY_WEAKENED outcome. Paired negative controls: pure rename/move and rename-with-gutting. Review gate: no score changes; deterministic graph delta and provenance.

Task 5: design and record an experimental cross-file compound risk feature and legacy A03/A06 desired outcomes; do not update required branch verdicts. Run offline fixtures only after approval. Review gate: no false positives on safe cleanup/refactor controls.

Task 6: instrument structured finding/evidence checks and report stage timing; add test manifest schema validator and generated documentation proof of equivalence. Review gate: old harness data ingests unchanged.

At each task Codex should produce: exact changed files, tests invoked, fixture oracle, observed outputs, diff summary, performance impact, security/privacy implications and rollback path. Stop on unexpected legacy verdict drift, unexpected network execution, missing test oracle or performance breach. No full regression runner, live PR recreation, token use or branch merges without explicit permission.

## 12. Sources and related implementations

External sources researched:
- Tree-sitter incremental parser and grammar framework: https://tree-sitter.github.io/
- CodeQL extractors, semantic representations: https://codeql.github.com/docs/codeql-overview/about-codeql/
- CodeQL JavaScript binding/call/dataflow models: https://codeql.github.com/docs/codeql-language-guides/codeql-library-for-javascript/
- GumTree fine-grained AST differencing (ASE 2014): https://dl.acm.org/doi/10.1145/2642937.2642982
- Code property graphs (IEEE S&P 2014): https://www.ieee-security.org/TC/SP2014/papers/ModelingandDiscoveringVulnerabilitieswithCodePropertyGraphs.pdf
- Roslyn semantic model: https://learn.microsoft.com/en-us/dotnet/csharp/roslyn-sdk/work-with-semantics
- Clang AST matching and dataflow: https://clang.llvm.org/docs/LibASTMatchers.html ; https://clang.llvm.org/docs/DataFlowAnalysisIntro.html
- Infer reactive/differential CI: https://fbinfer.com/docs/steps-for-ci/
- Semgrep taint and cross-file cost: https://docs.semgrep.dev/writing-rules/data-flow/taint-mode/overview ; https://docs.semgrep.dev/semgrep-code/semgrep-pro-engine-intro
- Cargo resolved dependency graphs: https://doc.rust-lang.org/cargo/commands/cargo-metadata.html
- Bazel graph queries: https://bazel.build/query/language
- GitHub SARIF code-scanning support: https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support
- GitHub Actions security boundary: https://docs.github.com/en/actions/reference/security/secure-use

## 13. Acceptance definition

A production-grade PayloadGuard does not merely classify a PR as destructive. It identifies the introduced consequence, affected consumers and actual evidence; measures uncertainty and coverage; avoids interrupting benign refactors; can be configured and audited; and is safe to run against attacker-controlled source in CI. Until measured, label detector performance as unknown. This research document is the architectural baseline for agent implementation, not a statement that these capabilities already exist.
