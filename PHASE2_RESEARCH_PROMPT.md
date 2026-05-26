# PayloadGuard Phase 2 — Research Prompt

Feed this prompt to a research agent or LLM to get implementation guidance before beginning Phase 2 development. The goal is to surface concrete implementation decisions, toolchain tradeoffs, and sequencing risks before writing any code.

---

## Context

PayloadGuard is a Python CLI + GitHub Action that performs static pre-merge analysis of pull requests across five layers (surface, forensic, SCA, structural AST, temporal/semantic). Phase 1 is live at v1.2.0 with 236 passing tests and a 33-branch regression harness. The codebase is pure Python, runs as a GitHub Action composite step, and is installed on consumer repos via a pinned SHA in their workflow files.

Phase 2 adds three capabilities:
1. eBPF runtime defence agent (kernel-level process and network monitoring on CI runners)
2. Z3 SMT solver integration (formal verification of detection decision boundaries)
3. Auto-remediation (mutable tag → immutable SHA translation in workflow files)

---

## Research Questions

### A. eBPF Runtime Defence Agent

1. **Library choice**: Compare `bpftrace` (scripting), `libbpf` (C, CO-RE portable), `cilium/ebpf` (Go), and `BCC` (Python). Which is most appropriate for a GitHub Action that must attach probes on an ephemeral Ubuntu 22.04 / 24.04 runner at workflow startup with no persistent kernel module? Consider: compilation speed, BTF dependency, portability across GitHub-hosted runner kernel versions (5.15 LTS → 6.x), and binary size.

2. **Probe selection**: For each of the following threat patterns, specify the exact syscall hooks (`tracepoint`, `kprobe`, or `uprobe`) and the filtering logic needed:
   - Prevent a workflow step reading `/proc/<pid>/mem` of the runner worker process
   - Detect and kill the chain: `npm install` → `postinstall` → `node` → `curl` → external IP
   - Block outbound TCP connections to non-allowlisted destinations from any child of `bash` or `sh` spawned by a workflow step
   - Detect `ptrace(PTRACE_ATTACH, ...)` targeting the runner worker PID

3. **Process ancestry tracking**: What data structure and kernel attachment point gives the most reliable parent→child process tree on a Linux 5.15+ kernel? How do you handle PID reuse correctly? Is `task_struct` walking via `kprobe` on `sched_process_fork` sufficient, or is there a better approach?

4. **Egress allowlist design**: Propose a minimal allowlist schema (YAML or JSON) for common CI use cases: npm, pip, cargo, go modules, docker pull, apt-get. How granular should it be — domain-only, or domain + port + protocol? How does the agent handle HTTPS inspection (SNI vs full TLS)?

5. **Runner constraints**: GitHub-hosted runners run inside a VM (not a container), so eBPF is available. However, `CAP_BPF` and `CAP_PERFMON` may not be granted by default. What is the minimum capability set required, and how do you request it in a GitHub Actions workflow step without running the entire job as root? Is `sudo bpftool` the realistic path?

6. **Graceful degradation**: When eBPF is unavailable (restricted kernel, container sandbox, macOS runner), the agent must fall back to Phase 1 static-only mode without failing the workflow. What detection and fallback mechanism is most reliable?

---

### B. Z3 SMT Solver Integration

7. **Scope definition**: Formally verifying the entire 5-layer pipeline is intractable. Which specific decision boundaries are well-suited to SMT encoding, and which are not? Evaluate each layer:
   - L2c signal classification (finite pattern set → severity mapping): SMT-encodable?
   - L3 scoring model (integer arithmetic, threshold comparisons): SMT-encodable?
   - L4 structural ratio calculation (floating-point): risks with Z3 real vs float arithmetic?
   - L5b MCI heuristic (string operations, regex, tokenisation): tractable?

8. **Encoding strategy**: For the L2c OIDC typosquat decision tree specifically (the newest CRITICAL signal), write a sketch of the Z3 Python binding encoding that proves: "for all action strings A, if `_is_oidc_consumer_typosquatted(A)` returns True, then the verdict score increases by ≥5 and the final verdict is DESTRUCTIVE". What are the boundary conditions that make this proof non-trivial?

9. **Proof vs property-based testing**: Compare Z3 formal proofs against hypothesis-style property-based testing (Hypothesis library) for the same decision boundaries. In terms of implementation effort, coverage guarantees, and maintenance burden — when does Z3 justify the overhead over Hypothesis?

10. **Integration with CI**: How do you integrate Z3 proof scripts into a pytest suite so that failed proofs surface as test failures? Should proofs run in a separate CI job or inline with the existing test suite? What is the typical runtime for Z3 proofs over the scoring model?

---

### C. Auto-Remediation (Mutable Tag → Immutable SHA)

11. **YAML parsing**: GitHub Actions workflows use YAML with `uses:` fields in varied positions (jobs → steps, reusable workflows, matrix strategies). What is the most robust parsing approach to locate all `uses:` values without false positives on comments or multiline strings? Compare `ruamel.yaml` (round-trip preserving), `PyYAML`, and regex-only approaches.

12. **SHA resolution**: Given a `uses: actions/checkout@v4` string, describe the exact GitHub API call sequence to resolve it to a verified commit SHA. What API endpoints are used? How do you handle tag objects (annotated vs lightweight) correctly? What happens when a tag points to a tag object rather than a commit directly?

13. **Verification**: After resolution, how do you verify the SHA is not a squash commit that discards history? Should the tool also verify the commit is signed (GPG/SSH)? What trust model is appropriate for third-party actions vs first-party (github.com/actions/*)?

14. **PR workflow**: Should auto-remediation open a new PR with the pinned SHAs, commit directly to the offending branch, or post a review comment with the suggested changes? What are the security implications of each approach in the context of a tool that itself runs inside GitHub Actions?

---

### D. Sequencing and Integration

15. **Build order**: Given the dependencies between the three components, what is the optimal development sequence? Specifically: does the Z3 work need to happen before, during, or after the eBPF work? Can auto-remediation ship independently as a standalone action?

16. **Packaging**: Phase 1 ships as a composite GitHub Action using a Python script. Should Phase 2 components ship as: (a) additional steps in the same composite action, (b) a separate action called before the main scan, (c) a sidecar container, or (d) a compiled binary distributed via releases? Evaluate each against the constraint that the action must work on GitHub-hosted runners without pre-installed dependencies.

17. **Test harness extension**: The existing harness has 33 branches across `safe/`, `destructive/`, `adversarial/`, `workflow-security/`, and `rta/` categories. Propose the structure of a `runtime/` track that validates eBPF interception. Specifically: how do you create a branch that contains a benign-looking `postinstall` script that attempts to read `/proc/self/mem` and exfiltrate to `localhost:9999`, without that branch actually executing harmful code when opened as a PR on GitHub?

18. **WSL2 development environment**: For compiling C-based eBPF probes and running Z3 proofs on a Ryzen 7800X3D / 64GB RAM machine: what WSL2 configuration (kernel version, memory allocation, BTF support) is optimal? Are there any known issues with eBPF development in WSL2 vs native Linux?

---

## Deliverable Format

Return a structured report with the following sections:

1. **Toolchain decisions** — one recommended choice per question with 2–3 sentence justification
2. **Implementation risks** — top 5 risks across all three components, ranked by likelihood × impact
3. **Dependency map** — which components block which (can Z3 proofs start before eBPF is written?)
4. **Effort breakdown** — per-component estimate in sessions (1 session ≈ 1–2 hours of focused implementation)
5. **Z3 quick-start sketch** — a working 20-line Python Z3 proof of the L3 scoring threshold as a concrete starting point
6. **eBPF quick-start sketch** — the minimal `libbpf` or `cilium/ebpf` skeleton that attaches a `sys_enter_execve` probe and prints the comm of the calling process, compilable on Ubuntu 22.04

This report will be used directly to begin implementation — be concrete and opinionated, not exhaustive.
