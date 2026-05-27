# PayloadGuard Phase 2 — Implementation Plan

> **Status:** Pre-implementation research complete. Ready to begin Stage 1.
> **Phase 1 baseline:** v1.2.0 — 236 passing tests, 33-branch regression harness, live on GitHub Marketplace.

---

## Overview

Phase 2 adds three capabilities to PayloadGuard's existing 5-layer static pre-merge analysis:

| Component | What it does | Risk level |
|---|---|---|
| **A. eBPF Runtime Defence Agent** | Kernel-level process and network monitoring on CI runners | High |
| **B. Z3 SMT Solver Integration** | Formal verification of detection decision boundaries | Medium |
| **C. Auto-Remediation** | Mutable tag → immutable SHA translation in workflow files | Low |

**Recommended build order:** Auto-Remediation first (independent, no kernel coupling) → Z3 and eBPF in parallel → Integration and packaging last.

**Critical context:** GitHub announced a native `dependencies:` workflow lockfile on 26 March 2026, with public preview in 3–6 months and GA at ~6 months. Auto-remediation output must be designed as a forward-compatible drop-in for that block. PayloadGuard becomes the maintainer and auditor of the lockfile, not a competitor.

---

## Toolchain Decisions

| # | Question | Decision | Justification |
|---|---|---|---|
| 1 | eBPF library | **cilium/ebpf + bpf2go** | Single static Go binary (8–15 MB), CO-RE/BTF, no runtime compile on runner. `bpf2go` compiles C probes at developer time and embeds ELF as a `[]byte` constant. BCC and bpftrace both require ~80 MB of runtime deps and multi-second startup. |
| 2 | Probe set | Tracepoints + kprobe + `bpf_send_signal` | `sched_process_fork/exec`, `sys_enter_connect/sendto/sendmsg/sendmmsg`, `sys_enter_ptrace`, kprobe on `proc_mem_open`. Do NOT use BPF-LSM — `bpf` is not in Ubuntu's default `lsm=` list. |
| 3 | Process tree | LRU hash `(pid, start_ns)` | `BPF_MAP_TYPE_LRU_HASH` size 16384 keyed on `(pid, start_ns)`. Pair `sched_process_fork/exec/exit` tracepoints with kprobe on `wake_up_new_task` to close the NCC Group TOCTOU race. |
| 4 | Egress allowlist | `domain:port` YAML, IPs pinned at policy-load | Domain-only allowlists are a known bypass class (see Harden-Runner CVEs). Enforce on pinned IPs via `sys_enter_connect`/`sendto`. SNI-only for HTTPS — no full TLS interception. |
| 5 | Capabilities | sudo-launched agent | GitHub-hosted Ubuntu runners grant `runner` passwordless sudo. Minimum: CAP_BPF + CAP_PERFMON + CAP_SYS_ADMIN (last required due to `cilium/ebpf#1929` for modules-BTF walking). |
| 6 | Degradation | Pre-flight probe, `PAYLOADGUARD_RUNTIME=disabled` | Never fail the workflow due to missing eBPF. Probe: kernel ≥5.15, `/sys/kernel/btf/vmlinux` readable, `tracefs` mounted, caps present, canary kprobe attachable. |
| 7 | Z3 scope | L2c + L3 only | L2c (finite enumerations) and L3 (integer arithmetic) produce `unsat` in <1 s. L4 float ratios: encode as `Real` with interval bounds, not `FPSort(8, 24)`. L5b regex/MCI: use Hypothesis instead — Z3 string theory is too slow. |
| 8 | Z3 encoding | Lift strings/booleans to integer constants | For the OIDC typosquat proof, encode `IsTyposquat` as `Bool` + `TYPO_WEIGHT = 5`. The proof reduces to integer arithmetic — fast and decisive. |
| 9 | Z3 vs Hypothesis | Z3 for ≤10 named safety properties; Hypothesis for everything else | Z3 justifies overhead when a single counterexample would be a security incident (e.g., a signal combination that flips DESTRUCTIVE→PASS). Hypothesis finds bugs faster everywhere else. |
| 10 | Z3 CI integration | Inline pytest, `@pytest.mark.proof`, 5 s per-proof timeout | Target <5 s combined for all proofs. Treat `unknown` as a failure — never allow it to silently pass. |
| 11 | YAML parser | **ruamel.yaml** round-trip mode | PyYAML loses comments and reorders maps. Regex-only fails on multiline strings and commented-out `uses:` lines. ruamel.yaml `YAML(typ='rt')` preserves comments and formatting. |
| 12 | SHA resolution | `git/ref/tags` → `git/tags` → commit SHA | Lightweight tag: `object.type == "commit"` directly. Annotated tag: `object.type == "tag"` → dereference inner `object.sha`. Always append the original tag as a comment (`# v4.2.2`) for Dependabot/Renovate compatibility. |
| 13 | Verification | Parent-count + canonical-repo + reachable-from-tag | No GPG/SSH signing as a blocking check — adoption too low. Third-party actions get an annotation in the PR description. |
| 14 | PR workflow | **New PR only** — never commit direct | New PR requires only `pull-requests: write` (least privilege), produces an audit diff, and runs through normal review. Committing direct requires `contents: write` and is attackable via the same `GITHUB_TOKEN` the tool holds. |
| 15 | Build order | Auto-Remediation → (Z3 + eBPF parallel) → Integration | See Stage plan below. |
| 16 | Packaging | Composite action + precompiled binary from Releases | `uses: org/payloadguard@v2` downloads the agent binary at action startup. Cross-compile amd64 + arm64 and attach to GitHub Releases. |
| 17 | Test harness | `tests/runtime/` with self-targeted fixtures | Fixtures target own PID or localhost only — safe to open as a normal PR (no secrets passed to `pull_request` triggers). |
| 18 | WSL2 dev env | Rebuild kernel from `linux-msft-wsl-6.6.y` | Default WSL2 kernel lacks `CONFIG_DEBUG_INFO_BTF` and several tracepoints. Add BPF/BTF/IKHEADERS flags, copy `bzImage` to Windows, point `.wslconfig` `kernel=` at it. `.wslconfig`: `memory=24GB processors=8`. |

---

## Component A — eBPF Runtime Defence Agent

### Probe specification

| Threat pattern | Attach point | Filter |
|---|---|---|
| `/proc/<pid>/mem` read of Runner.Worker | `kprobe/proc_mem_open` (primary); `tracepoint:syscalls:sys_enter_openat` (fallback) | `target->comm == "Runner.Worker"` AND `current->tgid != target->tgid` |
| `npm install → postinstall → node → curl → external IP` | `tracepoint:sched:sched_process_fork` + `sched_process_exec` + `sys_enter_connect` | Walk PID ancestry map; if any ancestor `comm ∈ {npm, yarn, pnpm}` and a later ancestor is `node` and child is `curl`/`wget`, with destination IP not in allowlist → SIGKILL |
| Outbound TCP from child of bash/sh | `tracepoint:syscalls:sys_enter_connect` + `sendto` + `sendmsg` + `sendmmsg` | Any ancestor `comm ∈ {bash, sh, dash, zsh}` AND `sin_addr` not in pinned allowlist → `bpf_send_signal(9)` |
| `ptrace(PTRACE_ATTACH, runner_worker_pid)` | `tracepoint:syscalls:sys_enter_ptrace` | `args[0] ∈ {16 (PTRACE_ATTACH), 0x4206 (PTRACE_SEIZE)}` AND `args[1] == runner_worker_pid` → `bpf_send_signal(9)` |

> **Note on BPF-LSM:** `CONFIG_BPF_LSM=y` is compiled into Ubuntu runner kernels but the `bpf` LSM is not in the active boot list (`cat /sys/kernel/security/lsm` returns `lockdown,capability,landlock,yama,apparmor`). `BPF_PROG_TYPE_LSM` programs will fail to load on stock GitHub runners. Use tracepoints and kprobes throughout.

### Egress allowlist schema

```yaml
# payloadguard-policy.yaml
version: 1
defaults:
  protocol: tcp
  resolve_at: policy_load   # pin IPs at load time, NOT per-connection
ecosystems:
  npm:
    - registry.npmjs.org:443
    - registry.yarnpkg.com:443
  pip:
    - pypi.org:443
    - files.pythonhosted.org:443
  cargo:
    - crates.io:443
    - static.crates.io:443
  go:
    - proxy.golang.org:443
    - sum.golang.org:443
  docker:
    - registry-1.docker.io:443
    - auth.docker.io:443
    - production.cloudflare.docker.com:443
  apt:
    - archive.ubuntu.com:80
    - security.ubuntu.com:80
    - ppa.launchpadcontent.net:443
github:
  - github.com:443
  - api.github.com:443
  - objects.githubusercontent.com:443
extra: []
```

### Pre-flight capability probe (degradation sequence)

```
1. uname -r → must be ≥ 5.15
2. /sys/kernel/btf/vmlinux exists and readable
3. /sys/fs/bpf mounted (or mountable)
4. effective capabilities include CAP_BPF and CAP_PERFMON
5. canary kprobe attaches without error
```

On any failure: set `PAYLOADGUARD_RUNTIME=disabled`, emit `::warning::`, continue in static-only mode. Never fail the workflow.

### eBPF quick-start sketch

`probe.c` (compiled at developer time via `bpf2go`):

```c
//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct event {
    __u32 pid;
    __u32 ppid;
    char  comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx) {
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->pid  = bpf_get_current_pid_tgid() >> 32;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}
```

Build on Ubuntu 22.04:

```bash
sudo apt install -y clang llvm libbpf-dev linux-tools-generic
go install github.com/cilium/ebpf/cmd/bpf2go@latest
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
go generate && go build -o pg-agent .
sudo ./pg-agent
```

---

## Component B — Z3 SMT Solver Integration

### Layer encodability

| Layer | Z3-encodable? | Approach | Risk |
|---|---|---|---|
| L2c — finite signal → severity | **Yes, ideal** | `EnumSort`, `IntSort`, `ForAll` | None — `unsat` in <100 ms |
| L3 — integer arithmetic, thresholds | **Yes, ideal** | `Int`, `Sum`, comparison | None — sub-second |
| L4 — structural ratios, floats | **Discouraged** | `Real` with bounded intervals only; NOT `FPSort(8, 24)` | FPA solver orders-of-magnitude slower |
| L5b — regex, tokenisation, MCI | **Not worth it** | Use Hypothesis | String+arithmetic undecidable; expect timeouts |

### Named safety properties (≤10 target)

1. Typosquat signal implies `verdict_score ≥ 5`
2. Typosquat signal implies final verdict is `DESTRUCTIVE`
3. No negative-weight signal combination can cancel a typosquat
4. Severity mapping is total (every signal maps to exactly one severity)
5. Score monotonicity — adding a CRITICAL signal never decreases total score
6. `PASS` verdict requires `score < DESTRUCTIVE_THRESHOLD`
7. Verdict transitions are deterministic given identical signal sets
8. OIDC consumer typosquat → score cannot be reduced to `PASS` by any trust signal
9. Score upper bound is finite and within `Int` range
10. Empty signal set always produces `PASS`

### Z3 quick-start sketch (L3 scoring threshold)

```python
# tests/proofs/test_scoring_monotonicity.py
from z3 import Solver, Int, Bool, Implies, Not, unsat

def test_typosquat_implies_destructive():
    """For all signal combinations: if OIDC typosquat is detected,
    the verdict score is >= 5 and verdict is DESTRUCTIVE."""
    s = Solver()
    s.set("timeout", 5000)

    is_typo = Bool("is_typo")              # _is_oidc_consumer_typosquatted(A)
    base    = Int("base")                  # sum of non-typo signal contributions
    neg_max = Int("neg_max")               # max negative contribution from trust signals
    score   = Int("score")                 # final score

    TYPO_WEIGHT = 5
    DESTRUCTIVE_THRESHOLD = 5

    s.add(base    >= 0,  base    <= 20)    # bounded signal stack
    s.add(neg_max >= -2, neg_max <= 0)     # bounded trust subtraction
    s.add(Implies(is_typo,      score == base + TYPO_WEIGHT + neg_max))
    s.add(Implies(Not(is_typo), score == base + neg_max))

    # Assert the NEGATION of what we want to prove
    s.add(is_typo, score < DESTRUCTIVE_THRESHOLD)

    result = s.check()
    assert result == unsat, f"counterexample: {s.model()}"
```

> **Critical:** Treat `unknown` as a test failure — never allow it to silently pass. `unknown` means Z3 hit the timeout, not that the property holds.

### CI integration

```python
# pytest.ini / pyproject.toml
[pytest]
markers =
    proof: Z3 formal proofs — run with pytest -m proof

# Run inline, required on main and release/* branches
# Target: < 5 s combined for all 10 proofs
```

---

## Component C — Auto-Remediation

### SHA resolution sequence

```
GET /repos/{owner}/{repo}/git/ref/tags/{tag}
  └─ object.type == "commit"  →  done (lightweight tag), commit SHA = object.sha
  └─ object.type == "tag"     →  GET /repos/{owner}/{repo}/git/tags/{object.sha}
                                   └─ inner object.sha = commit SHA (annotated tag)

If ref is a branch (uses: org/repo@main):
  → GET /repos/{owner}/{repo}/git/ref/heads/{branch}
  → emit loud warning, do not treat as pinned
```

Always append the original tag as a comment: `uses: actions/checkout@abc123def456  # v4`

### PR workflow (security model)

- **Open a new PR** — requires only `pull-requests: write`
- **Never commit direct** — requires `contents: write`, attackable via `GITHUB_TOKEN`
- **Never use review comment as primary path** — no audit trail, easy to miss
- If PR creation fails (fork-PR / `pull_request_target` edge cases): fall back to a single consolidated review comment
- `GITHUB_TOKEN` rate limit inside Actions is **1,000 requests/hour/repo** — cache resolved SHAs across runs

### Verification

- Verify SHA is reachable from a release tag (not just a branch tip)
- Verify commit is from canonical repo, not a fork
- Record parent count (squash-commit heuristic) — do not block, annotate
- First-party actions (`actions/*`, `github/*`, `docker/*`): default-allow
- Third-party actions: annotated in PR description

---

## Implementation Risks

Ranked by likelihood × impact:

| # | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| 1 | GitHub runner kernel-config drift breaks agent silently | High | High | CO-RE handles struct layout. Add weekly CI job that boots both runner images and runs the pre-flight probe. |
| 2 | `bpf_send_signal(SIGKILL)` gated or reverted in future kernel | Low | Catastrophic to enforcement | Ship `--mode={audit,block}` with `audit` as default. Detection-and-report is the baseline; enforcement is opt-in. |
| 3 | Auto-remediation preempted by GitHub's native workflow lockfile (ETA Q3 2026) | Medium | Medium | Design output as forward-compatible `dependencies:` block drop-in. PayloadGuard becomes the lockfile maintainer, not a competitor. |
| 4 | Egress allowlist false-positive blocks for legitimate first-time-seen domains | High | Medium | Default to `--mode=audit`. Ship curated default allowlist. Require explicit per-repo opt-in to enforcement. |
| 5 | Z3 proofs become maintenance burden as scoring model evolves | Medium | Medium | Cap at ~10 properties. Treat proof failures as a required part of any scoring-model PR review. |

---

## Dependency Map

```
auto-remediation  ──── independent ────────────────────► ship anytime

Z3 proofs         ──── depends on: L2c/L3 code (Phase 1, already shipped)
                                   ↓
                       can begin immediately, before any eBPF work

eBPF agent        ──── depends on: nothing in this phase
                                   ↓
runtime/ harness  ──── depends on: eBPF agent's --dump-events JSON schema stable

packaging         ──── depends on: all three above
```

---

## Effort Breakdown

1 session ≈ 1–2 hours of focused implementation.

| Component | Sessions |
|---|---|
| Auto-remediation: YAML walker, SHA resolver, PR opener, tests | 6–8 |
| Z3: solver wrapper, 10 proof properties, pytest integration | 8–10 |
| eBPF agent: C probes + cilium/ebpf loader + ring buffer reader | 12–15 |
| eBPF agent: process ancestry + egress allowlist + policy loader | 6–8 |
| eBPF agent: graceful degradation + pre-flight probe + CLI flags | 3–4 |
| Runtime test harness (`tests/runtime/`) | 4–6 |
| Packaging: composite action, Releases binary cross-compile, install step | 3–4 |
| Documentation, README updates, threat-model writeup | 3–4 |
| **Total** | **45–59 sessions (~90–120 focused hours)** |

---

## Stage Plan

### Stage 1 — Ship auto-remediation (~8 sessions, weeks 1–2)

- ruamel.yaml round-trip YAML walker
- Annotated-tag-aware SHA resolver
- New-PR opener with `pull-requests: write` only
- Ship behind `--auto-remediate` flag; off by default
- **Advance threshold:** ≥10 production users, <1% false-positive rate on action resolution

### Stage 2 — Ship Z3 proofs (~10 sessions, parallel with Stage 3, weeks 2–4)

- Implement the 10 named safety properties
- `@pytest.mark.proof` marker, `make proofs` target
- All 10 proofs `unsat` in <5 s combined on `main`
- **Advance threshold:** zero `unknown` results on main across 30 days

### Stage 3 — Ship eBPF agent (~30 sessions, weeks 3–10)

- `--mode=audit` only for v2.0 — no enforcement yet
- Cross-compile amd64 + arm64, attach to GitHub Releases
- Composite action: `sudo curl … && sudo pg-agent --daemon &`
- **Advance to `--mode=block`:** ≥100 hours of production audit logs from beta users, <5 confirmed false-positive blocks per 1,000 workflow runs

### Stage 4 — Re-position auto-remediation (~Q3 2026)

When GitHub's `dependencies:` lockfile reaches public preview, pivot PayloadGuard to populate and audit the native lockfile format.

---

## Benchmarks That Change the Plan

| Benchmark | Response |
|---|---|
| GitHub disables passwordless sudo on hosted runners | eBPF agent moves to self-hosted runner deployment guide; deprioritise GitHub-hosted path |
| CVE class against `bpf_send_signal` and helper gated | Drop to audit-only permanently |
| Z3 proofs balloon past 30 s combined | Migrate to nightly CI job, not inline pytest |
| GitHub `dependencies:` lockfile ships early | Accelerate Stage 4 pivot |

---

## WSL2 Development Environment (Ryzen 7800X3D / 64 GB RAM)

Rebuild the WSL2 kernel from `microsoft/WSL2-Linux-Kernel` branch `linux-msft-wsl-6.6.y` or later with these flags added to `Microsoft/config-wsl`:

```
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_BPF_EVENTS=y
CONFIG_HAVE_EBPF_JIT=y
CONFIG_DEBUG_INFO=y
CONFIG_DEBUG_INFO_BTF=y
CONFIG_IKHEADERS=y
```

Build:
```bash
make -j$(nproc) KCONFIG_CONFIG=Microsoft/config-wsl
# copy arch/x86/boot/bzImage to Windows
```

`.wslconfig`:
```ini
[wsl2]
kernel=C:\\path\\to\\bzImage
memory=24GB
processors=8
```

**Known issues vs native Linux:**
- `/sys/fs/bpf` may need manual mounting: `sudo mount -t bpf bpf /sys/fs/bpf`
- `bpf_send_signal` works on 6.6+ but verifier behaviour can differ on older microsoft-wsl kernels — validate on the rebuilt kernel
- ARM64 WSL2: build `arch/arm64/boot/Image` instead
- Docker Desktop may break when custom kernels move features from built-in to modules

---

## Runtime Test Harness Structure

```
tests/runtime/
  fixtures/
    procmem-read/
      action.yml          # triggers benign /proc/self/mem open
      probe.sh            # reads /proc/self/mem, 0-byte operation
    postinstall-curl/
      package.json        # npm script with postinstall hook
      postinstall.sh      # curls 127.0.0.1:9999 (localhost only)
    ptrace-self/
      attacker.c          # ptrace(PTRACE_TRACEME, 0) — not PTRACE_ATTACH
  expected/
    procmem-read.json     # expected agent event output
    postinstall-curl.json
    ptrace-self.json
  harness.py              # launches agent in test mode, runs fixture, diffs output
```

**Safety design:** all malicious behaviour is self-targeted (own PID, `127.0.0.1`, `PTRACE_TRACEME`). Agent test mode uses a configurable comm string (`Runner.Worker.test`) rather than the production target. Safe to open as a normal PR — secrets not passed to `pull_request` triggers for external contributors. Do not use `pull_request_target`.

---

## Caveats and Known Unknowns

- **Harden-Runner internals are not public.** Its release notes describe detection behaviour but the specific kernel attach points are undisclosed. The probe recommendations in this plan are derived from public Falco, Tetragon, and Tracee precedent — not Harden-Runner internals.
- **Confirm `lsm=` on live runner before any LSM-dependent feature.** `cat /sys/kernel/security/lsm` on a live runner; do not assume BTF-LSM is active.
- **GitHub `dependencies:` lockfile is a roadmap item, not a shipped feature.** Timeline is the vendor's stated estimate and may slip.
- **`bpf_send_signal()` is `gpl_only`.** Probe C code must declare `char LICENSE[] SEC("license") = "GPL"`. The userspace Go agent can use any license — this is a kernel-side convention only.
- **`GITHUB_TOKEN` inside Actions is 1,000 req/hr/repo**, not 5,000/hr. Cache resolved SHAs across runs.
- **Z3 `unknown` must be treated as failure.** Configure per-proof timeouts and assert `result == unsat`.
- **Harden-Runner has multiple disclosed egress-bypass CVEs** (DNS-over-HTTPS bypass GHSA-46g3-37rh-v698, DNS-rebinding CVE-2026-25598, `sendto`/`sendmsg`/`sendmmsg` audit gaps). Treat any egress-allowlist feature as defence-in-depth, never as a sole control.
- **Runner kernel versions change weekly.** Validate via the pre-flight probe at runtime — never hardcode kernel version strings.
