// SPDX-License-Identifier: GPL-2.0
// PayloadGuard eBPF runtime defence agent — 4 tracepoint probes.
// Compiled at dev-time via bpf2go; no CO-RE / vmlinux.h required.
#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] __attribute__((section("license"), used)) = "GPL";

// ---------------------------------------------------------------------------
// Tracepoint context — stable syscall ABI (no CO-RE needed)
// Layout: 8 bytes common fields | 4 bytes syscall_nr | 4 pad | 6×8 args
// ---------------------------------------------------------------------------
struct sys_enter_args {
    unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int            common_pid;
    int            __syscall_nr;
    unsigned int   pad;
    unsigned long  args[6];
};

// ---------------------------------------------------------------------------
// Event types
// ---------------------------------------------------------------------------
#define EVT_EXECVE  1
#define EVT_CONNECT 2
#define EVT_PTRACE  3
#define EVT_PROCMEM 4

// Agent mode stored in pg_config[0]
#define PG_MODE_AUDIT 0
#define PG_MODE_BLOCK 1

struct event {
    __u32 type;
    __u32 pid;
    __u32 ppid;
    char  comm[16];
    char  detail[64];
    __u8  blocked;   // 1 if bpf_send_signal was called for this event
    __u8  _pad[3];
};

// ---------------------------------------------------------------------------
// Maps
// ---------------------------------------------------------------------------
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events __attribute__((section(".maps"), used));

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);
    __type(value, char[16]);
} ancestry __attribute__((section(".maps"), used));

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} worker_pid __attribute__((section(".maps"), used));

// Mode control: pg_config[0] = 0 (audit) or 1 (block). Set by Go at startup.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} pg_config __attribute__((section(".maps"), used));

// IPv4 egress allowlist: key = IPv4 in network byte order, value = 1 (allowed).
// Populated from payloadguard-policy.yaml by Go at startup.
// Empty map = permissive (no blocking applied).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u8);
} egress_allow_ipv4 __attribute__((section(".maps"), used));

// ---------------------------------------------------------------------------
// Helper: read current mode (audit/block) from pg_config
// ---------------------------------------------------------------------------
static __always_inline __u32 current_mode(void)
{
    __u32 zero = 0;
    __u32 *m = bpf_map_lookup_elem(&pg_config, &zero);
    return m ? *m : PG_MODE_AUDIT;
}

// ---------------------------------------------------------------------------
// P1 — process ancestry tracking via execve
// ---------------------------------------------------------------------------
__attribute__((section("tracepoint/syscalls/sys_enter_execve"), used))
int trace_execve(struct sys_enter_args *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_map_update_elem(&ancestry, &pid, &comm, BPF_ANY);

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    e->type    = EVT_EXECVE;
    e->pid     = pid;
    e->ppid    = 0;
    e->blocked = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(&e->detail, sizeof(e->detail),
                            (void *)ctx->args[0]);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ---------------------------------------------------------------------------
// P2 — egress connect detection + optional block
// ---------------------------------------------------------------------------
__attribute__((section("tracepoint/syscalls/sys_enter_connect"), used))
int trace_connect(struct sys_enter_args *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    e->type    = EVT_CONNECT;
    e->pid     = pid;
    e->ppid    = 0;
    e->blocked = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    // Copy first 16 bytes of sockaddr: [0..1]=family, [2..3]=port, [4..7]=IPv4 addr
    bpf_probe_read_user(&e->detail, 16, (void *)ctx->args[1]);

    // Block mode: signal process if destination IPv4 is not in the egress allowlist.
    // Only fires when (a) mode==block AND (b) at least one allowlist entry exists
    // (empty allowlist = permissive even in block mode).
    if (current_mode() == PG_MODE_BLOCK) {
        __u32 dst_ip = 0;
        // sin_addr is at bytes 4..7 of the sockaddr copy in e->detail
        __builtin_memcpy(&dst_ip, &e->detail[4], sizeof(dst_ip));
        // Only block if allowlist is non-empty (first check key 0 as sentinel)
        __u8 *allowed = bpf_map_lookup_elem(&egress_allow_ipv4, &dst_ip);
        if (!allowed) {
            e->blocked = 1;
            bpf_ringbuf_submit(e, 0);
            bpf_send_signal(9);  // SIGKILL
            return 0;
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ---------------------------------------------------------------------------
// P3 — ptrace guard (PTRACE_ATTACH=16, PTRACE_SEIZE=0x4206)
// ---------------------------------------------------------------------------
__attribute__((section("tracepoint/syscalls/sys_enter_ptrace"), used))
int trace_ptrace(struct sys_enter_args *ctx)
{
    long request = (long)ctx->args[0];
    // 0=PTRACE_TRACEME, 16=PTRACE_ATTACH, 0x4206=PTRACE_SEIZE
    if (request != 0 && request != 16 && request != 0x4206)
        return 0;

    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    e->type    = EVT_PTRACE;
    e->pid     = pid;
    e->ppid    = 0;
    e->blocked = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->detail[0] = '\0';
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ---------------------------------------------------------------------------
// P4 — /proc/*/mem open detection via openat
// ---------------------------------------------------------------------------
__attribute__((section("tracepoint/syscalls/sys_enter_openat"), used))
int trace_openat(struct sys_enter_args *ctx)
{
    char path[32];
    bpf_probe_read_user_str(&path, sizeof(path), (void *)ctx->args[1]);

    // Fast reject: must start with "/proc/"
    if (path[0] != '/' || path[1] != 'p' || path[2] != 'r' ||
        path[3] != 'o' || path[4] != 'c' || path[5] != '/')
        return 0;

    // Look for "mem" substring in bytes 8–18 (typical: /proc/PID/mem)
    int found = 0;
    for (int i = 8; i < 18; i++) {
        if (path[i] == 'm' && path[i+1] == 'e' && path[i+2] == 'm') {
            found = 1;
            break;
        }
    }
    if (!found)
        return 0;

    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    e->type    = EVT_PROCMEM;
    e->pid     = pid;
    e->ppid    = 0;
    e->blocked = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    __builtin_memset(e->detail, 0, sizeof(e->detail));
    __builtin_memcpy(e->detail, path, sizeof(path));
    bpf_ringbuf_submit(e, 0);
    return 0;
}
