package main

import (
	"fmt"
	"os"
	"runtime"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/rlimit"
)

// preflight returns true if this environment supports eBPF ring buffers and
// tracepoint programs. On failure it emits a GitHub Actions warning and returns
// false. It never returns an error — the agent always exits 0.
func preflight() bool {
	// 1. Architecture — only amd64 / arm64 supported
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		warn("unsupported arch " + runtime.GOARCH + " — skipping eBPF agent")
		return false
	}

	// 2. Kernel ≥ 5.8 required for BPF_MAP_TYPE_RINGBUF
	var uts syscall.Utsname
	if err := syscall.Uname(&uts); err != nil {
		warn("cannot determine kernel version: " + err.Error())
		return false
	}
	release := int8sToStr(uts.Release[:])
	var major, minor int
	if _, err := fmt.Sscanf(release, "%d.%d", &major, &minor); err != nil {
		warn("cannot parse kernel version '" + release + "'")
		return false
	}
	if major < 5 || (major == 5 && minor < 8) {
		warn(fmt.Sprintf("kernel %s < 5.8 — ringbuf unavailable, skipping eBPF", release))
		return false
	}

	// 3. BPF filesystem must be mounted
	if _, err := os.Stat("/sys/fs/bpf"); err != nil {
		warn("BPF filesystem not mounted (/sys/fs/bpf absent) — skipping eBPF")
		return false
	}

	// 4. Remove memlock limit before canary load — required on kernels without
	//    automatic memlock exemption (including WSL2). Must happen before any
	//    BPF program or map is created.
	if err := rlimit.RemoveMemlock(); err != nil {
		warn("RemoveMemlock: " + err.Error())
		return false
	}

	// 5. Canary load — verify that BPF_PROG_TYPE_TRACEPOINT is actually supported.
	//    Some kernels (e.g. containers without CONFIG_KPROBES) have BPF_SYSCALL
	//    but reject tracepoint programs. We detect this early and exit 0.
	canary, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:    ebpf.TracePoint,
		License: "GPL",
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
	})
	if err != nil {
		warn(fmt.Sprintf("kernel %s: BPF_PROG_TYPE_TRACEPOINT unavailable (%v) — skipping eBPF agent", release, err))
		return false
	}
	canary.Close()

	return true
}

func warn(msg string) {
	fmt.Fprintf(os.Stderr, "::warning::pg-agent: %s\n", msg)
}

func int8sToStr(arr []int8) string {
	b := make([]byte, 0, len(arr))
	for _, v := range arr {
		if v == 0 {
			break
		}
		b = append(b, byte(v))
	}
	return string(b)
}
