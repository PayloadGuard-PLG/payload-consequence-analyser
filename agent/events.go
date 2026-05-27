package main

const (
	EvtExecve  uint32 = 1
	EvtConnect uint32 = 2
	EvtPtrace  uint32 = 3
	EvtProcmem uint32 = 4
)

// Event must match the C struct layout in bpf/probe.c exactly (packed, little-endian).
// type(4) + pid(4) + ppid(4) + comm(16) + detail(64) + blocked(1) + _pad(3) = 96 bytes
type Event struct {
	Type    uint32
	Pid     uint32
	Ppid    uint32
	Comm    [16]byte
	Detail  [64]byte
	Blocked uint8
	Pad     [3]uint8
}

func (e *Event) CommStr() string   { return nullterm(e.Comm[:]) }
func (e *Event) DetailStr() string { return nullterm(e.Detail[:]) }

func nullterm(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func eventTypeName(t uint32) string {
	switch t {
	case EvtExecve:
		return "execve"
	case EvtConnect:
		return "egress_connect"
	case EvtPtrace:
		return "ptrace_attach"
	case EvtProcmem:
		return "procmem_open"
	default:
		return "unknown"
	}
}
