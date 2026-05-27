package main

import (
	"github.com/cilium/ebpf/link"
)

type linkCloser interface {
	Close() error
}

func attachAll(objs *ProbeObjects) ([]linkCloser, error) {
	var links []linkCloser

	l1, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TraceExecve, nil)
	if err != nil {
		closeLinks(links)
		return nil, err
	}
	links = append(links, l1)

	l2, err := link.Tracepoint("syscalls", "sys_enter_connect", objs.TraceConnect, nil)
	if err != nil {
		closeLinks(links)
		return nil, err
	}
	links = append(links, l2)

	l3, err := link.Tracepoint("syscalls", "sys_enter_ptrace", objs.TracePtrace, nil)
	if err != nil {
		closeLinks(links)
		return nil, err
	}
	links = append(links, l3)

	l4, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.TraceOpenat, nil)
	if err != nil {
		closeLinks(links)
		return nil, err
	}
	links = append(links, l4)

	return links, nil
}

func closeLinks(links []linkCloser) {
	for _, l := range links {
		l.Close()
	}
}
