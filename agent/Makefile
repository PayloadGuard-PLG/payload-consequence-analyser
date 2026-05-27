CLANG   ?= clang
BPF2GO  := $(shell go env GOPATH)/bin/bpf2go
CFLAGS  := -O2 -g -Wall -target bpf \
           -I/usr/include \
           -I/usr/include/x86_64-linux-gnu

.PHONY: generate build-amd64 build-arm64 clean test

generate:
	cd agent && go generate ./...

build-amd64: generate
	cd agent && GOOS=linux GOARCH=amd64 go build -o ../dist/pg-agent-linux-amd64 .

build-arm64: generate
	cd agent && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o ../dist/pg-agent-linux-arm64 .

clean:
	rm -f agent/probe_bpf*.go agent/probe_bpf*.o
	rm -rf dist/

# Run from agent/ directory directly
.PHONY: local-generate local-build local-clean

local-generate:
	go generate ./...

local-build: local-generate
	GOOS=linux GOARCH=amd64 go build -o ../dist/pg-agent-linux-amd64 .

local-clean:
	rm -f probe_bpf*.go probe_bpf*.o
