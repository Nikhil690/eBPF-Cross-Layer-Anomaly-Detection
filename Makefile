CLANG   := clang
CFLAGS  := -O2 -g -target bpf -D__TARGET_ARCH_x86

.PHONY: all generate build clean

all: build

generate:
	go generate ./...

build: generate
	CGO_ENABLED=0 go build -o ebpf-cla .

vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h

run: build
	sudo ./ebpf-cla $(IFACE)

clean:
	rm -f *_bpfel.go *_bpfel.o *_bpfeb.go *_bpfeb.o ebpf-cla
