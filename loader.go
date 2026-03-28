package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -target bpf -D__TARGET_ARCH_x86" XDP ./bpf/xdp.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -target bpf -D__TARGET_ARCH_x86" TC ./bpf/tc.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -target bpf -D__TARGET_ARCH_x86" Tracepoint ./bpf/tracepoint.c

import (
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type Loader struct {
	xdpObjs XDPObjects
	tcObjs  TCObjects
	tpObjs  TracepointObjects

	xdpLink link.Link
	tcLink  link.Link
	tpLink  link.Link

	ringRB  *ringbuf.Reader   // kernel ring buffer
	sweptCh chan TCClaCorrRecord // userspace-swept short-lived flows
}

func NewLoader(iface string) (*Loader, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}

	l := &Loader{sweptCh: make(chan TCClaCorrRecord, 4096)}

	/* ── 1. Load XDP (creates flow_stats_map) ──────────── */
	if err := LoadXDPObjects(&l.xdpObjs, nil); err != nil {
		return nil, fmt.Errorf("load xdp: %w", err)
	}

	ifc, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("interface %s: %w", iface, err)
	}
	l.xdpLink, err = link.AttachXDP(link.XDPOptions{
		Program:   l.xdpObjs.XdpFlowMonitor,
		Interface: ifc.Index,
	})
	if err != nil {
		return nil, fmt.Errorf("attach xdp: %w", err)
	}

	/* ── 2. Load TC (shares flow_stats_map from XDP) ───── */
	if err := LoadTCObjects(&l.tcObjs, &ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			"flow_stats_map": l.xdpObjs.FlowStatsMap,
		},
	}); err != nil {
		return nil, fmt.Errorf("load tc: %w", err)
	}

	l.tcLink, err = link.AttachTCX(link.TCXOptions{
		Program:   l.tcObjs.TcCorrelate,
		Interface: ifc.Index,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		return nil, fmt.Errorf("attach tc: %w", err)
	}

	/* ── 3. Load Tracepoint (shares corr_window + ring) ── */
	if err := LoadTracepointObjects(&l.tpObjs, &ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			"corr_window_map": l.tcObjs.CorrWindowMap,
			"ring_events":     l.tcObjs.RingEvents,
		},
	}); err != nil {
		return nil, fmt.Errorf("load tracepoint: %w", err)
	}
	l.tpLink, err = link.Tracepoint("syscalls", "sys_enter_connect",
		l.tpObjs.TraceConnect, nil)
	if err != nil {
		return nil, fmt.Errorf("attach tracepoint: %w", err)
	}

	/* ── 4. Ring buffer reader (shared ring_events from TC) */
	l.ringRB, err = ringbuf.NewReader(l.tcObjs.RingEvents)
	if err != nil {
		return nil, fmt.Errorf("ringbuf reader: %w", err)
	}

	log.Printf("[loader] attached XDP+TC on %s, tracepoint sys_enter_connect", iface)

	/* ── 5. Start userspace corr_window sweeper ────────── */
	go l.sweepCorrWindow()

	return l, nil
}

// sweepCorrWindow iterates corr_window_map every 20ms, emits any entries
// older than 5ms directly to the events channel (bypassing ring buffer).
// This catches short-lived connections (port scans) whose sockets close
// before the kernel-side 5ms flush fires.
func (l *Loader) sweepCorrWindow() {
	const windowNS = uint64(5_000_000) // 5 ms
	const tickMS = 20                  // sweep every 20 ms
	ticker := time.NewTicker(tickMS * time.Millisecond)
	defer ticker.Stop()
	for range ticker.C {
		nowNS := uint64(time.Now().UnixNano())
		var cookie uint64
		var rec TCClaCorrRecord
		iter := l.tcObjs.CorrWindowMap.Iterate()
		var toDelete []uint64
		for iter.Next(&cookie, &rec) {
			if rec.WindowStartNs == 0 {
				continue
			}
			age := nowNS - rec.WindowStartNs
			if age >= windowNS {
				l.sweptCh <- rec
				toDelete = append(toDelete, cookie)
			}
		}
		for _, k := range toDelete {
			_ = l.tcObjs.CorrWindowMap.Delete(k)
		}
	}
}

func (l *Loader) Close() {
	if l.ringRB != nil {
		l.ringRB.Close()
	}
	if l.xdpLink != nil {
		l.xdpLink.Close()
	}
	if l.tcLink != nil {
		l.tcLink.Close()
	}
	if l.tpLink != nil {
		l.tpLink.Close()
	}
	l.xdpObjs.Close()
	l.tcObjs.Close()
	l.tpObjs.Close()
}

func ifaceFromArgs() string {
	if len(os.Args) > 1 {
		return os.Args[1]
	}
	return "eth0"
}
