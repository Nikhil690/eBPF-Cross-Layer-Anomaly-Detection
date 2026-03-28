package main

import (
	"bytes"
	"encoding/binary"
	"strings"
)

// CorrRecord mirrors bpf/common.h struct corr_record (128 bytes).
type CorrRecord struct {
	Cookie        uint64
	WindowStartNS uint64
	Net           NetStats
	Proc          ProcStats
	LayerCoverage uint8
	Pad           [7]byte
}

type NetStats struct {
	PktCount     uint64
	ByteCount    uint64
	LastSeenNS   uint64
	FirstSeenNS  uint64
	SYNCount     uint32
	RSTCount     uint32
	FINCount     uint32
	TCPFlagsSeen uint32
	IATSumNS     uint64
}

type ProcStats struct {
	PID          uint32
	UID          uint32
	Comm         [16]byte
	SyscallCount uint64
	ExecveCount  uint64
	MmapCount    uint64
}

// ParseCorrRecord reads a corr_record from ring buffer bytes.
func ParseCorrRecord(raw []byte) (CorrRecord, error) {
	var rec CorrRecord
	r := bytes.NewReader(raw)
	err := binary.Read(r, binary.LittleEndian, &rec)
	return rec, err
}

func int8SliceToBytes(s []int8) [16]byte {
	var b [16]byte
	for i, v := range s {
		if i >= 16 {
			break
		}
		b[i] = byte(v)
	}
	return b
}

// CommString returns the null-trimmed process name.
func (p *ProcStats) CommString() string {
	n := bytes.IndexByte(p.Comm[:], 0)
	if n < 0 {
		n = len(p.Comm)
	}
	return strings.TrimRight(string(p.Comm[:n]), "\x00")
}

// tcRecordToCorrRecord converts the bpf2go-generated TCClaCorrRecord into
// the canonical CorrRecord used throughout userspace.
func tcRecordToCorrRecord(t TCClaCorrRecord) CorrRecord {
	return CorrRecord{
		Cookie:        t.Cookie,
		WindowStartNS: t.WindowStartNs,
		Net: NetStats{
			PktCount:     t.Net.PktCount,
			ByteCount:    t.Net.ByteCount,
			LastSeenNS:   t.Net.LastSeenNs,
			FirstSeenNS:  t.Net.FirstSeenNs,
			SYNCount:     t.Net.SynCount,
			RSTCount:     t.Net.RstCount,
			FINCount:     t.Net.FinCount,
			TCPFlagsSeen: t.Net.TcpFlagsSeen,
			IATSumNS:     t.Net.IatSumNs,
		},
		Proc: ProcStats{
			PID:          t.Proc.Pid,
			UID:          t.Proc.Uid,
			Comm:         int8SliceToBytes(t.Proc.Comm[:]),
			SyscallCount: t.Proc.SyscallCount,
			ExecveCount:  t.Proc.ExecveCount,
			MmapCount:    t.Proc.MmapCount,
		},
		LayerCoverage: t.LayerCoverage,
	}
}

// ExtractFeatures converts a CorrRecord into a FeatureVector for scoring.
func ExtractFeatures(rec CorrRecord) FeatureVector {
	duration := float64(rec.Net.LastSeenNS - rec.Net.FirstSeenNS)
	pktRate := 0.0
	if duration > 0 {
		pktRate = float64(rec.Net.PktCount) / (duration / 1e9)
	}
	synRatio := 0.0
	if rec.Net.PktCount > 0 {
		synRatio = float64(rec.Net.SYNCount) / float64(rec.Net.PktCount)
	}

	layers := 0
	for i := 0; i < 4; i++ {
		if rec.LayerCoverage&(1<<i) != 0 {
			layers++
		}
	}

	return FeatureVector{
		PktCount:      float64(rec.Net.PktCount),
		ByteCount:     float64(rec.Net.ByteCount),
		SYNCount:      float64(rec.Net.SYNCount),
		RSTCount:      float64(rec.Net.RSTCount),
		SYNRatio:      synRatio,
		Duration:      duration,
		PktRate:       pktRate,
		LayerCoverage: float64(layers),
		ConnectRate:   float64(rec.Proc.SyscallCount),
	}
}
