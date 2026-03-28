package main

import (
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/cilium/ebpf/ringbuf"
)

func main() {
	iface, csvPath, label := parseArgs()
	loader, err := NewLoader(iface)
	if err != nil {
		log.Fatalf("loader: %v", err)
	}
	defer loader.Close()

	stats := &OnlineStats{}
	alerts := 0
	total := 0

	/* ── Optional CSV writer ───────────────────────────── */
	var csvW *csv.Writer
	if csvPath != "" {
		f, err := os.OpenFile(csvPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatalf("csv open: %v", err)
		}
		defer f.Close()
		csvW = csv.NewWriter(f)
		// Write header only if file is empty
		fi, _ := f.Stat()
		if fi.Size() == 0 {
			csvW.Write([]string{
				"timestamp", "label", "score", "layers",
				"syn_count", "rst_count", "pkt_count", "byte_count",
				"pkt_rate", "layer_coverage", "connect_rate", "cookie",
			})
			csvW.Flush()
		}
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	processRecord := func(cr CorrRecord) {
		fv := ExtractFeatures(cr)
		stats.Update(fv)
		score := stats.AnomalyScore(fv)
		total++

		layers := layerString(cr.LayerCoverage)
		comm := cr.Proc.CommString()

		if csvW != nil {
			csvW.Write([]string{
				time.Now().Format("15:04:05.000"),
				label,
				strconv.FormatFloat(score, 'f', 3, 64),
				layers,
				strconv.FormatUint(uint64(cr.Net.SYNCount), 10),
				strconv.FormatUint(uint64(cr.Net.RSTCount), 10),
				strconv.FormatUint(cr.Net.PktCount, 10),
				strconv.FormatUint(cr.Net.ByteCount, 10),
				strconv.FormatFloat(fv.PktRate, 'f', 2, 64),
				strconv.FormatFloat(fv.LayerCoverage, 'f', 0, 64),
				strconv.FormatFloat(fv.ConnectRate, 'f', 0, 64),
				strconv.FormatUint(cr.Cookie, 10),
			})
			csvW.Flush()
		}

		if score > AnomalyThreshold {
			alerts++
			log.Printf("[ALERT] score=%.2f layers=%s syn=%d pkt=%d pid=%d comm=%s cookie=%d",
				score, layers, cr.Net.SYNCount, cr.Net.PktCount,
				cr.Proc.PID, comm, cr.Cookie)
		} else if total%50 == 0 {
			log.Printf("[info ] score=%.2f layers=%s pkt=%d total_events=%d alerts=%d",
				score, layers, cr.Net.PktCount, total, alerts)
		}
	}

	/* ── Ring buffer consumer ──────────────────────────── */
	go func() {
		for {
			rec, err := loader.ringRB.Read()
			if err != nil {
				if err == ringbuf.ErrClosed {
					return
				}
				continue
			}
			cr, err := ParseCorrRecord(rec.RawSample)
			if err != nil {
				log.Printf("[warn] parse: %v", err)
				continue
			}
			processRecord(cr)
		}
	}()

	/* ── Swept short-lived flow consumer ───────────────── */
	go func() {
		for tcRec := range loader.sweptCh {
			cr := tcRecordToCorrRecord(tcRec)
			processRecord(cr)
		}
	}()

	if csvPath != "" {
		fmt.Printf("eBPF-CLA running on %s | csv=%s label=%s (Ctrl+C to stop)\n", iface, csvPath, label)
	} else {
		fmt.Printf("eBPF-CLA running on %s (Ctrl+C to stop)\n", iface)
	}
	<-stop
	fmt.Println()
	log.Printf("[done] total_events=%d alerts=%d", total, alerts)
}

func parseArgs() (iface, csvPath, label string) {
	iface = "eth0"
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--csv":
			if i+1 < len(args) {
				i++
				csvPath = args[i]
			}
		case "--label":
			if i+1 < len(args) {
				i++
				label = args[i]
			}
		default:
			if args[i] != "" && args[i][0] != '-' {
				iface = args[i]
			}
		}
	}
	return
}

func layerString(mask uint8) string {
	s := ""
	if mask&0x01 != 0 { s += "X" } else { s += "." }
	if mask&0x02 != 0 { s += "T" } else { s += "." }
	if mask&0x04 != 0 { s += "S" } else { s += "." }
	if mask&0x08 != 0 { s += "U" } else { s += "." }
	return s
}
