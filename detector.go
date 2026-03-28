package main

import (
	"math"
	"sync"
)

// FeatureVector — 9 features extracted from CorrRecord.
type FeatureVector struct {
	PktCount      float64
	ByteCount     float64
	SYNCount      float64
	RSTCount      float64
	SYNRatio      float64 // SYN / total pkts
	Duration      float64 // nanoseconds
	PktRate       float64 // pkts/sec
	LayerCoverage float64 // number of layers observed
	ConnectRate   float64 // connect() syscall count
}

const NumFeatures = 9
const AnomalyThreshold = 4.0

// OnlineStats tracks mean + variance incrementally (Welford's algorithm).
type OnlineStats struct {
	mu   sync.Mutex
	n    float64
	mean [NumFeatures]float64
	M2   [NumFeatures]float64
}

func (s *OnlineStats) Update(f FeatureVector) {
	v := f.asSlice()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.n++
	for i, x := range v {
		delta := x - s.mean[i]
		s.mean[i] += delta / s.n
		s.M2[i] += delta * (x - s.mean[i])
	}
}

func (s *OnlineStats) stdDev(i int) float64 {
	if s.n < 2 {
		return 1.0
	}
	return math.Sqrt(s.M2[i] / (s.n - 1))
}

// AnomalyScore returns Euclidean z-score distance. >threshold = anomaly.
// Returns 0 during warmup (n<50) to suppress cold-start false positives.
func (s *OnlineStats) AnomalyScore(f FeatureVector) float64 {
	v := f.asSlice()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.n < 50 {
		return 0
	}
	var score float64
	for i, x := range v {
		sd := s.stdDev(i)
		if sd < 1e-9 {
			continue
		}
		z := math.Abs(x-s.mean[i]) / sd
		score += z * z
	}
	return math.Sqrt(score)
}

func (f FeatureVector) asSlice() [NumFeatures]float64 {
	return [NumFeatures]float64{
		f.PktCount, f.ByteCount, f.SYNCount,
		f.RSTCount, f.SYNRatio, f.Duration,
		f.PktRate, f.LayerCoverage, f.ConnectRate,
	}
}
