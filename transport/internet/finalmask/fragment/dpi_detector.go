package fragment

import (
	"math"
	"time"
)

// DPIDetector analyzes outgoing traffic patterns to detect signs of active
// DPI probing. When ТСПУ (or similar DPI) is actively analyzing a connection,
// it creates observable anomalies:
//
//   1. Unusual response timing patterns (DPI adds processing latency)
//   2. Packet loss/retransmission bursts (DPI injects RSTs or drops packets)
//   3. Entropy anomalies in ACK patterns
//
// The detector uses lightweight statistical analysis (no neural network needed)
// to flag connections that are likely being probed.
type DPIDetector struct {
	sensitivity float64 // 0.0 (never trigger) to 1.0 (very sensitive)
}

// NewDPIDetector creates a detector with the given sensitivity.
func NewDPIDetector(sensitivity float64) *DPIDetector {
	if sensitivity <= 0 {
		sensitivity = 0.5
	}
	if sensitivity > 1 {
		sensitivity = 1.0
	}
	return &DPIDetector{sensitivity: sensitivity}
}

// IsCompromised analyzes recent write patterns and returns true if DPI
// activity is suspected. It looks for:
//   - Abnormal inter-arrival time variance (DPI adds variable delay)
//   - Sudden changes in packet size distribution (DPI modifying/injecting)
//   - Periodic patterns in timing that don't match our mimicry profile
func (d *DPIDetector) IsCompromised(sizes []int, times []time.Time) bool {
	if len(sizes) < 16 || len(times) < 16 {
		return false
	}

	// Analyze the last 64 samples (or fewer if not available)
	n := len(sizes)
	if n > 64 {
		sizes = sizes[n-64:]
		times = times[n-64:]
		n = 64
	}

	score := 0.0

	// Test 1: Inter-arrival time coefficient of variation
	// Normal traffic has moderate CV (0.3-1.5). DPI interference creates
	// either very regular timing (CV < 0.1) or extreme variance (CV > 3.0)
	score += d.timingAnomalyScore(times)

	// Test 2: Size distribution regularity
	// DPI probes often use fixed-size packets. If we see unusual clustering
	// around sizes not in our profile, it's suspicious.
	score += d.sizeAnomalyScore(sizes)

	// Test 3: Timing periodicity detection via autocorrelation
	// DPI systems often probe at regular intervals, creating detectable periodicity
	score += d.periodicityScore(times)

	// Threshold scales with sensitivity: higher sensitivity = lower threshold
	threshold := 2.5 - d.sensitivity*1.5 // Range: 1.0 (high sens) to 2.5 (low sens)
	return score >= threshold
}

// timingAnomalyScore computes an anomaly score from inter-arrival time statistics.
func (d *DPIDetector) timingAnomalyScore(times []time.Time) float64 {
	if len(times) < 2 {
		return 0
	}

	// Compute inter-arrival times
	intervals := make([]float64, len(times)-1)
	for i := 1; i < len(times); i++ {
		intervals[i-1] = times[i].Sub(times[i-1]).Seconds() * 1000 // ms
	}

	mean, stddev := meanStd(intervals)
	if mean < 0.001 {
		return 0
	}

	cv := stddev / mean // coefficient of variation

	// Score: too regular (cv < 0.1) or too chaotic (cv > 3.0)
	if cv < 0.1 {
		return 1.0 // Suspiciously regular — DPI might be pacing responses
	}
	if cv > 3.0 {
		return 0.8 // Extreme variance — DPI interference
	}

	// Check for sudden timing shifts (split into halves)
	if len(intervals) >= 8 {
		half := len(intervals) / 2
		mean1, _ := meanStd(intervals[:half])
		mean2, _ := meanStd(intervals[half:])
		ratio := mean2 / mean1
		if ratio < 0.001 {
			ratio = 0.001
		}
		if ratio > 3.0 || ratio < 0.33 {
			return 0.7 // Abrupt timing change — possible DPI intervention
		}
	}

	return 0
}

// sizeAnomalyScore detects unusual packet size clustering.
func (d *DPIDetector) sizeAnomalyScore(sizes []int) float64 {
	if len(sizes) < 8 {
		return 0
	}

	// Check if too many packets have exactly the same size
	// (natural traffic has size variety; DPI probes are often fixed-size)
	sizeCount := make(map[int]int)
	for _, s := range sizes {
		// Round to nearest 10 to group similar sizes
		rounded := (s / 10) * 10
		sizeCount[rounded]++
	}

	maxFreq := 0
	for _, count := range sizeCount {
		if count > maxFreq {
			maxFreq = count
		}
	}

	// If >70% of packets cluster at one size, suspicious
	ratio := float64(maxFreq) / float64(len(sizes))
	if ratio > 0.7 {
		return 1.0
	}
	if ratio > 0.5 {
		return 0.5
	}

	return 0
}

// periodicityScore detects regular periodicity in timing via autocorrelation.
func (d *DPIDetector) periodicityScore(times []time.Time) float64 {
	if len(times) < 16 {
		return 0
	}

	// Compute inter-arrival times
	intervals := make([]float64, len(times)-1)
	for i := 1; i < len(times); i++ {
		intervals[i-1] = times[i].Sub(times[i-1]).Seconds() * 1000
	}

	mean, stddev := meanStd(intervals)
	if stddev < 0.001 {
		return 0.5 // Near-zero variance is itself suspicious
	}

	// Compute autocorrelation at lags 1-8
	maxCorr := 0.0
	for lag := 1; lag <= 8 && lag < len(intervals)/2; lag++ {
		corr := autocorrelation(intervals, mean, stddev, lag)
		if math.Abs(corr) > maxCorr {
			maxCorr = math.Abs(corr)
		}
	}

	// High autocorrelation suggests artificial periodicity
	if maxCorr > 0.8 {
		return 1.0 // Strong periodicity — likely DPI probing
	}
	if maxCorr > 0.6 {
		return 0.5
	}

	return 0
}

// ==================== Statistical Utilities ====================

func meanStd(data []float64) (float64, float64) {
	if len(data) == 0 {
		return 0, 0
	}
	sum := 0.0
	for _, v := range data {
		sum += v
	}
	mean := sum / float64(len(data))

	varSum := 0.0
	for _, v := range data {
		diff := v - mean
		varSum += diff * diff
	}
	stddev := math.Sqrt(varSum / float64(len(data)))
	return mean, stddev
}

func autocorrelation(data []float64, mean, stddev float64, lag int) float64 {
	if stddev < 1e-10 || lag >= len(data) {
		return 0
	}
	n := len(data) - lag
	sum := 0.0
	for i := 0; i < n; i++ {
		sum += (data[i] - mean) * (data[i+lag] - mean)
	}
	return sum / (float64(n) * stddev * stddev)
}
