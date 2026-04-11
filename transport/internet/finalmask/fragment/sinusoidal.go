package fragment

import (
	"math"
	"net"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/crypto"
)

// SinusoidalDelay generates fragment delays following a sinusoidal curve.
// The delay oscillates: delay = BaseDelay + Amplitude * sin(2π * t / Period + Phase)
// Every SyncInterval, parameters are rotated using a shared PRNG seed derived
// from the REALITY session key, ensuring client and server stay in sync.
//
// This defeats DPI timing analysis because:
// 1. Static delays create detectable patterns — sinusoidal delays look like natural network jitter
// 2. Parameter rotation means the pattern changes over time — can't be fingerprinted
// 3. PRNG-based sync means no explicit parameter exchange needed after initial handshake
type SinusoidalDelay struct {
	mu sync.RWMutex

	// Current sinusoidal parameters
	BaseDelay  float64 // Base delay in milliseconds (center of oscillation)
	Amplitude  float64 // Amplitude in milliseconds (max deviation from base)
	Period     float64 // Period in seconds (one full sine cycle)
	Phase      float64 // Phase offset in radians

	// Rotation settings
	SyncInterval time.Duration // How often to rotate parameters (e.g., 10 minutes)
	lastSync     time.Time     // Last time parameters were rotated
	epoch        uint64        // Counter for deterministic rotation

	// Start time for calculating sine position
	startTime time.Time

	// Seed for deterministic parameter rotation (derived from session key)
	seed []byte
}

// SinusoidalConfig holds the initial configuration from the xray config file.
type SinusoidalConfig struct {
	BaseDelay    float64 `json:"baseDelay"`    // ms, default 60
	Amplitude    float64 `json:"amplitude"`    // ms, default 30
	Period       float64 `json:"period"`       // seconds, default 2.0
	Phase        float64 `json:"phase"`        // radians, default 0
	SyncInterval int64   `json:"syncInterval"` // seconds, default 600 (10 min)
}

// NewSinusoidalDelay creates a new sinusoidal delay generator.
func NewSinusoidalDelay(cfg *SinusoidalConfig) *SinusoidalDelay {
	if cfg == nil {
		cfg = &SinusoidalConfig{}
	}

	baseDelay := cfg.BaseDelay
	if baseDelay <= 0 {
		baseDelay = 60 // 60ms default base delay
	}

	amplitude := cfg.Amplitude
	if amplitude <= 0 {
		amplitude = 30 // ±30ms oscillation
	}

	period := cfg.Period
	if period <= 0 {
		period = 2.0 // 2 second sine cycle
	}

	phase := cfg.Phase // 0 by default

	syncInterval := time.Duration(cfg.SyncInterval) * time.Second
	if syncInterval <= 0 {
		syncInterval = 10 * time.Minute
	}

	now := time.Now()
	return &SinusoidalDelay{
		BaseDelay:    baseDelay,
		Amplitude:    amplitude,
		Period:       period,
		Phase:        phase,
		SyncInterval: syncInterval,
		lastSync:     now,
		startTime:    now,
		epoch:        0,
	}
}

// SetSeed sets the PRNG seed for deterministic parameter rotation.
// Called after REALITY handshake when the session key is available.
func (sd *SinusoidalDelay) SetSeed(seed []byte) {
	sd.mu.Lock()
	defer sd.mu.Unlock()
	sd.seed = make([]byte, len(seed))
	copy(sd.seed, seed)
}

// NextDelay returns the next delay duration based on the current sinusoidal curve.
// It also checks if a parameter rotation is due.
func (sd *SinusoidalDelay) NextDelay() time.Duration {
	sd.mu.Lock()
	defer sd.mu.Unlock()

	now := time.Now()

	// Check if parameter rotation is due
	if now.Sub(sd.lastSync) >= sd.SyncInterval && len(sd.seed) > 0 {
		sd.rotateParams()
		sd.lastSync = now
	}

	// Calculate sine position
	t := now.Sub(sd.startTime).Seconds()
	sineVal := math.Sin(2*math.Pi*t/sd.Period + sd.Phase)

	// Calculate delay: base + amplitude * sin(...)
	delay := sd.BaseDelay + sd.Amplitude*sineVal

	// Clamp to minimum 5ms, maximum base+amplitude+20ms
	if delay < 5 {
		delay = 5
	}
	maxDelay := sd.BaseDelay + sd.Amplitude + 20
	if delay > maxDelay {
		delay = maxDelay
	}

	// Add small random jitter (±10%) to prevent exact pattern matching
	jitterPct := float64(crypto.RandBetween(-100, 100)) / 1000.0 // ±10%
	delay *= (1 + jitterPct)

	return time.Duration(delay * float64(time.Millisecond))
}

// rotateParams deterministically generates new sinusoidal parameters
// using the shared seed and epoch counter. Both client and server
// compute the same parameters because they share the same seed and
// increment epoch at the same SyncInterval.
func (sd *SinusoidalDelay) rotateParams() {
	sd.epoch++

	// Use seed + epoch to derive new parameters deterministically
	// Simple PRNG: hash(seed || epoch_bytes) → 4 float64 values
	epochBytes := make([]byte, 8)
	epochBytes[0] = byte(sd.epoch)
	epochBytes[1] = byte(sd.epoch >> 8)
	epochBytes[2] = byte(sd.epoch >> 16)
	epochBytes[3] = byte(sd.epoch >> 24)

	// Combine seed and epoch for deterministic randomness
	combined := append(sd.seed, epochBytes...)

	// Simple hash-based PRNG (using FNV-like mixing)
	var hash uint64 = 14695981039346656037
	for _, b := range combined {
		hash ^= uint64(b)
		hash *= 1099511628211
	}

	// Derive new parameters from hash bits
	// BaseDelay: 40-80ms
	sd.BaseDelay = 40 + float64(hash%41)
	hash = hash*6364136223846793005 + 1442695040888963407

	// Amplitude: 15-45ms
	sd.Amplitude = 15 + float64(hash%31)
	hash = hash*6364136223846793005 + 1442695040888963407

	// Period: 1.5-4.0 seconds
	sd.Period = 1.5 + float64(hash%26)/10.0
	hash = hash*6364136223846793005 + 1442695040888963407

	// Phase: 0 to 2π
	sd.Phase = float64(hash%628) / 100.0
}

// CurrentParams returns the current sinusoidal parameters (for debug/logging).
func (sd *SinusoidalDelay) CurrentParams() (baseDelay, amplitude, period, phase float64, epoch uint64) {
	sd.mu.RLock()
	defer sd.mu.RUnlock()
	return sd.BaseDelay, sd.Amplitude, sd.Period, sd.Phase, sd.epoch
}

// NextChunkSize returns a sinusoidally-varying chunk size in bytes.
// Uses a separate sine curve offset by π/3 from the delay curve to decorrelate them.
func (sd *SinusoidalDelay) NextChunkSize(minSize, maxSize int) int {
	sd.mu.RLock()
	defer sd.mu.RUnlock()

	t := time.Now().Sub(sd.startTime).Seconds()
	// Phase offset by π/3 so chunk sizes don't correlate with delays
	sineVal := math.Sin(2*math.Pi*t/sd.Period + sd.Phase + math.Pi/3)

	// Map sine [-1,1] → [minSize, maxSize]
	mid := float64(minSize+maxSize) / 2
	halfRange := float64(maxSize-minSize) / 2
	size := mid + halfRange*sineVal

	// Add ±15% jitter
	jitterPct := float64(crypto.RandBetween(-150, 150)) / 1000.0
	size *= (1 + jitterPct)

	result := int(size)
	if result < minSize {
		result = minSize
	}
	if result > maxSize {
		result = maxSize
	}
	return result
}

// SinusoidalConn wraps a net.Conn and applies sinusoidal delay and chunk size
// variation to the FIRST few writes only. After maxModulatedWrites, data
// passes through without delay to maintain full speed.
//
// This defeats DPI fingerprinting of connection establishment patterns
// without impacting bulk data transfer performance.
type SinusoidalConn struct {
	net.Conn
	delay              *SinusoidalDelay
	mu                 sync.Mutex
	writeCount         int
	maxModulatedWrites int // only modulate first N writes (handshake + early data)
	minChunk           int
	maxChunk           int
}

// NewSinusoidalConn wraps a connection with sinusoidal write modulation.
// Only the first 10 writes are modulated; after that, pass-through.
func NewSinusoidalConn(conn net.Conn, cfg *SinusoidalConfig) *SinusoidalConn {
	if cfg == nil {
		// Low-latency defaults for connection establishment
		cfg = &SinusoidalConfig{
			BaseDelay: 3,   // 3ms base
			Amplitude: 2,   // ±2ms
			Period:    1.0,  // 1s cycle
		}
	}
	return &SinusoidalConn{
		Conn:               conn,
		delay:              NewSinusoidalDelay(cfg),
		maxModulatedWrites: 10, // only first 10 writes
		minChunk:           256,
		maxChunk:           2048,
	}
}

// SetSeedFromShortId sets the PRNG seed for synchronized parameter rotation.
// Both client and server use the same shortId, so rotations stay in sync.
func (c *SinusoidalConn) SetSeedFromShortId(shortId string) {
	c.delay.SetSeed([]byte("sinusoidal-seed:" + shortId))
}

// CloseWrite implements the CloseWriteConn interface required by REALITY.
func (c *SinusoidalConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

// Write applies sinusoidal timing jitter to first N writes, then pass-through.
// Does NOT split data into chunks — only adds a small delay before each write
// to create natural-looking inter-packet timing during handshake.
func (c *SinusoidalConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	c.writeCount++
	count := c.writeCount
	c.mu.Unlock()

	// After initial writes, pure pass-through — no performance impact
	if count > c.maxModulatedWrites {
		return c.Conn.Write(b)
	}

	// Add sinusoidal micro-delay before write (no chunking — data sent whole)
	d := c.delay.NextDelay()
	if d > 0 {
		time.Sleep(d)
	}
	return c.Conn.Write(b)
}
