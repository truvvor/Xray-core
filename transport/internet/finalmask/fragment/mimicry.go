package fragment

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"math"
	"net"
	"sync"
	"time"
)

// MimicryProfile defines traffic patterns that mimic a real application.
// Each profile specifies packet size distribution and inter-arrival timing
// that matches a known protocol (WebRTC/Zoom, QUIC, etc.) so that DPI
// cannot distinguish VPN traffic from legitimate application traffic.
type MimicryProfile struct {
	Name string

	// Packet size distribution
	SizeDistribution SizeDistribution

	// Inter-arrival time distribution (in milliseconds)
	TimingDistribution TimingDistribution

	// Protocol-specific header template (prepended to obfuscation padding)
	// This makes the first bytes look like the target protocol
	HeaderTemplate []byte

	// Asymmetric: different profiles for upload vs download
	// If nil, same profile used for both directions
	ReverseProfile *MimicryProfile
}

// SizeDistribution models how packet sizes are distributed for a protocol.
type SizeDistribution struct {
	Type   string  // "bimodal", "histogram", "uniform"
	Params []float64
	// For bimodal: [mean1, stddev1, weight1, mean2, stddev2]
	// For histogram: pairs of [size, probability, size, probability, ...]
	// For uniform: [min, max]
}

// TimingDistribution models inter-packet timing for a protocol.
type TimingDistribution struct {
	Type   string  // "lognormal", "exponential", "gamma"
	Params []float64
	// For lognormal: [mu, sigma] — median ~exp(mu) ms
	// For exponential: [lambda] — mean = 1/lambda ms
	// For gamma: [shape, scale] ms
}

// MimicryConfig is parsed from JSON config under realitySettings.mimicry
type MimicryConfig struct {
	Profile      string  `json:"profile"`      // "webrtc_zoom", "quic_h3", "tls_normal"
	AutoRotate   bool    `json:"autoRotate"`   // auto-rotate on DPI detection
	RotateAfter  int64   `json:"rotateAfter"`  // seconds before proactive rotation (0 = disabled)
	Sensitivity  float64 `json:"sensitivity"`  // DPI detection sensitivity (0.0-1.0, default 0.5)
}

// ==================== Built-in Profiles ====================

// ProfileWebRTCZoom mimics Zoom/WebRTC video call traffic.
// Characteristics: bimodal packet sizes (large video frames ~1200 bytes + small
// control/audio packets ~100 bytes), lognormal inter-arrival times ~12ms median.
var ProfileWebRTCZoom = &MimicryProfile{
	Name: "webrtc_zoom",
	SizeDistribution: SizeDistribution{
		Type:   "bimodal",
		Params: []float64{1200, 150, 0.7, 100, 30}, // 70% ~1200±150, 30% ~100±30
	},
	TimingDistribution: TimingDistribution{
		Type:   "lognormal",
		Params: []float64{2.5, 0.5}, // median ~12ms, spread factor 0.5
	},
	// STUN-like binding request header (first 4 bytes of STUN)
	HeaderTemplate: []byte{0x00, 0x01, 0x00, 0x00},
}

// ProfileQUICH3 mimics QUIC/HTTP3 traffic (e.g., Chrome browsing).
// Characteristics: histogram-based sizes covering typical QUIC packet ranges,
// exponential inter-arrival for bursty browsing behavior.
var ProfileQUICH3 = &MimicryProfile{
	Name: "quic_h3",
	SizeDistribution: SizeDistribution{
		Type: "histogram",
		// [size, probability] pairs covering QUIC Initial (1200+), short headers (64-300), data (300-1200)
		Params: []float64{
			1200, 0.35, // QUIC Initial packets (35%)
			200, 0.25,  // Short header ACKs (25%)
			600, 0.25,  // Medium data packets (25%)
			80, 0.15,   // Small control packets (15%)
		},
	},
	TimingDistribution: TimingDistribution{
		Type:   "exponential",
		Params: []float64{0.05}, // mean ~20ms (lambda=0.05)
	},
	// QUIC long header initial byte pattern
	HeaderTemplate: []byte{0xC0, 0x00, 0x00, 0x01},
}

// ProfileTLSNormal mimics normal TLS web browsing (HTTPS).
// More conservative — close to what REALITY already looks like, but with
// realistic timing patterns instead of raw TCP pacing.
var ProfileTLSNormal = &MimicryProfile{
	Name: "tls_normal",
	SizeDistribution: SizeDistribution{
		Type:   "bimodal",
		Params: []float64{1400, 100, 0.6, 200, 80}, // 60% full MTU, 40% small
	},
	TimingDistribution: TimingDistribution{
		Type:   "gamma",
		Params: []float64{2.0, 8.0}, // shape=2, scale=8 → mean 16ms, mode 8ms
	},
	HeaderTemplate: nil, // No special header — REALITY already provides TLS header
}

// knownProfiles maps profile names to their definitions.
var knownProfiles = map[string]*MimicryProfile{
	"webrtc_zoom": ProfileWebRTCZoom,
	"quic_h3":     ProfileQUICH3,
	"tls_normal":  ProfileTLSNormal,
}

// GetMimicryProfile returns a profile by name, or nil if unknown.
func GetMimicryProfile(name string) *MimicryProfile {
	return knownProfiles[name]
}

// ==================== Mimicry Engine ====================

// MimicryEngine generates packet sizes and timing delays according to a profile.
// It uses a seeded PRNG for reproducible behavior (synced via shortId).
type MimicryEngine struct {
	mu      sync.Mutex
	profile *MimicryProfile
	seed    uint64
	state   uint64 // PRNG state

	// DPI detection
	detector    *DPIDetector
	autoRotate  bool
	rotateAfter time.Duration
	startTime   time.Time
	rotated     bool

	// Statistics for DPI detection
	writeSizes  []int
	writeTimes  []time.Time
}

// NewMimicryEngine creates a new engine with the given profile.
func NewMimicryEngine(profile *MimicryProfile, cfg *MimicryConfig) *MimicryEngine {
	sensitivity := 0.5
	rotateAfter := time.Duration(0)
	autoRotate := false

	if cfg != nil {
		if cfg.Sensitivity > 0 {
			sensitivity = cfg.Sensitivity
		}
		if cfg.AutoRotate {
			autoRotate = true
		}
		if cfg.RotateAfter > 0 {
			rotateAfter = time.Duration(cfg.RotateAfter) * time.Second
		}
	}

	return &MimicryEngine{
		profile:     profile,
		state:       14695981039346656037, // FNV offset basis
		detector:    NewDPIDetector(sensitivity),
		autoRotate:  autoRotate,
		rotateAfter: rotateAfter,
		startTime:   time.Now(),
		writeSizes:  make([]int, 0, 128),
		writeTimes:  make([]time.Time, 0, 128),
	}
}

// SetSeed initializes the PRNG from shortId for deterministic behavior.
func (e *MimicryEngine) SetSeed(shortId string) {
	h := sha256.Sum256([]byte("mimicry-seed:" + shortId))
	e.mu.Lock()
	e.seed = binary.BigEndian.Uint64(h[:8])
	e.state = e.seed
	e.mu.Unlock()
}

// nextRand returns the next PRNG value (xorshift64).
func (e *MimicryEngine) nextRand() uint64 {
	e.state ^= e.state << 13
	e.state ^= e.state >> 7
	e.state ^= e.state << 17
	return e.state
}

// nextFloat returns a random float64 in [0, 1).
func (e *MimicryEngine) nextFloat() float64 {
	return float64(e.nextRand()&0x1FFFFFFFFFFFFF) / float64(1<<53)
}

// NextPaddingSize returns the padding size based on the profile's size distribution.
// This replaces the old random 32-128 byte padding with protocol-realistic sizes.
func (e *MimicryEngine) NextPaddingSize() int {
	e.mu.Lock()
	defer e.mu.Unlock()

	dist := e.profile.SizeDistribution
	switch dist.Type {
	case "bimodal":
		return e.sampleBimodal(dist.Params)
	case "histogram":
		return e.sampleHistogram(dist.Params)
	case "uniform":
		min := int(dist.Params[0])
		max := int(dist.Params[1])
		return min + int(e.nextRand())%(max-min+1)
	default:
		return 64 + int(e.nextRand())%64 // fallback
	}
}

// NextDelay returns the inter-packet delay based on the profile's timing distribution.
func (e *MimicryEngine) NextDelay() time.Duration {
	e.mu.Lock()
	defer e.mu.Unlock()

	dist := e.profile.TimingDistribution
	var ms float64
	switch dist.Type {
	case "lognormal":
		ms = e.sampleLognormal(dist.Params[0], dist.Params[1])
	case "exponential":
		lambda := dist.Params[0]
		ms = -math.Log(1-e.nextFloat()) / lambda
	case "gamma":
		ms = e.sampleGamma(dist.Params[0], dist.Params[1])
	default:
		ms = 5 + e.nextFloat()*10 // fallback 5-15ms
	}

	// Clamp to reasonable range: 1ms - 50ms
	if ms < 1 {
		ms = 1
	}
	if ms > 50 {
		ms = 50
	}

	return time.Duration(ms * float64(time.Millisecond))
}

// HeaderTemplate returns the protocol-specific header bytes for the current profile.
func (e *MimicryEngine) HeaderTemplate() []byte {
	if e.profile.HeaderTemplate == nil {
		return nil
	}
	// Copy to avoid mutation
	h := make([]byte, len(e.profile.HeaderTemplate))
	copy(h, e.profile.HeaderTemplate)
	return h
}

// RecordWrite records a write for DPI detection analysis.
func (e *MimicryEngine) RecordWrite(size int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := time.Now()
	e.writeSizes = append(e.writeSizes, size)
	e.writeTimes = append(e.writeTimes, now)

	// Keep only last 128 samples
	if len(e.writeSizes) > 128 {
		e.writeSizes = e.writeSizes[len(e.writeSizes)-128:]
		e.writeTimes = e.writeTimes[len(e.writeTimes)-128:]
	}
}

// ShouldRotate checks if the profile should be rotated.
func (e *MimicryEngine) ShouldRotate() bool {
	if e.rotated {
		return false
	}

	// Proactive rotation after timer
	if e.rotateAfter > 0 && time.Since(e.startTime) > e.rotateAfter {
		return true
	}

	// Auto-rotate on DPI detection
	if e.autoRotate && len(e.writeSizes) >= 16 {
		return e.detector.IsCompromised(e.writeSizes, e.writeTimes)
	}

	return false
}

// RotateProfile switches to a different profile.
func (e *MimicryEngine) RotateProfile() {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.rotated = true
	currentName := e.profile.Name

	// Pick a different profile
	candidates := make([]*MimicryProfile, 0)
	for name, p := range knownProfiles {
		if name != currentName {
			candidates = append(candidates, p)
		}
	}
	if len(candidates) > 0 {
		idx := int(e.nextRand()) % len(candidates)
		e.profile = candidates[idx]
	}

	// Reset statistics
	e.writeSizes = e.writeSizes[:0]
	e.writeTimes = e.writeTimes[:0]
	e.startTime = time.Now()
	e.rotated = false
}

// ==================== Sampling Functions ====================

func (e *MimicryEngine) sampleBimodal(params []float64) int {
	// params: [mean1, std1, weight1, mean2, std2]
	mean1, std1, weight1 := params[0], params[1], params[2]
	mean2, std2 := params[3], params[4]

	r := e.nextFloat()
	var mean, std float64
	if r < weight1 {
		mean, std = mean1, std1
	} else {
		mean, std = mean2, std2
	}

	// Box-Muller transform for normal distribution
	u1, u2 := e.nextFloat(), e.nextFloat()
	if u1 < 1e-10 {
		u1 = 1e-10
	}
	z := math.Sqrt(-2*math.Log(u1)) * math.Cos(2*math.Pi*u2)
	val := mean + std*z

	size := int(val)
	if size < 32 {
		size = 32
	}
	if size > 1400 {
		size = 1400
	}
	return size
}

func (e *MimicryEngine) sampleHistogram(params []float64) int {
	// params: [size1, prob1, size2, prob2, ...]
	r := e.nextFloat()
	cumulative := 0.0
	for i := 0; i+1 < len(params); i += 2 {
		cumulative += params[i+1]
		if r <= cumulative {
			base := int(params[i])
			// Add ±20% jitter
			jitter := int(float64(base) * 0.2 * (e.nextFloat()*2 - 1))
			size := base + jitter
			if size < 32 {
				size = 32
			}
			if size > 1400 {
				size = 1400
			}
			return size
		}
	}
	return 200 // fallback
}

func (e *MimicryEngine) sampleLognormal(mu, sigma float64) float64 {
	// Box-Muller → lognormal
	u1, u2 := e.nextFloat(), e.nextFloat()
	if u1 < 1e-10 {
		u1 = 1e-10
	}
	z := math.Sqrt(-2*math.Log(u1)) * math.Cos(2*math.Pi*u2)
	return math.Exp(mu + sigma*z)
}

func (e *MimicryEngine) sampleGamma(shape, scale float64) float64 {
	// Marsaglia and Tsang's method for shape >= 1
	if shape < 1 {
		// Boost for shape < 1
		u := e.nextFloat()
		return e.sampleGamma(shape+1, scale) * math.Pow(u, 1/shape)
	}

	d := shape - 1.0/3.0
	c := 1.0 / math.Sqrt(9*d)

	for {
		var x, v float64
		for {
			u1, u2 := e.nextFloat(), e.nextFloat()
			if u1 < 1e-10 {
				u1 = 1e-10
			}
			x = math.Sqrt(-2*math.Log(u1)) * math.Cos(2*math.Pi*u2)
			v = 1 + c*x
			if v > 0 {
				break
			}
		}
		v = v * v * v
		u := e.nextFloat()

		if u < 1-0.0331*(x*x)*(x*x) {
			return d * v * scale
		}
		if math.Log(u) < 0.5*x*x+d*(1-v+math.Log(v)) {
			return d * v * scale
		}
	}
}

// ==================== Mimicry Connection Wrapper ====================

// MimicryConn wraps a TCP connection and applies traffic mimicry patterns.
// Replaces both ObfuscationClientConn (padding) and SinusoidalConn (timing).
type MimicryConn struct {
	net.Conn
	engine    *MimicryEngine
	mu        sync.Mutex
	writeNum  int
	maxWrites int // after this, pass-through
	shortId   string
}

// NewMimicryConn creates a connection wrapper that applies mimicry to the first
// N writes. After that, data passes through without modification for full speed.
func NewMimicryConn(conn net.Conn, profile *MimicryProfile, cfg *MimicryConfig, shortId string) *MimicryConn {
	engine := NewMimicryEngine(profile, cfg)
	engine.SetSeed(shortId)

	return &MimicryConn{
		Conn:      conn,
		engine:    engine,
		maxWrites: 15, // mimicry on first 15 writes (handshake + early data)
		shortId:   shortId,
	}
}

// CloseWrite implements the CloseWriteConn interface required by REALITY.
func (c *MimicryConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

// Write applies mimicry timing to first N writes, then pass-through.
func (c *MimicryConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	c.writeNum++
	num := c.writeNum
	c.mu.Unlock()

	// After initial writes, pure pass-through
	if num > c.maxWrites {
		// Periodically check for DPI and rotate if needed
		if num%64 == 0 {
			c.engine.RecordWrite(len(b))
			if c.engine.ShouldRotate() {
				c.engine.RotateProfile()
			}
		}
		return c.Conn.Write(b)
	}

	// Record for DPI detection
	c.engine.RecordWrite(len(b))

	// Apply mimicry timing delay
	delay := c.engine.NextDelay()
	if delay > 0 {
		time.Sleep(delay)
	}

	return c.Conn.Write(b)
}

// ==================== Enhanced Obfuscation with Mimicry ====================

// MimicryObfuscationClientConn combines protocol mimicry with obfuscation padding.
// The first write prepends a protocol-realistic header + mimicry-sized padding
// instead of simple random bytes.
type MimicryObfuscationClientConn struct {
	net.Conn
	mu        sync.Mutex
	engine    *MimicryEngine
	magic     byte
	firstDone bool
}

// NewMimicryObfuscationClientConn creates a client conn that uses mimicry
// for the obfuscation padding (first write before REALITY handshake).
func NewMimicryObfuscationClientConn(conn net.Conn, shortId string, profile *MimicryProfile, cfg *MimicryConfig) *MimicryObfuscationClientConn {
	engine := NewMimicryEngine(profile, cfg)
	engine.SetSeed(shortId)
	return &MimicryObfuscationClientConn{
		Conn:   conn,
		engine: engine,
		magic:  deriveMagic(shortId),
	}
}

// CloseWrite implements the CloseWriteConn interface required by REALITY.
func (c *MimicryObfuscationClientConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

// Write prepends mimicry-shaped padding before the first write.
// Format: [encoded_len(1)] [protocol_header(0-4)] [random_padding(N)] [original_data]
// The padding size follows the mimicry profile's size distribution.
func (c *MimicryObfuscationClientConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	if c.firstDone {
		c.mu.Unlock()
		return c.Conn.Write(b)
	}
	c.firstDone = true
	c.mu.Unlock()

	// Get mimicry-appropriate padding size
	paddingLen := c.engine.NextPaddingSize()
	// Clamp to valid range for server decoding (32-128)
	if paddingLen < 32 {
		paddingLen = 32
	}
	if paddingLen > 128 {
		paddingLen = 128
	}

	// Build header: [encoded_length(1)] [padding(paddingLen)] [original_data]
	header := make([]byte, 1+paddingLen)
	header[0] = byte(paddingLen) ^ c.magic

	// Fill padding with protocol-mimicking content
	tmpl := c.engine.HeaderTemplate()
	if tmpl != nil && len(tmpl) <= paddingLen {
		// Put protocol header template at the start of padding
		copy(header[1:], tmpl)
		// Fill rest with random
		rand.Read(header[1+len(tmpl):])
	} else {
		rand.Read(header[1:])
	}

	// Apply mimicry timing delay for the first packet
	delay := c.engine.NextDelay()
	if delay > 0 {
		time.Sleep(delay)
	}

	// Combine and send
	combined := make([]byte, len(header)+len(b))
	copy(combined, header)
	copy(combined[len(header):], b)

	n, err := c.Conn.Write(combined)
	if n <= len(header) {
		return 0, err
	}
	return n - len(header), err
}

// ==================== Mimicry Registry ====================

var (
	mimicryRegistry     = make(map[string]*MimicryConfig)
	mimicryRegistryLock sync.RWMutex
	mimicryGlobalConfig *MimicryConfig
	mimicryGlobalLock   sync.RWMutex
)

// RegisterMimicry stores a mimicry config for a given shortId.
func RegisterMimicry(shortId string, cfg *MimicryConfig) {
	mimicryRegistryLock.Lock()
	defer mimicryRegistryLock.Unlock()
	mimicryRegistry[shortId] = cfg
}

// GetMimicry retrieves the mimicry config for a given shortId.
func GetMimicry(shortId string) *MimicryConfig {
	mimicryRegistryLock.RLock()
	defer mimicryRegistryLock.RUnlock()
	return mimicryRegistry[shortId]
}

// SetGlobalMimicry sets a global mimicry config (server side).
func SetGlobalMimicry(cfg *MimicryConfig) {
	mimicryGlobalLock.Lock()
	defer mimicryGlobalLock.Unlock()
	mimicryGlobalConfig = cfg
}

// GetGlobalMimicry returns the global mimicry config.
func GetGlobalMimicry() *MimicryConfig {
	mimicryGlobalLock.RLock()
	defer mimicryGlobalLock.RUnlock()
	return mimicryGlobalConfig
}

// ==================== HMAC-based Resonance Tags ====================

// GenerateResonanceTag creates an 8-byte session tag that rotates every tagWindow.
// Both client and server generate the same tag because they share the shortId.
// This replaces plaintext shortId exposure in the padding.
func GenerateResonanceTag(shortId string, tagWindow time.Duration) []byte {
	if tagWindow <= 0 {
		tagWindow = 10 * time.Second
	}
	counter := uint64(time.Now().Unix()) / uint64(tagWindow.Seconds())
	counterBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(counterBytes, counter)

	key := sha256.Sum256([]byte("resonance-tag:" + shortId))
	mac := hmac.New(sha256.New, key[:])
	mac.Write(counterBytes)
	tag := mac.Sum(nil)
	return tag[:8]
}
