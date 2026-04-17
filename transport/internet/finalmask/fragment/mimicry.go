package fragment

import (
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

// ProfileEWS mimics Exchange Web Services (Outlook/ActiveSync) traffic.
// Characteristics: SOAP/XML payloads are typically medium-large with periodic
// sync polling. Bimodal: large SOAP responses ~2-4KB + small keepalive/ping ~100-200B.
// Timing: periodic polling with jitter — gamma distributed ~500ms mean
// with occasional burst syncs.
var ProfileEWS = &MimicryProfile{
	Name: "ews",
	SizeDistribution: SizeDistribution{
		Type:   "bimodal",
		Params: []float64{1400, 200, 0.55, 150, 50}, // 55% full TLS records, 45% small
	},
	TimingDistribution: TimingDistribution{
		Type:   "gamma",
		Params: []float64{1.5, 12.0}, // shape=1.5, scale=12 → mean 18ms, bursty
	},
	HeaderTemplate: nil, // Inside TLS — no visible header
}

// ProfileSMTPSSL mimics SMTP over TLS (port 465) traffic.
// Characteristics: command-response pattern — small commands (~50-200B) followed
// by medium responses (~200-800B), with occasional large DATA transfers.
// Timing: sequential command-response with human-speed gaps (50-300ms).
var ProfileSMTPSSL = &MimicryProfile{
	Name: "smtp_ssl",
	SizeDistribution: SizeDistribution{
		Type: "histogram",
		Params: []float64{
			120, 0.40,  // SMTP commands: EHLO, MAIL FROM, RCPT TO (40%)
			400, 0.30,  // SMTP responses + small body chunks (30%)
			1200, 0.20, // DATA transfer — large email body (20%)
			60, 0.10,   // Keepalive/NOOP (10%)
		},
	},
	TimingDistribution: TimingDistribution{
		Type:   "lognormal",
		Params: []float64{3.5, 1.0}, // median ~33ms, high variance for command gaps
	},
	HeaderTemplate: nil,
}

// ProfileSSH mimics SSH interactive session traffic.
// Characteristics: highly bimodal — tiny keystroke packets (~48-96B with SSH overhead)
// and medium command output bursts (~200-1400B). Timing: irregular human typing
// patterns with long pauses (lognormal, median ~100ms, high variance).
var ProfileSSH = &MimicryProfile{
	Name: "ssh",
	SizeDistribution: SizeDistribution{
		Type:   "bimodal",
		Params: []float64{64, 20, 0.6, 800, 400}, // 60% tiny keystrokes, 40% output bursts
	},
	TimingDistribution: TimingDistribution{
		Type:   "lognormal",
		Params: []float64{4.0, 1.2}, // median ~55ms, high variance (human typing)
	},
	HeaderTemplate: nil,
}

// knownProfiles maps profile names to their definitions.
var knownProfiles = map[string]*MimicryProfile{
	"webrtc_zoom": ProfileWebRTCZoom,
	"quic_h3":     ProfileQUICH3,
	"tls_normal":  ProfileTLSNormal,
	"ews":         ProfileEWS,
	"smtp_ssl":    ProfileSMTPSSL,
	"ssh":         ProfileSSH,
}

// GetMimicryProfile returns a profile by name, or nil if unknown.
func GetMimicryProfile(name string) *MimicryProfile {
	return knownProfiles[name]
}

// mimicryPaddingPool reuses small buffers (1+paddingLen, up to 129 bytes)
// for MimicryObfuscationClientConn.Write obfuscation padding.
// Capped at 256 bytes to cover any clamped paddingLen (32-128) + 1.
var mimicryPaddingPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 256)
		return &b
	},
}

// mimicryHeaderPool reuses small buffers for HeaderTemplate copies (≤8 bytes typical).
var mimicryHeaderPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 16)
		return &b
	},
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
// Returns a pooled slice — caller must return it via mimicryHeaderPool.Put when done.
// Returns (nil, nil) if no template.
func (e *MimicryEngine) HeaderTemplate() ([]byte, *[]byte) {
	if e.profile.HeaderTemplate == nil {
		return nil, nil
	}
	tLen := len(e.profile.HeaderTemplate)
	poolPtr := mimicryHeaderPool.Get().(*[]byte)
	h := *poolPtr
	if cap(h) < tLen {
		h = make([]byte, tLen)
		*poolPtr = h
	}
	h = h[:tLen]
	copy(h, e.profile.HeaderTemplate)
	return h, poolPtr
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

// MimicryConn wraps a TCP connection and applies traffic mimicry patterns
// to ALL writes for the lifetime of the connection. This is critical because
// ТСПУ analyzes ongoing traffic — stopping mimicry after N writes lets DPI
// detect the transition and kill the connection.
type MimicryConn struct {
	net.Conn
	engine   *MimicryEngine
	mu       sync.Mutex
	writeNum int
	shortId  string
}

// NewMimicryConn creates a connection wrapper that applies mimicry timing
// to ALL writes. Writes 1-3 (NFS/ML-KEM handshake) pass through without delay.
// Writes 4+ get mimicry-profiled timing. After write 32, delays are reduced
// to micro-delays (1-3ms) to maintain throughput while still looking like
// real protocol traffic to DPI.
func NewMimicryConn(conn net.Conn, profile *MimicryProfile, cfg *MimicryConfig, shortId string) *MimicryConn {
	engine := NewMimicryEngine(profile, cfg)
	engine.SetSeed(shortId)

	return &MimicryConn{
		Conn:    conn,
		engine:  engine,
		shortId: shortId,
	}
}

// CloseWrite implements the CloseWriteConn interface required by REALITY.
func (c *MimicryConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

// Write applies mimicry timing to ALL writes for the connection lifetime.
//
// Phase 1 (writes 1-3): NFS/ML-KEM handshake — no delay (timing-sensitive).
// Phase 2 (writes 4-32): Full mimicry delays from profile (1-50ms) — this is
//   the critical window where DPI makes its classification decision.
// Phase 3 (writes 33+): Micro-delays (1-3ms) — enough to prevent raw TCP
//   pacing detection while maintaining good throughput. DPI rotation checks
//   happen every 32 writes.
//
// ТСПУ kills connections where mimicry stops abruptly (timing signature change).
// Continuous micro-delays make the entire session look like one protocol flow.
func (c *MimicryConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	c.writeNum++
	num := c.writeNum
	c.mu.Unlock()

	// Record for DPI detection (sample every write in phases 1-2, every 32nd after)
	if num <= 32 || num%32 == 0 {
		c.engine.RecordWrite(len(b))
	}

	// Check DPI rotation periodically
	if num%32 == 0 && c.engine.ShouldRotate() {
		c.engine.RotateProfile()
	}

	// Phase 1: NFS handshake — no delay
	if num <= 3 {
		return c.Conn.Write(b)
	}

	// Phase 2: Full mimicry delays (critical classification window)
	if num <= 32 {
		delay := c.engine.NextDelay()
		if delay > 0 {
			time.Sleep(delay)
		}
		return c.Conn.Write(b)
	}

	// Phase 3: Micro-delays (1-3ms) — maintain protocol appearance
	// Uses a lightweight delay derived from the engine's PRNG, not the full
	// profile distribution, to minimize overhead while preventing raw TCP
	// timing fingerprinting.
	c.engine.mu.Lock()
	r := c.engine.nextFloat()
	c.engine.mu.Unlock()
	microDelay := time.Duration((1.0 + r*2.0) * float64(time.Millisecond)) // 1-3ms
	time.Sleep(microDelay)

	return c.Conn.Write(b)
}

// ==================== Enhanced Obfuscation with Mimicry ====================

// MimicryObfuscationClientConn combines protocol mimicry with V2 obfuscation.
// The first write uses Resonance Tags + XOR masking + mimicry-shaped padding.
type MimicryObfuscationClientConn struct {
	net.Conn
	mu        sync.Mutex
	engine    *MimicryEngine
	shortId   string
	firstDone bool
}

// NewMimicryObfuscationClientConn creates a client conn that uses mimicry
// for the obfuscation padding with V2 protocol (resonance tags + XOR masking).
func NewMimicryObfuscationClientConn(conn net.Conn, shortId string, profile *MimicryProfile, cfg *MimicryConfig) *MimicryObfuscationClientConn {
	engine := NewMimicryEngine(profile, cfg)
	engine.SetSeed(shortId)
	return &MimicryObfuscationClientConn{
		Conn:    conn,
		engine:  engine,
		shortId: shortId,
	}
}

// CloseWrite implements the CloseWriteConn interface required by REALITY.
func (c *MimicryObfuscationClientConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

// Write prepends V2 mimicry-shaped obfuscation before the first write.
// Uses resonance tags + XOR masking. Padding size follows mimicry profile.
// Format: [0x00] [resonance_tag(8)] [XOR-masked: paddingLen(1) + padding(N)] [data]
func (c *MimicryObfuscationClientConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	if c.firstDone {
		c.mu.Unlock()
		return c.Conn.Write(b)
	}
	c.firstDone = true
	c.mu.Unlock()

	// Get mimicry-appropriate padding size, clamped to server-decodable range
	paddingLen := c.engine.NextPaddingSize()
	if paddingLen < 32 {
		paddingLen = 32
	}
	if paddingLen > 128 {
		paddingLen = 128
	}

	tw := currentTimeWindow()

	// Generate resonance tag
	tag := generateResonanceTag(c.shortId, tw)

	// Build padding content with protocol-mimicking data — use pooled buffer
	padSize := 1 + paddingLen
	padPoolPtr := mimicryPaddingPool.Get().(*[]byte)
	paddingBuf := *padPoolPtr
	if cap(paddingBuf) < padSize {
		paddingBuf = make([]byte, padSize)
		*padPoolPtr = paddingBuf
	}
	paddingData := paddingBuf[:padSize]
	paddingData[0] = byte(paddingLen)

	// Fill padding with protocol template + random
	tmpl, tmplPoolPtr := c.engine.HeaderTemplate()
	if tmplPoolPtr != nil {
		defer mimicryHeaderPool.Put(tmplPoolPtr)
	}
	if tmpl != nil && len(tmpl) <= paddingLen {
		copy(paddingData[1:], tmpl)
		rand.Read(paddingData[1+len(tmpl):])
	} else {
		rand.Read(paddingData[1:])
	}

	// XOR-mask the entire padding region
	xorStream := deriveXORStream(c.shortId, tw, len(paddingData))
	for i := range paddingData {
		paddingData[i] ^= xorStream[i]
	}

	// NOTE: No timing delay here — this is pre-REALITY, delay would break
	// the TLS handshake. Mimicry timing is applied post-handshake by MimicryConn.

	// Build: [marker(1)] [tag(8)] [masked_padding(1+paddingLen)] [original_data]
	headerLen := 1 + resonanceTagLen + len(paddingData)
	totalLen := headerLen + len(b)

	// For the combined buffer we write header+padding inline and append data.
	// This is a one-shot per connection (firstDone gate), so allocation pressure
	// is low, but we still avoid it where the buffer fits in the padding pool.
	var combined []byte
	var combinedPoolPtr *[]byte
	if totalLen <= 256 {
		combinedPoolPtr = mimicryPaddingPool.Get().(*[]byte)
		cb := *combinedPoolPtr
		if cap(cb) < totalLen {
			cb = make([]byte, totalLen)
			*combinedPoolPtr = cb
		}
		combined = cb[:totalLen]
	} else {
		combined = make([]byte, totalLen)
	}

	combined[0] = obfsV2Marker
	copy(combined[1:1+resonanceTagLen], tag)
	copy(combined[1+resonanceTagLen:headerLen], paddingData)
	copy(combined[headerLen:], b)

	// Return padding buffer to pool
	mimicryPaddingPool.Put(padPoolPtr)

	n, err := c.Conn.Write(combined)

	// Return combined buffer if pooled
	if combinedPoolPtr != nil {
		mimicryPaddingPool.Put(combinedPoolPtr)
	}

	if n <= headerLen {
		return 0, err
	}
	return n - headerLen, err
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

// Note: Resonance tag generation moved to obfuscation.go (V2 protocol).
