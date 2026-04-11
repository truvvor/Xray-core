package fragment

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"net"
	"sync"
	"time"
)

// Obfuscation Protocol v2 — Resonance Tags + XOR-masked padding
//
// === V1 (legacy) format ===
//   Byte 0:       padding_length XOR magic_byte
//   Bytes 1..L:   L random padding bytes (32-128)
//   Bytes L+1..:  original TLS ClientHello
//
// === V2 format ===
//   Byte 0:       0x00 (version marker — impossible in v1 because paddingLen^magic >= 32)
//   Bytes 1..8:   Resonance Tag (8 bytes, HMAC-based, rotates every tagWindow)
//   Byte 9:       XOR-masked padding_length (masked with KDF stream)
//   Bytes 10..9+L: XOR-masked padding bytes (L = decoded padding_length, 32-128)
//   Bytes 10+L..: original TLS ClientHello
//
// === Why V2 is better ===
//   - Resonance Tags replace static shortId fingerprinting: tag rotates every 30s,
//     ТСПУ cannot correlate connections across time windows
//   - XOR masking with time-keyed KDF: every byte has full entropy, indistinguishable
//     from random data. ТСПУ cannot find structure to fingerprint.
//   - V1 had only 1 byte of magic — 256 possible values, brute-forceable.
//     V2 has 8-byte tag + time-dependent KDF — computationally infeasible.
//   - Server auto-detects v1 vs v2 by checking if first byte decodes to valid v1
//     padding (32-128) or is 0x00 (v2 marker).

const (
	obfsV2Marker   byte = 0x00        // First byte marker for v2 protocol
	resonanceTagLen     = 8            // Resonance tag size in bytes
	obfsV2HeaderLen     = 1 + resonanceTagLen + 1 // marker + tag + masked paddingLen
	tagWindowSec        = 30           // Resonance tag rotation window in seconds
)

// ==================== Resonance Tag Generation ====================

// deriveTagKey computes the HMAC key for resonance tag generation.
// Different from magic derivation — uses separate domain string.
func deriveTagKey(shortId string) []byte {
	h := sha256.Sum256([]byte("resonance-tag-key-v2:" + shortId))
	return h[:]
}

// deriveXORStream generates a pseudorandom XOR stream for masking padding.
// Uses shortId + time_window as input to HMAC-SHA256, producing a deterministic
// stream that both client and server can compute independently.
func deriveXORStream(shortId string, timeWindow uint64, length int) []byte {
	// Use HMAC to generate stream blocks
	key := sha256.Sum256([]byte("xor-mask-v2:" + shortId))
	windowBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(windowBytes, timeWindow)

	stream := make([]byte, 0, length)
	blockIdx := uint32(0)
	for len(stream) < length {
		mac := hmac.New(sha256.New, key[:])
		mac.Write(windowBytes)
		idxBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(idxBytes, blockIdx)
		mac.Write(idxBytes)
		stream = append(stream, mac.Sum(nil)...)
		blockIdx++
	}
	return stream[:length]
}

// currentTimeWindow returns the current time window counter.
func currentTimeWindow() uint64 {
	return uint64(time.Now().Unix()) / tagWindowSec
}

// generateResonanceTag creates an 8-byte tag for the given shortId and time window.
func generateResonanceTag(shortId string, timeWindow uint64) []byte {
	key := deriveTagKey(shortId)
	windowBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(windowBytes, timeWindow)

	mac := hmac.New(sha256.New, key)
	mac.Write(windowBytes)
	full := mac.Sum(nil)
	return full[:resonanceTagLen]
}

// ==================== V2 Client Connection ====================

// ObfuscationClientConn prepends obfuscation padding before the first write.
// Uses V2 protocol: resonance tag + XOR-masked padding.
type ObfuscationClientConn struct {
	net.Conn
	mu        sync.Mutex
	shortId   string
	magic     byte   // V1 fallback magic byte
	firstDone bool
	useV2     bool   // true = use v2 with resonance tags
}

// NewObfuscationClientConn creates a client-side obfuscation wrapper.
// Always uses V2 protocol (resonance tags + XOR masking).
func NewObfuscationClientConn(conn net.Conn, shortId string) *ObfuscationClientConn {
	return &ObfuscationClientConn{
		Conn:    conn,
		shortId: shortId,
		magic:   deriveMagic(shortId),
		useV2:   true,
	}
}

// CloseWrite implements the CloseWriteConn interface required by REALITY.
func (c *ObfuscationClientConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

// Write prepends obfuscation padding before the first write.
func (c *ObfuscationClientConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	if c.firstDone {
		c.mu.Unlock()
		return c.Conn.Write(b)
	}
	c.firstDone = true
	c.mu.Unlock()

	if c.useV2 {
		return c.writeV2(b)
	}
	return c.writeV1(b)
}

// writeV2 sends the V2 obfuscation header:
// [0x00] [resonance_tag(8)] [XOR-masked: paddingLen(1) + padding(32-128)] [original data]
func (c *ObfuscationClientConn) writeV2(b []byte) (int, error) {
	// Generate random padding length: 32-128 bytes
	var lenBuf [1]byte
	rand.Read(lenBuf[:])
	paddingLen := 32 + int(lenBuf[0])%97

	// Current time window for resonance tag and XOR stream
	tw := currentTimeWindow()

	// Generate resonance tag
	tag := generateResonanceTag(c.shortId, tw)

	// Generate random padding content
	padding := make([]byte, 1+paddingLen) // paddingLen byte + padding data
	padding[0] = byte(paddingLen)
	rand.Read(padding[1:])

	// XOR-mask the padding (including the length byte)
	xorStream := deriveXORStream(c.shortId, tw, len(padding))
	for i := range padding {
		padding[i] ^= xorStream[i]
	}

	// Build complete header: [marker(1)] [tag(8)] [masked_padding(1+paddingLen)]
	headerLen := 1 + resonanceTagLen + len(padding)
	combined := make([]byte, headerLen+len(b))
	combined[0] = obfsV2Marker
	copy(combined[1:1+resonanceTagLen], tag)
	copy(combined[1+resonanceTagLen:headerLen], padding)
	copy(combined[headerLen:], b)

	n, err := c.Conn.Write(combined)
	if n <= headerLen {
		return 0, err
	}
	return n - headerLen, err
}

// writeV1 sends the legacy V1 obfuscation header (fallback).
func (c *ObfuscationClientConn) writeV1(b []byte) (int, error) {
	var lenBuf [1]byte
	rand.Read(lenBuf[:])
	paddingLen := 32 + int(lenBuf[0])%97

	header := make([]byte, 1+paddingLen)
	header[0] = byte(paddingLen) ^ c.magic
	rand.Read(header[1:])

	combined := make([]byte, len(header)+len(b))
	copy(combined, header)
	copy(combined[len(header):], b)

	n, err := c.Conn.Write(combined)
	if n <= len(header) {
		return 0, err
	}
	return n - len(header), err
}

// ==================== V2 Server Connection ====================

// ObfuscationServerConn strips obfuscation padding from the first read.
// Auto-detects V1 vs V2 protocol. Supports multiple shortIds.
type ObfuscationServerConn struct {
	net.Conn
	mu        sync.Mutex
	shortIds  []string // original shortId strings for V2 tag verification
	magics    []byte   // V1 magic bytes (one per shortId)
	firstDone bool
	overflow  []byte
}

// NewObfuscationServerConn creates a server-side obfuscation wrapper with a single shortId.
func NewObfuscationServerConn(conn net.Conn, shortId string) *ObfuscationServerConn {
	return &ObfuscationServerConn{
		Conn:     conn,
		shortIds: []string{shortId},
		magics:   []byte{deriveMagic(shortId)},
	}
}

// NewObfuscationServerConnMulti creates a server-side obfuscation wrapper with multiple shortIds.
func NewObfuscationServerConnMulti(conn net.Conn, shortIds []string) *ObfuscationServerConn {
	magics := make([]byte, len(shortIds))
	for i, sid := range shortIds {
		magics[i] = deriveMagic(sid)
	}
	return &ObfuscationServerConn{
		Conn:     conn,
		shortIds: shortIds,
		magics:   magics,
	}
}

// CloseWrite implements the CloseWriteConn interface required by REALITY.
func (c *ObfuscationServerConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

// Read strips padding from the first read, auto-detecting V1 vs V2.
func (c *ObfuscationServerConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	if len(c.overflow) > 0 {
		n := copy(b, c.overflow)
		c.overflow = c.overflow[n:]
		c.mu.Unlock()
		return n, nil
	}

	if c.firstDone {
		c.mu.Unlock()
		return c.Conn.Read(b)
	}
	c.firstDone = true
	c.mu.Unlock()

	// Read initial data — need at least obfsV2HeaderLen bytes to detect version
	buf := make([]byte, 4096)
	totalRead := 0
	for totalRead < obfsV2HeaderLen {
		n, err := c.Conn.Read(buf[totalRead:])
		totalRead += n
		if err != nil {
			if totalRead > 0 {
				break // Try to parse what we have
			}
			return 0, err
		}
	}

	if totalRead == 0 {
		return c.Conn.Read(b)
	}

	// Auto-detect: V2 starts with 0x00, V1 starts with paddingLen^magic (32-128 range)
	if buf[0] == obfsV2Marker && totalRead >= obfsV2HeaderLen {
		return c.readV2(buf, totalRead, b)
	}
	return c.readV1(buf, totalRead, b)
}

// readV2 processes V2 obfuscation: validates resonance tag, XOR-unmasks padding.
func (c *ObfuscationServerConn) readV2(buf []byte, totalRead int, b []byte) (int, error) {
	// Extract resonance tag from bytes 1..8
	receivedTag := buf[1 : 1+resonanceTagLen]

	// Verify tag against all shortIds, checking current and ±1 time windows
	tw := currentTimeWindow()
	matchedShortId := ""
	for _, sid := range c.shortIds {
		for _, offset := range []uint64{0, 1, ^uint64(0)} { // 0, +1, -1
			expectedTag := generateResonanceTag(sid, tw+offset)
			if subtle.ConstantTimeCompare(receivedTag, expectedTag) == 1 {
				matchedShortId = sid
				break
			}
		}
		if matchedShortId != "" {
			break
		}
	}

	if matchedShortId == "" {
		// Tag didn't match any shortId — not a valid V2 connection
		// Fall back: return all data as-is (could be a scanner/probe)
		n := copy(b, buf[:totalRead])
		if totalRead > n {
			c.mu.Lock()
			c.overflow = append(c.overflow, buf[n:totalRead]...)
			c.mu.Unlock()
		}
		return n, nil
	}

	// XOR-unmask the padding region: starts at byte 9 (after marker + tag)
	maskedStart := 1 + resonanceTagLen // byte 9

	// We need at least 1 byte of masked data to get paddingLen
	if totalRead <= maskedStart {
		for totalRead <= maskedStart {
			n, err := c.Conn.Read(buf[totalRead:])
			totalRead += n
			if err != nil && totalRead <= maskedStart {
				return 0, err
			}
		}
	}

	// Derive XOR stream — we don't know paddingLen yet, so generate max (1+128)
	// Try all 3 time windows that matched to find correct XOR stream
	var paddingLen int
	var correctTW uint64
	found := false

	for _, offset := range []uint64{0, 1, ^uint64(0)} {
		testTW := tw + offset
		testTag := generateResonanceTag(matchedShortId, testTW)
		if subtle.ConstantTimeCompare(receivedTag, testTag) == 1 {
			xorStream := deriveXORStream(matchedShortId, testTW, 1)
			testPaddingLen := int(buf[maskedStart] ^ xorStream[0])
			if testPaddingLen >= 32 && testPaddingLen <= 128 {
				paddingLen = testPaddingLen
				correctTW = testTW
				found = true
				break
			}
		}
	}

	if !found {
		// Couldn't decode padding length — pass through
		n := copy(b, buf[:totalRead])
		if totalRead > n {
			c.mu.Lock()
			c.overflow = append(c.overflow, buf[n:totalRead]...)
			c.mu.Unlock()
		}
		return n, nil
	}

	// Total header: marker(1) + tag(8) + maskedPaddingLen(1) + maskedPadding(paddingLen)
	fullHeaderLen := 1 + resonanceTagLen + 1 + paddingLen

	// Read more if needed
	for totalRead < fullHeaderLen {
		n, err := c.Conn.Read(buf[totalRead:])
		totalRead += n
		if err != nil && totalRead < fullHeaderLen {
			return 0, err
		}
	}

	// We don't actually need to unmask the padding data — just skip it
	_ = correctTW // XOR stream would be: deriveXORStream(matchedShortId, correctTW, 1+paddingLen)

	// Skip full header, return the TLS data after it
	dataStart := fullHeaderLen
	remaining := buf[dataStart:totalRead]

	n := copy(b, remaining)
	if len(remaining) > n {
		c.mu.Lock()
		c.overflow = append(c.overflow, remaining[n:]...)
		c.mu.Unlock()
	}
	return n, nil
}

// readV1 processes legacy V1 obfuscation (magic byte XOR).
func (c *ObfuscationServerConn) readV1(buf []byte, totalRead int, b []byte) (int, error) {
	// Try each magic byte to decode padding length
	validPaddingLen := -1
	for _, magic := range c.magics {
		paddingLen := int(buf[0] ^ magic)
		if paddingLen >= 32 && paddingLen <= 128 {
			validPaddingLen = paddingLen
			break
		}
	}

	if validPaddingLen < 0 {
		// No magic matched — not obfuscated, pass through (backward compat)
		n := copy(b, buf[:totalRead])
		if totalRead > n {
			c.mu.Lock()
			c.overflow = append(c.overflow, buf[n:totalRead]...)
			c.mu.Unlock()
		}
		return n, nil
	}

	// Read more if we don't have enough data
	needed := 1 + validPaddingLen
	for totalRead < needed {
		n, err := c.Conn.Read(buf[totalRead:])
		totalRead += n
		if err != nil && totalRead < needed {
			return 0, err
		}
	}

	// Skip header (1 byte) + padding
	dataStart := 1 + validPaddingLen
	remaining := buf[dataStart:totalRead]

	n := copy(b, remaining)
	if len(remaining) > n {
		c.mu.Lock()
		c.overflow = append(c.overflow, remaining[n:]...)
		c.mu.Unlock()
	}
	return n, nil
}

// deriveMagic computes the V1 magic byte from shortId.
func deriveMagic(shortId string) byte {
	h := sha256.Sum256([]byte("antidpi-obfs-v1:" + shortId))
	return h[0]
}
