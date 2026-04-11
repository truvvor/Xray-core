package fragment

import (
	"crypto/rand"
	"crypto/sha256"
	"net"
	"sync"
)

// ObfuscationConn wraps a TCP connection to prepend random padding before the
// first write (client side) or strip padding before the first read (server side).
//
// Protocol:
//   Byte 0:       padding_length XOR magic_byte (derived from shortId)
//   Bytes 1..L:   L random padding bytes (L = decoded padding_length, range 32-128)
//   Bytes L+1..:  original TLS ClientHello (passed to REALITY)
//
// Why this defeats TSPU:
//   - TSPU scans for TLS record header (0x16 0x03 0x01) at the start of TCP stream
//   - With padding, the stream starts with random bytes — no TLS signature
//   - TSPU cannot determine where TLS data begins without knowing the magic byte
//   - The magic byte is derived from the REALITY shortId which TSPU doesn't have
//
// The magic byte derivation:
//   magic = SHA256(shortId)[0]
// Both client and server compute the same magic from the shared shortId config.

// ObfuscationClientConn prepends random padding before the first write.
type ObfuscationClientConn struct {
	net.Conn
	mu        sync.Mutex
	magic     byte   // XOR key for padding length byte
	firstDone bool   // whether first write (with padding) has been sent
}

// NewObfuscationClientConn creates a client-side obfuscation wrapper.
// shortId is the REALITY shortId from config, used to derive the magic byte.
func NewObfuscationClientConn(conn net.Conn, shortId string) *ObfuscationClientConn {
	return &ObfuscationClientConn{
		Conn:  conn,
		magic: deriveMagic(shortId),
	}
}

// CloseWrite implements the CloseWriteConn interface required by REALITY.
func (c *ObfuscationClientConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

// Write prepends random padding before the first write, then passes through.
func (c *ObfuscationClientConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	if c.firstDone {
		c.mu.Unlock()
		return c.Conn.Write(b)
	}
	c.firstDone = true
	c.mu.Unlock()

	// Generate random padding length: 32-128 bytes
	var lenBuf [1]byte
	rand.Read(lenBuf[:])
	paddingLen := 32 + int(lenBuf[0])%97 // 32 to 128

	// Build the obfuscated header + original data
	// [encoded_length(1)] [padding(paddingLen)] [original_data(len(b))]
	header := make([]byte, 1+paddingLen)
	header[0] = byte(paddingLen) ^ c.magic // XOR with magic to hide the length
	rand.Read(header[1:])                   // random padding

	// Write header + original data together to minimize TCP segments
	combined := make([]byte, len(header)+len(b))
	copy(combined, header)
	copy(combined[len(header):], b)

	n, err := c.Conn.Write(combined)
	if n <= len(header) {
		return 0, err
	}
	return n - len(header), err
}

// ObfuscationServerConn strips random padding from the first read.
// Supports multiple shortIds — tries each magic byte to find the valid one.
type ObfuscationServerConn struct {
	net.Conn
	mu        sync.Mutex
	magics    []byte // all possible magic bytes (one per shortId)
	firstDone bool
	overflow  []byte // data remaining after stripping padding from first read
}

// NewObfuscationServerConn creates a server-side obfuscation wrapper with a single shortId.
func NewObfuscationServerConn(conn net.Conn, shortId string) *ObfuscationServerConn {
	return &ObfuscationServerConn{
		Conn:   conn,
		magics: []byte{deriveMagic(shortId)},
	}
}

// NewObfuscationServerConnMulti creates a server-side obfuscation wrapper with multiple shortIds.
func NewObfuscationServerConnMulti(conn net.Conn, shortIds []string) *ObfuscationServerConn {
	magics := make([]byte, len(shortIds))
	for i, sid := range shortIds {
		magics[i] = deriveMagic(sid)
	}
	return &ObfuscationServerConn{
		Conn:   conn,
		magics: magics,
	}
}

// CloseWrite implements the CloseWriteConn interface required by REALITY.
func (c *ObfuscationServerConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

// Read strips padding from the first read, then passes through.
func (c *ObfuscationServerConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	// If we have leftover data from padding stripping, return it first
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

	// Read enough data to get the padding length + padding + some TLS data
	buf := make([]byte, 4096) // Should be enough for padding + ClientHello
	totalRead := 0
	for totalRead < 1 {
		n, err := c.Conn.Read(buf[totalRead:])
		totalRead += n
		if err != nil {
			return 0, err
		}
	}

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
		// No magic matched — this is not an obfuscated connection
		// Fall back: return data as-is (backward compatibility)
		n := copy(b, buf[:totalRead])
		if totalRead > n {
			c.mu.Lock()
			c.overflow = append(c.overflow, buf[n:totalRead]...)
			c.mu.Unlock()
		}
		return n, nil
	}

	// Read more if we don't have enough data yet
	needed := 1 + validPaddingLen // header + padding
	for totalRead < needed {
		n, err := c.Conn.Read(buf[totalRead:])
		totalRead += n
		if err != nil && totalRead < needed {
			return 0, err
		}
	}

	// Skip header (1 byte) + padding (validPaddingLen bytes)
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

// deriveMagic computes the magic byte from the REALITY shortId.
func deriveMagic(shortId string) byte {
	h := sha256.Sum256([]byte("antidpi-obfs-v1:" + shortId))
	return h[0]
}
