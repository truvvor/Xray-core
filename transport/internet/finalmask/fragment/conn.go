package fragment

import (
	"net"
	"time"

	"github.com/xtls/xray-core/common/crypto"
)

type fragmentConn struct {
	net.Conn
	config *Config
	count  uint64

	server bool
}

func NewConnClient(c *Config, raw net.Conn, server bool) (net.Conn, error) {
	conn := &fragmentConn{
		Conn:   raw,
		config: c,

		server: server,
	}

	return conn, nil
}

func NewConnServer(c *Config, raw net.Conn, server bool) (net.Conn, error) {
	return NewConnClient(c, raw, server)
}

func (c *fragmentConn) TcpMaskConn() {}

func (c *fragmentConn) RawConn() net.Conn {
	return c.Conn
}

func (c *fragmentConn) Splice() bool {
	if c.server {
		return false
	}
	return true
}

func (c *fragmentConn) Write(p []byte) (n int, err error) {
	c.count++

	if c.config.PacketsFrom == 0 && c.config.PacketsTo == 1 {
		// Anti-DPI: extend fragmentation to the first few post-handshake packets too
		// This breaks the "clean handshake then immediate data burst" pattern
		if c.count == 1 && len(p) > 5 && p[0] == 22 {
			return c.fragmentClientHello(p)
		} else if c.count <= 4 && len(p) > 64 {
			// Fragment first 3 data packets after ClientHello with random chunk sizes
			return c.fragmentGeneric(p)
		} else {
			return c.Conn.Write(p)
		}
	}

	if c.config.PacketsFrom != 0 && (c.count < uint64(c.config.PacketsFrom) || c.count > uint64(c.config.PacketsTo)) {
		// Anti-DPI: inject micro-jitter on ALL packets to disrupt timing analysis
		if c.config.DelayMax > 0 && c.count <= 10 {
			jitter := crypto.RandBetween(0, c.config.DelayMax/4)
			if jitter > 0 {
				time.Sleep(time.Duration(jitter) * time.Millisecond)
			}
		}
		return c.Conn.Write(p)
	}
	maxSplit := crypto.RandBetween(c.config.MaxSplitMin, c.config.MaxSplitMax)
	var splitNum int64
	for from := 0; ; {
		to := from + int(crypto.RandBetween(c.config.LengthMin, c.config.LengthMax))
		splitNum++
		if to > len(p) || (maxSplit > 0 && splitNum >= maxSplit) {
			to = len(p)
		}
		n, err := c.Conn.Write(p[from:to])
		from += n
		if err != nil {
			return from, err
		}
		time.Sleep(time.Duration(crypto.RandBetween(c.config.DelayMin, c.config.DelayMax)) * time.Millisecond)
		if from >= len(p) {
			return from, nil
		}
	}
}

// fragmentClientHello implements aggressive anti-ТСПУ ClientHello fragmentation.
//
// Strategy:
// 1. Send a dummy empty TLS record to disrupt DPI state machines
// 2. Find the SNI extension in the ClientHello
// 3. Use micro-fragments (1-2 bytes) specifically around the SNI area
// 4. Use configured fragment sizes for the rest of the handshake data
// 5. Add extra delays around SNI boundaries
//
// This defeats ТСПУ which reassembles TLS records looking for SNI.
// By splitting SNI across many tiny records with delays, the DPI
// either times out or fails to extract the server name.
func (c *fragmentConn) fragmentClientHello(p []byte) (int, error) {
	recordLen := 5 + ((int(p[3]) << 8) | int(p[4]))
	if len(p) < recordLen {
		return c.Conn.Write(p)
	}
	data := p[5:recordLen]

	// Find SNI extension offset for targeted micro-fragmentation
	sniStart, sniEnd := findSNIOffset(data)

	// Step 1: Send dummy empty TLS handshake record to poison DPI parser state.
	// Per RFC 8446 §5.1: "zero-length fragments of Application Data MAY be sent"
	// and implementations MUST handle empty records.
	// This forces DPI to handle an unexpected empty record before the real one.
	dummy := []byte{p[0], p[1], p[2], 0x00, 0x00}
	if _, err := c.Conn.Write(dummy); err != nil {
		return 0, err
	}
	time.Sleep(time.Duration(crypto.RandBetween(c.config.DelayMin, c.config.DelayMax)) * time.Millisecond)

	// Step 2: Fragment ClientHello into multiple TLS records.
	// Each fragment gets its own 5-byte TLS record header (same type + version).
	// Around the SNI area, use tiny 1-2 byte fragments to make SNI extraction
	// impossible without full reassembly with buffering.
	buff := make([]byte, 2048)
	for from := 0; from < len(data); {
		var chunkSize int

		if sniStart >= 0 && from >= sniStart-2 && from < sniEnd+2 {
			// Inside/near SNI area: micro-fragments of 1-2 bytes
			// This splits the server name across many tiny TLS records
			chunkSize = 1 + int(crypto.RandBetween(0, 1))
		} else if sniStart >= 0 && from >= sniStart-10 && from < sniStart {
			// Approaching SNI: smaller fragments to randomize the split point
			chunkSize = int(crypto.RandBetween(2, 5))
		} else {
			// Outside SNI: use configured fragment size for speed
			chunkSize = int(crypto.RandBetween(c.config.LengthMin, c.config.LengthMax))
		}

		to := from + chunkSize
		if to > len(data) {
			to = len(data)
		}

		l := to - from
		if 5+l > len(buff) {
			buff = make([]byte, 5+l)
		}
		// Copy TLS record header: type + version from original
		copy(buff[:3], p)
		// Set new fragment length
		buff[3] = byte(l >> 8)
		buff[4] = byte(l)
		// Copy fragment data
		copy(buff[5:], data[from:to])
		from = to

		if _, err := c.Conn.Write(buff[:5+l]); err != nil {
			return 0, err
		}

		// Add inter-fragment delay
		if from < len(data) {
			delay := crypto.RandBetween(c.config.DelayMin, c.config.DelayMax)
			// Double delay around SNI boundaries to force DPI timeout
			if sniStart >= 0 && from >= sniStart && from <= sniEnd {
				delay = delay + crypto.RandBetween(c.config.DelayMin, c.config.DelayMax)
			}
			time.Sleep(time.Duration(delay) * time.Millisecond)
		}
	}

	// Write any remaining data after the ClientHello record (e.g., ChangeCipherSpec)
	if len(p) > recordLen {
		time.Sleep(time.Duration(crypto.RandBetween(c.config.DelayMin, c.config.DelayMax)) * time.Millisecond)
		if _, err := c.Conn.Write(p[recordLen:]); err != nil {
			return 0, err
		}
	}

	return len(p), nil
}

// findSNIOffset locates the Server Name Indication extension within TLS ClientHello
// handshake data (data starts AFTER the 5-byte TLS record header).
// Returns (start, end) byte offsets of the SNI extension, or (-1, -1) if not found.
func findSNIOffset(data []byte) (int, int) {
	if len(data) < 43 {
		return -1, -1
	}

	// TLS Handshake structure:
	// [0]      handshake type (0x01 = ClientHello)
	// [1:4]    handshake length (3 bytes)
	// [4:6]    client version
	// [6:38]   client random (32 bytes)
	pos := 38

	// Session ID
	if pos >= len(data) {
		return -1, -1
	}
	sessIDLen := int(data[pos])
	pos += 1 + sessIDLen

	// Cipher suites (2-byte length prefix)
	if pos+2 > len(data) {
		return -1, -1
	}
	csLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2 + csLen

	// Compression methods (1-byte length prefix)
	if pos+1 > len(data) {
		return -1, -1
	}
	compLen := int(data[pos])
	pos += 1 + compLen

	// Extensions (2-byte total length prefix)
	if pos+2 > len(data) {
		return -1, -1
	}
	extTotalLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2
	extEnd := pos + extTotalLen
	if extEnd > len(data) {
		extEnd = len(data)
	}

	// Scan through extensions looking for SNI (type 0x0000)
	for pos+4 <= extEnd {
		extType := int(data[pos])<<8 | int(data[pos+1])
		extLen := int(data[pos+2])<<8 | int(data[pos+3])

		if extType == 0 {
			// Found SNI extension
			// Return the full extension range including type+length header
			sniEnd := pos + 4 + extLen
			if sniEnd > len(data) {
				sniEnd = len(data)
			}
			return pos, sniEnd
		}

		pos += 4 + extLen
	}

	return -1, -1
}

// fragmentGeneric splits arbitrary data into random-sized chunks with optional delays.
// Used for post-handshake packets to defeat DPI traffic pattern analysis.
func (c *fragmentConn) fragmentGeneric(p []byte) (int, error) {
	maxSplit := crypto.RandBetween(c.config.MaxSplitMin, c.config.MaxSplitMax)
	if maxSplit <= 0 {
		maxSplit = 3
	}
	var splitNum int64
	for from := 0; ; {
		to := from + int(crypto.RandBetween(c.config.LengthMin, c.config.LengthMax))
		splitNum++
		if to > len(p) || (maxSplit > 0 && splitNum >= maxSplit) {
			to = len(p)
		}
		n, err := c.Conn.Write(p[from:to])
		from += n
		if err != nil {
			return from, err
		}
		if from >= len(p) {
			return from, nil
		}
		if c.config.DelayMax > 0 {
			time.Sleep(time.Duration(crypto.RandBetween(c.config.DelayMin, c.config.DelayMax)) * time.Millisecond)
		}
	}
}
