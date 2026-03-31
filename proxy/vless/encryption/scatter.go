package encryption

import (
	"net"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/crypto"
)

// ScatterConn breaks TLS record-to-TCP segment alignment by splitting writes
// into random-sized chunks. DPI systems commonly assume that TLS records are
// perfectly aligned with TCP segments; scattering destroys that assumption.
//
// It wraps the underlying transport connection (below CommonConn), so the
// encrypted TLS records produced by CommonConn are scattered across multiple
// TCP segments before hitting the wire.
type ScatterConn struct {
	net.Conn
	mu          sync.Mutex
	writeCount  int
	maxScatter  int // scatter first N writes (0 = all)
	minChunk    int // minimum fragment size in bytes
	maxChunk    int // maximum fragment size in bytes
	maxJitterMs int64
}

// NewScatterConn wraps a connection to scatter TLS records across TCP segments.
// Only the first `maxScatter` writes are scattered (0 = scatter all).
// Chunk sizes are randomized between minChunk and maxChunk bytes.
func NewScatterConn(conn net.Conn, minChunk, maxChunk, maxScatter int, maxJitterMs int64) *ScatterConn {
	if minChunk <= 0 {
		minChunk = 64
	}
	if maxChunk <= minChunk {
		maxChunk = minChunk + 256
	}
	return &ScatterConn{
		Conn:        conn,
		minChunk:    minChunk,
		maxChunk:    maxChunk,
		maxScatter:  maxScatter,
		maxJitterMs: maxJitterMs,
	}
}

func (sc *ScatterConn) Write(b []byte) (int, error) {
	sc.mu.Lock()
	sc.writeCount++
	count := sc.writeCount
	sc.mu.Unlock()

	// After maxScatter writes, pass through without scattering
	if sc.maxScatter > 0 && count > sc.maxScatter {
		return sc.Conn.Write(b)
	}

	// Small writes (< 2x minChunk) are not worth splitting
	if len(b) < sc.minChunk*2 {
		return sc.Conn.Write(b)
	}

	total := 0
	for len(b) > 0 {
		chunkSize := int(crypto.RandBetween(int64(sc.minChunk), int64(sc.maxChunk)))
		if chunkSize >= len(b) {
			// Last chunk: send the remainder
			n, err := sc.Conn.Write(b)
			total += n
			return total, err
		}

		n, err := sc.Conn.Write(b[:chunkSize])
		total += n
		if err != nil {
			return total, err
		}
		b = b[chunkSize:]

		// Optional micro-jitter between chunks (0-maxJitter ms)
		if sc.maxJitterMs > 0 {
			jitter := crypto.RandBetween(0, sc.maxJitterMs)
			if jitter > 0 {
				time.Sleep(time.Duration(jitter) * time.Millisecond)
			}
		}
	}
	return total, nil
}
