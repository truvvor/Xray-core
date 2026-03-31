package encryption

import (
	"crypto/rand"
	"net"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/crypto"
)

// HeartbeatConn wraps a connection and sends periodic dummy TLS Application Data
// records during idle periods. This prevents DPI from identifying "sleeping tunnels"
// which behave differently from real browser connections.
type HeartbeatConn struct {
	net.Conn
	ticker   *time.Ticker
	done     chan struct{}
	once     sync.Once
	lastSend time.Time
	mu       sync.Mutex
}

// NewHeartbeatConn creates a connection wrapper that sends noise during idle periods.
// minInterval and maxInterval define the range (in milliseconds) for heartbeat timing.
func NewHeartbeatConn(conn net.Conn, minIntervalMs, maxIntervalMs int64) *HeartbeatConn {
	if minIntervalMs <= 0 {
		minIntervalMs = 5000
	}
	if maxIntervalMs <= 0 {
		maxIntervalMs = 15000
	}
	hc := &HeartbeatConn{
		Conn:     conn,
		done:     make(chan struct{}),
		lastSend: time.Now(),
	}
	interval := time.Duration(crypto.RandBetween(minIntervalMs, maxIntervalMs)) * time.Millisecond
	hc.ticker = time.NewTicker(interval)
	go hc.heartbeatLoop(minIntervalMs, maxIntervalMs)
	return hc
}

func (hc *HeartbeatConn) heartbeatLoop(minMs, maxMs int64) {
	for {
		select {
		case <-hc.ticker.C:
			hc.mu.Lock()
			idle := time.Since(hc.lastSend)
			hc.mu.Unlock()

			// Only send heartbeat if connection has been idle for at least 2 seconds
			if idle < 2*time.Second {
				continue
			}

			// Build a fake TLS 1.3 Application Data record with random payload
			payloadLen := int(crypto.RandBetween(16, 128))
			record := make([]byte, 5+payloadLen)
			record[0] = 0x17 // Application Data
			record[1] = 0x03
			record[2] = 0x03 // TLS 1.2 record version (standard for TLS 1.3)
			record[3] = byte(payloadLen >> 8)
			record[4] = byte(payloadLen)
			rand.Read(record[5:])

			hc.Conn.Write(record) // best-effort, ignore errors

			// Randomize the next interval
			newInterval := time.Duration(crypto.RandBetween(minMs, maxMs)) * time.Millisecond
			hc.ticker.Reset(newInterval)
		case <-hc.done:
			return
		}
	}
}

func (hc *HeartbeatConn) Write(b []byte) (int, error) {
	hc.mu.Lock()
	hc.lastSend = time.Now()
	hc.mu.Unlock()
	return hc.Conn.Write(b)
}

func (hc *HeartbeatConn) Close() error {
	hc.once.Do(func() {
		hc.ticker.Stop()
		close(hc.done)
	})
	return hc.Conn.Close()
}
