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
			// Original ClientHello fragmentation path — fall through below
		} else if c.count <= 4 && len(p) > 64 {
			// Fragment first 3 data packets after ClientHello with random chunk sizes
			return c.fragmentGeneric(p)
		} else {
			return c.Conn.Write(p)
		}
		recordLen := 5 + ((int(p[3]) << 8) | int(p[4]))
		if len(p) < recordLen {
			return c.Conn.Write(p)
		}
		data := p[5:recordLen]
		buff := make([]byte, 2048)
		var hello []byte
		maxSplit := crypto.RandBetween(c.config.MaxSplitMin, c.config.MaxSplitMax)
		var splitNum int64
		for from := 0; ; {
			to := from + int(crypto.RandBetween(c.config.LengthMin, c.config.LengthMax))
			splitNum++
			if to > len(data) || (maxSplit > 0 && splitNum >= maxSplit) {
				to = len(data)
			}
			l := to - from
			if 5+l > len(buff) {
				buff = make([]byte, 5+l)
			}
			copy(buff[:3], p)
			copy(buff[5:], data[from:to])
			from = to
			buff[3] = byte(l >> 8)
			buff[4] = byte(l)
			if c.config.DelayMax == 0 {
				hello = append(hello, buff[:5+l]...)
			} else {
				_, err := c.Conn.Write(buff[:5+l])
				time.Sleep(time.Duration(crypto.RandBetween(c.config.DelayMin, c.config.DelayMax)) * time.Millisecond)
				if err != nil {
					return 0, err
				}
			}
			if from == len(data) {
				if len(hello) > 0 {
					_, err := c.Conn.Write(hello)
					if err != nil {
						return 0, err
					}
				}
				if len(p) > recordLen {
					n, err := c.Conn.Write(p[recordLen:])
					if err != nil {
						return recordLen + n, err
					}
				}
				return len(p), nil
			}
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
