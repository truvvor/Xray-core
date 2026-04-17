package reality

import (
	"bytes"
	"errors"
	"io"
	"net"
)

// tolerantReadConn wraps a net.Conn and transparently skips any
// zero-length TLS handshake records that appear at the very start
// of the stream.
//
// Commit 3c526ef ("anti-DPI: SNI-targeted ClientHello
// micro-fragmentation + dummy record injection") in this repo makes
// the client fragmenter prefix its ClientHello with an empty
// handshake record as a DPI-parser-poisoning measure. Per RFC 8446
// §5.1 zero-length Handshake fragments are not permitted, and the
// pinned xtls/reality reader correctly rejects them — which kills
// every session before the REALITY handshake can start.
//
// Because the prefix is only emitted before the real ClientHello,
// this wrapper peeks at record headers on the first Read() and
// discards any 0x16 / any-version / 0x0000 record. After the first
// non-empty record is observed, the wrapper falls through to the
// underlying Read() with zero overhead for the rest of the session.
type tolerantReadConn struct {
	net.Conn
	prefixScanned bool
	// buf holds bytes already read from the underlying conn that
	// belong to the first non-empty record and must be returned to
	// the next Read() call.
	buf bytes.Buffer
}

func newTolerantReadConn(c net.Conn) *tolerantReadConn {
	return &tolerantReadConn{Conn: c}
}

func (t *tolerantReadConn) Read(p []byte) (int, error) {
	if t.prefixScanned {
		if t.buf.Len() > 0 {
			return t.buf.Read(p)
		}
		return t.Conn.Read(p)
	}

	// Scan and drop leading zero-length handshake records.
	// Budget: at most 4 leading empty records, 5 bytes each, to avoid
	// a malicious client keeping the server reading forever.
	var header [5]byte
	for i := 0; i < 4; i++ {
		if _, err := io.ReadFull(t.Conn, header[:]); err != nil {
			return 0, err
		}
		contentType := header[0]
		length := int(header[3])<<8 | int(header[4])
		isHandshake := contentType == 0x16 // TLS ContentType.Handshake
		if isHandshake && length == 0 {
			continue
		}
		// First real record: put its header into buf and read its
		// body so the caller gets a coherent record start.
		t.buf.Write(header[:])
		if length > 0 {
			body := make([]byte, length)
			if _, err := io.ReadFull(t.Conn, body); err != nil {
				return 0, err
			}
			t.buf.Write(body)
		}
		t.prefixScanned = true
		return t.buf.Read(p)
	}

	return 0, errors.New("reality: too many leading empty handshake records")
}
