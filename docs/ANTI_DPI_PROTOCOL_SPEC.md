# Anti-DPI Protocol Modifications — iOS Client Compatibility Guide

> **Branch**: `claude/optimize-encryption-dpi-w8aSj`
> **Base commit**: `28b163c` (2026-03-31)
> **Purpose**: Exact specification of all wire-format changes for building a compatible iOS client

---

## Architecture Overview

```
iOS App
  ↓ plaintext
CommonConn (AEAD encryption + record sizing)
  ↓ encrypted TLS records
ScatterConn (TCP segment fragmentation)
  ↓ fragmented TCP segments
[HeartbeatConn] (idle keepalive, non-XTLS only)
  ↓
Wire (TLS 1.3 Application Data)
```

**Critical**: ScatterConn wraps the connection **before** CommonConn. Encrypted records are fragmented, not plaintext.

---

## Modification 1: TLS Record Size Distribution

| Property | Value |
|----------|-------|
| **File** | `proxy/vless/encryption/common.go:55-70` |
| **Scope** | CLIENT + SERVER |
| **Wire impact** | Changes payload size of each TLS record |
| **Server enforces?** | No — server reads by actual record length |

### What changed

Original Xray-core uses fixed 8192-byte max record size. Modified to a three-tier random distribution:

```
dice = crypto_random(0..100)

if dice < 10:       // 10% probability
    max = 256 + random(0..768)       →  256..1024 bytes
elif dice < 30:     // 20% probability
    max = 1024 + random(0..3072)     → 1024..4096 bytes
else:               // 70% probability
    max = 4096 + random(0..4096)     → 4096..8192 bytes
```

### iOS implementation

- Apply **per-write** — each `Write()` call independently rolls new random size
- If plaintext `len(data) > maxRecordSize`, split into multiple records
- Each record: `[0x17, 0x03, 0x03, len_hi, len_lo, AEAD_sealed_payload]`
- Valid record length range: 17–16640 bytes (payload + 16-byte auth tag)

---

## Modification 2: ScatterConn (TCP Segment Fragmentation)

| Property | Value |
|----------|-------|
| **File** | `proxy/vless/encryption/scatter.go` (new) |
| **Integration** | `client.go:71`, `server.go:122` |
| **Scope** | CLIENT + SERVER (symmetric) |
| **Wire impact** | Splits TLS records across multiple TCP segments |
| **Server enforces?** | No — TCP auto-reassembles, but server also sends scattered |

### Parameters

```
minChunk    = 64      // minimum TCP segment payload
maxChunk    = 512     // maximum TCP segment payload
maxScatter  = 50      // scatter first 50 writes, then passthrough
maxJitterMs = 2       // 0-2ms random delay between chunks
```

### Algorithm

```
func Write(b []byte):
    writeCount++

    // After 50 writes, stop scattering (performance)
    if writeCount > 50:
        return conn.Write(b)

    // Don't split tiny writes (< 128 bytes)
    if len(b) < minChunk * 2:
        return conn.Write(b)

    // Fragment into random chunks
    while len(b) > 0:
        chunkSize = random(64..512)
        if chunkSize >= len(b):
            conn.Write(b)  // last chunk
            break
        conn.Write(b[:chunkSize])
        b = b[chunkSize:]
        sleep(random(0..2) ms)  // micro-jitter
```

### iOS implementation

- Wrap the raw TCP connection with ScatterConn **before** passing to CommonConn
- Call chain: `CommonConn(ScatterConn(tcp_conn))`
- Use `arc4random_uniform()` or `SecRandomCopyBytes()` for chunk sizes

---

## Modification 3: HeartbeatConn (Idle Keepalive)

| Property | Value |
|----------|-------|
| **File** | `proxy/vless/encryption/heartbeat.go` (new) |
| **Integration** | `outbound.go:295-300` |
| **Scope** | CLIENT only |
| **Wire impact** | Sends fake TLS records during idle periods |
| **Server enforces?** | No — extra packets ignored |

### Activation condition

```
Only when:
  - Flow is NOT XTLS Vision (XRV)
  - ML-KEM-768 encryption is enabled (h.encryption != nil)
```

### Parameters

```
minIntervalMs = 5000    // 5 seconds
maxIntervalMs = 15000   // 15 seconds
idleThreshold = 2s      // only send if idle > 2 seconds
```

### Heartbeat packet format

```
Byte 0:     0x17          // TLS Application Data type
Byte 1-2:   0x03 0x03     // TLS 1.2 record version (standard for TLS 1.3)
Byte 3-4:   payload_len   // big-endian, 16..128
Byte 5+:    random_bytes  // crypto random, 16-128 bytes
```

### Algorithm

```
Background goroutine:
    every random(5000..15000) ms:
        if time_since_last_write > 2s:
            payloadLen = random(16..128)
            record = [0x17, 0x03, 0x03, payloadLen >> 8, payloadLen & 0xFF, random(payloadLen)]
            conn.Write(record)  // best-effort, ignore errors

            // Re-randomize next interval
            ticker.Reset(random(5000..15000) ms)

On Write(b):
    update lastSend = now()
    return conn.Write(b)

On Close():
    stop heartbeat goroutine
    close connection
```

### iOS implementation

- Run heartbeat on a background `DispatchQueue` or `Task`
- Track `lastSend` timestamp, update on every real write
- Use `SecRandomCopyBytes()` for payload generation
- **Only for non-XTLS flows** with ML-KEM-768 encryption enabled

---

## Modification 4: VLESS Header Padding

| Property | Value |
|----------|-------|
| **File** | `proxy/vless/encoding/addons.go:33-42` |
| **Scope** | CLIENT (encoder) + SERVER (decoder ignores) |
| **Wire impact** | Extra 17-65 bytes in VLESS header |
| **Server enforces?** | No — server ignores unmarshal errors (treats as padding) |

### Wire format

For non-XTLS flows (when `requestAddons.Flow` is empty):

```
Original VLESS addons: [protobuf_encoded_addons]
Modified VLESS addons: [1 byte: paddingLen] [paddingLen bytes: random]

paddingLen = random(16..64)
padding = crypto_random(paddingLen)
```

### Server behavior

Server tries `proto.Unmarshal(buffer, addons)`. If it fails (because padding is not valid protobuf), it silently ignores the error and treats addons as empty. This is intentional — see `addons.go:62`.

### iOS implementation

```swift
let paddingLen = UInt8(secureRandom(16...64))
var header = Data()
header.append(paddingLen)
header.append(secureRandomBytes(count: Int(paddingLen)))
// Write as VLESS addons field
```

---

## Modification 5: VMess AEAD Trailing Padding

| Property | Value |
|----------|-------|
| **File** | `proxy/vmess/aead/encrypt.go:53-59` |
| **Scope** | CLIENT only (if using VMess) |
| **Wire impact** | 0-32 extra bytes after AEAD header |
| **Server enforces?** | No — server reads exact lengths, ignores trailing |

### Wire format

```
[16: authID] [18: encrypted_payloadLen] [8: nonce] [payload+tag] [0-32: random_padding]
                                                                   ↑ NEW: trailing noise
```

### iOS implementation (VMess only)

```swift
let paddingLen = secureRandom(0...32)
let padding = secureRandomBytes(count: paddingLen)
outputBuffer.append(padding)  // Append after sealed VMess header
```

---

## Modification 6: REALITY SessionID Timestamp Jitter

| Property | Value |
|----------|-------|
| **File** | `transport/internet/reality/reality.go:147-149` |
| **Scope** | CLIENT only |
| **Wire impact** | SessionID bytes 4-7 in TLS ClientHello |
| **Server enforces?** | No |

### What changed

```
// Original:
sessionId[4:8] = uint32(time.Now().Unix())

// Modified:
jitter = random(-300..300)  // ±5 minutes
sessionId[4:8] = uint32(time.Now().Unix() + jitter)
```

### iOS implementation

```swift
let jitter = Int64(secureRandom(-300...300))
let timestamp = UInt32(truncatingIfNeeded: Int64(Date().timeIntervalSince1970) + jitter)
sessionId[4..<8] = withUnsafeBytes(of: timestamp.bigEndian) { Data($0) }
```

---

## Modification 7: Extended Post-Handshake Fragmentation (FinalMask)

| Property | Value |
|----------|-------|
| **File** | `transport/internet/finalmask/fragment/conn.go:49-119` |
| **Scope** | CLIENT (transport layer) |
| **Wire impact** | Packets 2-4 fragmented + micro-jitter on first 10 packets |
| **Server enforces?** | No — TCP reassembly handles it |

### What changed

```
Packet 1 (ClientHello, type=22): original fragmentation (unchanged)
Packets 2-4 (len > 64):         NEW — fragmentGeneric() splits into random chunks
Packets 5-10:                    NEW — micro-jitter (0 to DelayMax/4 ms)
Packets 11+:                     passthrough (no modification)
```

### fragmentGeneric algorithm

```
func fragmentGeneric(p []byte):
    while len(p) > 0:
        chunkSize = random(LengthMin..LengthMax)
        conn.Write(p[:chunkSize])
        sleep(random(DelayMin..DelayMax) ms)
        p = p[chunkSize:]
```

### iOS implementation

- If using FinalMask transport, fragment first 4 packets
- Add random delay between fragments
- This is transport-layer — may not apply if iOS uses a different transport

---

## Implementation Priority for iOS

### MUST IMPLEMENT (protocol correctness)

| # | Feature | Reason |
|---|---------|--------|
| 1 | Record size distribution (10/20/70) | Both sides use variable sizes |
| 2 | ScatterConn (64-512 byte TCP chunks) | Server also sends scattered |
| 3 | VLESS header padding (16-64 bytes) | Server expects either protobuf or padding |

### SHOULD IMPLEMENT (anti-DPI effectiveness)

| # | Feature | Reason |
|---|---------|--------|
| 4 | HeartbeatConn (5-15s idle keepalive) | Prevents idle tunnel detection |
| 5 | SessionID jitter (±300s) | Prevents timestamp correlation |
| 6 | VMess AEAD padding (0-32 bytes) | Only if using VMess protocol |

### OPTIONAL (transport-layer, depends on iOS architecture)

| # | Feature | Reason |
|---|---------|--------|
| 7 | FinalMask post-handshake fragmentation | Transport-level, may use different approach on iOS |

---

## Constants Reference

```
// Record sizes
RECORD_SIZE_SMALL_MIN   = 256
RECORD_SIZE_SMALL_MAX   = 1024
RECORD_SIZE_MEDIUM_MIN  = 1024
RECORD_SIZE_MEDIUM_MAX  = 4096
RECORD_SIZE_LARGE_MIN   = 4096
RECORD_SIZE_LARGE_MAX   = 8192
RECORD_SIZE_PROB_SMALL  = 10   // percent
RECORD_SIZE_PROB_MEDIUM = 20   // percent (cumulative: 30)
RECORD_SIZE_PROB_LARGE  = 70   // percent (cumulative: 100)

// Scatter
SCATTER_MIN_CHUNK       = 64
SCATTER_MAX_CHUNK       = 512
SCATTER_MAX_WRITES      = 50
SCATTER_MAX_JITTER_MS   = 2

// Heartbeat
HEARTBEAT_MIN_INTERVAL  = 5000   // ms
HEARTBEAT_MAX_INTERVAL  = 15000  // ms
HEARTBEAT_IDLE_THRESH   = 2000   // ms
HEARTBEAT_PAYLOAD_MIN   = 16     // bytes
HEARTBEAT_PAYLOAD_MAX   = 128    // bytes

// VLESS padding
VLESS_PADDING_MIN       = 16     // bytes
VLESS_PADDING_MAX       = 64     // bytes

// VMess padding
VMESS_PADDING_MIN       = 0      // bytes
VMESS_PADDING_MAX       = 32     // bytes

// REALITY SessionID
REALITY_JITTER_MIN      = -300   // seconds
REALITY_JITTER_MAX      = 300    // seconds

// TLS record header
TLS_APP_DATA            = 0x17
TLS_VERSION_HI          = 0x03
TLS_VERSION_LO          = 0x03
TLS_RECORD_MIN_LEN      = 17     // 1 byte payload + 16 byte auth tag
TLS_RECORD_MAX_LEN      = 16640  // RFC 8446 §5.2: 16384 + 256
```
