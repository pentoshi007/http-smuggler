# Smuggling Variant Capabilities

The capability source of truth is `http_smuggler/core/variant_registry.py`.
Use `http-smuggler list-variants` for the runtime matrix used by CLI and scans.

## Status Model

- `implemented`: generator + executor + detector wired and testable.
- `experimental`: wired, but behavior may require manual validation.
- `planned`: recognized by CLI, but intentionally not executed.

When a planned variant is requested, scan reports include it under `not_tested`
with reason `not_implemented`.

## Current Capability Matrix

### Classic HTTP/1.1

| Variant | Description | Transport | Status |
|---------|-------------|-----------|--------|
| `CL.TE` | Content-Length vs Transfer-Encoding | `http1` | `implemented` |
| `TE.CL` | Transfer-Encoding vs Content-Length | `http1` | `implemented` |
| `TE.TE` | Transfer-Encoding obfuscation | `http1` | `implemented` |
| `CL.CL` | Duplicate Content-Length | `http1` | `planned` |
| `CL.0` | Backend ignores Content-Length | `http1` | `planned` |
| `0.CL` | Frontend ignores body, backend reads Content-Length | `http1` | `planned` |

### HTTP/2

| Variant | Description | Transport | Status |
|---------|-------------|-----------|--------|
| `H2.CL` | HTTP/2 Content-Length injection | `http2` | `implemented` |
| `H2.TE` | HTTP/2 Transfer-Encoding injection | `http2` | `implemented` |
| `H2.CRLF` | HTTP/2 CRLF injection | `http2` | `implemented` |
| `H2.0` | HTTP/2 request tunneling | `http2` | `planned` |
| `h2c` | h2c cleartext upgrade smuggling | `http2` | `planned` |
| `H2.Tunnel` | HTTP/2 tunnel abuse | `http2` | `planned` |

### WebSocket

| Variant | Description | Transport | Status |
|---------|-------------|-----------|--------|
| `WS.Version` | Sec-WebSocket-Version manipulation | `websocket` | `implemented` |
| `WS.Upgrade` | Upgrade header smuggling | `websocket` | `planned` |

### Advanced

| Variant | Description | Transport | Status |
|---------|-------------|-----------|--------|
| `Pause` | Pause-based desync | `http1` | `experimental` |
| `CSD` | Client-side desync | `browser` | `experimental` |

## Detection Coverage

### Classic-first default scan set

- `CL.TE`
- `TE.CL`
- `TE.TE`

### Detection methods by maturity

- Implemented classic variants: timing + differential.
- Implemented HTTP/2 variants: timing + differential using HTTP/2 frames.
- `WS.Version`: timing + differential style checks over HTTP/1 upgrade behavior.
- `Pause` / `CSD`: experimental, should be manually validated.
