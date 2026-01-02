# HTTP-Smuggler Architecture

## Overview

HTTP-Smuggler is built with a modular architecture that separates concerns into distinct layers:

```
┌─────────────────────────────────────────────────────────────┐
│                         CLI Layer                            │
│                       (main.py)                              │
└─────────────────────────┬───────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────┐
│                     Core Engine                              │
│                    (core/engine.py)                          │
└─────────────────────────┬───────────────────────────────────┘
                          │
        ┌─────────────────┼─────────────────┐
        │                 │                 │
        ▼                 ▼                 ▼
┌───────────────┐ ┌───────────────┐ ┌───────────────┐
│   Detection   │ │   Payloads    │ │   Crawling    │
│    Layer      │ │    Layer      │ │    Layer      │
└───────┬───────┘ └───────┬───────┘ └───────┬───────┘
        │                 │                 │
        └─────────────────┼─────────────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │    Network Layer      │
              │  (raw_socket, http2)  │
              └───────────────────────┘
```

## Module Structure

### Core (`http_smuggler/core/`)

- **config.py** - Configuration dataclasses for all scan options
- **models.py** - Data models (Endpoint, ScanResult, VulnerabilityReport, etc.)
- **exceptions.py** - Custom exception hierarchy
- **engine.py** - Main SmugglerEngine orchestrator

### Network (`http_smuggler/network/`)

- **raw_socket.py** - Low-level HTTP/1.1 socket client (bypasses library normalization)
- **http2_client.py** - HTTP/2 frame manipulation using hyperframe

### Detection (`http_smuggler/detection/`)

- **protocol.py** - ALPN negotiation, h2c/WebSocket detection
- **timing.py** - Timeout-based vulnerability detection
- **differential.py** - Response poisoning detection

### Payloads (`http_smuggler/payloads/`)

- **generator.py** - Base PayloadGenerator ABC
- **obfuscation.py** - 56 Transfer-Encoding mutations
- **classic/** - CL.TE, TE.CL, TE.TE generators
- **http2/** - H2.CL, H2.TE, CRLF injection generators
- **websocket/** - WebSocket version smuggling
- **advanced/** - Pause-based, Client-side desync

### Crawler (`http_smuggler/crawler/`)

- **spider.py** - Async domain crawler with rate limiting

### Exploitation (`http_smuggler/exploits/`)

- **exploit_runner.py** - Session capture, ACL bypass confirmation

### Analysis (`http_smuggler/analysis/`)

- **reporter.py** - JSON, Markdown, Text report generation

### Utilities (`http_smuggler/utils/`)

- **logging.py** - Structured logging with Rich
- **helpers.py** - URL parsing, timing, rate limiting

## Data Flow

1. **Input**: Target URL + configuration
2. **Protocol Detection**: Identify HTTP versions, ALPN, proxy detection
3. **Endpoint Discovery**: Crawl domain or use provided endpoints
4. **Payload Generation**: Create variant-specific payloads
5. **Detection**: Timing-based → Differential confirmation
6. **Exploitation**: Optional vulnerability confirmation
7. **Output**: Structured report (JSON/Markdown/Text)

## Key Design Decisions

### Raw Socket Communication

We bypass standard HTTP libraries (requests, httpx) for smuggling payloads because they normalize requests, removing the malformations needed for testing.

### Async Architecture

All network operations are async for concurrent testing and efficient timeout handling.

### Payload Abstraction

Each smuggling variant has its own PayloadGenerator that produces both timing and differential payloads, allowing easy extension.

### Safety First

Default mode is "normal" which uses timing detection first (safe, single-request) before differential (two-request, slightly impactful).
