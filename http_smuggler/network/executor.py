"""Transport executors for sending payloads over protocol-correct channels."""

import asyncio
import time
from abc import ABC, abstractmethod
from typing import Dict, Optional

from http_smuggler.core.config import NetworkConfig
from http_smuggler.network.http2_client import HTTP2RawClient
from http_smuggler.network.raw_socket import AsyncRawHttpClient, RawResponse
from http_smuggler.payloads.generator import Payload


def inject_http1_context(
    raw_request: bytes,
    headers: Optional[Dict[str, str]] = None,
    cookies: Optional[Dict[str, str]] = None,
) -> bytes:
    """Inject request context headers/cookies into a raw HTTP/1 request."""
    headers = headers or {}
    cookies = cookies or {}

    if not raw_request or b"\r\n\r\n" not in raw_request:
        return raw_request

    # Skip HTTP/2 pseudo-header serialized payloads.
    first_line = raw_request.split(b"\r\n", 1)[0]
    if first_line.startswith(b":"):
        return raw_request

    header_blob, body = raw_request.split(b"\r\n\r\n", 1)
    lines = header_blob.split(b"\r\n")
    if not lines:
        return raw_request

    normalized_existing = {line.split(b":", 1)[0].strip().lower() for line in lines[1:] if b":" in line}
    extra_lines = []

    for key, value in headers.items():
        key_bytes = key.encode("utf-8", errors="ignore")
        if key_bytes.lower() in normalized_existing:
            continue
        extra_lines.append(f"{key}: {value}".encode())

    if cookies and b"cookie" not in normalized_existing:
        cookie_value = "; ".join(f"{k}={v}" for k, v in cookies.items())
        extra_lines.append(f"Cookie: {cookie_value}".encode())

    if not extra_lines:
        return raw_request

    updated = b"\r\n".join(lines + extra_lines) + b"\r\n\r\n" + body
    return updated


class TransportExecutor(ABC):
    """Protocol-specific payload sender."""

    def __init__(self, network: Optional[NetworkConfig] = None):
        self.network = network or NetworkConfig()

    @abstractmethod
    async def send_payload(
        self,
        payload: Payload,
        host: str,
        port: int,
        use_ssl: bool,
        receive_timeout: float,
    ) -> RawResponse:
        """Send payload and return normalized response."""


class Http1Executor(TransportExecutor):
    """Executor for raw HTTP/1 payload transmission."""

    async def send_payload(
        self,
        payload: Payload,
        host: str,
        port: int,
        use_ssl: bool,
        receive_timeout: float,
    ) -> RawResponse:
        request_bytes = payload.http1_raw or payload.raw_request
        request_bytes = inject_http1_context(
            request_bytes,
            headers=self.network.request_headers,
            cookies=self.network.request_cookies,
        )

        async with AsyncRawHttpClient(self.network) as client:
            await client.connect(host, port, use_ssl)

            pause_spec = payload.metadata.get("pause_spec", {})
            first_chunk = payload.metadata.get("first_chunk")
            second_chunk = payload.metadata.get("second_chunk")

            if pause_spec and first_chunk is not None and second_chunk is not None:
                first = first_chunk.encode() if isinstance(first_chunk, str) else first_chunk
                second = second_chunk.encode() if isinstance(second_chunk, str) else second_chunk
                first = inject_http1_context(
                    first,
                    headers=self.network.request_headers,
                    cookies=self.network.request_cookies,
                )
                await client.send_raw(first)
                pause_duration = float(pause_spec.get("pause_duration", 0))
                if pause_duration > 0:
                    await asyncio.sleep(pause_duration)
                await client.send_raw(second)
                raw_data, response_time = await client.receive(receive_timeout)
                response = RawResponse.from_raw(raw_data, response_time)
                if not raw_data:
                    response.connection_closed = True
                return response

            return await client.send_and_receive(
                request_bytes,
                receive_timeout=receive_timeout,
            )


class Http2Executor(TransportExecutor):
    """Executor for protocol-correct HTTP/2 payload transmission."""

    async def send_payload(
        self,
        payload: Payload,
        host: str,
        port: int,
        use_ssl: bool,
        receive_timeout: float,
    ) -> RawResponse:
        if not use_ssl:
            # h2c support is planned; return a deterministic non-match response.
            return RawResponse(
                raw_data=b"",
                status_code=None,
                body=b"",
                timeout_occurred=False,
                connection_closed=True,
            )

        headers = payload.http2_headers or payload.metadata.get("h2_headers")
        body = payload.http2_body
        if body is None and "body" in payload.metadata:
            body = payload.metadata["body"]

        if not headers:
            return RawResponse(raw_data=b"", status_code=None, body=b"")

        start = time.monotonic()
        async with HTTP2RawClient(self.network) as client:
            await client.connect(host, port)
            stream_id = await client.send_smuggling_request(headers=headers, body=body)
            h2_response = await client.receive_response(stream_id, timeout=receive_timeout)
        elapsed = time.monotonic() - start

        return self._to_raw_response(h2_response.status, h2_response.headers, h2_response.body, elapsed)

    async def send_simple_request(
        self,
        host: str,
        port: int,
        path: str,
        receive_timeout: float,
        method: str = "GET",
        body: Optional[bytes] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> RawResponse:
        """Send a simple control request over HTTP/2 (baseline/victim requests)."""
        hdrs = [
            (":method", method),
            (":path", path or "/"),
            (":scheme", "https"),
            (":authority", host),
        ]
        for key, value in (headers or {}).items():
            hdrs.append((key.lower(), value))
        if self.network.request_cookies:
            cookie_value = "; ".join(
                f"{k}={v}" for k, v in self.network.request_cookies.items()
            )
            hdrs.append(("cookie", cookie_value))

        start = time.monotonic()
        async with HTTP2RawClient(self.network) as client:
            await client.connect(host, port)
            stream_id = await client.send_smuggling_request(headers=hdrs, body=body)
            h2_response = await client.receive_response(stream_id, timeout=receive_timeout)
        elapsed = time.monotonic() - start
        return self._to_raw_response(
            h2_response.status,
            h2_response.headers,
            h2_response.body,
            elapsed,
        )

    @staticmethod
    def _to_raw_response(
        status: Optional[int],
        headers: Dict[str, str],
        body: Optional[bytes],
        response_time: float,
    ) -> RawResponse:
        response_body = body or b""
        raw = f"HTTP/2 {status or ''}\r\n\r\n".encode() + response_body
        return RawResponse(
            raw_data=raw,
            status_code=status,
            status_text=str(status) if status is not None else None,
            headers=headers,
            body=response_body,
            response_time=response_time,
        )


def get_executor(
    transport: str,
    network: Optional[NetworkConfig] = None,
) -> TransportExecutor:
    """Factory helper for transport executors."""
    if transport == "http2":
        return Http2Executor(network)
    return Http1Executor(network)
