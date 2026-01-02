"""Raw socket client for sending malformed HTTP/1.1 requests.

Standard HTTP libraries (requests, httpx, aiohttp) validate and normalize
requests, making them unsuitable for HTTP smuggling testing. This module
provides a raw socket interface that sends bytes exactly as specified.
"""

import socket
import ssl
import time
import asyncio
from typing import Optional, Tuple, Dict, Any
from dataclasses import dataclass, field
from urllib.parse import urlparse

from http_smuggler.core.exceptions import (
    ConnectionError,
    ConnectionRefusedError,
    ConnectionTimeoutError,
    SSLError,
    DNSResolutionError,
    InvalidResponseError,
)
from http_smuggler.core.config import NetworkConfig


@dataclass
class RawResponse:
    """Raw HTTP response from socket."""

    raw_data: bytes
    status_code: Optional[int] = None
    status_text: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    response_time: float = 0.0

    # Connection state
    connection_closed: bool = False
    timeout_occurred: bool = False

    @classmethod
    def from_raw(cls, raw_data: bytes, response_time: float = 0.0) -> "RawResponse":
        """Parse raw HTTP response data."""
        response = cls(raw_data=raw_data, response_time=response_time)

        if not raw_data:
            return response

        try:
            # Skip 100 Continue responses (Issue #8 fix)
            # Server may send "HTTP/1.1 100 Continue" before the actual response
            while raw_data.startswith(b"HTTP/1.1 100") or raw_data.startswith(b"HTTP/1.0 100"):
                if b"\r\n\r\n" in raw_data:
                    # Find end of 100 response and skip it
                    idx = raw_data.index(b"\r\n\r\n") + 4
                    raw_data = raw_data[idx:]
                    if not raw_data:
                        return response
                else:
                    break

            # Split headers and body
            if b"\r\n\r\n" in raw_data:
                header_section, body = raw_data.split(b"\r\n\r\n", 1)
                response.body = body
            else:
                header_section = raw_data

            # Parse status line
            lines = header_section.split(b"\r\n")
            if lines:
                status_line = lines[0].decode("utf-8", errors="replace")
                parts = status_line.split(" ", 2)
                if len(parts) >= 2:
                    try:
                        response.status_code = int(parts[1])
                        response.status_text = parts[2] if len(parts) > 2 else ""
                    except ValueError:
                        pass

                # Parse headers
                for line in lines[1:]:
                    if b":" in line:
                        key, value = line.split(b":", 1)
                        key = key.decode("utf-8", errors="replace").strip()
                        value = value.decode("utf-8", errors="replace").strip()
                        # Store headers case-insensitively
                        response.headers[key.lower()] = value

        except Exception:
            # If parsing fails, we still have raw_data
            pass

        return response

    def get_header(self, name: str, default: Optional[str] = None) -> Optional[str]:
        """Get header value case-insensitively."""
        return self.headers.get(name.lower(), default)


class RawHttpClient:
    """Raw HTTP/1.1 client using sockets for malformed request testing."""

    def __init__(self, config: Optional[NetworkConfig] = None):
        self.config = config or NetworkConfig()
        self._socket: Optional[socket.socket] = None
        self._ssl_context: Optional[ssl.SSLContext] = None
        self._connected_host: Optional[str] = None
        self._connected_port: Optional[int] = None
        self._is_ssl: bool = False

    def _create_ssl_context(self, verify: bool = True) -> ssl.SSLContext:
        """Create SSL context for HTTPS connections."""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

        if verify:
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_default_certs()
        else:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

        # Enable ALPN for protocol negotiation detection
        context.set_alpn_protocols(["http/1.1"])

        # Load custom cert/key if provided
        if self.config.ssl_cert_path and self.config.ssl_key_path:
            context.load_cert_chain(self.config.ssl_cert_path, self.config.ssl_key_path)

        return context

    def connect(
        self,
        host: str,
        port: int,
        use_ssl: bool = False,
        server_hostname: Optional[str] = None,
    ) -> None:
        """Establish connection to target host."""
        # Close existing connection if any
        self.close()

        try:
            # Resolve hostname
            try:
                addr_info = socket.getaddrinfo(
                    host, port, socket.AF_UNSPEC, socket.SOCK_STREAM
                )
                if not addr_info:
                    raise DNSResolutionError(host)
            except socket.gaierror:
                raise DNSResolutionError(host)

            # Use first resolved address
            family, socktype, proto, canonname, sockaddr = addr_info[0]

            # Create socket
            self._socket = socket.socket(family, socktype, proto)
            self._socket.settimeout(self.config.connect_timeout)

            # Set socket options
            self._socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

            # Connect
            try:
                self._socket.connect(sockaddr)
            except socket.timeout:
                raise ConnectionTimeoutError(
                    host, port, self.config.connect_timeout, "connect"
                )
            except ConnectionRefusedError as e:
                raise ConnectionRefusedError(host, port)
            except OSError as e:
                raise ConnectionError(f"Connection to {host}:{port} failed: {e}")

            # Wrap with SSL if needed
            if use_ssl:
                self._ssl_context = self._create_ssl_context(self.config.verify_ssl)
                hostname = server_hostname or host
                try:
                    self._socket = self._ssl_context.wrap_socket(
                        self._socket, server_hostname=hostname
                    )
                except ssl.SSLError as e:
                    raise SSLError(host, str(e), str(e))
                except ssl.CertificateError as e:
                    raise SSLError(
                        host, f"Certificate verification failed: {e}", str(e)
                    )
                self._is_ssl = True

            self._connected_host = host
            self._connected_port = port

        except (
            DNSResolutionError,
            ConnectionTimeoutError,
            ConnectionRefusedError,
            SSLError,
        ):
            raise
        except Exception as e:
            self.close()
            raise ConnectionError(f"Failed to connect to {host}:{port}: {e}")

    def send_raw(self, data: bytes, timeout: Optional[float] = None) -> None:
        """Send raw bytes over the connection."""
        if not self._socket:
            raise ConnectionError("Not connected")

        timeout = timeout or self.config.write_timeout
        self._socket.settimeout(timeout)

        try:
            total_sent = 0
            while total_sent < len(data):
                sent = self._socket.send(data[total_sent:])
                if sent == 0:
                    raise ConnectionError("Connection closed during send")
                total_sent += sent
        except socket.timeout:
            raise ConnectionTimeoutError(
                self._connected_host or "unknown",
                self._connected_port or 0,
                timeout,
                "write",
            )
        except Exception as e:
            raise ConnectionError(f"Send failed: {e}")

    def receive(
        self, timeout: Optional[float] = None, max_size: Optional[int] = None
    ) -> Tuple[bytes, float]:
        """Receive response data with timing information.

        Returns:
            Tuple of (received_data, response_time)
        """
        if not self._socket:
            raise ConnectionError("Not connected")

        timeout = timeout or self.config.read_timeout
        max_size = max_size or self.config.max_response_size

        self._socket.settimeout(timeout)

        start_time = time.time()
        chunks = []
        total_size = 0

        try:
            while total_size < max_size:
                try:
                    chunk = self._socket.recv(self.config.socket_buffer_size)
                    if not chunk:
                        # Connection closed
                        break
                    chunks.append(chunk)
                    total_size += len(chunk)

                    # Check if we have a complete response
                    data = b"".join(chunks)
                    if self._is_response_complete(data):
                        break

                except socket.timeout:
                    # Timeout is expected for timing-based detection
                    break
                except Exception:
                    break

        except Exception as e:
            raise ConnectionError(f"Receive failed: {e}")

        response_time = time.time() - start_time
        return b"".join(chunks), response_time

    def _is_response_complete(self, data: bytes) -> bool:
        """Check if we've received a complete HTTP response."""
        if b"\r\n\r\n" not in data:
            return False

        header_end = data.index(b"\r\n\r\n") + 4
        headers = data[:header_end].decode("utf-8", errors="replace").lower()
        body = data[header_end:]

        # Check Content-Length
        if "content-length:" in headers:
            for line in headers.split("\r\n"):
                if line.startswith("content-length:"):
                    try:
                        content_length = int(line.split(":", 1)[1].strip())
                        return len(body) >= content_length
                    except ValueError:
                        pass

        # Check for chunked encoding
        if "transfer-encoding: chunked" in headers:
            return body.endswith(b"0\r\n\r\n")

        # For responses with no body indication, check for connection: close
        if "connection: close" in headers:
            return True

        # Default: assume complete if we have headers + some body
        return len(body) > 0

    def send_and_receive(
        self,
        data: bytes,
        send_timeout: Optional[float] = None,
        receive_timeout: Optional[float] = None,
    ) -> RawResponse:
        """Send request and receive response."""
        self.send_raw(data, send_timeout)
        raw_data, response_time = self.receive(receive_timeout)

        response = RawResponse.from_raw(raw_data, response_time)

        # Check connection state
        if not raw_data:
            response.connection_closed = True

        return response

    def close(self) -> None:
        """Close the connection."""
        if self._socket:
            try:
                self._socket.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                self._socket.close()
            except Exception:
                pass
            self._socket = None

        self._connected_host = None
        self._connected_port = None
        self._is_ssl = False

    def is_connected(self) -> bool:
        """Check if connection is still open."""
        return self._socket is not None

    @property
    def alpn_protocol(self) -> Optional[str]:
        """Get negotiated ALPN protocol (for SSL connections)."""
        if self._socket and self._is_ssl:
            try:
                return self._socket.selected_alpn_protocol()
            except Exception:
                pass
        return None

    def __enter__(self) -> "RawHttpClient":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()


class AsyncRawHttpClient:
    """Async version of RawHttpClient for concurrent testing."""

    def __init__(self, config: Optional[NetworkConfig] = None):
        self.config = config or NetworkConfig()
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._connected_host: Optional[str] = None
        self._connected_port: Optional[int] = None
        self._is_ssl: bool = False

    def _create_ssl_context(self, verify: bool = True) -> ssl.SSLContext:
        """Create SSL context for HTTPS connections."""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

        if verify:
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_default_certs()
        else:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

        context.set_alpn_protocols(["http/1.1"])

        if self.config.ssl_cert_path and self.config.ssl_key_path:
            context.load_cert_chain(self.config.ssl_cert_path, self.config.ssl_key_path)

        return context

    async def connect(
        self,
        host: str,
        port: int,
        use_ssl: bool = False,
        server_hostname: Optional[str] = None,
    ) -> None:
        """Establish async connection to target host."""
        await self.close()

        try:
            ssl_context = None
            if use_ssl:
                ssl_context = self._create_ssl_context(self.config.verify_ssl)
                self._is_ssl = True

            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host,
                    port,
                    ssl=ssl_context,
                    server_hostname=server_hostname or host if use_ssl else None,
                ),
                timeout=self.config.connect_timeout,
            )

            # Set TCP_NODELAY for accurate timing measurements (Issue #12 fix)
            # This disables Nagle's algorithm which can buffer small writes
            sock = self._writer.get_extra_info('socket')
            if sock:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            self._connected_host = host
            self._connected_port = port

        except asyncio.TimeoutError:
            raise ConnectionTimeoutError(
                host, port, self.config.connect_timeout, "connect"
            )
        except ssl.SSLError as e:
            raise SSLError(host, str(e), str(e))
        except OSError as e:
            if "Name or service not known" in str(e):
                raise DNSResolutionError(host)
            raise ConnectionError(f"Failed to connect to {host}:{port}: {e}")

    async def send_raw(self, data: bytes, timeout: Optional[float] = None) -> None:
        """Send raw bytes over the connection."""
        if not self._writer:
            raise ConnectionError("Not connected")

        timeout = timeout or self.config.write_timeout

        try:
            self._writer.write(data)
            await asyncio.wait_for(self._writer.drain(), timeout=timeout)
        except asyncio.TimeoutError:
            raise ConnectionTimeoutError(
                self._connected_host or "unknown",
                self._connected_port or 0,
                timeout,
                "write",
            )

    async def receive(
        self, timeout: Optional[float] = None, max_size: Optional[int] = None
    ) -> Tuple[bytes, float]:
        """Receive response data with timing information."""
        if not self._reader:
            raise ConnectionError("Not connected")

        timeout = timeout or self.config.read_timeout
        max_size = max_size or self.config.max_response_size

        start_time = time.time()
        chunks = []
        total_size = 0

        try:
            while total_size < max_size:
                try:
                    chunk = await asyncio.wait_for(
                        self._reader.read(self.config.socket_buffer_size),
                        timeout=timeout,
                    )
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total_size += len(chunk)

                    data = b"".join(chunks)
                    if self._is_response_complete(data):
                        break

                except asyncio.TimeoutError:
                    break
        except Exception:
            pass

        response_time = time.time() - start_time
        return b"".join(chunks), response_time

    def _is_response_complete(self, data: bytes) -> bool:
        """Check if we've received a complete HTTP response."""
        if b"\r\n\r\n" not in data:
            return False

        header_end = data.index(b"\r\n\r\n") + 4
        headers = data[:header_end].decode("utf-8", errors="replace").lower()
        body = data[header_end:]

        if "content-length:" in headers:
            for line in headers.split("\r\n"):
                if line.startswith("content-length:"):
                    try:
                        content_length = int(line.split(":", 1)[1].strip())
                        return len(body) >= content_length
                    except ValueError:
                        pass

        if "transfer-encoding: chunked" in headers:
            return body.endswith(b"0\r\n\r\n")

        if "connection: close" in headers:
            return True

        return len(body) > 0

    async def send_and_receive(
        self,
        data: bytes,
        send_timeout: Optional[float] = None,
        receive_timeout: Optional[float] = None,
    ) -> RawResponse:
        """Send request and receive response."""
        await self.send_raw(data, send_timeout)
        raw_data, response_time = await self.receive(receive_timeout)

        response = RawResponse.from_raw(raw_data, response_time)

        if not raw_data:
            response.connection_closed = True

        return response

    async def close(self) -> None:
        """Close the connection."""
        if self._writer:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass
            self._writer = None
            self._reader = None

        self._connected_host = None
        self._connected_port = None
        self._is_ssl = False

    def is_connected(self) -> bool:
        """Check if connection is still open."""
        return self._writer is not None and not self._writer.is_closing()

    async def __aenter__(self) -> "AsyncRawHttpClient":
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()


def build_raw_request(
    method: str,
    path: str,
    host: str,
    headers: Optional[Dict[str, str]] = None,
    body: Optional[bytes] = None,
    http_version: str = "HTTP/1.1",
) -> bytes:
    """Build a raw HTTP request.

    This function builds requests exactly as specified, without any
    normalization or validation. Use for crafting smuggling payloads.

    Args:
        method: HTTP method (GET, POST, etc.)
        path: Request path (e.g., /)
        host: Host header value
        headers: Additional headers (Content-Length, Transfer-Encoding handled separately)
        body: Request body bytes
        http_version: HTTP version string (HTTP/1.0, HTTP/1.1)

    Returns:
        Raw HTTP request bytes
    """
    headers = headers or {}

    # Build request line
    request_line = f"{method} {path} {http_version}\r\n"

    # Build headers
    header_lines = [f"Host: {host}"]
    for key, value in headers.items():
        header_lines.append(f"{key}: {value}")

    # Combine
    request = request_line + "\r\n".join(header_lines) + "\r\n\r\n"

    if body:
        return request.encode("utf-8") + body
    return request.encode("utf-8")


def parse_url(url: str) -> Tuple[str, str, int, str, bool]:
    """Parse URL into components.

    Returns:
        Tuple of (scheme, host, port, path, use_ssl)
    """
    parsed = urlparse(url)

    scheme = parsed.scheme or "http"
    host = parsed.hostname or ""

    if parsed.port:
        port = parsed.port
    elif scheme == "https":
        port = 443
    else:
        port = 80

    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    use_ssl = scheme == "https"

    return scheme, host, port, path, use_ssl
