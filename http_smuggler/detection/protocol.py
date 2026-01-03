"""Protocol detection for HTTP Smuggler.

Detects supported protocols (HTTP/1.1, HTTP/2, WebSocket) and server characteristics
through ALPN negotiation, direct HTTP/2 connection testing, h2c upgrade testing,
and WebSocket handshake testing.

Key detection methods:
1. ALPN negotiation (test h2-only first, then http/1.1-only)
2. Direct HTTP/2 connection verification (preface + SETTINGS handshake)
3. Fallback HTTP/2 detection for servers without ALPN
4. NPN (Next Protocol Negotiation) fallback for older servers
5. h2c upgrade testing for cleartext HTTP/2
"""

import ssl
import socket
import asyncio
import struct
import logging
from typing import Optional, List, Dict, Any, Tuple, Set
from dataclasses import dataclass, field

from http_smuggler.core.models import HttpVersion, ProtocolProfile
from http_smuggler.core.config import NetworkConfig
from http_smuggler.core.exceptions import (
    ConnectionError,
    ConnectionTimeoutError,
    SSLError,
    DNSResolutionError,
    ALPNNegotiationError,
)
from http_smuggler.utils.helpers import parse_url, ParsedURL

logger = logging.getLogger(__name__)


# HTTP/2 constants
H2_CONNECTION_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
# Empty SETTINGS frame: length=0 (3 bytes) + type=0x04 (1 byte) + flags=0x00 (1 byte) + stream_id=0 (4 bytes)
H2_EMPTY_SETTINGS = b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"
# SETTINGS frame type
H2_FRAME_SETTINGS = 0x04
H2_FRAME_GOAWAY = 0x07


@dataclass
class ProtocolDetectionResult:
    """Detailed protocol detection results."""

    # HTTP versions
    supports_http1: bool = True
    supports_http2: bool = False
    supports_h2c: bool = False

    # ALPN
    alpn_protocols: List[str] = field(default_factory=list)
    selected_alpn: Optional[str] = None
    alpn_supported: bool = False

    # NPN (legacy)
    npn_protocols: List[str] = field(default_factory=list)
    npn_supported: bool = False

    # HTTP/2 verification
    h2_verified: bool = False
    h2_detection_method: Optional[str] = None  # "alpn", "npn", "direct", "h2c"

    # WebSocket
    supports_websocket: bool = False
    websocket_paths: List[str] = field(default_factory=list)

    # Server info
    server_header: Optional[str] = None
    via_header: Optional[str] = None
    x_powered_by: Optional[str] = None

    # Connection behavior
    supports_keepalive: bool = True
    supports_pipelining: bool = False

    # Proxy detection
    is_proxied: bool = False
    proxy_type: Optional[str] = None

    # TLS info
    tls_version: Optional[str] = None

    def to_protocol_profile(self) -> ProtocolProfile:
        """Convert to ProtocolProfile model."""
        if self.supports_http2:
            primary = HttpVersion.HTTP_2
        else:
            primary = HttpVersion.HTTP_1_1

        return ProtocolProfile(
            primary_version=primary,
            alpn_protocols=self.alpn_protocols,
            supports_h2c=self.supports_h2c,
            supports_websocket=self.supports_websocket,
            supports_keepalive=self.supports_keepalive,
            server_header=self.server_header,
            via_header=self.via_header,
        )


class ProtocolDetector:
    """Detect supported protocols and server characteristics."""

    # Common WebSocket paths to test
    WEBSOCKET_PATHS = [
        "/socket.io/",
        "/ws",
        "/websocket",
        "/graphql-ws",
        "/subscriptions",
        "/sockjs/",
        "/cable",
        "/realtime",
    ]

    def __init__(self, config: Optional[NetworkConfig] = None):
        self.config = config or NetworkConfig()
        self._ssl_warning_logged = False

    def _create_ssl_context(
        self,
        alpn_protocols: Optional[List[str]] = None,
        require_tls_1_2: bool = True,
    ) -> ssl.SSLContext:
        """Create SSL context respecting config.verify_ssl setting.

        Args:
            alpn_protocols: ALPN protocols to set
            require_tls_1_2: Whether to require TLS 1.2+

        Returns:
            Configured SSLContext
        """
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

        if self.config.verify_ssl:
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_default_certs()
        else:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            # Log warning once per detector instance
            if not self._ssl_warning_logged:
                logger.warning(
                    "TLS certificate verification DISABLED - use only for testing"
                )
                self._ssl_warning_logged = True

        if require_tls_1_2:
            context.minimum_version = ssl.TLSVersion.TLSv1_2

        if alpn_protocols:
            context.set_alpn_protocols(alpn_protocols)

        return context

    async def detect(
        self,
        url: str,
        check_websocket: bool = True,
        check_h2c: bool = True,
    ) -> ProtocolDetectionResult:
        """Detect protocols supported by target.

        Uses multiple detection methods to ensure accurate protocol identification:
        1. ALPN negotiation (h2-only first, then http/1.1)
        2. Direct HTTP/2 connection test
        3. NPN fallback for older servers
        4. h2c upgrade for cleartext connections

        Args:
            url: Target URL
            check_websocket: Whether to check WebSocket support
            check_h2c: Whether to check h2c upgrade support

        Returns:
            ProtocolDetectionResult with all detected capabilities
        """
        parsed = parse_url(url)
        result = ProtocolDetectionResult()

        # 1. For HTTPS: Try multiple HTTP/2 detection methods
        if parsed.use_ssl:
            # Method 1: ALPN negotiation (most reliable for modern servers)
            alpn_result = await self._detect_alpn_protocols(parsed)
            result.alpn_protocols = alpn_result["protocols"]
            result.selected_alpn = alpn_result["selected"]
            result.alpn_supported = alpn_result["alpn_supported"]
            result.tls_version = alpn_result.get("tls_version")

            # Check if h2 was detected via ALPN
            if "h2" in result.alpn_protocols:
                result.supports_http2 = True
                result.h2_detection_method = "alpn"

            # Method 2: Direct HTTP/2 connection verification
            # This catches servers that support h2 but may have ALPN quirks
            if not result.supports_http2:
                h2_direct = await self._verify_http2_direct(parsed)
                if h2_direct:
                    result.supports_http2 = True
                    result.h2_detection_method = "direct"
                    if "h2" not in result.alpn_protocols:
                        result.alpn_protocols.append("h2")

            # Method 3: NPN fallback for older servers
            if not result.supports_http2:
                npn_result = await self._detect_npn_protocols(parsed)
                result.npn_protocols = npn_result["protocols"]
                result.npn_supported = npn_result["npn_supported"]
                if "h2" in result.npn_protocols:
                    result.supports_http2 = True
                    result.h2_detection_method = "npn"

            # Verify HTTP/2 actually works if detected via ALPN
            if result.supports_http2 and result.h2_detection_method == "alpn":
                result.h2_verified = await self._verify_http2_handshake(parsed)
            else:
                result.h2_verified = result.supports_http2

        # 2. Initial HTTP request for server info
        server_info = await self._get_server_info(parsed)
        result.server_header = server_info.get("server")
        result.via_header = server_info.get("via")
        result.x_powered_by = server_info.get("x-powered-by")
        result.is_proxied = result.via_header is not None

        # Detect proxy type from headers
        if result.is_proxied:
            result.proxy_type = self._identify_proxy_type(server_info)

        # 3. h2c upgrade test (for HTTP/cleartext)
        if check_h2c and not parsed.use_ssl:
            result.supports_h2c = await self._test_h2c_upgrade(parsed)
            if result.supports_h2c and not result.supports_http2:
                result.supports_http2 = True
                result.h2_detection_method = "h2c"

        # 4. WebSocket support check
        if check_websocket:
            ws_result = await self._test_websocket(parsed)
            result.supports_websocket = ws_result.get("supported", False)
            result.websocket_paths = ws_result.get("paths", [])

        # 5. Keep-alive and pipelining test
        conn_result = await self._test_connection_behavior(parsed)
        result.supports_keepalive = conn_result.get("keepalive", True)
        result.supports_pipelining = conn_result.get("pipelining", False)

        return result

    async def _detect_alpn_protocols(self, parsed: ParsedURL) -> Dict[str, Any]:
        """Detect ALL supported ALPN protocols by testing each individually.

        Tests each protocol separately to get accurate support detection,
        since servers may prefer one protocol when offered multiple options.

        Args:
            parsed: Parsed URL

        Returns:
            Dict with 'protocols' list, 'selected' protocol, 'alpn_supported' flag
        """
        result = {
            "protocols": [],
            "selected": None,
            "alpn_supported": False,
            "tls_version": None,
        }

        detected_protocols: Set[str] = set()

        # Test protocols individually - this is critical!
        # Testing h2 first ensures we detect HTTP/2 support even if server prefers http/1.1
        protocol_tests = [
            ["h2"],           # Test HTTP/2 explicitly first
            ["http/1.1"],     # Test HTTP/1.1 explicitly
            ["h2", "http/1.1"],  # Test preference when both offered
        ]

        for alpn_list in protocol_tests:
            try:
                selected, tls_version = await self._negotiate_alpn_single(
                    parsed.host, parsed.port, alpn_list
                )
                
                if selected:
                    result["alpn_supported"] = True
                    detected_protocols.add(selected)
                    
                    if result["tls_version"] is None:
                        result["tls_version"] = tls_version

                    # When testing single protocol, matching response means support
                    if len(alpn_list) == 1 and selected == alpn_list[0]:
                        detected_protocols.add(selected)
                    
                    # Prefer h2 as the "selected" protocol if supported
                    if selected == "h2":
                        result["selected"] = "h2"
                    elif result["selected"] is None:
                        result["selected"] = selected

            except asyncio.TimeoutError:
                continue
            except ssl.SSLError as e:
                # Some servers reject connections with certain ALPN offerings
                # This is fine - just means that protocol isn't supported
                continue
            except Exception:
                continue

        result["protocols"] = sorted(list(detected_protocols))
        return result

    async def _negotiate_alpn_single(
        self, host: str, port: int, protocols: List[str]
    ) -> Tuple[Optional[str], Optional[str]]:
        """Perform single ALPN negotiation attempt.

        Args:
            host: Target host
            port: Target port
            protocols: ALPN protocols to offer

        Returns:
            Tuple of (selected_protocol, tls_version)
        """
        context = self._create_ssl_context(alpn_protocols=protocols, require_tls_1_2=True)

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=context, server_hostname=host),
                timeout=self.config.connect_timeout,
            )

            # Get SSL info
            ssl_object = writer.get_extra_info("ssl_object")
            selected = None
            tls_version = None
            
            if ssl_object:
                selected = ssl_object.selected_alpn_protocol()
                try:
                    tls_version = ssl_object.version()
                except Exception:
                    pass

            writer.close()
            await writer.wait_closed()

            return selected, tls_version

        except asyncio.TimeoutError:
            raise
        except ssl.SSLError:
            raise
        except Exception:
            return None, None

    async def _verify_http2_direct(self, parsed: ParsedURL) -> bool:
        """Verify HTTP/2 support by attempting direct HTTP/2 connection.

        This bypasses ALPN and sends HTTP/2 preface directly to check
        if the server can handle HTTP/2 traffic.

        Args:
            parsed: Parsed URL

        Returns:
            True if server responds with valid HTTP/2 SETTINGS frame
        """
        # Offer h2 via ALPN but still test even if not negotiated
        context = self._create_ssl_context(
            alpn_protocols=["h2", "http/1.1"], require_tls_1_2=True
        )

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    parsed.host, parsed.port, ssl=context, server_hostname=parsed.host
                ),
                timeout=self.config.connect_timeout,
            )

            # Check if ALPN negotiated h2
            ssl_object = writer.get_extra_info("ssl_object")
            alpn_selected = ssl_object.selected_alpn_protocol() if ssl_object else None

            # If h2 was selected via ALPN, verify with preface
            # If not selected, still try - some servers support h2 without ALPN
            
            # Send HTTP/2 connection preface + SETTINGS
            writer.write(H2_CONNECTION_PREFACE + H2_EMPTY_SETTINGS)
            await writer.drain()

            # Read response - expect SETTINGS frame
            try:
                response = await asyncio.wait_for(
                    reader.read(256),
                    timeout=5.0,
                )

                # Check for valid HTTP/2 frame
                if self._is_valid_h2_settings_response(response):
                    writer.close()
                    await writer.wait_closed()
                    return True

            except asyncio.TimeoutError:
                pass

            writer.close()
            await writer.wait_closed()
            return alpn_selected == "h2"  # Trust ALPN if preface verification times out

        except Exception:
            return False

    async def _verify_http2_handshake(self, parsed: ParsedURL) -> bool:
        """Verify HTTP/2 works by completing full handshake.

        Args:
            parsed: Parsed URL

        Returns:
            True if HTTP/2 handshake completes successfully
        """
        context = self._create_ssl_context(alpn_protocols=["h2"], require_tls_1_2=True)

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    parsed.host, parsed.port, ssl=context, server_hostname=parsed.host
                ),
                timeout=self.config.connect_timeout,
            )

            # Verify ALPN selected h2
            ssl_object = writer.get_extra_info("ssl_object")
            if not ssl_object or ssl_object.selected_alpn_protocol() != "h2":
                writer.close()
                await writer.wait_closed()
                return False

            # Send HTTP/2 connection preface + SETTINGS
            writer.write(H2_CONNECTION_PREFACE + H2_EMPTY_SETTINGS)
            await writer.drain()

            # Read server's response (should be SETTINGS frame)
            try:
                response = await asyncio.wait_for(
                    reader.read(256),
                    timeout=5.0,
                )

                if self._is_valid_h2_settings_response(response):
                    writer.close()
                    await writer.wait_closed()
                    return True

            except asyncio.TimeoutError:
                # Some servers delay SETTINGS - if ALPN worked, consider it verified
                writer.close()
                await writer.wait_closed()
                return True

            writer.close()
            await writer.wait_closed()
            return False

        except Exception:
            return False

    def _is_valid_h2_settings_response(self, response: bytes) -> bool:
        """Check if response contains valid HTTP/2 SETTINGS frame.

        Args:
            response: Raw response bytes

        Returns:
            True if valid SETTINGS frame found
        """
        if len(response) < 9:
            return False

        try:
            # HTTP/2 frame format:
            # - Length: 3 bytes
            # - Type: 1 byte
            # - Flags: 1 byte
            # - Stream ID: 4 bytes (R + 31 bits)

            # Parse frame header
            frame_length = (response[0] << 16) | (response[1] << 8) | response[2]
            frame_type = response[3]
            stream_id = struct.unpack(">I", response[5:9])[0] & 0x7FFFFFFF

            # SETTINGS frame: type 0x04, stream ID 0
            if frame_type == H2_FRAME_SETTINGS and stream_id == 0:
                return True

            # GOAWAY frame also indicates HTTP/2 (even if rejecting)
            if frame_type == H2_FRAME_GOAWAY:
                return True

            return False

        except Exception:
            return False

    async def _detect_npn_protocols(self, parsed: ParsedURL) -> Dict[str, Any]:
        """Detect NPN (Next Protocol Negotiation) protocols.

        NPN is deprecated but some older servers still use it.

        Args:
            parsed: Parsed URL

        Returns:
            Dict with 'protocols' list and 'npn_supported' flag
        """
        result = {"protocols": [], "npn_supported": False}

        # NPN is largely deprecated and not well supported in modern Python
        # We'll try to detect it via TLS extension
        try:
            context = self._create_ssl_context(require_tls_1_2=False)

            # Check if NPN is available (deprecated in Python 3.10+)
            if hasattr(context, 'set_npn_protocols'):
                context.set_npn_protocols(["h2", "http/1.1"])
                
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        parsed.host, parsed.port, ssl=context, server_hostname=parsed.host
                    ),
                    timeout=self.config.connect_timeout,
                )

                ssl_object = writer.get_extra_info("ssl_object")
                if ssl_object and hasattr(ssl_object, 'selected_npn_protocol'):
                    selected = ssl_object.selected_npn_protocol()
                    if selected:
                        result["npn_supported"] = True
                        result["protocols"].append(selected)

                writer.close()
                await writer.wait_closed()

        except Exception:
            pass

        return result

    async def _get_server_info(self, parsed: ParsedURL) -> Dict[str, Optional[str]]:
        """Get server information from HTTP response headers."""
        result: Dict[str, Optional[str]] = {
            "server": None,
            "via": None,
            "x-powered-by": None,
            "x-served-by": None,
        }

        request = (
            f"HEAD {parsed.path} HTTP/1.1\r\n"
            f"Host: {parsed.host_header}\r\n"
            f"Connection: close\r\n"
            f"User-Agent: Mozilla/5.0 (compatible; HTTPSmuggler/1.0)\r\n"
            f"\r\n"
        ).encode()

        try:
            if parsed.use_ssl:
                context = self._create_ssl_context(require_tls_1_2=False)
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(parsed.host, parsed.port, ssl=context),
                    timeout=self.config.connect_timeout,
                )
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(parsed.host, parsed.port),
                    timeout=self.config.connect_timeout,
                )

            writer.write(request)
            await writer.drain()

            response = await asyncio.wait_for(
                reader.read(8192),
                timeout=self.config.read_timeout,
            )

            writer.close()
            await writer.wait_closed()

            headers = self._parse_response_headers(response)
            for key in list(result.keys()):
                result[key] = headers.get(key)

        except Exception:
            pass

        return result

    async def _test_h2c_upgrade(self, parsed: ParsedURL) -> bool:
        """Test if server supports h2c (HTTP/2 Cleartext) upgrade.

        Args:
            parsed: Parsed URL

        Returns:
            True if h2c is supported
        """
        # h2c upgrade request with proper HTTP2-Settings
        request = (
            f"GET {parsed.path} HTTP/1.1\r\n"
            f"Host: {parsed.host_header}\r\n"
            f"Connection: Upgrade, HTTP2-Settings\r\n"
            f"Upgrade: h2c\r\n"
            f"HTTP2-Settings: AAMAAABkAAQCAAAAAAIAAAAA\r\n"
            f"User-Agent: Mozilla/5.0 (compatible; HTTPSmuggler/1.0)\r\n"
            f"\r\n"
        ).encode()

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(parsed.host, parsed.port),
                timeout=self.config.connect_timeout,
            )

            writer.write(request)
            await writer.drain()

            response = await asyncio.wait_for(
                reader.read(8192),
                timeout=self.config.read_timeout,
            )

            writer.close()
            await writer.wait_closed()

            # Check for 101 Switching Protocols with Upgrade: h2c
            response_str = response.decode("utf-8", errors="replace")
            if "101" in response_str:
                response_lower = response_str.lower()
                return "upgrade" in response_lower and "h2c" in response_lower
            
            return False

        except Exception:
            return False

    async def _test_websocket(self, parsed: ParsedURL) -> Dict[str, Any]:
        """Test WebSocket support on various paths.

        Args:
            parsed: Parsed URL

        Returns:
            Dict with 'supported' bool and 'paths' list
        """
        result = {"supported": False, "paths": []}

        for ws_path in self.WEBSOCKET_PATHS:
            if await self._test_websocket_path(parsed, ws_path):
                result["supported"] = True
                result["paths"].append(ws_path)

        return result

    async def _test_websocket_path(self, parsed: ParsedURL, path: str) -> bool:
        """Test WebSocket support on a specific path.

        Args:
            parsed: Parsed URL
            path: WebSocket path to test

        Returns:
            True if WebSocket handshake is accepted or returns expected upgrade response
        """
        import base64
        import os

        # Generate random WebSocket key
        ws_key = base64.b64encode(os.urandom(16)).decode()

        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {parsed.host_header}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {ws_key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"Origin: {parsed.origin}\r\n"
            f"\r\n"
        ).encode()

        try:
            if parsed.use_ssl:
                context = self._create_ssl_context(require_tls_1_2=False)
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(parsed.host, parsed.port, ssl=context),
                    timeout=self.config.connect_timeout,
                )
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(parsed.host, parsed.port),
                    timeout=self.config.connect_timeout,
                )

            writer.write(request)
            await writer.drain()

            response = await asyncio.wait_for(
                reader.read(4096),
                timeout=self.config.read_timeout,
            )

            writer.close()
            await writer.wait_closed()

            response_str = response.decode("utf-8", errors="replace")

            # 101 = WebSocket handshake accepted
            # 426 = Upgrade required (WebSocket endpoint exists but needs proper handshake)
            # Both indicate WebSocket support
            return "101" in response_str or "426" in response_str

        except Exception:
            return False

    async def _test_connection_behavior(self, parsed: ParsedURL) -> Dict[str, bool]:
        """Test connection keep-alive and pipelining support.

        Args:
            parsed: Parsed URL

        Returns:
            Dict with 'keepalive' and 'pipelining' booleans
        """
        result = {"keepalive": True, "pipelining": False}

        # Test keep-alive
        request = (
            f"GET {parsed.path} HTTP/1.1\r\n"
            f"Host: {parsed.host_header}\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
        ).encode()

        try:
            if parsed.use_ssl:
                context = self._create_ssl_context(require_tls_1_2=False)
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(parsed.host, parsed.port, ssl=context),
                    timeout=self.config.connect_timeout,
                )
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(parsed.host, parsed.port),
                    timeout=self.config.connect_timeout,
                )

            writer.write(request)
            await writer.drain()

            response = await asyncio.wait_for(
                reader.read(8192),
                timeout=self.config.read_timeout,
            )

            headers = self._parse_response_headers(response)
            connection = headers.get("connection", "").lower()

            # Check if connection stays open
            result["keepalive"] = connection != "close"

            # Test pipelining by sending second request immediately
            if result["keepalive"]:
                try:
                    writer.write(request)
                    await writer.drain()

                    response2 = await asyncio.wait_for(
                        reader.read(8192),
                        timeout=2.0,  # Short timeout for pipelining test
                    )

                    # If we get a valid response, pipelining works
                    if response2 and b"HTTP/1.1" in response2:
                        result["pipelining"] = True

                except Exception:
                    pass

            writer.close()
            await writer.wait_closed()

        except Exception:
            pass

        return result

    def _parse_response_headers(self, response: bytes) -> Dict[str, str]:
        """Parse HTTP response headers.

        Args:
            response: Raw HTTP response

        Returns:
            Dict of header name to value (lowercase keys)
        """
        headers = {}

        try:
            if b"\r\n\r\n" in response:
                header_section = response.split(b"\r\n\r\n")[0]
            else:
                header_section = response

            lines = header_section.split(b"\r\n")

            for line in lines[1:]:  # Skip status line
                if b":" in line:
                    key, value = line.split(b":", 1)
                    key = key.decode("utf-8", errors="replace").strip().lower()
                    value = value.decode("utf-8", errors="replace").strip()
                    headers[key] = value

        except Exception:
            pass

        return headers

    def _identify_proxy_type(
        self, server_info: Dict[str, Optional[str]]
    ) -> Optional[str]:
        """Identify proxy type from server headers.

        Args:
            server_info: Server info headers

        Returns:
            Proxy type name or None
        """
        via = (server_info.get("via") or "").lower()
        server = (server_info.get("server") or "").lower()

        proxy_signatures = {
            "cloudflare": ["cloudflare"],
            "akamai": ["akamai", "akamai-ghost"],
            "aws-alb": ["awselb", "amazon"],
            "aws-cloudfront": ["cloudfront", "amz-cf"],
            "nginx": ["nginx"],
            "haproxy": ["haproxy"],
            "varnish": ["varnish"],
            "squid": ["squid"],
            "apache": ["apache"],
            "envoy": ["envoy"],
            "traefik": ["traefik"],
        }

        combined = f"{via} {server}"

        for proxy_name, signatures in proxy_signatures.items():
            for sig in signatures:
                if sig in combined:
                    return proxy_name

        return None


async def detect_protocols(
    url: str,
    config: Optional[NetworkConfig] = None,
) -> ProtocolProfile:
    """Convenience function to detect protocols for a URL.

    Args:
        url: Target URL
        config: Optional network configuration

    Returns:
        ProtocolProfile with detected capabilities
    """
    detector = ProtocolDetector(config)
    result = await detector.detect(url)
    return result.to_protocol_profile()
