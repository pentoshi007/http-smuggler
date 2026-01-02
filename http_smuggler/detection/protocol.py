"""Protocol detection for HTTP Smuggler.

Detects supported protocols (HTTP/1.1, HTTP/2, WebSocket) and server characteristics
through ALPN negotiation, h2c upgrade testing, and WebSocket handshake testing.
"""

import ssl
import socket
import asyncio
from typing import Optional, List, Dict, Any, Tuple
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
    
    async def detect(
        self,
        url: str,
        check_websocket: bool = True,
        check_h2c: bool = True,
    ) -> ProtocolDetectionResult:
        """Detect protocols supported by target.
        
        Args:
            url: Target URL
            check_websocket: Whether to check WebSocket support
            check_h2c: Whether to check h2c upgrade support
        
        Returns:
            ProtocolDetectionResult with all detected capabilities
        """
        parsed = parse_url(url)
        result = ProtocolDetectionResult()
        
        # 1. ALPN negotiation (for HTTPS)
        if parsed.use_ssl:
            alpn_result = await self._detect_alpn(parsed)
            result.alpn_protocols = alpn_result.get("protocols", [])
            result.selected_alpn = alpn_result.get("selected")
            result.supports_http2 = "h2" in result.alpn_protocols
        
        # 2. Initial HTTP request for server info
        server_info = await self._get_server_info(parsed)
        result.server_header = server_info.get("server")
        result.via_header = server_info.get("via")
        result.x_powered_by = server_info.get("x-powered-by")
        result.is_proxied = result.via_header is not None
        
        # Detect proxy type from headers
        if result.is_proxied:
            result.proxy_type = self._identify_proxy_type(server_info)
        
        # 3. h2c upgrade test (for HTTP)
        if check_h2c and not parsed.use_ssl:
            result.supports_h2c = await self._test_h2c_upgrade(parsed)
        
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
    
    async def _detect_alpn(self, parsed: ParsedURL) -> Dict[str, Any]:
        """Detect supported ALPN protocols.
        
        Args:
            parsed: Parsed URL
        
        Returns:
            Dict with 'protocols' list and 'selected' protocol
        """
        result = {"protocols": [], "selected": None}
        
        # Test with h2 preference
        for alpn_list in [["h2", "http/1.1"], ["http/1.1"]]:
            try:
                selected = await self._negotiate_alpn(
                    parsed.host, 
                    parsed.port, 
                    alpn_list
                )
                if selected and selected not in result["protocols"]:
                    result["protocols"].append(selected)
                if result["selected"] is None:
                    result["selected"] = selected
            except Exception:
                pass
        
        return result
    
    async def _negotiate_alpn(
        self, 
        host: str, 
        port: int, 
        protocols: List[str]
    ) -> Optional[str]:
        """Perform ALPN negotiation.
        
        Args:
            host: Target host
            port: Target port
            protocols: ALPN protocols to offer
        
        Returns:
            Selected protocol or None
        """
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.set_alpn_protocols(protocols)
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host, port, ssl=context, server_hostname=host
                ),
                timeout=self.config.connect_timeout,
            )
            
            # Get selected protocol
            ssl_object = writer.get_extra_info('ssl_object')
            selected = ssl_object.selected_alpn_protocol() if ssl_object else None
            
            writer.close()
            await writer.wait_closed()
            
            return selected
            
        except asyncio.TimeoutError:
            raise ConnectionTimeoutError(host, port, self.config.connect_timeout, "alpn")
        except ssl.SSLError as e:
            raise SSLError(host, str(e))
        except Exception:
            return None
    
    async def _get_server_info(self, parsed: ParsedURL) -> Dict[str, Optional[str]]:
        """Get server information from HTTP response headers.
        
        Args:
            parsed: Parsed URL
        
        Returns:
            Dict with server info headers
        """
        result = {
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
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        parsed.host, parsed.port, ssl=context
                    ),
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
            
            # Parse headers
            headers = self._parse_response_headers(response)
            for key in result.keys():
                result[key] = headers.get(key)
            
        except Exception:
            pass
        
        return result
    
    async def _test_h2c_upgrade(self, parsed: ParsedURL) -> bool:
        """Test if server supports h2c upgrade.
        
        Args:
            parsed: Parsed URL
        
        Returns:
            True if h2c is supported
        """
        # h2c upgrade request
        request = (
            f"GET {parsed.path} HTTP/1.1\r\n"
            f"Host: {parsed.host_header}\r\n"
            f"Connection: Upgrade, HTTP2-Settings\r\n"
            f"Upgrade: h2c\r\n"
            f"HTTP2-Settings: AAMAAABkAAQCAAAAAAIAAAAA\r\n"  # Base64 encoded settings
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
            
            # Check for 101 Switching Protocols
            response_str = response.decode("utf-8", errors="replace")
            return "101" in response_str and "upgrade" in response_str.lower()
            
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
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        parsed.host, parsed.port, ssl=context
                    ),
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
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        parsed.host, parsed.port, ssl=context
                    ),
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
    
    def _identify_proxy_type(self, server_info: Dict[str, Optional[str]]) -> Optional[str]:
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

