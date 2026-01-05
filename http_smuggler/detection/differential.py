"""Differential response detection for HTTP request smuggling.

Differential detection works by:
1. Sending a smuggling payload that poisons the next request
2. Sending a "victim" request on the same connection
3. Checking if victim response is different than expected

If the victim receives a response meant for the smuggled request,
the target is vulnerable to HTTP request smuggling.
"""

import asyncio
import time
from typing import Optional, List, Tuple
from dataclasses import dataclass

from http_smuggler.core.config import SafetyConfig, NetworkConfig
from http_smuggler.core.models import DetectionResult, DetectionMethod, SmugglingVariant
from http_smuggler.core.exceptions import (
    ConnectionError,
    ConnectionTimeoutError,
    DifferentialDetectionError,
)
from http_smuggler.network.raw_socket import AsyncRawHttpClient, RawResponse
from http_smuggler.payloads.generator import Payload, PayloadCategory
from http_smuggler.utils.helpers import parse_url


@dataclass
class DifferentialTestResult:
    """Result of a single differential test."""
    payload_name: str
    variant: SmugglingVariant
    smuggle_response: Optional[RawResponse]
    victim_response: Optional[RawResponse]
    is_poisoned: bool
    confidence: float
    evidence: str


class DifferentialDetector:
    """Differential response detection for smuggling.
    
    Uses request pairs to detect if a smuggling payload can
    affect subsequent requests on the same connection.
    """
    
    # Status codes that indicate poisoning
    POISON_STATUS_CODES = {404, 400, 405, 501}
    
    # Body patterns that indicate poisoning
    POISON_PATTERNS = [
        b"smuggled",
        b"404",
        b"not found",
        b"GPOST",
        b"GGET",
        b"unrecognized method",
        b"bad request",
        b"malformed",
        b"invalid request",
    ]
    
    def __init__(
        self,
        safety_config: Optional[SafetyConfig] = None,
        network_config: Optional[NetworkConfig] = None,
    ):
        self.safety = safety_config or SafetyConfig()
        self.network = network_config or NetworkConfig()

        # Detection settings - lowered threshold for better detection
        self.confidence_threshold = 0.6  # Lowered from 0.7 for more sensitive detection
    
    async def detect(
        self,
        smuggle_payload: Payload,
        host: str,
        port: int,
        use_ssl: bool,
        victim_path: str = "/",
    ) -> DetectionResult:
        """Detect smuggling using differential response analysis.
        
        Args:
            smuggle_payload: Payload to attempt smuggling
            host: Target host
            port: Target port
            use_ssl: Whether to use SSL/TLS
            victim_path: Path for victim request
        
        Returns:
            DetectionResult with vulnerability assessment
        """
        # Build victim request
        victim_request = self._build_victim_request(host, victim_path)
        
        try:
            async with AsyncRawHttpClient(self.network) as client:
                await client.connect(host, port, use_ssl)
                
                # First: Get baseline victim response (clean connection)
                baseline_response = await client.send_and_receive(
                    victim_request,
                    receive_timeout=self.safety.differential_detection_timeout,
                )
                
                # Reconnect for the actual test
                await client.close()
                await client.connect(host, port, use_ssl)
                
                # Step 1: Send smuggle payload
                smuggle_response = await client.send_and_receive(
                    smuggle_payload.raw_request,
                    receive_timeout=self.safety.differential_detection_timeout,
                )

                # CRITICAL FIX: Use longer adaptive delay based on baseline response time
                # The backend needs time to process the smuggled request before we send victim
                # TryHackMe labs and real servers may need 500ms-5s to process
                baseline_time = baseline_response.response_time if baseline_response else 0.5
                # Minimum 0.5s, scale with baseline, cap at 5s
                adaptive_delay = max(0.5, min(baseline_time * 3, 5.0))
                await asyncio.sleep(adaptive_delay)

                # Check if connection is still alive before sending victim request
                # Server may have closed connection or sent RST
                try:
                    # Try to peek at any pending data (buffered responses)
                    # This also validates the connection is still open
                    if hasattr(client, '_reader') and client._reader:
                        # Non-blocking read to flush any pending data
                        try:
                            pending_data = await asyncio.wait_for(
                                client._reader.read(8192),
                                timeout=0.1
                            )
                            if pending_data:
                                # There was buffered data - might be from smuggled request
                                pass
                        except asyncio.TimeoutError:
                            # No pending data, connection is clean
                            pass
                except Exception:
                    # Connection may be closed, try to reconnect
                    try:
                        await client.close()
                        await client.connect(host, port, use_ssl)
                    except Exception:
                        pass

                # Step 2: Send victim request on SAME connection
                victim_response = await client.send_and_receive(
                    victim_request,
                    receive_timeout=self.safety.differential_detection_timeout,
                )
                
        except ConnectionTimeoutError:
            # Timeout might still indicate vulnerability
            return DetectionResult(
                payload_name=smuggle_payload.name,
                variant=smuggle_payload.variant,
                vulnerable=False,
                confidence=0.3,
                response_time=self.safety.differential_detection_timeout,
                response_status=None,
                evidence="Connection timeout during differential test",
                detection_method=DetectionMethod.DIFFERENTIAL,
            )
        except Exception as e:
            return DetectionResult(
                payload_name=smuggle_payload.name,
                variant=smuggle_payload.variant,
                vulnerable=False,
                confidence=0.0,
                response_time=0.0,
                response_status=None,
                evidence=f"Detection failed: {str(e)}",
                detection_method=DetectionMethod.DIFFERENTIAL,
            )
        
        # Analyze results
        test_result = self._analyze_responses(
            smuggle_payload,
            baseline_response,
            smuggle_response,
            victim_response,
        )
        
        return DetectionResult(
            payload_name=test_result.payload_name,
            variant=test_result.variant,
            vulnerable=test_result.is_poisoned and test_result.confidence >= self.confidence_threshold,
            confidence=test_result.confidence,
            response_time=0.0,  # Not timing-based
            response_status=victim_response.status_code if victim_response else None,
            evidence=test_result.evidence,
            detection_method=DetectionMethod.DIFFERENTIAL,
        )
    
    def _build_victim_request(self, host: str, path: str) -> bytes:
        """Build a simple victim request for differential testing."""
        return (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Connection: keep-alive\r\n"
            f"User-Agent: Mozilla/5.0 (compatible; Victim/1.0)\r\n"
            f"\r\n"
        ).encode()
    
    def _analyze_responses(
        self,
        payload: Payload,
        baseline: RawResponse,
        smuggle: RawResponse,
        victim: RawResponse,
    ) -> DifferentialTestResult:
        """Analyze responses to detect poisoning.
        
        Args:
            payload: The smuggling payload used
            baseline: Response from clean victim request
            smuggle: Response from smuggle payload
            victim: Response from victim request after smuggle
        
        Returns:
            DifferentialTestResult with analysis
        """
        is_poisoned = False
        confidence = 0.0
        evidence_parts = []
        
        # Check 1: Status code changed from baseline
        if baseline.status_code and victim.status_code:
            if baseline.status_code != victim.status_code:
                evidence_parts.append(
                    f"Status changed: {baseline.status_code} -> {victim.status_code}"
                )
                
                # Certain status codes strongly indicate poisoning
                if victim.status_code in self.POISON_STATUS_CODES:
                    is_poisoned = True
                    confidence = max(confidence, 0.9)
                else:
                    confidence = max(confidence, 0.6)
        
        # Check 2: Victim got status we expected from smuggle
        # e.g., if we smuggled GET /404, victim should get 404
        if victim.status_code and smuggle.status_code:
            if victim.status_code in self.POISON_STATUS_CODES:
                if victim.status_code != baseline.status_code:
                    is_poisoned = True
                    confidence = max(confidence, 0.85)
                    evidence_parts.append(f"Victim got poison status: {victim.status_code}")
        
        # Check 3: Poison patterns in victim body
        if victim.body:
            victim_body_lower = victim.body.lower()
            for pattern in self.POISON_PATTERNS:
                if pattern.lower() in victim_body_lower:
                    # Check this pattern wasn't in baseline
                    if baseline.body and pattern.lower() not in baseline.body.lower():
                        is_poisoned = True
                        confidence = max(confidence, 0.95)
                        evidence_parts.append(f"Poison pattern found: {pattern.decode()}")
                        break
        
        # Check 4: Smuggled path appears in victim response
        if payload.poison_prefix and victim.body:
            if payload.poison_prefix.encode() in victim.body:
                is_poisoned = True
                confidence = max(confidence, 0.95)
                evidence_parts.append(f"Smuggled path in response: {payload.poison_prefix}")
        
        # Check 5: Response body significantly different
        if baseline.body and victim.body:
            baseline_len = len(baseline.body)
            victim_len = len(victim.body)
            
            if baseline_len > 0:
                ratio = abs(victim_len - baseline_len) / baseline_len
                if ratio > 0.5:  # 50% difference
                    confidence = max(confidence, 0.5)
                    evidence_parts.append(f"Body length changed by {ratio:.0%}")
        
        # Check 6: GPOST/GGET method error
        if victim.body:
            victim_str = victim.body.decode("utf-8", errors="ignore").upper()
            if "GPOST" in victim_str or "GGET" in victim_str:
                is_poisoned = True
                confidence = max(confidence, 0.95)
                evidence_parts.append("GPOST/GGET method error detected")
        
        # Build final evidence string
        if evidence_parts:
            evidence = " | ".join(evidence_parts)
        else:
            evidence = "No poisoning indicators detected"
        
        return DifferentialTestResult(
            payload_name=payload.name,
            variant=payload.variant,
            smuggle_response=smuggle,
            victim_response=victim,
            is_poisoned=is_poisoned,
            confidence=confidence,
            evidence=evidence,
        )
    
    async def detect_batch(
        self,
        payloads: List[Payload],
        host: str,
        port: int,
        use_ssl: bool,
        victim_path: str = "/",
    ) -> List[DetectionResult]:
        """Run differential detection on multiple payloads.
        
        Args:
            payloads: List of differential payloads to test
            host: Target host
            port: Target port
            use_ssl: Whether to use SSL/TLS
            victim_path: Path for victim requests
        
        Returns:
            List of DetectionResults
        """
        # Filter to differential payloads only
        diff_payloads = [
            p for p in payloads
            if p.category == PayloadCategory.DIFFERENTIAL
        ]
        
        if not diff_payloads:
            return []
        
        results = []
        
        for payload in diff_payloads:
            result = await self.detect(
                payload,
                host,
                port,
                use_ssl,
                victim_path,
            )
            results.append(result)
            
            # Rate limiting between tests
            await asyncio.sleep(self.safety.min_delay_between_tests)
        
        return results
    
    async def confirm_vulnerability(
        self,
        payload: Payload,
        host: str,
        port: int,
        use_ssl: bool,
        attempts: int = 3,
    ) -> Tuple[bool, float]:
        """Confirm a vulnerability with multiple attempts.
        
        Args:
            payload: Payload that showed positive
            host: Target host
            port: Target port
            use_ssl: Whether to use SSL/TLS
            attempts: Number of confirmation attempts
        
        Returns:
            Tuple of (confirmed, confidence)
        """
        positive_count = 0
        total_confidence = 0.0
        
        for _ in range(attempts):
            result = await self.detect(payload, host, port, use_ssl)
            
            if result.vulnerable:
                positive_count += 1
                total_confidence += result.confidence
            
            await asyncio.sleep(self.safety.min_delay_between_tests)
        
        # Confirmed if majority of attempts were positive
        confirmed = positive_count >= (attempts // 2 + 1)
        avg_confidence = total_confidence / attempts if attempts > 0 else 0.0
        
        return confirmed, avg_confidence


async def differential_detect(
    url: str,
    payloads: List[Payload],
    safety_config: Optional[SafetyConfig] = None,
) -> List[DetectionResult]:
    """Convenience function for differential detection.
    
    Args:
        url: Target URL
        payloads: Payloads to test
        safety_config: Optional safety configuration
    
    Returns:
        List of detection results
    """
    parsed = parse_url(url)
    
    detector = DifferentialDetector(safety_config)
    
    return await detector.detect_batch(
        payloads,
        parsed.host,
        parsed.port,
        parsed.use_ssl,
        parsed.path,
    )

