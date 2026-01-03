"""Timing-based detection for HTTP request smuggling.

Timing detection is the safest detection method as it:
- Doesn't affect other users' sessions
- Uses single requests (no request pairing needed)
- Detects vulnerability through timeout behavior

A target is potentially vulnerable if a smuggling payload causes
significantly longer response times than baseline requests.
"""

import asyncio
import time
from typing import Optional, List, Tuple
from dataclasses import dataclass, field
from statistics import mean, stdev

from http_smuggler.core.config import SafetyConfig, NetworkConfig
from http_smuggler.core.models import DetectionResult, DetectionMethod, SmugglingVariant
from http_smuggler.core.exceptions import (
    ConnectionError,
    ConnectionTimeoutError,
    TimingDetectionError,
)
from http_smuggler.network.raw_socket import AsyncRawHttpClient, RawResponse
from http_smuggler.payloads.generator import Payload, PayloadCategory
from http_smuggler.utils.helpers import parse_url, TimingStats


@dataclass
class BaselineResult:
    """Results from baseline timing measurement."""
    avg_time: float
    min_time: float
    max_time: float
    std_dev: float
    samples: List[float] = field(default_factory=list)
    
    def is_timeout(self, response_time: float, threshold_multiplier: float = 3.0) -> bool:
        """Check if a response time indicates a timeout.
        
        Args:
            response_time: Measured response time
            threshold_multiplier: How many standard deviations above avg
        
        Returns:
            True if response time indicates timeout
        """
        # Use multiple criteria
        # 1. Much longer than average
        if response_time > self.avg_time * 5:
            return True
        
        # 2. More than threshold_multiplier std devs above mean
        if self.std_dev > 0:
            z_score = (response_time - self.avg_time) / self.std_dev
            if z_score > threshold_multiplier:
                return True
        
        # 3. Absolute timeout threshold (5+ seconds)
        if response_time >= 5.0 and response_time > self.max_time * 2:
            return True
        
        return False


class TimingDetector:
    """Timing-based HTTP smuggling detector.
    
    Uses timeout behavior to detect potential vulnerabilities.
    If a payload causes the server to wait (timeout), it suggests
    the server is parsing the request differently than expected.
    """
    
    def __init__(
        self,
        safety_config: Optional[SafetyConfig] = None,
        network_config: Optional[NetworkConfig] = None,
    ):
        self.safety = safety_config or SafetyConfig()
        self.network = network_config or NetworkConfig()
        
        # Detection thresholds
        self.baseline_requests = 5  # Number of requests for baseline (increased for statistical validity)
        self.timeout_threshold = 5.0  # Minimum timeout to consider (seconds)
        self.confidence_threshold = 0.7  # Minimum confidence for positive detection
    
    async def measure_baseline(
        self,
        host: str,
        port: int,
        use_ssl: bool,
        path: str = "/",
    ) -> BaselineResult:
        """Measure baseline response time for normal requests.
        
        Args:
            host: Target host
            port: Target port
            use_ssl: Whether to use SSL/TLS
            path: Request path
        
        Returns:
            BaselineResult with timing statistics
        """
        times = []
        
        # Build a simple baseline request
        baseline_request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Connection: keep-alive\r\n"
            f"User-Agent: Mozilla/5.0 (compatible; HTTPSmuggler/1.0)\r\n"
            f"\r\n"
        ).encode()
        
        for i in range(self.baseline_requests):
            try:
                async with AsyncRawHttpClient(self.network) as client:
                    await client.connect(host, port, use_ssl)
                    
                    start = time.monotonic()
                    response = await client.send_and_receive(
                        baseline_request,
                        receive_timeout=self.safety.timing_detection_timeout,
                    )
                    elapsed = time.monotonic() - start
                    
                    if response.status_code and 200 <= response.status_code < 500:
                        times.append(elapsed)
            except Exception:
                # Skip failed baseline requests
                pass
            
            # Small delay between baseline requests
            await asyncio.sleep(0.1)
        
        if not times:
            # Default baseline if all requests failed
            return BaselineResult(
                avg_time=1.0,
                min_time=0.5,
                max_time=2.0,
                std_dev=0.5,
                samples=[],
            )
        
        avg = mean(times)
        std = stdev(times) if len(times) > 1 else 0.1
        
        return BaselineResult(
            avg_time=avg,
            min_time=min(times),
            max_time=max(times),
            std_dev=std,
            samples=times,
        )
    
    async def detect(
        self,
        payload: Payload,
        host: str,
        port: int,
        use_ssl: bool,
        baseline: Optional[BaselineResult] = None,
    ) -> DetectionResult:
        """Detect potential vulnerability using timing analysis.
        
        Args:
            payload: Smuggling payload to test
            host: Target host
            port: Target port
            use_ssl: Whether to use SSL/TLS
            baseline: Pre-computed baseline (or None to measure)
        
        Returns:
            DetectionResult with vulnerability assessment
        """
        # Get baseline if not provided
        if baseline is None:
            baseline = await self.measure_baseline(host, port, use_ssl)
        
        # Send payload and measure timing
        try:
            async with AsyncRawHttpClient(self.network) as client:
                await client.connect(host, port, use_ssl)
                
                start = time.monotonic()
                response = await client.send_and_receive(
                    payload.raw_request,
                    receive_timeout=self.safety.timing_detection_timeout,
                )
                elapsed = time.monotonic() - start
                
        except ConnectionTimeoutError:
            # Timeout is actually a positive indicator for timing detection!
            elapsed = self.safety.timing_detection_timeout
            response = RawResponse(raw_data=b"", timeout_occurred=True)
        except Exception as e:
            return DetectionResult(
                payload_name=payload.name,
                variant=payload.variant,
                vulnerable=False,
                confidence=0.0,
                response_time=0.0,
                response_status=None,
                evidence=f"Detection failed: {str(e)}",
                detection_method=DetectionMethod.TIMING,
            )
        
        # Analyze timing
        is_timeout = baseline.is_timeout(elapsed)
        is_absolute_timeout = elapsed >= self.timeout_threshold
        timed_out = response.timeout_occurred if hasattr(response, 'timeout_occurred') else False
        
        # Calculate confidence
        confidence = self._calculate_confidence(
            elapsed,
            baseline,
            is_timeout,
            is_absolute_timeout,
            timed_out,
        )
        
        # Build evidence string
        evidence = self._build_evidence(
            elapsed,
            baseline,
            is_timeout,
            response.status_code if response else None,
        )
        
        vulnerable = confidence >= self.confidence_threshold
        
        return DetectionResult(
            payload_name=payload.name,
            variant=payload.variant,
            vulnerable=vulnerable,
            confidence=confidence,
            response_time=elapsed,
            response_status=response.status_code if response else None,
            evidence=evidence,
            detection_method=DetectionMethod.TIMING,
        )
    
    def _calculate_confidence(
        self,
        elapsed: float,
        baseline: BaselineResult,
        is_timeout: bool,
        is_absolute_timeout: bool,
        connection_timed_out: bool,
    ) -> float:
        """Calculate confidence score for timing detection.
        
        Args:
            elapsed: Response time in seconds
            baseline: Baseline timing data
            is_timeout: Whether this exceeds baseline threshold
            is_absolute_timeout: Whether this exceeds absolute threshold
            connection_timed_out: Whether connection actually timed out
        
        Returns:
            Confidence score from 0.0 to 1.0
        """
        confidence = 0.0
        
        # Connection timeout is strong indicator
        if connection_timed_out:
            confidence = 0.9
        
        # Absolute timeout with clean connection is good indicator
        elif is_absolute_timeout and elapsed >= self.timeout_threshold * 2:
            confidence = 0.85
        
        elif is_absolute_timeout:
            confidence = 0.75
        
        # Relative timeout based on baseline
        elif is_timeout:
            # Calculate how many times longer than average
            ratio = elapsed / baseline.avg_time if baseline.avg_time > 0 else 1
            
            if ratio >= 10:
                confidence = 0.8
            elif ratio >= 5:
                confidence = 0.7
            elif ratio >= 3:
                confidence = 0.6
            else:
                confidence = 0.5
        
        # Minor slowdown
        elif elapsed > baseline.avg_time * 2:
            confidence = 0.4
        
        else:
            confidence = 0.1
        
        return min(confidence, 1.0)
    
    def _build_evidence(
        self,
        elapsed: float,
        baseline: BaselineResult,
        is_timeout: bool,
        status_code: Optional[int],
    ) -> str:
        """Build evidence string describing the timing result."""
        parts = []
        
        parts.append(f"Response time: {elapsed:.2f}s")
        parts.append(f"Baseline avg: {baseline.avg_time:.2f}s")
        
        if is_timeout:
            ratio = elapsed / baseline.avg_time if baseline.avg_time > 0 else 0
            parts.append(f"Timeout detected ({ratio:.1f}x baseline)")
        
        if status_code:
            parts.append(f"Status: {status_code}")
        
        if elapsed >= self.timeout_threshold:
            parts.append(f"Exceeds {self.timeout_threshold}s threshold")
        
        return " | ".join(parts)
    
    async def detect_batch(
        self,
        payloads: List[Payload],
        host: str,
        port: int,
        use_ssl: bool,
    ) -> List[DetectionResult]:
        """Detect vulnerabilities using multiple payloads.
        
        Args:
            payloads: List of timing payloads to test
            host: Target host
            port: Target port
            use_ssl: Whether to use SSL/TLS
        
        Returns:
            List of DetectionResults
        """
        # Filter to timing payloads only
        timing_payloads = [
            p for p in payloads
            if p.category == PayloadCategory.TIMING
        ]
        
        if not timing_payloads:
            return []
        
        # Measure baseline once
        baseline = await self.measure_baseline(host, port, use_ssl)
        
        results = []
        
        for payload in timing_payloads:
            result = await self.detect(
                payload,
                host,
                port,
                use_ssl,
                baseline,
            )
            results.append(result)
            
            # Rate limiting between requests
            await asyncio.sleep(self.safety.min_delay_between_tests)
        
        return results


async def timing_detect(
    url: str,
    payloads: List[Payload],
    safety_config: Optional[SafetyConfig] = None,
) -> List[DetectionResult]:
    """Convenience function for timing detection.
    
    Args:
        url: Target URL
        payloads: Payloads to test
        safety_config: Optional safety configuration
    
    Returns:
        List of detection results
    """
    parsed = parse_url(url)
    
    detector = TimingDetector(safety_config)
    
    return await detector.detect_batch(
        payloads,
        parsed.host,
        parsed.port,
        parsed.use_ssl,
    )

