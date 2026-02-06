"""Main smuggling engine for HTTP Smuggler.

Orchestrates the complete scanning workflow:
1. Protocol detection
2. Endpoint discovery (crawling)
3. Payload generation
4. Timing-based detection
5. Differential confirmation
6. Exploitation verification
7. Report generation
"""

import asyncio
from typing import Optional, List, Set, Dict, Any, Tuple
from datetime import datetime
from dataclasses import dataclass

from http_smuggler.core.config import (
    ScanConfig,
    ScanMode,
    OutputFormat,
)
from http_smuggler.core.models import (
    Endpoint,
    ScanResult,
    VulnerabilityReport,
    DetectionResult,
    DetectionMethod,
    ExploitationResult,
    ProtocolProfile,
    SmugglingVariant,
    HttpVersion,
)
from http_smuggler.core.exceptions import (
    ConfigurationError,
    ScanAbortedError,
    WAFDetectedError,
    RateLimitError,
)

from http_smuggler.detection.protocol import ProtocolDetector
from http_smuggler.detection.timing import TimingDetector, BaselineResult
from http_smuggler.detection.differential import DifferentialDetector

from http_smuggler.payloads.generator import Payload, PayloadCategory, CompositePayloadGenerator
from http_smuggler.payloads.classic import (
    CLTEPayloadGenerator,
    TECLPayloadGenerator,
    TETEPayloadGenerator,
)
from http_smuggler.payloads.http2 import (
    H2CLPayloadGenerator,
    H2TEPayloadGenerator,
    H2CRLFPayloadGenerator,
)
from http_smuggler.payloads.websocket import WebSocketVersionPayloadGenerator
from http_smuggler.payloads.advanced import (
    PauseBasedPayloadGenerator,
    ClientSideDesyncPayloadGenerator,
)

from http_smuggler.crawler.spider import DomainCrawler
from http_smuggler.exploits.exploit_runner import ExploitRunner
from http_smuggler.analysis.reporter import Reporter

from http_smuggler.utils.helpers import parse_url
from http_smuggler.utils.logging import ScanLogger
from http_smuggler.core.variant_registry import get_capability, VariantTransport


@dataclass
class ScanProgress:
    """Track scan progress."""
    phase: str
    total_endpoints: int = 0
    tested_endpoints: int = 0
    total_payloads: int = 0
    tested_payloads: int = 0
    vulnerabilities_found: int = 0


class SmugglerEngine:
    """Main engine for HTTP request smuggling detection."""
    
    def __init__(self, config: ScanConfig):
        """Initialize the smuggling engine.
        
        Args:
            config: Scan configuration
        """
        self.config = config
        
        # Validate configuration
        errors = config.validate()
        if errors:
            raise ConfigurationError(errors)
        
        # Initialize components
        self.protocol_detector = ProtocolDetector(config.network)
        self.timing_detector = TimingDetector(
            config.safety,
            config.network,
            confidence_mode=config.confidence_mode.value,
        )
        self.differential_detector = DifferentialDetector(
            config.safety,
            config.network,
            confidence_mode=config.confidence_mode.value,
        )
        self.crawler = DomainCrawler(config.crawl)

        # Initialize exploit runner with auto-listeners enabled in aggressive mode
        auto_listeners = (
            config.auto_listeners
            and config.mode == ScanMode.AGGRESSIVE
            and config.exploit.enabled
        )
        self.exploit_runner = ExploitRunner(
            config.exploit,
            config.safety,
            config.network,
            auto_listeners=auto_listeners,
        )
        self.reporter = Reporter(config.report)
        
        # Initialize payload generators
        self.payload_generator = self._init_generators()
        
        # Logging
        self.logger = ScanLogger(
            verbose=config.verbose,
            quiet=config.quiet,
        )
        
        # State
        self._aborted = False
        self._progress = ScanProgress(phase="init")
        self._baseline_cache: Dict[Tuple[str, str, str], BaselineResult] = {}
        self._skipped: List[Dict[str, str]] = []
        self._skip_index: Set[Tuple[str, str, str]] = set()
    
    def _init_generators(self) -> CompositePayloadGenerator:
        """Initialize payload generators based on config."""
        generator = CompositePayloadGenerator()
        
        enabled = set(self.config.payload.enabled_variants)
        
        # Classic variants
        if SmugglingVariant.CL_TE in enabled:
            generator.add_generator(CLTEPayloadGenerator())
        
        if SmugglingVariant.TE_CL in enabled:
            generator.add_generator(TECLPayloadGenerator())
        
        if SmugglingVariant.TE_TE in enabled:
            generator.add_generator(TETEPayloadGenerator(
                max_obfuscations=self.config.payload.max_te_obfuscations
            ))
        
        # HTTP/2 variants
        if SmugglingVariant.H2_CL in enabled:
            generator.add_generator(H2CLPayloadGenerator())
        
        if SmugglingVariant.H2_TE in enabled:
            generator.add_generator(H2TEPayloadGenerator())
        
        if SmugglingVariant.H2_CRLF in enabled:
            generator.add_generator(H2CRLFPayloadGenerator())
        
        # WebSocket variants
        if SmugglingVariant.WS_VERSION in enabled:
            generator.add_generator(WebSocketVersionPayloadGenerator())
        
        # Advanced variants
        if SmugglingVariant.PAUSE_BASED in enabled:
            generator.add_generator(PauseBasedPayloadGenerator())
        
        if SmugglingVariant.CLIENT_SIDE in enabled:
            generator.add_generator(ClientSideDesyncPayloadGenerator())

        wired_variants = {g.variant for g in generator.generators}
        missing = enabled - wired_variants
        for variant in sorted(missing, key=lambda v: v.value):
            self.config.payload.not_tested_variants.append(
                {
                    "variant": variant.value,
                    "reason": "not_wired_generator",
                    "status": "planned",
                }
            )
            self.config.payload.enabled_variants.discard(variant)
        
        return generator
    
    async def scan(self, target: Optional[str] = None) -> ScanResult:
        """Run a complete scan against the target.
        
        Args:
            target: Target URL (overrides config if provided)
        
        Returns:
            ScanResult with all findings
        """
        target_url = target or self.config.target_url
        if not target_url:
            raise ConfigurationError(["No target URL specified"])
        
        scan_start = datetime.utcnow()
        
        self.logger.scan_start(target_url)
        self._progress = ScanProgress(phase="protocol_detection")
        
        parsed = parse_url(target_url)
        
        # Phase 1: Protocol Detection
        self.logger.info("Detecting supported protocols...")
        protocol_profile = await self._detect_protocols(target_url)
        
        self.logger.protocol_detected(
            protocol_profile.primary_version.value,
            {
                "alpn": protocol_profile.alpn_protocols,
                "h2c": protocol_profile.supports_h2c,
                "websocket": protocol_profile.supports_websocket,
            }
        )

        # Warn about explicitly requested but unimplemented variants.
        for entry in self.config.payload.not_tested_variants:
            self.logger.warning(
                f"Variant {entry.get('variant')} not tested: {entry.get('reason')}"
            )
        
        # Phase 2: Endpoint Discovery
        if self.config.skip_crawl or self.config.target_endpoints:
            endpoints = self._get_manual_endpoints(target_url)
        else:
            self._progress.phase = "crawling"
            self.logger.info("Crawling domain for endpoints...")
            endpoints = await self._discover_endpoints(target_url)

        self._progress.total_endpoints = len(endpoints)
        self.logger.info(f"Found {len(endpoints)} endpoints to test")

        # Phase 3-5: Test Each Endpoint
        self._progress.phase = "testing"
        vulnerabilities = []
        
        for endpoint in endpoints:
            if self._aborted:
                break
            
            self.logger.endpoint_testing(endpoint.url)
            self._progress.tested_endpoints += 1
            
            endpoint_vulns = await self._test_endpoint(
                endpoint,
                protocol_profile,
                parsed.host,
                parsed.port,
                parsed.use_ssl,
            )
            
            vulnerabilities.extend(endpoint_vulns)
        
        scan_end = datetime.utcnow()
        duration = (scan_end - scan_start).total_seconds()

        self._progress.phase = "complete"
        self.logger.scan_complete(duration)

        # Cleanup auto-listeners
        if self.exploit_runner.auto_listeners:
            listener_info = self.exploit_runner.get_listener_info()
            if listener_info.get("active"):
                self.logger.info(
                    f"Auto-listeners used: {', '.join(listener_info['active'])}"
                )
            self.exploit_runner.cleanup_listeners()

        return ScanResult(
            target=target_url,
            scan_start=scan_start,
            scan_end=scan_end,
            protocol_profile=protocol_profile,
            endpoints_discovered=len(endpoints),
            endpoints_tested=self._progress.tested_endpoints,
            vulnerabilities=vulnerabilities,
            not_tested=self.config.payload.not_tested_variants,
            skipped=self._skipped,
        )
    
    async def _detect_protocols(self, url: str) -> ProtocolProfile:
        """Detect protocols supported by target."""
        try:
            result = await self.protocol_detector.detect(
                url,
                check_websocket=SmugglingVariant.WS_VERSION in self.config.payload.enabled_variants,
                check_h2c=not parse_url(url).use_ssl,
            )
            return result.to_protocol_profile()
        except Exception as e:
            self.logger.error(f"Protocol detection failed: {e}")
            # Return default profile
            return ProtocolProfile(
                primary_version=HttpVersion.HTTP_1_1,
                alpn_protocols=["http/1.1"],
                supports_h2c=False,
                supports_websocket=False,
                supports_keepalive=True,
                server_header=None,
                via_header=None,
            )
    
    async def _discover_endpoints(self, url: str) -> List[Endpoint]:
        """Discover endpoints via crawling."""
        try:
            result = await self.crawler.crawl(url)
            
            if result.errors:
                for error in result.errors[:5]:  # Log first 5 errors
                    self.logger.debug(f"Crawl error: {error}")
            
            return result.endpoints
        except Exception as e:
            self.logger.error(f"Crawling failed: {e}")
            # Return just the target URL
            return [Endpoint(url=url, method="GET")]
    
    def _get_manual_endpoints(self, target_url: str) -> List[Endpoint]:
        """Get manually specified endpoints."""
        if self.config.target_endpoints:
            return [
                Endpoint(url=ep, method="POST", accepts_body=True)
                for ep in self.config.target_endpoints
            ]
        return [Endpoint(url=target_url, method="POST", accepts_body=True)]
    
    async def _test_endpoint(
        self,
        endpoint: Endpoint,
        protocol: ProtocolProfile,
        host: str,
        port: int,
        use_ssl: bool,
    ) -> List[VulnerabilityReport]:
        """Test a single endpoint for smuggling vulnerabilities."""
        vulnerabilities = []
        endpoint_parsed = parse_url(endpoint.url)
        request_path = endpoint_parsed.full_path
        
        # Generate payloads for this endpoint
        payloads = self.payload_generator.generate_all(
            endpoint,
            list(self.config.payload.enabled_variants),
        )
        
        self._progress.total_payloads += len(payloads)
        
        # Group payloads by variant for organized testing
        payloads_by_variant: Dict[SmugglingVariant, List[Payload]] = {}
        for payload in payloads:
            if payload.variant not in payloads_by_variant:
                payloads_by_variant[payload.variant] = []
            payloads_by_variant[payload.variant].append(payload)
        
        for variant, variant_payloads in payloads_by_variant.items():
            if self._aborted:
                break
            
            # Filter based on scan mode
            if self.config.mode == ScanMode.PASSIVE:
                self._record_skip(endpoint.url, variant, "passive_mode")
                continue

            applicable, reason = self._is_variant_applicable(
                variant,
                protocol,
                use_ssl,
            )
            if not applicable:
                self._record_skip(endpoint.url, variant, reason)
                continue
            
            timing_payloads = [
                p for p in variant_payloads
                if p.category == PayloadCategory.TIMING
            ]
            
            differential_payloads = [
                p for p in variant_payloads
                if p.category == PayloadCategory.DIFFERENTIAL
            ]

            best_timing = await self._run_timing_checks(
                endpoint_url=endpoint.url,
                endpoint_method=endpoint.method,
                request_path=request_path,
                timing_payloads=timing_payloads,
                host=host,
                port=port,
                use_ssl=use_ssl,
            )

            best_diff: Optional[Tuple[DetectionResult, Payload]] = None
            if self.config.mode != ScanMode.SAFE and differential_payloads:
                best_diff = await self._run_differential_checks(
                    request_path=request_path,
                    differential_payloads=differential_payloads,
                    host=host,
                    port=port,
                    use_ssl=use_ssl,
                )

            selected: Optional[Tuple[DetectionResult, Payload]] = None
            if best_diff and best_diff[0].vulnerable:
                selected = best_diff
            elif best_timing and best_timing[0].vulnerable:
                selected = best_timing

            if selected:
                detection, payload = selected
                if (
                    self.config.mode == ScanMode.SAFE
                    and detection.detection_method == DetectionMethod.TIMING
                ):
                    vuln = self._build_timing_vulnerability(
                        endpoint,
                        detection,
                        payload,
                    )
                else:
                    vuln = await self._build_vulnerability(
                        endpoint,
                        detection,
                        payload,
                        host,
                        port,
                        use_ssl,
                    )
                vulnerabilities.append(vuln)
                self._progress.vulnerabilities_found += 1
            elif not timing_payloads and not differential_payloads:
                self._record_skip(endpoint.url, variant, "no_payloads")
        
        return vulnerabilities
    
    async def _run_timing_checks(
        self,
        endpoint_url: str,
        endpoint_method: str,
        request_path: str,
        timing_payloads: List[Payload],
        host: str,
        port: int,
        use_ssl: bool,
    ) -> Optional[Tuple[DetectionResult, Payload]]:
        """Run timing payload checks and return the best candidate result."""
        if not timing_payloads:
            return None

        best: Optional[Tuple[DetectionResult, Payload]] = None
        for payload in timing_payloads:
            if self._aborted:
                break
            self._progress.tested_payloads += 1
            self.logger.payload_sent(payload.name, payload.variant.value)

            baseline = await self._get_or_create_baseline(
                endpoint_url=endpoint_url,
                method=endpoint_method,
                request_path=request_path,
                transport=payload.transport,
                host=host,
                port=port,
                use_ssl=use_ssl,
            )
            result = await self._confirm_timing_payload(
                payload=payload,
                host=host,
                port=port,
                use_ssl=use_ssl,
                baseline=baseline,
                request_path=request_path,
            )

            if best is None or result.confidence > best[0].confidence:
                best = (result, payload)

            if result.vulnerable:
                self.logger.timing_result(
                    endpoint_url,
                    self.timing_detector.timeout_threshold,
                    result.response_time,
                    True,
                )

            await asyncio.sleep(self.config.safety.min_delay_between_tests)
        return best

    async def _run_differential_checks(
        self,
        request_path: str,
        differential_payloads: List[Payload],
        host: str,
        port: int,
        use_ssl: bool,
    ) -> Optional[Tuple[DetectionResult, Payload]]:
        """Run differential payload checks and return the best candidate result."""
        if not differential_payloads:
            return None

        best: Optional[Tuple[DetectionResult, Payload]] = None
        for payload in differential_payloads:
            if self._aborted:
                break
            self._progress.tested_payloads += 1
            self.logger.payload_sent(payload.name, payload.variant.value)
            try:
                result = await self.differential_detector.detect(
                    payload,
                    host,
                    port,
                    use_ssl,
                    victim_path=request_path,
                )
            except Exception as e:
                self.logger.debug(f"Differential detection failed for {payload.name}: {e}")
                continue

            result = await self._confirm_differential_result(
                payload=payload,
                first_result=result,
                host=host,
                port=port,
                use_ssl=use_ssl,
                request_path=request_path,
            )

            if best is None or result.confidence > best[0].confidence:
                best = (result, payload)

            await asyncio.sleep(self.config.safety.min_delay_between_tests)
        return best

    async def _confirm_timing_payload(
        self,
        payload: Payload,
        host: str,
        port: int,
        use_ssl: bool,
        baseline: BaselineResult,
        request_path: str,
    ) -> DetectionResult:
        """Run confirmation attempts for timing payloads."""
        attempts = max(1, self.config.confirm_attempts)
        positives = 0
        best: Optional[DetectionResult] = None

        for attempt in range(attempts):
            result = await self.timing_detector.detect(
                payload,
                host,
                port,
                use_ssl,
                baseline=baseline,
                request_path=request_path,
            )
            if best is None or result.confidence > best.confidence:
                best = result
            if result.vulnerable:
                positives += 1
            if attempt < attempts - 1:
                await asyncio.sleep(0.1)

        assert best is not None
        required = 1 if attempts == 1 else (attempts // 2) + 1
        best.vulnerable = positives >= required
        return best

    async def _confirm_differential_result(
        self,
        payload: Payload,
        first_result: DetectionResult,
        host: str,
        port: int,
        use_ssl: bool,
        request_path: str,
    ) -> DetectionResult:
        """Run confirmation attempts for differential payloads."""
        attempts = max(1, self.config.confirm_attempts)
        positives = 1 if first_result.vulnerable else 0
        best = first_result

        for attempt in range(1, attempts):
            result = await self.differential_detector.detect(
                payload,
                host,
                port,
                use_ssl,
                victim_path=request_path,
            )
            if result.confidence > best.confidence:
                best = result
            if result.vulnerable:
                positives += 1
            if attempt < attempts - 1:
                await asyncio.sleep(0.1)

        required = 1 if attempts == 1 else (attempts // 2) + 1
        best.vulnerable = positives >= required
        return best

    async def _get_or_create_baseline(
        self,
        endpoint_url: str,
        method: str,
        request_path: str,
        transport: str,
        host: str,
        port: int,
        use_ssl: bool,
    ) -> BaselineResult:
        """Fetch baseline from cache or measure it."""
        cache_key = (endpoint_url, method, transport)
        if cache_key not in self._baseline_cache:
            self._baseline_cache[cache_key] = await self.timing_detector.measure_baseline(
                host=host,
                port=port,
                use_ssl=use_ssl,
                path=request_path,
                transport=transport,
            )
        return self._baseline_cache[cache_key]

    def _record_skip(
        self,
        endpoint: str,
        variant: SmugglingVariant,
        reason: str,
    ) -> None:
        """Record variant/endpoint skips for reporting."""
        dedupe_key = (endpoint, variant.value, reason)
        if dedupe_key in self._skip_index:
            return
        self._skip_index.add(dedupe_key)
        self._skipped.append(
            {
                "endpoint": endpoint,
                "variant": variant.value,
                "reason": reason,
            }
        )

    def _is_variant_applicable(
        self,
        variant: SmugglingVariant,
        protocol: ProtocolProfile,
        use_ssl: bool,
    ) -> Tuple[bool, str]:
        """Determine if variant transport is applicable to target protocol profile."""
        capability = get_capability(variant)

        if capability.transport == VariantTransport.HTTP2:
            # Current executor implementation supports TLS ALPN h2 only.
            if not use_ssl:
                return False, "http2_tls_required"
            if protocol.primary_version == HttpVersion.HTTP_2:
                return True, ""
            if "h2" in protocol.alpn_protocols:
                return True, ""
            return False, "protocol_not_applicable"

        if capability.transport == VariantTransport.WEBSOCKET:
            if not protocol.supports_websocket:
                return False, "protocol_not_applicable"
            return True, ""

        return True, ""
    
    async def _build_vulnerability(
        self,
        endpoint: Endpoint,
        detection: DetectionResult,
        payload: Payload,
        host: str,
        port: int,
        use_ssl: bool,
    ) -> VulnerabilityReport:
        """Build vulnerability report with optional exploitation."""
        exploitation = None
        
        # Phase 5: Exploitation confirmation (aggressive mode only)
        if self.config.mode == ScanMode.AGGRESSIVE and self.config.exploit.enabled:
            exploit_result = await self.exploit_runner.run_exploits(
                detection, payload, host, port, use_ssl
            )
            exploitation = exploit_result.to_exploitation_result()
            
            if exploitation.successful:
                self.logger.vulnerability_found(
                    detection.variant.value,
                    endpoint.url,
                    detection.confidence,
                    "CRITICAL" if exploitation.successful else "HIGH",
                )
        else:
            self.logger.vulnerability_found(
                detection.variant.value,
                endpoint.url,
                detection.confidence,
                "HIGH",
            )
        
        return VulnerabilityReport(
            endpoint=endpoint.url,
            variant=detection.variant,
            severity="CRITICAL" if exploitation and exploitation.successful else "HIGH",
            detection_result=detection,
            payload_data={
                "name": payload.name,
                "raw": payload.raw_request[:500],  # Truncate for storage
                "description": payload.description,
            },
            exploitation=exploitation,
        )
    
    def _build_timing_vulnerability(
        self,
        endpoint: Endpoint,
        detection: DetectionResult,
        payload: Payload,
    ) -> VulnerabilityReport:
        """Build vulnerability from timing detection only."""
        self.logger.vulnerability_found(
            detection.variant.value,
            endpoint.url,
            detection.confidence,
            "MEDIUM",
        )
        
        return VulnerabilityReport(
            endpoint=endpoint.url,
            variant=detection.variant,
            severity="MEDIUM",  # Lower severity for timing-only
            detection_result=detection,
            payload_data={
                "name": payload.name,
                "raw": payload.raw_request[:500],
                "description": payload.description,
            },
            exploitation=None,
        )
    
    def abort(self) -> None:
        """Abort the current scan."""
        self._aborted = True
        self.logger.warning("Scan abort requested")
    
    @property
    def progress(self) -> ScanProgress:
        """Get current scan progress."""
        return self._progress


async def run_scan(
    target: str,
    mode: ScanMode = ScanMode.NORMAL,
    **kwargs,
) -> ScanResult:
    """Convenience function to run a scan.
    
    Args:
        target: Target URL
        mode: Scan mode
        **kwargs: Additional config options
    
    Returns:
        ScanResult with findings
    """
    config = ScanConfig(
        target_url=target,
        mode=mode,
        **kwargs,
    )
    
    engine = SmugglerEngine(config)
    return await engine.scan()
