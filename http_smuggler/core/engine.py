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
from typing import Optional, List, Set, Dict, Any
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
from http_smuggler.detection.timing import TimingDetector
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
        self.timing_detector = TimingDetector(config.safety, config.network)
        self.differential_detector = DifferentialDetector(config.safety, config.network)
        self.crawler = DomainCrawler(config.crawl)
        self.exploit_runner = ExploitRunner(config.exploit, config.safety, config.network)
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
    
    def _init_generators(self) -> CompositePayloadGenerator:
        """Initialize payload generators based on config."""
        generator = CompositePayloadGenerator()
        
        enabled = self.config.payload.enabled_variants
        
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
        
        # Phase 2: Endpoint Discovery
        if self.config.skip_crawl or self.config.target_endpoints:
            endpoints = self._get_manual_endpoints(target_url)
        else:
            self.logger.info("Crawling domain for endpoints...")
            endpoints = await self._discover_endpoints(target_url)
        
        self._progress.total_endpoints = len(endpoints)
        self.logger.info(f"Found {len(endpoints)} endpoints to test")
        
        # Phase 3-5: Test Each Endpoint
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
        
        self.logger.scan_complete(duration)
        
        return ScanResult(
            target=target_url,
            scan_start=scan_start,
            scan_end=scan_end,
            protocol_profile=protocol_profile,
            endpoints_discovered=len(endpoints),
            endpoints_tested=self._progress.tested_endpoints,
            vulnerabilities=vulnerabilities,
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
                continue  # Skip active testing in passive mode
            
            timing_payloads = [
                p for p in variant_payloads
                if p.category == PayloadCategory.TIMING
            ]
            
            differential_payloads = [
                p for p in variant_payloads
                if p.category == PayloadCategory.DIFFERENTIAL
            ]
            
            # Phase 3: Timing-based detection (always safe)
            for payload in timing_payloads:
                self._progress.tested_payloads += 1
                self.logger.payload_sent(payload.name, variant.value)
                
                timing_result = await self.timing_detector.detect(
                    payload, host, port, use_ssl
                )
                
                if timing_result.vulnerable:
                    self.logger.timing_result(
                        endpoint.url,
                        self.timing_detector.timeout_threshold,
                        timing_result.response_time,
                        True,
                    )
                    
                    # Phase 4: Differential confirmation (if not safe mode)
                    if self.config.mode != ScanMode.SAFE and differential_payloads:
                        diff_result = await self._confirm_with_differential(
                            differential_payloads[0],
                            host, port, use_ssl,
                        )
                        
                        if diff_result and diff_result.vulnerable:
                            vuln = await self._build_vulnerability(
                                endpoint,
                                diff_result,
                                payload,
                                host, port, use_ssl,
                            )
                            vulnerabilities.append(vuln)
                            self._progress.vulnerabilities_found += 1
                            break  # Found vulnerability for this variant
                    else:
                        # Safe mode: report based on timing only
                        vuln = self._build_timing_vulnerability(
                            endpoint,
                            timing_result,
                            payload,
                        )
                        vulnerabilities.append(vuln)
                        self._progress.vulnerabilities_found += 1
                        break
                
                # Rate limiting
                await asyncio.sleep(self.config.safety.min_delay_between_tests)
        
        return vulnerabilities
    
    async def _confirm_with_differential(
        self,
        payload: Payload,
        host: str,
        port: int,
        use_ssl: bool,
    ) -> Optional[DetectionResult]:
        """Confirm vulnerability with differential detection."""
        try:
            return await self.differential_detector.detect(
                payload, host, port, use_ssl
            )
        except Exception as e:
            self.logger.debug(f"Differential detection failed: {e}")
            return None
    
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

