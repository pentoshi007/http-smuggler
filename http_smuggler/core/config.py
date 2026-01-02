"""Configuration classes for HTTP Smuggler."""

from dataclasses import dataclass, field
from typing import Optional, List, Set
from enum import Enum

from .models import SmugglingVariant, HttpVersion


class ScanMode(Enum):
    """Scan mode determines the aggressiveness of testing."""

    PASSIVE = "passive"  # Only protocol detection, no active testing
    SAFE = "safe"  # Timing-based detection only (no impact on other users)
    NORMAL = "normal"  # Timing + differential detection
    AGGRESSIVE = "aggressive"  # Full testing with exploitation confirmation


class OutputFormat(Enum):
    """Output format for scan results."""

    JSON = "json"
    TEXT = "text"
    MARKDOWN = "markdown"


@dataclass
class NetworkConfig:
    """Network-level configuration."""

    # Connection settings
    connect_timeout: float = 10.0
    read_timeout: float = 30.0
    write_timeout: float = 10.0

    # Keep-alive settings
    keepalive: bool = True
    max_keepalive_connections: int = 10

    # SSL/TLS settings
    verify_ssl: bool = True
    ssl_cert_path: Optional[str] = None
    ssl_key_path: Optional[str] = None

    # Proxy settings
    proxy_url: Optional[str] = None
    proxy_auth: Optional[str] = None

    # Socket settings
    socket_buffer_size: int = 8192
    max_response_size: int = 10 * 1024 * 1024  # 10MB

    # Retry settings
    max_retries: int = 3
    retry_delay: float = 1.0


@dataclass
class CrawlConfig:
    """Configuration for domain crawling."""

    # Crawl depth and limits
    max_depth: int = 3
    max_pages: int = 100
    max_endpoints: int = 500

    # URL filtering
    include_patterns: List[str] = field(default_factory=list)
    exclude_patterns: List[str] = field(
        default_factory=lambda: [
            r"\.(?:css|js|ico|png|jpg|jpeg|gif|svg|woff|woff2|ttf|eot)$",
            r"/static/",
            r"/assets/",
            r"/(?:logout|signout)",
        ]
    )

    # Robots and sitemap
    respect_robots_txt: bool = True
    parse_sitemap: bool = True

    # Request settings
    follow_redirects: bool = True
    max_redirects: int = 5

    # Content parsing
    parse_forms: bool = True
    parse_javascript: bool = False  # Basic JS link extraction

    # Rate limiting
    requests_per_second: float = 10.0
    concurrent_requests: int = 5

    # Headers for crawling
    user_agent: str = "Mozilla/5.0 (compatible; HTTPSmuggler/1.0; Security Scanner)"
    custom_headers: dict = field(default_factory=dict)

    # Authentication
    cookies: dict = field(default_factory=dict)
    auth_header: Optional[str] = None


@dataclass
class SafetyConfig:
    """Safety and rate limiting configuration."""

    # Rate limiting
    requests_per_second: float = 2.0  # Conservative default
    min_delay_between_tests: float = 0.5
    max_delay_between_tests: float = 2.0

    # Concurrency
    max_concurrent_tests: int = 3
    max_concurrent_per_host: int = 2

    # Cooldown after potential detection
    cooldown_on_waf_detection: float = 30.0
    cooldown_on_rate_limit: float = 60.0

    # Test limits
    max_tests_per_endpoint: int = 50
    max_total_requests: int = 1000

    # Timeout for smuggling detection
    timing_detection_timeout: float = 10.0
    differential_detection_timeout: float = 15.0

    # Safety checks
    abort_on_waf_detection: bool = False
    abort_on_rate_limit: bool = True

    # Request mutation limits
    max_content_length: int = 65535
    max_chunk_size: int = 65535


@dataclass
class PayloadConfig:
    """Configuration for payload generation."""

    # Enabled variants
    enabled_variants: Set[SmugglingVariant] = field(
        default_factory=lambda: {
            SmugglingVariant.CL_TE,
            SmugglingVariant.TE_CL,
            SmugglingVariant.TE_TE,
            SmugglingVariant.H2_CL,
            SmugglingVariant.H2_TE,
            SmugglingVariant.H2_CRLF,
            SmugglingVariant.WS_VERSION,
        }
    )

    # Obfuscation settings
    use_te_obfuscation: bool = True
    max_te_obfuscations: int = 50  # Max obfuscation variants to try per endpoint

    # Payload customization
    smuggled_path: str = "/admin"  # Path to request in smuggled portion
    smuggled_method: str = "GET"
    smuggled_host: Optional[str] = None  # Override Host header in smuggled request

    # Timing payload settings
    timing_delay_chunk: int = 65535  # Large chunk to cause timeout
    timing_expected_delay: float = 5.0  # Expected delay in seconds

    # Differential payload settings
    poison_prefix: str = (
        "G"  # Prefix to poison next request (e.g., "GPOST" instead of "POST")
    )

    # HTTP/2 settings
    enable_h2_downgrade: bool = True
    enable_h2_crlf: bool = True

    # WebSocket settings
    ws_invalid_versions: List[int] = field(
        default_factory=lambda: [1337, 9999, 0, -1, 256, 65535]
    )


@dataclass
class ExploitConfig:
    """Configuration for exploitation confirmation."""

    # Enable/disable exploitation
    enabled: bool = True

    # What to attempt
    attempt_session_capture: bool = True
    attempt_cache_poisoning: bool = False  # Potentially impactful
    attempt_acl_bypass: bool = True

    # Session capture settings
    capture_timeout: float = 30.0
    max_capture_attempts: int = 3

    # Cache poisoning settings (use with caution)
    cache_poison_path: str = "/static/test.js"
    cache_poison_payload: str = "alert('XSS via cache poisoning')"

    # Evidence collection
    save_raw_requests: bool = True
    save_raw_responses: bool = True


@dataclass
class ReportConfig:
    """Configuration for reporting."""

    # Output format
    format: OutputFormat = OutputFormat.JSON

    # Output destination
    output_file: Optional[str] = None  # None = stdout

    # Verbosity
    include_raw_payloads: bool = True
    include_raw_responses: bool = True
    include_exploitation_details: bool = True

    # Filtering
    min_confidence: float = 0.5
    severity_filter: Optional[List[str]] = None  # None = all severities

    # Timestamps
    include_timestamps: bool = True
    timezone: str = "UTC"


@dataclass
class ScanConfig:
    """Main configuration for the HTTP Smuggler scanner."""

    # Target
    target_url: str = ""

    # Scan mode
    mode: ScanMode = ScanMode.NORMAL

    # Protocol preferences
    preferred_version: Optional[HttpVersion] = None  # None = auto-detect
    force_http2: bool = False
    force_http1: bool = False

    # Sub-configurations
    network: NetworkConfig = field(default_factory=NetworkConfig)
    crawl: CrawlConfig = field(default_factory=CrawlConfig)
    safety: SafetyConfig = field(default_factory=SafetyConfig)
    payload: PayloadConfig = field(default_factory=PayloadConfig)
    exploit: ExploitConfig = field(default_factory=ExploitConfig)
    report: ReportConfig = field(default_factory=ReportConfig)

    # Specific endpoints to test (skip crawling)
    target_endpoints: List[str] = field(default_factory=list)

    # Skip crawling entirely
    skip_crawl: bool = False

    # Verbosity
    verbose: bool = False
    debug: bool = False
    quiet: bool = False

    @classmethod
    def for_quick_scan(cls, target: str) -> "ScanConfig":
        """Create a quick scan configuration."""
        return cls(
            target_url=target,
            mode=ScanMode.SAFE,
            skip_crawl=True,
            crawl=CrawlConfig(max_pages=10, max_endpoints=20),
            safety=SafetyConfig(
                max_tests_per_endpoint=10,
                max_total_requests=100,
            ),
            payload=PayloadConfig(
                max_te_obfuscations=10,
                enabled_variants={
                    SmugglingVariant.CL_TE,
                    SmugglingVariant.TE_CL,
                },
            ),
            exploit=ExploitConfig(enabled=False),
        )

    @classmethod
    def for_full_scan(cls, target: str) -> "ScanConfig":
        """Create a comprehensive scan configuration."""
        return cls(
            target_url=target,
            mode=ScanMode.AGGRESSIVE,
            crawl=CrawlConfig(
                max_depth=5,
                max_pages=500,
                max_endpoints=1000,
            ),
            safety=SafetyConfig(
                max_tests_per_endpoint=100,
                max_total_requests=5000,
                requests_per_second=5.0,
            ),
            exploit=ExploitConfig(
                enabled=True,
                attempt_session_capture=True,
                attempt_cache_poisoning=False,
                attempt_acl_bypass=True,
            ),
        )

    @classmethod
    def for_h2_only(cls, target: str) -> "ScanConfig":
        """Create an HTTP/2 focused scan configuration."""
        return cls(
            target_url=target,
            mode=ScanMode.NORMAL,
            force_http2=True,
            payload=PayloadConfig(
                enabled_variants={
                    SmugglingVariant.H2_CL,
                    SmugglingVariant.H2_TE,
                    SmugglingVariant.H2_CRLF,
                    SmugglingVariant.H2_TUNNEL,
                },
                enable_h2_downgrade=True,
                enable_h2_crlf=True,
            ),
        )

    def validate(self) -> List[str]:
        """Validate configuration and return list of errors."""
        errors = []

        if not self.target_url:
            errors.append("target_url is required")

        if self.force_http2 and self.force_http1:
            errors.append("Cannot force both HTTP/1.1 and HTTP/2")

        if self.safety.requests_per_second <= 0:
            errors.append("requests_per_second must be positive")

        if self.safety.max_concurrent_tests <= 0:
            errors.append("max_concurrent_tests must be positive")

        if self.crawl.max_depth < 0:
            errors.append("max_depth cannot be negative")

        if not self.payload.enabled_variants:
            errors.append("At least one smuggling variant must be enabled")

        return errors
