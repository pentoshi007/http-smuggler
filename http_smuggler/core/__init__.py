"""Core modules for HTTP Smuggler."""

from .config import (
    ScanConfig,
    ScanMode,
    OutputFormat,
    NetworkConfig,
    CrawlConfig,
    SafetyConfig,
    PayloadConfig,
    ExploitConfig,
    ReportConfig,
)
from .models import (
    Endpoint,
    ScanResult,
    VulnerabilityReport,
    DetectionResult,
    ExploitationResult,
    ProtocolProfile,
    SmugglingVariant,
    DetectionMethod,
    HttpVersion,
)
from .exceptions import (
    SmugglerException,
    ConnectionError,
    ConnectionTimeoutError,
    SSLError,
    ProtocolError,
    HTTP2Error,
    DetectionError,
    PayloadError,
    ExploitationError,
    CrawlError,
    WAFDetectedError,
    RateLimitError,
    ConfigurationError,
    ScanAbortedError,
)
from .engine import SmugglerEngine, run_scan

__all__ = [
    # Config
    "ScanConfig",
    "ScanMode",
    "OutputFormat",
    "NetworkConfig",
    "CrawlConfig",
    "SafetyConfig",
    "PayloadConfig",
    "ExploitConfig",
    "ReportConfig",
    # Models
    "Endpoint",
    "ScanResult",
    "VulnerabilityReport",
    "DetectionResult",
    "ExploitationResult",
    "ProtocolProfile",
    "SmugglingVariant",
    "DetectionMethod",
    "HttpVersion",
    # Exceptions
    "SmugglerException",
    "ConnectionError",
    "ConnectionTimeoutError",
    "SSLError",
    "ProtocolError",
    "HTTP2Error",
    "DetectionError",
    "PayloadError",
    "ExploitationError",
    "CrawlError",
    "WAFDetectedError",
    "RateLimitError",
    "ConfigurationError",
    "ScanAbortedError",
    # Engine
    "SmugglerEngine",
    "run_scan",
]

