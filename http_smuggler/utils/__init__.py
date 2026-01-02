"""Utility modules for HTTP Smuggler."""

from .logging import (
    setup_logging,
    get_logger,
    log,
    ScanLogger,
    console,
    LogLevel,
)
from .helpers import (
    parse_url,
    ParsedURL,
    normalize_url,
    join_url,
    is_same_origin,
    RateLimiter,
    SlidingWindowRateLimiter,
    Timer,
    AsyncTimer,
    TimingStats,
    build_chunked_body,
    build_malformed_chunk,
    generate_request_id,
    is_timeout_response,
    is_smuggling_indicator,
    detect_waf_signature,
    gather_with_concurrency,
    retry_async,
)

__all__ = [
    # Logging
    "setup_logging",
    "get_logger",
    "log",
    "ScanLogger",
    "console",
    "LogLevel",
    # URL utilities
    "parse_url",
    "ParsedURL",
    "normalize_url",
    "join_url",
    "is_same_origin",
    # Rate limiting
    "RateLimiter",
    "SlidingWindowRateLimiter",
    # Timing
    "Timer",
    "AsyncTimer",
    "TimingStats",
    # Request building
    "build_chunked_body",
    "build_malformed_chunk",
    "generate_request_id",
    # Detection helpers
    "is_timeout_response",
    "is_smuggling_indicator",
    "detect_waf_signature",
    # Async utilities
    "gather_with_concurrency",
    "retry_async",
]

