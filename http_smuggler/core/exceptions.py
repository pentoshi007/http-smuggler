"""Custom exceptions for HTTP Smuggler."""

from typing import Optional, Any, Dict


class SmugglerException(Exception):
    """Base exception for all HTTP Smuggler errors."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def __str__(self) -> str:
        if self.details:
            return f"{self.message} | Details: {self.details}"
        return self.message


# ============================================================================
# Connection Errors
# ============================================================================


class ConnectionError(SmugglerException):
    """Base class for connection-related errors."""

    pass


class ConnectionRefusedError(ConnectionError):
    """Connection was refused by the target."""

    def __init__(self, host: str, port: int, message: Optional[str] = None):
        super().__init__(
            message or f"Connection refused to {host}:{port}",
            {"host": host, "port": port},
        )
        self.host = host
        self.port = port


class ConnectionTimeoutError(ConnectionError):
    """Connection timed out."""

    def __init__(self, host: str, port: int, timeout: float, phase: str = "connect"):
        super().__init__(
            f"Connection to {host}:{port} timed out after {timeout}s during {phase}",
            {"host": host, "port": port, "timeout": timeout, "phase": phase},
        )
        self.host = host
        self.port = port
        self.timeout = timeout
        self.phase = phase


class SSLError(ConnectionError):
    """SSL/TLS handshake or certificate error."""

    def __init__(self, host: str, message: str, ssl_error: Optional[str] = None):
        super().__init__(
            f"SSL error connecting to {host}: {message}",
            {"host": host, "ssl_error": ssl_error},
        )
        self.host = host
        self.ssl_error = ssl_error


class DNSResolutionError(ConnectionError):
    """DNS resolution failed."""

    def __init__(self, hostname: str):
        super().__init__(
            f"Failed to resolve hostname: {hostname}", {"hostname": hostname}
        )
        self.hostname = hostname


# ============================================================================
# Protocol Errors
# ============================================================================


class ProtocolError(SmugglerException):
    """Base class for protocol-related errors."""

    pass


class InvalidResponseError(ProtocolError):
    """Received an invalid or malformed response."""

    def __init__(self, message: str, raw_response: Optional[bytes] = None):
        super().__init__(
            message,
            {"raw_response_preview": raw_response[:500] if raw_response else None},
        )
        self.raw_response = raw_response


class HTTP2Error(ProtocolError):
    """HTTP/2 specific error."""

    def __init__(self, message: str, error_code: Optional[int] = None):
        super().__init__(message, {"h2_error_code": error_code})
        self.error_code = error_code


class ALPNNegotiationError(ProtocolError):
    """ALPN negotiation failed."""

    def __init__(self, offered: list, selected: Optional[str] = None):
        super().__init__(
            f"ALPN negotiation failed. Offered: {offered}, Selected: {selected}",
            {"offered": offered, "selected": selected},
        )
        self.offered = offered
        self.selected = selected


class WebSocketError(ProtocolError):
    """WebSocket protocol error."""

    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message, {"ws_status_code": status_code})
        self.status_code = status_code


# ============================================================================
# Detection Errors
# ============================================================================


class DetectionError(SmugglerException):
    """Base class for detection-related errors."""

    pass


class TimingDetectionError(DetectionError):
    """Error during timing-based detection."""

    def __init__(
        self,
        message: str,
        expected_time: Optional[float] = None,
        actual_time: Optional[float] = None,
    ):
        super().__init__(
            message, {"expected_time": expected_time, "actual_time": actual_time}
        )
        self.expected_time = expected_time
        self.actual_time = actual_time


class DifferentialDetectionError(DetectionError):
    """Error during differential response detection."""

    def __init__(
        self,
        message: str,
        smuggle_response: Optional[str] = None,
        victim_response: Optional[str] = None,
    ):
        super().__init__(
            message,
            {
                "smuggle_response_preview": smuggle_response[:200]
                if smuggle_response
                else None,
                "victim_response_preview": victim_response[:200]
                if victim_response
                else None,
            },
        )


class FalsePositiveError(DetectionError):
    """Detected what appears to be a false positive."""

    def __init__(self, reason: str, variant: str):
        super().__init__(
            f"False positive suspected for {variant}: {reason}",
            {"variant": variant, "reason": reason},
        )
        self.variant = variant
        self.reason = reason


# ============================================================================
# Payload Errors
# ============================================================================


class PayloadError(SmugglerException):
    """Base class for payload-related errors."""

    pass


class PayloadGenerationError(PayloadError):
    """Failed to generate a valid payload."""

    def __init__(self, variant: str, reason: str):
        super().__init__(
            f"Failed to generate {variant} payload: {reason}",
            {"variant": variant, "reason": reason},
        )
        self.variant = variant
        self.reason = reason


class PayloadTooLargeError(PayloadError):
    """Payload exceeds maximum allowed size."""

    def __init__(self, actual_size: int, max_size: int):
        super().__init__(
            f"Payload size {actual_size} exceeds maximum {max_size}",
            {"actual_size": actual_size, "max_size": max_size},
        )
        self.actual_size = actual_size
        self.max_size = max_size


# ============================================================================
# Exploitation Errors
# ============================================================================


class ExploitationError(SmugglerException):
    """Base class for exploitation-related errors."""

    pass


class SessionCaptureError(ExploitationError):
    """Failed to capture session data."""

    def __init__(self, message: str, attempts: int = 0):
        super().__init__(message, {"attempts": attempts})
        self.attempts = attempts


class CachePoisoningError(ExploitationError):
    """Cache poisoning attempt failed."""

    def __init__(self, message: str, cache_key: Optional[str] = None):
        super().__init__(message, {"cache_key": cache_key})
        self.cache_key = cache_key


# ============================================================================
# Crawling Errors
# ============================================================================


class CrawlError(SmugglerException):
    """Base class for crawling-related errors."""

    pass


class RobotsTxtError(CrawlError):
    """Error parsing or respecting robots.txt."""

    def __init__(self, url: str, message: str):
        super().__init__(f"robots.txt error for {url}: {message}", {"url": url})
        self.url = url


class CrawlDepthExceededError(CrawlError):
    """Maximum crawl depth exceeded."""

    def __init__(self, url: str, depth: int, max_depth: int):
        super().__init__(
            f"Crawl depth {depth} exceeded maximum {max_depth} for {url}",
            {"url": url, "depth": depth, "max_depth": max_depth},
        )
        self.url = url
        self.depth = depth
        self.max_depth = max_depth


# ============================================================================
# Rate Limiting / WAF Errors
# ============================================================================


class RateLimitError(SmugglerException):
    """Rate limiting detected."""

    def __init__(self, retry_after: Optional[float] = None):
        super().__init__(
            f"Rate limited{f', retry after {retry_after}s' if retry_after else ''}",
            {"retry_after": retry_after},
        )
        self.retry_after = retry_after


class WAFDetectedError(SmugglerException):
    """Web Application Firewall detected and blocking requests."""

    def __init__(self, waf_name: Optional[str] = None, evidence: Optional[str] = None):
        super().__init__(
            f"WAF detected{f': {waf_name}' if waf_name else ''}{f' - {evidence}' if evidence else ''}",
            {"waf_name": waf_name, "evidence": evidence},
        )
        self.waf_name = waf_name
        self.evidence = evidence


# ============================================================================
# Configuration Errors
# ============================================================================


class ConfigurationError(SmugglerException):
    """Invalid or missing configuration."""

    def __init__(self, errors: list):
        super().__init__(
            f"Configuration invalid: {'; '.join(errors)}", {"errors": errors}
        )
        self.errors = errors


# ============================================================================
# Scan Control
# ============================================================================


class ScanAbortedError(SmugglerException):
    """Scan was aborted."""

    def __init__(self, reason: str, partial_results: bool = False):
        super().__init__(
            f"Scan aborted: {reason}", {"partial_results": partial_results}
        )
        self.reason = reason
        self.partial_results = partial_results


class ScanTimeoutError(SmugglerException):
    """Scan exceeded maximum time limit."""

    def __init__(self, elapsed: float, max_time: float):
        super().__init__(
            f"Scan timed out after {elapsed}s (max: {max_time}s)",
            {"elapsed": elapsed, "max_time": max_time},
        )
        self.elapsed = elapsed
        self.max_time = max_time
