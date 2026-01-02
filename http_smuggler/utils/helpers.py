"""Helper utilities for HTTP Smuggler.

Common utilities for URL parsing, timing, rate limiting, and request building.
"""

import asyncio
import time
import re
import hashlib
import secrets
from typing import Optional, Tuple, Dict, List, Any, Callable, TypeVar
from urllib.parse import urlparse, urljoin, urlunparse, parse_qs, urlencode
from dataclasses import dataclass, field
from functools import wraps
from collections import deque


T = TypeVar('T')


# ============================================================================
# URL Utilities
# ============================================================================


@dataclass
class ParsedURL:
    """Parsed URL components."""
    scheme: str
    host: str
    port: int
    path: str
    query: str
    fragment: str
    use_ssl: bool
    
    @property
    def origin(self) -> str:
        """Get origin (scheme + host + port)."""
        default_port = 443 if self.use_ssl else 80
        if self.port == default_port:
            return f"{self.scheme}://{self.host}"
        return f"{self.scheme}://{self.host}:{self.port}"
    
    @property
    def full_path(self) -> str:
        """Get full path including query string."""
        if self.query:
            return f"{self.path}?{self.query}"
        return self.path
    
    @property
    def url(self) -> str:
        """Reconstruct full URL."""
        return f"{self.origin}{self.full_path}"
    
    @property
    def host_header(self) -> str:
        """Get Host header value."""
        default_port = 443 if self.use_ssl else 80
        if self.port == default_port:
            return self.host
        return f"{self.host}:{self.port}"


def parse_url(url: str) -> ParsedURL:
    """Parse URL into components.
    
    Args:
        url: Full URL string
    
    Returns:
        ParsedURL with all components
    """
    parsed = urlparse(url)
    
    scheme = parsed.scheme or "http"
    host = parsed.hostname or ""
    
    if parsed.port:
        port = parsed.port
    elif scheme == "https":
        port = 443
    else:
        port = 80
    
    path = parsed.path or "/"
    query = parsed.query or ""
    fragment = parsed.fragment or ""
    use_ssl = scheme == "https"
    
    return ParsedURL(
        scheme=scheme,
        host=host,
        port=port,
        path=path,
        query=query,
        fragment=fragment,
        use_ssl=use_ssl,
    )


def normalize_url(url: str) -> str:
    """Normalize URL by removing fragments and trailing slashes."""
    parsed = urlparse(url)
    
    # Remove fragment
    path = parsed.path or "/"
    
    # Ensure path starts with /
    if not path.startswith("/"):
        path = "/" + path
    
    # Remove trailing slash except for root
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    
    # Reconstruct
    return urlunparse((
        parsed.scheme,
        parsed.netloc,
        path,
        "",
        parsed.query,
        "",  # No fragment
    ))


def join_url(base: str, path: str) -> str:
    """Join base URL with path."""
    return urljoin(base, path)


def is_same_origin(url1: str, url2: str) -> bool:
    """Check if two URLs have the same origin."""
    p1 = parse_url(url1)
    p2 = parse_url(url2)
    return p1.origin == p2.origin


def extract_domain(url: str) -> str:
    """Extract domain from URL."""
    return parse_url(url).host


# ============================================================================
# Rate Limiting
# ============================================================================


class RateLimiter:
    """Token bucket rate limiter for controlling request rate."""
    
    def __init__(
        self,
        requests_per_second: float = 10.0,
        burst_size: Optional[int] = None,
    ):
        """Initialize rate limiter.
        
        Args:
            requests_per_second: Maximum sustained request rate
            burst_size: Maximum burst size (default: 2x RPS)
        """
        self.rps = requests_per_second
        self.burst_size = burst_size or int(requests_per_second * 2)
        self.tokens = float(self.burst_size)
        self.last_update = time.monotonic()
        self._lock = asyncio.Lock()
    
    async def acquire(self) -> float:
        """Acquire a token, waiting if necessary.
        
        Returns:
            Time waited in seconds
        """
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_update
            self.last_update = now
            
            # Add tokens based on elapsed time
            self.tokens = min(
                self.burst_size,
                self.tokens + elapsed * self.rps
            )
            
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return 0.0
            
            # Calculate wait time
            wait_time = (1.0 - self.tokens) / self.rps
            await asyncio.sleep(wait_time)
            self.tokens = 0.0
            self.last_update = time.monotonic()
            return wait_time
    
    def try_acquire(self) -> bool:
        """Try to acquire a token without waiting.
        
        Returns:
            True if token acquired, False otherwise
        """
        now = time.monotonic()
        elapsed = now - self.last_update
        self.last_update = now
        
        self.tokens = min(
            self.burst_size,
            self.tokens + elapsed * self.rps
        )
        
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False


class SlidingWindowRateLimiter:
    """Sliding window rate limiter with more precise control."""
    
    def __init__(
        self,
        max_requests: int,
        window_seconds: float,
    ):
        """Initialize sliding window rate limiter.
        
        Args:
            max_requests: Maximum requests per window
            window_seconds: Window size in seconds
        """
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: deque = deque()
        self._lock = asyncio.Lock()
    
    async def acquire(self) -> float:
        """Acquire permission to make a request.
        
        Returns:
            Time waited in seconds
        """
        async with self._lock:
            now = time.monotonic()
            
            # Remove expired entries
            cutoff = now - self.window_seconds
            while self.requests and self.requests[0] < cutoff:
                self.requests.popleft()
            
            if len(self.requests) < self.max_requests:
                self.requests.append(now)
                return 0.0
            
            # Calculate wait time until oldest request expires
            oldest = self.requests[0]
            wait_time = oldest + self.window_seconds - now
            
            if wait_time > 0:
                await asyncio.sleep(wait_time)
                now = time.monotonic()
            
            # Clean up and record
            cutoff = now - self.window_seconds
            while self.requests and self.requests[0] < cutoff:
                self.requests.popleft()
            
            self.requests.append(now)
            return wait_time if wait_time > 0 else 0.0


# ============================================================================
# Timing Utilities
# ============================================================================


@dataclass
class TimingStats:
    """Statistics for timing measurements."""
    min_time: float = float('inf')
    max_time: float = 0.0
    total_time: float = 0.0
    count: int = 0
    times: List[float] = field(default_factory=list)
    
    def add(self, time_value: float) -> None:
        """Add a timing measurement."""
        self.min_time = min(self.min_time, time_value)
        self.max_time = max(self.max_time, time_value)
        self.total_time += time_value
        self.count += 1
        self.times.append(time_value)
    
    @property
    def avg_time(self) -> float:
        """Get average time."""
        return self.total_time / self.count if self.count > 0 else 0.0
    
    @property
    def median_time(self) -> float:
        """Get median time."""
        if not self.times:
            return 0.0
        sorted_times = sorted(self.times)
        n = len(sorted_times)
        if n % 2 == 0:
            return (sorted_times[n//2 - 1] + sorted_times[n//2]) / 2
        return sorted_times[n//2]
    
    @property
    def std_dev(self) -> float:
        """Get standard deviation."""
        if self.count < 2:
            return 0.0
        avg = self.avg_time
        variance = sum((t - avg) ** 2 for t in self.times) / self.count
        return variance ** 0.5


class Timer:
    """Context manager for timing operations."""
    
    def __init__(self):
        self.start_time: float = 0.0
        self.end_time: float = 0.0
    
    def __enter__(self) -> "Timer":
        self.start_time = time.monotonic()
        return self
    
    def __exit__(self, *args) -> None:
        self.end_time = time.monotonic()
    
    @property
    def elapsed(self) -> float:
        """Get elapsed time in seconds."""
        if self.end_time:
            return self.end_time - self.start_time
        return time.monotonic() - self.start_time


class AsyncTimer:
    """Async context manager for timing operations."""
    
    def __init__(self):
        self.start_time: float = 0.0
        self.end_time: float = 0.0
    
    async def __aenter__(self) -> "AsyncTimer":
        self.start_time = time.monotonic()
        return self
    
    async def __aexit__(self, *args) -> None:
        self.end_time = time.monotonic()
    
    @property
    def elapsed(self) -> float:
        """Get elapsed time in seconds."""
        if self.end_time:
            return self.end_time - self.start_time
        return time.monotonic() - self.start_time


def timed(func: Callable[..., T]) -> Callable[..., Tuple[T, float]]:
    """Decorator to time function execution.
    
    Returns tuple of (result, elapsed_time).
    """
    @wraps(func)
    def wrapper(*args, **kwargs) -> Tuple[T, float]:
        start = time.monotonic()
        result = func(*args, **kwargs)
        elapsed = time.monotonic() - start
        return result, elapsed
    return wrapper


def async_timed(func: Callable[..., T]) -> Callable[..., Tuple[T, float]]:
    """Decorator to time async function execution.
    
    Returns tuple of (result, elapsed_time).
    """
    @wraps(func)
    async def wrapper(*args, **kwargs) -> Tuple[T, float]:
        start = time.monotonic()
        result = await func(*args, **kwargs)
        elapsed = time.monotonic() - start
        return result, elapsed
    return wrapper


# ============================================================================
# Request Building Utilities
# ============================================================================


def build_chunked_body(data: bytes) -> bytes:
    """Build a properly chunked transfer-encoded body.
    
    Args:
        data: Raw body data
    
    Returns:
        Chunked encoded body
    """
    if not data:
        return b"0\r\n\r\n"
    
    chunk_size = hex(len(data))[2:]
    return f"{chunk_size}\r\n".encode() + data + b"\r\n0\r\n\r\n"


def build_malformed_chunk(
    data: bytes,
    chunk_size_override: Optional[int] = None,
    omit_terminator: bool = False,
    extra_data: Optional[bytes] = None,
) -> bytes:
    """Build a malformed chunked body for smuggling.
    
    Args:
        data: Chunk data
        chunk_size_override: Override chunk size (for CL/TE conflicts)
        omit_terminator: Don't include final 0 chunk
        extra_data: Extra data after the chunk
    
    Returns:
        Malformed chunked body
    """
    if chunk_size_override is not None:
        size = hex(chunk_size_override)[2:]
    else:
        size = hex(len(data))[2:]
    
    result = f"{size}\r\n".encode() + data + b"\r\n"
    
    if not omit_terminator:
        result += b"0\r\n\r\n"
    
    if extra_data:
        result += extra_data
    
    return result


def generate_boundary() -> str:
    """Generate a random multipart boundary."""
    return f"----WebKitFormBoundary{secrets.token_hex(8)}"


def generate_request_id() -> str:
    """Generate a unique request identifier."""
    return secrets.token_hex(8)


def calculate_content_length(body: bytes) -> int:
    """Calculate Content-Length for a body."""
    return len(body)


# ============================================================================
# Detection Helpers
# ============================================================================


def is_timeout_response(response_time: float, threshold: float = 5.0) -> bool:
    """Check if response time indicates a timeout."""
    return response_time >= threshold


def is_error_response(status_code: int) -> bool:
    """Check if status code indicates an error."""
    return status_code >= 400


def is_smuggling_indicator(response_body: bytes) -> bool:
    """Check if response body contains smuggling indicators.
    
    Looks for common signs that a smuggled request was processed.
    """
    indicators = [
        b"GPOST",
        b"GGET",
        b"unrecognized method",
        b"invalid request",
        b"bad request",
        b"malformed",
    ]
    
    body_lower = response_body.lower()
    return any(ind.lower() in body_lower for ind in indicators)


def extract_server_info(headers: Dict[str, str]) -> Dict[str, Optional[str]]:
    """Extract server information from response headers."""
    return {
        "server": headers.get("server"),
        "via": headers.get("via"),
        "x-powered-by": headers.get("x-powered-by"),
        "x-served-by": headers.get("x-served-by"),
        "x-cache": headers.get("x-cache"),
    }


def detect_waf_signature(
    status_code: int,
    headers: Dict[str, str],
    body: bytes,
) -> Optional[str]:
    """Detect WAF presence from response.
    
    Returns:
        WAF name if detected, None otherwise
    """
    # Check headers
    server = headers.get("server", "").lower()
    
    waf_signatures = {
        "cloudflare": ["cloudflare", "cf-ray"],
        "akamai": ["akamai", "akamai-ghost"],
        "aws-waf": ["awselb", "x-amz-cf-id"],
        "imperva": ["incapsula", "x-cdn"],
        "f5-big-ip": ["bigip", "f5"],
        "barracuda": ["barracuda"],
        "fortinet": ["fortigate", "fortiweb"],
        "modsecurity": ["mod_security", "modsecurity"],
    }
    
    # Check server header
    for waf_name, signatures in waf_signatures.items():
        for sig in signatures:
            if sig in server:
                return waf_name
    
    # Check other headers
    for header, value in headers.items():
        header_lower = header.lower()
        value_lower = value.lower()
        
        for waf_name, signatures in waf_signatures.items():
            for sig in signatures:
                if sig in header_lower or sig in value_lower:
                    return waf_name
    
    # Check for blocking page patterns
    body_str = body.decode("utf-8", errors="ignore").lower()
    
    blocking_patterns = {
        "cloudflare": ["attention required", "cloudflare ray id"],
        "akamai": ["access denied", "reference #"],
        "imperva": ["incapsula incident id", "request unsuccessful"],
        "aws-waf": ["request blocked", "aws waf"],
    }
    
    for waf_name, patterns in blocking_patterns.items():
        for pattern in patterns:
            if pattern in body_str:
                return waf_name
    
    return None


# ============================================================================
# String Utilities
# ============================================================================


def safe_decode(data: bytes, encoding: str = "utf-8") -> str:
    """Safely decode bytes to string."""
    return data.decode(encoding, errors="replace")


def truncate(text: str, max_length: int = 100, suffix: str = "...") -> str:
    """Truncate text to maximum length."""
    if len(text) <= max_length:
        return text
    return text[:max_length - len(suffix)] + suffix


def hash_request(request: bytes) -> str:
    """Generate hash of a request for deduplication."""
    return hashlib.md5(request).hexdigest()[:12]


def sanitize_header_value(value: str) -> str:
    """Sanitize header value for safe display."""
    # Remove control characters except common ones
    return re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', value)


# ============================================================================
# Async Utilities
# ============================================================================


async def gather_with_concurrency(
    limit: int,
    *coroutines,
) -> List[Any]:
    """Run coroutines with concurrency limit.
    
    Args:
        limit: Maximum concurrent coroutines
        *coroutines: Coroutines to run
    
    Returns:
        List of results
    """
    semaphore = asyncio.Semaphore(limit)
    
    async def limited_coro(coro):
        async with semaphore:
            return await coro
    
    return await asyncio.gather(*[limited_coro(c) for c in coroutines])


async def retry_async(
    func: Callable,
    max_retries: int = 3,
    delay: float = 1.0,
    backoff: float = 2.0,
    exceptions: Tuple = (Exception,),
) -> Any:
    """Retry an async function with exponential backoff.
    
    Args:
        func: Async function to call
        max_retries: Maximum retry attempts
        delay: Initial delay between retries
        backoff: Backoff multiplier
        exceptions: Exceptions to catch and retry
    
    Returns:
        Function result
    """
    last_exception = None
    current_delay = delay
    
    for attempt in range(max_retries + 1):
        try:
            return await func()
        except exceptions as e:
            last_exception = e
            if attempt < max_retries:
                await asyncio.sleep(current_delay)
                current_delay *= backoff
    
    raise last_exception

