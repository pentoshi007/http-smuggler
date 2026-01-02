"""Base payload generator framework for HTTP Smuggler.

Provides abstract base classes and common utilities for generating
HTTP request smuggling payloads across all variants.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Callable
from enum import Enum

from http_smuggler.core.models import (
    Endpoint,
    SmugglingVariant,
    DetectionMethod,
)


class PayloadCategory(Enum):
    """Category of payload purpose."""
    TIMING = "timing"           # Causes timeout if vulnerable
    DIFFERENTIAL = "differential"  # Poisons next response
    ECHO = "echo"               # Reflects in response
    EXPLOIT = "exploit"         # Actual exploitation


@dataclass
class Payload:
    """Represents a single smuggling payload.
    
    Attributes:
        name: Unique identifier for the payload
        variant: Smuggling variant (CL.TE, TE.CL, etc.)
        category: Purpose category (timing, differential, etc.)
        raw_request: The raw HTTP request bytes
        description: Human-readable description
        detection_method: How to detect if vulnerable
        expected_behavior: What happens if target is vulnerable
        expected_timeout: Expected timeout in seconds (for timing payloads)
        poison_prefix: Prefix that poisons next request (for differential)
        metadata: Additional payload-specific data
    """
    name: str
    variant: SmugglingVariant
    category: PayloadCategory
    raw_request: bytes
    description: str
    detection_method: DetectionMethod
    expected_behavior: str
    expected_timeout: float = 5.0
    poison_prefix: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __str__(self) -> str:
        return f"Payload({self.name}, {self.variant.value})"
    
    def __repr__(self) -> str:
        return (
            f"Payload(name={self.name!r}, variant={self.variant.value!r}, "
            f"category={self.category.value!r})"
        )


@dataclass
class PayloadTemplate:
    """Template for generating payloads with variable substitution.
    
    Templates use {variable} syntax for substitution.
    """
    name: str
    template: str
    variant: SmugglingVariant
    category: PayloadCategory
    detection_method: DetectionMethod
    description: str
    expected_behavior: str
    required_vars: List[str] = field(default_factory=list)
    optional_vars: Dict[str, str] = field(default_factory=dict)
    
    def render(self, **kwargs) -> bytes:
        """Render template with provided variables.
        
        Args:
            **kwargs: Variable values
        
        Returns:
            Rendered payload bytes
        """
        # Apply optional defaults
        variables = {**self.optional_vars, **kwargs}
        
        # Check required variables
        missing = [v for v in self.required_vars if v not in variables]
        if missing:
            raise ValueError(f"Missing required variables: {missing}")
        
        # Render template
        result = self.template
        for key, value in variables.items():
            result = result.replace(f"{{{key}}}", str(value))
        
        return result.encode("utf-8")
    
    def to_payload(self, **kwargs) -> Payload:
        """Generate a Payload instance from this template.
        
        Args:
            **kwargs: Variable values for rendering
        
        Returns:
            Payload instance
        """
        return Payload(
            name=self.name,
            variant=self.variant,
            category=self.category,
            raw_request=self.render(**kwargs),
            description=self.description,
            detection_method=self.detection_method,
            expected_behavior=self.expected_behavior,
            metadata={"template_vars": kwargs},
        )


class PayloadGenerator(ABC):
    """Abstract base class for payload generators.
    
    Each smuggling variant should implement this interface to generate
    both timing-based and differential detection payloads.
    """
    
    @property
    @abstractmethod
    def variant(self) -> SmugglingVariant:
        """The smuggling variant this generator handles."""
        pass
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name for this generator."""
        pass
    
    @abstractmethod
    def generate_timing_payloads(self, endpoint: Endpoint) -> List[Payload]:
        """Generate timing-based detection payloads.
        
        Timing payloads should cause a detectable timeout if the target
        is vulnerable to this smuggling variant.
        
        Args:
            endpoint: Target endpoint information
        
        Returns:
            List of timing detection payloads
        """
        pass
    
    @abstractmethod
    def generate_differential_payloads(self, endpoint: Endpoint) -> List[Payload]:
        """Generate differential response detection payloads.
        
        Differential payloads should poison the next request's response
        if the target is vulnerable.
        
        Args:
            endpoint: Target endpoint information
        
        Returns:
            List of differential detection payloads
        """
        pass
    
    def generate_all_payloads(self, endpoint: Endpoint) -> List[Payload]:
        """Generate all payloads for an endpoint.
        
        Args:
            endpoint: Target endpoint information
        
        Returns:
            Combined list of all payload types
        """
        payloads = []
        payloads.extend(self.generate_timing_payloads(endpoint))
        payloads.extend(self.generate_differential_payloads(endpoint))
        return payloads


class CompositePayloadGenerator:
    """Combines multiple payload generators."""
    
    def __init__(self, generators: Optional[List[PayloadGenerator]] = None):
        self.generators: List[PayloadGenerator] = generators or []
    
    def add_generator(self, generator: PayloadGenerator) -> None:
        """Add a payload generator."""
        self.generators.append(generator)
    
    def remove_generator(self, variant: SmugglingVariant) -> None:
        """Remove generators for a specific variant."""
        self.generators = [g for g in self.generators if g.variant != variant]
    
    def generate_all(
        self,
        endpoint: Endpoint,
        variants: Optional[List[SmugglingVariant]] = None,
    ) -> List[Payload]:
        """Generate payloads from all registered generators.
        
        Args:
            endpoint: Target endpoint
            variants: Optional filter for specific variants
        
        Returns:
            Combined list of all payloads
        """
        payloads = []
        
        for generator in self.generators:
            if variants is None or generator.variant in variants:
                payloads.extend(generator.generate_all_payloads(endpoint))
        
        return payloads
    
    def generate_timing(
        self,
        endpoint: Endpoint,
        variants: Optional[List[SmugglingVariant]] = None,
    ) -> List[Payload]:
        """Generate only timing payloads.
        
        Args:
            endpoint: Target endpoint
            variants: Optional filter for specific variants
        
        Returns:
            List of timing payloads
        """
        payloads = []
        
        for generator in self.generators:
            if variants is None or generator.variant in variants:
                payloads.extend(generator.generate_timing_payloads(endpoint))
        
        return payloads
    
    def generate_differential(
        self,
        endpoint: Endpoint,
        variants: Optional[List[SmugglingVariant]] = None,
    ) -> List[Payload]:
        """Generate only differential payloads.
        
        Args:
            endpoint: Target endpoint
            variants: Optional filter for specific variants
        
        Returns:
            List of differential payloads
        """
        payloads = []
        
        for generator in self.generators:
            if variants is None or generator.variant in variants:
                payloads.extend(generator.generate_differential_payloads(endpoint))
        
        return payloads


# ============================================================================
# Utility Functions for Payload Building
# ============================================================================


def build_request_line(method: str, path: str, version: str = "HTTP/1.1") -> str:
    """Build HTTP request line."""
    return f"{method} {path} {version}\r\n"


def build_header(name: str, value: str) -> str:
    """Build a single HTTP header."""
    return f"{name}: {value}\r\n"


def build_headers(headers: Dict[str, str]) -> str:
    """Build multiple HTTP headers."""
    return "".join(build_header(k, v) for k, v in headers.items())


def build_chunked_body(data: bytes) -> bytes:
    """Build properly chunked body."""
    if not data:
        return b"0\r\n\r\n"
    chunk_size = hex(len(data))[2:]
    return f"{chunk_size}\r\n".encode() + data + b"\r\n0\r\n\r\n"


def build_incomplete_chunked(data: bytes, chunk_size_override: Optional[int] = None) -> bytes:
    """Build incomplete chunked body for timing attacks.
    
    This creates a body that looks like chunked encoding but is incomplete,
    causing servers that process Transfer-Encoding to wait for more data.
    """
    if chunk_size_override is not None:
        size = hex(chunk_size_override)[2:]
    else:
        size = hex(len(data))[2:]
    
    return f"{size}\r\n".encode() + data


def calculate_content_length(body: bytes) -> int:
    """Calculate Content-Length for a body."""
    return len(body)


def extract_host_from_url(url: str) -> str:
    """Extract host from URL for Host header."""
    from urllib.parse import urlparse
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if parsed.port and parsed.port not in (80, 443):
        host = f"{host}:{parsed.port}"
    return host


def extract_path_from_url(url: str) -> str:
    """Extract path from URL."""
    from urllib.parse import urlparse
    parsed = urlparse(url)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    return path

