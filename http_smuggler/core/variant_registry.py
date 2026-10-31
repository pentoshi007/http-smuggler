"""Variant capability registry for HTTP Smuggler.

This module is the single source of truth for supported variants, their
implementation status, transport requirements, and detector coverage.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Dict, Iterable, List, Optional, Set, Tuple

from http_smuggler.core.models import SmugglingVariant


class VariantStatus(Enum):
    """Implementation status for a smuggling variant."""

    IMPLEMENTED = "implemented"
    EXPERIMENTAL = "experimental"
    PLANNED = "planned"


class VariantTransport(Enum):
    """Primary wire transport used to test a variant."""

    HTTP1 = "http1"
    HTTP2 = "http2"
    WEBSOCKET = "websocket"
    BROWSER = "browser"


@dataclass(frozen=True)
class VariantCapability:
    """Capability metadata for one smuggling variant."""

    variant: SmugglingVariant
    description: str
    category: str
    status: VariantStatus
    transport: VariantTransport
    detectors: Tuple[str, ...]
    exploit_support: bool


VARIANT_CAPABILITIES: Dict[SmugglingVariant, VariantCapability] = {
    # Classic HTTP/1.1
    SmugglingVariant.CL_TE: VariantCapability(
        variant=SmugglingVariant.CL_TE,
        description="Content-Length vs Transfer-Encoding",
        category="Classic",
        status=VariantStatus.IMPLEMENTED,
        transport=VariantTransport.HTTP1,
        detectors=("timing", "differential"),
        exploit_support=True,
    ),
    SmugglingVariant.TE_CL: VariantCapability(
        variant=SmugglingVariant.TE_CL,
        description="Transfer-Encoding vs Content-Length",
        category="Classic",
        status=VariantStatus.IMPLEMENTED,
        transport=VariantTransport.HTTP1,
        detectors=("timing", "differential"),
        exploit_support=True,
    ),
    SmugglingVariant.TE_TE: VariantCapability(
        variant=SmugglingVariant.TE_TE,
        description="Transfer-Encoding obfuscation",
        category="Classic",
        status=VariantStatus.IMPLEMENTED,
        transport=VariantTransport.HTTP1,
        detectors=("timing", "differential"),
        exploit_support=True,
    ),
    SmugglingVariant.CL_CL: VariantCapability(
        variant=SmugglingVariant.CL_CL,
        description="Duplicate Content-Length",
        category="Classic",
        status=VariantStatus.PLANNED,
        transport=VariantTransport.HTTP1,
        detectors=("timing", "differential"),
        exploit_support=True,
    ),
    SmugglingVariant.CL_0: VariantCapability(
        variant=SmugglingVariant.CL_0,
        description="Backend ignores Content-Length",
        category="Classic",
        status=VariantStatus.PLANNED,
        transport=VariantTransport.HTTP1,
        detectors=("timing", "differential"),
        exploit_support=True,
    ),
    SmugglingVariant.ZERO_CL: VariantCapability(
        variant=SmugglingVariant.ZERO_CL,
        description="Frontend ignores body, backend reads Content-Length",
        category="Classic",
        status=VariantStatus.PLANNED,
        transport=VariantTransport.HTTP1,
        detectors=("timing", "differential"),
        exploit_support=True,
    ),
    # HTTP/2
    SmugglingVariant.H2_CL: VariantCapability(
        variant=SmugglingVariant.H2_CL,
        description="HTTP/2 Content-Length injection",
        category="HTTP/2",
        status=VariantStatus.IMPLEMENTED,
        transport=VariantTransport.HTTP2,
        detectors=("timing", "differential"),
        exploit_support=True,
    ),
    SmugglingVariant.H2_TE: VariantCapability(
        variant=SmugglingVariant.H2_TE,
        description="HTTP/2 Transfer-Encoding injection",
        category="HTTP/2",
        status=VariantStatus.IMPLEMENTED,
        transport=VariantTransport.HTTP2,
        detectors=("timing", "differential"),
        exploit_support=True,
    ),
    SmugglingVariant.H2_CRLF: VariantCapability(
        variant=SmugglingVariant.H2_CRLF,
        description="HTTP/2 CRLF injection",
        category="HTTP/2",
        status=VariantStatus.IMPLEMENTED,
        transport=VariantTransport.HTTP2,
        detectors=("timing", "differential"),
        exploit_support=True,
    ),
    SmugglingVariant.H2_0: VariantCapability(
        variant=SmugglingVariant.H2_0,
        description="HTTP/2 request tunneling",
        category="HTTP/2",
        status=VariantStatus.PLANNED,
        transport=VariantTransport.HTTP2,
        detectors=("timing", "differential"),
        exploit_support=True,
    ),
    SmugglingVariant.H2C: VariantCapability(
        variant=SmugglingVariant.H2C,
        description="h2c cleartext upgrade smuggling",
        category="HTTP/2",
        status=VariantStatus.PLANNED,
        transport=VariantTransport.HTTP2,
        detectors=("timing", "differential"),
        exploit_support=True,
    ),
    SmugglingVariant.H2_TUNNEL: VariantCapability(
        variant=SmugglingVariant.H2_TUNNEL,
        description="HTTP/2 tunnel abuse",
        category="HTTP/2",
        status=VariantStatus.PLANNED,
        transport=VariantTransport.HTTP2,
        detectors=("timing", "differential"),
        exploit_support=True,
    ),
    # WebSocket
    SmugglingVariant.WS_VERSION: VariantCapability(
        variant=SmugglingVariant.WS_VERSION,
        description="Sec-WebSocket-Version manipulation",
        category="WebSocket",
        status=VariantStatus.IMPLEMENTED,
        transport=VariantTransport.WEBSOCKET,
        detectors=("timing", "differential"),
        exploit_support=True,
    ),
    SmugglingVariant.WS_UPGRADE: VariantCapability(
        variant=SmugglingVariant.WS_UPGRADE,
        description="Upgrade header smuggling",
        category="WebSocket",
        status=VariantStatus.PLANNED,
        transport=VariantTransport.WEBSOCKET,
        detectors=("differential",),
        exploit_support=True,
    ),
    # Advanced
    SmugglingVariant.PAUSE_BASED: VariantCapability(
        variant=SmugglingVariant.PAUSE_BASED,
        description="Pause-based desync",
        category="Advanced",
        status=VariantStatus.EXPERIMENTAL,
        transport=VariantTransport.HTTP1,
        detectors=("timing", "differential"),
        exploit_support=True,
    ),
    SmugglingVariant.CLIENT_SIDE: VariantCapability(
        variant=SmugglingVariant.CLIENT_SIDE,
        description="Client-side desync",
        category="Advanced",
        status=VariantStatus.EXPERIMENTAL,
        transport=VariantTransport.BROWSER,
        detectors=("timing", "differential"),
        exploit_support=True,
    ),
}


# Default reliability-first set: classic variants only.
DEFAULT_SCAN_VARIANTS: Set[SmugglingVariant] = {
    SmugglingVariant.CL_TE,
    SmugglingVariant.TE_CL,
    SmugglingVariant.TE_TE,
}


def get_capability(variant: SmugglingVariant) -> VariantCapability:
    """Get capability metadata for one variant."""
    return VARIANT_CAPABILITIES[variant]


def list_capabilities(
    statuses: Optional[Set[VariantStatus]] = None,
) -> List[VariantCapability]:
    """List capabilities filtered by status."""
    capabilities = list(VARIANT_CAPABILITIES.values())
    if statuses is None:
        return sorted(capabilities, key=lambda c: c.variant.value)
    return sorted(
        [c for c in capabilities if c.status in statuses],
        key=lambda c: c.variant.value,
    )


def get_implemented_variants() -> Set[SmugglingVariant]:
    """Return variants that are fully implemented."""
    return {
        c.variant
        for c in VARIANT_CAPABILITIES.values()
        if c.status == VariantStatus.IMPLEMENTED
    }


def get_enabled_variants_for_scan() -> Set[SmugglingVariant]:
    """Return default enabled variants for scans."""
    return set(DEFAULT_SCAN_VARIANTS)


def build_variant_map() -> Dict[str, SmugglingVariant]:
    """Build a normalized name -> variant lookup map."""
    mapping: Dict[str, SmugglingVariant] = {}
    for variant in VARIANT_CAPABILITIES:
        mapping[variant.value] = variant
        mapping[variant.value.lower()] = variant
    # Keep common aliases explicit.
    mapping["pause"] = SmugglingVariant.PAUSE_BASED
    mapping["csd"] = SmugglingVariant.CLIENT_SIDE
    return mapping


def classify_requested_variants(
    requested: Iterable[SmugglingVariant],
) -> Tuple[Set[SmugglingVariant], List[Dict[str, str]]]:
    """Split requested variants into enabled and not-testable buckets."""
    enabled: Set[SmugglingVariant] = set()
    not_tested: List[Dict[str, str]] = []

    for variant in requested:
        capability = get_capability(variant)
        if capability.status == VariantStatus.PLANNED:
            not_tested.append(
                {
                    "variant": variant.value,
                    "reason": "not_implemented",
                    "status": capability.status.value,
                }
            )
            continue
        enabled.add(variant)

    return enabled, not_tested
