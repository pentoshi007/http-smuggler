"""Tests for variant capability registry behavior."""

from http_smuggler.core.models import SmugglingVariant
from http_smuggler.core.variant_registry import (
    VariantStatus,
    build_variant_map,
    classify_requested_variants,
    get_capability,
    get_enabled_variants_for_scan,
    get_implemented_variants,
)


def test_default_scan_set_is_implemented_only():
    """Default scan variants must all be fully implemented."""
    defaults = get_enabled_variants_for_scan()
    implemented = get_implemented_variants()
    assert defaults
    assert defaults.issubset(implemented)


def test_classify_requested_variants_marks_planned():
    """Planned variants should be moved to not_tested with a clear reason."""
    enabled, not_tested = classify_requested_variants(
        {
            SmugglingVariant.CL_TE,
            SmugglingVariant.CL_CL,
        }
    )

    assert SmugglingVariant.CL_TE in enabled
    assert SmugglingVariant.CL_CL not in enabled
    assert any(
        entry["variant"] == SmugglingVariant.CL_CL.value
        and entry["reason"] == "not_implemented"
        and entry["status"] == VariantStatus.PLANNED.value
        for entry in not_tested
    )


def test_variant_map_handles_aliases():
    """Variant map should handle common aliases and case-insensitive lookup."""
    variant_map = build_variant_map()

    assert variant_map["cl.te"] == SmugglingVariant.CL_TE
    assert variant_map["pause"] == SmugglingVariant.PAUSE_BASED
    assert variant_map["csd"] == SmugglingVariant.CLIENT_SIDE


def test_capability_registry_has_transport_and_status():
    """Each capability should expose status/transport metadata."""
    capability = get_capability(SmugglingVariant.H2_TE)
    assert capability.status in {
        VariantStatus.IMPLEMENTED,
        VariantStatus.EXPERIMENTAL,
        VariantStatus.PLANNED,
    }
    assert capability.transport.value in {"http1", "http2", "websocket", "browser"}
