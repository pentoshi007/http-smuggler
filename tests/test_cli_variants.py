"""Tests for CLI variant parsing and planned-variant handling."""

import pytest
import click

from http_smuggler.core.models import SmugglingVariant
from http_smuggler.main import _parse_variants


def test_parse_variants_planned_only():
    """Planned-only requests should produce not_tested entries."""
    enabled, not_tested = _parse_variants("CL.CL,H2.0", http2_only=False, classic_only=False)

    assert enabled == set()
    assert len(not_tested) == 2
    assert {entry["variant"] for entry in not_tested} == {"CL.CL", "H2.0"}
    assert all(entry["reason"] == "not_implemented" for entry in not_tested)


def test_parse_variants_mixed_implemented_and_planned():
    """Implemented variants should remain enabled while planned are excluded."""
    enabled, not_tested = _parse_variants("CL.TE,CL.0", http2_only=False, classic_only=False)

    assert SmugglingVariant.CL_TE in enabled
    assert SmugglingVariant.CL_0 not in enabled
    assert any(entry["variant"] == "CL.0" for entry in not_tested)


def test_parse_variants_unknown_is_strict_error():
    """Unknown variants should raise a CLI parameter error."""
    with pytest.raises(click.BadParameter) as exc:
        _parse_variants("NOT.A.VARIANT", http2_only=False, classic_only=False)

    assert "Unknown variant(s)" in str(exc.value)
