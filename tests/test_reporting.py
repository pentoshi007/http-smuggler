"""Tests for reporting output with capability notes."""

from datetime import datetime

from http_smuggler.analysis.reporter import Reporter
from http_smuggler.core.config import OutputFormat, ReportConfig
from http_smuggler.core.models import HttpVersion, ProtocolProfile, ScanResult


def _scan_result_with_notes() -> ScanResult:
    now = datetime.utcnow()
    return ScanResult(
        target="https://example.com",
        scan_start=now,
        scan_end=now,
        protocol_profile=ProtocolProfile(
            primary_version=HttpVersion.HTTP_1_1,
            alpn_protocols=["http/1.1"],
            supports_h2c=False,
            supports_websocket=False,
            supports_keepalive=True,
            server_header="test",
            via_header=None,
        ),
        endpoints_discovered=1,
        endpoints_tested=1,
        vulnerabilities=[],
        not_tested=[{"variant": "CL.CL", "reason": "not_implemented", "status": "planned"}],
        skipped=[{"endpoint": "https://example.com", "variant": "H2.CL", "reason": "http2_tls_required"}],
    )


def test_markdown_includes_capability_notes():
    """Markdown report should include not-tested and skipped sections."""
    reporter = Reporter(ReportConfig(format=OutputFormat.MARKDOWN))
    content = reporter.to_markdown(_scan_result_with_notes())

    assert "## Capability Notes" in content
    assert "### Not Tested Variants" in content
    assert "### Skipped Checks" in content
    assert "CL.CL" in content
    assert "http2_tls_required" in content


def test_text_includes_not_tested_and_skipped_counts():
    """Text report should include counts and detailed note lines."""
    reporter = Reporter(ReportConfig(format=OutputFormat.TEXT))
    content = reporter.to_text(_scan_result_with_notes())

    assert "Not Tested Variants: 1" in content
    assert "Skipped Checks: 1" in content
    assert "CL.CL: not_implemented" in content
    assert "H2.CL @ https://example.com: http2_tls_required" in content
