"""Report generation for HTTP Smuggler.

Generates comprehensive reports in multiple formats:
- JSON: Machine-readable format for integration
- Markdown: Human-readable documentation
- Text: Simple console-friendly output
"""

import json
from typing import Optional, List, Dict, Any, Union
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from http_smuggler.core.config import OutputFormat, ReportConfig
from http_smuggler.core.models import (
    ScanResult,
    VulnerabilityReport,
    ProtocolProfile,
)


class Reporter:
    """Generate scan reports in multiple formats."""
    
    def __init__(self, config: Optional[ReportConfig] = None):
        self.config = config or ReportConfig()
    
    def generate(
        self,
        scan_result: ScanResult,
        format: Optional[OutputFormat] = None,
    ) -> str:
        """Generate report in specified format.
        
        Args:
            scan_result: Scan results to report
            format: Output format (default from config)
        
        Returns:
            Formatted report string
        """
        format = format or self.config.format
        
        if format == OutputFormat.JSON:
            return self.to_json(scan_result)
        elif format == OutputFormat.MARKDOWN:
            return self.to_markdown(scan_result)
        else:
            return self.to_text(scan_result)
    
    def to_json(self, scan_result: ScanResult) -> str:
        """Generate JSON format report.
        
        Args:
            scan_result: Scan results
        
        Returns:
            JSON string
        """
        data = scan_result.to_dict()
        
        # Add metadata
        data["_metadata"] = {
            "generator": "HTTP-Smuggler",
            "version": "1.0.0",
            "generated_at": datetime.utcnow().isoformat() + "Z",
        }
        
        return json.dumps(data, indent=2, default=str)
    
    def to_markdown(self, scan_result: ScanResult) -> str:
        """Generate Markdown format report.
        
        Args:
            scan_result: Scan results
        
        Returns:
            Markdown string
        """
        lines = []
        
        # Header
        lines.append("# HTTP Request Smuggling Scan Report")
        lines.append("")
        lines.append(f"**Target:** {scan_result.target}")
        lines.append(f"**Scan Start:** {scan_result.scan_start.isoformat()}")
        lines.append(f"**Scan End:** {scan_result.scan_end.isoformat()}")
        duration = (scan_result.scan_end - scan_result.scan_start).total_seconds()
        lines.append(f"**Duration:** {duration:.2f} seconds")
        lines.append("")
        
        # Summary
        lines.append("## Summary")
        lines.append("")
        lines.append(f"- **Endpoints Discovered:** {scan_result.endpoints_discovered}")
        lines.append(f"- **Endpoints Tested:** {scan_result.endpoints_tested}")
        lines.append(f"- **Vulnerabilities Found:** {len(scan_result.vulnerabilities)}")
        lines.append("")
        
        # Severity breakdown
        critical = len([v for v in scan_result.vulnerabilities if v.severity == "CRITICAL"])
        high = len([v for v in scan_result.vulnerabilities if v.severity == "HIGH"])
        medium = len([v for v in scan_result.vulnerabilities if v.severity == "MEDIUM"])
        low = len([v for v in scan_result.vulnerabilities if v.severity == "LOW"])
        
        if scan_result.vulnerabilities:
            lines.append("### Severity Breakdown")
            lines.append("")
            lines.append(f"| Severity | Count |")
            lines.append("|----------|-------|")
            lines.append(f"| Critical | {critical} |")
            lines.append(f"| High | {high} |")
            lines.append(f"| Medium | {medium} |")
            lines.append(f"| Low | {low} |")
            lines.append("")
        
        # Protocol Information
        lines.append("## Protocol Information")
        lines.append("")
        profile = scan_result.protocol_profile
        lines.append(f"- **Primary Protocol:** {profile.primary_version.value}")
        lines.append(f"- **ALPN Protocols:** {', '.join(profile.alpn_protocols) or 'None'}")
        lines.append(f"- **HTTP/2 Cleartext (h2c):** {'Yes' if profile.supports_h2c else 'No'}")
        lines.append(f"- **WebSocket Support:** {'Yes' if profile.supports_websocket else 'No'}")
        lines.append(f"- **Keep-Alive:** {'Yes' if profile.supports_keepalive else 'No'}")
        lines.append(f"- **Proxy Detected:** {'Yes' if profile.has_proxy else 'No'}")
        
        if profile.server_header:
            lines.append(f"- **Server:** {profile.server_header}")
        if profile.via_header:
            lines.append(f"- **Via:** {profile.via_header}")
        lines.append("")
        
        # Vulnerabilities
        if scan_result.vulnerabilities:
            lines.append("## Vulnerabilities")
            lines.append("")
            
            for i, vuln in enumerate(scan_result.vulnerabilities, 1):
                lines.extend(self._vulnerability_to_markdown(vuln, i))
        else:
            lines.append("## No Vulnerabilities Found")
            lines.append("")
            lines.append("The scan did not detect any HTTP request smuggling vulnerabilities.")
            lines.append("")
        
        # Remediation
        if scan_result.vulnerabilities:
            lines.append("## Remediation Recommendations")
            lines.append("")
            lines.append("### General Recommendations")
            lines.append("")
            lines.append("1. **Use HTTP/2 end-to-end** - Avoid downgrading to HTTP/1.1")
            lines.append("2. **Disable connection reuse** - Between frontend and backend")
            lines.append("3. **Normalize request parsing** - Ensure consistent header interpretation")
            lines.append("4. **Reject ambiguous requests** - Block requests with conflicting headers")
            lines.append("5. **Update server software** - Apply security patches")
            lines.append("")
        
        # Footer
        lines.append("---")
        lines.append("")
        lines.append(f"*Report generated by HTTP-Smuggler at {datetime.utcnow().isoformat()}Z*")
        
        return "\n".join(lines)
    
    def _vulnerability_to_markdown(
        self,
        vuln: VulnerabilityReport,
        index: int,
    ) -> List[str]:
        """Convert vulnerability to Markdown section."""
        lines = []
        
        severity_emoji = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🟢",
        }.get(vuln.severity, "⚪")
        
        lines.append(f"### {severity_emoji} Vulnerability #{index}: {vuln.variant.value}")
        lines.append("")
        lines.append(f"**Endpoint:** `{vuln.endpoint}`")
        lines.append(f"**Severity:** {vuln.severity}")
        lines.append(f"**CWE:** CWE-444 (Inconsistent Interpretation of HTTP Requests)")
        lines.append("")
        
        # Detection details
        lines.append("#### Detection Details")
        lines.append("")
        lines.append(f"- **Method:** {vuln.detection_result.detection_method.value}")
        lines.append(f"- **Confidence:** {vuln.detection_result.confidence:.0%}")
        lines.append(f"- **Response Time:** {vuln.detection_result.response_time:.2f}s")
        lines.append(f"- **Evidence:** {vuln.detection_result.evidence}")
        lines.append("")
        
        # Payload (if configured to include)
        if self.config.include_raw_payloads and vuln.payload_data:
            lines.append("#### Payload")
            lines.append("")
            lines.append("```http")
            raw = vuln.payload_data.get("raw", "")
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8", errors="replace")
            lines.append(raw[:500] + "..." if len(raw) > 500 else raw)
            lines.append("```")
            lines.append("")
        
        # Exploitation (if attempted)
        if vuln.exploitation and self.config.include_exploitation_details:
            lines.append("#### Exploitation")
            lines.append("")
            if vuln.exploitation.successful:
                lines.append(f"✅ **Exploitation Successful**")
                lines.append(f"- Impact: {vuln.exploitation.impact}")
                if vuln.exploitation.captured_data:
                    lines.append(f"- Captured Data: `{vuln.exploitation.captured_data[:100]}...`")
            else:
                lines.append(f"❌ **Exploitation Not Confirmed**")
            lines.append("")
        
        # Impact
        lines.append("#### Potential Impact")
        lines.append("")
        lines.append("- **Session Hijacking:** Attacker can capture other users' requests")
        lines.append("- **Cache Poisoning:** Malicious content served to other users")
        lines.append("- **ACL Bypass:** Access to restricted endpoints")
        lines.append("")
        
        return lines
    
    def to_text(self, scan_result: ScanResult) -> str:
        """Generate plain text format report.
        
        Args:
            scan_result: Scan results
        
        Returns:
            Plain text string
        """
        lines = []
        
        # Header
        lines.append("=" * 60)
        lines.append("HTTP REQUEST SMUGGLING SCAN REPORT")
        lines.append("=" * 60)
        lines.append("")
        lines.append(f"Target: {scan_result.target}")
        lines.append(f"Scan Start: {scan_result.scan_start.isoformat()}")
        lines.append(f"Scan End: {scan_result.scan_end.isoformat()}")
        duration = (scan_result.scan_end - scan_result.scan_start).total_seconds()
        lines.append(f"Duration: {duration:.2f} seconds")
        lines.append("")
        
        # Summary
        lines.append("-" * 40)
        lines.append("SUMMARY")
        lines.append("-" * 40)
        lines.append(f"Endpoints Discovered: {scan_result.endpoints_discovered}")
        lines.append(f"Endpoints Tested: {scan_result.endpoints_tested}")
        lines.append(f"Vulnerabilities Found: {len(scan_result.vulnerabilities)}")
        lines.append("")
        
        # Protocol Info
        lines.append("-" * 40)
        lines.append("PROTOCOL INFORMATION")
        lines.append("-" * 40)
        profile = scan_result.protocol_profile
        lines.append(f"Primary Protocol: {profile.primary_version.value}")
        lines.append(f"ALPN: {', '.join(profile.alpn_protocols) or 'None'}")
        lines.append(f"h2c Support: {'Yes' if profile.supports_h2c else 'No'}")
        lines.append(f"WebSocket: {'Yes' if profile.supports_websocket else 'No'}")
        lines.append(f"Proxy Detected: {'Yes' if profile.has_proxy else 'No'}")
        lines.append("")
        
        # Vulnerabilities
        if scan_result.vulnerabilities:
            lines.append("-" * 40)
            lines.append("VULNERABILITIES")
            lines.append("-" * 40)
            lines.append("")
            
            for i, vuln in enumerate(scan_result.vulnerabilities, 1):
                lines.append(f"[{i}] {vuln.variant.value} - {vuln.severity}")
                lines.append(f"    Endpoint: {vuln.endpoint}")
                lines.append(f"    Confidence: {vuln.detection_result.confidence:.0%}")
                lines.append(f"    Evidence: {vuln.detection_result.evidence}")
                
                if vuln.exploitation:
                    status = "CONFIRMED" if vuln.exploitation.successful else "Not Confirmed"
                    lines.append(f"    Exploitation: {status}")
                
                lines.append("")
        else:
            lines.append("-" * 40)
            lines.append("NO VULNERABILITIES FOUND")
            lines.append("-" * 40)
            lines.append("")
        
        lines.append("=" * 60)
        
        return "\n".join(lines)
    
    def save(
        self,
        scan_result: ScanResult,
        filepath: Union[str, Path],
        format: Optional[OutputFormat] = None,
    ) -> None:
        """Save report to file.
        
        Args:
            scan_result: Scan results
            filepath: Output file path
            format: Output format (inferred from extension if not specified)
        """
        filepath = Path(filepath)
        
        # Infer format from extension if not specified
        if format is None:
            ext = filepath.suffix.lower()
            if ext == ".json":
                format = OutputFormat.JSON
            elif ext in [".md", ".markdown"]:
                format = OutputFormat.MARKDOWN
            else:
                format = OutputFormat.TEXT
        
        content = self.generate(scan_result, format)
        
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)


def generate_report(
    scan_result: ScanResult,
    format: OutputFormat = OutputFormat.JSON,
    filepath: Optional[Union[str, Path]] = None,
    config: Optional[ReportConfig] = None,
) -> str:
    """Convenience function to generate a report.
    
    Args:
        scan_result: Scan results
        format: Output format
        filepath: Optional file to save to
        config: Optional report configuration
    
    Returns:
        Report content string
    """
    reporter = Reporter(config)
    content = reporter.generate(scan_result, format)
    
    if filepath:
        reporter.save(scan_result, filepath, format)
    
    return content

