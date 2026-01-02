"""HTTP-Smuggler: Advanced HTTP Request Smuggling Detection Tool.

A comprehensive tool for detecting and exploiting HTTP request smuggling
vulnerabilities across all known variants including CL.TE, TE.CL, TE.TE,
HTTP/2 downgrade attacks, and WebSocket smuggling.
"""

__version__ = "1.0.0"
__author__ = "Security Research Team"

from http_smuggler.core.config import ScanConfig, ScanMode
from http_smuggler.core.engine import SmugglerEngine, run_scan
from http_smuggler.core.models import ScanResult, VulnerabilityReport

__all__ = [
    "__version__",
    "ScanConfig",
    "ScanMode",
    "SmugglerEngine",
    "run_scan",
    "ScanResult",
    "VulnerabilityReport",
]

