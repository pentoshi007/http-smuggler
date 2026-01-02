from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from enum import Enum, auto
from datetime import datetime


class HttpVersion(Enum):
    HTTP_1_0 = "HTTP/1.0"
    HTTP_1_1 = "HTTP/1.1"
    HTTP_2 = "HTTP/2"
    UNKNOWN = "Unknown"


class SmugglingVariant(Enum):
    CL_TE = "CL.TE"
    TE_CL = "TE.CL"
    TE_TE = "TE.TE"
    CL_CL = "CL.CL"
    CL_0 = "CL.0"
    ZERO_CL = "0.CL"
    H2_CL = "H2.CL"
    H2_TE = "H2.TE"
    H2_0 = "H2.0"
    H2C = "h2c"
    H2_CRLF = "H2.CRLF"
    H2_TUNNEL = "H2.Tunnel"
    WS_VERSION = "WS.Version"
    WS_UPGRADE = "WS.Upgrade"
    PAUSE_BASED = "Pause"
    CLIENT_SIDE = "CSD"


class DetectionMethod(Enum):
    TIMING = "timing"
    DIFFERENTIAL = "differential"
    ECHO = "echo"


@dataclass
class Endpoint:
    url: str
    method: str = "GET"
    content_type: Optional[str] = None
    accepts_body: bool = False
    discovered_from: Optional[str] = None


@dataclass
class ProtocolProfile:
    primary_version: HttpVersion
    alpn_protocols: List[str]
    supports_h2c: bool
    supports_websocket: bool
    supports_keepalive: bool
    server_header: Optional[str]
    via_header: Optional[str]

    @property
    def has_proxy(self) -> bool:
        return self.via_header is not None


@dataclass
class DetectionResult:
    payload_name: str
    variant: SmugglingVariant
    vulnerable: bool
    confidence: float
    response_time: float
    response_status: Optional[int]
    evidence: str
    detection_method: DetectionMethod


@dataclass
class ExploitationResult:
    attempted: bool
    successful: bool
    impact: Optional[str] = None
    captured_data: Optional[str] = None
    steps: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None


@dataclass
class VulnerabilityReport:
    endpoint: str
    variant: SmugglingVariant
    severity: str
    detection_result: DetectionResult
    payload_data: Dict[str, Any]
    exploitation: Optional[ExploitationResult] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": f"{self.variant.value}-{hash(self.endpoint) % 10000}",
            "endpoint": self.endpoint,
            "variant": self.variant.value,
            "severity": self.severity,
            "cwe": "CWE-444",
            "cvss_estimate": self._estimate_cvss(),
            "detection": {
                "method": self.detection_result.detection_method.value,
                "confidence": self.detection_result.confidence,
                "response_time": self.detection_result.response_time,
                "evidence": self.detection_result.evidence,
            },
            "payload": self.payload_data,
            "exploitation": self.exploitation.__dict__
            if self.exploitation
            else {"attempted": False},
            "impact": self._describe_impact(),
            "remediation": self._get_remediation(),
        }

    def _estimate_cvss(self) -> float:
        base_scores = {
            SmugglingVariant.CL_TE: 8.1,
            SmugglingVariant.TE_CL: 8.1,
            SmugglingVariant.TE_TE: 7.5,
            SmugglingVariant.H2_CL: 8.6,
            SmugglingVariant.H2_TE: 8.6,
            SmugglingVariant.H2_CRLF: 9.1,
            SmugglingVariant.WS_VERSION: 7.5,
            SmugglingVariant.CL_0: 7.5,
        }

        score = base_scores.get(self.variant, 7.0)

        if self.exploitation and self.exploitation.successful:
            score = min(score + 0.5, 10.0)

        return score

    def _describe_impact(self) -> Dict[str, Any]:
        return {
            "summary": "HTTP Request Smuggling enables severe attacks including session hijacking and cache poisoning",
            "potential_attacks": {
                "session_hijacking": {
                    "possible": True,
                    "description": "Attacker can capture other users' session cookies",
                },
                "cache_poisoning": {
                    "possible": True,
                    "description": "Attacker can poison web cache to serve malicious content",
                },
                "access_control_bypass": {
                    "possible": True,
                    "description": "Attacker can access restricted endpoints",
                },
            },
        }

    def _get_remediation(self) -> Dict[str, Any]:
        return {
            "general": [
                "Ensure frontend and backend use same method for request boundaries",
                "Use HTTP/2 end-to-end without downgrading",
                "Disable connection reuse between frontend and backend",
            ],
            "priority": "HIGH" if self.severity in ["CRITICAL", "HIGH"] else "MEDIUM",
        }


@dataclass
class ScanResult:
    target: str
    scan_start: datetime
    scan_end: datetime
    protocol_profile: ProtocolProfile
    endpoints_discovered: int
    endpoints_tested: int
    vulnerabilities: List[VulnerabilityReport]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "scan_start": self.scan_start.isoformat(),
            "scan_end": self.scan_end.isoformat(),
            "duration_seconds": (self.scan_end - self.scan_start).total_seconds(),
            "protocol": {
                "version": self.protocol_profile.primary_version.value,
                "alpn": self.protocol_profile.alpn_protocols,
                "h2c_supported": self.protocol_profile.supports_h2c,
                "websocket_supported": self.protocol_profile.supports_websocket,
                "proxy_detected": self.protocol_profile.has_proxy,
            },
            "discovery": {
                "endpoints_found": self.endpoints_discovered,
                "endpoints_tested": self.endpoints_tested,
            },
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "summary": {
                "total_vulnerabilities": len(self.vulnerabilities),
                "critical": len(
                    [v for v in self.vulnerabilities if v.severity == "CRITICAL"]
                ),
                "high": len([v for v in self.vulnerabilities if v.severity == "HIGH"]),
                "variants_found": list(
                    set(v.variant.value for v in self.vulnerabilities)
                ),
            },
        }
