"""Detection modules for HTTP Smuggler."""

from .protocol import ProtocolDetector, ProtocolDetectionResult, detect_protocols
from .timing import TimingDetector, BaselineResult, timing_detect
from .differential import DifferentialDetector, DifferentialTestResult, differential_detect

__all__ = [
    # Protocol detection
    "ProtocolDetector",
    "ProtocolDetectionResult",
    "detect_protocols",
    # Timing detection
    "TimingDetector",
    "BaselineResult",
    "timing_detect",
    # Differential detection
    "DifferentialDetector",
    "DifferentialTestResult",
    "differential_detect",
]
