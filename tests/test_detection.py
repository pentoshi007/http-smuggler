"""Tests for detection modules."""

import pytest

from http_smuggler.detection.timing import TimingDetector, BaselineResult
from http_smuggler.detection.differential import DifferentialDetector
from http_smuggler.core.config import SafetyConfig, NetworkConfig


class TestBaselineResult:
    """Tests for baseline timing results."""
    
    def test_is_timeout_high_multiplier(self):
        """Test timeout detection with high response time."""
        baseline = BaselineResult(
            avg_time=1.0,
            min_time=0.5,
            max_time=1.5,
            std_dev=0.2,
            samples=[0.8, 1.0, 1.2],
        )
        
        # 5x average should be timeout
        assert baseline.is_timeout(5.5)
        
        # Normal response should not be timeout
        assert not baseline.is_timeout(1.2)
    
    def test_is_timeout_absolute(self):
        """Test absolute timeout threshold."""
        baseline = BaselineResult(
            avg_time=0.5,
            min_time=0.3,
            max_time=0.7,
            std_dev=0.1,
            samples=[0.4, 0.5, 0.6],
        )
        
        # 6 seconds with max of 0.7 should be timeout
        assert baseline.is_timeout(6.0)


class TestTimingDetector:
    """Tests for timing detector."""
    
    def test_init_with_defaults(self):
        """Test detector initialization."""
        detector = TimingDetector()
        
        assert detector.baseline_requests == 3
        assert detector.timeout_threshold == 5.0
        assert detector.confidence_threshold == 0.7
    
    def test_init_with_config(self):
        """Test detector with custom config."""
        safety = SafetyConfig(timing_detection_timeout=15.0)
        network = NetworkConfig(connect_timeout=10.0)
        
        detector = TimingDetector(safety, network)
        
        assert detector.safety.timing_detection_timeout == 15.0
        assert detector.network.connect_timeout == 10.0


class TestDifferentialDetector:
    """Tests for differential detector."""
    
    def test_init_with_defaults(self):
        """Test detector initialization."""
        detector = DifferentialDetector()
        
        assert detector.confidence_threshold == 0.7
        assert 404 in detector.POISON_STATUS_CODES
    
    def test_poison_patterns(self):
        """Test poison patterns are defined."""
        detector = DifferentialDetector()
        
        assert len(detector.POISON_PATTERNS) > 0
        assert b"GPOST" in detector.POISON_PATTERNS

