"""Tests for payload generation."""

import pytest

from http_smuggler.core.models import Endpoint, SmugglingVariant
from http_smuggler.payloads.generator import PayloadCategory
from http_smuggler.payloads.classic import (
    CLTEPayloadGenerator,
    TECLPayloadGenerator,
    TETEPayloadGenerator,
)
from http_smuggler.payloads.obfuscation import (
    TE_OBFUSCATIONS,
    get_te_mutations,
    get_categories_summary,
)


class TestCLTEPayloadGenerator:
    """Tests for CL.TE payload generator."""
    
    def test_generator_variant(self):
        """Test generator returns correct variant."""
        gen = CLTEPayloadGenerator()
        assert gen.variant == SmugglingVariant.CL_TE
    
    def test_generate_timing_payloads(self, sample_endpoint):
        """Test timing payload generation."""
        gen = CLTEPayloadGenerator()
        payloads = gen.generate_timing_payloads(sample_endpoint)
        
        assert len(payloads) > 0
        for payload in payloads:
            assert payload.category == PayloadCategory.TIMING
            assert payload.variant == SmugglingVariant.CL_TE
            assert len(payload.raw_request) > 0
    
    def test_generate_differential_payloads(self, sample_endpoint):
        """Test differential payload generation."""
        gen = CLTEPayloadGenerator()
        payloads = gen.generate_differential_payloads(sample_endpoint)
        
        assert len(payloads) > 0
        for payload in payloads:
            assert payload.category == PayloadCategory.DIFFERENTIAL
            assert payload.variant == SmugglingVariant.CL_TE


class TestTECLPayloadGenerator:
    """Tests for TE.CL payload generator."""
    
    def test_generator_variant(self):
        """Test generator returns correct variant."""
        gen = TECLPayloadGenerator()
        assert gen.variant == SmugglingVariant.TE_CL
    
    def test_generate_all_payloads(self, sample_endpoint):
        """Test generating all payloads."""
        gen = TECLPayloadGenerator()
        payloads = gen.generate_all_payloads(sample_endpoint)
        
        assert len(payloads) > 0
        
        timing = [p for p in payloads if p.category == PayloadCategory.TIMING]
        differential = [p for p in payloads if p.category == PayloadCategory.DIFFERENTIAL]
        
        assert len(timing) > 0
        assert len(differential) > 0


class TestTEObfuscations:
    """Tests for Transfer-Encoding obfuscations."""
    
    def test_obfuscation_count(self):
        """Test we have 50+ obfuscations."""
        assert len(TE_OBFUSCATIONS) >= 50
    
    def test_get_te_mutations(self):
        """Test getting mutation strings."""
        mutations = get_te_mutations()
        
        assert len(mutations) == len(TE_OBFUSCATIONS)
        assert all(isinstance(m, str) for m in mutations)
    
    def test_categories_summary(self):
        """Test category summary."""
        summary = get_categories_summary()
        
        assert len(summary) > 0
        total = sum(summary.values())
        assert total == len(TE_OBFUSCATIONS)
    
    def test_all_have_chunked(self):
        """Test all obfuscations reference chunked encoding."""
        for obf in TE_OBFUSCATIONS:
            # Most should contain 'chunked' in some form
            header_lower = obf.header.lower()
            assert 'chunk' in header_lower or 'transfer' in header_lower

