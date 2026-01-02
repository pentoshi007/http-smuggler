"""Payload generation modules for HTTP Smuggler."""

from .generator import (
    Payload,
    PayloadTemplate,
    PayloadGenerator,
    PayloadCategory,
    CompositePayloadGenerator,
    build_request_line,
    build_header,
    build_headers,
    build_chunked_body,
    build_incomplete_chunked,
    calculate_content_length,
    extract_host_from_url,
    extract_path_from_url,
)
from .obfuscation import (
    TE_OBFUSCATIONS,
    get_te_mutations,
    get_te_mutations_by_category,
    ObfuscationCategory,
)

__all__ = [
    # Generator
    "Payload",
    "PayloadTemplate",
    "PayloadGenerator",
    "PayloadCategory",
    "CompositePayloadGenerator",
    # Building utilities
    "build_request_line",
    "build_header",
    "build_headers",
    "build_chunked_body",
    "build_incomplete_chunked",
    "calculate_content_length",
    "extract_host_from_url",
    "extract_path_from_url",
    # Obfuscation
    "TE_OBFUSCATIONS",
    "get_te_mutations",
    "get_te_mutations_by_category",
    "ObfuscationCategory",
]

