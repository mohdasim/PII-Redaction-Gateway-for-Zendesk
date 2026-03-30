"""Layer 1: Fast regex-based PII detection.

Uses compiled regex patterns with optional validators (e.g., Luhn check for
credit cards, prefix validation for SSNs) to detect structured PII. This is
the first pass in the detection pipeline — fast, free, and catches ~80% of
structured PII.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

from src.models.pii_entity import PIIEntity


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

def luhn_check(number: str) -> bool:
    """Validate a credit card number using the Luhn algorithm."""
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    odd_digits = digits[-1::-2]
    even_digits = digits[-2::-2]
    total = sum(odd_digits) + sum(sum(divmod(2 * d, 10)) for d in even_digits)
    return total % 10 == 0


def validate_ssn(value: str) -> bool:
    """Reject known-invalid SSN prefixes and all-zero groups."""
    digits_only = re.sub(r"[\s-]", "", value)
    if len(digits_only) != 9:
        return False
    area, group, serial = digits_only[:3], digits_only[3:5], digits_only[5:]
    # Invalid area numbers
    if area in ("000", "666") or int(area) >= 900:
        return False
    # No group can be all zeros
    if group == "00" or serial == "0000":
        return False
    return True


def validate_phone(value: str) -> bool:
    """Validate phone number has reasonable digit count."""
    digits = re.sub(r"\D", "", value)
    return 7 <= len(digits) <= 15


def validate_credit_card(value: str) -> bool:
    """Validate credit card with Luhn check and known prefixes."""
    digits_only = re.sub(r"[\s-]", "", value)
    if not luhn_check(digits_only):
        return False
    # Check known card prefixes
    if digits_only[0] == "4":  # Visa
        return len(digits_only) in (13, 16, 19)
    if digits_only[:2] in ("34", "37"):  # Amex
        return len(digits_only) == 15
    first_two = int(digits_only[:2])
    first_four = int(digits_only[:4])
    if 51 <= first_two <= 55 or 2221 <= first_four <= 2720:  # Mastercard
        return len(digits_only) == 16
    if digits_only[:4] == "6011" or digits_only[:2] == "65":  # Discover
        return len(digits_only) == 16
    # Accept any other Luhn-valid 13-19 digit number as potential card
    return True


def validate_icd10(value: str) -> bool:
    """Basic ICD-10 code validation — must start with valid category letter."""
    valid_prefixes = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ") - {"U"}  # U is reserved
    return len(value) >= 3 and value[0] in valid_prefixes


# ---------------------------------------------------------------------------
# Pattern registry
# ---------------------------------------------------------------------------

@dataclass
class PIIPattern:
    """A compiled regex pattern with metadata for PII detection."""

    pii_type: str
    regex: re.Pattern
    validator: Callable[[str], bool] | None = None
    confidence: float = 0.95
    group: int = 0  # Which capture group contains the PII


# All patterns are compiled once at module load time
_PATTERNS: list[PIIPattern] = [
    # --- SSN ---
    PIIPattern(
        pii_type="SSN",
        regex=re.compile(
            r"(?i)(?:ssn|social\s+security)[\s:#]*"
            r"(\d{3}[-\s]?\d{2}[-\s]?\d{4})"
        ),
        validator=validate_ssn,
        confidence=0.99,
        group=1,
    ),
    PIIPattern(
        pii_type="SSN",
        regex=re.compile(r"\b(\d{3}-\d{2}-\d{4})\b"),
        validator=validate_ssn,
        confidence=0.95,
    ),

    # --- Credit Card ---
    PIIPattern(
        pii_type="CREDIT_CARD",
        regex=re.compile(
            r"\b(\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{1,4})\b"
        ),
        validator=validate_credit_card,
        confidence=0.95,
    ),
    # Amex format: 4-6-5
    PIIPattern(
        pii_type="CREDIT_CARD",
        regex=re.compile(r"\b(\d{4}[-\s]?\d{6}[-\s]?\d{5})\b"),
        validator=validate_credit_card,
        confidence=0.95,
    ),

    # --- Email ---
    PIIPattern(
        pii_type="EMAIL",
        regex=re.compile(
            r"\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b"
        ),
        confidence=0.99,
    ),

    # --- Phone Numbers ---
    # US format: (xxx) xxx-xxxx, xxx-xxx-xxxx, xxx.xxx.xxxx, +1 xxx xxx xxxx
    PIIPattern(
        pii_type="PHONE",
        regex=re.compile(
            r"(?:\+?1[-.\s]?)?"
            r"\(?[2-9]\d{2}\)?[-.\s]?"
            r"\d{3}[-.\s]?\d{4}"
        ),
        validator=validate_phone,
        confidence=0.90,
    ),
    # International format
    PIIPattern(
        pii_type="PHONE",
        regex=re.compile(r"\b(\+[1-9]\d{6,14})\b"),
        validator=validate_phone,
        confidence=0.85,
    ),

    # --- Passwords / Credentials ---
    PIIPattern(
        pii_type="PASSWORD",
        regex=re.compile(
            r"(?i)(?:password|passwd|pwd|secret|token|api[_\s]?key|"
            r"private[_\s]?key|access[_\s]?key|auth[_\s]?token)"
            r"[\s:=]+[\"']?(\S{4,})[\"']?"
        ),
        confidence=0.95,
        group=1,
    ),

    # --- PHI: Medical Record Numbers ---
    PIIPattern(
        pii_type="PHI",
        regex=re.compile(
            r"(?i)(?:MRN|medical\s+record|patient\s+id|health\s+id)"
            r"[\s:#]*(\w{4,})"
        ),
        confidence=0.90,
        group=1,
    ),

    # --- PHI: Date of Birth ---
    PIIPattern(
        pii_type="DATE_OF_BIRTH",
        regex=re.compile(
            r"(?i)(?:DOB|date\s+of\s+birth|born|birthday)"
            r"[\s:]*(\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4})"
        ),
        confidence=0.95,
        group=1,
    ),

    # --- PHI: ICD-10 Diagnosis Codes ---
    PIIPattern(
        pii_type="PHI",
        regex=re.compile(
            r"(?i)(?:diagnosis|dx|icd)[\s:#]*"
            r"([A-Z]\d{2}(?:\.\d{1,4})?)"
        ),
        validator=validate_icd10,
        confidence=0.85,
        group=1,
    ),

    # --- Addresses ---
    PIIPattern(
        pii_type="ADDRESS",
        regex=re.compile(
            r"\b(\d{1,5}\s+(?:[A-Z][a-z]+\s+){1,3}"
            r"(?:St|Street|Ave|Avenue|Blvd|Boulevard|Dr|Drive|Rd|Road|"
            r"Ln|Lane|Ct|Court|Way|Pl|Place|Cir|Circle|Trl|Trail|"
            r"Pkwy|Parkway|Hwy|Highway)\.?)"
            r"(?:\s*,?\s*(?:Apt|Suite|Unit|#)\s*\w+)?",
            re.IGNORECASE,
        ),
        confidence=0.85,
        group=1,
    ),
    # ZIP code in address context
    PIIPattern(
        pii_type="ADDRESS",
        regex=re.compile(
            r"(?i)(?:zip|postal|address|city|state)[\s,:]*.*?"
            r"(\b\d{5}(?:-\d{4})?\b)"
        ),
        confidence=0.80,
        group=1,
    ),
]


class RegexDetector:
    """Fast pattern-based PII detector using compiled regexes."""

    def __init__(self, enabled_pii_types: list[str] | None = None):
        """Initialize with optional PII type filter.

        Args:
            enabled_pii_types: List of PII types to detect. None means all.
        """
        if enabled_pii_types is not None:
            enabled = set(enabled_pii_types)
            self._patterns = [p for p in _PATTERNS if p.pii_type in enabled]
        else:
            self._patterns = list(_PATTERNS)

    def detect(self, text: str) -> list[PIIEntity]:
        """Detect PII entities in the given text.

        Args:
            text: The text to scan for PII.

        Returns:
            List of PIIEntity objects found, deduplicated.
        """
        if not text:
            return []

        entities: list[PIIEntity] = []

        for pattern in self._patterns:
            for match in pattern.regex.finditer(text):
                matched_text = match.group(pattern.group) if pattern.group else match.group(0)
                if not matched_text:
                    continue

                # Run validator if present
                if pattern.validator and not pattern.validator(matched_text):
                    continue

                # Calculate offsets for the captured group
                if pattern.group:
                    start = match.start(pattern.group)
                    end = match.end(pattern.group)
                else:
                    start = match.start()
                    end = match.end()

                entities.append(
                    PIIEntity(
                        pii_type=pattern.pii_type,
                        start=start,
                        end=end,
                        confidence=pattern.confidence,
                        detection_method="regex",
                    )
                )

        return self._deduplicate(entities)

    @staticmethod
    def _deduplicate(entities: list[PIIEntity]) -> list[PIIEntity]:
        """Remove duplicate/overlapping entities, keeping higher confidence."""
        if not entities:
            return []

        # Sort by start position, then by confidence descending
        sorted_entities = sorted(entities, key=lambda e: (e.start, -e.confidence))

        result: list[PIIEntity] = [sorted_entities[0]]
        for entity in sorted_entities[1:]:
            last = result[-1]
            if entity.overlaps(last):
                # Merge overlapping entities
                result[-1] = last.merge(entity)
            else:
                result.append(entity)

        return result
