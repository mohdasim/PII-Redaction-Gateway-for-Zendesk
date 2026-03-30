"""Data models for PII detection and redaction results."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class PIIEntity:
    """A single detected PII span in text.

    Attributes:
        pii_type: Category of PII (e.g., SSN, CREDIT_CARD, EMAIL, PHONE,
                  PASSWORD, PHI, ADDRESS, NAME, DATE_OF_BIRTH).
        start: Character offset where the PII begins in the original text.
        end: Character offset where the PII ends (exclusive).
        confidence: Detection confidence score between 0.0 and 1.0.
        detection_method: How it was detected — "regex" or "llm".
    """

    pii_type: str
    start: int
    end: int
    confidence: float = 1.0
    detection_method: str = "regex"

    @property
    def length(self) -> int:
        return self.end - self.start

    def overlaps(self, other: PIIEntity) -> bool:
        """Check if this entity overlaps with another."""
        return self.start < other.end and other.start < self.end

    def merge(self, other: PIIEntity) -> PIIEntity:
        """Merge two overlapping entities, keeping the higher confidence."""
        return PIIEntity(
            pii_type=self.pii_type if self.confidence >= other.confidence else other.pii_type,
            start=min(self.start, other.start),
            end=max(self.end, other.end),
            confidence=max(self.confidence, other.confidence),
            detection_method=(
                self.detection_method
                if self.confidence >= other.confidence
                else other.detection_method
            ),
        )

    def to_audit_dict(self) -> dict:
        """Return audit-safe representation (no actual PII text)."""
        return {
            "pii_type": self.pii_type,
            "start": self.start,
            "end": self.end,
            "confidence": self.confidence,
            "detection_method": self.detection_method,
        }


@dataclass
class RedactionResult:
    """Result of a redaction operation on a single text field.

    Attributes:
        original_length: Length of the original text.
        redacted_text: The text after redaction has been applied.
        entities_found: List of PII entities that were detected.
        redaction_count: Number of redactions applied.
    """

    original_length: int
    redacted_text: str
    entities_found: list[PIIEntity] = field(default_factory=list)
    redaction_count: int = 0

    def to_audit_dict(self) -> dict:
        """Return audit-safe representation."""
        return {
            "original_length": self.original_length,
            "redacted_length": len(self.redacted_text),
            "redaction_count": self.redaction_count,
            "entities": [e.to_audit_dict() for e in self.entities_found],
        }
