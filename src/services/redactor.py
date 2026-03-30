"""Applies redaction to text based on detected PII entities.

Supports two redaction styles:
- "bracket": Replace PII with [REDACTED-TYPE], e.g., [REDACTED-SSN]
- "mask": Replace PII with asterisks of the same length
"""

from __future__ import annotations

from src.models.pii_entity import PIIEntity, RedactionResult


class Redactor:
    """Applies redaction replacements to text fields."""

    def __init__(self, style: str = "bracket"):
        """Initialize the redactor.

        Args:
            style: Redaction style — "bracket" or "mask".
        """
        if style not in ("bracket", "mask"):
            raise ValueError(f"Invalid redaction style: {style}. Must be 'bracket' or 'mask'.")
        self._style = style

    def redact(self, text: str, entities: list[PIIEntity]) -> RedactionResult:
        """Redact PII from text based on detected entities.

        Entities are processed from end to start so that character offsets
        remain valid after each replacement.

        Args:
            text: Original text containing PII.
            entities: List of PIIEntity objects to redact.

        Returns:
            RedactionResult with redacted text and metadata.
        """
        if not entities:
            return RedactionResult(
                original_length=len(text),
                redacted_text=text,
                entities_found=[],
                redaction_count=0,
            )

        # Merge overlapping entities first
        merged = self._merge_overlapping(sorted(entities, key=lambda e: e.start))

        # Apply redactions from end to start
        redacted = text
        for entity in reversed(merged):
            # Clamp to text bounds
            start = max(0, entity.start)
            end = min(len(redacted), entity.end)
            if start >= end:
                continue
            replacement = self._get_replacement(entity, end - start)
            redacted = redacted[:start] + replacement + redacted[end:]

        return RedactionResult(
            original_length=len(text),
            redacted_text=redacted,
            entities_found=merged,
            redaction_count=len(merged),
        )

    def _get_replacement(self, entity: PIIEntity, original_length: int) -> str:
        """Generate the replacement string for a PII entity."""
        if self._style == "bracket":
            return f"[REDACTED-{entity.pii_type}]"
        else:  # mask
            return "*" * original_length

    @staticmethod
    def _merge_overlapping(entities: list[PIIEntity]) -> list[PIIEntity]:
        """Merge overlapping or adjacent entities.

        Args:
            entities: Sorted list of PIIEntity objects (by start position).

        Returns:
            Merged list with no overlaps.
        """
        if not entities:
            return []

        merged: list[PIIEntity] = [entities[0]]

        for entity in entities[1:]:
            last = merged[-1]
            if entity.overlaps(last):
                merged[-1] = last.merge(entity)
            else:
                merged.append(entity)

        return merged
