"""Unit tests for the Redactor service."""

import pytest

from src.models.pii_entity import PIIEntity
from src.services.redactor import Redactor


class TestRedactorBracketMode:
    """Tests for bracket-style redaction."""

    @pytest.fixture
    def redactor(self):
        return Redactor(style="bracket")

    def test_single_entity(self, redactor):
        text = "My SSN is 123-45-6789 please."
        entity = PIIEntity(pii_type="SSN", start=10, end=21, confidence=0.99)
        result = redactor.redact(text, [entity])

        assert "[REDACTED-SSN]" in result.redacted_text
        assert "123-45-6789" not in result.redacted_text
        assert result.redaction_count == 1
        assert result.original_length == len(text)

    def test_multiple_entities(self, redactor):
        text = "SSN: 123-45-6789, Email: test@test.com"
        entities = [
            PIIEntity(pii_type="SSN", start=5, end=16, confidence=0.99),
            PIIEntity(pii_type="EMAIL", start=25, end=38, confidence=0.99),
        ]
        result = redactor.redact(text, entities)

        assert "[REDACTED-SSN]" in result.redacted_text
        assert "[REDACTED-EMAIL]" in result.redacted_text
        assert result.redaction_count == 2

    def test_no_entities(self, redactor):
        text = "Clean text with no PII."
        result = redactor.redact(text, [])

        assert result.redacted_text == text
        assert result.redaction_count == 0

    def test_entity_at_start(self, redactor):
        text = "test@test.com is my email"
        entity = PIIEntity(pii_type="EMAIL", start=0, end=13, confidence=0.99)
        result = redactor.redact(text, [entity])

        assert result.redacted_text.startswith("[REDACTED-EMAIL]")

    def test_entity_at_end(self, redactor):
        text = "My email is test@test.com"
        entity = PIIEntity(pii_type="EMAIL", start=12, end=25, confidence=0.99)
        result = redactor.redact(text, [entity])

        assert result.redacted_text.endswith("[REDACTED-EMAIL]")


class TestRedactorMaskMode:
    """Tests for mask-style redaction."""

    @pytest.fixture
    def redactor(self):
        return Redactor(style="mask")

    def test_mask_replaces_with_asterisks(self, redactor):
        text = "SSN: 123-45-6789"
        entity = PIIEntity(pii_type="SSN", start=5, end=16, confidence=0.99)
        result = redactor.redact(text, [entity])

        assert result.redacted_text == "SSN: ***********"
        assert result.redaction_count == 1

    def test_mask_preserves_length(self, redactor):
        text = "Email: test@example.com"
        entity = PIIEntity(pii_type="EMAIL", start=7, end=23, confidence=0.99)
        result = redactor.redact(text, [entity])

        assert len(result.redacted_text) == len(text)


class TestRedactorOverlaps:
    """Tests for overlapping entity handling."""

    @pytest.fixture
    def redactor(self):
        return Redactor(style="bracket")

    def test_overlapping_entities_merged(self, redactor):
        text = "Info: 123-45-6789 is my social."
        entities = [
            PIIEntity(pii_type="SSN", start=6, end=17, confidence=0.95),
            PIIEntity(pii_type="SSN", start=6, end=17, confidence=0.99),
        ]
        result = redactor.redact(text, entities)

        # Should merge into one redaction
        assert result.redacted_text.count("[REDACTED-SSN]") == 1
        assert result.redaction_count == 1

    def test_adjacent_entities_not_merged(self, redactor):
        text = "AB CD"
        entities = [
            PIIEntity(pii_type="NAME", start=0, end=2, confidence=0.9),
            PIIEntity(pii_type="NAME", start=3, end=5, confidence=0.9),
        ]
        result = redactor.redact(text, entities)
        assert result.redaction_count == 2


class TestRedactorEdgeCases:
    """Edge case tests."""

    def test_invalid_style_raises(self):
        with pytest.raises(ValueError):
            Redactor(style="invalid")

    def test_unicode_text(self):
        redactor = Redactor(style="bracket")
        text = "Email: user@example.com, Name: Müller"
        entity = PIIEntity(pii_type="EMAIL", start=7, end=23, confidence=0.99)
        result = redactor.redact(text, [entity])
        assert "[REDACTED-EMAIL]" in result.redacted_text
        assert "Müller" in result.redacted_text

    def test_entities_to_audit_dict(self):
        redactor = Redactor(style="bracket")
        text = "SSN: 123-45-6789"
        entity = PIIEntity(pii_type="SSN", start=5, end=16, confidence=0.99)
        result = redactor.redact(text, [entity])

        audit = result.to_audit_dict()
        assert audit["redaction_count"] == 1
        assert len(audit["entities"]) == 1
        assert "start" in audit["entities"][0]
        # Ensure no actual PII in audit
        assert "123-45-6789" not in str(audit)
