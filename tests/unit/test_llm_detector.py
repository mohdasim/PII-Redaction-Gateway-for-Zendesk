"""Unit tests for the LLM-based PII detector."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from src.services.llm_detector import LLMDetector, LLMProvider


class MockProvider(LLMProvider):
    """Mock LLM provider for testing."""

    def __init__(self, responses=None, should_fail=False, api_key=None):
        self._responses = responses or []
        self._should_fail = should_fail
        self._call_count = 0

    def detect_pii(self, text):
        self._call_count += 1
        if self._should_fail:
            raise Exception("Provider unavailable")
        return self._responses


class TestLLMDetector:
    """Tests for the LLM detector orchestration."""

    def test_detect_maps_to_entities(self):
        """LLM detections are mapped to PIIEntity objects with correct offsets."""
        detector = LLMDetector.__new__(LLMDetector)
        detector._confidence_threshold = 0.7
        detector._providers = [
            ("mock", MockProvider(responses=[
                {"text": "John Smith", "type": "NAME", "confidence": 0.95, "reasoning": "Full name"},
                {"text": "john@example.com", "type": "EMAIL", "confidence": 0.99, "reasoning": "Email"},
            ]))
        ]

        text = "Patient John Smith can be reached at john@example.com."
        entities = detector.detect(text)

        assert len(entities) == 2
        name_entity = next(e for e in entities if e.pii_type == "NAME")
        assert name_entity.confidence == 0.95
        assert name_entity.detection_method == "llm"
        assert text[name_entity.start:name_entity.end] == "John Smith"

    def test_low_confidence_filtered(self):
        """Detections below confidence threshold are filtered out."""
        detector = LLMDetector.__new__(LLMDetector)
        detector._confidence_threshold = 0.7
        detector._providers = [
            ("mock", MockProvider(responses=[
                {"text": "maybe", "type": "NAME", "confidence": 0.3, "reasoning": "Uncertain"},
                {"text": "john@test.com", "type": "EMAIL", "confidence": 0.9, "reasoning": "Email"},
            ]))
        ]

        text = "Maybe john@test.com is the contact."
        entities = detector.detect(text)

        assert len(entities) == 1
        assert entities[0].pii_type == "EMAIL"

    def test_fallback_on_provider_failure(self):
        """Falls back to secondary provider when primary fails."""
        primary = MockProvider(should_fail=True)
        secondary = MockProvider(responses=[
            {"text": "Jane Doe", "type": "NAME", "confidence": 0.9, "reasoning": "Name"},
        ])

        detector = LLMDetector.__new__(LLMDetector)
        detector._confidence_threshold = 0.7
        detector._providers = [("primary", primary), ("secondary", secondary)]

        text = "Contact Jane Doe for details."
        entities = detector.detect(text)

        assert len(entities) == 1
        assert primary._call_count == 1
        assert secondary._call_count == 1

    def test_all_providers_fail_returns_empty(self):
        """Returns empty list when all providers fail."""
        detector = LLMDetector.__new__(LLMDetector)
        detector._confidence_threshold = 0.7
        detector._providers = [
            ("p1", MockProvider(should_fail=True)),
            ("p2", MockProvider(should_fail=True)),
        ]

        entities = detector.detect("Some text")
        assert entities == []

    def test_empty_text_returns_empty(self):
        """Empty input text returns empty list."""
        detector = LLMDetector.__new__(LLMDetector)
        detector._confidence_threshold = 0.7
        detector._providers = [("mock", MockProvider())]

        assert detector.detect("") == []

    def test_no_providers_returns_empty(self):
        """No configured providers returns empty list."""
        detector = LLMDetector.__new__(LLMDetector)
        detector._confidence_threshold = 0.7
        detector._providers = []

        assert detector.detect("Some text with PII") == []

    def test_type_normalization(self):
        """LLM-returned types are normalized to standard types."""
        assert LLMDetector._normalize_type("PERSON_NAME") == "NAME"
        assert LLMDetector._normalize_type("PHONE_NUMBER") == "PHONE"
        assert LLMDetector._normalize_type("SOCIAL_SECURITY_NUMBER") == "SSN"
        assert LLMDetector._normalize_type("CREDIT_CARD_NUMBER") == "CREDIT_CARD"
        assert LLMDetector._normalize_type("MEDICATION") == "PHI"
        assert LLMDetector._normalize_type("DOB") == "DATE_OF_BIRTH"
        assert LLMDetector._normalize_type("UNKNOWN_TYPE") == "OTHER_PII"

    def test_text_chunking(self):
        """Long text is split into chunks."""
        chunks = LLMDetector._chunk_text("a" * 20000)
        assert len(chunks) >= 2
        # All offsets should be non-negative and chunks should cover full text
        total_len = sum(len(c[0]) for c in chunks)
        assert total_len == 20000

    def test_text_chunking_short_text(self):
        """Short text is not chunked."""
        chunks = LLMDetector._chunk_text("short text")
        assert len(chunks) == 1
        assert chunks[0] == ("short text", 0)

    def test_provider_name(self):
        """Provider name returns first available provider."""
        detector = LLMDetector.__new__(LLMDetector)
        detector._providers = [("claude", MockProvider())]
        assert detector.provider_name == "claude"

    def test_provider_name_none(self):
        """Provider name returns 'none' when no providers configured."""
        detector = LLMDetector.__new__(LLMDetector)
        detector._providers = []
        assert detector.provider_name == "none"


class TestLLMProviderResponseParsing:
    """Tests for LLM response JSON parsing."""

    def test_parse_valid_json_array(self):
        provider = MockProvider()
        result = provider._parse_response('[{"text": "test", "type": "NAME"}]')
        assert len(result) == 1

    def test_parse_empty_array(self):
        provider = MockProvider()
        result = provider._parse_response("[]")
        assert result == []

    def test_parse_markdown_fenced(self):
        provider = MockProvider()
        result = provider._parse_response('```json\n[{"text": "test"}]\n```')
        assert len(result) == 1

    def test_parse_json_with_surrounding_text(self):
        provider = MockProvider()
        result = provider._parse_response('Here are the results: [{"text": "John"}] end')
        assert len(result) == 1

    def test_parse_invalid_json(self):
        provider = MockProvider()
        result = provider._parse_response("This is not JSON at all")
        assert result == []

    def test_parse_non_array_json(self):
        provider = MockProvider()
        result = provider._parse_response('{"text": "not an array"}')
        assert result == []
