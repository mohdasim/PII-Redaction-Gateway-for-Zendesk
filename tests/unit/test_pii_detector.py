"""Unit tests for the PIIDetector orchestrator."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from src.models.pii_entity import PIIEntity
from src.services.pii_detector import PIIDetector
from src.utils.config import Config


@pytest.fixture
def config_no_llm():
    """Config with LLM disabled."""
    return Config(
        llm_enabled=False,
        redaction_style="bracket",
        enabled_pii_types="SSN,CREDIT_CARD,EMAIL,PHONE,PASSWORD,PHI,ADDRESS,NAME,DATE_OF_BIRTH",
        webhook_secret="test",
        zendesk_subdomain="test",
        zendesk_email="test@test.com",
        zendesk_api_token="test",
        audit_s3_bucket="test-bucket",
    )


class TestPIIDetectorRegexOnly:
    """Tests with LLM disabled (regex-only mode)."""

    def test_detect_ssn(self, config_no_llm):
        detector = PIIDetector(config_no_llm)
        result = detector.detect_and_redact("My SSN is 123-45-6789.")

        assert result.redaction_count >= 1
        assert "[REDACTED-SSN]" in result.redacted_text
        assert "123-45-6789" not in result.redacted_text

    def test_detect_email(self, config_no_llm):
        detector = PIIDetector(config_no_llm)
        result = detector.detect_and_redact("Email: test@example.com")

        assert result.redaction_count >= 1
        assert "[REDACTED-EMAIL]" in result.redacted_text

    def test_detect_multiple_types(self, config_no_llm):
        detector = PIIDetector(config_no_llm)
        text = "SSN: 456-78-9012, email: john@test.com, phone (555) 123-4567"
        result = detector.detect_and_redact(text)

        assert result.redaction_count >= 2
        assert "456-78-9012" not in result.redacted_text
        assert "john@test.com" not in result.redacted_text

    def test_clean_text_no_redaction(self, config_no_llm):
        detector = PIIDetector(config_no_llm)
        result = detector.detect_and_redact("Hello, I have a question about pricing.")

        assert result.redaction_count == 0
        assert result.redacted_text == "Hello, I have a question about pricing."

    def test_empty_text(self, config_no_llm):
        detector = PIIDetector(config_no_llm)
        result = detector.detect_and_redact("")

        assert result.redaction_count == 0
        assert result.redacted_text == ""

    def test_whitespace_only(self, config_no_llm):
        detector = PIIDetector(config_no_llm)
        result = detector.detect_and_redact("   ")

        assert result.redaction_count == 0

    def test_llm_provider_name_disabled(self, config_no_llm):
        detector = PIIDetector(config_no_llm)
        assert detector.llm_provider_name == "none"


class TestPIIDetectorMerging:
    """Tests for entity merging logic."""

    def test_merge_overlapping_same_type(self):
        regex = [PIIEntity("SSN", 0, 11, 0.95, "regex")]
        llm = [PIIEntity("SSN", 0, 11, 0.99, "llm")]

        merged = PIIDetector._merge_entities(regex, llm)
        assert len(merged) == 1
        assert merged[0].confidence == 0.99

    def test_merge_non_overlapping(self):
        regex = [PIIEntity("SSN", 0, 11, 0.95, "regex")]
        llm = [PIIEntity("EMAIL", 20, 35, 0.90, "llm")]

        merged = PIIDetector._merge_entities(regex, llm)
        assert len(merged) == 2

    def test_merge_empty_llm(self):
        regex = [PIIEntity("SSN", 0, 11, 0.95, "regex")]
        merged = PIIDetector._merge_entities(regex, [])
        assert merged == regex

    def test_merge_empty_regex(self):
        llm = [PIIEntity("NAME", 0, 10, 0.85, "llm")]
        merged = PIIDetector._merge_entities([], llm)
        assert merged == llm
