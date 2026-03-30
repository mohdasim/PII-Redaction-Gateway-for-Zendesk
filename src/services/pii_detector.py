"""Orchestrator for the two-layer PII detection pipeline.

Layer 1: Regex-based detection (fast, free, always runs)
Layer 2: LLM-based detection (contextual, configurable, optional)

Merges and deduplicates results from both layers before passing to the Redactor.
"""

from __future__ import annotations

import time

from src.models.pii_entity import PIIEntity, RedactionResult
from src.services.llm_detector import LLMDetector
from src.services.redactor import Redactor
from src.services.regex_detector import RegexDetector
from src.utils.config import Config
from src.utils.logger import get_logger

logger = get_logger(__name__)


class PIIDetector:
    """Two-layer PII detection and redaction orchestrator."""

    def __init__(self, config: Config):
        self._config = config

        # Layer 1: Always initialize regex detector
        self._regex_detector = RegexDetector(
            enabled_pii_types=config.pii_types_list,
        )

        # Layer 2: LLM detector (optional)
        self._llm_detector: LLMDetector | None = None
        if config.llm_enabled:
            api_keys = {
                "anthropic_api_key": config.anthropic_api_key.get_secret_value(),
                "openai_api_key": config.openai_api_key.get_secret_value(),
                "gemini_api_key": config.gemini_api_key.get_secret_value(),
            }
            # Only create if at least one key is provided
            if any(v for v in api_keys.values()):
                self._llm_detector = LLMDetector(
                    primary_provider=config.llm_provider,
                    api_keys=api_keys,
                    confidence_threshold=config.llm_confidence_threshold,
                )

        # Redactor
        self._redactor = Redactor(style=config.redaction_style)

    def detect_and_redact(self, text: str) -> RedactionResult:
        """Run the full detection and redaction pipeline on a text field.

        Args:
            text: The text to scan and redact.

        Returns:
            RedactionResult with redacted text and entity metadata.
        """
        if not text or not text.strip():
            return RedactionResult(
                original_length=len(text) if text else 0,
                redacted_text=text or "",
                entities_found=[],
                redaction_count=0,
            )

        start_time = time.time()

        # Layer 1: Regex detection (always runs)
        regex_entities = self._regex_detector.detect(text)
        logger.info(
            "Regex detection complete",
            extra={"extra_fields": {"regex_count": len(regex_entities)}},
        )

        # Layer 2: LLM detection (if enabled)
        llm_entities: list[PIIEntity] = []
        if self._llm_detector:
            try:
                llm_entities = self._llm_detector.detect(text)
                logger.info(
                    "LLM detection complete",
                    extra={"extra_fields": {
                        "llm_count": len(llm_entities),
                        "provider": self._llm_detector.provider_name,
                    }},
                )
            except Exception as e:
                logger.warning(
                    "LLM detection failed — proceeding with regex-only results",
                    extra={"extra_fields": {"error": str(e)}},
                )

        # Merge and deduplicate
        all_entities = self._merge_entities(regex_entities, llm_entities)

        elapsed_ms = (time.time() - start_time) * 1000
        logger.info(
            "Detection pipeline complete",
            extra={"extra_fields": {
                "total_entities": len(all_entities),
                "processing_ms": round(elapsed_ms, 1),
            }},
        )

        # Apply redaction
        return self._redactor.redact(text, all_entities)

    @staticmethod
    def _merge_entities(
        regex_entities: list[PIIEntity],
        llm_entities: list[PIIEntity],
    ) -> list[PIIEntity]:
        """Merge regex and LLM detection results, deduplicating overlaps.

        Strategy:
        - If both layers detect the same span, keep higher confidence.
        - If they detect overlapping spans, merge them.
        - Non-overlapping detections from either layer are kept.
        """
        if not llm_entities:
            return regex_entities
        if not regex_entities:
            return llm_entities

        combined = regex_entities + llm_entities
        combined.sort(key=lambda e: (e.start, -e.confidence))

        merged: list[PIIEntity] = [combined[0]]
        for entity in combined[1:]:
            last = merged[-1]
            if entity.overlaps(last):
                merged[-1] = last.merge(entity)
            else:
                merged.append(entity)

        return merged

    @property
    def llm_provider_name(self) -> str:
        """Return the active LLM provider name, or 'none' if disabled."""
        if self._llm_detector:
            return self._llm_detector.provider_name
        return "none"
