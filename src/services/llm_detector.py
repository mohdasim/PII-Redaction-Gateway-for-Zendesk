"""Layer 2: LLM-based contextual PII detection.

Uses Claude (primary), OpenAI, or Gemini as fallback providers to detect
context-dependent PII that regex cannot catch — names, addresses in free text,
medical terms associated with individuals, obfuscated PII, etc.
"""

from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod

from src.models.pii_entity import PIIEntity
from src.utils.logger import get_logger

logger = get_logger(__name__)

# System prompt shared across all providers
PII_DETECTION_SYSTEM_PROMPT = """You are a PII detection specialist. Analyze the following text and identify ALL personally identifiable information (PII) and protected health information (PHI).

For each PII entity found, return a JSON array with objects containing:
- "text": the exact substring that is PII (must match the original text exactly)
- "type": one of ["NAME", "ADDRESS", "PHONE", "EMAIL", "SSN", "CREDIT_CARD", "PASSWORD", "PHI", "DATE_OF_BIRTH", "MEDICAL_RECORD", "DIAGNOSIS", "MEDICATION", "OTHER_PII"]
- "confidence": a float from 0.0 to 1.0
- "reasoning": brief explanation of why this is PII

Rules:
1. Be thorough — catch full names, partial addresses, medical terms, implied PII.
2. Consider context — "John" alone may not be PII, but "patient John Smith" is.
3. Detect PII even when obfuscated (e.g., "my social is one two three...").
4. Medication names, diagnoses, and treatment plans are PHI when associated with a person.
5. Return ONLY the JSON array, no other text. No markdown fencing.
6. If no PII is found, return an empty array: []"""

PII_DETECTION_USER_TEMPLATE = """Analyze this text for PII:
---
{text}
---"""

# Max characters to send to LLM per chunk
MAX_CHUNK_SIZE = 12000


class LLMProvider(ABC):
    """Abstract base class for LLM PII detection providers."""

    @abstractmethod
    def detect_pii(self, text: str) -> list[dict]:
        """Send text to LLM and return raw PII detections.

        Returns:
            List of dicts with keys: text, type, confidence, reasoning.
        """

    def _parse_response(self, response_text: str) -> list[dict]:
        """Parse JSON array from LLM response text."""
        text = response_text.strip()
        # Strip markdown code fences if present
        if text.startswith("```"):
            text = text.split("\n", 1)[-1]
            if text.endswith("```"):
                text = text[:-3]
            text = text.strip()

        try:
            result = json.loads(text)
            if isinstance(result, list):
                return result
            return []
        except json.JSONDecodeError:
            # Try to find JSON array in the response
            start = text.find("[")
            end = text.rfind("]")
            if start != -1 and end != -1 and end > start:
                try:
                    return json.loads(text[start : end + 1])
                except json.JSONDecodeError:
                    pass
            logger.warning("Failed to parse LLM response as JSON")
            return []


class ClaudeProvider(LLMProvider):
    """Anthropic Claude provider for PII detection."""

    def __init__(self, api_key: str, model: str = "claude-sonnet-4-20250514"):
        import anthropic

        self._client = anthropic.Anthropic(api_key=api_key, timeout=10.0)
        self._model = model

    def detect_pii(self, text: str) -> list[dict]:
        response = self._client.messages.create(
            model=self._model,
            max_tokens=2048,
            temperature=0,
            system=PII_DETECTION_SYSTEM_PROMPT,
            messages=[
                {"role": "user", "content": PII_DETECTION_USER_TEMPLATE.format(text=text)}
            ],
        )
        return self._parse_response(response.content[0].text)


class OpenAIProvider(LLMProvider):
    """OpenAI provider for PII detection."""

    def __init__(self, api_key: str, model: str = "gpt-4o-mini"):
        import openai

        self._client = openai.OpenAI(api_key=api_key, timeout=10.0)
        self._model = model

    def detect_pii(self, text: str) -> list[dict]:
        response = self._client.chat.completions.create(
            model=self._model,
            max_tokens=2048,
            temperature=0,
            messages=[
                {"role": "system", "content": PII_DETECTION_SYSTEM_PROMPT},
                {"role": "user", "content": PII_DETECTION_USER_TEMPLATE.format(text=text)},
            ],
        )
        return self._parse_response(response.choices[0].message.content or "[]")


class GeminiProvider(LLMProvider):
    """Google Gemini provider for PII detection."""

    def __init__(self, api_key: str, model: str = "gemini-1.5-flash"):
        import google.generativeai as genai

        genai.configure(api_key=api_key)
        self._model = genai.GenerativeModel(
            model,
            system_instruction=PII_DETECTION_SYSTEM_PROMPT,
        )

    def detect_pii(self, text: str) -> list[dict]:
        response = self._model.generate_content(
            PII_DETECTION_USER_TEMPLATE.format(text=text),
            generation_config={"temperature": 0, "max_output_tokens": 2048},
        )
        return self._parse_response(response.text)


class LLMDetector:
    """Multi-provider LLM PII detector with fallback chain.

    Tries the primary provider first. If it fails, falls back to secondary
    and tertiary providers in order.
    """

    # Map of provider names to classes and their API key config field
    PROVIDER_MAP = {
        "claude": ("anthropic_api_key", ClaudeProvider),
        "openai": ("openai_api_key", OpenAIProvider),
        "gemini": ("gemini_api_key", GeminiProvider),
    }

    FALLBACK_ORDER = {
        "claude": ["openai", "gemini"],
        "openai": ["claude", "gemini"],
        "gemini": ["claude", "openai"],
    }

    def __init__(
        self,
        primary_provider: str = "claude",
        api_keys: dict[str, str] | None = None,
        confidence_threshold: float = 0.7,
    ):
        self._primary = primary_provider
        self._api_keys = api_keys or {}
        self._confidence_threshold = confidence_threshold
        self._providers: list[tuple[str, LLMProvider]] = []
        self._init_providers()

    def _init_providers(self):
        """Initialize the provider fallback chain."""
        provider_order = [self._primary] + self.FALLBACK_ORDER.get(self._primary, [])

        for name in provider_order:
            key_field, provider_cls = self.PROVIDER_MAP[name]
            api_key = self._api_keys.get(key_field, "")
            if api_key:
                try:
                    provider = provider_cls(api_key=api_key)
                    self._providers.append((name, provider))
                except Exception as e:
                    logger.warning(f"Failed to initialize {name} provider: {e}")

    def detect(self, text: str) -> list[PIIEntity]:
        """Detect PII using LLM with fallback chain.

        Args:
            text: Text to analyze for PII.

        Returns:
            List of PIIEntity objects detected by the LLM.
        """
        if not text or not self._providers:
            return []

        # Chunk long text
        chunks = self._chunk_text(text)
        all_entities: list[PIIEntity] = []

        for chunk_text, chunk_offset in chunks:
            entities = self._detect_chunk(chunk_text, chunk_offset)
            all_entities.extend(entities)

        return all_entities

    def _detect_chunk(self, text: str, offset: int) -> list[PIIEntity]:
        """Detect PII in a single text chunk, trying providers in order."""
        for name, provider in self._providers:
            try:
                raw_detections = provider.detect_pii(text)
                entities = self._map_to_entities(raw_detections, text, offset)
                logger.info(
                    f"LLM detection complete via {name}",
                    extra={"extra_fields": {"provider": name, "detections": len(entities)}},
                )
                return entities
            except Exception as e:
                logger.warning(
                    f"LLM provider {name} failed, trying next",
                    extra={"extra_fields": {"provider": name, "error": str(e)}},
                )
                continue

        logger.warning("All LLM providers failed — returning empty results")
        return []

    def _map_to_entities(
        self, detections: list[dict], text: str, offset: int
    ) -> list[PIIEntity]:
        """Map raw LLM detections to PIIEntity objects with character offsets."""
        entities: list[PIIEntity] = []

        for det in detections:
            pii_text = det.get("text", "")
            pii_type = det.get("type", "OTHER_PII")
            confidence = float(det.get("confidence", 0.5))

            # Skip low-confidence detections
            if confidence < self._confidence_threshold:
                continue

            # Find the text in the original to get character offsets
            idx = text.find(pii_text)
            if idx == -1:
                # Try case-insensitive search
                lower_text = text.lower()
                idx = lower_text.find(pii_text.lower())
                if idx == -1:
                    continue

            # Normalize type names
            pii_type = self._normalize_type(pii_type)

            entities.append(
                PIIEntity(
                    pii_type=pii_type,
                    start=idx + offset,
                    end=idx + len(pii_text) + offset,
                    confidence=confidence,
                    detection_method="llm",
                )
            )

        return entities

    @staticmethod
    def _normalize_type(pii_type: str) -> str:
        """Normalize LLM-returned PII type to our standard types."""
        type_map = {
            "NAME": "NAME",
            "PERSON_NAME": "NAME",
            "FULL_NAME": "NAME",
            "ADDRESS": "ADDRESS",
            "STREET_ADDRESS": "ADDRESS",
            "PHONE": "PHONE",
            "PHONE_NUMBER": "PHONE",
            "EMAIL": "EMAIL",
            "EMAIL_ADDRESS": "EMAIL",
            "SSN": "SSN",
            "SOCIAL_SECURITY": "SSN",
            "SOCIAL_SECURITY_NUMBER": "SSN",
            "CREDIT_CARD": "CREDIT_CARD",
            "CREDIT_CARD_NUMBER": "CREDIT_CARD",
            "PASSWORD": "PASSWORD",
            "CREDENTIAL": "PASSWORD",
            "PHI": "PHI",
            "MEDICAL_RECORD": "PHI",
            "DIAGNOSIS": "PHI",
            "MEDICATION": "PHI",
            "DATE_OF_BIRTH": "DATE_OF_BIRTH",
            "DOB": "DATE_OF_BIRTH",
        }
        return type_map.get(pii_type.upper(), "OTHER_PII")

    @staticmethod
    def _chunk_text(text: str) -> list[tuple[str, int]]:
        """Split text into chunks with their offset in the original.

        Returns:
            List of (chunk_text, offset) tuples.
        """
        if len(text) <= MAX_CHUNK_SIZE:
            return [(text, 0)]

        chunks: list[tuple[str, int]] = []
        start = 0
        while start < len(text):
            end = min(start + MAX_CHUNK_SIZE, len(text))

            # Try to break at a sentence or paragraph boundary
            if end < len(text):
                for sep in ("\n\n", "\n", ". ", " "):
                    break_point = text.rfind(sep, start, end)
                    if break_point > start:
                        end = break_point + len(sep)
                        break

            chunks.append((text[start:end], start))
            start = end

        return chunks

    @property
    def provider_name(self) -> str:
        """Return the name of the first available provider."""
        if self._providers:
            return self._providers[0][0]
        return "none"
