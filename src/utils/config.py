"""Central configuration management using Pydantic Settings."""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Literal

from pydantic import SecretStr
from pydantic_settings import BaseSettings


class Config(BaseSettings):
    """Application configuration loaded from environment variables."""

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "extra": "ignore"}

    # LLM Configuration
    llm_provider: Literal["claude", "openai", "gemini"] = "claude"
    llm_enabled: bool = True
    llm_confidence_threshold: float = 0.7
    anthropic_api_key: SecretStr = SecretStr("")
    openai_api_key: SecretStr = SecretStr("")
    gemini_api_key: SecretStr = SecretStr("")

    # Zendesk Configuration
    zendesk_subdomain: str = ""
    zendesk_email: str = ""
    zendesk_api_token: SecretStr = SecretStr("")

    # Webhook Authentication
    webhook_secret: SecretStr = SecretStr("")

    # Redaction Configuration
    redaction_style: Literal["bracket", "mask"] = "bracket"
    enabled_pii_types: str = "SSN,CREDIT_CARD,EMAIL,PHONE,PASSWORD,PHI,ADDRESS,NAME,DATE_OF_BIRTH"

    # AWS / Audit
    audit_s3_bucket: str = "pii-redaction-audit-bucket"
    aws_region: str = "us-east-1"

    # Logging
    log_level: str = "INFO"

    @property
    def pii_types_list(self) -> list[str]:
        """Return enabled PII types as a list."""
        return [t.strip() for t in self.enabled_pii_types.split(",") if t.strip()]


@lru_cache(maxsize=1)
def get_config() -> Config:
    """Return a cached singleton Config instance."""
    return Config()
