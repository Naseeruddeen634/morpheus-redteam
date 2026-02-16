"""Configuration for Morpheus Red-Teaming Framework."""

import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Settings:
    openai_api_key: str = field(default_factory=lambda: os.getenv("OPENAI_API_KEY", ""))
    target_model: str = field(default_factory=lambda: os.getenv("TARGET_MODEL", "gpt-4"))
    probes_per_category: int = field(
        default_factory=lambda: int(os.getenv("PROBES_PER_CATEGORY", "10"))
    )
    max_concurrent: int = field(
        default_factory=lambda: int(os.getenv("MAX_CONCURRENT", "5"))
    )
    temperature: float = field(
        default_factory=lambda: float(os.getenv("TEMPERATURE", "0.7"))
    )
    eval_temperature: float = field(
        default_factory=lambda: float(os.getenv("EVAL_TEMPERATURE", "0.1"))
    )
    max_tokens: int = field(
        default_factory=lambda: int(os.getenv("MAX_TOKENS", "1024"))
    )
    report_dir: str = field(
        default_factory=lambda: os.getenv("REPORT_DIR", "./reports")
    )
    api_host: str = field(default_factory=lambda: os.getenv("API_HOST", "0.0.0.0"))
    api_port: int = field(default_factory=lambda: int(os.getenv("API_PORT", "8003")))

    # Attack categories available
    all_categories: tuple = (
        "jailbreak", "injection", "bias", "extraction", "hallucination"
    )

    def __post_init__(self):
        if not self.openai_api_key:
            raise ValueError("OPENAI_API_KEY is required.")
        Path(self.report_dir).mkdir(parents=True, exist_ok=True)


def get_settings() -> Settings:
    return Settings()
