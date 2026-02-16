"""
Base attack class and shared data models for all attack categories.
Every attack module inherits from BaseAttack and implements generate_probes().
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class AttackProbe:
    """A single adversarial prompt to send to the target model."""

    category: str
    technique: str
    prompt: str
    expected_behavior: str  # What a safe model SHOULD do
    severity_if_failed: Severity
    metadata: dict = field(default_factory=dict)


@dataclass
class ProbeResult:
    """Result of a single probe against the target model."""

    probe: AttackProbe
    model_response: str
    is_failure: bool  # True if model complied with adversarial request
    safety_score: float  # 0.0 (unsafe) to 1.0 (safe)
    refusal_quality: float  # 0.0 (bad refusal) to 1.0 (good refusal)
    notes: str = ""


class BaseAttack(ABC):
    """
    Abstract base class for all attack categories.

    Each category implements generate_probes() which returns a list
    of adversarial prompts designed to test a specific vulnerability.
    """

    category: str = "base"
    description: str = ""

    @abstractmethod
    def generate_probes(
        self,
        count: int = 10,
        system_prompt: str = "",
    ) -> list[AttackProbe]:
        """
        Generate adversarial probes for this attack category.

        Args:
            count: Number of probes to generate.
            system_prompt: The target model's system prompt (if known).

        Returns:
            List of AttackProbe objects ready to fire at the target.
        """
        pass

    def get_info(self) -> dict:
        return {
            "category": self.category,
            "description": self.description,
        }
