"""
Audit orchestrator.
Coordinates the full red-teaming pipeline: attack generation,
model probing, response evaluation, scoring, and report generation.
"""

import hashlib
import logging
import time
from datetime import datetime, timezone

from langchain_openai import ChatOpenAI

from app.config import Settings
from app.attacks.jailbreak import JailbreakAttack
from app.attacks.injection import InjectionAttack
from app.attacks.bias import BiasAttack
from app.attacks.extraction import ExtractionAttack
from app.attacks.hallucination import HallucinationAttack
from app.attacks.base import AttackProbe, Severity
from app.evaluators.safety import SafetyEvaluator
from app.evaluators.bias_scorer import BiasScorer
from app.reports.generator import ReportGenerator

logger = logging.getLogger(__name__)


# Map category names to attack classes
ATTACK_REGISTRY = {
    "jailbreak": JailbreakAttack,
    "injection": InjectionAttack,
    "bias": BiasAttack,
    "extraction": ExtractionAttack,
    "hallucination": HallucinationAttack,
}


class AuditOrchestrator:
    """Runs a full red-team audit against a target LLM."""

    def __init__(self, settings: Settings):
        self.settings = settings

        # Target model (the one being audited)
        self.target_llm = ChatOpenAI(
            model_name=settings.target_model,
            openai_api_key=settings.openai_api_key,
            temperature=0.7,
            max_tokens=settings.max_tokens,
        )

        # Evaluator model (judges the target's responses)
        self.safety_evaluator = SafetyEvaluator(
            api_key=settings.openai_api_key,
            model=settings.target_model,
            temperature=settings.eval_temperature,
        )

        self.bias_scorer = BiasScorer(
            api_key=settings.openai_api_key,
            model=settings.target_model,
            temperature=settings.eval_temperature,
        )

        self.report_generator = ReportGenerator(report_dir=settings.report_dir)

        logger.info(
            f"Orchestrator ready — target: {settings.target_model}, "
            f"probes/category: {settings.probes_per_category}"
        )

    def run_audit(
        self,
        categories: list[str] | None = None,
        probes_per_category: int | None = None,
        system_prompt: str = "",
    ) -> dict:
        """
        Execute a full red-team audit.

        1. Generate attack probes for each category
        2. Fire probes at the target model
        3. Evaluate each response
        4. Score per-category robustness
        5. Generate audit report
        """
        start_time = time.time()

        cats = categories or list(self.settings.all_categories)
        count = probes_per_category or self.settings.probes_per_category

        # Generate audit ID
        audit_id = self._generate_audit_id()
        logger.info(f"Starting audit {audit_id} — categories: {cats}, probes: {count}/cat")

        all_results = []
        category_scores = {}
        critical_failures = []

        for cat_name in cats:
            if cat_name not in ATTACK_REGISTRY:
                logger.warning(f"Unknown category: {cat_name}, skipping")
                continue

            attack_class = ATTACK_REGISTRY[cat_name]()
            probes = attack_class.generate_probes(count=count, system_prompt=system_prompt)

            logger.info(f"Running {len(probes)} probes for category: {cat_name}")

            cat_results = []
            for probe in probes:
                result = self._execute_probe(probe, system_prompt)
                cat_results.append(result)
                all_results.append(result)

                if result.get("is_failure") and result.get("severity") in ("critical", "high"):
                    critical_failures.append(result)

            # Calculate category robustness
            if cat_results:
                failures = sum(1 for r in cat_results if r.get("is_failure", False))
                robustness = (len(cat_results) - failures) / len(cat_results)
                category_scores[cat_name] = round(robustness, 4)
            else:
                category_scores[cat_name] = 1.0

        # Calculate overall robustness
        if all_results:
            total_failures = sum(1 for r in all_results if r.get("is_failure", False))
            overall_robustness = (len(all_results) - total_failures) / len(all_results)
        else:
            overall_robustness = 1.0

        # Generate report
        report = self.report_generator.generate(
            audit_id=audit_id,
            target_model=self.settings.target_model,
            results=all_results,
            category_scores=category_scores,
            overall_robustness=overall_robustness,
            critical_failures=critical_failures,
        )

        elapsed = round(time.time() - start_time, 2)

        return {
            "audit_id": audit_id,
            "target_model": self.settings.target_model,
            "total_probes": len(all_results),
            "overall_robustness": round(overall_robustness, 4),
            "category_scores": category_scores,
            "critical_failures": len(critical_failures),
            "total_time_seconds": elapsed,
            "report_paths": report,
        }

    def run_category(
        self,
        category: str,
        probes_count: int | None = None,
        system_prompt: str = "",
    ) -> dict:
        """Run probes for a single attack category."""
        return self.run_audit(
            categories=[category],
            probes_per_category=probes_count,
            system_prompt=system_prompt,
        )

    def _execute_probe(self, probe: AttackProbe, system_prompt: str = "") -> dict:
        """Fire a single probe at the target model and evaluate the response."""
        from langchain.schema import HumanMessage, SystemMessage

        # Build messages
        messages = []
        if system_prompt:
            messages.append(SystemMessage(content=system_prompt))
        messages.append(HumanMessage(content=probe.prompt))

        # Get target model response
        try:
            response = self.target_llm.invoke(messages)
            model_response = response.content
        except Exception as e:
            logger.error(f"Probe failed: {e}")
            model_response = f"[ERROR: {str(e)}]"

        # Evaluate the response
        eval_result = self.safety_evaluator.evaluate(
            prompt=probe.prompt,
            response=model_response,
            expected_behavior=probe.expected_behavior,
        )

        return {
            "category": probe.category,
            "technique": probe.technique,
            "prompt": probe.prompt[:200] + "..." if len(probe.prompt) > 200 else probe.prompt,
            "expected_behavior": probe.expected_behavior,
            "model_response": model_response[:500] + "..." if len(model_response) > 500 else model_response,
            "safety_score": eval_result["safety_score"],
            "refusal_quality": eval_result["refusal_quality"],
            "is_failure": eval_result["is_failure"],
            "severity": probe.severity_if_failed.value,
            "notes": eval_result["notes"],
        }

    def get_available_attacks(self) -> list[dict]:
        """List all available attack categories."""
        return [
            cls().get_info() for cls in ATTACK_REGISTRY.values()
        ]

    def _generate_audit_id(self) -> str:
        timestamp = datetime.now(timezone.utc).isoformat()
        hash_input = f"{timestamp}_{self.settings.target_model}"
        return "aud_" + hashlib.md5(hash_input.encode()).hexdigest()[:8]
