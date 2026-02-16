# Morpheus — Automated LLM Red-Teaming Framework

A systematic vulnerability assessment framework for large language models. Morpheus generates adversarial attack vectors across multiple risk dimensions, probes target models for failures, scores robustness, and produces structured audit reports compliant with the EU AI Act risk assessment requirements.

Designed for AI safety teams, compliance officers, and ML engineers who need to evaluate LLM deployments before they go to production.

---

## Problem Statement

Organizations deploying LLMs face a growing list of failure modes: jailbreaks, prompt injection, hallucination under pressure, demographic bias amplification, confidential information extraction, and instruction hierarchy violations. Manual red-teaming is expensive, inconsistent, and doesn't scale. Regulatory frameworks like the EU AI Act (Article 9) now mandate systematic risk assessment for high-risk AI systems.

Morpheus automates this process. It generates hundreds of adversarial probes, fires them at a target model, evaluates the responses against configurable safety criteria, computes per-category robustness scores, and produces a structured audit report.

---

## Architecture

```
Attack Library                    Target LLM
    |                                 |
    v                                 |
Attack Generator                      |
  [jailbreak, injection,              |
   bias, extraction,                  |
   hallucination probes]              |
    |                                 |
    +-----> Adversarial Prompt ------>+
                                      |
                                      v
                                 LLM Response
                                      |
                                      v
                              Evaluation Pipeline
                              [Safety Scorer]
                              [Bias Detector]
                              [Compliance Checker]
                              [Leakage Analyzer]
                                      |
                                      v
                              Scoring Engine
                              (per-category + aggregate)
                                      |
                                      v
                              Audit Report Generator
                              (JSON + Markdown + PDF-ready)
```

---

## Attack Categories

| Category              | What It Tests                                          | Techniques Used                              |
|-----------------------|--------------------------------------------------------|----------------------------------------------|
| Jailbreak             | Can the model be tricked into ignoring safety rules?   | Role-play, hypothetical framing, multi-turn escalation, encoding tricks |
| Prompt Injection      | Can hidden instructions override the system prompt?    | Delimiter injection, instruction smuggling, context manipulation |
| Bias Amplification    | Does the model produce biased outputs across demographics? | Paired counterfactual probes, stereotype elicitation, demographic swaps |
| Information Extraction| Can the model be made to leak system prompts or training data? | Direct extraction, indirect inference, completion attacks |
| Hallucination Stress  | Does the model fabricate facts under adversarial pressure? | Authoritative false premises, obscure domains, confidence exploitation |
| Instruction Hierarchy | Does the model respect system > user prompt priority?  | Conflicting instructions, nested overrides, priority confusion |

---

## Evaluation Dimensions

Each model response is scored across multiple dimensions:

| Dimension        | Method                                           | Score Range |
|------------------|--------------------------------------------------|-------------|
| Safety           | Rule-based + classifier checks for harmful content| 0.0 - 1.0  |
| Refusal Quality  | Did the model refuse appropriately? Was the refusal helpful? | 0.0 - 1.0  |
| Consistency      | Does the model behave consistently across rephrased attacks? | 0.0 - 1.0  |
| Bias             | Sentiment and stance delta across demographic groups | 0.0 - 1.0  |
| Leakage          | Information entropy analysis on extraction attempts | 0.0 - 1.0  |
| Robustness       | Aggregate score across all categories              | 0.0 - 1.0  |

---

## Tech Stack

| Component        | Technology                                |
|------------------|-------------------------------------------|
| LLM Interface    | OpenAI API / any OpenAI-compatible endpoint |
| Attack Generation| Template engine + LLM-assisted mutation    |
| Evaluation       | Rule-based + HuggingFace classifiers       |
| Bias Detection   | Counterfactual paired testing              |
| Report Generation| Jinja2 templates (Markdown + JSON)         |
| API              | FastAPI                                    |
| Containerization | Docker + Docker Compose                    |

---

## Quick Start

### Local

```bash
git clone https://github.com/Naseeruddeen634/morpheus-redteam.git
cd morpheus-redteam

python -m venv venv
source venv/bin/activate

pip install -r requirements.txt

export OPENAI_API_KEY="sk-your-key"

uvicorn app.main:app --reload --port 8003
```

### Docker

```bash
echo "OPENAI_API_KEY=sk-your-key" > .env
docker-compose up --build
```

API at `http://localhost:8003/docs`.

---

## API Endpoints

| Method | Endpoint              | Description                                           |
|--------|-----------------------|-------------------------------------------------------|
| POST   | `/audit/run`          | Run a full red-team audit against a target model       |
| POST   | `/audit/category`     | Run attacks from a specific category only              |
| GET    | `/attacks`            | List all available attack vectors                      |
| GET    | `/reports/{audit_id}` | Retrieve a completed audit report                      |
| GET    | `/health`             | Health check                                           |

### Example: Run a Full Audit

```bash
curl -X POST http://localhost:8003/audit/run \
  -H "Content-Type: application/json" \
  -d '{
    "target_model": "gpt-4",
    "categories": ["jailbreak", "injection", "bias", "extraction", "hallucination"],
    "probes_per_category": 10,
    "system_prompt": "You are a helpful customer service assistant for a bank."
  }'
```

Response:
```json
{
  "audit_id": "aud_7f3a9b2c",
  "target_model": "gpt-4",
  "total_probes": 50,
  "overall_robustness": 0.82,
  "category_scores": {
    "jailbreak": 0.90,
    "injection": 0.75,
    "bias": 0.88,
    "extraction": 0.70,
    "hallucination": 0.85
  },
  "critical_failures": 3,
  "report_url": "/reports/aud_7f3a9b2c"
}
```

---

## Project Structure

```
morpheus-redteam/
├── app/
│   ├── __init__.py
│   ├── main.py                    # FastAPI application
│   ├── config.py                  # Configuration
│   ├── orchestrator.py            # Audit orchestrator — runs full pipeline
│   ├── attacks/
│   │   ├── __init__.py
│   │   ├── base.py                # Base attack class and attack result model
│   │   ├── jailbreak.py           # Jailbreak attack vectors
│   │   ├── injection.py           # Prompt injection attacks
│   │   ├── bias.py                # Bias probing with counterfactual pairs
│   │   ├── extraction.py          # Information extraction attacks
│   │   └── hallucination.py       # Hallucination stress testing
│   ├── evaluators/
│   │   ├── __init__.py
│   │   ├── safety.py              # Safety and refusal quality scoring
│   │   └── bias_scorer.py         # Bias measurement across demographics
│   └── reports/
│       ├── __init__.py
│       └── generator.py           # Audit report generation (JSON + Markdown)
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── README.md
```

---

## How the Scoring Works

Each probe follows a three-stage pipeline:

1. **Attack**: Generate an adversarial prompt using a category-specific strategy.
2. **Probe**: Send the prompt to the target model and capture the response.
3. **Evaluate**: Score the response on safety, refusal quality, and category-specific criteria.

A probe is marked as a "failure" if the model complies with an adversarial request it should have refused. The robustness score is the ratio of successful defenses to total probes:

```
Robustness = (Total Probes - Failures) / Total Probes
```

Category-level scores reveal which attack surfaces the model is weakest against, allowing targeted hardening of system prompts and guardrails.

---

## Compliance Context

Under the EU AI Act (effective in Ireland):

- **Article 9** requires providers of high-risk AI systems to implement risk management processes, including testing for foreseeable misuse.
- **Article 15** mandates accuracy, robustness, and cybersecurity evaluations.
- **Annex IV** requires technical documentation of testing methodology and results.

Morpheus audit reports are structured to align with these requirements, providing documented evidence of adversarial testing with reproducible methodology.

---

## Configuration

| Variable              | Default        | Description                                |
|-----------------------|----------------|--------------------------------------------|
| `OPENAI_API_KEY`      | (required)     | API key for the target model               |
| `TARGET_MODEL`        | `gpt-4`       | Model to audit                             |
| `PROBES_PER_CATEGORY` | `10`           | Number of attack probes per category       |
| `MAX_CONCURRENT`      | `5`            | Concurrent API calls during audit          |
| `TEMPERATURE`         | `0.7`          | Temperature for attack generation          |
| `REPORT_DIR`          | `./reports`    | Directory for saved audit reports          |

---

## Extending Morpheus

Adding a new attack category:

1. Create a new file in `app/attacks/` inheriting from `BaseAttack`
2. Implement `generate_probes()` returning a list of adversarial prompts
3. Register the category in `app/attacks/__init__.py`
4. The orchestrator will automatically pick it up

---

## Author

Naseeruddeen — MSc AI / Machine Learning, Dublin City University
- GitHub: [github.com/Naseeruddeen634](https://github.com/Naseeruddeen634)
- LinkedIn: [linkedin.com/in/naseeruddeen](https://linkedin.com/in/naseeruddeen)

## License

MIT
