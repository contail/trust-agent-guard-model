"""Security Judge prompt evaluation script.

Calls Ollama (or any OpenAI-compatible endpoint) with the security judge prompt
and test cases, then compares results against expected verdicts.

Usage:
    # Start Ollama first: ollama serve
    python -m security-judge.eval.run_judge_eval

    # Custom endpoint / model:
    JUDGE_BASE_URL=http://localhost:11434/v1 JUDGE_MODEL=qwen3:8b python -m security-judge.eval.run_judge_eval
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import httpx

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SYSTEM_PROMPT_PATH = PROJECT_ROOT / "prompts" / os.getenv("JUDGE_PROMPT", "system_prompt_v2.txt")
TEST_CASES_PATH = PROJECT_ROOT / "prompts" / os.getenv("JUDGE_CASES", "test_cases_v2.json")
RESULTS_DIR = PROJECT_ROOT / "eval" / "results"

# ---------------------------------------------------------------------------
# Config (env vars with defaults for local Ollama)
# ---------------------------------------------------------------------------

BASE_URL = os.getenv("JUDGE_BASE_URL", "http://localhost:11434/v1")
API_KEY = os.getenv("JUDGE_API_KEY", "ollama")
MODEL = os.getenv("JUDGE_MODEL", "qwen3:8b")
TIMEOUT = float(os.getenv("JUDGE_TIMEOUT", "60"))


def load_system_prompt() -> str:
    return SYSTEM_PROMPT_PATH.read_text(encoding="utf-8")


def load_test_cases() -> list[dict]:
    return json.loads(TEST_CASES_PATH.read_text(encoding="utf-8"))


def build_user_content(case: dict) -> str:
    lines: list[str] = []

    lines.append("## Detect Adapter Results")
    lines.append("")
    lines.append("| Adapter | Score | Label |")
    lines.append("|---------|-------|-------|")
    for det in case["detect_results"]:
        lines.append(f"| {det['model_id']} | {det['score']:.3f} | {det['label']} |")
    lines.append("")

    if case.get("context"):
        lines.append("## Context")
        lines.append(case["context"])
        lines.append("")

    lines.append("## Agent Action")
    lines.append(case["query"])
    lines.append("")

    if case.get("draft_response"):
        lines.append("## Draft Response")
        lines.append(case["draft_response"])
        lines.append("")

    return "\n".join(lines).strip()


def call_judge(system_prompt: str, user_content: str) -> dict:
    """Call the LLM and return parsed JSON verdict."""
    url = BASE_URL.rstrip("/") + "/chat/completions"
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json",
    }

    payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content + "\n\n/no_think"},
        ],
        "temperature": 0,
        "top_p": 1,
        "max_tokens": 2048,
        "stream": False,
        # Qwen3: disable thinking mode to get clean JSON output
        "extra_body": {"chat_template_kwargs": {"enable_thinking": False}},
    }

    resp = httpx.post(url, headers=headers, json=payload, timeout=TIMEOUT)
    resp.raise_for_status()

    raw = resp.json()
    content = raw["choices"][0]["message"]["content"]

    # Ollama might wrap JSON in markdown code blocks or thinking tags
    content = _extract_json(content)
    return json.loads(content)


def _extract_json(text: str) -> str:
    """Extract JSON from potential markdown code blocks or thinking tags."""
    import re

    # Remove <think>...</think> blocks (Qwen3 thinking mode)
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)

    # Try to find JSON in code blocks
    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if match:
        return match.group(1)

    # Try to find raw JSON object
    match = re.search(r"\{[^{}]*\}", text, re.DOTALL)
    if match:
        return match.group(0)

    return text.strip()


def verdict_to_decision(verdict: dict) -> str:
    """Map verdict to PASS/BLOCK/ESCALATE like trust-layer does."""
    if not verdict.get("threat_confirmed", False):
        return "PASS"

    severity = verdict.get("severity", "NONE")
    if severity in ("CRITICAL", "HIGH"):
        return "BLOCK"
    if severity in ("MEDIUM", "LOW"):
        return "ESCALATE"
    return "PASS"


def check_result(expected: str, actual: str) -> str:
    """Check if the actual decision matches expected."""
    if expected == "PASS_OR_ESCALATE":
        return "PASS" if actual in ("PASS", "ESCALATE") else "FAIL"
    return "PASS" if actual == expected else "FAIL"


def run_eval():
    system_prompt = load_system_prompt()
    test_cases = load_test_cases()

    print(f"{'='*70}")
    print(f"Security Judge Eval — {MODEL} @ {BASE_URL}")
    print(f"Test cases: {len(test_cases)}")
    print(f"{'='*70}\n")

    results = []
    pass_count = 0
    fail_count = 0

    for i, case in enumerate(test_cases, 1):
        case_id = case["id"]
        expected = case["expected_verdict"]
        user_content = build_user_content(case)

        print(f"[{i}/{len(test_cases)}] {case_id}: {case['description']}")
        print(f"  Query: {case['query'][:60]}...")

        try:
            start = time.perf_counter()
            verdict = call_judge(system_prompt, user_content)
            latency_ms = int((time.perf_counter() - start) * 1000)

            actual_decision = verdict_to_decision(verdict)
            check = check_result(expected, actual_decision)

            result = {
                "case_id": case_id,
                "category": case["category"],
                "expected": expected,
                "actual_decision": actual_decision,
                "verdict": verdict,
                "latency_ms": latency_ms,
                "check": check,
            }

            if check == "PASS":
                pass_count += 1
                status = "OK"
            else:
                fail_count += 1
                status = "FAIL"

            print(f"  Verdict: threat={verdict.get('threat_confirmed')}, "
                  f"type={verdict.get('threat_type')}, "
                  f"severity={verdict.get('severity')}")
            print(f"  Decision: {actual_decision} (expected: {expected}) → {status}")
            print(f"  Reasoning: {verdict.get('reasoning', 'N/A')}")
            print(f"  Latency: {latency_ms}ms")
            print()

        except Exception as e:
            fail_count += 1
            result = {
                "case_id": case_id,
                "category": case["category"],
                "expected": expected,
                "actual_decision": "ERROR",
                "error": str(e),
                "check": "FAIL",
            }
            print(f"  ERROR: {e}\n")

        results.append(result)

    # Summary
    total = len(test_cases)
    print(f"{'='*70}")
    print(f"Results: {pass_count}/{total} passed, {fail_count}/{total} failed")
    print(f"Accuracy: {pass_count/total*100:.1f}%")
    print(f"{'='*70}")

    # Save results
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    output_path = RESULTS_DIR / f"eval_{MODEL.replace(':', '_')}_{timestamp}.json"

    output = {
        "model": MODEL,
        "base_url": BASE_URL,
        "timestamp": timestamp,
        "summary": {
            "total": total,
            "passed": pass_count,
            "failed": fail_count,
            "accuracy": round(pass_count / total * 100, 1),
        },
        "results": results,
    }

    output_path.write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\nResults saved to: {output_path}")

    return fail_count == 0


if __name__ == "__main__":
    success = run_eval()
    sys.exit(0 if success else 1)
