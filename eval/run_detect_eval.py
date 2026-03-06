"""
Evaluate all 6 Detect LoRA adapters (Qwen3-0.6B).

For each adapter, loads valid.jsonl and measures:
- Accuracy, Precision, Recall, F1 (binary YES/NO)
- Per-example results saved to JSON

Usage:
    python eval/run_detect_eval.py
    python eval/run_detect_eval.py --category dangerous_execution
"""

import json
import sys
import time
from pathlib import Path

from mlx_lm import load, generate

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DETECT_DATA_DIR = PROJECT_ROOT / "data" / "detect"
DETECT_ADAPTER_DIR = PROJECT_ROOT / "training" / "detect"
RESULTS_DIR = PROJECT_ROOT / "eval" / "results"

MODEL_PATH = "Qwen/Qwen3-0.6B"

CATEGORIES = [
    "dangerous_execution",
    "credential_theft",
    "data_exfiltration",
    "prompt_injection",
    "supply_chain",
    "privilege_escalation",
]


def load_jsonl(path):
    examples = []
    with open(path) as f:
        for line in f:
            if line.strip():
                examples.append(json.loads(line))
    return examples


def extract_yes_no(text):
    """Extract YES or NO from model output."""
    text = text.strip().upper()
    # Remove thinking tags if present
    import re
    text = re.sub(r"<THINK>.*?</THINK>", "", text, flags=re.DOTALL).strip().upper()

    if text.startswith("YES"):
        return "YES"
    if text.startswith("NO"):
        return "NO"

    # Fallback: search for YES/NO anywhere
    if "YES" in text and "NO" not in text:
        return "YES"
    if "NO" in text and "YES" not in text:
        return "NO"

    return text[:10]  # Return first 10 chars for debugging


def eval_adapter(category, model, tokenizer):
    """Evaluate a single adapter on its validation data."""
    valid_path = DETECT_DATA_DIR / category / "valid.jsonl"
    examples = load_jsonl(valid_path)

    tp = fp = tn = fn = 0
    results = []

    for i, ex in enumerate(examples):
        expected = ex["messages"][-1]["content"]  # YES or NO
        messages = ex["messages"][:2]  # system + user only

        prompt = tokenizer.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=True,
            enable_thinking=False,
        )

        start = time.perf_counter()
        response = generate(
            model, tokenizer, prompt=prompt,
            max_tokens=8,
        )
        latency_ms = int((time.perf_counter() - start) * 1000)

        predicted = extract_yes_no(response)
        correct = predicted == expected

        # Confusion matrix (YES = positive)
        if expected == "YES" and predicted == "YES":
            tp += 1
        elif expected == "NO" and predicted == "YES":
            fp += 1
        elif expected == "NO" and predicted == "NO":
            tn += 1
        elif expected == "YES" and predicted == "NO":
            fn += 1

        results.append({
            "idx": i,
            "expected": expected,
            "predicted": predicted,
            "correct": correct,
            "latency_ms": latency_ms,
            "raw_output": response[:50],
        })

        if not correct:
            user_msg = ex["messages"][1]["content"][:80]
            print(f"    WRONG [{i}] expected={expected} got={predicted} | {user_msg}...")

    # Metrics
    total = len(examples)
    accuracy = (tp + tn) / total if total > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    metrics = {
        "total": total,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "accuracy": round(accuracy * 100, 1),
        "precision": round(precision * 100, 1),
        "recall": round(recall * 100, 1),
        "f1": round(f1 * 100, 1),
    }

    return metrics, results


def main():
    # Parse optional --category flag
    selected = None
    if "--category" in sys.argv:
        idx = sys.argv.index("--category")
        if idx + 1 < len(sys.argv):
            selected = sys.argv[idx + 1]

    categories = [selected] if selected else CATEGORIES

    print(f"{'='*60}")
    print(f"Detect Pipeline Evaluation — {MODEL_PATH}")
    print(f"Categories: {len(categories)}")
    print(f"{'='*60}\n")

    all_metrics = {}
    all_results = {}

    for cat in categories:
        adapter_path = str(DETECT_ADAPTER_DIR / cat)
        print(f"Loading adapter: {cat}...")
        model, tokenizer = load(MODEL_PATH, adapter_path=adapter_path)

        print(f"  Evaluating {cat}...")
        metrics, results = eval_adapter(cat, model, tokenizer)
        all_metrics[cat] = metrics
        all_results[cat] = results

        print(f"  Accuracy: {metrics['accuracy']}%  "
              f"Precision: {metrics['precision']}%  "
              f"Recall: {metrics['recall']}%  "
              f"F1: {metrics['f1']}%")
        print(f"  TP={metrics['tp']} FP={metrics['fp']} TN={metrics['tn']} FN={metrics['fn']}")
        print(f"  Total: {metrics['total']}\n")

        # Free memory
        del model, tokenizer

    # Summary table
    print(f"\n{'='*60}")
    print(f"{'Category':<25} {'Acc':>6} {'Prec':>6} {'Rec':>6} {'F1':>6} {'N':>5}")
    print(f"{'-'*60}")
    total_correct = 0
    total_examples = 0
    for cat in categories:
        m = all_metrics[cat]
        total_correct += m["tp"] + m["tn"]
        total_examples += m["total"]
        print(f"{cat:<25} {m['accuracy']:>5.1f}% {m['precision']:>5.1f}% {m['recall']:>5.1f}% {m['f1']:>5.1f}% {m['total']:>5}")

    if len(categories) > 1:
        overall_acc = total_correct / total_examples * 100 if total_examples > 0 else 0
        print(f"{'-'*60}")
        print(f"{'OVERALL':<25} {overall_acc:>5.1f}%{'':>20} {total_examples:>5}")
    print(f"{'='*60}")

    # Save results
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    output_path = RESULTS_DIR / f"eval_detect_{timestamp}.json"
    output = {
        "model": MODEL_PATH,
        "timestamp": timestamp,
        "summary": all_metrics,
        "results": all_results,
    }
    output_path.write_text(json.dumps(output, ensure_ascii=False, indent=2))
    print(f"\nResults saved to: {output_path}")


if __name__ == "__main__":
    main()
