"""Compare old vs new credential_theft adapter on issue25 merged valid data."""
import json
import re
from pathlib import Path
from mlx_lm import load, generate

MODEL_PATH = "Qwen/Qwen3-0.6B"


def load_jsonl(path):
    with open(path) as f:
        return [json.loads(l) for l in f if l.strip()]


def extract_yes_no(text):
    text = re.sub(r"<[Tt][Hh][Ii][Nn][Kk]>.*?</[Tt][Hh][Ii][Nn][Kk]>", "", text, flags=re.DOTALL).strip().upper()
    if text.startswith("YES"):
        return "YES"
    if text.startswith("NO"):
        return "NO"
    if "YES" in text and "NO" not in text:
        return "YES"
    if "NO" in text and "YES" not in text:
        return "NO"
    return text[:10]


def eval_adapter(adapter_path, valid_path):
    model, tokenizer = load(MODEL_PATH, adapter_path=adapter_path)
    examples = load_jsonl(valid_path)
    tp = fp = tn = fn = 0
    wrongs = []
    for i, ex in enumerate(examples):
        expected = ex["messages"][-1]["content"]
        messages = ex["messages"][:2]
        prompt = tokenizer.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=True, enable_thinking=False
        )
        response = generate(model, tokenizer, prompt=prompt, max_tokens=8)
        predicted = extract_yes_no(response)
        if expected == "YES" and predicted == "YES":
            tp += 1
        elif expected == "NO" and predicted == "YES":
            fp += 1
        elif expected == "NO" and predicted == "NO":
            tn += 1
        elif expected == "YES" and predicted == "NO":
            fn += 1
        if predicted != expected:
            wrongs.append(f"  [{i}] exp={expected} got={predicted} | {ex['messages'][1]['content'][:80]}")
    del model, tokenizer
    total = len(examples)
    acc = (tp + tn) / total * 100 if total else 0
    prec = tp / (tp + fp) * 100 if (tp + fp) else 0
    rec = tp / (tp + fn) * 100 if (tp + fn) else 0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0
    return {
        "acc": round(acc, 1), "prec": round(prec, 1),
        "rec": round(rec, 1), "f1": round(f1, 1),
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "total": total, "wrongs": wrongs,
    }


if __name__ == "__main__":
    valid_path = "data/detect/credential_theft_issue25/valid.jsonl"

    print("=== OLD adapter (credential_theft / issue25) ===")
    old = eval_adapter("training/detect/credential_theft", valid_path)
    print(f"Acc={old['acc']}% Prec={old['prec']}% Rec={old['rec']}% F1={old['f1']}%")
    print(f"TP={old['tp']} FP={old['fp']} TN={old['tn']} FN={old['fn']} Total={old['total']}")
    for w in old["wrongs"]:
        print(w)

    print()
    print("=== NEW adapter (credential_theft_v3 / patched) ===")
    new = eval_adapter("training/detect/credential_theft_v3", valid_path)
    print()
    print("=== v3 on v3 valid (new examples) ===")
    new2 = eval_adapter("training/detect/credential_theft_v3", "data/detect/credential_theft_v3/valid.jsonl")
    print(f"Acc={new2['acc']}% Prec={new2['prec']}% Rec={new2['rec']}% F1={new2['f1']}%")
    print(f"TP={new2['tp']} FP={new2['fp']} TN={new2['tn']} FN={new2['fn']} Total={new2['total']}")
    for w in new2["wrongs"]:
        print(w)
    print(f"Acc={new['acc']}% Prec={new['prec']}% Rec={new['rec']}% F1={new['f1']}%")
    print(f"TP={new['tp']} FP={new['fp']} TN={new['tn']} FN={new['fn']} Total={new['total']}")
    for w in new["wrongs"]:
        print(w)
