"""Split training JSONL into train/valid sets for mlx-lm fine-tuning."""

import json
import random
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "processed"
OUT_DIR = Path(__file__).resolve().parent / "data"

def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    src = DATA_DIR / "train_v5.jsonl"
    if not src.exists():
        src = DATA_DIR / "train_v4.jsonl"
    if not src.exists():
        src = DATA_DIR / "train_v3.jsonl"
    print(f"Source: {src}")
    with open(src) as f:
        examples = [json.loads(line) for line in f if line.strip()]

    random.seed(42)
    random.shuffle(examples)

    # 85/15 split
    split_idx = int(len(examples) * 0.85)
    train = examples[:split_idx]
    valid = examples[split_idx:]

    for name, data in [("train.jsonl", train), ("valid.jsonl", valid)]:
        path = OUT_DIR / name
        with open(path, "w") as f:
            for ex in data:
                f.write(json.dumps(ex, ensure_ascii=False) + "\n")
        print(f"{name}: {len(data)} examples → {path}")

    # Stats
    from collections import Counter
    for name, data in [("Train", train), ("Valid", valid)]:
        counts = Counter()
        for ex in data:
            verdict = json.loads(ex["messages"][2]["content"])
            if "config_safe" in verdict:
                key = "CONFIG_DIAGNOSIS"
            elif verdict.get("threat_confirmed"):
                key = verdict["threat_type"]
            else:
                key = "SAFE"
            counts[key] += 1
        print(f"\n{name} distribution:")
        for k, v in sorted(counts.items()):
            print(f"  {k}: {v}")

if __name__ == "__main__":
    main()
