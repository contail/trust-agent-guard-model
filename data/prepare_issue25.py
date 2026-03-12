"""
Merge issue25 data with latest detect data to create new training sets.
"""
import json
import random
import pathlib

random.seed(42)

BASE = pathlib.Path(__file__).parent.parent
ISSUE25_DIR = BASE / "data" / "issue25"
DETECT_DIR = BASE / "data" / "detect"

# Map category to latest data directory
LATEST_DATA = {
    "credential_theft": "credential_theft",
    "dangerous_execution": "dangerous_execution_v3",
    "data_exfiltration": "data_exfiltration_v2",
    "privilege_escalation": "privilege_escalation_v2",
    "prompt_injection": "prompt_injection_v2",
    "supply_chain": "supply_chain_v2",
}

# Output version suffix
OUTPUT_SUFFIX = "_issue25"


def load_jsonl(path):
    examples = []
    with open(path) as f:
        for line in f:
            if line.strip():
                examples.append(json.loads(line))
    return examples


def main():
    for category, latest_dir in LATEST_DATA.items():
        # Load existing data
        existing_train = load_jsonl(DETECT_DIR / latest_dir / "train.jsonl")
        existing_valid = load_jsonl(DETECT_DIR / latest_dir / "valid.jsonl")
        existing_all = existing_train + existing_valid

        # Load issue25 data
        issue25_path = ISSUE25_DIR / f"{category}.jsonl"
        if not issue25_path.exists():
            print(f"  SKIP {category}: no issue25 data")
            continue
        issue25_data = load_jsonl(issue25_path)

        # Merge and deduplicate by user content
        seen = set()
        merged = []
        for ex in existing_all + issue25_data:
            key = ex["messages"][1]["content"]
            if key not in seen:
                seen.add(key)
                merged.append(ex)

        random.shuffle(merged)

        # Split 85/15
        split_idx = int(len(merged) * 0.85)
        train_data = merged[:split_idx]
        valid_data = merged[split_idx:]

        # Save
        out_dir = DETECT_DIR / f"{category}{OUTPUT_SUFFIX}"
        out_dir.mkdir(parents=True, exist_ok=True)

        with open(out_dir / "train.jsonl", "w") as f:
            for ex in train_data:
                f.write(json.dumps(ex, ensure_ascii=False) + "\n")
        with open(out_dir / "valid.jsonl", "w") as f:
            for ex in valid_data:
                f.write(json.dumps(ex, ensure_ascii=False) + "\n")

        n_new = len(merged) - len(existing_all)
        print(f"  {category}: {len(existing_all)} existing + {len(issue25_data)} issue25 = {len(merged)} merged (dedup removed {len(existing_all) + len(issue25_data) - len(merged)})")
        print(f"    -> train: {len(train_data)}, valid: {len(valid_data)}")

    print("\nDone! New data dirs created with suffix '_issue25'")


if __name__ == "__main__":
    main()
