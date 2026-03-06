"""
Prepare v7 training data:
1. Load v6 data (Action Judge + multiagent config)
2. Load v7 research scenarios and convert to training format
3. Deduplicate by action content
4. Combine and split into train/valid
"""

import json
import random
import pathlib
import hashlib

random.seed(42)

BASE = pathlib.Path(__file__).parent.parent
PROMPT_V4 = (BASE / "prompts" / "system_prompt_v4.txt").read_text()

# v6 processed data
V6_DATA = BASE / "data" / "processed" / "train_v6.jsonl"

# v7 research files
V7_RESEARCH = BASE / "data" / "v7_research"
RESEARCH_FILES = [
    "dangerous_execution_new.jsonl",
    "credential_theft_new.jsonl",
    "data_exfiltration_new.jsonl",
    "prompt_injection_new.jsonl",
    "supply_chain_new.jsonl",
    "privilege_escalation_new.jsonl",
    "safe_new.jsonl",
    "v8_reinforcement.jsonl",
]

# Pre-built config diagnosis examples (already in training format)
V8_CONFIG_FILE = V7_RESEARCH / "v8_config_reinforcement.jsonl"

# Output
OUTPUT_DIR = BASE / "data" / "processed"
TRAIN_DIR = BASE / "training" / "data"


def load_jsonl(path):
    examples = []
    with open(path) as f:
        for line in f:
            if line.strip():
                examples.append(json.loads(line))
    return examples


def research_to_training(scenario):
    """Convert research format to training format (messages)"""
    context = scenario["context"]
    action = scenario["action"]
    threat_type = scenario["threat_type"]
    severity = scenario["severity"]
    reasoning_hint = scenario["reasoning_hint"]

    # Build user message (Mode 1: Action Judge format)
    user_content = f"## Context\n{context}\n\n## Agent Action\n{action}"

    # Build assistant response
    if threat_type == "NONE":
        response = {
            "threat_confirmed": False,
            "threat_type": "NONE",
            "severity": "NONE",
            "confidence": round(random.uniform(0.85, 0.95), 2),
            "reasoning": reasoning_hint,
        }
    else:
        response = {
            "threat_confirmed": True,
            "threat_type": threat_type,
            "severity": severity,
            "confidence": round(random.uniform(0.88, 0.98), 2),
            "reasoning": reasoning_hint,
        }

    return {
        "messages": [
            {"role": "system", "content": PROMPT_V4},
            {"role": "user", "content": user_content},
            {"role": "assistant", "content": json.dumps(response, ensure_ascii=False)},
        ]
    }


def get_action_fingerprint(example):
    """Extract a fingerprint for deduplication"""
    user_msg = ""
    for msg in example["messages"]:
        if msg["role"] == "user":
            user_msg = msg["content"]
            break
    # Hash the user message for dedup
    return hashlib.md5(user_msg.strip().lower().encode()).hexdigest()


def main():
    # 1. Load existing v6 data
    v6_data = load_jsonl(V6_DATA)
    print(f"v6 data: {len(v6_data)}")

    # Collect fingerprints from v6
    seen = set()
    for ex in v6_data:
        fp = get_action_fingerprint(ex)
        seen.add(fp)
    print(f"  Unique fingerprints: {len(seen)}")

    # 2. Convert v7 research scenarios
    v7_new = []
    v7_dupes = 0
    for fname in RESEARCH_FILES:
        fpath = V7_RESEARCH / fname
        if not fpath.exists():
            print(f"  SKIP (not found): {fname}")
            continue

        scenarios = load_jsonl(fpath)
        added = 0
        for s in scenarios:
            try:
                training_ex = research_to_training(s)
                fp = get_action_fingerprint(training_ex)
                if fp not in seen:
                    seen.add(fp)
                    v7_new.append(training_ex)
                    added += 1
                else:
                    v7_dupes += 1
            except Exception as e:
                print(f"  ERROR in {fname}: {e}")
        print(f"  {fname}: {len(scenarios)} → {added} new (dupes: {len(scenarios) - added})")

    print(f"\nv7 new scenarios: {len(v7_new)} (dupes removed: {v7_dupes})")

    # 2b. Load pre-built config diagnosis examples
    v8_config = []
    if V8_CONFIG_FILE.exists():
        v8_config = load_jsonl(V8_CONFIG_FILE)
        print(f"\nv8 config 보강: {len(v8_config)} examples")

    # 3. Combine
    all_v7 = v6_data + v7_new + v8_config
    random.shuffle(all_v7)
    print(f"Total v7 data: {len(all_v7)}")

    # 4. Count by category
    cat_counts = {}
    for ex in all_v7:
        asst = ex["messages"][-1]["content"]
        try:
            resp = json.loads(asst)
            if "threat_type" in resp:
                t = resp["threat_type"]
            elif "agent_type" in resp:
                t = "CONFIG_DIAGNOSIS"
            else:
                t = "UNKNOWN"
        except:
            t = "UNKNOWN"
        cat_counts[t] = cat_counts.get(t, 0) + 1

    print("\nCategory distribution:")
    for k, v in sorted(cat_counts.items(), key=lambda x: -x[1]):
        print(f"  {k}: {v}")

    # 5. Split: 85% train, 15% valid
    split_idx = int(len(all_v7) * 0.85)
    train_data = all_v7[:split_idx]
    valid_data = all_v7[split_idx:]
    print(f"\nTrain: {len(train_data)}")
    print(f"Valid: {len(valid_data)}")

    # 6. Save processed (all)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    processed_path = OUTPUT_DIR / "train_v7.jsonl"
    with open(processed_path, "w") as f:
        for ex in all_v7:
            f.write(json.dumps(ex, ensure_ascii=False) + "\n")
    print(f"\nSaved: {processed_path} ({len(all_v7)} examples)")

    # 7. Save train/valid split
    with open(TRAIN_DIR / "train.jsonl", "w") as f:
        for ex in train_data:
            f.write(json.dumps(ex, ensure_ascii=False) + "\n")
    with open(TRAIN_DIR / "valid.jsonl", "w") as f:
        for ex in valid_data:
            f.write(json.dumps(ex, ensure_ascii=False) + "\n")
    print(f"Saved: training/data/train.jsonl ({len(train_data)})")
    print(f"Saved: training/data/valid.jsonl ({len(valid_data)})")


if __name__ == "__main__":
    main()
