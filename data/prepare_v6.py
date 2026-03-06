"""
Prepare v6 training data:
1. Take v5 Action Judge data (update system prompt to v4)
2. Replace old config_diagnosis data with new multiagent config data
3. Combine and split into train/valid
"""

import json
import random
import pathlib

random.seed(42)

BASE = pathlib.Path(__file__).parent.parent
PROMPT_V3 = (BASE / "prompts" / "system_prompt_v3.txt").read_text()
PROMPT_V4 = (BASE / "prompts" / "system_prompt_v4.txt").read_text()

# Source files
V5_TRAIN = BASE / "training" / "data" / "train.jsonl"
V5_VALID = BASE / "training" / "data" / "valid.jsonl"
MULTIAGENT_BASE = BASE / "data" / "batches" / "multiagent_config.jsonl"
MULTIAGENT_AUG = BASE / "data" / "batches" / "multiagent_config_augmented.jsonl"

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


def is_config_diagnosis(example):
    """Check if this is an old config diagnosis example (v3 format)"""
    user_msg = example["messages"][1]["content"] if len(example["messages"]) > 1 else ""
    assistant_msg = example["messages"][-1]["content"] if example["messages"] else ""
    return "## Config" in user_msg and "config_safe" in assistant_msg and "agent_type" not in assistant_msg


def update_system_prompt(example):
    """Replace v3 system prompt with v4"""
    new_example = json.loads(json.dumps(example))
    if new_example["messages"][0]["role"] == "system":
        new_example["messages"][0]["content"] = PROMPT_V4
    return new_example


def main():
    # Load existing v5 data
    v5_train = load_jsonl(V5_TRAIN)
    v5_valid = load_jsonl(V5_VALID)
    all_v5 = v5_train + v5_valid
    print(f"v5 data: {len(all_v5)} ({len(v5_train)} train + {len(v5_valid)} valid)")

    # Separate: Action Judge vs old Config Diagnosis
    action_judge = []
    old_config = []
    for ex in all_v5:
        if is_config_diagnosis(ex):
            old_config.append(ex)
        else:
            action_judge.append(ex)
    print(f"  Action Judge: {len(action_judge)}")
    print(f"  Old Config Diagnosis (to replace): {len(old_config)}")

    # Update system prompt for Action Judge examples
    action_judge_v4 = [update_system_prompt(ex) for ex in action_judge]

    # Load new multiagent config data (already has v4 system prompt)
    multiagent_base = load_jsonl(MULTIAGENT_BASE)
    multiagent_aug = load_jsonl(MULTIAGENT_AUG)
    new_config = multiagent_base + multiagent_aug
    print(f"  New Multiagent Config: {len(new_config)}")

    # Combine
    all_v6 = action_judge_v4 + new_config
    random.shuffle(all_v6)
    print(f"\nTotal v6 data: {len(all_v6)}")

    # Split: 85% train, 15% valid
    split_idx = int(len(all_v6) * 0.85)
    train_data = all_v6[:split_idx]
    valid_data = all_v6[split_idx:]
    print(f"  Train: {len(train_data)}")
    print(f"  Valid: {len(valid_data)}")

    # Save processed
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    processed_path = OUTPUT_DIR / "train_v6.jsonl"
    with open(processed_path, "w") as f:
        for ex in all_v6:
            f.write(json.dumps(ex, ensure_ascii=False) + "\n")
    print(f"\nSaved: {processed_path} ({len(all_v6)} examples)")

    # Save train/valid split
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
