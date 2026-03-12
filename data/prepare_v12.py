"""
Prepare v12 Judge training data: existing v11 data + session chains.

Strategy: Use per-mode system prompts to keep token count within max_seq_length=4096.
- Mode 1 (Action Judge) examples get Mode 1 prompt only
- Mode 2 (Config Diagnosis) examples get Mode 2 prompt only
- Mode 3 (Session Analysis) examples get Mode 3 prompt only

At inference time, the full v5 prompt (all 3 modes) is used —
the model learns each mode's behavior independently and generalizes.
"""
import json
import random
import pathlib
import re

random.seed(42)

BASE = pathlib.Path(__file__).parent.parent
PROMPT_V5_FULL = (BASE / "prompts" / "system_prompt_v5.txt").read_text()

# Sources
EXISTING_TRAIN = BASE / "training" / "data" / "train.jsonl"
EXISTING_VALID = BASE / "training" / "data" / "valid.jsonl"
SESSION_TRAIN = BASE / "data" / "session_chains" / "train.jsonl"
SESSION_VALID = BASE / "data" / "session_chains" / "valid.jsonl"

# Output
OUTPUT_DIR = BASE / "data" / "processed" / "v12"


def extract_mode_prompts(full_prompt):
    """Split v5 prompt into per-mode prompts."""
    header = "You are a security judge for autonomous AI agents.\n\n"

    # Split by "---" separator — yields [header, mode1, mode2, mode3]
    sections = re.split(r"\n---\n", full_prompt)

    mode1 = header + sections[1].strip()
    mode2 = header + sections[2].strip()
    mode3 = header + sections[3].strip()

    return mode1, mode2, mode3


# Extract per-mode prompts
MODE1_PROMPT, MODE2_PROMPT, MODE3_PROMPT = extract_mode_prompts(PROMPT_V5_FULL)


def load_jsonl(path):
    examples = []
    with open(path) as f:
        for line in f:
            if line.strip():
                examples.append(json.loads(line))
    return examples


def classify_mode(ex):
    """Classify which mode an example belongs to."""
    user_content = ex["messages"][1]["content"]
    if "## Session History" in user_content:
        return "session"
    elif "## Config" in user_content:
        return "config"
    else:
        return "action"


def update_system_prompt_by_mode(examples):
    """Replace system prompt based on example mode."""
    prompt_map = {
        "action": MODE1_PROMPT,
        "config": MODE2_PROMPT,
        "session": MODE3_PROMPT,
    }
    for ex in examples:
        mode = classify_mode(ex)
        ex["messages"][0]["content"] = prompt_map[mode]
    return examples


def deduplicate(examples):
    """Deduplicate by user content."""
    seen = set()
    deduped = []
    for ex in examples:
        key = ex["messages"][1]["content"]
        if key not in seen:
            seen.add(key)
            deduped.append(ex)
    return deduped


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # Show per-mode prompt sizes
    print(f"Per-mode prompt sizes:")
    print(f"  Mode 1 (Action):  {len(MODE1_PROMPT):,} chars (~{len(MODE1_PROMPT)//4} tokens)")
    print(f"  Mode 2 (Config):  {len(MODE2_PROMPT):,} chars (~{len(MODE2_PROMPT)//4} tokens)")
    print(f"  Mode 3 (Session): {len(MODE3_PROMPT):,} chars (~{len(MODE3_PROMPT)//4} tokens)")
    print(f"  Full v5:          {len(PROMPT_V5_FULL):,} chars (~{len(PROMPT_V5_FULL)//4} tokens)")
    print()

    # Load existing data
    existing_train = load_jsonl(EXISTING_TRAIN)
    existing_valid = load_jsonl(EXISTING_VALID)
    print(f"Existing: train={len(existing_train)}, valid={len(existing_valid)}")

    # Load session chain data
    session_train = load_jsonl(SESSION_TRAIN)
    session_valid = load_jsonl(SESSION_VALID)
    print(f"Session chains: train={len(session_train)}, valid={len(session_valid)}")

    # Merge
    all_train = existing_train + session_train
    all_valid = existing_valid + session_valid

    # Apply per-mode system prompts
    update_system_prompt_by_mode(all_train)
    update_system_prompt_by_mode(all_valid)

    # Deduplicate
    all_train = deduplicate(all_train)
    all_valid = deduplicate(all_valid)

    # Shuffle
    random.shuffle(all_train)
    random.shuffle(all_valid)

    # Verify token sizes
    max_chars = 0
    for ex in all_train + all_valid:
        total = sum(len(m["content"]) for m in ex["messages"])
        max_chars = max(max_chars, total)
    print(f"\nMax total chars (per-mode prompt): {max_chars:,} (~{max_chars//4} tokens)")

    # Save
    with open(OUTPUT_DIR / "train.jsonl", "w") as f:
        for ex in all_train:
            f.write(json.dumps(ex, ensure_ascii=False) + "\n")
    with open(OUTPUT_DIR / "valid.jsonl", "w") as f:
        for ex in all_valid:
            f.write(json.dumps(ex, ensure_ascii=False) + "\n")

    print(f"\nv12 merged: train={len(all_train)}, valid={len(all_valid)}, total={len(all_train) + len(all_valid)}")

    # Mode distribution
    mode_counts = {"action": 0, "config": 0, "session": 0}
    for ex in all_train + all_valid:
        mode_counts[classify_mode(ex)] += 1
    print("\nMode distribution:")
    for mode, count in sorted(mode_counts.items()):
        print(f"  {mode}: {count}")


if __name__ == "__main__":
    main()
