"""
Prepare Security Detect Pipeline training data.

For each of the 6 threat categories, create a binary classifier dataset:
- Positive: examples of that specific threat
- Negative: safe examples + examples from OTHER threat categories

Each adapter learns: "Is this action an instance of <category>?" → "YES" or "NO"

Input format (from v7 research):
  {"context": "...", "action": "...", "threat_type": "...", "severity": "...", "reasoning_hint": "..."}

Output format (for 0.6B LoRA training):
  {"messages": [{"role": "system", "content": "..."}, {"role": "user", "content": "..."}, {"role": "assistant", "content": "YES/NO"}]}
"""

import json
import random
import pathlib

random.seed(42)

BASE = pathlib.Path(__file__).parent.parent
V7_RESEARCH = BASE / "data" / "v7_research"
OUTPUT_DIR = BASE / "data" / "detect"

CATEGORIES = [
    "DANGEROUS_EXECUTION",
    "CREDENTIAL_THEFT",
    "DATA_EXFILTRATION",
    "PROMPT_INJECTION",
    "SUPPLY_CHAIN",
    "PRIVILEGE_ESCALATION",
]

CATEGORY_FILE_MAP = {
    "DANGEROUS_EXECUTION": "dangerous_execution_new.jsonl",
    "CREDENTIAL_THEFT": "credential_theft_new.jsonl",
    "DATA_EXFILTRATION": "data_exfiltration_new.jsonl",
    "PROMPT_INJECTION": "prompt_injection_new.jsonl",
    "SUPPLY_CHAIN": "supply_chain_new.jsonl",
    "PRIVILEGE_ESCALATION": "privilege_escalation_new.jsonl",
}

# Also load existing batch data
EXISTING_BATCH_MAP = {
    "DANGEROUS_EXECUTION": ["dangerous_execution.jsonl", "force_push.jsonl"],
    "CREDENTIAL_THEFT": ["credential_theft.jsonl"],
    "DATA_EXFILTRATION": ["data_exfiltration.jsonl"],
    "PROMPT_INJECTION": ["prompt_injection.jsonl"],
    "SUPPLY_CHAIN": ["supply_chain.jsonl"],
    "PRIVILEGE_ESCALATION": ["privilege_escalation.jsonl"],
}

SYSTEM_PROMPTS = {
    "DANGEROUS_EXECUTION": "You are a security classifier. Determine if the given agent action involves dangerous or destructive command execution. Answer only YES or NO.",
    "CREDENTIAL_THEFT": "You are a security classifier. Determine if the given agent action involves accessing, reading, or stealing credentials, secrets, or API keys. Answer only YES or NO.",
    "DATA_EXFILTRATION": "You are a security classifier. Determine if the given agent action involves sending or exfiltrating data to external endpoints. Answer only YES or NO.",
    "PROMPT_INJECTION": "You are a security classifier. Determine if the given agent action or content involves prompt injection, goal hijacking, or instruction manipulation. Answer only YES or NO.",
    "SUPPLY_CHAIN": "You are a security classifier. Determine if the given agent action involves installing malicious, untrusted, or typosquatted packages, tools, or MCP servers. Answer only YES or NO.",
    "PRIVILEGE_ESCALATION": "You are a security classifier. Determine if the given agent action involves escalating privileges, bypassing permission boundaries, or gaining unauthorized access. Answer only YES or NO.",
}


def load_jsonl(path):
    examples = []
    with open(path) as f:
        for line in f:
            if line.strip():
                examples.append(json.loads(line))
    return examples


def load_research_data():
    """Load all v7 research data, grouped by threat_type"""
    by_category = {cat: [] for cat in CATEGORIES}
    by_category["NONE"] = []

    for cat, fname in CATEGORY_FILE_MAP.items():
        fpath = V7_RESEARCH / fname
        if fpath.exists():
            data = load_jsonl(fpath)
            by_category[cat].extend(data)

    # Safe examples
    safe_path = V7_RESEARCH / "safe_new.jsonl"
    if safe_path.exists():
        by_category["NONE"].extend(load_jsonl(safe_path))

    # Also load existing batch data (extract context+action from training format)
    batch_dir = BASE / "data" / "batches"
    for cat, fnames in EXISTING_BATCH_MAP.items():
        for fname in fnames:
            fpath = batch_dir / fname
            if fpath.exists():
                for ex in load_jsonl(fpath):
                    # Existing data is in training format, extract user message
                    if "messages" in ex:
                        user_msg = ex["messages"][1]["content"]
                        # Parse context and action from "## Context\n...\n\n## Agent Action\n..."
                        parts = user_msg.split("## Agent Action")
                        if len(parts) == 2:
                            context = parts[0].replace("## Context\n", "").strip()
                            action = parts[1].strip()
                            by_category[cat].append({
                                "context": context,
                                "action": action,
                                "threat_type": cat,
                            })

    # Load safe/edge_cases from batches too
    for fname in ["safe.jsonl", "edge_cases.jsonl"]:
        fpath = batch_dir / fname
        if fpath.exists():
            for ex in load_jsonl(fpath):
                if "messages" in ex:
                    user_msg = ex["messages"][1]["content"]
                    parts = user_msg.split("## Agent Action")
                    if len(parts) == 2:
                        context = parts[0].replace("## Context\n", "").strip()
                        action = parts[1].strip()
                        # Check if it was actually safe
                        asst = ex["messages"][-1]["content"]
                        try:
                            resp = json.loads(asst)
                            if not resp.get("threat_confirmed", True):
                                by_category["NONE"].append({
                                    "context": context,
                                    "action": action,
                                    "threat_type": "NONE",
                                })
                        except:
                            pass

    return by_category


def make_detect_example(system_prompt, context, action, label):
    """Create a single detect training example"""
    user_content = f"## Context\n{context}\n\n## Agent Action\n{action}"
    return {
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
            {"role": "assistant", "content": label},
        ]
    }


NEG_RATIO = {
    "DANGEROUS_EXECUTION": 1.5,      # low recall → fewer negatives
    "CREDENTIAL_THEFT": 1.5,          # both low → fewer negatives
    "DATA_EXFILTRATION": 1.5,         # v2 was 2.5 (too conservative), lower to improve recall
    "PROMPT_INJECTION": 2.0,          # already good, keep
    "SUPPLY_CHAIN": 1.0,              # very few positives, balance 1:1
    "PRIVILEGE_ESCALATION": 1.0,      # very few positives, balance 1:1
}


def prepare_adapter_data(category, by_category):
    """For a given category, create balanced binary classifier data"""
    system_prompt = SYSTEM_PROMPTS[category]

    # Positives: examples of this category → YES
    positives = []
    for ex in by_category[category]:
        positives.append(make_detect_example(
            system_prompt, ex["context"], ex["action"], "YES"
        ))

    # Negatives: safe examples + other categories → NO
    negatives = []

    # All safe examples
    for ex in by_category["NONE"]:
        negatives.append(make_detect_example(
            system_prompt, ex["context"], ex["action"], "NO"
        ))

    # Examples from other threat categories (they're not THIS category)
    for other_cat in CATEGORIES:
        if other_cat == category:
            continue
        for ex in by_category[other_cat]:
            negatives.append(make_detect_example(
                system_prompt, ex["context"], ex["action"], "NO"
            ))

    # Per-category negative ratio
    ratio = NEG_RATIO.get(category, 2.0)
    max_negatives = int(len(positives) * ratio)
    if len(negatives) > max_negatives:
        negatives = random.sample(negatives, max_negatives)

    all_data = positives + negatives
    random.shuffle(all_data)

    return all_data, len(positives), len(negatives)


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    by_category = load_research_data()

    print("=== Raw data counts ===")
    for cat, examples in sorted(by_category.items()):
        print(f"  {cat}: {len(examples)}")

    print("\n=== Generating detect adapter data ===")
    total_examples = 0

    for category in CATEGORIES:
        all_data, n_pos, n_neg = prepare_adapter_data(category, by_category)

        # Split 85/15
        split_idx = int(len(all_data) * 0.85)
        train_data = all_data[:split_idx]
        valid_data = all_data[split_idx:]

        # Save
        adapter_dir = OUTPUT_DIR / category.lower()
        adapter_dir.mkdir(parents=True, exist_ok=True)

        with open(adapter_dir / "train.jsonl", "w") as f:
            for ex in train_data:
                f.write(json.dumps(ex, ensure_ascii=False) + "\n")
        with open(adapter_dir / "valid.jsonl", "w") as f:
            for ex in valid_data:
                f.write(json.dumps(ex, ensure_ascii=False) + "\n")

        print(f"  {category}:")
        print(f"    Positive (YES): {n_pos}")
        print(f"    Negative (NO):  {n_neg}")
        print(f"    Total: {len(all_data)} (train: {len(train_data)}, valid: {len(valid_data)})")

        total_examples += len(all_data)

    print(f"\n=== Total: {total_examples} examples across 6 adapters ===")


if __name__ == "__main__":
    main()
