"""Convert MLX LoRA adapter to HuggingFace PEFT format for vLLM serving."""
import argparse
import json
import re
from pathlib import Path

import mlx.core as mx
import numpy as np
from safetensors.numpy import save_file


def convert_key(mlx_key: str) -> str:
    """Convert MLX LoRA key to PEFT key format.

    MLX:  model.layers.20.mlp.down_proj.lora_a
    PEFT: base_model.model.model.layers.20.mlp.down_proj.lora_A.weight
    """
    key = mlx_key.replace("lora_a", "lora_A.weight").replace("lora_b", "lora_B.weight")
    key = f"base_model.model.{key}"
    return key


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mlx-adapter", required=True, help="Path to MLX adapter directory")
    parser.add_argument("--output", required=True, help="Output PEFT adapter directory")
    parser.add_argument("--base-model", default="Qwen/Qwen3-8B", help="Base model name")
    args = parser.parse_args()

    mlx_dir = Path(args.mlx_adapter)
    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Load MLX adapter config
    with open(mlx_dir / "adapter_config.json") as f:
        mlx_config = json.load(f)

    lora_params = mlx_config.get("lora_parameters", {})
    rank = lora_params.get("rank", 8)
    alpha = lora_params.get("scale", 20.0)
    dropout = lora_params.get("dropout", 0.0)

    # Load MLX weights
    mlx_weights = mx.load(str(mlx_dir / "adapters.safetensors"))

    # Detect target modules from keys
    target_modules = set()
    for key in mlx_weights.keys():
        # Extract module name: model.layers.X.{module}.lora_a -> {module}
        parts = key.split(".")
        # Find the part between layer number and lora_a/lora_b
        for i, p in enumerate(parts):
            if p.startswith("lora_"):
                module = ".".join(parts[3:i])  # after "model.layers.N."
                target_modules.add(module)
                break

    # Convert weights: MLX stores lora_a as (in, rank), PEFT expects (rank, in)
    # MLX stores lora_b as (rank, out), PEFT expects (out, rank)
    peft_weights = {}
    for mlx_key, mlx_val in mlx_weights.items():
        peft_key = convert_key(mlx_key)
        val = np.array(mlx_val)

        if "lora_A" in peft_key:
            # MLX lora_a: (in_features, rank) -> PEFT: (rank, in_features)
            val = val.T
        elif "lora_B" in peft_key:
            # MLX lora_b: (rank, out_features) -> PEFT: (out_features, rank)
            val = val.T

        peft_weights[peft_key] = val

    # Save weights
    save_file(peft_weights, str(out_dir / "adapter_model.safetensors"))

    # Create PEFT adapter_config.json
    peft_config = {
        "auto_mapping": None,
        "base_model_name_or_path": args.base_model,
        "bias": "none",
        "fan_in_fan_out": False,
        "inference_mode": True,
        "init_lora_weights": True,
        "layers_to_transform": None,
        "layers_pattern": None,
        "lora_alpha": alpha,
        "lora_dropout": dropout,
        "modules_to_save": None,
        "peft_type": "LORA",
        "r": rank,
        "revision": None,
        "target_modules": sorted(target_modules),
        "task_type": "CAUSAL_LM",
    }

    with open(out_dir / "adapter_config.json", "w") as f:
        json.dump(peft_config, f, indent=2)

    print(f"Converted {len(peft_weights)} tensors")
    print(f"Rank: {rank}, Alpha: {alpha}")
    print(f"Target modules: {sorted(target_modules)}")
    print(f"Output: {out_dir}")


if __name__ == "__main__":
    main()
