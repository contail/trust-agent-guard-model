#!/bin/bash
# Train all 6 detect adapters sequentially
# Qwen3-0.6B, ~10min each, total ~60min

PYTHON=/Users/sangjin/miniconda3/bin/python
BASE=/Users/sangjin/PycharmProjects/test-llm/security-judge

CATEGORIES=(
  dangerous_execution
  credential_theft
  data_exfiltration
  prompt_injection
  supply_chain
  privilege_escalation
)

for cat in "${CATEGORIES[@]}"; do
  echo "============================================"
  echo "Training detect adapter: $cat"
  echo "============================================"

  mkdir -p "$BASE/training/detect/$cat"

  $PYTHON -m mlx_lm.lora \
    --model Qwen/Qwen3-0.6B \
    --train \
    --data "$BASE/data/detect/$cat" \
    --adapter-path "$BASE/training/detect/$cat" \
    --batch-size 2 \
    --grad-accumulation-steps 2 \
    --iters 500 \
    --learning-rate 2e-5 \
    --num-layers 8 \
    --max-seq-length 2048 \
    --steps-per-eval 100 \
    --save-every 100 \
    --steps-per-report 10

  echo ""
  echo "Completed: $cat"
  echo ""
done

echo "============================================"
echo "All 6 detect adapters trained!"
echo "============================================"
