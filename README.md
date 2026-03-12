# Trust Agent Guard

AI 에이전트의 액션을 실시간으로 분석하고 위협을 탐지하는 2-Stage 보안 파이프라인.

## 아키텍처

```
Agent Request
    │
    ▼
┌─────────────────────────────────┐
│  Stage 1: Detect (Qwen3-0.6B)  │
│  6개 LoRA 어댑터 병렬 실행       │
│  Peak mem: ~2.3GB               │
└────────────┬────────────────────┘
             │ 카테고리별 위험 점수 (0.0 ~ 1.0)
             ▼
┌─────────────────────────────────┐
│  Score-based Routing            │
│  · max < 0.20 → FAST_PASS      │
│  · max > 0.80 → FAST_BLOCK     │
│  · 0.20~0.80  → JUDGE 호출     │
└────────────┬────────────────────┘
             │ (불확실한 케이스만)
             ▼
┌─────────────────────────────────┐
│  Stage 2: Judge (Qwen3-8B)     │
│  LoRA 어댑터 — 위협 상세 분석    │
│  JSON 응답: threat_confirmed,   │
│  severity, reasoning            │
└─────────────────────────────────┘
```

## 위협 탐지 카테고리 (6개)

| 카테고리 | 설명 |
|---------|------|
| dangerous_execution | 위험한 명령 실행 (rm -rf, force push, 방화벽 해제 등) |
| credential_theft | 크레덴셜/시크릿 탈취 (IMDS, 키체인, kubeconfig, grep 검색 등) |
| data_exfiltration | 데이터 유출 (DNS 터널링, S3 업로드, webhook 전송 등) |
| prompt_injection | 프롬프트 인젝션 (hidden div, [INST] 태그, goal hijacking 등) |
| supply_chain | 공급망 공격 (타이포스쿼팅, curl pipe bash, 악성 MCP 서버 등) |
| privilege_escalation | 권한 상승 (sudoers 수정, SUID 비트, IAM 정책, Docker 특권 등) |

## Detect Pipeline 성능

| 카테고리 | Accuracy | Precision | Recall | F1 |
|---------|----------|-----------|--------|-----|
| dangerous_execution | **96.8%** | 95.2% | 97.6% | 96.4% |
| data_exfiltration | **94.8%** | 95.5% | 87.5% | 91.3% |
| credential_theft | **91.1%** | 83.8% | 91.2% | 87.3% |
| prompt_injection | **89.8%** | 80.0% | 90.3% | 84.8% |
| supply_chain | **83.3%** | 75.0% | 100.0% | 85.7% |
| privilege_escalation | **78.8%** | 75.0% | 88.9% | 81.4% |

> 학습: Qwen3-0.6B + LoRA, 500 iters, batch_size=2, lr=2e-5

## 배포

| 서버 | 포트 | 모델 | GPU |
|------|------|------|-----|
| 35.213.141.149 | :8002 | Detect Pipeline (0.6B × 6) | A100 25% VRAM |
| 35.213.141.149 | :8001 | Judge (8B) | A100 70% VRAM |

Trust Layer 연동:
- `POST /v1/guard/evaluate` — Inbound 요청 평가
- `POST /v1/guard/evaluate_response` — Outbound 응답 평가
- Decision: PASS / REWRITE / BLOCK / ESCALATE

## 빠른 시작

### 요구사항

- **로컬 학습/평가**: Apple Silicon Mac (M1~M4), RAM 32GB+ 권장
- **서버 배포**: NVIDIA GPU (A100 80GB 권장)
- Python 3.10+

### 설치

```bash
pip install mlx-lm  # 로컬 (Apple Silicon)
```

베이스 모델(Qwen3-0.6B, Qwen3-8B)은 첫 실행 시 HuggingFace에서 자동 다운로드됩니다.

### 평가 실행

```bash
# Detect 어댑터 전체 평가 (6개 카테고리)
python eval/run_detect_eval.py

# 특정 카테고리만
python eval/run_detect_eval.py --category credential_theft

# Judge 단독 평가
python eval/run_finetuned_eval.py
```

### 학습

```bash
# Detect 전체 학습 (~60분, 6개 순차)
bash training/train_detect_all.sh

# 개별 어댑터 학습
python -m mlx_lm.lora \
  --model Qwen/Qwen3-0.6B \
  --train \
  --data data/detect/<category> \
  --adapter-path training/detect/<category> \
  --batch-size 2 \
  --grad-accumulation-steps 2 \
  --iters 500 \
  --learning-rate 2e-5 \
  --num-layers 8
```

## 프로젝트 구조

```
security-judge/
├── README.md
├── prompts/
│   ├── system_prompt_v4.txt       # Judge 시스템 프롬프트 (Action Judge + Config Diagnosis)
│   └── test_cases_*.json          # 테스트 케이스
├── eval/
│   ├── run_detect_eval.py         # Detect 어댑터 평가
│   ├── run_finetuned_eval.py      # Judge 단독 평가
│   ├── run_e2e_eval.py            # E2E 파이프라인 평가
│   └── results/                   # 평가 결과 JSON
├── training/
│   ├── adapters_v11/              # Judge LoRA 어댑터 (8B, latest)
│   ├── detect/                    # Detect LoRA 어댑터 (0.6B × 6)
│   │   ├── dangerous_execution/
│   │   ├── credential_theft/      # v3 (issue25 + patch)
│   │   ├── data_exfiltration/
│   │   ├── prompt_injection/
│   │   ├── supply_chain/
│   │   └── privilege_escalation/  # v4 (augmented)
│   └── train_detect_all.sh
├── data/
│   ├── prepare_detect.py          # Detect 학습 데이터 생성
│   ├── prepare_v7.py              # Judge 학습 데이터 생성
│   ├── generate_detect_augment.py # Detect 증량 데이터 생성
│   ├── detect/                    # Detect train/valid 데이터 (카테고리별)
│   ├── issue25/                   # Issue 25 보강 데이터
│   └── v7_research/               # 연구 기반 시나리오 데이터
└── scripts/
```

## 학습 이력

| 버전 | 모델 | 데이터 | 비고 |
|------|------|--------|------|
| Detect v1 | 0.6B × 6 | ~340 each | 초기 학습, 500 iters |
| Detect v2 | 0.6B × 6 | ~340~640 | per-category NEG_RATIO 튜닝 |
| **Detect v3/v4** | 0.6B × 6 | **480~700 each** | **issue25 보강 + augment (현재)** |
| Judge v7 | 8B | 1506 examples | v6 379 + research 1127 |
| Judge v9~v11 | 8B | 확장 | config diagnosis 포함 |

## 알려진 한계

- **supply_chain 타이포스쿼팅**: 0.6B 모델이 미세한 철자 차이(reqeusts vs requests) 구분 어려움 → 룰 기반(편집거리) 보완 검토 필요
- **8B + 0.6B 동시 학습 불가**: Metal GPU contention으로 순차 실행 필요 (Apple Silicon)
- **M4 Pro 48GB OOM 방지**: 8B 학습 시 batch_size=1 + grad_accumulation + grad_checkpoint 필수
