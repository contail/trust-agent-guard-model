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
└────────────┬────────────────────┘
             │ 카테고리별 위험 점수 (0.0 ~ 1.0)
             ▼
┌─────────────────────────────────┐
│  Score-based Routing            │
│  · max < 0.2  → FAST_PASS      │
│  · max > 0.8  → FAST_BLOCK     │
│  · 0.2 ~ 0.8  → JUDGE 호출     │
└────────────┬────────────────────┘
             │ (불확실한 케이스만)
             ▼
┌─────────────────────────────────┐
│  Stage 2: Judge (Qwen3-8B)     │
│  LoRA 어댑터 — 위협 상세 분석    │
└─────────────────────────────────┘
```

## 위협 탐지 카테고리 (6개)

| 카테고리 | 설명 |
|---------|------|
| dangerous_execution | 위험한 명령 실행 (rm -rf, 방화벽 해제 등) |
| credential_theft | 크레덴셜/시크릿 탈취 (키체인, IMDS 등) |
| data_exfiltration | 데이터 유출 (DNS 터널링, S3 업로드 등) |
| prompt_injection | 프롬프트 인젝션 (hidden div, [INST] 태그 등) |
| supply_chain | 공급망 공격 (타이포스쿼팅, curl pipe bash 등) |
| privilege_escalation | 권한 상승 (sudoers 수정, SUID 비트 등) |

## 빠른 시작

### 요구사항

- Apple Silicon Mac (M1/M2/M3/M4)
- RAM 32GB 이상 권장 (Detect만: 16GB)
- Python 3.10+

### 설치

```bash
pip install mlx-lm
```

베이스 모델(Qwen3-0.6B, Qwen3-8B)은 첫 실행 시 HuggingFace에서 자동 다운로드됩니다.

### 평가 실행

```bash
# E2E 파이프라인 평가 (Detect → Routing → Judge)
python eval/run_e2e_eval.py test_cases_v3

# Judge 단독 평가
python eval/run_finetuned_eval.py

# Detect 어댑터 평가
python eval/run_detect_eval.py
```

## 프로젝트 구조

```
trust-agent-guard/
├── README.md
├── docs/
│   └── REPORT.md              # 평가 리포트
├── prompts/
│   ├── system_prompt_v4.txt   # Judge 시스템 프롬프트
│   ├── test_cases_v3.json     # 테스트 케이스 (38건)
│   └── test_cases_v4.json     # 확장 테스트 케이스 (39건)
├── eval/
│   ├── run_e2e_eval.py        # E2E 파이프라인 평가
│   ├── run_finetuned_eval.py  # Judge 단독 평가
│   └── run_detect_eval.py     # Detect 어댑터 평가
├── training/
│   ├── adapters_v7/           # Judge LoRA 어댑터 (8B)
│   ├── detect/                # Detect LoRA 어댑터 (0.6B × 6)
│   └── train_detect_all.sh    # Detect 학습 스크립트
└── data/
    ├── prepare_v7.py          # Judge 학습 데이터 생성
    ├── prepare_detect.py      # Detect 학습 데이터 생성
    └── v7_research/           # 연구 기반 시나리오 데이터
```

## 성능

| 방식 | 정확도 (38건) |
|------|-------------|
| E2E Pipeline (Logprobs) | **89.5%** |
| E2E Pipeline (Binary) | 73.7% |
| 기존 Trust Layer API | 68.4% |

자세한 평가 결과는 [docs/REPORT.md](docs/REPORT.md) 참고.
