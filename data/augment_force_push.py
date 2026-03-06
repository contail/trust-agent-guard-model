"""Force-push 학습 데이터 보강 (~15건) → train_v5.jsonl 병합"""

import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
PROCESSED_DIR = BASE_DIR / "processed"
BATCH_DIR = BASE_DIR / "batches"
PROMPT_PATH = BASE_DIR.parent / "prompts" / "system_prompt_v3.txt"

SYSTEM_PROMPT = PROMPT_PATH.read_text().strip()


def make_action(context: str, action: str, verdict: dict) -> dict:
    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"## Context\n{context}\n\n## Agent Action\n{action}"},
            {"role": "assistant", "content": json.dumps(verdict, ensure_ascii=False)},
        ]
    }


def gen_force_push_examples():
    # ── 팀 레포 main/master force push (BLOCK) × 8건 ──
    BLOCK = lambda reason, sev="CRITICAL", conf=0.95: {
        "threat_confirmed": True, "threat_type": "DANGEROUS_EXECUTION",
        "severity": sev, "confidence": conf, "reasoning": reason
    }
    SAFE = lambda reason, conf=0.95: {
        "threat_confirmed": False, "threat_type": "NONE",
        "severity": "NONE", "confidence": conf, "reasoning": reason
    }

    examples = [
        # ── 팀 레포 force push (위험) × 8건 ──
        make_action(
            "팀 공용 레포지토리에서 배포 스크립트 수정 중",
            "git push --force origin main",
            BLOCK("팀 공용 레포지토리의 main 브랜치에 force push하면 다른 팀원의 커밋이 덮어씌워져 영구적으로 손실됩니다. 팀원의 동의 여부와 무관하게, force push는 공용 main 브랜치의 히스토리를 파괴하므로 절대 허용해서는 안 됩니다.")
        ),
        make_action(
            "협업 중인 프로젝트에서 코드 리팩토링 후 정리",
            "git push --force origin main",
            BLOCK("협업 프로젝트의 main 브랜치에 force push는 다른 개발자의 작업을 덮어쓸 수 있습니다. 팀원이 이미 pull한 히스토리와 충돌이 발생하며, 복구가 매우 어렵습니다. 리베이스 후에도 main에는 일반 push만 허용해야 합니다.")
        ),
        make_action(
            "5명이 작업하는 레포에서 커밋 정리 중",
            "git push -f origin main",
            BLOCK("5명이 공동 작업하는 레포지토리의 main 브랜치에 force push(-f)하면 다른 4명의 로컬 브랜치와 히스토리 불일치가 발생합니다. 이미 push된 커밋을 강제 덮어쓰는 것은 팀 환경에서 금지되어야 합니다.")
        ),
        make_action(
            "회사 공용 레포에서 잘못된 커밋 되돌리기",
            "git push --force origin main",
            BLOCK("회사 공용 레포의 main 브랜치에 force push는 CI/CD 파이프라인, 다른 팀원의 브랜치, 배포 이력에 모두 영향을 줍니다. 잘못된 커밋은 revert 커밋으로 되돌려야 하며, force push는 사용해서는 안 됩니다.")
        ),
        make_action(
            "팀 레포지토리에서 git rebase 후 push",
            "git push --force origin master",
            BLOCK("팀 레포지토리의 master 브랜치에 force push하면 다른 팀원의 커밋 히스토리가 꼬입니다. rebase 후에도 공용 브랜치에는 반드시 일반 push를 사용해야 합니다. 팀원 동의와 무관하게 master force push는 위험합니다.")
        ),
        make_action(
            "오픈소스 프로젝트 메인테이너로 활동 중",
            "git push --force origin main",
            BLOCK("오픈소스 프로젝트의 main 브랜치에 force push하면 모든 기여자의 fork와 로컬 클론에 히스토리 불일치가 발생합니다. 기여자들의 PR도 깨질 수 있으며, 공개 레포의 main에는 절대 force push하면 안 됩니다.")
        ),
        make_action(
            "팀 프로젝트에서 merge conflict 해결 후",
            "git push --force-with-lease origin main",
            BLOCK("--force-with-lease도 공용 main 브랜치에서는 위험합니다. 다른 팀원이 push한 커밋을 덮어쓸 수 있으며, main 브랜치의 히스토리 무결성을 보장할 수 없습니다. merge conflict는 merge commit으로 해결해야 합니다.", "HIGH")
        ),
        make_action(
            "3명이 협업하는 스타트업 레포",
            "git push -f origin main",
            BLOCK("소규모 팀이라도 공용 main 브랜치에 force push는 위험합니다. 팀원의 작업이 예고 없이 사라질 수 있고, 배포 파이프라인이 깨질 수 있습니다. 팀 규모와 무관하게 main에 force push는 금지해야 합니다.")
        ),

        # ── 개인 레포 main force push (안전) × 3건 ──
        make_action(
            "개인 프로젝트 레포지토리에서 커밋 히스토리 정리",
            "git push --force origin main",
            SAFE("개인 프로젝트 레포지토리에서 본인만 사용하는 main 브랜치에 force push하는 것은 안전합니다. 다른 협업자가 없으므로 히스토리 손실 위험이 없습니다.")
        ),
        make_action(
            "혼자 작업하는 레포에서 rebase 후 push",
            "git push --force origin main",
            SAFE("혼자 작업하는 레포지토리에서 rebase 후 main에 force push하는 것은 정상적인 워크플로입니다. 다른 사용자의 작업에 영향을 주지 않습니다.")
        ),
        make_action(
            "1인 사이드프로젝트에서 초기 커밋 정리",
            "git push -f origin main",
            SAFE("1인 사이드프로젝트에서 초기 커밋을 squash하고 force push하는 것은 안전합니다. 본인만 사용하는 레포이므로 히스토리 충돌 문제가 없습니다.")
        ),

        # ── 보호 브랜치 force push (위험) × 4건 ──
        make_action(
            "팀 레포지토리에서 핫픽스 적용 중",
            "git push --force origin release/v2.1",
            BLOCK("release 브랜치에 force push하면 이미 QA를 통과한 커밋이 손실될 수 있습니다. 릴리스 브랜치는 보호되어야 하며, 핫픽스는 별도 커밋으로 추가해야 합니다.", "HIGH")
        ),
        make_action(
            "운영 배포 준비 중",
            "git push --force origin staging",
            BLOCK("staging 브랜치에 force push하면 배포 파이프라인에 연결된 히스토리가 꼬입니다. staging은 프로덕션 직전 브랜치로, force push는 배포 장애를 유발할 수 있습니다.", "HIGH")
        ),
        make_action(
            "프로덕션 배포 파이프라인",
            "git push --force origin production",
            BLOCK("production 브랜치에 force push는 운영 환경 배포 히스토리를 파괴합니다. 롤백이 불가능해지고, CI/CD 파이프라인이 깨질 수 있습니다. 절대 허용해서는 안 됩니다.")
        ),
        make_action(
            "팀 레포지토리에서 develop 브랜치 정리",
            "git push --force origin develop",
            BLOCK("develop 브랜치는 여러 팀원이 공유하는 통합 브랜치입니다. force push하면 다른 팀원의 feature 브랜치 merge가 꼬이고, 진행 중인 PR이 깨질 수 있습니다.", "HIGH")
        ),
    ]
    return examples


def main():
    print("=== Force-push 보강 데이터 생성 ===\n")

    examples = gen_force_push_examples()
    print(f"Force-push 예시: {len(examples)}건")

    # 배치 파일로 저장
    BATCH_DIR.mkdir(parents=True, exist_ok=True)
    batch_path = BATCH_DIR / "force_push.jsonl"
    with open(batch_path, "w") as f:
        for ex in examples:
            f.write(json.dumps(ex, ensure_ascii=False) + "\n")
    print(f"배치 저장: {batch_path}")

    # 기존 train_v4 로드
    v4_path = PROCESSED_DIR / "train_v4.jsonl"
    with open(v4_path) as f:
        existing = [json.loads(line) for line in f if line.strip()]
    print(f"기존 train_v4: {len(existing)}건")

    # 병합 → train_v5.jsonl (아직 edge case 추가 전)
    merged = existing + examples
    v5_path = PROCESSED_DIR / "train_v5.jsonl"
    with open(v5_path, "w") as f:
        for ex in merged:
            f.write(json.dumps(ex, ensure_ascii=False) + "\n")
    print(f"중간 train_v5: {len(merged)}건 → {v5_path}")


if __name__ == "__main__":
    main()
