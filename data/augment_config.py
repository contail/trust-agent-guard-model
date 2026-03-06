"""Config Diagnosis 학습 데이터 15건 추가 + train_v4.jsonl 재병합"""

import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
PROCESSED_DIR = BASE_DIR / "processed"
BATCH_DIR = BASE_DIR / "batches"
PROMPT_PATH = BASE_DIR.parent / "prompts" / "system_prompt_v3.txt"

SYSTEM_PROMPT = PROMPT_PATH.read_text().strip()


def make_config(context: str, config_json: str, verdict: dict) -> dict:
    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"## Context\n{context}\n\n## Config\n```json\n{config_json}\n```"},
            {"role": "assistant", "content": json.dumps(verdict, ensure_ascii=False)},
        ]
    }


def gen_extra_config():
    examples = []

    # 단일 문제 (5건) — 다양한 필드
    singles = [
        {
            "context": "OpenClaw 실행 확인 점검",
            "config": {"gateway": {"bind": "127.0.0.1", "auth": {"mode": "token", "token": "q1w2e3r4t5y6u7i8o9p0a1s2d3f4g5h6"}}, "tools": {"exec": {"ask": "off"}, "allow": ["read", "write"]}, "agentguard": {"gateEnabled": True, "gateFailOpen": False}},
            "verdict": {
                "config_safe": False,
                "findings": [{"field": "tools.exec.ask", "current_value": "off", "expected_value": "always", "severity": "CRITICAL", "description": "실행 확인이 비활성화되어 있어 에이전트가 승인 없이 명령을 실행합니다."}],
                "overall_severity": "CRITICAL",
                "reasoning": "tools.exec.ask가 off로 설정되어 있어 모든 명령이 확인 없이 실행됩니다. always로 변경해야 합니다."
            }
        },
        {
            "context": "OpenClaw 인증 모드 점검",
            "config": {"gateway": {"bind": "127.0.0.1", "auth": {"mode": "none"}}, "tools": {"exec": {"ask": "always"}, "allow": ["read", "write"]}, "agentguard": {"gateEnabled": True, "gateFailOpen": False}},
            "verdict": {
                "config_safe": False,
                "findings": [{"field": "gateway.auth.mode", "current_value": "none", "expected_value": "token 또는 mTLS", "severity": "CRITICAL", "description": "인증이 비활성화되어 있어 누구나 에이전트에 접근할 수 있습니다."}],
                "overall_severity": "CRITICAL",
                "reasoning": "gateway.auth.mode가 none으로 설정되어 인증 없이 에이전트에 접근 가능합니다. token 또는 mTLS로 변경해야 합니다."
            }
        },
        {
            "context": "AgentGuard 게이트 점검",
            "config": {"gateway": {"bind": "127.0.0.1", "auth": {"mode": "token", "token": "z1x2c3v4b5n6m7l8k9j0h1g2f3d4s5a6"}}, "tools": {"exec": {"ask": "always"}, "allow": ["read"]}, "agentguard": {"gateEnabled": False, "gateFailOpen": False}},
            "verdict": {
                "config_safe": False,
                "findings": [{"field": "agentguard.gateEnabled", "current_value": False, "expected_value": True, "severity": "CRITICAL", "description": "보안 게이트가 비활성화되어 모든 요청이 검사 없이 통과합니다."}],
                "overall_severity": "CRITICAL",
                "reasoning": "AgentGuard 게이트가 비활성화되어 Detect Pipeline과 Judge의 보안 검사가 작동하지 않습니다."
            }
        },
        {
            "context": "OpenClaw 도구 와일드카드 점검",
            "config": {"gateway": {"bind": "127.0.0.1", "auth": {"mode": "token", "token": "p9o8i7u6y5t4r3e2w1q0a9s8d7f6g5h4"}}, "tools": {"exec": {"ask": "always"}, "allow": ["*"]}, "agentguard": {"gateEnabled": True, "gateFailOpen": False}},
            "verdict": {
                "config_safe": False,
                "findings": [{"field": "tools.allow", "current_value": "[\"*\"]", "expected_value": "필요한 도구만 명시적으로 나열", "severity": "HIGH", "description": "와일드카드로 모든 도구가 허용되어 있어 에이전트가 제한 없이 도구를 사용합니다."}],
                "overall_severity": "HIGH",
                "reasoning": "tools.allow가 와일드카드(*)로 설정되어 모든 도구를 사용할 수 있습니다. 최소 권한 원칙에 따라 필요한 도구만 나열해야 합니다."
            }
        },
        {
            "context": "AgentGuard failOpen 점검",
            "config": {"gateway": {"bind": "127.0.0.1", "auth": {"mode": "token", "token": "m1n2b3v4c5x6z7l8k9j0h1g2f3d4s5a6"}}, "tools": {"exec": {"ask": "always"}, "allow": ["read", "write"]}, "agentguard": {"gateEnabled": True, "gateFailOpen": True}},
            "verdict": {
                "config_safe": False,
                "findings": [{"field": "agentguard.gateFailOpen", "current_value": True, "expected_value": False, "severity": "HIGH", "description": "gateFailOpen이 true이면 보안 서비스 장애 시 모든 요청이 무검사 통과합니다."}],
                "overall_severity": "HIGH",
                "reasoning": "gateFailOpen이 true로 설정되어 보안 서비스 장애 시 fail-open 동작합니다. false로 변경하여 fail-close 정책을 적용해야 합니다."
            }
        },
    ]

    # 복합 문제 (5건)
    multis = [
        {
            "context": "OpenClaw 인증 + 실행 점검",
            "config": {"gateway": {"bind": "127.0.0.1", "auth": {"mode": "none"}}, "tools": {"exec": {"ask": "off"}, "allow": ["read", "exec"]}, "agentguard": {"gateEnabled": True, "gateFailOpen": False}},
            "verdict": {
                "config_safe": False,
                "findings": [
                    {"field": "gateway.auth.mode", "current_value": "none", "expected_value": "token 또는 mTLS", "severity": "CRITICAL", "description": "인증이 비활성화되어 있습니다."},
                    {"field": "tools.exec.ask", "current_value": "off", "expected_value": "always", "severity": "CRITICAL", "description": "실행 확인이 비활성화되어 있습니다."}
                ],
                "overall_severity": "CRITICAL",
                "reasoning": "인증이 없고 실행 확인도 비활성화되어 있어 누구나 에이전트를 통해 명령을 실행할 수 있습니다."
            }
        },
        {
            "context": "OpenClaw 게이트 + 바인드 점검",
            "config": {"gateway": {"bind": "0.0.0.0", "auth": {"mode": "token", "token": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"}}, "tools": {"exec": {"ask": "always"}, "allow": ["read"]}, "agentguard": {"gateEnabled": False, "gateFailOpen": True}},
            "verdict": {
                "config_safe": False,
                "findings": [
                    {"field": "gateway.bind", "current_value": "0.0.0.0", "expected_value": "127.0.0.1", "severity": "HIGH", "description": "외부 네트워크에 노출되어 있습니다."},
                    {"field": "agentguard.gateEnabled", "current_value": False, "expected_value": True, "severity": "CRITICAL", "description": "보안 게이트가 비활성화되어 있습니다."},
                    {"field": "agentguard.gateFailOpen", "current_value": True, "expected_value": False, "severity": "HIGH", "description": "fail-open 정책입니다."}
                ],
                "overall_severity": "CRITICAL",
                "reasoning": "외부에 노출된 상태에서 보안 게이트가 꺼져 있고 fail-open까지 설정되어 있습니다. 보안이 전혀 작동하지 않습니다."
            }
        },
        {
            "context": "OpenClaw 토큰 + Telegram 점검",
            "config": {"gateway": {"bind": "127.0.0.1", "auth": {"mode": "token", "token": "test"}}, "channels": {"telegram": {"dmPolicy": "open", "allowFrom": []}}, "tools": {"exec": {"ask": "always"}, "allow": ["read"]}, "agentguard": {"gateEnabled": True, "gateFailOpen": False}},
            "verdict": {
                "config_safe": False,
                "findings": [
                    {"field": "gateway.auth.token", "current_value": "test", "expected_value": "32자 이상의 랜덤 문자열", "severity": "HIGH", "description": "토큰이 4자로 짧고 추측 가능합니다."},
                    {"field": "channels.telegram.dmPolicy", "current_value": "open", "expected_value": "allowlist", "severity": "HIGH", "description": "Telegram이 누구에게나 열려 있습니다."}
                ],
                "overall_severity": "HIGH",
                "reasoning": "약한 인증 토큰과 개방된 Telegram 정책이 결합되어 있어 외부 공격에 취약합니다."
            }
        },
        {
            "context": "OpenClaw exec-approvals + 도구 점검",
            "config": {"gateway": {"bind": "127.0.0.1", "auth": {"mode": "token", "token": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"}}, "tools": {"exec": {"ask": "always"}, "allow": ["*"]}, "exec-approvals": [{"pattern": "*", "approved": True}], "agentguard": {"gateEnabled": True, "gateFailOpen": False}},
            "verdict": {
                "config_safe": False,
                "findings": [
                    {"field": "tools.allow", "current_value": "[\"*\"]", "expected_value": "필요한 도구만 나열", "severity": "HIGH", "description": "모든 도구가 와일드카드로 허용되어 있습니다."},
                    {"field": "exec-approvals", "current_value": "{\"pattern\": \"*\"}", "expected_value": "특정 명령 패턴만 승인", "severity": "CRITICAL", "description": "모든 명령이 자동 승인됩니다."}
                ],
                "overall_severity": "CRITICAL",
                "reasoning": "모든 도구가 허용되고 모든 명령이 자동 승인되어 실질적으로 실행 제한이 없습니다."
            }
        },
        {
            "context": "OpenClaw 전체 보안 점검",
            "config": {"gateway": {"bind": "0.0.0.0", "auth": {"mode": "none"}}, "tools": {"exec": {"ask": "never"}, "allow": ["*"]}, "channels": {"telegram": {"dmPolicy": "open", "allowFrom": []}}, "agentguard": {"gateEnabled": False, "gateFailOpen": True}},
            "verdict": {
                "config_safe": False,
                "findings": [
                    {"field": "gateway.bind", "current_value": "0.0.0.0", "expected_value": "127.0.0.1", "severity": "HIGH", "description": "외부 네트워크에 노출되어 있습니다."},
                    {"field": "gateway.auth.mode", "current_value": "none", "expected_value": "token 또는 mTLS", "severity": "CRITICAL", "description": "인증이 비활성화되어 있습니다."},
                    {"field": "tools.exec.ask", "current_value": "never", "expected_value": "always", "severity": "CRITICAL", "description": "실행 확인이 비활성화되어 있습니다."},
                    {"field": "tools.allow", "current_value": "[\"*\"]", "expected_value": "필요한 도구만 나열", "severity": "HIGH", "description": "모든 도구가 허용되어 있습니다."},
                    {"field": "channels.telegram.dmPolicy", "current_value": "open", "expected_value": "allowlist", "severity": "HIGH", "description": "Telegram이 누구에게나 열려 있습니다."},
                    {"field": "agentguard.gateEnabled", "current_value": False, "expected_value": True, "severity": "CRITICAL", "description": "보안 게이트가 비활성화되어 있습니다."},
                    {"field": "agentguard.gateFailOpen", "current_value": True, "expected_value": False, "severity": "HIGH", "description": "fail-open 정책입니다."}
                ],
                "overall_severity": "CRITICAL",
                "reasoning": "모든 보안 설정이 비활성화된 최악의 상태입니다. 외부 노출, 인증 없음, 실행 확인 없음, 보안 게이트 꺼짐. 즉시 전체 재설정이 필요합니다."
            }
        },
    ]

    # 안전한 설정 (5건)
    safes = [
        {
            "context": "OpenClaw 표준 보안 설정",
            "config": {"gateway": {"bind": "127.0.0.1", "auth": {"mode": "token", "token": "r4t5y6u7i8o9p0a1s2d3f4g5h6j7k8l9"}}, "tools": {"exec": {"ask": "always"}, "allow": ["read", "write", "web_fetch"]}, "agentguard": {"gateEnabled": True, "gateFailOpen": False}},
            "verdict": {"config_safe": True, "findings": [], "overall_severity": "NONE", "reasoning": "모든 보안 설정이 적절합니다. 인증 활성화, 충분한 토큰 길이, 실행 확인 필수, 보안 게이트 활성화."}
        },
        {
            "context": "OpenClaw 최소 권한 설정",
            "config": {"gateway": {"bind": "127.0.0.1", "auth": {"mode": "mTLS", "certPath": "/etc/ssl/agent.crt", "keyPath": "/etc/ssl/agent.key"}}, "tools": {"exec": {"ask": "always"}, "allow": ["read"]}, "agentguard": {"gateEnabled": True, "gateFailOpen": False}},
            "verdict": {"config_safe": True, "findings": [], "overall_severity": "NONE", "reasoning": "mTLS 인증과 최소 권한 원칙이 적용되어 있습니다. read 도구만 허용되어 안전합니다."}
        },
        {
            "context": "OpenClaw Telegram 안전 설정",
            "config": {"gateway": {"bind": "127.0.0.1", "auth": {"mode": "token", "token": "t5y6u7i8o9p0a1s2d3f4g5h6j7k8l9m0"}}, "channels": {"telegram": {"dmPolicy": "allowlist", "allowFrom": [123456789]}}, "tools": {"exec": {"ask": "always"}, "allow": ["read", "write"]}, "agentguard": {"gateEnabled": True, "gateFailOpen": False}},
            "verdict": {"config_safe": True, "findings": [], "overall_severity": "NONE", "reasoning": "Telegram이 allowlist 모드로 제한되어 있고, 인증과 보안 게이트가 모두 활성화되어 있습니다."}
        },
        {
            "context": "OpenClaw exec-approvals 안전 설정",
            "config": {"gateway": {"bind": "127.0.0.1", "auth": {"mode": "token", "token": "u7i8o9p0a1s2d3f4g5h6j7k8l9m0n1b2"}}, "tools": {"exec": {"ask": "always"}, "allow": ["read", "exec"]}, "exec-approvals": [{"pattern": "npm test", "approved": True}, {"pattern": "pytest", "approved": True}], "agentguard": {"gateEnabled": True, "gateFailOpen": False}},
            "verdict": {"config_safe": True, "findings": [], "overall_severity": "NONE", "reasoning": "exec-approvals가 특정 테스트 명령만 허용합니다. 와일드카드 없이 안전하게 구성되어 있습니다."}
        },
        {
            "context": "OpenClaw 프로덕션 권장 설정",
            "config": {"gateway": {"bind": "127.0.0.1", "auth": {"mode": "mTLS", "certPath": "/etc/ssl/prod.crt", "keyPath": "/etc/ssl/prod.key"}}, "tools": {"exec": {"ask": "always"}, "allow": ["read"]}, "channels": {"telegram": {"dmPolicy": "allowlist", "allowFrom": [111222333]}}, "exec-approvals": [{"pattern": "npm run build", "approved": True}], "agentguard": {"gateEnabled": True, "gateFailOpen": False}},
            "verdict": {"config_safe": True, "findings": [], "overall_severity": "NONE", "reasoning": "프로덕션 환경에 적합한 보안 설정입니다. mTLS 인증, 최소 도구, allowlist, 특정 승인 패턴만 허용."}
        },
    ]

    for cfg in singles:
        examples.append(make_config(cfg["context"], json.dumps(cfg["config"], indent=2, ensure_ascii=False), cfg["verdict"]))
    for cfg in multis:
        examples.append(make_config(cfg["context"], json.dumps(cfg["config"], indent=2, ensure_ascii=False), cfg["verdict"]))
    for cfg in safes:
        examples.append(make_config(cfg["context"], json.dumps(cfg["config"], indent=2, ensure_ascii=False), cfg["verdict"]))

    return examples


def main():
    print("=== Config Diagnosis 보강 ===\n")

    extra = gen_extra_config()
    print(f"추가 Config 예시: {len(extra)}건")

    # 기존 train_v4 로드
    v4_path = PROCESSED_DIR / "train_v4.jsonl"
    with open(v4_path) as f:
        existing = [json.loads(line) for line in f if line.strip()]
    print(f"기존 train_v4: {len(existing)}건")

    # 기존 config_diagnosis.jsonl에 추가
    existing_batch = BATCH_DIR / "config_diagnosis.jsonl"
    with open(existing_batch, "a") as f:
        for ex in extra:
            f.write(json.dumps(ex, ensure_ascii=False) + "\n")

    # 병합
    merged = existing + extra
    with open(v4_path, "w") as f:
        for ex in merged:
            f.write(json.dumps(ex, ensure_ascii=False) + "\n")
    print(f"새 train_v4: {len(merged)}건")

    # 분포
    from collections import Counter
    counts = Counter()
    for ex in merged:
        user_msg = ex["messages"][1]["content"]
        assistant_msg = json.loads(ex["messages"][2]["content"])
        if "## Config" in user_msg:
            counts["CONFIG_DIAGNOSIS"] += 1
        elif assistant_msg.get("threat_confirmed"):
            counts[assistant_msg["threat_type"]] += 1
        else:
            counts["SAFE"] += 1
    print("\n카테고리 분포:")
    for k, v in sorted(counts.items()):
        print(f"  {k}: {v}")
    print(f"  합계: {sum(counts.values())}")


if __name__ == "__main__":
    main()
