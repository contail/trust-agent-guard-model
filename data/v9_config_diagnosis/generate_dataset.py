#!/usr/bin/env python3
"""Generate config diagnosis training data from real OpenClaw/AgentGuard configs.

Each example is based on a realistic scenario and teaches the model to:
1. Recognize "loopback" = "127.0.0.1" (safe)
2. Assess exec.ask=off as MEDIUM when AgentGuard LLM Gateway is active
3. Correctly identify auth.mode=token as safe
4. Handle config_files section (auth-profiles, exec-approvals)
5. Score safe configs with high security_score
"""

import json
import os

SYSTEM_PROMPT_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "prompts", "system_prompt_v4.txt")

with open(SYSTEM_PROMPT_PATH) as f:
    SYSTEM_PROMPT = f.read().strip()


def make_entry(user_content: str, assistant_json: dict) -> dict:
    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
            {"role": "assistant", "content": json.dumps(assistant_json, ensure_ascii=False)},
        ]
    }


# ============================================================
# Scenario configs (user messages) and correct assessments
# ============================================================

SCENARIOS = []

# ---------- 1. Real safe config: loopback + token auth + exec.ask=off + AgentGuard active ----------
SCENARIOS.append(make_entry(
    user_content='## Config\n```json\n{"config":{"gateway":{"bind":"loopback","mode":"local","port":18789,"auth":{"mode":"token","token":"d54ff74802e6d80dae1864b1a2cee4d6fef7a16c949cb480"}},"tools":{"allow":["group:fs","group:runtime","group:web","exec","read","write","edit","apply_patch","web_fetch","web_search","memory_search","memory_get","image"],"exec":{"ask":"off","host":"gateway"}},"channels":{"discord":{"enabled":true,"dmPolicy":"pairing","allowFrom":["778617145546375189"]},"telegram":{"enabled":true,"dmPolicy":"pairing","streaming":"partial"}}},"config_files":{"auth-profiles":{"anthropic:default":{"mode":"api_key","key":"sk-ant-a***"},"anthropic:manual":{"mode":"token","token":"sk-ant-a***"}},"exec-approvals":{"defaults":{"security":"full","ask":"off"},"agents":{"main":{"allowlist":[{"pattern":"/usr/local/bin/gh"},{"pattern":"/Users/user/.agentguard/bin/agentguard"}],"ask":"off","security":"full"}}}}}\n```',
    assistant_json={
        "agent_type": "openclaw",
        "config_safe": True,
        "security_score": 92,
        "findings": [
            {
                "field": "tools.exec.ask",
                "current_value": "off",
                "expected_value": "always",
                "severity": "MEDIUM",
                "category": "HITL",
                "description": "실행 확인이 비활성화되어 있지만, AgentGuard LLM Gateway가 tool call을 감시하므로 위험이 완화됩니다.",
                "remediation": "보다 엄격한 제어를 원하면 exec.ask를 'on-miss'로 변경하세요. 단, 'always'로 설정하면 AgentGuard fix 등 자동화가 불가능해질 수 있습니다."
            }
        ],
        "overall_severity": "MEDIUM",
        "reasoning": "게이트웨이가 loopback으로 바인딩되어 외부 접근이 차단되고, token 인증이 활성화되어 있습니다. exec.ask=off이지만 AgentGuard가 tool call을 감시하므로 위험이 완화됩니다. exec-approvals에 특정 명령만 허용되어 전반적으로 양호한 보안 구성입니다."
    }
))

# ---------- 2. Fully safe config: everything locked down ----------
SCENARIOS.append(make_entry(
    user_content='## Config\n```json\n{"config":{"gateway":{"bind":"127.0.0.1","port":18789,"auth":{"mode":"token","token":"a9f3e7b2c1d4f5a6e8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3"}},"tools":{"allow":["read","write","web_fetch"],"exec":{"ask":"always"}},"channels":{"telegram":{"enabled":true,"dmPolicy":"allowlist"}}},"config_files":{"exec-approvals":{"agents":{"main":{"allowlist":[{"pattern":"/usr/bin/git"},{"pattern":"/usr/local/bin/npm"}]}}}}}\n```',
    assistant_json={
        "agent_type": "openclaw",
        "config_safe": True,
        "security_score": 100,
        "findings": [],
        "overall_severity": "NONE",
        "reasoning": "모든 보안 설정이 올바르게 구성되어 있습니다. 127.0.0.1 바인딩, token 인증(48자 토큰), exec.ask=always, 제한된 도구 목록, allowlist DM 정책, 특정 명령만 허용하는 exec-approvals까지 모범적인 보안 구성입니다."
    }
))

# ---------- 3. "loopback" string vs "127.0.0.1" — both safe ----------
SCENARIOS.append(make_entry(
    user_content='## Config\n```json\n{"config":{"gateway":{"bind":"loopback","port":18789,"auth":{"mode":"token","token":"b8c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2"}},"tools":{"allow":["read","write","exec"],"exec":{"ask":"on-miss"}}}}\n```',
    assistant_json={
        "agent_type": "openclaw",
        "config_safe": True,
        "security_score": 100,
        "findings": [],
        "overall_severity": "NONE",
        "reasoning": "gateway.bind가 'loopback'으로 설정되어 로컬 접근만 허용됩니다. 이는 '127.0.0.1'과 동일한 보안 수준입니다. token 인증, on-miss 실행 확인, 제한된 도구 목록으로 안전한 구성입니다."
    }
))

# ---------- 4. exec.ask=off WITHOUT AgentGuard — truly dangerous ----------
SCENARIOS.append(make_entry(
    user_content='## Config\n```json\n{"config":{"gateway":{"bind":"127.0.0.1","port":18789,"auth":{"mode":"token","token":"c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"}},"tools":{"allow":["exec","read","write","web_fetch"],"exec":{"ask":"off"}}}}\n```',
    assistant_json={
        "agent_type": "openclaw",
        "config_safe": False,
        "security_score": 75,
        "findings": [
            {
                "field": "tools.exec.ask",
                "current_value": "off",
                "expected_value": "always 또는 on-miss",
                "severity": "CRITICAL",
                "category": "HITL",
                "description": "실행 확인이 비활성화되어 에이전트가 사용자 승인 없이 모든 명령을 실행할 수 있습니다. AgentGuard 보안 게이트 정보가 없어 보완 수단이 확인되지 않습니다.",
                "remediation": "tools.exec.ask를 'always' 또는 'on-miss'로 설정하세요. AgentGuard를 사용 중이라면 LLM Gateway가 보완할 수 있습니다."
            }
        ],
        "overall_severity": "CRITICAL",
        "reasoning": "네트워크와 인증은 안전하지만, exec.ask=off로 사용자 확인 없이 명령이 실행됩니다. AgentGuard 같은 보안 레이어 정보가 없어 CRITICAL로 판단합니다."
    }
))

# ---------- 5. exec.ask=off WITH AgentGuard LLM Gateway enforce mode — well mitigated ----------
SCENARIOS.append(make_entry(
    user_content='## Config\n```json\n{"config":{"gateway":{"bind":"loopback","port":18789,"auth":{"mode":"token","token":"e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0"}},"tools":{"allow":["read","write","exec","web_fetch"],"exec":{"ask":"off"}},"agentguard":{"gateEnabled":true,"llmMode":"enforce","gateFailOpen":false}}}\n```',
    assistant_json={
        "agent_type": "openclaw",
        "config_safe": True,
        "security_score": 92,
        "findings": [
            {
                "field": "tools.exec.ask",
                "current_value": "off",
                "expected_value": "always",
                "severity": "MEDIUM",
                "category": "HITL",
                "description": "실행 확인이 비활성화되어 있지만, AgentGuard LLM Gateway가 enforce 모드로 위험한 tool call을 차단합니다.",
                "remediation": "AgentGuard가 활성화되어 위험이 완화됩니다. 추가 보호가 필요하면 exec.ask를 'on-miss'로 설정하세요."
            }
        ],
        "overall_severity": "MEDIUM",
        "reasoning": "exec.ask=off이지만 AgentGuard LLM Gateway가 enforce 모드로 작동하여 위험한 명령을 차단합니다. loopback 바인딩, token 인증, gateFailOpen=false로 보안이 잘 구성되어 있습니다."
    }
))

# ---------- 6. Real dangerous: 0.0.0.0 + no auth + exec.ask=off ----------
SCENARIOS.append(make_entry(
    user_content='## Config\n```json\n{"config":{"gateway":{"bind":"0.0.0.0","port":18789,"auth":{"mode":"none"}},"tools":{"allow":["*"],"exec":{"ask":"off"}},"channels":{"telegram":{"dmPolicy":"open"}}},"config_files":{"exec-approvals":{"agents":{"*":{"allowlist":[{"pattern":"*"}]}}}}}\n```',
    assistant_json={
        "agent_type": "openclaw",
        "config_safe": False,
        "security_score": 0,
        "findings": [
            {
                "field": "gateway.auth.mode",
                "current_value": "none",
                "expected_value": "token 또는 mTLS",
                "severity": "CRITICAL",
                "category": "AUTH",
                "description": "인증이 완전히 비활성화되어 누구나 API를 호출할 수 있습니다.",
                "remediation": "gateway.auth.mode를 'token'으로 설정하고 강력한 토큰을 생성하세요."
            },
            {
                "field": "gateway.bind",
                "current_value": "0.0.0.0",
                "expected_value": "127.0.0.1 또는 loopback",
                "severity": "HIGH",
                "category": "NETWORK",
                "description": "모든 네트워크 인터페이스에 바인딩되어 외부에서 접근 가능합니다.",
                "remediation": "gateway.bind를 '127.0.0.1' 또는 'loopback'으로 변경하세요."
            },
            {
                "field": "tools.exec.ask",
                "current_value": "off",
                "expected_value": "always",
                "severity": "CRITICAL",
                "category": "HITL",
                "description": "실행 확인이 비활성화되어 에이전트가 사용자 승인 없이 모든 명령을 실행합니다.",
                "remediation": "tools.exec.ask를 'always'로 설정하세요."
            },
            {
                "field": "tools.allow",
                "current_value": "[\"*\"]",
                "expected_value": "필요한 도구만 명시적으로 나열",
                "severity": "HIGH",
                "category": "PERMISSIONS",
                "description": "와일드카드로 모든 도구가 허용됩니다.",
                "remediation": "필요한 도구만 명시적으로 허용하세요."
            },
            {
                "field": "exec-approvals.agents.*.allowlist[0].pattern",
                "current_value": "*",
                "expected_value": "구체적인 명령 패턴",
                "severity": "CRITICAL",
                "category": "EXECUTION",
                "description": "모든 에이전트에 대해 와일드카드 실행 승인이 설정되어 있습니다.",
                "remediation": "필요한 명령만 구체적 패턴으로 승인하세요."
            },
            {
                "field": "channels.telegram.dmPolicy",
                "current_value": "open",
                "expected_value": "allowlist 또는 pairing",
                "severity": "HIGH",
                "category": "AUTH",
                "description": "DM 정책이 open으로 설정되어 누구나 에이전트에게 메시지를 보낼 수 있습니다.",
                "remediation": "dmPolicy를 'allowlist' 또는 'pairing'으로 변경하세요."
            }
        ],
        "overall_severity": "CRITICAL",
        "reasoning": "모든 보안 메커니즘이 비활성화된 최악의 설정입니다. 외부 네트워크 노출, 인증 없음, 실행 확인 없음, 와일드카드 도구/명령 허용, 개방형 DM 정책으로 에이전트가 완전히 제어 불능 상태입니다."
    }
))

# ---------- 7. auth.mode=token with weak token ----------
SCENARIOS.append(make_entry(
    user_content='## Config\n```json\n{"config":{"gateway":{"bind":"127.0.0.1","port":18789,"auth":{"mode":"token","token":"abc123"}},"tools":{"allow":["read","write"],"exec":{"ask":"always"}}}}\n```',
    assistant_json={
        "agent_type": "openclaw",
        "config_safe": False,
        "security_score": 85,
        "findings": [
            {
                "field": "gateway.auth.token",
                "current_value": "abc123 (6자)",
                "expected_value": "32자 이상의 랜덤 문자열",
                "severity": "HIGH",
                "category": "AUTH",
                "description": "인증 토큰이 너무 짧고 추측 가능합니다. 브루트포스 공격에 취약합니다.",
                "remediation": "openssl rand -hex 24 등으로 최소 32자 이상의 랜덤 토큰을 생성하세요."
            }
        ],
        "overall_severity": "HIGH",
        "reasoning": "token 인증이 활성화되어 있으나 토큰이 6자로 너무 짧습니다. 나머지 설정(로컬 바인딩, 제한된 도구, exec.ask=always)은 안전합니다."
    }
))

# ---------- 8. Real config with config_files: auth-profiles with masked keys ----------
SCENARIOS.append(make_entry(
    user_content='## Config\n```json\n{"config":{"gateway":{"bind":"loopback","port":18789,"auth":{"mode":"token","token":"f0e1d2c3b4a5f6e7d8c9b0a1f2e3d4c5b6a7f8e9"}},"tools":{"allow":["read","write","exec","web_fetch","web_search"],"exec":{"ask":"off"}},"channels":{"discord":{"enabled":true,"dmPolicy":"pairing","allowFrom":["778617145546375189"]}}},"config_files":{"auth-profiles":{"anthropic:default":{"mode":"api_key","key":"sk-ant-a***(1 key)"},"openai:default":{"mode":"api_key","key":"sk-proj-***(1 key)"}},"exec-approvals":{"agents":{"main":{"allowlist":[{"pattern":"/usr/local/bin/gh"},{"pattern":"/Users/user/.agentguard/bin/agentguard"},{"pattern":"/usr/bin/git"}],"ask":"off"}}}}}\n```',
    assistant_json={
        "agent_type": "openclaw",
        "config_safe": True,
        "security_score": 92,
        "findings": [
            {
                "field": "tools.exec.ask",
                "current_value": "off",
                "expected_value": "always 또는 on-miss",
                "severity": "MEDIUM",
                "category": "HITL",
                "description": "실행 확인이 비활성화되어 있습니다. exec-approvals에 특정 명령만 허용되어 있어 위험이 제한적입니다.",
                "remediation": "추가 보호가 필요하면 exec.ask를 'on-miss'로 설정하세요."
            }
        ],
        "overall_severity": "MEDIUM",
        "reasoning": "loopback 바인딩과 token 인증으로 네트워크 보안이 확보되어 있습니다. API 키는 마스킹 처리되어 있고, exec-approvals에 특정 명령(gh, agentguard, git)만 허용되어 있습니다. exec.ask=off이지만 제한된 exec-approvals와 결합하여 위험이 완화됩니다."
    }
))

# ---------- 9. Mixed: safe network but dangerous exec-approvals wildcard ----------
SCENARIOS.append(make_entry(
    user_content='## Config\n```json\n{"config":{"gateway":{"bind":"loopback","port":18789,"auth":{"mode":"token","token":"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"}},"tools":{"allow":["read","write","exec"],"exec":{"ask":"off"}}},"config_files":{"exec-approvals":{"agents":{"*":{"allowlist":[{"pattern":"*"}]},"main":{"allowlist":[{"pattern":"*"}]}}}}}\n```',
    assistant_json={
        "agent_type": "openclaw",
        "config_safe": False,
        "security_score": 42,
        "findings": [
            {
                "field": "exec-approvals.agents.*.allowlist[0].pattern",
                "current_value": "*",
                "expected_value": "구체적인 명령 패턴",
                "severity": "CRITICAL",
                "category": "EXECUTION",
                "description": "모든 에이전트에 와일드카드 실행 승인이 설정되어 모든 명령이 자동 허용됩니다.",
                "remediation": "에이전트별로 필요한 명령만 구체적인 패턴으로 승인하세요."
            },
            {
                "field": "exec-approvals.agents.main.allowlist[0].pattern",
                "current_value": "*",
                "expected_value": "구체적인 명령 패턴",
                "severity": "CRITICAL",
                "category": "EXECUTION",
                "description": "main 에이전트에 와일드카드 실행 승인이 설정되어 있습니다.",
                "remediation": "/usr/local/bin/gh, /usr/bin/git 등 필요한 명령만 지정하세요."
            },
            {
                "field": "tools.exec.ask",
                "current_value": "off",
                "expected_value": "always 또는 on-miss",
                "severity": "MEDIUM",
                "category": "HITL",
                "description": "실행 확인이 비활성화되어 있습니다. 와일드카드 exec-approvals와 결합하면 위험이 증가합니다.",
                "remediation": "exec.ask를 'on-miss'로 설정하거나 exec-approvals를 제한하세요."
            }
        ],
        "overall_severity": "CRITICAL",
        "reasoning": "네트워크(loopback)와 인증(token)은 안전하지만, 모든 에이전트에 와일드카드 exec-approvals가 설정되어 있어 어떤 명령이든 실행 가능합니다. exec.ask=off와 결합하면 에이전트가 제한 없이 명령을 실행할 수 있습니다."
    }
))

# ---------- 10. dmPolicy=pairing is safe (not "open") ----------
SCENARIOS.append(make_entry(
    user_content='## Config\n```json\n{"config":{"gateway":{"bind":"loopback","port":18789,"auth":{"mode":"token","token":"d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3"}},"tools":{"allow":["read","write","web_fetch"],"exec":{"ask":"always"}},"channels":{"discord":{"enabled":true,"dmPolicy":"pairing","groupPolicy":"allowlist","allowFrom":["778617145546375189"]},"telegram":{"enabled":true,"dmPolicy":"pairing","groupPolicy":"allowlist","streaming":"partial"}}}}\n```',
    assistant_json={
        "agent_type": "openclaw",
        "config_safe": True,
        "security_score": 100,
        "findings": [],
        "overall_severity": "NONE",
        "reasoning": "완벽한 보안 구성입니다. loopback 바인딩, 강력한 token 인증, exec.ask=always, 제한된 도구 목록이 설정되어 있습니다. Discord와 Telegram 모두 pairing DM 정책과 allowlist 그룹 정책으로 접근이 제한되어 있습니다."
    }
))

# ---------- 11. AgentGuard gateEnabled=false + gateFailOpen=true — dangerous ----------
SCENARIOS.append(make_entry(
    user_content='## Config\n```json\n{"config":{"gateway":{"bind":"loopback","port":18789,"auth":{"mode":"token","token":"c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2"}},"tools":{"allow":["read","write","exec"],"exec":{"ask":"off"}},"agentguard":{"gateEnabled":false,"gateFailOpen":true,"llmMode":"monitor"}}}\n```',
    assistant_json={
        "agent_type": "openclaw",
        "config_safe": False,
        "security_score": 35,
        "findings": [
            {
                "field": "tools.exec.ask",
                "current_value": "off",
                "expected_value": "always",
                "severity": "CRITICAL",
                "category": "HITL",
                "description": "실행 확인이 비활성화되어 있고 AgentGuard 보안 게이트도 꺼져 있어 보완 수단이 없습니다.",
                "remediation": "tools.exec.ask를 'always'로 설정하거나 AgentGuard를 활성화하세요."
            },
            {
                "field": "agentguard.gateEnabled",
                "current_value": False,
                "expected_value": True,
                "severity": "CRITICAL",
                "category": "EXECUTION",
                "description": "AgentGuard 보안 게이트가 비활성화되어 모든 요청이 보안 검사 없이 통과합니다.",
                "remediation": "agentguard.gateEnabled를 true로 설정하세요."
            },
            {
                "field": "agentguard.gateFailOpen",
                "current_value": True,
                "expected_value": False,
                "severity": "HIGH",
                "category": "EXECUTION",
                "description": "게이트 실패 시 요청이 허용되어 보안 우회가 가능합니다.",
                "remediation": "agentguard.gateFailOpen을 false로 설정하세요."
            }
        ],
        "overall_severity": "CRITICAL",
        "reasoning": "네트워크와 인증은 안전하지만, exec.ask=off이면서 AgentGuard 보안 게이트가 비활성화되어 보완 수단이 없습니다. 에이전트가 사용자 확인 없이 명령을 실행할 수 있고, 보안 검사도 우회됩니다."
    }
))

# ---------- 12. 0.0.0.0 bind with token auth — partial danger ----------
SCENARIOS.append(make_entry(
    user_content='## Config\n```json\n{"config":{"gateway":{"bind":"0.0.0.0","port":18789,"auth":{"mode":"token","token":"e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4"}},"tools":{"allow":["read","write"],"exec":{"ask":"always"}}}}\n```',
    assistant_json={
        "agent_type": "openclaw",
        "config_safe": False,
        "security_score": 85,
        "findings": [
            {
                "field": "gateway.bind",
                "current_value": "0.0.0.0",
                "expected_value": "127.0.0.1 또는 loopback",
                "severity": "HIGH",
                "category": "NETWORK",
                "description": "모든 네트워크 인터페이스에 바인딩되어 같은 네트워크의 다른 사용자가 접근할 수 있습니다.",
                "remediation": "외부 접근이 필요하지 않다면 gateway.bind를 '127.0.0.1' 또는 'loopback'으로 변경하세요."
            }
        ],
        "overall_severity": "HIGH",
        "reasoning": "token 인증이 설정되어 무단 접근은 방지되지만, 0.0.0.0 바인딩으로 네트워크에 노출됩니다. exec.ask=always와 제한된 도구 목록은 안전합니다."
    }
))

# ---------- 13. AgentGuard LLM Gateway confirm mode — very safe ----------
SCENARIOS.append(make_entry(
    user_content='## Config\n```json\n{"config":{"gateway":{"bind":"loopback","port":18789,"auth":{"mode":"token","token":"b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1"}},"tools":{"allow":["read","write","exec","web_fetch"],"exec":{"ask":"off"}},"agentguard":{"gateEnabled":true,"llmMode":"confirm","gateFailOpen":false}}}\n```',
    assistant_json={
        "agent_type": "openclaw",
        "config_safe": True,
        "security_score": 97,
        "findings": [
            {
                "field": "tools.exec.ask",
                "current_value": "off",
                "expected_value": "always",
                "severity": "LOW",
                "category": "HITL",
                "description": "실행 확인이 비활성화되어 있지만, AgentGuard LLM Gateway가 confirm 모드로 위험한 작업에 대해 사용자 승인을 요청합니다.",
                "remediation": "현재 AgentGuard confirm 모드로 충분히 보호됩니다. 추가 변경 불필요합니다."
            }
        ],
        "overall_severity": "LOW",
        "reasoning": "AgentGuard LLM Gateway가 confirm 모드로 작동하여 위험한 tool call에 대해 사용자 승인을 요청합니다. loopback 바인딩, token 인증, gateFailOpen=false로 매우 안전한 구성입니다."
    }
))

# ---------- 14. Tools allow wildcard ["*"] but otherwise safe ----------
SCENARIOS.append(make_entry(
    user_content='## Config\n```json\n{"config":{"gateway":{"bind":"127.0.0.1","port":18789,"auth":{"mode":"token","token":"a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9"}},"tools":{"allow":["*"],"exec":{"ask":"always"}}}}\n```',
    assistant_json={
        "agent_type": "openclaw",
        "config_safe": False,
        "security_score": 85,
        "findings": [
            {
                "field": "tools.allow",
                "current_value": "[\"*\"]",
                "expected_value": "필요한 도구만 명시적으로 나열",
                "severity": "HIGH",
                "category": "PERMISSIONS",
                "description": "와일드카드로 모든 도구가 허용되어 에이전트가 의도치 않은 도구를 사용할 수 있습니다.",
                "remediation": "read, write, exec 등 필요한 도구만 명시적으로 지정하세요."
            }
        ],
        "overall_severity": "HIGH",
        "reasoning": "네트워크와 인증은 안전하고 exec.ask=always로 실행 확인도 있지만, 도구 허용 목록이 와일드카드로 설정되어 있어 에이전트가 모든 도구에 접근할 수 있습니다."
    }
))

# ---------- 15. Real config with AgentGuard monitor mode + specific exec-approvals ----------
SCENARIOS.append(make_entry(
    user_content='## Config\n```json\n{"config":{"gateway":{"bind":"loopback","mode":"local","port":18789,"auth":{"mode":"token","token":"d54ff74802e6d80dae1864b1a2cee4d6fef7a16c949cb480"},"tailscale":{"mode":"off"}},"tools":{"allow":["group:fs","group:runtime","group:web","exec","read","write","edit","apply_patch","web_fetch","web_search","memory_search","memory_get","image"],"exec":{"ask":"off","host":"gateway"}},"channels":{"discord":{"enabled":true,"dmPolicy":"pairing","groupPolicy":"allowlist","allowFrom":["778617145546375189"]},"telegram":{"enabled":true,"dmPolicy":"pairing","groupPolicy":"allowlist","streaming":"partial"}},"agents":{"defaults":{"model":{"primary":"anthropic/claude-sonnet-4-5"},"workspace":"/Users/user/.openclaw/workspace"}},"meta":{"lastTouchedAt":"2026-03-06T02:57:57.769Z"}},"config_files":{"auth-profiles":{"anthropic:default":{"mode":"api_key","key":"sk-ant-a***(1 key)"},"anthropic:manual":{"mode":"token","token":"sk-ant-a***(1 key)"}},"exec-approvals":{"defaults":{"security":"full","ask":"off"},"agents":{"main":{"allowlist":[{"pattern":"/usr/local/bin/gh"},{"pattern":"/Users/user/.agentguard/bin/agentguard"}],"ask":"off","security":"full"}}}}}\n```',
    assistant_json={
        "agent_type": "openclaw",
        "config_safe": True,
        "security_score": 92,
        "findings": [
            {
                "field": "tools.exec.ask",
                "current_value": "off",
                "expected_value": "always 또는 on-miss",
                "severity": "MEDIUM",
                "category": "HITL",
                "description": "실행 확인이 비활성화되어 있지만, exec-approvals에 특정 명령(gh, agentguard)만 허용되어 위험이 제한적입니다.",
                "remediation": "추가 보호가 필요하면 exec.ask를 'on-miss'로 설정하세요. AgentGuard를 함께 사용하면 보안이 더 강화됩니다."
            }
        ],
        "overall_severity": "MEDIUM",
        "reasoning": "실제 운영 환경에서 사용되는 안전한 구성입니다. loopback 바인딩, 48자 token 인증, pairing DM 정책, allowlist 그룹 정책이 설정되어 있습니다. exec.ask=off이지만 exec-approvals에 gh와 agentguard만 허용되어 위험이 제한됩니다. API 키는 마스킹 처리되어 있습니다."
    }
))

# ---------- 16. Only auth-profiles without exec-approvals (minimal config) ----------
SCENARIOS.append(make_entry(
    user_content='## Config\n```json\n{"config":{"gateway":{"bind":"loopback","port":18789,"auth":{"mode":"token","token":"x9y8z7w6v5u4t3s2r1q0p9o8n7m6l5k4j3i2h1g0"}},"tools":{"allow":["read","write","web_fetch"],"exec":{"ask":"on-miss"}}},"config_files":{"auth-profiles":{"anthropic:default":{"mode":"api_key","key":"sk-ant-a***(1 key)"}}}}\n```',
    assistant_json={
        "agent_type": "openclaw",
        "config_safe": True,
        "security_score": 100,
        "findings": [],
        "overall_severity": "NONE",
        "reasoning": "안전한 구성입니다. loopback 바인딩으로 로컬 접근만 허용되고, 강력한 token 인증이 설정되어 있습니다. exec.ask=on-miss로 미승인 명령에 대해 확인을 요청하며, 도구 목록이 제한되어 있습니다. API 키는 마스킹 처리되어 있습니다."
    }
))

# ---------- 17. Tailscale mode ON (remote access scenario) ----------
SCENARIOS.append(make_entry(
    user_content='## Config\n```json\n{"config":{"gateway":{"bind":"0.0.0.0","port":18789,"auth":{"mode":"token","token":"h1g2f3e4d5c6b7a8h9g0f1e2d3c4b5a6h7g8f9e0"},"tailscale":{"mode":"on"}},"tools":{"allow":["read","write","exec"],"exec":{"ask":"always"}}}}\n```',
    assistant_json={
        "agent_type": "openclaw",
        "config_safe": False,
        "security_score": 85,
        "findings": [
            {
                "field": "gateway.bind",
                "current_value": "0.0.0.0",
                "expected_value": "127.0.0.1 또는 loopback",
                "severity": "HIGH",
                "category": "NETWORK",
                "description": "0.0.0.0 바인딩이지만 Tailscale이 활성화되어 있어 VPN 내에서만 접근 가능할 수 있습니다. 그래도 로컬 바인딩이 더 안전합니다.",
                "remediation": "원격 접근이 꼭 필요하다면 Tailscale VPN 내에서만 접근 가능한지 확인하세요. 가능하면 loopback으로 변경하세요."
            }
        ],
        "overall_severity": "HIGH",
        "reasoning": "Tailscale VPN이 활성화되어 있어 직접적인 외부 노출은 제한되지만, 0.0.0.0 바인딩은 여전히 위험합니다. token 인증과 exec.ask=always로 다른 보안 설정은 양호합니다."
    }
))

# ---------- 18. Claude Code config ----------
SCENARIOS.append(make_entry(
    user_content='## Config\n```json\n{"permissions":{"allow":["read","write","edit"],"deny":[".env","sudo","curl|bash",".ssh","credentials"]},"mcpServers":{"filesystem":{"command":"npx","args":["@modelcontextprotocol/server-filesystem","/Users/user/projects"]}}}\n```',
    assistant_json={
        "agent_type": "claude_code",
        "config_safe": True,
        "security_score": 92,
        "findings": [
            {
                "field": "permissions.disableBypassPermissionsMode",
                "current_value": "missing",
                "expected_value": "disable",
                "severity": "MEDIUM",
                "category": "PERMISSIONS",
                "description": "퍼미션 우회 모드 비활성화 설정이 없습니다.",
                "remediation": "disableBypassPermissionsMode를 'disable'로 설정하세요."
            }
        ],
        "overall_severity": "MEDIUM",
        "reasoning": "deny 목록에 주요 민감 패턴(.env, sudo, .ssh 등)이 포함되어 있고, 도구 허용이 제한적입니다. MCP 서버도 공식 패키지만 사용합니다. 퍼미션 우회 모드 비활성화 설정만 추가하면 됩니다."
    }
))

# ---------- 19. Config with localhost port in user message (LLM Gateway) ----------
SCENARIOS.append(make_entry(
    user_content='## Config\n```json\n{"config":{"gateway":{"bind":"loopback","port":18789,"auth":{"mode":"token","token":"j2k3l4m5n6o7p8q9r0s1t2u3v4w5x6y7z8a9b0c1"}},"tools":{"allow":["read","write","exec"],"exec":{"ask":"off"}},"agentguard":{"gateEnabled":true,"llmMode":"monitor","llmPort":10081,"gateFailOpen":true}}}\n```',
    assistant_json={
        "agent_type": "openclaw",
        "config_safe": False,
        "security_score": 77,
        "findings": [
            {
                "field": "tools.exec.ask",
                "current_value": "off",
                "expected_value": "always 또는 on-miss",
                "severity": "MEDIUM",
                "category": "HITL",
                "description": "실행 확인이 비활성화되어 있지만, AgentGuard LLM Gateway가 monitor 모드로 위험한 도구 호출을 감시합니다.",
                "remediation": "보다 강력한 보호를 원하면 llmMode를 'enforce'로 변경하세요."
            },
            {
                "field": "agentguard.gateFailOpen",
                "current_value": True,
                "expected_value": False,
                "severity": "HIGH",
                "category": "EXECUTION",
                "description": "AgentGuard 게이트 장애 시 요청이 허용됩니다.",
                "remediation": "agentguard.gateFailOpen을 false로 설정하세요."
            }
        ],
        "overall_severity": "HIGH",
        "reasoning": "loopback 바인딩과 token 인증으로 기본 보안은 확보되어 있습니다. AgentGuard LLM Gateway가 monitor 모드로 작동하여 exec.ask=off의 위험을 부분적으로 완화하지만, gateFailOpen=true로 장애 시 보안이 무력화될 수 있습니다."
    }
))

# ---------- 20. Minimal config — missing many fields ----------
SCENARIOS.append(make_entry(
    user_content='## Config\n```json\n{"config":{"gateway":{"port":18789},"tools":{"exec":{"ask":"off"}}}}\n```',
    assistant_json={
        "agent_type": "openclaw",
        "config_safe": False,
        "security_score": 60,
        "findings": [
            {
                "field": "gateway.auth.mode",
                "current_value": "미설정 (기본값)",
                "expected_value": "token",
                "severity": "CRITICAL",
                "category": "AUTH",
                "description": "인증 모드가 명시적으로 설정되지 않았습니다. 기본값에 따라 인증이 없을 수 있습니다.",
                "remediation": "gateway.auth.mode를 'token'으로 설정하고 강력한 토큰을 생성하세요."
            },
            {
                "field": "tools.exec.ask",
                "current_value": "off",
                "expected_value": "always",
                "severity": "CRITICAL",
                "category": "HITL",
                "description": "실행 확인이 비활성화되어 있고 다른 보안 레이어 정보가 없습니다.",
                "remediation": "tools.exec.ask를 'always'로 설정하세요."
            }
        ],
        "overall_severity": "CRITICAL",
        "reasoning": "최소한의 설정만 있어 많은 보안 필드가 누락되어 있습니다. 인증 설정과 실행 확인이 없어 보안 위험이 높습니다. bind 주소도 미설정으로 기본값에 의존합니다."
    }
))


def main():
    out_dir = os.path.dirname(__file__)
    out_path = os.path.join(out_dir, "config_diagnosis_v9.jsonl")

    with open(out_path, "w") as f:
        for entry in SCENARIOS:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    print(f"Generated {len(SCENARIOS)} examples → {out_path}")

    # Also print summary
    safe_count = sum(1 for s in SCENARIOS if json.loads(s["messages"][2]["content"])["config_safe"])
    dangerous_count = len(SCENARIOS) - safe_count
    print(f"  Safe configs: {safe_count}")
    print(f"  Dangerous configs: {dangerous_count}")

    # Score distribution
    scores = [json.loads(s["messages"][2]["content"])["security_score"] for s in SCENARIOS]
    print(f"  Score range: {min(scores)} - {max(scores)}")
    print(f"  High score (≥90): {sum(1 for s in scores if s >= 90)}")
    print(f"  Medium score (50-89): {sum(1 for s in scores if 50 <= s < 90)}")
    print(f"  Low score (<50): {sum(1 for s in scores if s < 50)}")


if __name__ == "__main__":
    main()
