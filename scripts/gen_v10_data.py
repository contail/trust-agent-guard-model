"""Generate 30 new config diagnosis training examples for v10."""
import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
V9_DATA = PROJECT_ROOT / "data" / "v9_config_diagnosis" / "config_diagnosis_v9.jsonl"
V10_DIR = PROJECT_ROOT / "data" / "v10_config_diagnosis"
V10_DIR.mkdir(parents=True, exist_ok=True)

# Read system prompt from existing data
with open(V9_DATA) as f:
    system_prompt = json.loads(f.readline())["messages"][0]["content"]

new_examples = []


def make(config_json, safe, score, findings, severity, reasoning):
    user_content = "## Config\n```json\n" + json.dumps(config_json, ensure_ascii=False) + "\n```"
    assistant_content = json.dumps({
        "agent_type": "openclaw",
        "config_safe": safe,
        "security_score": score,
        "findings": findings,
        "overall_severity": severity,
        "reasoning": reasoning
    }, ensure_ascii=False)
    return {
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
            {"role": "assistant", "content": assistant_content}
        ]
    }


def finding(field, cur, exp, sev, cat, desc, fix):
    return {"field": field, "current_value": cur, "expected_value": exp,
            "severity": sev, "category": cat, "description": desc, "remediation": fix}


# ============ SAFE (15) ============

# S1: loopback + token + exec.ask=off + AgentGuard enforce
new_examples.append(make(
    {"config": {"gateway": {"bind": "loopback", "port": 18789, "auth": {"mode": "token", "token": "abc123def456ghi789jkl012mno345pq"}},
                "tools": {"exec": {"ask": "off"}, "allow": ["read", "write", "exec", "web_fetch"]}},
     "agentguard": {"gateEnabled": True, "gateFailOpen": False, "llmMode": "enforce"}},
    True, 92,
    [finding("tools.exec.ask", "off", "always", "MEDIUM", "HITL",
             "exec.ask=off이지만 AgentGuard LLM Gateway(enforce 모드)가 모든 tool call을 감시하고 차단하므로 위험이 완화됩니다.",
             "추가 보안을 원하면 exec.ask를 on-miss로 변경하세요.")],
    "MEDIUM",
    "loopback 바인딩으로 외부 접근이 차단되고, token 인증이 활성화되어 있습니다. exec.ask=off이지만 AgentGuard가 enforce 모드로 모든 요청을 검사하므로 실질적 위험이 낮습니다."
))

# S2: loopback + token + exec.ask=off + AgentGuard confirm
new_examples.append(make(
    {"config": {"gateway": {"bind": "loopback", "port": 18789, "auth": {"mode": "token", "token": "x9y8z7w6v5u4t3s2r1q0p9o8n7m6l5k4"}},
                "tools": {"exec": {"ask": "off"}, "allow": ["read", "write", "exec"]}},
     "agentguard": {"gateEnabled": True, "gateFailOpen": False, "llmMode": "confirm"}},
    True, 95,
    [finding("tools.exec.ask", "off", "always", "MEDIUM", "HITL",
             "exec.ask=off이지만 AgentGuard confirm 모드가 위험한 tool call에 대해 사용자 승인을 요청하므로 보완됩니다.",
             "현재 설정으로 충분히 안전합니다.")],
    "MEDIUM",
    "loopback + token 인증으로 네트워크와 인증이 안전합니다. exec.ask=off이지만 AgentGuard confirm 모드가 위험한 실행에 대해 사용자 확인을 요구하므로 위험이 완화됩니다."
))

# S3: 127.0.0.1 + token + exec.ask=on-miss + AgentGuard enforce
new_examples.append(make(
    {"config": {"gateway": {"bind": "127.0.0.1", "port": 18789, "auth": {"mode": "token", "token": "secure-token-value-32chars-long!!"}},
                "tools": {"exec": {"ask": "on-miss"}, "allow": ["read", "write", "exec"]}},
     "agentguard": {"gateEnabled": True, "gateFailOpen": False, "llmMode": "enforce"}},
    True, 97,
    [finding("tools.exec.ask", "on-miss", "always", "LOW", "HITL",
             "exec.ask=on-miss는 allowlist에 없는 명령만 확인을 요구합니다. AgentGuard enforce와 함께 충분히 안전합니다.",
             "현재 설정이 적절합니다.")],
    "LOW",
    "127.0.0.1 바인딩, token 인증, exec.ask=on-miss, AgentGuard enforce 모드가 적절히 설정되어 안전한 구성입니다."
))

# S4: loopback + token + exec.ask=always (no AgentGuard)
new_examples.append(make(
    {"config": {"gateway": {"bind": "loopback", "port": 18789, "auth": {"mode": "token", "token": "long-random-token-for-auth-12345"}},
                "tools": {"exec": {"ask": "always"}, "allow": ["read", "write"]}}},
    True, 100, [], "NONE",
    "loopback 바인딩으로 로컬 접근만 허용, token 인증 적용, exec.ask=always로 모든 실행에 확인 필요. 안전한 구성입니다."
))

# S5: tailnet + token + exec.ask=always + AgentGuard
new_examples.append(make(
    {"config": {"gateway": {"bind": "tailnet", "port": 18789, "auth": {"mode": "token", "token": "tailnet-secure-token-abc123def4"}},
                "tools": {"exec": {"ask": "always"}, "allow": ["read", "write", "exec"]}},
     "agentguard": {"gateEnabled": True, "gateFailOpen": False, "llmMode": "enforce"}},
    True, 98,
    [finding("gateway.bind", "tailnet", "loopback", "INFO", "NETWORK",
             "Tailscale 네트워크는 암호화된 VPN 위에서 동작하므로 안전합니다.",
             "로컬 전용이면 loopback으로 변경하세요.")],
    "INFO",
    "Tailscale VPN 접근만 허용, token 인증, exec.ask=always, AgentGuard enforce. 매우 안전한 구성입니다."
))

# S6: loopback + password auth + exec.ask=always
new_examples.append(make(
    {"config": {"gateway": {"bind": "loopback", "port": 18789, "auth": {"mode": "password", "password": "strong-p@ssw0rd-2024!"}},
                "tools": {"exec": {"ask": "always"}, "allow": ["read", "write"]}}},
    True, 95,
    [finding("gateway.auth.mode", "password", "token", "LOW", "AUTH",
             "password 인증은 동작하지만 token이 더 안전합니다.",
             "token 인증으로 변경을 권장합니다.")],
    "LOW",
    "loopback + password 인증 + exec.ask=always. password는 token보다 약하지만 loopback 환경에서 안전합니다."
))

# S7: loopback + token + exec.ask=off + AgentGuard enforce + specific exec-approvals
new_examples.append(make(
    {"config": {"gateway": {"bind": "loopback", "port": 18789, "auth": {"mode": "token", "token": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"}},
                "tools": {"exec": {"ask": "off"}, "allow": ["read", "write", "exec"]}},
     "config_files": {"exec-approvals": {"defaults": {"security": "full", "ask": "off"},
                                          "agents": {"main": {"allowlist": [{"pattern": "/usr/local/bin/gh"}, {"pattern": "/usr/bin/git"}],
                                                               "ask": "off", "security": "full"}}}},
     "agentguard": {"gateEnabled": True, "gateFailOpen": False, "llmMode": "enforce"}},
    True, 90,
    [finding("tools.exec.ask", "off", "on-miss", "MEDIUM", "HITL",
             "exec.ask=off이지만 exec-approvals에 특정 명령만 허용되고 AgentGuard가 감시합니다.",
             "추가 보안을 원하면 exec.ask를 on-miss로 변경하세요.")],
    "MEDIUM",
    "loopback + token으로 안전. exec.ask=off이지만 exec-approvals에 gh, git만 허용되고 AgentGuard enforce가 활성화되어 있습니다."
))

# S8: loopback + token + exec.ask=off + AgentGuard monitor (weak but safe overall)
new_examples.append(make(
    {"config": {"gateway": {"bind": "loopback", "port": 18789, "auth": {"mode": "token", "token": "monitor-mode-token-1234567890ab"}},
                "tools": {"exec": {"ask": "off"}, "allow": ["read", "exec"]}},
     "agentguard": {"gateEnabled": True, "gateFailOpen": False, "llmMode": "monitor"}},
    True, 88,
    [finding("tools.exec.ask", "off", "always", "MEDIUM", "HITL",
             "exec.ask=off이고 AgentGuard monitor 모드라 차단은 안 하지만, loopback 환경에서 위험이 제한적입니다.",
             "AgentGuard를 enforce 모드로 변경하면 더 안전합니다.")],
    "MEDIUM",
    "loopback + token, AgentGuard monitor 모드. exec.ask=off이지만 loopback 환경에서 외부 접근이 불가하므로 안전합니다."
))

# S9: 127.0.0.1 + token + exec.ask=off + AgentGuard enforce + limited tools
new_examples.append(make(
    {"config": {"gateway": {"bind": "127.0.0.1", "port": 18789, "auth": {"mode": "token", "token": "limited-tools-token-abcdef1234"}},
                "tools": {"exec": {"ask": "off"}, "allow": ["read"]}},
     "agentguard": {"gateEnabled": True, "gateFailOpen": False, "llmMode": "enforce"}},
    True, 95,
    [finding("tools.exec.ask", "off", "always", "LOW", "HITL",
             "exec.ask=off이지만 허용 도구가 read만이고 AgentGuard enforce가 활성화되어 실질적 위험이 매우 낮습니다.",
             "현재 설정으로 충분합니다.")],
    "LOW",
    "127.0.0.1 바인딩, token 인증, 허용 도구가 read만. AgentGuard enforce가 감시하므로 안전합니다."
))

# S10: loopback + token + exec.ask=off + AgentGuard enforce + DM pairing
new_examples.append(make(
    {"config": {"gateway": {"bind": "loopback", "port": 18789, "auth": {"mode": "token", "token": "dm-pairing-token-xyz789abc012"}},
                "tools": {"exec": {"ask": "off"}, "allow": ["read", "write", "exec", "web_fetch"]},
                "channels": {"discord": {"enabled": True, "dmPolicy": "pairing"}, "telegram": {"enabled": True, "dmPolicy": "pairing"}}},
     "agentguard": {"gateEnabled": True, "gateFailOpen": False, "llmMode": "enforce"}},
    True, 92,
    [finding("tools.exec.ask", "off", "always", "MEDIUM", "HITL",
             "exec.ask=off이지만 AgentGuard enforce가 보완합니다.",
             "현재 설정이 적절합니다.")],
    "MEDIUM",
    "loopback + token + AgentGuard enforce + DM pairing. exec.ask=off이지만 AgentGuard가 보완하고 채널도 안전합니다."
))

# S11: loopback + token + exec.ask=always + open DM
new_examples.append(make(
    {"config": {"gateway": {"bind": "loopback", "port": 18789, "auth": {"mode": "token", "token": "channels-open-token-secure12345"}},
                "tools": {"exec": {"ask": "always"}, "allow": ["read", "write"]},
                "channels": {"discord": {"enabled": True, "dmPolicy": "open"}}}},
    True, 90,
    [finding("channels.discord.dmPolicy", "open", "pairing", "MEDIUM", "ACCESS",
             "Discord DM 정책이 open으로 누구나 에이전트에 메시지를 보낼 수 있습니다.",
             "dmPolicy를 pairing 또는 allowlist로 변경하세요.")],
    "MEDIUM",
    "loopback + token + exec.ask=always는 안전. Discord DM open이 있지만 전반적으로 안전한 구성입니다."
))

# S12: loopback + token + exec.ask=off + AgentGuard enforce (full tool set)
new_examples.append(make(
    {"config": {"gateway": {"bind": "loopback", "mode": "local", "port": 18789,
                             "auth": {"mode": "token", "token": "full-tools-enforce-token-abcdef"}},
                "tools": {"exec": {"ask": "off", "host": "gateway"},
                          "allow": ["group:fs", "group:runtime", "group:web", "exec", "read", "write", "edit", "web_fetch", "web_search"]}},
     "agentguard": {"gateEnabled": True, "gateFailOpen": False, "llmMode": "enforce"}},
    True, 90,
    [finding("tools.exec.ask", "off", "on-miss", "MEDIUM", "HITL",
             "exec.ask=off이지만 AgentGuard enforce가 모든 tool call을 검사합니다.",
             "보다 엄격한 제어를 원하면 exec.ask를 on-miss로 변경하세요.")],
    "MEDIUM",
    "loopback + token으로 네트워크 안전. 허용 도구가 많고 exec.ask=off이지만, AgentGuard enforce가 모든 요청을 검사하므로 위험이 완화됩니다."
))

# S13: trusted-proxy + exec.ask=always
new_examples.append(make(
    {"config": {"gateway": {"bind": "loopback", "port": 18789, "auth": {"mode": "trusted-proxy", "trustedProxies": ["127.0.0.1"]}},
                "tools": {"exec": {"ask": "always"}, "allow": ["read", "write"]}}},
    True, 93,
    [finding("gateway.auth.mode", "trusted-proxy", "token", "LOW", "AUTH",
             "trusted-proxy는 리버스 프록시 뒤에서 적합합니다. trustedProxies가 loopback으로 제한되어 안전합니다.",
             "리버스 프록시 없이 사용한다면 token으로 변경하세요.")],
    "LOW",
    "loopback + trusted-proxy(127.0.0.1) + exec.ask=always. 안전한 구성입니다."
))

# S14: loopback + token + exec.ask=off + AgentGuard enforce + auth-profiles
new_examples.append(make(
    {"config": {"gateway": {"bind": "loopback", "port": 18789, "auth": {"mode": "token", "token": "auth-profile-token-masked-12345"}},
                "tools": {"exec": {"ask": "off"}, "allow": ["read", "write", "exec"]}},
     "config_files": {"auth-profiles": {"anthropic:default": {"mode": "api_key", "key": "sk-ant-***"}}},
     "agentguard": {"gateEnabled": True, "gateFailOpen": False, "llmMode": "enforce"}},
    True, 92,
    [finding("tools.exec.ask", "off", "on-miss", "MEDIUM", "HITL",
             "exec.ask=off이지만 AgentGuard enforce가 보완합니다.",
             "exec.ask를 on-miss로 변경하세요.")],
    "MEDIUM",
    "loopback + token + AgentGuard enforce. auth-profiles 키가 마스킹되어 있고 exec.ask=off이지만 AgentGuard가 보완합니다."
))

# S15: loopback + token + exec.ask=off + AgentGuard enforce (variation)
new_examples.append(make(
    {"config": {"gateway": {"bind": "loopback", "port": 19000, "auth": {"mode": "token", "token": "another-variation-token-9876543"}},
                "tools": {"exec": {"ask": "off"}, "allow": ["read", "write", "exec", "edit", "apply_patch"]}},
     "agentguard": {"gateEnabled": True, "gateFailOpen": False, "llmMode": "enforce"}},
    True, 92,
    [finding("tools.exec.ask", "off", "always", "MEDIUM", "HITL",
             "exec.ask=off이지만 AgentGuard enforce가 모든 tool call을 실시간 검사합니다.",
             "exec.ask를 on-miss로 변경하면 더 안전합니다.")],
    "MEDIUM",
    "loopback + token + AgentGuard enforce(gateFailOpen=false). exec.ask=off이지만 AgentGuard가 모든 요청을 검사하므로 안전합니다."
))

# ============ DANGEROUS (15) ============

# D1: auth.mode=none
new_examples.append(make(
    {"config": {"gateway": {"bind": "loopback", "port": 18789, "auth": {"mode": "none"}},
                "tools": {"exec": {"ask": "always"}, "allow": ["read", "write"]}}},
    False, 40,
    [finding("gateway.auth.mode", "none", "token", "CRITICAL", "AUTH",
             "인증이 비활성화되어 누구나 에이전트에 접근할 수 있습니다.",
             "gateway.auth.mode를 token으로 변경하세요.")],
    "CRITICAL",
    "인증이 비활성화(mode=none)되어 다른 프로세스가 인증 없이 에이전트에 접근할 수 있습니다. 심각한 보안 취약점입니다."
))

# D2: bind=0.0.0.0
new_examples.append(make(
    {"config": {"gateway": {"bind": "0.0.0.0", "port": 18789, "auth": {"mode": "token", "token": "exposed-but-has-token-12345678"}},
                "tools": {"exec": {"ask": "always"}, "allow": ["read", "write"]}}},
    False, 50,
    [finding("gateway.bind", "0.0.0.0", "loopback", "HIGH", "NETWORK",
             "0.0.0.0 바인딩으로 외부에서 접근 가능합니다.",
             "loopback 또는 127.0.0.1로 변경하세요.")],
    "HIGH",
    "0.0.0.0으로 외부 네트워크에서 접근 가능합니다. token 인증이 있지만 네트워크 노출이 공격 표면을 확대합니다."
))

# D3: bind=lan + auth=none
new_examples.append(make(
    {"config": {"gateway": {"bind": "lan", "port": 18789, "auth": {"mode": "none"}},
                "tools": {"exec": {"ask": "off"}, "allow": ["read", "write", "exec"]}}},
    False, 0,
    [finding("gateway.bind", "lan", "loopback", "CRITICAL", "NETWORK",
             "LAN 바인딩으로 같은 네트워크의 모든 장치에서 접근 가능합니다.", "loopback으로 변경하세요."),
     finding("gateway.auth.mode", "none", "token", "CRITICAL", "AUTH",
             "인증이 없습니다.", "token 인증을 활성화하세요."),
     finding("tools.exec.ask", "off", "always", "CRITICAL", "HITL",
             "실행 확인이 비활성화되어 있고 보완 수단이 없습니다.", "exec.ask를 always로 변경하세요.")],
    "CRITICAL",
    "LAN 바인딩 + 인증 없음 + exec.ask=off. 같은 네트워크의 누구나 에이전트를 통해 명령을 실행할 수 있습니다."
))

# D4: exec.ask=off + AgentGuard disabled
new_examples.append(make(
    {"config": {"gateway": {"bind": "loopback", "port": 18789, "auth": {"mode": "token", "token": "no-guard-token-abcdef12345678"}},
                "tools": {"exec": {"ask": "off"}, "allow": ["read", "write", "exec"]}},
     "agentguard": {"gateEnabled": False, "gateFailOpen": True}},
    False, 45,
    [finding("tools.exec.ask", "off", "always", "CRITICAL", "HITL",
             "실행 확인이 비활성화되어 있고 AgentGuard도 꺼져 있어 보완 수단이 없습니다.",
             "exec.ask를 always로 변경하거나 AgentGuard를 활성화하세요."),
     finding("agentguard.gateEnabled", False, True, "HIGH", "EXECUTION",
             "AgentGuard가 비활성화되어 있습니다.", "gateEnabled를 true로 설정하세요.")],
    "CRITICAL",
    "exec.ask=off이면서 AgentGuard도 비활성화되어 명령 실행에 대한 보안 검사가 전혀 없습니다."
))

# D5: wildcard exec-approvals
new_examples.append(make(
    {"config": {"gateway": {"bind": "loopback", "port": 18789, "auth": {"mode": "token", "token": "wildcard-exec-token-1234567890"}},
                "tools": {"exec": {"ask": "off"}, "allow": ["read", "write", "exec"]}},
     "config_files": {"exec-approvals": {"defaults": {"security": "full", "ask": "off"},
                                          "agents": {"main": {"allowlist": [{"pattern": "*"}], "ask": "off", "security": "full"}}}}},
    False, 20,
    [finding("exec-approvals.agents.main.allowlist", "*", "specific commands only", "CRITICAL", "EXECUTION",
             "exec-approvals에 와일드카드(*)가 설정되어 모든 명령이 자동 승인됩니다.",
             "와일드카드를 제거하고 필요한 명령만 허용하세요."),
     finding("tools.exec.ask", "off", "always", "CRITICAL", "HITL",
             "와일드카드 allowlist + exec.ask=off로 모든 명령이 무검사 실행됩니다.",
             "exec.ask를 always로 변경하세요.")],
    "CRITICAL",
    "exec-approvals에 와일드카드(*)가 설정되어 모든 명령이 자동 승인되며, exec.ask=off로 확인도 없습니다."
))

# D6: 0.0.0.0 + auth=none + exec.ask=off
new_examples.append(make(
    {"config": {"gateway": {"bind": "0.0.0.0", "port": 18789, "auth": {"mode": "none"}},
                "tools": {"exec": {"ask": "off"}, "allow": ["read", "write", "exec"]}}},
    False, 0,
    [finding("gateway.bind", "0.0.0.0", "loopback", "CRITICAL", "NETWORK",
             "모든 네트워크에서 접근 가능합니다.", "loopback으로 변경하세요."),
     finding("gateway.auth.mode", "none", "token", "CRITICAL", "AUTH",
             "인증이 없습니다.", "token 인증을 활성화하세요."),
     finding("tools.exec.ask", "off", "always", "CRITICAL", "HITL",
             "실행 확인이 없습니다.", "exec.ask를 always로 변경하세요.")],
    "CRITICAL",
    "네트워크 노출 + 인증 없음 + 실행 확인 없음. 인터넷에서 누구나 임의 명령을 실행할 수 있습니다."
))

# D7: gateEnabled + gateFailOpen=true + monitor
new_examples.append(make(
    {"config": {"gateway": {"bind": "loopback", "port": 18789, "auth": {"mode": "token", "token": "failopen-weak-token-1234567890"}},
                "tools": {"exec": {"ask": "off"}, "allow": ["read", "write", "exec"]}},
     "agentguard": {"gateEnabled": True, "gateFailOpen": True, "llmMode": "monitor"}},
    False, 55,
    [finding("tools.exec.ask", "off", "always", "HIGH", "HITL",
             "exec.ask=off이고 AgentGuard가 monitor(차단 안함) + gateFailOpen=true라 실질적 보호가 부족합니다.",
             "exec.ask를 always로 변경하거나 AgentGuard를 enforce로 설정하세요."),
     finding("agentguard.gateFailOpen", True, False, "HIGH", "EXECUTION",
             "게이트 실패 시 요청이 허용됩니다.", "gateFailOpen을 false로 설정하세요.")],
    "HIGH",
    "exec.ask=off + AgentGuard monitor(차단 불가) + gateFailOpen=true. AgentGuard가 있지만 실질적 차단 능력이 없습니다."
))

# D8: auth=none + AgentGuard enabled
new_examples.append(make(
    {"config": {"gateway": {"bind": "loopback", "port": 18789, "auth": {"mode": "none"}},
                "tools": {"exec": {"ask": "always"}, "allow": ["read"]}},
     "agentguard": {"gateEnabled": True, "gateFailOpen": False, "llmMode": "enforce"}},
    False, 45,
    [finding("gateway.auth.mode", "none", "token", "CRITICAL", "AUTH",
             "인증이 없습니다. AgentGuard가 있어도 인증 없이 접근하는 것 자체가 위험합니다.",
             "token 인증을 활성화하세요.")],
    "CRITICAL",
    "인증 없음(mode=none). AgentGuard enforce가 활성화되어 있지만, 인증 부재는 근본적 보안 결함입니다."
))

# D9: 0.0.0.0 + token + exec.ask=off + no AgentGuard
new_examples.append(make(
    {"config": {"gateway": {"bind": "0.0.0.0", "port": 18789, "auth": {"mode": "token", "token": "exposed-no-guard-token-abcdef"}},
                "tools": {"exec": {"ask": "off"}, "allow": ["read", "write", "exec"]}}},
    False, 30,
    [finding("gateway.bind", "0.0.0.0", "loopback", "HIGH", "NETWORK",
             "외부 네트워크에 노출되어 있습니다.", "loopback으로 변경하세요."),
     finding("tools.exec.ask", "off", "always", "CRITICAL", "HITL",
             "실행 확인이 없고 AgentGuard도 없습니다.", "exec.ask를 always로 변경하고 AgentGuard를 활성화하세요.")],
    "CRITICAL",
    "외부 노출(0.0.0.0) + exec.ask=off + AgentGuard 미설정. 토큰 유출 시 외부에서 임의 명령 실행이 가능합니다."
))

# D10: exec.ask=off + AgentGuard disabled + wildcard allow
new_examples.append(make(
    {"config": {"gateway": {"bind": "loopback", "port": 18789, "auth": {"mode": "token", "token": "wildcard-allow-no-guard-token12"}},
                "tools": {"exec": {"ask": "off"}, "allow": ["*"]}},
     "agentguard": {"gateEnabled": False}},
    False, 30,
    [finding("tools.exec.ask", "off", "always", "CRITICAL", "HITL",
             "실행 확인이 없고 AgentGuard도 꺼져 있습니다.",
             "exec.ask를 always로 변경하거나 AgentGuard를 활성화하세요."),
     finding("tools.allow", "*", "specific tools only", "HIGH", "PERMISSIONS",
             "모든 도구가 와일드카드로 허용되어 있습니다.", "필요한 도구만 허용하세요."),
     finding("agentguard.gateEnabled", False, True, "HIGH", "EXECUTION",
             "AgentGuard가 비활성화되어 있습니다.", "gateEnabled를 true로 설정하세요.")],
    "CRITICAL",
    "exec.ask=off + AgentGuard 비활성화 + 와일드카드 도구 허용. 어떤 도구든 확인 없이 사용 가능합니다."
))

# D11: 0.0.0.0 + DM open
new_examples.append(make(
    {"config": {"gateway": {"bind": "0.0.0.0", "port": 18789, "auth": {"mode": "token", "token": "dm-open-exposed-token-12345678"}},
                "tools": {"exec": {"ask": "always"}, "allow": ["read", "write"]},
                "channels": {"discord": {"enabled": True, "dmPolicy": "open"}, "telegram": {"enabled": True, "dmPolicy": "open"}}}},
    False, 45,
    [finding("gateway.bind", "0.0.0.0", "loopback", "HIGH", "NETWORK",
             "외부 노출되어 있습니다.", "loopback으로 변경하세요."),
     finding("channels.*.dmPolicy", "open", "pairing", "HIGH", "ACCESS",
             "모든 채널 DM이 open으로 누구나 메시지 가능합니다.", "pairing 또는 allowlist로 변경하세요.")],
    "HIGH",
    "외부 노출(0.0.0.0) + 모든 채널 DM open. 외부에서 에이전트에 접근하고 메시지를 보낼 수 있습니다."
))

# D12: gateEnabled=false + gateFailOpen=true + llmMode=enforce (gate off nullifies enforce)
new_examples.append(make(
    {"config": {"gateway": {"bind": "loopback", "port": 18789, "auth": {"mode": "token", "token": "gate-disabled-failopen-token123"}},
                "tools": {"exec": {"ask": "off"}, "allow": ["read", "write", "exec"]}},
     "agentguard": {"gateEnabled": False, "gateFailOpen": True, "llmMode": "enforce"}},
    False, 40,
    [finding("tools.exec.ask", "off", "always", "CRITICAL", "HITL",
             "exec.ask=off이고 AgentGuard 게이트가 비활성화되어 보완 수단이 없습니다. llmMode=enforce 설정은 gateEnabled=false라 적용되지 않습니다.",
             "AgentGuard를 활성화하거나 exec.ask를 always로 변경하세요."),
     finding("agentguard.gateEnabled", False, True, "HIGH", "EXECUTION",
             "AgentGuard가 비활성화되어 llmMode 설정이 무의미합니다.", "gateEnabled를 true로 설정하세요.")],
    "CRITICAL",
    "exec.ask=off + AgentGuard 비활성화(gateEnabled=false). llmMode=enforce가 설정되어 있지만 게이트가 꺼져 있어 적용되지 않습니다."
))

# D13: auth=none + 0.0.0.0 + AgentGuard enforce
new_examples.append(make(
    {"config": {"gateway": {"bind": "0.0.0.0", "port": 18789, "auth": {"mode": "none"}},
                "tools": {"exec": {"ask": "always"}, "allow": ["read"]}},
     "agentguard": {"gateEnabled": True, "gateFailOpen": False, "llmMode": "enforce"}},
    False, 20,
    [finding("gateway.bind", "0.0.0.0", "loopback", "CRITICAL", "NETWORK",
             "외부 노출되어 있습니다.", "loopback으로 변경하세요."),
     finding("gateway.auth.mode", "none", "token", "CRITICAL", "AUTH",
             "인증이 없어 외부에서 누구나 접근 가능합니다.", "token 인증을 활성화하세요.")],
    "CRITICAL",
    "외부 노출(0.0.0.0) + 인증 없음(none). AgentGuard가 있어도 극도로 위험합니다."
))

# D14: wildcard exec-approvals + AgentGuard enforce (wildcard still dangerous)
new_examples.append(make(
    {"config": {"gateway": {"bind": "loopback", "port": 18789, "auth": {"mode": "token", "token": "wildcard-with-guard-token-abc12"}},
                "tools": {"exec": {"ask": "off"}, "allow": ["read", "write", "exec"]}},
     "config_files": {"exec-approvals": {"defaults": {"security": "full", "ask": "off", "askFallback": "deny"},
                                          "agents": {"main": {"allowlist": [{"pattern": "*"}], "ask": "off", "security": "full"}}}},
     "agentguard": {"gateEnabled": True, "gateFailOpen": False, "llmMode": "enforce"}},
    False, 50,
    [finding("exec-approvals.agents.main.allowlist", "*", "specific commands", "CRITICAL", "EXECUTION",
             "exec-approvals 와일드카드(*)가 모든 명령을 자동 승인합니다. AgentGuard가 있어도 와일드카드는 위험합니다.",
             "와일드카드를 제거하고 필요한 명령만 허용하세요.")],
    "CRITICAL",
    "exec-approvals에 와일드카드가 설정되어 모든 시스템 명령이 자동 승인됩니다. AgentGuard enforce가 있지만 와일드카드 자체가 CRITICAL입니다."
))

# D15: weak token + exec.ask=off + no AgentGuard
new_examples.append(make(
    {"config": {"gateway": {"bind": "loopback", "port": 18789, "auth": {"mode": "token", "token": "abc"}},
                "tools": {"exec": {"ask": "off"}, "allow": ["read", "write", "exec"]}},
     "agentguard": {"gateEnabled": False}},
    False, 35,
    [finding("gateway.auth.token", "abc", "32+ character random token", "HIGH", "AUTH",
             "토큰이 3자로 브루트포스에 취약합니다.", "최소 32자 이상의 랜덤 토큰을 사용하세요."),
     finding("tools.exec.ask", "off", "always", "CRITICAL", "HITL",
             "실행 확인이 없고 AgentGuard도 없습니다.", "exec.ask를 always로 변경하거나 AgentGuard를 활성화하세요."),
     finding("agentguard.gateEnabled", False, True, "HIGH", "EXECUTION",
             "AgentGuard가 비활성화되어 있습니다.", "gateEnabled를 true로 설정하세요.")],
    "CRITICAL",
    "약한 토큰(3자) + exec.ask=off + AgentGuard 비활성화. 다층적 보안 결함이 있습니다."
))

# Write
output_path = V10_DIR / "config_diagnosis_v10_new.jsonl"
with open(output_path, "w") as f:
    for ex in new_examples:
        f.write(json.dumps(ex, ensure_ascii=False) + "\n")

safe_count = sum(1 for e in new_examples if json.loads(e["messages"][2]["content"])["config_safe"])
print(f"Generated {len(new_examples)} new examples (safe: {safe_count}, dangerous: {len(new_examples) - safe_count})")
print(f"Saved to: {output_path}")
