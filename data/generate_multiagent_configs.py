"""
Generate training data for multi-agent Config Diagnosis.
Covers: OpenClaw, Claude Code, AutoGPT, CrewAI, LangGraph, Cursor, Cline, AgentGuard
Each example: system prompt + config input → JSON diagnosis output
"""

import json
import random
import pathlib

SYSTEM_PROMPT_PATH = pathlib.Path(__file__).parent.parent / "prompts" / "system_prompt_v4.txt"
OUTPUT_DIR = pathlib.Path(__file__).parent / "batches"

SYSTEM_PROMPT = SYSTEM_PROMPT_PATH.read_text()

def make_example(config_text: str, response: dict) -> dict:
    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"## Config\n\n```json\n{config_text}\n```"},
            {"role": "assistant", "content": json.dumps(response, ensure_ascii=False)},
        ]
    }


# ============================================================
# OpenClaw configs
# ============================================================
def generate_openclaw_configs():
    examples = []

    # --- DANGEROUS: sandbox off + full profile + no auth ---
    examples.append(make_example(
        json.dumps({
            "gateway": {"auth": {"mode": "none"}, "bind": "0.0.0.0"},
            "tools": {"profile": "full", "sandbox": {"mode": "off"}, "exec": {"ask": "never"}},
            "channels": {"telegram": {"dmPolicy": "open"}},
        }, indent=2),
        {
            "agent_type": "openclaw",
            "config_safe": False,
            "security_score": 0,
            "findings": [
                {"field": "gateway.auth.mode", "current_value": "none", "expected_value": "token 또는 mTLS", "severity": "CRITICAL", "category": "AUTH", "description": "인증이 완전히 비활성화되어 있어 누구나 게이트웨이에 접근할 수 있습니다.", "remediation": "gateway.auth.mode를 'token' 또는 'mTLS'로 설정하고, 강력한 인증 토큰을 구성하세요."},
                {"field": "gateway.bind", "current_value": "0.0.0.0", "expected_value": "127.0.0.1", "severity": "HIGH", "category": "NETWORK", "description": "모든 네트워크 인터페이스에 바인딩되어 외부에서 직접 접근이 가능합니다.", "remediation": "gateway.bind를 '127.0.0.1'로 변경하여 로컬 접근만 허용하세요."},
                {"field": "tools.profile", "current_value": "full", "expected_value": "minimal 또는 messaging", "severity": "HIGH", "category": "PERMISSIONS", "description": "에이전트가 모든 도구에 접근할 수 있어 공격 표면이 넓습니다.", "remediation": "tools.profile을 'minimal'로 설정하고 필요한 도구만 개별 허용하세요."},
                {"field": "tools.sandbox.mode", "current_value": "off", "expected_value": "all 또는 session", "severity": "CRITICAL", "category": "SANDBOX", "description": "샌드박스가 비활성화되어 에이전트가 호스트에서 직접 실행됩니다.", "remediation": "tools.sandbox.mode를 'all'로 설정하여 모든 세션을 Docker 컨테이너에서 격리하세요."},
                {"field": "tools.exec.ask", "current_value": "never", "expected_value": "always", "severity": "CRITICAL", "category": "HITL", "description": "명령 실행 시 사용자 확인을 요청하지 않아 위험한 명령이 자동 실행됩니다.", "remediation": "tools.exec.ask를 'always'로 설정하여 모든 실행 전 승인을 받으세요."},
                {"field": "channels.telegram.dmPolicy", "current_value": "open", "expected_value": "allowlist", "severity": "HIGH", "category": "AUTH", "description": "누구나 텔레그램을 통해 에이전트에 메시지를 보낼 수 있습니다.", "remediation": "dmPolicy를 'allowlist'로 변경하고 allowFrom에 허가된 사용자 ID만 등록하세요."},
            ],
            "overall_severity": "CRITICAL",
            "reasoning": "인증 미설정, 샌드박스 비활성화, 전체 도구 접근, 실행 확인 없음 등 모든 핵심 보안 설정이 위험한 상태입니다. 즉시 전면적인 보안 강화가 필요합니다."
        }
    ))

    # --- SAFE: well-configured OpenClaw ---
    examples.append(make_example(
        json.dumps({
            "gateway": {"auth": {"mode": "token", "token": "sk-oc-a8f3b2c1d9e7f4a5b6c8d0e1f2a3b4c5"}, "bind": "127.0.0.1"},
            "tools": {"profile": "minimal", "sandbox": {"mode": "all", "docker": {"network": "none"}}, "exec": {"ask": "always"}},
            "channels": {"telegram": {"dmPolicy": "allowlist", "allowFrom": ["123456789"]}},
        }, indent=2),
        {
            "agent_type": "openclaw",
            "config_safe": True,
            "security_score": 100,
            "findings": [],
            "overall_severity": "NONE",
            "reasoning": "토큰 인증, 로컬 바인딩, 최소 도구 프로필, 전체 샌드박스 격리, 네트워크 차단, 실행 확인 등 모든 보안 설정이 올바르게 구성되어 있습니다."
        }
    ))

    # --- PARTIAL: sandbox on but auth weak ---
    examples.append(make_example(
        json.dumps({
            "gateway": {"auth": {"mode": "token", "token": "admin123"}, "bind": "127.0.0.1"},
            "tools": {"profile": "minimal", "sandbox": {"mode": "all"}, "exec": {"ask": "always"}},
        }, indent=2),
        {
            "agent_type": "openclaw",
            "config_safe": False,
            "security_score": 85,
            "findings": [
                {"field": "gateway.auth.token", "current_value": "admin123", "expected_value": "32자 이상의 랜덤 문자열", "severity": "HIGH", "category": "AUTH", "description": "인증 토큰이 너무 짧고 추측 가능합니다. 무차별 대입 공격에 취약합니다.", "remediation": "openssl rand -hex 32 등으로 생성한 32자 이상의 랜덤 토큰으로 교체하세요."},
            ],
            "overall_severity": "HIGH",
            "reasoning": "대부분의 보안 설정은 잘 구성되어 있으나, 인증 토큰이 짧고 추측 가능하여 보안 위험이 존재합니다."
        }
    ))

    # --- DANGEROUS: sandbox non-main + full profile ---
    examples.append(make_example(
        json.dumps({
            "gateway": {"auth": {"mode": "token", "token": "sk-oc-x9y8z7w6v5u4t3s2r1q0p9o8n7m6l5k4"}, "bind": "127.0.0.1"},
            "tools": {"profile": "full", "sandbox": {"mode": "non-main", "docker": {"network": "bridge"}}, "exec": {"ask": "off"}},
        }, indent=2),
        {
            "agent_type": "openclaw",
            "config_safe": False,
            "security_score": 30,
            "findings": [
                {"field": "tools.profile", "current_value": "full", "expected_value": "minimal 또는 messaging", "severity": "HIGH", "category": "PERMISSIONS", "description": "에이전트가 모든 도구에 접근할 수 있어 불필요한 공격 표면이 노출됩니다.", "remediation": "tools.profile을 'minimal'로 설정하세요."},
                {"field": "tools.sandbox.mode", "current_value": "non-main", "expected_value": "all 또는 session", "severity": "HIGH", "category": "SANDBOX", "description": "메인 DM은 호스트에서 직접 실행되어 격리가 불완전합니다.", "remediation": "sandbox.mode를 'all'로 변경하여 모든 세션을 격리하세요."},
                {"field": "tools.sandbox.docker.network", "current_value": "bridge", "expected_value": "none", "severity": "HIGH", "category": "NETWORK", "description": "샌드박스 컨테이너가 네트워크에 접근할 수 있어 데이터 유출 위험이 있습니다.", "remediation": "docker.network를 'none'으로 설정하여 네트워크를 완전히 차단하세요."},
                {"field": "tools.exec.ask", "current_value": "off", "expected_value": "always", "severity": "CRITICAL", "category": "HITL", "description": "명령 실행 시 사용자 승인 없이 자동 실행됩니다.", "remediation": "tools.exec.ask를 'always'로 설정하세요."},
            ],
            "overall_severity": "CRITICAL",
            "reasoning": "실행 확인이 비활성화되고, 도구 프로필이 전체 접근이며, 샌드박스 격리가 불완전합니다. 특히 exec.ask 비활성화는 즉시 수정이 필요합니다."
        }
    ))

    # --- OpenClaw with wildcard exec-approvals ---
    examples.append(make_example(
        json.dumps({
            "gateway": {"auth": {"mode": "token", "token": "sk-oc-valid32chartoken1234567890abcd"}, "bind": "127.0.0.1"},
            "tools": {"profile": "messaging", "sandbox": {"mode": "all"}, "exec": {"ask": "always"}},
            "exec-approvals": [{"pattern": "*", "auto": True}],
        }, indent=2),
        {
            "agent_type": "openclaw",
            "config_safe": False,
            "security_score": 60,
            "findings": [
                {"field": "exec-approvals[0].pattern", "current_value": "*", "expected_value": "구체적인 명령 패턴", "severity": "CRITICAL", "category": "EXECUTION", "description": "와일드카드 실행 승인 패턴으로 모든 명령이 자동 승인됩니다. exec.ask가 always여도 이 설정이 우회합니다.", "remediation": "exec-approvals에서 와일드카드를 제거하고 허용할 명령만 구체적으로 지정하세요. 예: {\"pattern\": \"git status\"}"},
            ],
            "overall_severity": "CRITICAL",
            "reasoning": "대부분 잘 구성되어 있으나, exec-approvals의 와일드카드 패턴이 실행 확인 메커니즘을 완전히 무력화합니다."
        }
    ))

    return examples


# ============================================================
# Claude Code configs
# ============================================================
def generate_claude_code_configs():
    examples = []

    # --- DANGEROUS: no deny rules, bypass enabled ---
    examples.append(make_example(
        json.dumps({
            "permissions": {
                "allow": ["Bash", "Read", "Write", "Edit", "Glob", "Grep", "WebSearch", "WebFetch"],
                "deny": [],
                "ask": []
            },
            "mcpServers": {
                "filesystem": {"command": "npx", "args": ["@modelcontextprotocol/server-filesystem", "/"]},
                "unknown-server": {"command": "npx", "args": ["some-unknown-mcp-server"]}
            }
        }, indent=2),
        {
            "agent_type": "claude_code",
            "config_safe": False,
            "security_score": 20,
            "findings": [
                {"field": "permissions.deny", "current_value": "[]", "expected_value": "민감 패턴 포함 (예: .env, sudo, curl, wget)", "severity": "HIGH", "category": "PERMISSIONS", "description": "deny 규칙이 비어있어 민감한 파일 접근이나 위험한 명령을 차단하지 못합니다.", "remediation": "permissions.deny에 ['Read(**/.env)', 'Bash(sudo:*)', 'Bash(curl:*)', 'Bash(wget:*)', 'Read(**/.ssh/*)']를 추가하세요."},
                {"field": "permissions.disableBypassPermissionsMode", "current_value": "missing", "expected_value": "disable", "severity": "CRITICAL", "category": "PERMISSIONS", "description": "우회 권한 모드를 비활성화하는 설정이 없어 보안 규칙을 우회할 수 있습니다.", "remediation": "permissions.disableBypassPermissionsMode를 'disable'로 설정하세요."},
                {"field": "mcpServers.filesystem.args", "current_value": "[\"/\"]", "expected_value": "프로젝트 디렉토리만", "severity": "CRITICAL", "category": "SANDBOX", "description": "MCP 파일시스템 서버가 루트(/) 전체에 접근할 수 있어 모든 시스템 파일이 노출됩니다.", "remediation": "파일시스템 서버의 경로를 프로젝트 디렉토리로 제한하세요. 예: /Users/user/project"},
                {"field": "mcpServers.unknown-server", "current_value": "some-unknown-mcp-server", "expected_value": "검증된 MCP 서버만 사용", "severity": "HIGH", "category": "SANDBOX", "description": "검증되지 않은 MCP 서버가 등록되어 있습니다. 악성 도구가 포함될 수 있습니다.", "remediation": "알 수 없는 MCP 서버를 제거하거나, npm 페이지에서 신뢰성을 확인한 후 사용하세요."},
            ],
            "overall_severity": "CRITICAL",
            "reasoning": "deny 규칙 없음, 우회 모드 비활성화 미설정, 루트 파일시스템 노출, 미검증 MCP 서버 등 다수의 심각한 보안 문제가 존재합니다."
        }
    ))

    # --- SAFE: well-configured Claude Code ---
    examples.append(make_example(
        json.dumps({
            "permissions": {
                "allow": ["Read", "Glob", "Grep", "WebSearch"],
                "deny": ["Read(**/.env)", "Read(**/.ssh/*)", "Read(**/.aws/*)", "Bash(sudo:*)", "Bash(curl:*)", "Bash(wget:*)", "Bash(rm -rf:*)"],
                "ask": ["Bash(git push:*)", "Write", "Edit"],
                "disableBypassPermissionsMode": "disable"
            },
            "mcpServers": {
                "filesystem": {"command": "npx", "args": ["@modelcontextprotocol/server-filesystem", "/Users/user/project"]}
            }
        }, indent=2),
        {
            "agent_type": "claude_code",
            "config_safe": True,
            "security_score": 100,
            "findings": [],
            "overall_severity": "NONE",
            "reasoning": "deny 규칙에 민감 파일과 위험 명령이 포함되어 있고, 우회 모드가 비활성화되어 있으며, 쓰기/편집은 확인을 거치고, MCP 서버도 프로젝트 범위로 제한되어 있습니다."
        }
    ))

    # --- PARTIAL: good deny but broad allow ---
    examples.append(make_example(
        json.dumps({
            "permissions": {
                "allow": ["Bash", "Read", "Write", "Edit", "Glob", "Grep"],
                "deny": ["Read(**/.env)", "Bash(sudo:*)"],
                "ask": [],
                "disableBypassPermissionsMode": "disable"
            }
        }, indent=2),
        {
            "agent_type": "claude_code",
            "config_safe": False,
            "security_score": 70,
            "findings": [
                {"field": "permissions.allow", "current_value": "Bash, Write, Edit 무조건 허용", "expected_value": "Write와 Edit는 ask로 이동", "severity": "HIGH", "category": "PERMISSIONS", "description": "Bash, Write, Edit가 확인 없이 자동 허용되어 파일 수정과 명령 실행이 무제한입니다.", "remediation": "Write와 Edit를 ask 목록으로 이동하고, Bash도 ask로 이동하거나 구체적인 패턴만 allow하세요."},
                {"field": "permissions.deny", "current_value": ".env, sudo만 차단", "expected_value": ".ssh, .aws, curl, wget, rm -rf 등 추가", "severity": "MEDIUM", "category": "PERMISSIONS", "description": "deny 목록이 불충분합니다. SSH 키, AWS 자격증명, 네트워크 명령 등이 차단되지 않습니다.", "remediation": "deny에 Read(**/.ssh/*), Read(**/.aws/*), Bash(curl:*), Bash(wget:*) 등을 추가하세요."},
            ],
            "overall_severity": "HIGH",
            "reasoning": "기본적인 보안 설정은 있으나, allow 범위가 너무 넓고 deny 목록이 불충분하여 보안 사각지대가 존재합니다."
        }
    ))

    return examples


# ============================================================
# AutoGPT configs
# ============================================================
def generate_autogpt_configs():
    examples = []

    # --- DANGEROUS: local commands + denylist + no workspace restriction ---
    examples.append(make_example(
        json.dumps({
            "EXECUTE_LOCAL_COMMANDS": True,
            "SHELL_COMMAND_CONTROL": "denylist",
            "SHELL_DENYLIST": "sudo,su",
            "SHELL_ALLOWLIST": "",
            "RESTRICT_TO_WORKSPACE": False,
            "CONTINUOUS_MODE": True,
            "DISABLED_COMMAND_CATEGORIES": []
        }, indent=2),
        {
            "agent_type": "autogpt",
            "config_safe": False,
            "security_score": 0,
            "findings": [
                {"field": "EXECUTE_LOCAL_COMMANDS", "current_value": "True", "expected_value": "False", "severity": "CRITICAL", "category": "EXECUTION", "description": "로컬 명령 실행이 활성화되어 에이전트가 시스템 명령을 실행할 수 있습니다.", "remediation": "EXECUTE_LOCAL_COMMANDS를 False로 설정하거나, Docker 환경에서만 True로 사용하세요."},
                {"field": "SHELL_COMMAND_CONTROL", "current_value": "denylist", "expected_value": "allowlist", "severity": "HIGH", "category": "PERMISSIONS", "description": "denylist 모드는 CVE-2024-6091로 인해 경로 조작으로 우회 가능합니다.", "remediation": "SHELL_COMMAND_CONTROL을 'allowlist'로 변경하고 필요한 명령만 SHELL_ALLOWLIST에 지정하세요."},
                {"field": "RESTRICT_TO_WORKSPACE", "current_value": "False", "expected_value": "True", "severity": "CRITICAL", "category": "SANDBOX", "description": "작업 공간 제한이 해제되어 에이전트가 파일시스템 전체에 접근할 수 있습니다.", "remediation": "RESTRICT_TO_WORKSPACE를 True로 설정하세요."},
                {"field": "CONTINUOUS_MODE", "current_value": "True", "expected_value": "False", "severity": "HIGH", "category": "HITL", "description": "연속 모드가 활성화되어 사용자 승인 없이 모든 작업이 자동 실행됩니다.", "remediation": "CONTINUOUS_MODE를 False로 설정하여 각 작업마다 사용자 승인을 받으세요."},
                {"field": "DISABLED_COMMAND_CATEGORIES", "current_value": "[]", "expected_value": "불필요한 카테고리 비활성화", "severity": "MEDIUM", "category": "PERMISSIONS", "description": "모든 명령 카테고리가 활성화되어 있습니다. 불필요한 기능이 공격에 악용될 수 있습니다.", "remediation": "사용하지 않는 카테고리를 비활성화하세요. 예: autogpt.commands.execute_code, autogpt.commands.git_operations"},
            ],
            "overall_severity": "CRITICAL",
            "reasoning": "로컬 명령 실행, 우회 가능한 denylist, 작업 공간 제한 해제, 연속 모드 등 모든 주요 보안 설정이 위험한 상태입니다. Docker 없이 이 설정을 사용하면 시스템이 완전히 노출됩니다."
        }
    ))

    # --- SAFE: AutoGPT ---
    examples.append(make_example(
        json.dumps({
            "EXECUTE_LOCAL_COMMANDS": False,
            "SHELL_COMMAND_CONTROL": "allowlist",
            "SHELL_ALLOWLIST": "cat,echo,ls,pwd",
            "RESTRICT_TO_WORKSPACE": True,
            "CONTINUOUS_MODE": False,
            "DISABLED_COMMAND_CATEGORIES": ["autogpt.commands.execute_code", "autogpt.commands.git_operations"]
        }, indent=2),
        {
            "agent_type": "autogpt",
            "config_safe": True,
            "security_score": 95,
            "findings": [],
            "overall_severity": "NONE",
            "reasoning": "로컬 명령 실행 비활성화, allowlist 기반 명령 제어, 작업 공간 제한, 연속 모드 비활성화, 불필요한 카테고리 비활성화 등 보안 설정이 잘 구성되어 있습니다."
        }
    ))

    # --- PARTIAL: denylist but Docker + workspace restricted ---
    examples.append(make_example(
        json.dumps({
            "EXECUTE_LOCAL_COMMANDS": True,
            "SHELL_COMMAND_CONTROL": "denylist",
            "SHELL_DENYLIST": "sudo,su,rm,chmod,chown,shutdown,reboot",
            "RESTRICT_TO_WORKSPACE": True,
            "CONTINUOUS_MODE": False,
            "DOCKER_ENABLED": True
        }, indent=2),
        {
            "agent_type": "autogpt",
            "config_safe": False,
            "security_score": 55,
            "findings": [
                {"field": "SHELL_COMMAND_CONTROL", "current_value": "denylist", "expected_value": "allowlist", "severity": "HIGH", "category": "PERMISSIONS", "description": "denylist 모드는 경로 조작(/bin/./cmd)이나 명령 체이닝(echo;cmd)으로 우회 가능합니다 (CVE-2024-6091).", "remediation": "SHELL_COMMAND_CONTROL을 'allowlist'로 변경하세요. denylist는 근본적으로 안전하지 않습니다."},
                {"field": "EXECUTE_LOCAL_COMMANDS", "current_value": "True", "expected_value": "False (Docker 없이는 위험)", "severity": "MEDIUM", "category": "EXECUTION", "description": "Docker가 활성화되어 있어 위험은 줄지만, denylist 우회와 결합되면 컨테이너 내에서도 위험할 수 있습니다.", "remediation": "가능하면 False로 설정하거나, allowlist와 함께 사용하세요."},
            ],
            "overall_severity": "HIGH",
            "reasoning": "Docker와 작업 공간 제한으로 기본적인 격리는 있지만, denylist 방식이 근본적으로 우회 가능하여 보안 위험이 존재합니다."
        }
    ))

    return examples


# ============================================================
# CrewAI configs
# ============================================================
def generate_crewai_configs():
    examples = []

    # --- DANGEROUS: unsafe code execution + delegation ---
    examples.append(make_example(
        json.dumps({
            "agents": [
                {
                    "role": "Developer",
                    "goal": "Write and execute code",
                    "allow_code_execution": True,
                    "code_execution_mode": "unsafe",
                    "allow_delegation": True,
                    "max_iter": 100,
                    "max_execution_time": None,
                    "max_rpm": None
                }
            ],
            "process": "hierarchical",
            "manager_llm": "gpt-4"
        }, indent=2),
        {
            "agent_type": "crewai",
            "config_safe": False,
            "security_score": 5,
            "findings": [
                {"field": "agents[0].code_execution_mode", "current_value": "unsafe", "expected_value": "safe", "severity": "CRITICAL", "category": "SANDBOX", "description": "코드가 호스트에서 직접 실행됩니다. Docker 샌드박스 없이 임의 코드 실행이 가능합니다.", "remediation": "code_execution_mode를 'safe'로 변경하여 Docker 샌드박스에서 실행되도록 하세요."},
                {"field": "agents[0].allow_code_execution", "current_value": "True", "expected_value": "False (sandbox 없이는 위험)", "severity": "CRITICAL", "category": "EXECUTION", "description": "unsafe 모드와 결합되어 에이전트가 호스트에서 임의 코드를 실행할 수 있습니다.", "remediation": "code_execution_mode를 'safe'로 먼저 변경하거나, 코드 실행이 불필요하면 False로 설정하세요."},
                {"field": "agents[0].allow_delegation", "current_value": "True", "expected_value": "False", "severity": "HIGH", "category": "PERMISSIONS", "description": "위임이 허용되어 프롬프트 인젝션된 에이전트가 코드 실행 에이전트에게 위험한 작업을 위임할 수 있습니다.", "remediation": "allow_delegation을 False로 설정하거나, 위임 대상 에이전트의 권한을 최소화하세요."},
                {"field": "agents[0].max_iter", "current_value": "100", "expected_value": "25 이하", "severity": "MEDIUM", "category": "EXECUTION", "description": "반복 횟수가 과도하게 높아 비용 폭발이나 무한 루프 위험이 있습니다.", "remediation": "max_iter를 20-25로 제한하세요."},
                {"field": "agents[0].max_execution_time", "current_value": "null", "expected_value": "300 (5분)", "severity": "MEDIUM", "category": "EXECUTION", "description": "실행 시간 제한이 없어 에이전트가 무한히 실행될 수 있습니다.", "remediation": "max_execution_time을 300(초)으로 설정하세요."},
                {"field": "agents[0].max_rpm", "current_value": "null", "expected_value": "60 이하", "severity": "MEDIUM", "category": "EXECUTION", "description": "API 호출 속도 제한이 없어 비용이 통제 불능으로 증가할 수 있습니다.", "remediation": "max_rpm을 30-60으로 설정하세요."},
            ],
            "overall_severity": "CRITICAL",
            "reasoning": "호스트에서 직접 코드 실행, 위임 허용, 반복/시간/비용 제한 없음 등 에이전트가 사실상 무제한 권한을 갖고 있습니다. 프롬프트 인젝션 시 심각한 피해가 발생할 수 있습니다."
        }
    ))

    # --- SAFE: CrewAI ---
    examples.append(make_example(
        json.dumps({
            "agents": [
                {
                    "role": "Researcher",
                    "goal": "Research and analyze data",
                    "allow_code_execution": False,
                    "allow_delegation": False,
                    "max_iter": 20,
                    "max_execution_time": 300,
                    "max_rpm": 30
                }
            ],
            "process": "sequential"
        }, indent=2),
        {
            "agent_type": "crewai",
            "config_safe": True,
            "security_score": 100,
            "findings": [],
            "overall_severity": "NONE",
            "reasoning": "코드 실행 비활성화, 위임 비활성화, 적절한 반복/시간/비용 제한이 설정되어 있습니다. 안전한 구성입니다."
        }
    ))

    # --- PARTIAL: code execution safe mode but delegation ---
    examples.append(make_example(
        json.dumps({
            "agents": [
                {
                    "role": "Developer",
                    "goal": "Write code",
                    "allow_code_execution": True,
                    "code_execution_mode": "safe",
                    "allow_delegation": True,
                    "max_iter": 20,
                    "max_execution_time": 300,
                    "max_rpm": 60
                }
            ],
            "process": "sequential"
        }, indent=2),
        {
            "agent_type": "crewai",
            "config_safe": False,
            "security_score": 77,
            "findings": [
                {"field": "agents[0].allow_delegation", "current_value": "True", "expected_value": "False", "severity": "HIGH", "category": "PERMISSIONS", "description": "코드 실행 권한이 있는 에이전트에 위임이 허용되면, 다른 에이전트가 이 에이전트를 통해 코드를 실행할 수 있습니다.", "remediation": "allow_delegation을 False로 설정하거나, 코드 실행 에이전트와 위임 에이전트를 분리하세요."},
            ],
            "overall_severity": "HIGH",
            "reasoning": "Docker 샌드박스로 코드를 안전하게 실행하지만, 위임 허용으로 인해 다른 에이전트를 통한 간접 공격이 가능합니다."
        }
    ))

    return examples


# ============================================================
# LangGraph configs
# ============================================================
def generate_langgraph_configs():
    examples = []

    # --- DANGEROUS: no auth, no interrupt, no recursion limit ---
    examples.append(make_example(
        json.dumps({
            "dependencies": ["."],
            "graphs": {"agent": "./src/agent/graph.py:graph"},
            "env": ".env",
            "cors": {"allow_origins": ["*"], "allow_methods": ["*"]},
            "disable_studio_auth": True
        }, indent=2),
        {
            "agent_type": "langgraph",
            "config_safe": False,
            "security_score": 15,
            "findings": [
                {"field": "auth", "current_value": "missing", "expected_value": "auth 핸들러 구성", "severity": "CRITICAL", "category": "AUTH", "description": "인증 설정이 없어 누구나 API에 접근할 수 있습니다.", "remediation": "langgraph.json에 auth 섹션을 추가하고 인증 핸들러를 구현하세요. 예: {\"auth\": {\"path\": \"src/auth.py:auth\"}}"},
                {"field": "cors.allow_origins", "current_value": "[\"*\"]", "expected_value": "특정 도메인만 허용", "severity": "HIGH", "category": "NETWORK", "description": "모든 출처에서의 CORS 요청이 허용되어 CSRF 공격에 취약합니다.", "remediation": "allow_origins를 실제 프론트엔드 도메인만 포함하도록 제한하세요."},
                {"field": "disable_studio_auth", "current_value": "True", "expected_value": "False", "severity": "CRITICAL", "category": "AUTH", "description": "Studio 인증이 비활성화되어 LangGraph Studio에서 무인증 접근이 가능합니다.", "remediation": "프로덕션에서는 반드시 disable_studio_auth를 false로 설정하세요."},
            ],
            "overall_severity": "CRITICAL",
            "reasoning": "인증 미설정, CORS 전체 허용, Studio 인증 비활성화로 API가 완전히 노출되어 있습니다. 프로덕션에서 사용하면 안 되는 설정입니다."
        }
    ))

    # --- SAFE: LangGraph ---
    examples.append(make_example(
        json.dumps({
            "dependencies": ["."],
            "graphs": {"agent": "./src/agent/graph.py:graph"},
            "env": ".env",
            "auth": {"path": "src/security/auth.py:auth"},
            "cors": {"allow_origins": ["https://app.example.com"], "allow_methods": ["GET", "POST"]},
            "disable_studio_auth": False
        }, indent=2),
        {
            "agent_type": "langgraph",
            "config_safe": True,
            "security_score": 95,
            "findings": [],
            "overall_severity": "NONE",
            "reasoning": "인증 핸들러 구성, CORS 도메인 제한, Studio 인증 활성화 등 기본적인 보안 설정이 잘 되어 있습니다."
        }
    ))

    return examples


# ============================================================
# Cursor configs
# ============================================================
def generate_cursor_configs():
    examples = []

    # --- DANGEROUS: allow-all network + broad filesystem ---
    examples.append(make_example(
        json.dumps({
            "networkPolicy": {"default": "allow"},
            "filesystem": {"allowWrite": ["/", "/etc", "/Users"]},
            "cursorignore": []
        }, indent=2),
        {
            "agent_type": "cursor",
            "config_safe": False,
            "security_score": 10,
            "findings": [
                {"field": "networkPolicy.default", "current_value": "allow", "expected_value": "deny", "severity": "HIGH", "category": "NETWORK", "description": "기본 네트워크 정책이 모든 접근을 허용하여 데이터 유출 위험이 있습니다.", "remediation": "networkPolicy.default를 'deny'로 설정하고 필요한 도메인만 allow 목록에 추가하세요."},
                {"field": "filesystem.allowWrite", "current_value": "[\"/\", \"/etc\", \"/Users\"]", "expected_value": "프로젝트 디렉토리만", "severity": "CRITICAL", "category": "SANDBOX", "description": "루트 디렉토리와 시스템 디렉토리에 쓰기 권한이 있어 시스템 파일 변조가 가능합니다.", "remediation": "allowWrite를 프로젝트 디렉토리만으로 제한하세요. 예: [\"/Users/user/project\"]"},
                {"field": "cursorignore", "current_value": "[]", "expected_value": ".env, .ssh, .aws 등 포함", "severity": "HIGH", "category": "CREDENTIALS", "description": ".cursorignore가 비어있어 민감한 파일이 AI에 노출될 수 있습니다.", "remediation": ".cursorignore에 .env, .ssh/, .aws/, *.pem, *.key 등 민감한 패턴을 추가하세요."},
            ],
            "overall_severity": "CRITICAL",
            "reasoning": "네트워크 무제한, 파일시스템 전체 쓰기, 민감 파일 미보호로 에이전트가 시스템을 자유롭게 변경하고 데이터를 유출할 수 있습니다."
        }
    ))

    # --- SAFE: Cursor ---
    examples.append(make_example(
        json.dumps({
            "networkPolicy": {"default": "deny", "allow": ["api.github.com", "registry.npmjs.org"]},
            "filesystem": {"allowWrite": ["/Users/user/project"]},
            "cursorignore": [".env", ".env.*", ".ssh/", ".aws/", "*.pem", "*.key", "credentials.json"]
        }, indent=2),
        {
            "agent_type": "cursor",
            "config_safe": True,
            "security_score": 100,
            "findings": [],
            "overall_severity": "NONE",
            "reasoning": "네트워크 기본 차단 + 필요 도메인만 허용, 프로젝트 디렉토리만 쓰기 허용, 민감 파일 패턴 차단이 잘 구성되어 있습니다."
        }
    ))

    return examples


# ============================================================
# Cline configs
# ============================================================
def generate_cline_configs():
    examples = []

    # --- DANGEROUS: auto-approve all + no ignore ---
    examples.append(make_example(
        json.dumps({
            "CLINE_COMMAND_PERMISSIONS": "*",
            "clineignore": [],
            "autoApprove": {"readFiles": True, "editFiles": True, "executeCommands": True, "useBrowser": True},
            "strictPlanModeEnabled": False
        }, indent=2),
        {
            "agent_type": "cline",
            "config_safe": False,
            "security_score": 5,
            "findings": [
                {"field": "CLINE_COMMAND_PERMISSIONS", "current_value": "*", "expected_value": "구체적인 명령 목록", "severity": "HIGH", "category": "PERMISSIONS", "description": "모든 명령이 허용되어 위험한 시스템 명령도 실행 가능합니다.", "remediation": "허용할 명령을 구체적으로 지정하세요. 예: 'npm *', 'git *', 'ls', 'cat'"},
                {"field": "autoApprove.editFiles", "current_value": "True", "expected_value": "False", "severity": "CRITICAL", "category": "HITL", "description": "파일 수정이 자동 승인되어 중요한 파일이 사전 확인 없이 변경될 수 있습니다.", "remediation": "editFiles 자동 승인을 비활성화하여 파일 수정 전 확인을 받으세요."},
                {"field": "autoApprove.executeCommands", "current_value": "True", "expected_value": "False", "severity": "CRITICAL", "category": "HITL", "description": "명령 실행이 자동 승인되어 위험한 명령이 확인 없이 실행됩니다.", "remediation": "executeCommands 자동 승인을 비활성화하세요."},
                {"field": "clineignore", "current_value": "[]", "expected_value": ".env, .ssh, .aws 등 포함", "severity": "HIGH", "category": "CREDENTIALS", "description": ".clineignore가 비어있어 민감한 파일이 AI에 노출됩니다.", "remediation": ".clineignore에 .env, .ssh/, .aws/, *.pem, *.key 등을 추가하세요."},
                {"field": "strictPlanModeEnabled", "current_value": "False", "expected_value": "True", "severity": "MEDIUM", "category": "HITL", "description": "Plan 모드에서도 파일 수정이 가능하여 실수로 코드가 변경될 수 있습니다.", "remediation": "strictPlanModeEnabled를 True로 설정하세요."},
            ],
            "overall_severity": "CRITICAL",
            "reasoning": "모든 작업이 자동 승인되고 명령 제한이 없으며 민감 파일도 보호되지 않습니다. 에이전트가 사실상 무제한 권한을 갖고 있는 상태입니다."
        }
    ))

    # --- SAFE: Cline ---
    examples.append(make_example(
        json.dumps({
            "CLINE_COMMAND_PERMISSIONS": "npm *, git *, ls, cat, pwd, echo",
            "clineignore": [".env", ".env.*", ".ssh/", ".aws/", "*.pem", "*.key"],
            "autoApprove": {"readFiles": True, "editFiles": False, "executeCommands": False, "useBrowser": False},
            "strictPlanModeEnabled": True
        }, indent=2),
        {
            "agent_type": "cline",
            "config_safe": True,
            "security_score": 95,
            "findings": [],
            "overall_severity": "NONE",
            "reasoning": "명령 허용 목록이 구체적이고, 민감 파일이 보호되며, 파일 수정과 명령 실행 시 사용자 확인을 거칩니다. 안전한 구성입니다."
        }
    ))

    return examples


# ============================================================
# AgentGuard proxy configs
# ============================================================
def generate_agentguard_configs():
    examples = []

    # --- DANGEROUS: gate disabled + fail open ---
    examples.append(make_example(
        json.dumps({
            "agentguard": {
                "gateEnabled": False,
                "gateFailOpen": True,
                "gateMode": "monitor"
            },
            "mcp-policy": {
                "denied_tools": [],
                "denied_paths": [],
                "mode": "permissive"
            }
        }, indent=2),
        {
            "agent_type": "agentguard",
            "config_safe": False,
            "security_score": 0,
            "findings": [
                {"field": "agentguard.gateEnabled", "current_value": "False", "expected_value": "True", "severity": "CRITICAL", "category": "AUTH", "description": "보안 게이트가 비활성화되어 모든 요청이 검사 없이 통과합니다.", "remediation": "gateEnabled를 True로 설정하여 보안 게이트를 활성화하세요."},
                {"field": "agentguard.gateFailOpen", "current_value": "True", "expected_value": "False", "severity": "HIGH", "category": "AUTH", "description": "게이트 장애 시 모든 요청을 허용합니다. 의도적 장애 유발로 보안을 우회할 수 있습니다.", "remediation": "gateFailOpen을 False로 설정하여 장애 시 요청을 차단하세요."},
                {"field": "agentguard.gateMode", "current_value": "monitor", "expected_value": "enforce", "severity": "HIGH", "category": "AUTH", "description": "모니터 모드는 위험한 요청을 감지만 하고 차단하지 않습니다.", "remediation": "프로덕션에서는 gateMode를 'enforce'로 설정하세요."},
                {"field": "mcp-policy.denied_tools", "current_value": "[]", "expected_value": "위험 도구 패턴 포함", "severity": "HIGH", "category": "PERMISSIONS", "description": "차단된 도구가 없어 모든 MCP 도구가 사용 가능합니다.", "remediation": "denied_tools에 write_*, execute_*, delete_* 등 위험 패턴을 추가하세요."},
                {"field": "mcp-policy.denied_paths", "current_value": "[]", "expected_value": "민감 경로 포함", "severity": "HIGH", "category": "CREDENTIALS", "description": "차단된 경로가 없어 민감한 디렉토리에 접근 가능합니다.", "remediation": "denied_paths에 /etc/*, ~/.ssh/*, ~/.aws/*, ~/.gnupg/* 등을 추가하세요."},
                {"field": "mcp-policy.mode", "current_value": "permissive", "expected_value": "enforce", "severity": "HIGH", "category": "PERMISSIONS", "description": "permissive 모드는 정책 위반을 허용합니다.", "remediation": "mode를 'enforce'로 변경하세요."},
            ],
            "overall_severity": "CRITICAL",
            "reasoning": "보안 게이트 비활성화, fail-open, 모니터 모드, 빈 차단 목록 등 AgentGuard가 사실상 아무 보호 기능도 수행하지 않는 상태입니다."
        }
    ))

    # --- SAFE: AgentGuard ---
    examples.append(make_example(
        json.dumps({
            "agentguard": {
                "gateEnabled": True,
                "gateFailOpen": False,
                "gateMode": "enforce"
            },
            "mcp-policy": {
                "denied_tools": ["write_*", "execute_*", "delete_*", "admin_*"],
                "denied_paths": ["/etc/*", "~/.ssh/*", "~/.aws/*", "~/.gnupg/*", "**/.env"],
                "mode": "enforce"
            }
        }, indent=2),
        {
            "agent_type": "agentguard",
            "config_safe": True,
            "security_score": 100,
            "findings": [],
            "overall_severity": "NONE",
            "reasoning": "보안 게이트 활성화, fail-closed, enforce 모드, 위험 도구/경로 차단이 잘 구성되어 있습니다."
        }
    ))

    return examples


# ============================================================
# Mixed / edge case configs
# ============================================================
def generate_edge_cases():
    examples = []

    # --- Unknown agent type detection ---
    examples.append(make_example(
        json.dumps({
            "runtime": {"sandbox": False, "allow_network": True},
            "tools": {"enabled": ["shell", "file_write", "http_request"]},
            "auth": None,
            "max_steps": 1000
        }, indent=2),
        {
            "agent_type": "unknown",
            "config_safe": False,
            "security_score": 20,
            "findings": [
                {"field": "runtime.sandbox", "current_value": "False", "expected_value": "True", "severity": "CRITICAL", "category": "SANDBOX", "description": "샌드박스가 비활성화되어 에이전트가 호스트에서 직접 실행됩니다.", "remediation": "sandbox를 True로 설정하거나 Docker/VM 기반 격리를 구성하세요."},
                {"field": "auth", "current_value": "null", "expected_value": "인증 설정 필요", "severity": "CRITICAL", "category": "AUTH", "description": "인증이 설정되지 않아 무인증 접근이 가능합니다.", "remediation": "토큰 기반 또는 mTLS 인증을 구성하세요."},
                {"field": "tools.enabled", "current_value": "shell, file_write, http_request", "expected_value": "최소 권한 원칙 적용", "severity": "HIGH", "category": "PERMISSIONS", "description": "shell, 파일 쓰기, HTTP 요청이 모두 활성화되어 공격 체인이 가능합니다.", "remediation": "필요한 도구만 활성화하고, 특히 shell과 http_request의 동시 활성화를 피하세요."},
                {"field": "max_steps", "current_value": "1000", "expected_value": "100 이하", "severity": "MEDIUM", "category": "EXECUTION", "description": "최대 단계 수가 과도하게 높아 비용 폭발 위험이 있습니다.", "remediation": "max_steps를 50-100으로 제한하세요."},
            ],
            "overall_severity": "CRITICAL",
            "reasoning": "알 수 없는 에이전트 유형이지만, 공통 보안 원칙 기준으로 샌드박스 미사용, 인증 없음, 과도한 도구 권한 등 심각한 문제가 있습니다."
        }
    ))

    # --- Near-perfect config with one subtle issue ---
    examples.append(make_example(
        json.dumps({
            "gateway": {"auth": {"mode": "token", "token": "sk-oc-a8f3b2c1d9e7f4a5b6c8d0e1f2a3b4c5"}, "bind": "127.0.0.1"},
            "tools": {"profile": "minimal", "sandbox": {"mode": "all", "docker": {"network": "none"}}, "exec": {"ask": "always"}, "allow": ["read", "search"]},
            "channels": {"telegram": {"dmPolicy": "allowlist", "allowFrom": ["123456789"]}},
            "agentguard": {"gateEnabled": True, "gateFailOpen": False, "gateMode": "enforce"}
        }, indent=2),
        {
            "agent_type": "openclaw",
            "config_safe": True,
            "security_score": 100,
            "findings": [],
            "overall_severity": "NONE",
            "reasoning": "인증, 샌드박스, 네트워크 격리, 도구 제한, 사용자 확인, AgentGuard 연동 등 모든 보안 설정이 모범적으로 구성되어 있습니다. 프로덕션 배포에 적합합니다."
        }
    ))

    return examples


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    all_examples = []
    generators = {
        "openclaw": generate_openclaw_configs,
        "claude_code": generate_claude_code_configs,
        "autogpt": generate_autogpt_configs,
        "crewai": generate_crewai_configs,
        "langgraph": generate_langgraph_configs,
        "cursor": generate_cursor_configs,
        "cline": generate_cline_configs,
        "agentguard": generate_agentguard_configs,
        "edge_cases": generate_edge_cases,
    }

    for name, gen_fn in generators.items():
        examples = gen_fn()
        print(f"  {name}: {len(examples)} examples")
        all_examples.extend(examples)

    # Write combined output
    output_path = OUTPUT_DIR / "multiagent_config.jsonl"
    with open(output_path, "w") as f:
        for ex in all_examples:
            f.write(json.dumps(ex, ensure_ascii=False) + "\n")

    print(f"\nTotal: {len(all_examples)} examples → {output_path}")

    # Also write per-agent files for inspection
    for name, gen_fn in generators.items():
        per_agent_path = OUTPUT_DIR / f"config_{name}.jsonl"
        examples = gen_fn()
        with open(per_agent_path, "w") as f:
            for ex in examples:
                f.write(json.dumps(ex, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    main()
