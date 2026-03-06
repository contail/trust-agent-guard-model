"""
Augment multi-agent config training data with variations.
Takes base examples and generates variations by:
1. Shuffling field values between safe/dangerous
2. Combining partial issues
3. Varying severity levels
"""

import json
import copy
import random
import pathlib

SYSTEM_PROMPT_PATH = pathlib.Path(__file__).parent.parent / "prompts" / "system_prompt_v4.txt"
OUTPUT_DIR = pathlib.Path(__file__).parent / "batches"
SYSTEM_PROMPT = SYSTEM_PROMPT_PATH.read_text()

random.seed(42)


def make_example(config_text: str, response: dict) -> dict:
    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"## Config\n\n```json\n{config_text}\n```"},
            {"role": "assistant", "content": json.dumps(response, ensure_ascii=False)},
        ]
    }


def calc_score(findings):
    score = 100
    for f in findings:
        sev = f["severity"]
        if sev == "CRITICAL":
            score -= 25
        elif sev == "HIGH":
            score -= 15
        elif sev == "MEDIUM":
            score -= 8
        elif sev == "LOW":
            score -= 3
    return max(0, score)


def overall_sev(findings):
    if not findings:
        return "NONE"
    sevs = [f["severity"] for f in findings]
    for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if s in sevs:
            return s
    return "NONE"


# ============================================================
# OpenClaw variations
# ============================================================
def openclaw_variations():
    examples = []

    # Variation 1: sandbox session + messaging profile + weak token
    examples.append(make_example(
        json.dumps({
            "gateway": {"auth": {"mode": "token", "token": "test"}, "bind": "127.0.0.1"},
            "tools": {"profile": "messaging", "sandbox": {"mode": "session", "docker": {"network": "bridge"}}, "exec": {"ask": "always"}},
        }, indent=2),
        {
            "agent_type": "openclaw",
            "config_safe": False,
            "security_score": 70,
            "findings": [
                {"field": "gateway.auth.token", "current_value": "test", "expected_value": "32자 이상의 랜덤 문자열", "severity": "HIGH", "category": "AUTH", "description": "인증 토큰이 4자로 매우 짧아 무차별 대입 공격에 취약합니다.", "remediation": "openssl rand -hex 32로 생성한 랜덤 토큰으로 교체하세요."},
                {"field": "tools.sandbox.docker.network", "current_value": "bridge", "expected_value": "none", "severity": "HIGH", "category": "NETWORK", "description": "Docker 브릿지 네트워크 사용으로 컨테이너가 외부 통신이 가능합니다.", "remediation": "docker.network를 'none'으로 변경하세요."},
            ],
            "overall_severity": "HIGH",
            "reasoning": "세션 단위 샌드박스와 messaging 프로필은 적절하나, 토큰 강도와 네트워크 격리가 부족합니다."
        }
    ))

    # Variation 2: good config but 0.0.0.0 bind
    examples.append(make_example(
        json.dumps({
            "gateway": {"auth": {"mode": "mTLS"}, "bind": "0.0.0.0", "tls": {"cert": "/etc/ssl/cert.pem", "key": "/etc/ssl/key.pem"}},
            "tools": {"profile": "minimal", "sandbox": {"mode": "all", "docker": {"network": "none"}}, "exec": {"ask": "always"}},
        }, indent=2),
        {
            "agent_type": "openclaw",
            "config_safe": False,
            "security_score": 85,
            "findings": [
                {"field": "gateway.bind", "current_value": "0.0.0.0", "expected_value": "127.0.0.1", "severity": "HIGH", "category": "NETWORK", "description": "mTLS로 인증은 강력하지만, 모든 인터페이스에 바인딩되어 불필요한 네트워크 노출이 있습니다.", "remediation": "외부 접근이 필요없다면 bind를 '127.0.0.1'로 변경하세요. 외부 접근이 필요하면 방화벽으로 접근을 제한하세요."},
            ],
            "overall_severity": "HIGH",
            "reasoning": "mTLS, 최소 프로필, 전체 샌드박스 등 대부분 우수하나, 네트워크 바인딩만 수정이 필요합니다."
        }
    ))

    # Variation 3: profile full but sandbox all
    examples.append(make_example(
        json.dumps({
            "gateway": {"auth": {"mode": "token", "token": "sk-oc-b7d4e2f1a8c3b5d9e6f0a2c4d8e1f3a5"}, "bind": "127.0.0.1"},
            "tools": {"profile": "full", "sandbox": {"mode": "all", "docker": {"network": "none"}}, "exec": {"ask": "always"}},
            "channels": {"slack": {"dmPolicy": "allowlist"}},
        }, indent=2),
        {
            "agent_type": "openclaw",
            "config_safe": False,
            "security_score": 85,
            "findings": [
                {"field": "tools.profile", "current_value": "full", "expected_value": "minimal 또는 messaging", "severity": "HIGH", "category": "PERMISSIONS", "description": "전체 도구 접근이 허용되어 있으나, 샌드박스와 네트워크 차단으로 위험이 제한됩니다.", "remediation": "가능하면 tools.profile을 'minimal'로 변경하고 필요한 도구만 개별 추가하세요."},
            ],
            "overall_severity": "HIGH",
            "reasoning": "강력한 샌드박스와 네트워크 격리가 있어 위험은 제한적이지만, 최소 권한 원칙을 위해 도구 프로필을 줄이는 것을 권장합니다."
        }
    ))

    # Variation 4: telegram open + weak token + no sandbox
    examples.append(make_example(
        json.dumps({
            "gateway": {"auth": {"mode": "token", "token": "password"}, "bind": "0.0.0.0"},
            "tools": {"profile": "messaging", "sandbox": {"mode": "off"}, "exec": {"ask": "always"}},
            "channels": {"telegram": {"dmPolicy": "open"}, "discord": {"dmPolicy": "open"}},
        }, indent=2),
        {
            "agent_type": "openclaw",
            "config_safe": False,
            "security_score": 15,
            "findings": [
                {"field": "gateway.auth.token", "current_value": "password", "expected_value": "32자 이상의 랜덤 문자열", "severity": "HIGH", "category": "AUTH", "description": "인증 토큰이 매우 약하고 일반적인 비밀번호입니다.", "remediation": "강력한 랜덤 토큰으로 교체하세요."},
                {"field": "gateway.bind", "current_value": "0.0.0.0", "expected_value": "127.0.0.1", "severity": "HIGH", "category": "NETWORK", "description": "약한 토큰과 결합되어 외부 접근 시 무차별 대입이 쉽습니다.", "remediation": "bind를 '127.0.0.1'로 변경하세요."},
                {"field": "tools.sandbox.mode", "current_value": "off", "expected_value": "all", "severity": "CRITICAL", "category": "SANDBOX", "description": "샌드박스 없이 에이전트가 호스트에서 직접 실행됩니다.", "remediation": "sandbox.mode를 'all'로 설정하세요."},
                {"field": "channels.telegram.dmPolicy", "current_value": "open", "expected_value": "allowlist", "severity": "HIGH", "category": "AUTH", "description": "텔레그램 채널이 모든 사용자에게 개방되어 있습니다.", "remediation": "dmPolicy를 'allowlist'로 변경하세요."},
                {"field": "channels.discord.dmPolicy", "current_value": "open", "expected_value": "allowlist", "severity": "HIGH", "category": "AUTH", "description": "디스코드 채널도 모든 사용자에게 개방되어 있습니다.", "remediation": "dmPolicy를 'allowlist'로 변경하세요."},
            ],
            "overall_severity": "CRITICAL",
            "reasoning": "약한 인증, 샌드박스 미사용, 외부 노출, 채널 개방 등 복합적인 보안 문제가 있어 즉시 전면 개선이 필요합니다."
        }
    ))

    # Variation 5: agent mode sandbox
    examples.append(make_example(
        json.dumps({
            "gateway": {"auth": {"mode": "token", "token": "sk-oc-c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6"}, "bind": "127.0.0.1"},
            "tools": {"profile": "minimal", "sandbox": {"mode": "agent"}, "exec": {"ask": "always"}},
            "agents": {"defaults": {"model": "anthropic/claude-sonnet-4-6"}},
        }, indent=2),
        {
            "agent_type": "openclaw",
            "config_safe": True,
            "security_score": 95,
            "findings": [],
            "overall_severity": "NONE",
            "reasoning": "에이전트별 샌드박스 격리, 최소 도구 프로필, 강력한 토큰, 로컬 바인딩 등 안전한 구성입니다."
        }
    ))

    return examples


# ============================================================
# Claude Code variations
# ============================================================
def claude_code_variations():
    examples = []

    # Variation 1: enterprise managed settings
    examples.append(make_example(
        json.dumps({
            "permissions": {
                "allow": ["Read", "Glob", "Grep"],
                "deny": ["Read(**/.env)", "Read(**/.ssh/*)", "Read(**/.aws/*)", "Bash(sudo:*)", "Bash(curl:*)", "Bash(wget:*)", "Bash(rm -rf:*)"],
                "ask": ["Bash", "Write", "Edit", "WebFetch"],
                "disableBypassPermissionsMode": "disable"
            }
        }, indent=2),
        {
            "agent_type": "claude_code",
            "config_safe": True,
            "security_score": 100,
            "findings": [],
            "overall_severity": "NONE",
            "reasoning": "deny에 민감 파일/명령 패턴이 포함되고, Bash/Write/Edit는 확인 필요, 우회 모드 비활성화로 보안이 잘 구성되어 있습니다."
        }
    ))

    # Variation 2: MCP server with too many servers
    examples.append(make_example(
        json.dumps({
            "permissions": {
                "allow": ["Read", "Glob"],
                "deny": ["Read(**/.env)", "Bash(sudo:*)"],
                "ask": ["Bash", "Write"],
                "disableBypassPermissionsMode": "disable"
            },
            "mcpServers": {
                "filesystem": {"command": "npx", "args": ["@modelcontextprotocol/server-filesystem", "/Users/user/project"]},
                "github": {"command": "npx", "args": ["@modelcontextprotocol/server-github"]},
                "slack": {"command": "npx", "args": ["@modelcontextprotocol/server-slack"]},
                "custom-tool": {"command": "node", "args": ["./my-custom-mcp/index.js"]}
            }
        }, indent=2),
        {
            "agent_type": "claude_code",
            "config_safe": False,
            "security_score": 85,
            "findings": [
                {"field": "mcpServers.custom-tool", "current_value": "./my-custom-mcp/index.js", "expected_value": "검증된 MCP 서버만 사용", "severity": "HIGH", "category": "SANDBOX", "description": "로컬 커스텀 MCP 서버가 등록되어 있습니다. 검증되지 않은 서버는 악성 도구를 제공할 수 있습니다.", "remediation": "커스텀 MCP 서버의 코드를 감사하고, 신뢰할 수 없으면 제거하세요."},
            ],
            "overall_severity": "HIGH",
            "reasoning": "기본 보안 설정은 우수하나, 검증되지 않은 커스텀 MCP 서버가 잠재적 위험입니다."
        }
    ))

    # Variation 3: deny has patterns but missing key ones
    examples.append(make_example(
        json.dumps({
            "permissions": {
                "allow": ["Read", "Glob", "Grep", "Bash", "Write", "Edit"],
                "deny": ["Bash(sudo:*)", "Bash(rm -rf /:*)"],
                "ask": []
            }
        }, indent=2),
        {
            "agent_type": "claude_code",
            "config_safe": False,
            "security_score": 40,
            "findings": [
                {"field": "permissions.allow", "current_value": "Bash, Write, Edit 무조건 허용", "expected_value": "Bash, Write, Edit는 ask로 이동", "severity": "HIGH", "category": "PERMISSIONS", "description": "위험한 도구들이 확인 없이 자동 허용됩니다.", "remediation": "Bash, Write, Edit를 ask 목록으로 이동하세요."},
                {"field": "permissions.deny", "current_value": "sudo, rm -rf /만 차단", "expected_value": ".env, .ssh, .aws, curl, wget 등 추가", "severity": "HIGH", "category": "CREDENTIALS", "description": "민감 파일 접근(SSH 키, AWS 자격증명, .env)이 차단되지 않습니다.", "remediation": "deny에 Read(**/.env), Read(**/.ssh/*), Read(**/.aws/*), Bash(curl:*), Bash(wget:*) 등을 추가하세요."},
                {"field": "permissions.disableBypassPermissionsMode", "current_value": "missing", "expected_value": "disable", "severity": "CRITICAL", "category": "PERMISSIONS", "description": "우회 모드 비활성화 설정이 없습니다.", "remediation": "disableBypassPermissionsMode를 'disable'로 설정하세요."},
            ],
            "overall_severity": "CRITICAL",
            "reasoning": "deny 목록이 불충분하고, 위험 도구가 자동 허용되며, 우회 모드 비활성화가 없어 보안이 매우 취약합니다."
        }
    ))

    # Variation 4: project settings with local overrides
    examples.append(make_example(
        json.dumps({
            "permissions": {
                "allow": ["Read", "Glob", "Grep", "WebSearch"],
                "deny": ["Read(**/.env)", "Read(**/.env.*)", "Read(**/.ssh/*)", "Read(**/.aws/*)", "Read(**/.gnupg/*)", "Bash(sudo:*)", "Bash(curl:*)", "Bash(wget:*)", "Bash(nc:*)", "Bash(ncat:*)"],
                "ask": ["Bash", "Write", "Edit", "WebFetch"],
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
            "reasoning": "deny에 .env 변형, SSH/AWS/GPG 키, 네트워크 도구(curl, wget, nc)까지 차단하고, MCP 서버도 프로젝트 범위로 제한된 모범적인 구성입니다."
        }
    ))

    return examples


# ============================================================
# AutoGPT variations
# ============================================================
def autogpt_variations():
    examples = []

    # Variation 1: allowlist but too broad
    examples.append(make_example(
        json.dumps({
            "EXECUTE_LOCAL_COMMANDS": True,
            "SHELL_COMMAND_CONTROL": "allowlist",
            "SHELL_ALLOWLIST": "cat,echo,ls,pwd,python,pip,npm,node,git,curl,wget,ssh",
            "RESTRICT_TO_WORKSPACE": True,
            "CONTINUOUS_MODE": False
        }, indent=2),
        {
            "agent_type": "autogpt",
            "config_safe": False,
            "security_score": 55,
            "findings": [
                {"field": "SHELL_ALLOWLIST", "current_value": "python, pip, npm, curl, wget, ssh 포함", "expected_value": "안전한 읽기 명령만", "severity": "HIGH", "category": "PERMISSIONS", "description": "allowlist에 위험한 명령(python, curl, wget, ssh)이 포함되어 있어 코드 실행, 네트워크 통신, 원격 접속이 가능합니다.", "remediation": "python, pip, npm, curl, wget, ssh를 allowlist에서 제거하세요. 꼭 필요하면 Docker 환경에서만 허용하세요."},
                {"field": "EXECUTE_LOCAL_COMMANDS", "current_value": "True", "expected_value": "False (또는 Docker 필수)", "severity": "MEDIUM", "category": "EXECUTION", "description": "로컬 명령 실행이 활성화되어 있습니다. allowlist가 있지만 포함된 명령들의 위험성이 높습니다.", "remediation": "Docker 환경에서 실행하거나 EXECUTE_LOCAL_COMMANDS를 False로 설정하세요."},
            ],
            "overall_severity": "HIGH",
            "reasoning": "allowlist 모드는 좋으나 허용된 명령 목록이 너무 넓어 위험합니다. 특히 curl, wget, ssh는 데이터 유출과 원격 접속에 악용될 수 있습니다."
        }
    ))

    # Variation 2: safe but missing disabled categories
    examples.append(make_example(
        json.dumps({
            "EXECUTE_LOCAL_COMMANDS": False,
            "SHELL_COMMAND_CONTROL": "allowlist",
            "SHELL_ALLOWLIST": "cat,echo,ls",
            "RESTRICT_TO_WORKSPACE": True,
            "CONTINUOUS_MODE": False,
            "DISABLED_COMMAND_CATEGORIES": []
        }, indent=2),
        {
            "agent_type": "autogpt",
            "config_safe": True,
            "security_score": 92,
            "findings": [
                {"field": "DISABLED_COMMAND_CATEGORIES", "current_value": "[]", "expected_value": "불필요한 카테고리 비활성화 권장", "severity": "LOW", "category": "PERMISSIONS", "description": "로컬 명령이 비활성화되어 위험은 낮지만, 불필요한 명령 카테고리를 비활성화하면 공격 표면을 더 줄일 수 있습니다.", "remediation": "사용하지 않는 카테고리(execute_code, git_operations 등)를 DISABLED_COMMAND_CATEGORIES에 추가하세요."},
            ],
            "overall_severity": "LOW",
            "reasoning": "핵심 보안 설정은 모두 안전합니다. 명령 카테고리 비활성화는 추가 방어 계층으로 권장되지만 필수는 아닙니다."
        }
    ))

    # Variation 3: continuous mode with Docker
    examples.append(make_example(
        json.dumps({
            "EXECUTE_LOCAL_COMMANDS": True,
            "SHELL_COMMAND_CONTROL": "allowlist",
            "SHELL_ALLOWLIST": "cat,ls,pwd",
            "RESTRICT_TO_WORKSPACE": True,
            "CONTINUOUS_MODE": True,
            "DOCKER_ENABLED": True
        }, indent=2),
        {
            "agent_type": "autogpt",
            "config_safe": False,
            "security_score": 70,
            "findings": [
                {"field": "CONTINUOUS_MODE", "current_value": "True", "expected_value": "False", "severity": "HIGH", "category": "HITL", "description": "연속 모드에서는 사용자 승인 없이 작업이 계속됩니다. Docker 내에서도 예상치 못한 행동이 발생할 수 있습니다.", "remediation": "프로덕션에서는 CONTINUOUS_MODE를 False로 설정하세요. 테스트 환경에서만 사용하세요."},
            ],
            "overall_severity": "HIGH",
            "reasoning": "Docker + allowlist + workspace 제한으로 기본 격리는 있으나, 연속 모드로 인해 인간 감독이 없어 위험합니다."
        }
    ))

    return examples


# ============================================================
# CrewAI variations
# ============================================================
def crewai_variations():
    examples = []

    # Variation 1: multiple agents with mixed security
    examples.append(make_example(
        json.dumps({
            "agents": [
                {
                    "role": "Researcher",
                    "allow_code_execution": False,
                    "allow_delegation": False,
                    "max_iter": 20
                },
                {
                    "role": "Developer",
                    "allow_code_execution": True,
                    "code_execution_mode": "safe",
                    "allow_delegation": False,
                    "max_iter": 20,
                    "max_execution_time": 300
                }
            ],
            "process": "sequential"
        }, indent=2),
        {
            "agent_type": "crewai",
            "config_safe": True,
            "security_score": 95,
            "findings": [],
            "overall_severity": "NONE",
            "reasoning": "Researcher는 코드 실행 없이 안전하고, Developer는 Docker 샌드박스에서 실행되며 위임 비활성화, 적절한 제한이 설정되어 있습니다."
        }
    ))

    # Variation 2: hierarchical with unsafe manager
    examples.append(make_example(
        json.dumps({
            "agents": [
                {
                    "role": "Manager",
                    "allow_code_execution": False,
                    "allow_delegation": True,
                    "max_iter": 50
                },
                {
                    "role": "Worker",
                    "allow_code_execution": True,
                    "code_execution_mode": "unsafe",
                    "allow_delegation": False,
                    "max_iter": 20
                }
            ],
            "process": "hierarchical",
            "manager_agent": "Manager"
        }, indent=2),
        {
            "agent_type": "crewai",
            "config_safe": False,
            "security_score": 35,
            "findings": [
                {"field": "agents[1].code_execution_mode", "current_value": "unsafe", "expected_value": "safe", "severity": "CRITICAL", "category": "SANDBOX", "description": "Worker 에이전트가 호스트에서 직접 코드를 실행합니다.", "remediation": "code_execution_mode를 'safe'로 변경하여 Docker 샌드박스에서 실행하세요."},
                {"field": "agents[0].allow_delegation + agents[1].code_execution", "current_value": "Manager 위임 → Worker 코드 실행", "expected_value": "위임 체인에서 코드 실행 분리", "severity": "CRITICAL", "category": "PERMISSIONS", "description": "Manager가 Worker에게 위임할 수 있고, Worker는 unsafe 코드 실행이 가능하여 위험한 위임 체인이 형성됩니다.", "remediation": "Worker의 code_execution_mode를 'safe'로 변경하거나, Manager의 allow_delegation을 False로 설정하세요."},
                {"field": "agents[0].max_iter", "current_value": "50", "expected_value": "25 이하", "severity": "MEDIUM", "category": "EXECUTION", "description": "Manager의 반복 횟수가 과도합니다.", "remediation": "max_iter를 25로 줄이세요."},
            ],
            "overall_severity": "CRITICAL",
            "reasoning": "Manager→Worker 위임 체인에서 Worker가 호스트 코드 실행이 가능하여 프롬프트 인젝션 시 심각한 피해가 발생할 수 있습니다."
        }
    ))

    # Variation 3: all safe but no execution time limit
    examples.append(make_example(
        json.dumps({
            "agents": [
                {
                    "role": "Analyst",
                    "allow_code_execution": True,
                    "code_execution_mode": "safe",
                    "allow_delegation": False,
                    "max_iter": 20,
                    "max_execution_time": None,
                    "max_rpm": None
                }
            ],
            "process": "sequential"
        }, indent=2),
        {
            "agent_type": "crewai",
            "config_safe": False,
            "security_score": 84,
            "findings": [
                {"field": "agents[0].max_execution_time", "current_value": "null", "expected_value": "300", "severity": "MEDIUM", "category": "EXECUTION", "description": "실행 시간 제한이 없어 무한 실행 위험이 있습니다.", "remediation": "max_execution_time을 300(5분)으로 설정하세요."},
                {"field": "agents[0].max_rpm", "current_value": "null", "expected_value": "30-60", "severity": "MEDIUM", "category": "EXECUTION", "description": "API 속도 제한이 없어 비용 통제가 안됩니다.", "remediation": "max_rpm을 30-60으로 설정하세요."},
            ],
            "overall_severity": "MEDIUM",
            "reasoning": "핵심 보안(샌드박스, 위임 제한)은 잘 설정되었으나, 실행 시간과 비용 제한이 없어 리소스 소모 공격에 취약합니다."
        }
    ))

    return examples


# ============================================================
# LangGraph variations
# ============================================================
def langgraph_variations():
    examples = []

    # Variation 1: auth exists but CORS too broad
    examples.append(make_example(
        json.dumps({
            "dependencies": ["."],
            "graphs": {"agent": "./src/graph.py:graph"},
            "auth": {"path": "src/auth.py:verify_token"},
            "cors": {"allow_origins": ["*"]},
            "disable_studio_auth": False
        }, indent=2),
        {
            "agent_type": "langgraph",
            "config_safe": False,
            "security_score": 85,
            "findings": [
                {"field": "cors.allow_origins", "current_value": "[\"*\"]", "expected_value": "특정 도메인만", "severity": "HIGH", "category": "NETWORK", "description": "CORS가 모든 출처를 허용하여 인증이 있어도 CSRF 공격에 노출될 수 있습니다.", "remediation": "allow_origins를 실제 프론트엔드 도메인으로 제한하세요."},
            ],
            "overall_severity": "HIGH",
            "reasoning": "인증과 Studio 보안은 잘 설정되었으나, CORS 정책이 너무 광범위합니다."
        }
    ))

    # Variation 2: development config (acceptable for dev)
    examples.append(make_example(
        json.dumps({
            "dependencies": ["."],
            "graphs": {"agent": "./src/graph.py:graph"},
            "env": ".env",
            "disable_studio_auth": True,
            "comment": "development only"
        }, indent=2),
        {
            "agent_type": "langgraph",
            "config_safe": False,
            "security_score": 45,
            "findings": [
                {"field": "auth", "current_value": "missing", "expected_value": "인증 핸들러 필요", "severity": "CRITICAL", "category": "AUTH", "description": "인증이 설정되지 않았습니다. 개발 환경이라도 기본 인증을 구성하는 것이 좋습니다.", "remediation": "auth 섹션을 추가하세요. 개발용으로 간단한 API 키 검증이라도 구현하세요."},
                {"field": "disable_studio_auth", "current_value": "True", "expected_value": "False (프로덕션)", "severity": "HIGH", "category": "AUTH", "description": "Studio 인증이 비활성화되어 있습니다. 개발 환경에서는 허용되지만 프로덕션 배포 전 반드시 변경해야 합니다.", "remediation": "프로덕션 배포 전 disable_studio_auth를 false로 변경하세요."},
            ],
            "overall_severity": "CRITICAL",
            "reasoning": "개발 환경용 설정으로 보이지만, 인증 부재와 Studio 무인증은 프로덕션 배포 시 심각한 위험입니다. 개발 단계에서부터 보안을 구성하는 것을 권장합니다."
        }
    ))

    # Variation 3: fully configured production
    examples.append(make_example(
        json.dumps({
            "dependencies": ["."],
            "graphs": {"agent": "./src/graph.py:graph"},
            "auth": {"path": "src/security/auth.py:verify_jwt"},
            "cors": {"allow_origins": ["https://dashboard.example.com"], "allow_methods": ["GET", "POST"], "allow_headers": ["Authorization", "Content-Type"]},
            "disable_studio_auth": False,
            "env": ".env"
        }, indent=2),
        {
            "agent_type": "langgraph",
            "config_safe": True,
            "security_score": 100,
            "findings": [],
            "overall_severity": "NONE",
            "reasoning": "JWT 인증, 도메인 제한 CORS, Studio 인증 활성화 등 프로덕션에 적합한 보안 설정입니다."
        }
    ))

    return examples


# ============================================================
# Cursor variations
# ============================================================
def cursor_variations():
    examples = []

    # Variation 1: deny network but broad filesystem
    examples.append(make_example(
        json.dumps({
            "networkPolicy": {"default": "deny", "allow": ["api.github.com"]},
            "filesystem": {"allowWrite": ["/Users/user", "/tmp"]},
            "cursorignore": [".env"]
        }, indent=2),
        {
            "agent_type": "cursor",
            "config_safe": False,
            "security_score": 70,
            "findings": [
                {"field": "filesystem.allowWrite", "current_value": "[\"/Users/user\", \"/tmp\"]", "expected_value": "프로젝트 디렉토리만", "severity": "HIGH", "category": "SANDBOX", "description": "홈 디렉토리 전체에 쓰기 권한이 있어 SSH 키, AWS 설정 등이 변조될 수 있습니다.", "remediation": "allowWrite를 프로젝트 디렉토리만으로 제한하세요. /tmp도 제거를 권장합니다."},
                {"field": "cursorignore", "current_value": "[\".env\"]만", "expected_value": ".ssh, .aws, *.pem 등 추가", "severity": "MEDIUM", "category": "CREDENTIALS", "description": ".env만 차단되고 다른 민감 파일은 보호되지 않습니다.", "remediation": ".cursorignore에 .ssh/, .aws/, .gnupg/, *.pem, *.key, credentials.json 등을 추가하세요."},
            ],
            "overall_severity": "HIGH",
            "reasoning": "네트워크 정책은 잘 설정되었으나 파일시스템 범위가 넓고 ignore 패턴이 불충분합니다."
        }
    ))

    # Variation 2: network allow with many domains
    examples.append(make_example(
        json.dumps({
            "networkPolicy": {"default": "deny", "allow": ["api.github.com", "registry.npmjs.org", "pypi.org", "cdn.jsdelivr.net", "raw.githubusercontent.com"]},
            "filesystem": {"allowWrite": ["/Users/user/projects/myapp"]},
            "cursorignore": [".env", ".env.*", ".ssh/", ".aws/", "*.pem", "*.key"]
        }, indent=2),
        {
            "agent_type": "cursor",
            "config_safe": True,
            "security_score": 95,
            "findings": [],
            "overall_severity": "NONE",
            "reasoning": "네트워크는 신뢰할 수 있는 개발 도메인만 허용하고, 파일시스템은 프로젝트로 제한되며, 민감 파일 패턴이 잘 차단되어 있습니다."
        }
    ))

    return examples


# ============================================================
# Cline variations
# ============================================================
def cline_variations():
    examples = []

    # Variation 1: read auto-approve only
    examples.append(make_example(
        json.dumps({
            "CLINE_COMMAND_PERMISSIONS": "npm test, npm run build, git status, git diff, ls, cat, pwd",
            "clineignore": [".env", ".ssh/", ".aws/"],
            "autoApprove": {"readFiles": True, "editFiles": False, "executeCommands": False, "useBrowser": False},
            "strictPlanModeEnabled": True
        }, indent=2),
        {
            "agent_type": "cline",
            "config_safe": True,
            "security_score": 100,
            "findings": [],
            "overall_severity": "NONE",
            "reasoning": "명령 허용이 구체적이고, 민감 파일 보호, 읽기만 자동 승인, Plan 모드 엄격 설정 등 안전한 구성입니다."
        }
    ))

    # Variation 2: some auto-approve with missing ignore
    examples.append(make_example(
        json.dumps({
            "CLINE_COMMAND_PERMISSIONS": "npm *, git *, python *",
            "clineignore": [],
            "autoApprove": {"readFiles": True, "editFiles": True, "executeCommands": False, "useBrowser": False},
            "strictPlanModeEnabled": False
        }, indent=2),
        {
            "agent_type": "cline",
            "config_safe": False,
            "security_score": 52,
            "findings": [
                {"field": "CLINE_COMMAND_PERMISSIONS", "current_value": "python * 포함", "expected_value": "python 제거 또는 구체적 명령만", "severity": "HIGH", "category": "EXECUTION", "description": "python *이 허용되어 임의 Python 스크립트 실행이 가능합니다.", "remediation": "python *을 제거하고 필요한 경우 'python -m pytest' 등 구체적인 명령만 허용하세요."},
                {"field": "autoApprove.editFiles", "current_value": "True", "expected_value": "False", "severity": "HIGH", "category": "HITL", "description": "파일 수정이 자동 승인되어 중요 코드가 확인 없이 변경될 수 있습니다.", "remediation": "editFiles를 False로 변경하세요."},
                {"field": "clineignore", "current_value": "[]", "expected_value": ".env, .ssh, .aws 등", "severity": "HIGH", "category": "CREDENTIALS", "description": ".clineignore가 비어있어 모든 파일이 AI에 노출됩니다.", "remediation": ".clineignore에 .env, .ssh/, .aws/, *.pem, *.key를 추가하세요."},
                {"field": "strictPlanModeEnabled", "current_value": "False", "expected_value": "True", "severity": "MEDIUM", "category": "HITL", "description": "Plan 모드에서 파일 수정이 가능합니다.", "remediation": "strictPlanModeEnabled를 True로 설정하세요."},
            ],
            "overall_severity": "HIGH",
            "reasoning": "python 실행 허용, 파일 수정 자동 승인, 민감 파일 미보호로 코드 변조와 자격 증명 노출 위험이 있습니다."
        }
    ))

    # Variation 3: commands too broad
    examples.append(make_example(
        json.dumps({
            "CLINE_COMMAND_PERMISSIONS": "npm *, git *, curl *, wget *, ssh *",
            "clineignore": [".env", ".ssh/"],
            "autoApprove": {"readFiles": True, "editFiles": False, "executeCommands": True, "useBrowser": False},
            "strictPlanModeEnabled": True
        }, indent=2),
        {
            "agent_type": "cline",
            "config_safe": False,
            "security_score": 40,
            "findings": [
                {"field": "CLINE_COMMAND_PERMISSIONS", "current_value": "curl *, wget *, ssh * 포함", "expected_value": "네트워크 명령 제거", "severity": "HIGH", "category": "PERMISSIONS", "description": "curl, wget, ssh가 허용되어 데이터 유출, 악성 다운로드, 원격 접속이 가능합니다.", "remediation": "curl *, wget *, ssh *를 명령 허용 목록에서 제거하세요."},
                {"field": "autoApprove.executeCommands", "current_value": "True", "expected_value": "False", "severity": "CRITICAL", "category": "HITL", "description": "명령 자동 실행 + curl/wget/ssh 허용이 결합되어 매우 위험합니다.", "remediation": "executeCommands를 False로 변경하여 명령 실행 전 확인을 받으세요."},
            ],
            "overall_severity": "CRITICAL",
            "reasoning": "네트워크 명령 허용과 자동 실행이 결합되어 데이터 유출이나 원격 공격이 사용자 확인 없이 가능합니다."
        }
    ))

    return examples


# ============================================================
# AgentGuard variations
# ============================================================
def agentguard_variations():
    examples = []

    # Variation 1: gate enabled but monitor mode
    examples.append(make_example(
        json.dumps({
            "agentguard": {
                "gateEnabled": True,
                "gateFailOpen": False,
                "gateMode": "monitor"
            },
            "mcp-policy": {
                "denied_tools": ["write_*", "execute_*"],
                "denied_paths": ["/etc/*", "~/.ssh/*"],
                "mode": "enforce"
            }
        }, indent=2),
        {
            "agent_type": "agentguard",
            "config_safe": False,
            "security_score": 77,
            "findings": [
                {"field": "agentguard.gateMode", "current_value": "monitor", "expected_value": "enforce", "severity": "HIGH", "category": "AUTH", "description": "모니터 모드는 위험 요청을 감지하지만 차단하지 않습니다. 로그만 남기고 실행은 허용됩니다.", "remediation": "프로덕션에서는 gateMode를 'enforce'로 변경하세요. 초기 도입 시에만 monitor 모드를 사용하세요."},
            ],
            "overall_severity": "HIGH",
            "reasoning": "MCP 정책과 게이트 설정은 대체로 양호하나, 모니터 모드에서는 실제 차단이 이루어지지 않아 보안 효과가 제한적입니다."
        }
    ))

    # Variation 2: gate enabled but fail-open
    examples.append(make_example(
        json.dumps({
            "agentguard": {
                "gateEnabled": True,
                "gateFailOpen": True,
                "gateMode": "enforce"
            },
            "mcp-policy": {
                "denied_tools": ["write_*", "execute_*", "delete_*"],
                "denied_paths": ["/etc/*", "~/.ssh/*", "~/.aws/*", "~/.gnupg/*", "**/.env"],
                "mode": "enforce"
            }
        }, indent=2),
        {
            "agent_type": "agentguard",
            "config_safe": False,
            "security_score": 85,
            "findings": [
                {"field": "agentguard.gateFailOpen", "current_value": "True", "expected_value": "False", "severity": "HIGH", "category": "AUTH", "description": "게이트 장애 시 모든 요청이 허용됩니다. 의도적 장애 유발로 보안을 우회할 수 있습니다.", "remediation": "gateFailOpen을 False로 설정하여 장애 시에도 요청을 차단하세요(fail-closed)."},
            ],
            "overall_severity": "HIGH",
            "reasoning": "enforce 모드와 충분한 정책이 있으나, fail-open 설정은 장애 시 보안이 무력화되는 위험이 있습니다."
        }
    ))

    return examples


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    all_examples = []
    generators = {
        "openclaw_aug": openclaw_variations,
        "claude_code_aug": claude_code_variations,
        "autogpt_aug": autogpt_variations,
        "crewai_aug": crewai_variations,
        "langgraph_aug": langgraph_variations,
        "cursor_aug": cursor_variations,
        "cline_aug": cline_variations,
        "agentguard_aug": agentguard_variations,
    }

    for name, gen_fn in generators.items():
        examples = gen_fn()
        print(f"  {name}: {len(examples)} examples")
        all_examples.extend(examples)

    output_path = OUTPUT_DIR / "multiagent_config_augmented.jsonl"
    with open(output_path, "w") as f:
        for ex in all_examples:
            f.write(json.dumps(ex, ensure_ascii=False) + "\n")

    print(f"\nTotal augmented: {len(all_examples)} examples → {output_path}")


if __name__ == "__main__":
    main()
