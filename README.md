# ROE Gate

**Out-of-band Rules of Engagement enforcement for autonomous AI penetration testing agents.**

[![Version](https://img.shields.io/badge/version-0.1.0-blue)](https://github.com/Grey-Line-Interactive/ROEGATE)
[![Python](https://img.shields.io/badge/python-3.10%2B-green)](https://www.python.org)
[![License](https://img.shields.io/badge/license-MIT-brightgreen)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-289%20passing-brightgreen)](tests/)

ROE Gate is a reference monitor that sits between an AI pentest agent and the network. Every action the agent attempts — port scans, HTTP requests, SQL injection tests — must pass through the gate before it can execute. If the action violates the Rules of Engagement, the gate blocks it and no command is run. The agent never holds the signing keys and cannot bypass the gate.

> **Patent Pending** (U.S. Provisional Application No. 63/993,983) — ROE Gate implements a novel architecture for constraining autonomous security testing agents. See [roegate.io](https://roegate.io) for the white paper.

---

## The Problem

LLM-based agents performing autonomous penetration testing cannot reliably self-regulate through prompting alone. Prompt-based guardrails — system messages, constitutions, tool descriptions — fail 20-28% of the time under adversarial conditions.

Consider a real scenario:

1. An agent is authorized to test a web application for SQL injection
2. It discovers a SQLi vulnerability and extracts database credentials from error messages
3. The agent decides these credentials should be verified — a reasonable next step in a manual pentest
4. It connects directly to the **production database** on port 5432
5. It enumerates tables, extracts PII, and exfiltrates data

The ROE said "web application testing only, no direct database access." The agent's system prompt said the same thing. But the agent reasoned its way around the restriction because prompt-based guardrails are **advisory, not mandatory**.

## The Solution

ROE Gate implements the **Reference Monitor** pattern — a mandatory, out-of-band enforcement layer that the agent cannot bypass, influence, or reason around:

```
Agent tries: nmap -p 1-1000 10.0.2.50

        ┌─────────────────────────────────────┐
        │          GATE SERVICE               │  Separate process
        │          (port 19990)               │  Agent can't touch it
        │                                     │
        │  1. Rule Engine                     │
        │     10.0.2.50 is OUT OF SCOPE       │
        │     → HARD_DENY                     │
        │                                     │
        │  No token issued.                   │
        │  No command executed.               │
        │  Denial logged to audit trail.      │
        └─────────────────────────────────────┘
                        │
                        ▼
          Agent receives: "DENIED — 10.0.2.50
          is in out_of_scope (Production
          database tier — NO DIRECT ACCESS)"
```

### Three-Stage Pipeline

| Stage | Component | What It Does |
|-------|-----------|-------------|
| **1** | Deterministic Rule Engine | Checks IP ranges, ports, time windows, action categories against the ROE spec. Same input = same output. No LLM involved. Handles ~80% of decisions. |
| **2** | Isolated Judge LLM | A separate LLM with **no access** to the agent's context, reasoning, or conversation history evaluates edge cases. The agent cannot influence the judge. |
| **3** | Cryptographic Action Signing | Approved actions get a signed token (HMAC-SHA256 or Ed25519) with a 30-second TTL. The executor verifies the signature before running anything. Replay attacks are blocked. |

### Full Data Flow

```
Agent                MCP Server           Gate Service          Executor
  │                      │                      │                   │
  │ roe_nmap_scan(       │                      │                   │
  │   host=10.0.1.5)     │                      │                   │
  │─────────────────────►│                      │                   │
  │                      │ POST /evaluate       │                   │
  │                      │─────────────────────►│                   │
  │                      │            ┌─────────┴──────────┐        │
  │                      │            │ 1. Rule Engine ✓   │        │
  │                      │            │ 2. Judge LLM  ✓   │        │
  │                      │            │ 3. Sign Token      │        │
  │                      │            └─────────┬──────────┘        │
  │                      │ {ALLOW, token}       │                   │
  │                      │◄─────────────────────│                   │
  │                      │                      │                   │
  │                      │ POST /execute {token}│                   │
  │                      │─────────────────────►│ verify sig ✓      │
  │                      │                      │ check TTL  ✓      │
  │                      │                      │ check replay ✓    │
  │                      │                      │──────────────────►│
  │                      │                      │   nmap 10.0.1.5   │
  │                      │                      │◄──────────────────│
  │ {nmap output}        │ {stdout, rc}         │                   │
  │◄─────────────────────│◄─────────────────────│   AUDIT LOGGED    │
```

---

## Quick Start

### Requirements

- Python 3.10+ (`python3 --version` to check)
- `pyyaml` (only required dependency — installed automatically)

### Install

```bash
git clone https://github.com/Grey-Line-Interactive/ROEGATE.git
cd ROEGATE

# Install the package (makes the `roe-gate` CLI available)
pip install -e .

# Or with dev tools (pytest, ruff)
pip install -e ".[dev]"
```

After install, verify the CLI works:

```bash
roe-gate --help
```

> **Note:** If you're on macOS, the system Python may be 3.9. Use `python3.10+` or install via [pyenv](https://github.com/pyenv/pyenv) / [Homebrew](https://brew.sh) (`brew install python@3.12`). You can also run without installing: `python3 -m src --help`

### Define Your ROE

Create a YAML file describing the engagement scope (see [examples/local_corp_roe.yaml](examples/local_corp_roe.yaml)):

```yaml
roe:
  metadata:
    engagement_id: "ENG-2024-001"
    client: "Acme Corp"
    approved_by: "John Smith, CISO"

  schedule:
    valid_from: "2024-01-15T00:00:00Z"
    valid_until: "2024-02-15T23:59:59Z"

  scope:
    in_scope:
      networks:
        - cidr: "10.0.0.0/24"
          description: "Web application subnet"
          ports: [80, 443, 8080]
      domains:
        - pattern: "*.app.corp.local"
          include_subdomains: true

    out_of_scope:
      networks:
        - cidr: "10.0.2.0/24"
          reason: "Production database — NO ACCESS"

  actions:
    allowed:
      - category: "web_application_testing"
        methods: [sql_injection, xss, csrf]
    denied:
      - category: "denial_of_service"
        reason: "No DoS testing"

  emergency:
    max_consecutive_denials: 3
```

Or build one visually:

```bash
roe-gate creator       # Opens the ROE Creator web form in your browser
roe-gate roe-creator   # Same thing, alternative name
```

### Launch

```bash
# Launch the gated pentest agent (starts gate service + MCP server + Claude Code)
roe-gate pentest --roe examples/local_corp_roe.yaml

# With the real-time audit dashboard
roe-gate pentest --roe examples/local_corp_roe.yaml --dashboard

# Dry run — start the gate service and print config without launching Claude Code
roe-gate pentest --roe examples/local_corp_roe.yaml --dry-run
```

---

## Claude Code Integration

ROE Gate integrates with [Claude Code](https://docs.anthropic.com/en/docs/claude-code) through MCP tools and a PreToolUse hook. The `roe-gate pentest` command handles all the wiring automatically.

### Gated MCP Tools

The agent gets 7 gated tools instead of direct shell access:

| MCP Tool | Purpose |
|---|---|
| `roe_nmap_scan` | Port scanning |
| `roe_http_request` | HTTP requests (GET, POST, etc.) |
| `roe_dns_lookup` | DNS resolution |
| `roe_service_probe` | Service/banner probing |
| `roe_directory_scan` | Web directory enumeration |
| `roe_sql_injection_test` | SQL injection testing |
| `roe_shell_command` | Arbitrary commands (all gated) |

### Four-Tier Command Gating

A PreToolUse hook intercepts all Bash calls with four tiers of enforcement:

| Tier | Check | Example |
|------|-------|---------|
| **0** | Safe command allowlist | `ls`, `cat`, `grep` — allowed immediately |
| **1** | Known network tools | `nmap`, `curl`, `sqlmap` — denied, suggests MCP tool |
| **2** | Target extraction | `python3 -c "s.connect(('10.0.0.5', 80))"` — IP detected, denied |
| **3** | Embedded tool detection | `bash -c "nmap 10.0.0.5"` — tool name in args, denied |

This catches bypass attempts through Python, Perl, Ruby, bash redirections (`/dev/tcp`), and arbitrary binaries.

### Human-in-the-Loop

Enable HITL mode for actions that require human approval:

```bash
roe-gate pentest --roe my_roe.yaml --hitl
```

When the gate encounters a `REQUIRE_APPROVAL` action, it pauses and waits for human sign-off via the dashboard or API.

---

## Use with Any Agent Framework

ROE Gate is agent-agnostic. Use the HTTP API directly from any language:

```python
import requests

# Evaluate an action
response = requests.post("http://localhost:19990/api/v1/evaluate", json={
    "action": {
        "tool": "nmap",
        "category": "PORT_SCANNING",
        "target_host": "10.0.0.5",
        "target_port": 80,
        "parameters": {"flags": ["-sV", "-p", "80"]}
    }
})

result = response.json()
if result["decision"] == "ALLOW":
    exec_response = requests.post("http://localhost:19990/api/v1/execute", json={
        "token": result["token"],
        "command": "nmap",
        "args": ["-sV", "-p", "80", "10.0.0.5"]
    })
    print(exec_response.json()["stdout"])
```

Or use the Python API:

```python
import yaml
from src.gate.gate import ROEGate
from src.core.action_intent import ActionIntent, ActionCategory, Target
from src.core.providers import AnthropicProvider
from src.tools.executor import ToolExecutor

with open("examples/local_corp_roe.yaml") as f:
    roe_spec = yaml.safe_load(f)["roe"]

provider = AnthropicProvider(api_key="sk-ant-...", model="claude-sonnet-4-6")

gate = ROEGate(roe_spec=roe_spec, llm_provider=provider)
executor = ToolExecutor(signer=gate.signer, roe_hash=gate.roe_hash)

intent = ActionIntent(
    tool="nmap", args=["-sV", "-p", "80", "10.0.0.1"],
    category=ActionCategory.RECONNAISSANCE,
    target=Target(host="10.0.0.1", port=80),
    description="Port scan of web app subnet",
)

decision = gate.evaluate(intent)
print(decision.decision)    # ALLOW, DENY, or HALT
print(decision.reasoning)   # Why the decision was made
```

---

## Multi-Vendor Judge LLM

The Judge LLM can run on any provider — choose based on your privacy, cost, and latency requirements:

| Provider | Install | Notes |
|---|---|---|
| **Anthropic** (Claude) | `pip install -e ".[anthropic]"` | Claude Sonnet, Opus |
| **OpenAI** (GPT-4) | `pip install -e ".[openai]"` | GPT-4o, o1, any OpenAI-compatible API |
| **Claude Agent SDK** | `pip install -e ".[claude-agent-sdk]"` | Claude Code integration |
| **HuggingFace Transformers** | `pip install -e ".[transformers]"` | Local models with GPU |
| **llama.cpp** | `pip install -e ".[llama-cpp]"` | Local GGUF models, CPU or GPU |
| **Ollama** | Base install | Any Ollama-served model |
| **Hybrid** (Local + Cloud) | Both extras | Local first, cloud fallback for low-confidence |
| **Mock** | Base install | Deterministic, for testing |

```bash
# Install all providers at once
pip install -e ".[all-providers]"
```

---

## CLI Reference

```bash
roe-gate pentest --roe <file>              # Launch gated pentest agent (gate + MCP + Claude Code)
roe-gate pentest --roe <file> --dashboard  # Same, with real-time audit dashboard
roe-gate pentest --roe <file> --dry-run    # Start gate service only, print config
roe-gate pentest --roe <file> --hitl       # Enable human-in-the-loop approval
roe-gate creator                           # Open the ROE Creator web form
roe-gate validate <file>                   # Validate a ROE specification file
roe-gate demo                              # Run the built-in demo scenario
roe-gate info                              # Print system info and available providers
```

---

## Project Structure

```
src/
├── core/           # Rule engine, judge LLM, action intents, LLM providers
├── gate/           # Gate orchestrator (evaluate → sign → execute pipeline)
├── crypto/         # HMAC-SHA256 and Ed25519 token signing/verification
├── service/        # HTTP API server, MCP server, dashboard, ROE creator
├── tools/          # Tool executor with token verification
├── audit/          # Event logging
├── agents/         # Agent framework and config
└── licensing/      # Tier definitions

examples/           # ROE specs, agent configs, launch scripts
tests/              # 289 tests
```

## Tests

```bash
pip install -e ".[dev]"
python -m pytest tests/ -v
```

---

## Commercial Licensing

The **Community Edition** is free and MIT-licensed for personal use, research, learning, and CTFs. It includes the full gate engine with no feature restrictions.

**Commercial use** by organizations requires a paid license:

| Tier | For | Includes |
|---|---|---|
| **Pro** | Security teams running AI agents on live engagements | Multi-ROE management, structured audit logging, alerting |
| **Enterprise** | Large organizations with multiple teams | Unlimited ROEs, custom integrations, dedicated support, SLA |
| **MSSP/OEM** | Managed security providers and vendors | Multi-tenant, white-label, patent license for redistribution |

See [roegate.io](https://roegate.io) for pricing or contact [rick@greylineinteractive.com](mailto:rick@greylineinteractive.com).

## License

[MIT](LICENSE) — See license for usage terms.

---

Built by [Grey Line Interactive](https://roegate.io)
