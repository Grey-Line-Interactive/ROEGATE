# ROE Gate — Start Guide: OpenAI / GPT-4o Agent

> **Tester provider:** `openai` (OpenAI API or any OpenAI-compatible endpoint)
> **Judge provider:** `openai` or `anthropic`
> **Best for:** Teams already standardized on GPT-4o, Azure OpenAI, or any OpenAI-compatible inference server (Together AI, Groq, vLLM, LM Studio).

---

## Scenario

Throughout this guide you will set up a complete, end-to-end gated penetration test of a fictitious staging environment:

| Target | Address | Notes |
|---|---|---|
| `webapp.corp.local` | `192.168.100.10` ports 80, 443 | Primary web application |
| `intranet.corp.local` | `192.168.100.20` port 8080 | Internal intranet portal |
| `api.corp.local` | `192.168.101.10` ports 8080, 8443 | REST API |
| **OUT OF SCOPE** | `192.168.200.0/24` | Production DB tier |
| **OUT OF SCOPE** | `192.168.201.0/24` | Payments (PCI DSS) |

Quick Docker targets:

```bash
docker run -d -p 80:80 --name dvwa vulnerables/web-dvwa
docker run -d -p 3000:3000 --name juiceshop bkimminich/juice-shop
echo "127.0.0.1 webapp.corp.local" | sudo tee -a /etc/hosts
echo "127.0.0.1 api.corp.local"    | sudo tee -a /etc/hosts
```

---

## Part 1 — Prerequisites

### System Requirements

- Python 3.10+
- pip 23+
- `curl` and `nmap` installed
- macOS, Linux, or WSL2

### OpenAI API Key

Get your API key from [platform.openai.com](https://platform.openai.com/):

1. Sign in → **API keys** → **Create new secret key**
2. Copy the key (starts with `sk-`)

Export it:

```bash
export OPENAI_API_KEY="sk-..."
```

Add to your shell profile:

```bash
echo 'export OPENAI_API_KEY="sk-..."' >> ~/.zshrc
source ~/.zshrc
```

Verify:

```bash
curl https://api.openai.com/v1/models \
  -H "Authorization: Bearer $OPENAI_API_KEY" | jq '.data[0].id'
```

#### Using Azure OpenAI

If you're using Azure OpenAI, set:

```bash
export OPENAI_API_KEY="your-azure-key"
export OPENAI_BASE_URL="https://YOUR_RESOURCE.openai.azure.com/openai/deployments/YOUR_DEPLOYMENT"
```

#### Using OpenAI-Compatible APIs (Groq, Together, vLLM, LM Studio)

```bash
# Groq
export OPENAI_API_KEY="gsk_..."
export OPENAI_BASE_URL="https://api.groq.com/openai/v1"

# Together AI
export OPENAI_API_KEY="..."
export OPENAI_BASE_URL="https://api.together.xyz/v1"

# Local vLLM server
export OPENAI_API_KEY="dummy"        # vLLM doesn't check this
export OPENAI_BASE_URL="http://localhost:8000/v1"

# LM Studio
export OPENAI_API_KEY="dummy"
export OPENAI_BASE_URL="http://localhost:1234/v1"
```

---

## Part 2 — Install ROE Gate

```bash
# Clone the repository
git clone https://github.com/Grey-Line-Interactive/ROEGATE.git
cd ROEGATE

# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# Install ROE Gate
pip install -e .

# Install OpenAI package (if not already installed as a dependency)
pip install openai

# Verify
roe-gate --help
```

---

## Part 3 — Build Your ROE Specification with ROE Gate Creator

### Launch the Creator

```bash
roe-gate creator
# Starts a local server and opens http://127.0.0.1:19990 in your browser
# Press Ctrl+C when done
```

### Fill Out the Form

**Metadata**
- Engagement ID: `ENG-2025-001`
- Client: `CorpSec Labs`
- Approved By: `Jane Smith, CISO`

**Scope → In Scope → Networks**
- `192.168.100.0/24` — "Web app staging" — ports `80,443,8080`
- `192.168.101.0/24` — "API staging" — ports `8080,8443`

**Scope → In Scope → Domains**
- `*.corp.local` (include subdomains)

**Scope → Out of Scope → Networks**
- `192.168.200.0/24` — "Production DB tier"
- `192.168.201.0/24` — "Payments — PCI DSS"

**Actions → Allowed**
- `reconnaissance` — port_scan, service_enumeration, dns_lookup, directory_enumeration
- `web_application_testing` — sql_injection, xss, csrf, authentication_bypass
- `api_testing` — parameter_fuzzing, authentication_testing, injection_testing

**Actions → Denied**
- `denial_of_service`, `data_exfiltration`, `lateral_movement`, `persistence`

**Emergency:** kill switch enabled, max consecutive denials: `5`

Export and save as `examples/corpsec_labs_roe.yaml`, then:

```bash
roe-gate validate examples/corpsec_labs_roe.yaml
```

> **Shortcut:** `examples/corpsec_labs_roe.yaml` is already provided for this scenario.

---

## Part 4 — Configure roe_gate_config.yaml

```bash
cp examples/roe_gate_config.yaml my_pentest_config.yaml
```

### Standard OpenAI (GPT-4o)

```yaml
tester:
  provider: "openai"
  model: "gpt-4o"
  api_key_env: "OPENAI_API_KEY"
  max_turns: 50
  temperature: 0.1

judge:
  provider: "openai"
  model: "gpt-4o-mini"        # cheaper model is fine for the judge
  api_key_env: "OPENAI_API_KEY"

gate:
  roe: "examples/corpsec_labs_roe.yaml"
  port: 19990
  signing: "hmac"
  hitl: false
  dashboard: true
```

### Azure OpenAI

```yaml
tester:
  provider: "openai"
  model: "gpt-4o"
  api_key_env: "OPENAI_API_KEY"
  base_url: "https://YOUR_RESOURCE.openai.azure.com/openai/deployments/gpt-4o"
  max_turns: 50
  temperature: 0.1

judge:
  provider: "openai"
  model: "gpt-4o-mini"
  api_key_env: "OPENAI_API_KEY"
  base_url: "https://YOUR_RESOURCE.openai.azure.com/openai/deployments/gpt-4o-mini"

gate:
  roe: "examples/corpsec_labs_roe.yaml"
  port: 19990
  signing: "hmac"
  hitl: false
  dashboard: true
```

### Groq (fast inference)

```yaml
tester:
  provider: "openai"
  model: "llama-3.3-70b-versatile"
  api_key_env: "OPENAI_API_KEY"     # set to GROQ_API_KEY value
  base_url: "https://api.groq.com/openai/v1"
  max_turns: 50

judge:
  provider: "openai"
  model: "llama-3.1-8b-instant"
  api_key_env: "OPENAI_API_KEY"
  base_url: "https://api.groq.com/openai/v1"

gate:
  roe: "examples/corpsec_labs_roe.yaml"
  port: 19990
  signing: "hmac"
  hitl: false
  dashboard: true
```

> **Tip:** Using a cheap model (`gpt-4o-mini`, `llama-3.1-8b`) for the judge and a stronger model (`gpt-4o`, `llama-3.3-70b`) for the tester is a cost-effective pattern. The judge just needs to reason about ROE compliance — it doesn't need to be highly capable.

---

## Part 5 — Launch Your First Gated Pentest

### Dry Run

```bash
roe-gate pentest --config my_pentest_config.yaml --dry-run
```

Expected:

```
  ROE Gate v0.1.0
  ────────────────────────────────────────
  ROE:       examples/corpsec_labs_roe.yaml
  Judge:     openai (gpt-4o-mini)
  Tester:    openai (gpt-4o)
  Signing:   HMAC-SHA256
  Dashboard: http://127.0.0.1:19990/dashboard
  ────────────────────────────────────────
  [Gate] Gate service started (dry-run mode)
  [Gate] Rule Engine ready.
  [Gate] Judge LLM (openai) ready.
  [Gate] Signer ready.
```

### Live Pentest

```bash
roe-gate pentest --config my_pentest_config.yaml
```

### Custom Objective

```bash
roe-gate pentest \
  --config my_pentest_config.yaml \
  --objective "Perform a comprehensive web application security test of webapp.corp.local (192.168.100.10) and the REST API at api.corp.local (192.168.101.10). Start with reconnaissance, then test for SQL injection, XSS, broken authentication, and API security issues. Document all findings."
```

### CLI Overrides

```bash
# Use GPT-4o-mini tester for faster/cheaper runs
roe-gate pentest --config my_pentest_config.yaml --model gpt-4o-mini

# Enable human approval for critical actions
roe-gate pentest --config my_pentest_config.yaml --human-in-the-loop

# Use a different port
roe-gate pentest --config my_pentest_config.yaml --gate-port 19991
```

---

## Part 6 — Using the Audit Dashboard

Navigate to `http://127.0.0.1:19990/dashboard`.

### Decision Feed

Each row shows:
- **[ALLOW]** — within ROE, token issued, tool ran
- **[DENY]** — violated ROE, tool blocked
- **[ESCALATE]** — `requires_approval` action, awaiting human input

Expand any entry to see:
- Judge's reasoning (from GPT-4o-mini)
- ROE clauses cited
- Token ID
- Tool, target, parameters

### What a GPT-4o Pentest Looks Like

GPT-4o tends to be methodical and thorough. Typical sequence you'll see:

1. `nmap -sV 192.168.100.10` → `[ALLOW] reconnaissance`
2. `gobuster dir -u http://webapp.corp.local` → `[ALLOW] reconnaissance`
3. `nikto -h webapp.corp.local` → `[ALLOW] web_application_testing`
4. `sqlmap -u "http://webapp.corp.local/login"` → `[ALLOW] web_application_testing`
5. `curl http://192.168.200.5` → `[DENY] out_of_scope (production DB tier)`

The final DENY demonstrates the gate working — GPT-4o tried to pivot to an out-of-scope host and was blocked.

### Emergency Halt

The red **Emergency Halt** button denies all further tool calls instantly. Use it if the agent behaves unexpectedly.

---

## Part 7 — Human-in-the-Loop (HITL) Approval

```bash
roe-gate pentest --config my_pentest_config.yaml --human-in-the-loop
```

When GPT-4o requests a critical action (e.g., exploiting a critical CVE, credential stuffing beyond limits), the dashboard shows it in amber:

```
[ESCALATE] sqlmap --level=5 --risk=3 → webapp.corp.local:443
Category:  critical_exploitation (CVSS 9.8)
Reasoning: Agent is attempting a high-intensity SQL injection sweep
           that could impact service availability.
⏱ 4:47 remaining
[Approve] [Deny]
```

Review the full reasoning, then **Approve** or **Deny**. If the timer (set in your ROE's `timeout_seconds`) expires, the action is denied automatically.

---

## Part 8 — Exporting Audit Events

### Dashboard Export

- **Export JSON** button → downloads `roe_gate_audit_TIMESTAMP.json`
- **Export CSV** button → downloads `roe_gate_audit_TIMESTAMP.csv`

### API Export

```bash
# JSON
curl http://127.0.0.1:19990/api/v1/audit | jq .

# CSV
curl -o audit.csv http://127.0.0.1:19990/api/v1/audit/export

# Stats
curl http://127.0.0.1:19990/api/v1/stats | jq '{
  total: .total_decisions,
  allowed: .allow_count,
  denied: .deny_count,
  escalated: .escalate_count
}'
```

### Sample CSV Output

```csv
timestamp,event_type,decision,tool,category,target_host,target_port,reasoning
2025-01-15T14:32:01,action_evaluation,ALLOW,nmap,reconnaissance,192.168.100.10,80,...
2025-01-15T14:32:09,action_evaluation,ALLOW,gobuster,reconnaissance,webapp.corp.local,80,...
2025-01-15T14:32:45,action_evaluation,ALLOW,sqlmap,web_application_testing,webapp.corp.local,443,...
2025-01-15T14:33:10,action_evaluation,DENY,curl,direct_database_access,192.168.200.5,5432,...
```

---

## Part 9 — Alerting (Optional)

```yaml
gate:
  slack_webhook: "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
  webhook_url: "https://your-siem.internal/events"
```

---

## Part 10 — After the Test

1. Export the audit log (JSON + CSV)
2. Review DENY decisions — scope boundary enforcement proof
3. Review ESCALATE decisions — high-severity findings
4. Press `Ctrl+C` to shut down
5. Review the terminal output for the agent's final report

---

## Troubleshooting

**`401 Unauthorized` from OpenAI API**

```bash
echo $OPENAI_API_KEY
curl https://api.openai.com/v1/models -H "Authorization: Bearer $OPENAI_API_KEY"
```

**`Model not found` error**

Check that your model name is correct for your account tier:

```bash
curl https://api.openai.com/v1/models \
  -H "Authorization: Bearer $OPENAI_API_KEY" | jq '[.data[].id | select(startswith("gpt-4"))]'
```

**Azure `DeploymentNotFound`**

Your `base_url` must include the deployment name:

```
https://YOUR_RESOURCE.openai.azure.com/openai/deployments/YOUR_DEPLOYMENT_NAME
```

**`openai.RateLimitError`**

GPT-4o has rate limits on lower API tiers. Switch to `gpt-4o-mini` for the tester, or reduce `max_turns`:

```yaml
tester:
  model: "gpt-4o-mini"
  max_turns: 20
```

**Agent makes no progress**

Check for DENY decisions in the dashboard. The ROE may be too restrictive for your actual lab environment. Ensure your lab targets match the `in_scope` networks in `corpsec_labs_roe.yaml`.

---

## Next Steps

- Try the judge with `claude-cli` or `anthropic` for cross-provider validation
- Use Groq's API for significantly faster tester inference at lower cost
- Add `slack_webhook` for real-time DENY alerts
- Try `examples/multi_vendor_pentest.py` to use GPT-4o as tester and Claude as judge simultaneously

**Other START Guides:**
- [`START_claude_code.md`](START_claude_code.md) — Claude Code tester (MCP integration)
- [`START_anthropic_api.md`](START_anthropic_api.md) — Anthropic API tester
- [`START_ollama.md`](START_ollama.md) — Ollama local model tester
