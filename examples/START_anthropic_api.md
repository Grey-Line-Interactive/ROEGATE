# ROE Gate — Start Guide: Anthropic API Agent

> **Tester provider:** `anthropic` (direct Anthropic API calls)
> **Judge provider:** `anthropic` (Anthropic API, isolated context)
> **Best for:** Production pipelines and CI/CD integrations where you want a fully API-driven, headless pentest agent without a local Claude Code install.

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

Replace these with your own lab IPs. Quick Docker targets:

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
- `curl` and `nmap` installed (for the agent to use)
- macOS, Linux, or WSL2

### Anthropic API Key

Get your API key from the [Anthropic Console](https://console.anthropic.com/):

1. Sign in → **API Keys** → **Create Key**
2. Copy the key (starts with `sk-ant-`)

Export it:

```bash
export ANTHROPIC_API_KEY="sk-ant-api03-..."
```

Add to your shell profile to persist:

```bash
echo 'export ANTHROPIC_API_KEY="sk-ant-api03-..."' >> ~/.zshrc
source ~/.zshrc
```

Verify:

```bash
curl https://api.anthropic.com/v1/models \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "anthropic-version: 2023-06-01" | jq '.models[0].id'
# "claude-sonnet-4-6-20250929" or similar
```

---

## Part 2 — Install ROE Gate

```bash
# Clone the repository
git clone https://github.com/Grey-Line-Interactive/ROEGATE.git
cd ROEGATE

# Create and activate a virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# Install ROE Gate and all dependencies
pip install -e .

# Verify the installation
roe-gate --help
```

Expected output:

```
usage: roe-gate [-h] {pentest,validate,demo,info} ...

ROE Gate — Rules of Engagement Enforcement for AI Pentest Agents
...
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
- `192.168.201.0/24` — "Payment processing — PCI DSS"

**Actions → Allowed**
- `reconnaissance` — port_scan, service_enumeration, dns_lookup, directory_enumeration
- `web_application_testing` — sql_injection, xss, csrf, authentication_bypass
- `api_testing` — parameter_fuzzing, authentication_testing, injection_testing

**Actions → Denied**
- `denial_of_service`, `data_exfiltration`, `lateral_movement`, `persistence`

**Emergency**
- Kill switch: enabled
- Max consecutive denials: `5`

Export and save as `examples/corpsec_labs_roe.yaml`, then validate:

```bash
roe-gate validate examples/corpsec_labs_roe.yaml
```

> **Shortcut:** The file `examples/corpsec_labs_roe.yaml` is already provided and ready to use.

---

## Part 4 — Configure roe_gate_config.yaml

```bash
cp examples/roe_gate_config.yaml my_pentest_config.yaml
```

Edit `my_pentest_config.yaml` for the Anthropic API:

```yaml
# Pentest agent — Anthropic API drives the test
tester:
  provider: "anthropic"
  model: "claude-sonnet-4-6"
  api_key_env: "ANTHROPIC_API_KEY"
  max_turns: 50
  temperature: 0.1

# Judge LLM — separate Anthropic API call, isolated from agent context
judge:
  provider: "anthropic"
  model: "claude-sonnet-4-6"
  api_key_env: "ANTHROPIC_API_KEY"

# Gate service
gate:
  roe: "examples/corpsec_labs_roe.yaml"
  port: 19990
  signing: "hmac"
  hitl: false
  dashboard: true
```

> **Cost note:** Both the tester and judge consume API tokens. Each gate evaluation calls the judge once. A typical 50-turn pentest session uses roughly 50,000–150,000 tokens total (tester + judge). Monitor usage in the Anthropic Console.

---

## Part 5 — Launch Your First Gated Pentest

### Dry Run

```bash
roe-gate pentest --config my_pentest_config.yaml --dry-run
```

You should see:

```
  ROE Gate v0.1.0
  ────────────────────────────────────────
  ROE:       examples/corpsec_labs_roe.yaml
  Judge:     anthropic (claude-sonnet-4-6)
  Tester:    anthropic (claude-sonnet-4-6)
  Signing:   HMAC-SHA256
  Dashboard: http://127.0.0.1:19990/dashboard
  ────────────────────────────────────────
  [Gate] Gate service started (dry-run mode)
  [Gate] Rule Engine ready.
  [Gate] Judge LLM (anthropic) ready.
  [Gate] Signer ready.
  [DRY-RUN] Agent not launched. Gate is live.
```

### Live Pentest

```bash
roe-gate pentest --config my_pentest_config.yaml
```

### Custom Objective

```bash
roe-gate pentest \
  --config my_pentest_config.yaml \
  --objective "Assess the security of webapp.corp.local (192.168.100.10). Begin with reconnaissance, enumerate services, then test for OWASP Top 10 vulnerabilities. Also assess api.corp.local (192.168.101.10) for API security issues."
```

### CLI Overrides

Any flag on the CLI overrides the config file:

```bash
# Switch to a faster/cheaper model for tester
roe-gate pentest --config my_pentest_config.yaml --model claude-haiku-4-5

# Enable HITL approval on the fly
roe-gate pentest --config my_pentest_config.yaml --human-in-the-loop

# Change the gate port
roe-gate pentest --config my_pentest_config.yaml --gate-port 19991
```

---

## Part 6 — Using the Audit Dashboard

Navigate to `http://127.0.0.1:19990/dashboard` once the gate is running.

### Reading the Decision Feed

Each entry shows:
- **[ALLOW]** — action was within ROE, token issued, tool executed
- **[DENY]** — action violated ROE (scope, category, or timing), tool blocked
- **[ESCALATE]** — action in `requires_approval` category, awaiting human input

Click any entry to expand it and see:
- Judge's full reasoning
- ROE clauses referenced
- Cryptographic token ID (for ALLOW decisions)
- Tool name, target, and parameters

### Watching the Agent Work

With the Anthropic API tester, the agent issues tool calls via the API and each one flows through the gate before execution. You'll see the dashboard populate in real time as the agent progresses through:

1. Port scanning (`nmap` → `reconnaissance` category)
2. Service enumeration (`curl` banner grabs)
3. Directory busting (`gobuster` or `ffuf`)
4. Web vulnerability testing (`sqlmap`, `nikto`)
5. API fuzzing (`curl`, `ffuf`)

Any attempt to hit an out-of-scope target (e.g., `192.168.200.x`) will appear as a `DENY` with the rule cited.

### Emergency Halt

The **Emergency Halt** button (top right, red) immediately sets the gate to deny-all mode. Use it if the agent is doing something unexpected.

---

## Part 7 — Human-in-the-Loop (HITL) Approval

Enable HITL to manually approve critical actions before they execute.

```bash
roe-gate pentest --config my_pentest_config.yaml --human-in-the-loop
```

Or set in config:

```yaml
gate:
  hitl: true
```

When the agent requests an action with a CVSS ≥ 9.0 exploit or credential testing beyond the limit, the dashboard will highlight it in amber as `ESCALATE`. You'll see:

```
[ESCALATE] sqlmap → webapp.corp.local:443
Reason: Critical SQLi exploit — CVSS 9.8 — requires human approval
⏱ 4:52 remaining
[Approve] [Deny]
```

Click **Approve** to issue the cryptographic token. Click **Deny** to block it. If the timer expires with no response, the action is denied automatically.

---

## Part 8 — Exporting Audit Events

### From the Dashboard

- **Export JSON** — full audit log with all fields (click in dashboard)
- **Export CSV** — spreadsheet-friendly format

### Via API

```bash
# JSON audit log
curl http://127.0.0.1:19990/api/v1/audit | jq '.[0:5]'

# CSV download
curl -o pentest_audit.csv http://127.0.0.1:19990/api/v1/audit/export

# Stats summary
curl http://127.0.0.1:19990/api/v1/stats | jq .
```

### SOC2 Compliance Report

```bash
curl -X POST http://127.0.0.1:19990/api/v1/compliance/soc2 \
  -H "Content-Type: application/json" \
  -d '{"engagement_id": "ENG-2025-001"}' | jq .
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

1. Export audit log (JSON + CSV)
2. Review DENY decisions — these are boundary enforcement events
3. Review ESCALATE decisions — these are the high-severity findings
4. Press `Ctrl+C` to shut down the gate service cleanly
5. Check the agent's terminal output for findings summary

---

## Troubleshooting

**`401 Unauthorized` from Anthropic API**

```bash
# Check key is set
echo $ANTHROPIC_API_KEY

# Test directly
curl https://api.anthropic.com/v1/messages \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -H "Content-Type: application/json" \
  -d '{"model":"claude-haiku-4-5-20251001","max_tokens":10,"messages":[{"role":"user","content":"hi"}]}'
```

**Agent runs but immediately stops**

The Anthropic API tester requires `anthropic` package version ≥ 0.40:

```bash
pip install --upgrade anthropic
```

**`Rate limit exceeded`**

The Anthropic API has per-minute token limits. Reduce agent speed:

```yaml
tester:
  max_turns: 20    # fewer turns per session
  temperature: 0.1
```

Or use a Tier 2+ Anthropic account for higher rate limits.

**Gate port conflict**

```bash
roe-gate pentest --config my_pentest_config.yaml --gate-port 19991
```

---

## Next Steps

- Try `--human-in-the-loop` to manually approve critical exploits
- Switch the judge to `claude-cli` to save API costs while keeping the tester on the API
- Explore `examples/multi_vendor_pentest.py` to chain providers
- Try the other START guides to compare providers

**Other START Guides:**
- [`START_claude_code.md`](START_claude_code.md) — Claude Code tester (MCP integration)
- [`START_openai.md`](START_openai.md) — OpenAI / GPT-4o tester
- [`START_ollama.md`](START_ollama.md) — Ollama local model tester
