# ROE Gate — Start Guide: Claude Code Agent

> **Tester provider:** `claude-code` (Claude Agent SDK + MCP Server)
> **Judge provider:** `claude-cli` (Claude subscription, no API key required)
> **Best for:** Maximum integration — Claude Code drives the pentest through the MCP tool layer with full PreToolUse enforcement hooks.

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

Replace these with your own lab IPs. A quick way to get a realistic target is Docker:

```bash
# DVWA — classic web app vuln lab
docker run -d -p 80:80 --name dvwa vulnerables/web-dvwa

# OWASP Juice Shop — modern vulnerable node app
docker run -d -p 3000:3000 --name juiceshop bkimminich/juice-shop

# Map to corp.local in /etc/hosts
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

### Install Claude Code CLI

```bash
npm install -g @anthropic-ai/claude-code
```

Authenticate (one-time):

```bash
claude
# Follow the browser OAuth prompt to authenticate your Anthropic account.
# Claude Code will store credentials at ~/.claude/
```

Verify:

```bash
claude --version
# Claude Code 1.x.x
```

### API Key (for the Judge LLM)

The **judge** in this guide uses `claude-cli` (your Claude subscription). No extra API key is needed.

If you prefer the judge to use the Anthropic API instead, export:

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
```

Add to your shell profile (`~/.zshrc` or `~/.bashrc`) to persist it.

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

Install the Claude Agent SDK (required for claude-code tester):

```bash
pip install claude-agent-sdk
```

---

## Part 3 — Build Your ROE Specification with ROE Gate Creator

The **ROE Gate Creator** is a browser-based visual form builder that generates your YAML specification. No YAML knowledge required.

### Launch the Creator

```bash
roe-gate creator
# Starts a local server and opens http://127.0.0.1:19990 in your browser
# Press Ctrl+C when done
```

### Fill Out the Form

Using the Creator UI, enter the following for the CorpSec Labs scenario:

**Metadata tab**
- Engagement ID: `ENG-2025-001`
- Client: `CorpSec Labs`
- Approved By: `Jane Smith, CISO`

**Scope → In Scope → Networks**
- Add: `192.168.100.0/24` — "Web app staging subnet" — ports `80,443,8080`
- Add: `192.168.101.0/24` — "API staging subnet" — ports `8080,8443`

**Scope → In Scope → Domains**
- Add: `*.corp.local` (check "Include subdomains")

**Scope → Out of Scope → Networks**
- Add: `192.168.200.0/24` — reason: "Production DB tier"
- Add: `192.168.201.0/24` — reason: "Payment processing — PCI DSS"

**Actions → Allowed**
- `reconnaissance` — methods: port_scan, service_enumeration, dns_lookup, directory_enumeration
- `web_application_testing` — methods: sql_injection, xss, csrf, authentication_bypass, idor
- `api_testing` — methods: parameter_fuzzing, authentication_testing, injection_testing

**Actions → Denied**
- `denial_of_service`
- `data_exfiltration`
- `lateral_movement`
- `persistence`

**Actions → Requires Approval**
- `critical_exploitation` — condition: CVSS >= 9.0 — timeout: 300s — on timeout: deny

**Emergency**
- Enable kill switch
- Max consecutive denials: `5`

Click **Export YAML** and save as `examples/corpsec_labs_roe.yaml`.

> **Tip:** The example file `examples/corpsec_labs_roe.yaml` is already filled out for this scenario. You can use it directly or use it as a reference while exploring the Creator.

Validate your ROE before using it:

```bash
roe-gate validate examples/corpsec_labs_roe.yaml
```

Expected:

```
✓ ROE specification is valid
  Engagement: ENG-2025-001 (CorpSec Labs)
  In-scope networks: 2  |  Domains: 4
  Allowed categories: 3  |  Denied: 6  |  Requires approval: 1
```

---

## Part 4 — Configure roe_gate_config.yaml

Copy the template and edit it:

```bash
cp examples/roe_gate_config.yaml my_pentest_config.yaml
```

Edit `my_pentest_config.yaml`:

```yaml
# Pentest agent — Claude Code drives the test via MCP
tester:
  provider: "claude-code"
  model: "claude-sonnet-4-6"
  api_key_env: "ANTHROPIC_API_KEY"   # optional if using claude-cli auth
  max_turns: 50
  temperature: 0.1

# Judge LLM — runs in isolation, never sees the agent's context
judge:
  provider: "claude-cli"             # uses your Claude subscription
  model: "claude-sonnet-4-6"

# Gate service
gate:
  roe: "examples/corpsec_labs_roe.yaml"
  port: 19990
  signing: "hmac"
  hitl: false          # set true to enable human approval prompts
  dashboard: true      # open the real-time audit dashboard
```

> **Note on `hitl`:** When `hitl: true`, actions in the `requires_approval` ROE category
> will pause and prompt you in the dashboard before executing. Set it `false` for fully
> autonomous runs, `true` when you want to manually approve critical exploits.

---

## Part 5 — Launch Your First Gated Pentest

### Dry Run (verify everything is wired up)

```bash
roe-gate pentest --config my_pentest_config.yaml --dry-run
```

This starts the gate service and validates the configuration without launching the agent. You should see:

```
  ROE Gate v0.1.0
  ────────────────────────────────────────
  ROE:       examples/corpsec_labs_roe.yaml
  Judge:     claude-cli (claude-sonnet-4-6)
  Tester:    claude-code (claude-sonnet-4-6)
  Signing:   HMAC-SHA256
  Dashboard: http://127.0.0.1:19990/dashboard
  ────────────────────────────────────────
  [Gate] Gate service started (dry-run mode)
  [Gate] Rule Engine ready.
  [Gate] Judge LLM ready.
  [Gate] Signer ready.
  [DRY-RUN] Agent not launched. Gate is live.
```

Open `http://127.0.0.1:19990/dashboard` — you should see the empty audit dashboard with green status indicators.

Press `Ctrl+C` to stop.

### Live Pentest

```bash
roe-gate pentest --config my_pentest_config.yaml
```

ROE Gate will:

1. Start the gate service on port 19990
2. Load and validate `corpsec_labs_roe.yaml`
3. Initialize the HMAC signer and judge LLM
4. Launch Claude Code with MCP gated tools
5. Open the audit dashboard in your browser

The agent will begin reconnaissance automatically. Watch the dashboard populate with decisions in real time.

### Custom Objective

Pass a specific objective to focus the agent:

```bash
roe-gate pentest \
  --config my_pentest_config.yaml \
  --objective "Perform a web application security assessment of webapp.corp.local. Start with port scanning and service enumeration, then test for OWASP Top 10 vulnerabilities. Prioritize SQL injection and authentication bypass."
```

### Useful CLI Flags

```bash
# Enable human-in-the-loop approval at runtime (overrides config)
roe-gate pentest --config my_pentest_config.yaml --human-in-the-loop

# Verbose logging (see full gate decision details)
roe-gate pentest --config my_pentest_config.yaml --verbose

# Use a different port if 19990 is busy
roe-gate pentest --config my_pentest_config.yaml --gate-port 19991

# Use Ed25519 signing instead of HMAC
roe-gate pentest --config my_pentest_config.yaml --signing-algo ed25519
```

---

## Part 6 — Using the Audit Dashboard

The dashboard at `http://127.0.0.1:19990/dashboard` gives you real-time visibility into every gate decision.

### What You'll See

**Status Bar (top)**
- Gate health (green = online)
- Total decisions made
- ALLOW / DENY / ESCALATE counts
- Active agent session

**Decision Feed (main panel)**
Each row shows:
- Timestamp
- Decision (`ALLOW` / `DENY` / `ESCALATE`)
- Tool called (e.g., `nmap`, `curl`, `sqlmap`)
- Category (e.g., `reconnaissance`, `web_application_testing`)
- Target host + port
- Truncated reasoning from the judge

Click any row to expand the full decision, including:
- Complete judge reasoning
- ROE clauses cited
- Cryptographic token ID (if issued)
- Action parameters

**Emergency Halt Button**
The red **Emergency Halt** button at the top right immediately stops all gate approvals. Any subsequent tool calls will be denied regardless of ROE. Use this if the agent starts behaving unexpectedly.

---

## Part 7 — Human-in-the-Loop (HITL) Approval

When `hitl: true` is set (or `--human-in-the-loop` is passed), actions in the ROE's `requires_approval` category will **pause** and appear in the dashboard as `ESCALATE`.

### Enabling HITL

```bash
roe-gate pentest --config my_pentest_config.yaml --human-in-the-loop
```

Or in `my_pentest_config.yaml`:
```yaml
gate:
  hitl: true
```

### Approving Actions

When the agent requests an action needing approval (e.g., a critical exploit with CVSS ≥ 9.0), the dashboard will show it highlighted in amber with **Approve** and **Deny** buttons.

1. Click the escalated action in the dashboard to expand it
2. Review the full reasoning, tool, target, and parameters
3. Click **Approve** to issue the cryptographic token and allow execution
4. Click **Deny** to block the action

The agent will wait up to the ROE's `timeout_seconds` (default: 300 seconds). If you don't respond, the action is automatically denied.

> **HITL workflow tip:** Keep the dashboard open in a second monitor. The agent runs independently — it won't freeze, it just won't execute that specific action until you respond.

---

## Part 8 — Exporting Audit Events

### Export as JSON

In the dashboard, click **Export JSON**. Your browser will download:

```
roe_gate_audit_2025-01-15T14-30-00.json
```

The JSON contains the full audit log array with all fields.

### Export as CSV

Click **Export CSV** for a spreadsheet-compatible format:

```csv
timestamp,event_type,decision,tool,category,target_host,target_port,reasoning,token_issued,...
2025-01-15T14:32:01,action_evaluation,ALLOW,nmap,reconnaissance,192.168.100.10,80,...
2025-01-15T14:32:05,action_evaluation,ALLOW,curl,web_application_testing,webapp.corp.local,443,...
2025-01-15T14:32:09,action_evaluation,DENY,psql,direct_database_access,192.168.200.5,5432,...
```

### Export via API

```bash
# Full audit log as JSON
curl http://127.0.0.1:19990/api/v1/audit | jq .

# Stats summary
curl http://127.0.0.1:19990/api/v1/stats | jq .

# Download CSV directly
curl -o audit.csv http://127.0.0.1:19990/api/v1/audit/export
```

### Compliance Reports

ROE Gate can generate SOC2 and PCI-DSS formatted audit reports:

```bash
# Generate a SOC2 compliance report
curl -X POST http://127.0.0.1:19990/api/v1/compliance/soc2 \
  -H "Content-Type: application/json" \
  -d '{"engagement_id": "ENG-2025-001"}' | jq .
```

---

## Part 9 — Alerting (Optional)

Send real-time deny/escalate alerts to Slack:

```yaml
gate:
  slack_webhook: "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
```

Or to a generic webhook:

```yaml
gate:
  webhook_url: "https://your-siem.internal/roe-gate-events"
```

---

## Part 10 — After the Test

When the agent finishes:

1. **Export the audit log** (JSON + CSV) from the dashboard
2. **Review all DENY decisions** — these are your scope boundary enforcement points
3. **Review all ESCALATE decisions** — these are the high-severity findings that required human judgment
4. Press `Ctrl+C` in the terminal to cleanly shut down the gate service
5. Review the terminal output for the agent's final findings summary

---

## Troubleshooting

**`Gate Service did not become healthy within 15 seconds`**

Port 19990 may be in use. ROE Gate will auto-kill stale processes, but if it persists:

```bash
lsof -ti :19990 | xargs kill -9
roe-gate pentest --config my_pentest_config.yaml
```

**`claude: command not found`**

Claude Code is not installed or not on PATH:

```bash
npm install -g @anthropic-ai/claude-code
export PATH="$PATH:$(npm bin -g)"
```

**`Judge LLM returned empty response`**

If using `claude-cli` judge, ensure you're authenticated:

```bash
claude --version   # should not prompt for auth
claude -p "test"   # should return a response
```

If using `anthropic` judge, check your API key:

```bash
echo $ANTHROPIC_API_KEY
```

**Agent is running but not doing anything**

Check the dashboard for DENY decisions. The agent may be blocked because:
- Targets are out of scope in your ROE
- Rate limits have been hit
- Max consecutive denials reached (default: 5)

**`roe_spec validation error`**

Run `roe-gate validate examples/corpsec_labs_roe.yaml` and fix the reported issues. The most common issues are missing `metadata.engagement_id` or `scope.in_scope` being empty.

---

## Next Steps

- Try `--human-in-the-loop` to practice approving escalated actions
- Explore `examples/multi_vendor_pentest.py` to chain multiple providers
- Add `slack_webhook` to get real-time alerts on your phone
- Generate a compliance report with the `/api/v1/compliance/soc2` endpoint
- Try the other START guides to compare how different LLM providers perform as the pentester

**Other START Guides:**
- [`START_anthropic_api.md`](START_anthropic_api.md) — Anthropic API tester
- [`START_openai.md`](START_openai.md) — OpenAI / GPT-4o tester
- [`START_ollama.md`](START_ollama.md) — Ollama local model tester
