# ROE Gate — Start Guide: Ollama Local Model Agent

> **Tester provider:** `ollama` (local Ollama server — no API keys, no cloud)
> **Judge provider:** `ollama` (same or different local model)
> **Best for:** Air-gapped environments, privacy-sensitive engagements, offline labs, or anyone who wants zero cloud dependency. Everything runs on your machine.

---

## Scenario

Throughout this guide you will set up a complete, end-to-end gated penetration test of a fictitious staging environment — entirely offline:

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
- **RAM:** 8 GB minimum (for 7B models), 16 GB recommended (for 13B+ models)
- **Storage:** 5–15 GB for model files

### Install Ollama

**macOS / Linux:**

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

**macOS (Homebrew):**

```bash
brew install ollama
```

**Windows:** Download the installer from [ollama.com](https://ollama.com).

Start the Ollama server:

```bash
ollama serve
# Runs on http://localhost:11434 by default
```

In a separate terminal, verify it's running:

```bash
curl http://localhost:11434/api/tags | jq '.models[].name'
```

### Pull Models

Pull the models you'll use for the tester and judge:

```bash
# Recommended for tester (best tool-use capability for local models)
ollama pull llama3.1:8b        # 4.7 GB — good balance of speed and quality
ollama pull llama3.3:70b       # 43 GB  — best quality, needs 64 GB RAM

# Recommended for judge (smaller model is fine here)
ollama pull llama3.1:8b        # can reuse the same model
ollama pull phi3.5             # 2.2 GB — very fast, good for simple reasoning
ollama pull mistral:7b         # 4.1 GB — strong instruction following

# Verify models are available
ollama list
```

> **Model recommendation:**
> - `llama3.1:8b` — Good all-around choice. Understands pentest context and follows tool-use patterns reliably.
> - `llama3.3:70b` — Best local quality but requires significant RAM/GPU.
> - `mistral:7b` — Solid alternative if llama3.1 is too large.
> - Avoid very small models (<3B parameters) for the tester; they struggle with multi-step tool chaining.

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

# Verify
roe-gate --help
```

No API keys or cloud accounts needed. Everything communicates with your local Ollama server.

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

> **Shortcut:** `examples/corpsec_labs_roe.yaml` is already provided and ready to use.

---

## Part 4 — Configure roe_gate_config.yaml

Open `examples/roe_gate_config.yaml` directly and edit it:

### Standard Ollama Config (llama3.1:8b for both)

```yaml
tester:
  provider: "ollama"
  model: "llama3.1:8b"
  max_turns: 30          # local models are slower; fewer turns keeps sessions manageable
  temperature: 0.1
  # base_url: "http://localhost:11434"   # default; change if Ollama runs elsewhere

judge:
  provider: "ollama"
  model: "llama3.1:8b"   # can use same model or a smaller one
  # base_url: "http://localhost:11434"

gate:
  roe: "examples/corpsec_labs_roe.yaml"
  port: 19990
  signing: "hmac"
  hitl: false
  dashboard: true
```

### High-Quality Config (70B tester, 8B judge)

```yaml
tester:
  provider: "ollama"
  model: "llama3.3:70b"    # best local quality (needs 64 GB RAM)
  max_turns: 25
  temperature: 0.1

judge:
  provider: "ollama"
  model: "llama3.1:8b"     # judge doesn't need the 70B

gate:
  roe: "examples/corpsec_labs_roe.yaml"
  port: 19990
  signing: "hmac"
  hitl: false
  dashboard: true
```

### Remote Ollama Server

If Ollama runs on a different machine on your network:

```yaml
tester:
  provider: "ollama"
  model: "llama3.1:8b"
  base_url: "http://192.168.1.50:11434"

judge:
  provider: "ollama"
  model: "llama3.1:8b"
  base_url: "http://192.168.1.50:11434"
```

### Hybrid: Local Tester, Cloud Judge

For better judgment quality without adding cloud cost to the tester:

```yaml
tester:
  provider: "ollama"
  model: "llama3.1:8b"

judge:
  provider: "claude-cli"      # uses your Claude subscription (no extra API cost)
  model: "claude-sonnet-4-6"
  # or: provider: "anthropic", api_key_env: "ANTHROPIC_API_KEY"

gate:
  roe: "examples/corpsec_labs_roe.yaml"
  port: 19990
  signing: "hmac"
  hitl: false
  dashboard: true
```

This hybrid setup is often the best cost/quality tradeoff for local deployments.

---

## Part 5 — Launch Your First Gated Pentest

### Confirm Ollama is Running

```bash
# In a separate terminal (keep this running)
ollama serve

# Verify the model responds
ollama run llama3.1:8b "What is nmap used for? Answer in one sentence."
```

### Dry Run

```bash
roe-gate pentest --config examples/roe_gate_config.yaml --dry-run
```

Expected:

```
  ROE Gate v0.1.0
  ────────────────────────────────────────
  ROE:       examples/corpsec_labs_roe.yaml
  Judge:     ollama (llama3.1:8b) @ localhost:11434
  Tester:    ollama (llama3.1:8b) @ localhost:11434
  Signing:   HMAC-SHA256
  Dashboard: http://127.0.0.1:19990/dashboard
  ────────────────────────────────────────
  [Gate] Gate service started (dry-run mode)
  [Gate] Rule Engine ready.
  [Gate] Judge LLM (ollama) ready.
  [Gate] Signer ready.
  [DRY-RUN] Agent not launched. Gate is live.
```

### Live Pentest

```bash
roe-gate pentest --config examples/roe_gate_config.yaml
```

> **Speed note:** Local models are slower than cloud APIs. Expect 5–20 seconds per agent turn depending on your hardware. The dashboard updates in real time as each decision comes in.

### Custom Objective

```bash
roe-gate pentest \
  --config examples/roe_gate_config.yaml \
  --objective "Conduct a web application security assessment of webapp.corp.local (192.168.100.10). Perform reconnaissance, enumerate services, then test for SQL injection, XSS, and authentication bypass. Also test the API at api.corp.local (192.168.101.10) for common API vulnerabilities."
```

### CLI Overrides

```bash
# Use a different local model
roe-gate pentest --config examples/roe_gate_config.yaml --model mistral:7b

# Enable human approval
roe-gate pentest --config examples/roe_gate_config.yaml --human-in-the-loop

# Verbose mode (see full gate decisions in terminal)
roe-gate pentest --config examples/roe_gate_config.yaml --verbose
```

---

## Part 6 — Using the Audit Dashboard

Navigate to `http://127.0.0.1:19990/dashboard`.

### What to Expect with Local Models

Local models (especially 7B/8B parameter models) are capable but differ from cloud models in important ways:

- **Slower turns:** 10–30 seconds per agent action vs 1–3 seconds with cloud models
- **More literal:** They follow explicit instructions well but may need clearer prompts
- **DENY reasons:** The gate is model-agnostic — the deterministic rule engine catches most scope violations regardless of model quality. The LLM judge handles nuanced cases.

### Decision Feed

Each row shows:
- **[ALLOW]** — within ROE, token issued, tool ran
- **[DENY]** — violated ROE, tool blocked (deterministic engine caught it)
- **[ESCALATE]** — `requires_approval` action, awaiting human

Expand any entry to see the local model's reasoning. This is useful for evaluating whether your chosen model is reasoning correctly about ROE compliance.

### Comparing Model Quality

Try running the same pentest with different models to compare reasoning quality:

```bash
# Run with llama3.1:8b
roe-gate pentest --config examples/roe_gate_config.yaml --model llama3.1:8b

# Export the audit log
curl -o audit_llama31_8b.csv http://127.0.0.1:19990/api/v1/audit/export

# Run again with mistral:7b
roe-gate pentest --config examples/roe_gate_config.yaml --model mistral:7b
curl -o audit_mistral_7b.csv http://127.0.0.1:19990/api/v1/audit/export
```

Compare the DENY decisions and reasoning quality between the two CSV files.

### Emergency Halt

The red **Emergency Halt** button denies all further tool calls. Essential to have available since local models may occasionally produce unexpected outputs.

---

## Part 7 — Human-in-the-Loop (HITL) Approval

HITL is especially useful with local models since they may require more human oversight.

```bash
roe-gate pentest --config examples/roe_gate_config.yaml --human-in-the-loop
```

When the agent requests a critical action, the dashboard shows it in amber:

```
[ESCALATE] sqlmap → webapp.corp.local:443
Category:  critical_exploitation
Model:     llama3.1:8b
Reasoning: Agent is requesting high-intensity SQL injection with risk level 3,
           which may impact service availability.
⏱ 4:52 remaining
[Approve] [Deny]
```

> **Recommendation:** Always run with `hitl: true` when using smaller local models (<13B parameters). This gives you a human checkpoint on any actions the model classifies as requiring approval, compensating for potentially weaker reasoning.

---

## Part 8 — Exporting Audit Events

### Dashboard Export

- **Export JSON** → `roe_gate_audit_TIMESTAMP.json`
- **Export CSV** → `roe_gate_audit_TIMESTAMP.csv`

### API Export

```bash
# JSON audit
curl http://127.0.0.1:19990/api/v1/audit | jq .

# CSV download
curl -o audit.csv http://127.0.0.1:19990/api/v1/audit/export

# Stats
curl http://127.0.0.1:19990/api/v1/stats | jq .
```

### Sample CSV

```csv
timestamp,event_type,decision,tool,category,target_host,target_port,reasoning,token_issued
2025-01-15T14:32:01,action_evaluation,ALLOW,nmap,reconnaissance,192.168.100.10,80,...
2025-01-15T14:34:22,action_evaluation,ALLOW,curl,web_application_testing,webapp.corp.local,80,...
2025-01-15T14:36:05,action_evaluation,DENY,psql,direct_database_access,192.168.200.5,5432,...
```

Even with a local 8B model as the tester, the gate's deterministic rule engine correctly blocked the database access attempt.

---

## Part 9 — Optimizing for Local Models

### System Prompt Tuning

Local models respond better to explicit, structured objectives:

```bash
roe-gate pentest \
  --config examples/roe_gate_config.yaml \
  --objective "You are a penetration tester. Follow these steps IN ORDER:
1. Run nmap against 192.168.100.10 to find open ports and services
2. Use gobuster to enumerate directories on port 80
3. Test the login page for SQL injection using sqlmap
4. Test for XSS in any search or input fields
5. Document each finding with severity rating
Only test the 192.168.100.0/24 and 192.168.101.0/24 networks. Do NOT test any other IPs."
```

### Reduce Turns for Speed

```yaml
tester:
  max_turns: 20    # keep sessions tight for local models
```

### Use GPU Acceleration

If you have a GPU, Ollama uses it automatically. Verify:

```bash
ollama ps   # shows currently running model and hardware
```

For CUDA (NVIDIA):

```bash
# Verify CUDA is detected
ollama run llama3.1:8b "list your hardware" 2>&1 | head -5
```

For Apple Silicon (M1/M2/M3):

Ollama uses Metal automatically — no configuration needed. 8B models run very well on M-series chips.

---

## Part 10 — After the Test

1. Export the audit log (JSON + CSV)
2. Note that even with a local model, the gate's deterministic engine catches hard scope violations reliably
3. Review judge reasoning quality in the expanded decision view — this tells you if your model is strong enough for nuanced cases
4. Press `Ctrl+C` to shut down ROE Gate
5. Optionally stop Ollama: `pkill ollama`

---

## Troubleshooting

**`Connection refused` to localhost:11434**

Ollama isn't running. Start it:

```bash
ollama serve
# or on macOS: open the Ollama menu bar app
```

**`model not found` error**

Pull the model first:

```bash
ollama pull llama3.1:8b
ollama list   # verify it appears
```

**Agent is very slow**

Normal for local models on CPU. To speed up:
- Use a smaller model: `phi3.5` (2.2 GB) or `llama3.2:3b` (2 GB)
- Ensure Ollama is using your GPU (`ollama ps` shows hardware)
- Reduce `max_turns` in config

**Agent not making progress / loops**

Local 7B/8B models occasionally get stuck. Try:

```bash
# Use a larger model
roe-gate pentest --config examples/roe_gate_config.yaml --model llama3.3:70b

# Or use a clearer, step-by-step objective
roe-gate pentest --config examples/roe_gate_config.yaml \
  --objective "Step 1: Run nmap -sV 192.168.100.10. Step 2: Run gobuster. Step 3: ..."
```

**`ollama: command not found`**

Add Ollama to PATH:

```bash
export PATH="$PATH:/usr/local/bin"
# or on macOS:
export PATH="$PATH:/Applications/Ollama.app/Contents/Resources/bin"
```

**Out of memory (OOM) when loading model**

Use a smaller model or enable 4-bit quantization:

```bash
ollama pull llama3.1:8b-instruct-q4_K_M   # 4-bit quantized, uses ~5 GB RAM
```

---

## Next Steps

- Try the hybrid config: Ollama tester + `claude-cli` judge for better reasoning quality at no cloud cost
- Run the same scenario with `llama3.1:8b` vs `llama3.3:70b` and compare audit logs
- Pull `codellama` or `deepseek-coder` for code-focused vulnerability analysis
- Try `mistral:7b-instruct` as an alternative tester

**Other START Guides:**
- [`START_claude_code.md`](START_claude_code.md) — Claude Code tester (MCP integration)
- [`START_anthropic_api.md`](START_anthropic_api.md) — Anthropic API tester
- [`START_openai.md`](START_openai.md) — OpenAI / GPT-4o tester
