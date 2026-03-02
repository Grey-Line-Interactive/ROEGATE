"""ROE Creator Dashboard — visual ROE specification builder.

Provides a self-contained HTML page that lets users visually create,
edit, and export Rules of Engagement (ROE) YAML specifications.
Community (free) feature.
"""


def build_roe_creator_html() -> str:
    """Return a complete, self-contained HTML page for the ROE Creator Dashboard."""
    return _PAGE_HTML


_PAGE_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ROE Gate — ROE Creator</title>
<style>
/* ── Reset & Variables ─────────────────────────────────────────── */
:root {
  --bg: #0d1117;
  --surface: #161b22;
  --border: #30363d;
  --green: #00ff41;
  --green-dim: #00cc33;
  --amber: #ffb000;
  --red: #ff4444;
  --text: #e6edf3;
  --muted: #8b949e;
  --blue: #58a6ff;
  --surface-hover: #1c2129;
  --input-bg: #0d1117;
}
*, *::before, *::after { margin: 0; padding: 0; box-sizing: border-box; }
html { font-size: 14px; }
body {
  font-family: system-ui, -apple-system, 'Segoe UI', sans-serif;
  background: var(--bg);
  color: var(--text);
  min-height: 100vh;
  overflow-x: hidden;
}

/* ── Scrollbar ─────────────────────────────────────────────────── */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: var(--bg); }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: var(--muted); }

/* ── Header ────────────────────────────────────────────────────── */
.header {
  background: var(--surface);
  border-bottom: 1px solid var(--border);
  padding: 14px 24px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  position: sticky;
  top: 0;
  z-index: 100;
}
.header h1 {
  font-family: 'JetBrains Mono', 'Fira Code', monospace;
  font-size: 16px;
  color: var(--green);
  letter-spacing: 1px;
}
.header h1 .cursor {
  display: inline-block;
  width: 8px;
  height: 16px;
  background: var(--green);
  margin-left: 4px;
  animation: blink 1s step-end infinite;
  vertical-align: text-bottom;
}
@keyframes blink { 50% { opacity: 0; } }
.header-actions { display: flex; gap: 8px; }

/* ── Buttons ───────────────────────────────────────────────────── */
.btn {
  font-family: 'JetBrains Mono', 'Fira Code', monospace;
  font-size: 12px;
  padding: 7px 14px;
  border-radius: 6px;
  border: 1px solid var(--border);
  background: var(--surface);
  color: var(--text);
  cursor: pointer;
  transition: all 0.15s ease;
  display: inline-flex;
  align-items: center;
  gap: 6px;
}
.btn:hover { border-color: var(--green); color: var(--green); }
.btn-primary {
  background: var(--green);
  color: #000;
  border-color: var(--green);
  font-weight: 700;
}
.btn-primary:hover { background: var(--green-dim); border-color: var(--green-dim); color: #000; }
.btn-danger { border-color: var(--red); color: var(--red); }
.btn-danger:hover { background: #3d1f20; }
.btn-small { font-size: 11px; padding: 4px 10px; }

/* ── Layout ────────────────────────────────────────────────────── */
.main {
  display: flex;
  height: calc(100vh - 50px);
}
.form-panel {
  width: 60%;
  overflow-y: auto;
  padding: 16px 20px;
  border-right: 1px solid var(--border);
}
.preview-panel {
  width: 40%;
  display: flex;
  flex-direction: column;
  position: relative;
}
.preview-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 12px 16px;
  border-bottom: 1px solid var(--border);
  background: var(--surface);
  flex-shrink: 0;
}
.preview-header h2 {
  font-family: 'JetBrains Mono', 'Fira Code', monospace;
  font-size: 13px;
  color: var(--muted);
  text-transform: uppercase;
  letter-spacing: 1px;
}
.preview-actions { display: flex; gap: 6px; }
.preview-body {
  flex: 1;
  overflow-y: auto;
  padding: 16px;
}
.yaml-output {
  font-family: 'JetBrains Mono', 'Fira Code', monospace;
  font-size: 12px;
  line-height: 1.6;
  white-space: pre-wrap;
  word-break: break-all;
  tab-size: 2;
}

/* ── YAML syntax highlighting ──────────────────────────────────── */
.yaml-output .y-key { color: var(--green); }
.yaml-output .y-str { color: var(--amber); }
.yaml-output .y-num { color: var(--blue); }
.yaml-output .y-bool { color: #bc8cff; }
.yaml-output .y-comment { color: var(--muted); font-style: italic; }
.yaml-output .y-dash { color: var(--muted); }

/* ── Accordion ─────────────────────────────────────────────────── */
.accordion {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  margin-bottom: 10px;
  overflow: hidden;
}
.accordion-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 12px 16px;
  cursor: pointer;
  transition: background 0.15s ease;
  user-select: none;
}
.accordion-header:hover { background: var(--surface-hover); }
.accordion-header h3 {
  font-size: 13px;
  font-weight: 600;
  display: flex;
  align-items: center;
  gap: 8px;
}
.accordion-header .chevron {
  font-size: 11px;
  color: var(--muted);
  transition: transform 0.2s ease;
}
.accordion.open .accordion-header .chevron { transform: rotate(90deg); }
.accordion-body {
  max-height: 0;
  overflow: hidden;
  transition: max-height 0.3s ease;
}
.accordion.open .accordion-body {
  max-height: 4000px;
}
.accordion-content {
  padding: 4px 16px 16px;
}
.section-status {
  font-size: 11px;
  padding: 2px 8px;
  border-radius: 10px;
  font-weight: 600;
}
.section-status.complete { background: #0d2818; color: var(--green); }
.section-status.incomplete { background: #2d2200; color: var(--amber); }

/* ── Form elements ─────────────────────────────────────────────── */
.field { margin-bottom: 12px; }
.field label {
  display: block;
  font-size: 11px;
  color: var(--muted);
  text-transform: uppercase;
  letter-spacing: 0.5px;
  margin-bottom: 4px;
  font-weight: 600;
}
.field label .req { color: var(--red); margin-left: 2px; }
.field input[type="text"],
.field input[type="number"],
.field input[type="datetime-local"],
.field select,
.field textarea {
  font-family: 'JetBrains Mono', 'Fira Code', monospace;
  font-size: 13px;
  width: 100%;
  padding: 8px 10px;
  background: var(--input-bg);
  border: 1px solid var(--border);
  border-radius: 6px;
  color: var(--text);
  outline: none;
  transition: border-color 0.15s;
}
.field input:focus, .field select:focus, .field textarea:focus {
  border-color: var(--green);
}
.field input.error, .field select.error { border-color: var(--red); }
.field .error-msg { color: var(--red); font-size: 11px; margin-top: 2px; display: none; }
.field input.error + .error-msg { display: block; }
.field-row {
  display: flex;
  gap: 10px;
  align-items: flex-end;
}
.field-row .field { flex: 1; }

.checkbox-field {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 10px;
  cursor: pointer;
}
.checkbox-field input[type="checkbox"] {
  accent-color: var(--green);
  width: 16px;
  height: 16px;
  cursor: pointer;
}
.checkbox-field span {
  font-size: 13px;
}

/* ── Dynamic rows ──────────────────────────────────────────────── */
.dynamic-list { margin-top: 8px; }
.dynamic-row {
  display: flex;
  gap: 8px;
  align-items: flex-end;
  padding: 8px 10px;
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 6px;
  margin-bottom: 6px;
}
.dynamic-row .field { margin-bottom: 0; }
.dynamic-row .btn-remove {
  flex-shrink: 0;
  background: none;
  border: none;
  color: var(--red);
  cursor: pointer;
  font-size: 16px;
  padding: 4px 6px;
  border-radius: 4px;
  line-height: 1;
  opacity: 0.6;
  transition: opacity 0.15s;
}
.dynamic-row .btn-remove:hover { opacity: 1; background: #3d1f20; }
.add-row-btn {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  font-size: 12px;
  color: var(--green);
  cursor: pointer;
  padding: 6px 0;
  background: none;
  border: none;
  font-family: inherit;
}
.add-row-btn:hover { text-decoration: underline; }

/* ── Key-Value pairs ───────────────────────────────────────────── */
.kv-row {
  display: flex;
  gap: 8px;
  align-items: center;
  margin-bottom: 6px;
}
.kv-row input {
  font-family: 'JetBrains Mono', 'Fira Code', monospace;
  font-size: 12px;
  padding: 6px 8px;
  background: var(--input-bg);
  border: 1px solid var(--border);
  border-radius: 4px;
  color: var(--text);
  outline: none;
}
.kv-row input:focus { border-color: var(--green); }
.kv-row input.kv-key { width: 140px; }
.kv-row input.kv-val { flex: 1; }

/* ── Toast ─────────────────────────────────────────────────────── */
.toast {
  position: fixed;
  bottom: 20px;
  right: 20px;
  padding: 10px 18px;
  border-radius: 6px;
  font-size: 13px;
  font-family: 'JetBrains Mono', 'Fira Code', monospace;
  z-index: 999;
  opacity: 0;
  transform: translateY(10px);
  transition: all 0.2s ease;
  pointer-events: none;
}
.toast.show { opacity: 1; transform: translateY(0); }
.toast.success { background: #0d2818; color: var(--green); border: 1px solid var(--green); }
.toast.error { background: #3d1f20; color: var(--red); border: 1px solid var(--red); }

/* ── Responsive ────────────────────────────────────────────────── */
@media (max-width: 1024px) {
  .main { flex-direction: column; height: auto; }
  .form-panel { width: 100%; border-right: none; border-bottom: 1px solid var(--border); }
  .preview-panel { width: 100%; height: 50vh; }
}

/* ── Import modal ──────────────────────────────────────────────── */
.modal-overlay {
  position: fixed; inset: 0; background: rgba(0,0,0,0.6);
  display: none; align-items: center; justify-content: center; z-index: 200;
}
.modal-overlay.show { display: flex; }
.modal {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 24px;
  width: 90%;
  max-width: 500px;
}
.modal h3 { margin-bottom: 12px; font-size: 15px; color: var(--green); }
.modal textarea {
  font-family: 'JetBrains Mono', 'Fira Code', monospace;
  font-size: 12px;
  width: 100%;
  height: 200px;
  padding: 10px;
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 6px;
  color: var(--text);
  outline: none;
  resize: vertical;
}
.modal-actions { display: flex; gap: 8px; margin-top: 12px; justify-content: flex-end; }
</style>
</head>
<body>

<!-- ── Header ──────────────────────────────────────────────────── -->
<div class="header">
  <h1>ROE GATE &mdash; ROE Creator<span class="cursor"></span></h1>
  <div class="header-actions">
    <button class="btn" onclick="showImportModal()" title="Import YAML">Import YAML</button>
    <button class="btn" onclick="validateForm()" title="Validate">Validate</button>
    <button class="btn" onclick="copyYAML()" title="Ctrl+Shift+C">Copy YAML</button>
    <button class="btn btn-primary" onclick="downloadYAML()" title="Ctrl+S">Download .yaml</button>
  </div>
</div>

<!-- ── Main layout ─────────────────────────────────────────────── -->
<div class="main">

<!-- ── Left: Form ──────────────────────────────────────────────── -->
<div class="form-panel" id="form-panel">

  <!-- 1. Metadata -->
  <div class="accordion open" id="sec-metadata">
    <div class="accordion-header" onclick="toggleAccordion(this)">
      <h3><span class="chevron">&#9654;</span> Metadata</h3>
      <span class="section-status incomplete" id="status-metadata">Required</span>
    </div>
    <div class="accordion-body"><div class="accordion-content">
      <div class="field-row">
        <div class="field">
          <label>Engagement ID <span class="req">*</span></label>
          <input type="text" id="meta-engagement-id" placeholder="ENG-2024-001" data-required>
          <div class="error-msg">Required</div>
        </div>
        <div class="field">
          <label>Client Name <span class="req">*</span></label>
          <input type="text" id="meta-client" placeholder="Acme Corp" data-required>
          <div class="error-msg">Required</div>
        </div>
      </div>
      <div class="field-row">
        <div class="field">
          <label>Tester Name</label>
          <input type="text" id="meta-tester" placeholder="Security Team">
        </div>
        <div class="field">
          <label>Approved By</label>
          <input type="text" id="meta-approved-by" placeholder="CISO">
        </div>
      </div>
      <div class="field">
        <label>Classification</label>
        <select id="meta-classification">
          <option value="CONFIDENTIAL">CONFIDENTIAL</option>
          <option value="INTERNAL">INTERNAL</option>
          <option value="PUBLIC">PUBLIC</option>
        </select>
      </div>
    </div></div>
  </div>

  <!-- 2. Schedule -->
  <div class="accordion" id="sec-schedule">
    <div class="accordion-header" onclick="toggleAccordion(this)">
      <h3><span class="chevron">&#9654;</span> Schedule</h3>
      <span class="section-status incomplete" id="status-schedule">Required</span>
    </div>
    <div class="accordion-body"><div class="accordion-content">
      <div class="field-row">
        <div class="field">
          <label>Valid From <span class="req">*</span></label>
          <input type="datetime-local" id="sched-valid-from" data-required>
          <div class="error-msg">Required</div>
        </div>
        <div class="field">
          <label>Valid Until <span class="req">*</span></label>
          <input type="datetime-local" id="sched-valid-until" data-required>
          <div class="error-msg">Required</div>
        </div>
      </div>
      <div class="field-row">
        <div class="field">
          <label>Allowed Hours</label>
          <input type="text" id="sched-hours" placeholder="09:00-17:00">
        </div>
        <div class="field">
          <label>Timezone</label>
          <select id="sched-timezone">
            <option value="UTC">UTC</option>
            <option value="US/Eastern">US/Eastern</option>
            <option value="US/Central">US/Central</option>
            <option value="US/Mountain">US/Mountain</option>
            <option value="US/Pacific">US/Pacific</option>
            <option value="Europe/London">Europe/London</option>
            <option value="Europe/Berlin">Europe/Berlin</option>
            <option value="Europe/Paris">Europe/Paris</option>
            <option value="Asia/Tokyo">Asia/Tokyo</option>
            <option value="Asia/Shanghai">Asia/Shanghai</option>
            <option value="Asia/Kolkata">Asia/Kolkata</option>
            <option value="Australia/Sydney">Australia/Sydney</option>
          </select>
        </div>
      </div>
      <div class="field">
        <label>Blackout Periods</label>
        <div class="dynamic-list" id="blackout-list"></div>
        <button class="add-row-btn" onclick="addBlackoutRow()">+ Add blackout period</button>
      </div>
    </div></div>
  </div>

  <!-- 3. Scope — In-Scope -->
  <div class="accordion" id="sec-in-scope">
    <div class="accordion-header" onclick="toggleAccordion(this)">
      <h3><span class="chevron">&#9654;</span> Scope &mdash; In-Scope</h3>
      <span class="section-status incomplete" id="status-in-scope">Required</span>
    </div>
    <div class="accordion-body"><div class="accordion-content">
      <label style="font-size:12px;color:var(--text);margin-bottom:8px;display:block;font-weight:600">Networks</label>
      <div class="dynamic-list" id="in-scope-networks"></div>
      <button class="add-row-btn" onclick="addInScopeNetwork()">+ Add network</button>

      <label style="font-size:12px;color:var(--text);margin:14px 0 8px;display:block;font-weight:600">Domains</label>
      <div class="dynamic-list" id="in-scope-domains"></div>
      <button class="add-row-btn" onclick="addInScopeDomain()">+ Add domain</button>
    </div></div>
  </div>

  <!-- 4. Scope — Out-of-Scope -->
  <div class="accordion" id="sec-out-of-scope">
    <div class="accordion-header" onclick="toggleAccordion(this)">
      <h3><span class="chevron">&#9654;</span> Scope &mdash; Out-of-Scope</h3>
      <span class="section-status" id="status-out-of-scope" style="display:none"></span>
    </div>
    <div class="accordion-body"><div class="accordion-content">
      <label style="font-size:12px;color:var(--text);margin-bottom:8px;display:block;font-weight:600">Networks</label>
      <div class="dynamic-list" id="out-scope-networks"></div>
      <button class="add-row-btn" onclick="addOutScopeNetwork()">+ Add network</button>

      <label style="font-size:12px;color:var(--text);margin:14px 0 8px;display:block;font-weight:600">Services</label>
      <div class="dynamic-list" id="out-scope-services"></div>
      <button class="add-row-btn" onclick="addOutScopeService()">+ Add service</button>

      <label style="font-size:12px;color:var(--text);margin:14px 0 8px;display:block;font-weight:600">Domains</label>
      <div class="dynamic-list" id="out-scope-domains"></div>
      <button class="add-row-btn" onclick="addOutScopeDomain()">+ Add domain</button>
    </div></div>
  </div>

  <!-- 5. Actions — Allowed -->
  <div class="accordion" id="sec-allowed">
    <div class="accordion-header" onclick="toggleAccordion(this)">
      <h3><span class="chevron">&#9654;</span> Actions &mdash; Allowed</h3>
      <span class="section-status" id="status-allowed" style="display:none"></span>
    </div>
    <div class="accordion-body"><div class="accordion-content">
      <div class="dynamic-list" id="allowed-actions"></div>
      <button class="add-row-btn" onclick="addAllowedAction()">+ Add allowed action</button>
    </div></div>
  </div>

  <!-- 6. Actions — Denied -->
  <div class="accordion" id="sec-denied">
    <div class="accordion-header" onclick="toggleAccordion(this)">
      <h3><span class="chevron">&#9654;</span> Actions &mdash; Denied</h3>
      <span class="section-status" id="status-denied" style="display:none"></span>
    </div>
    <div class="accordion-body"><div class="accordion-content">
      <div class="dynamic-list" id="denied-actions"></div>
      <button class="add-row-btn" onclick="addDeniedAction()">+ Add denied action</button>
    </div></div>
  </div>

  <!-- 7. Constraints -->
  <div class="accordion" id="sec-constraints">
    <div class="accordion-header" onclick="toggleAccordion(this)">
      <h3><span class="chevron">&#9654;</span> Constraints</h3>
      <span class="section-status" id="status-constraints" style="display:none"></span>
    </div>
    <div class="accordion-body"><div class="accordion-content">
      <div class="field-row">
        <div class="field">
          <label>Max Concurrent Connections</label>
          <input type="number" id="con-max-connections" placeholder="10" min="1">
        </div>
        <div class="field">
          <label>Global Rate Limit</label>
          <input type="text" id="con-rate-limit" placeholder="500 requests/minute">
        </div>
      </div>
      <div class="checkbox-field">
        <input type="checkbox" id="con-no-persistent" checked>
        <span>No persistent changes</span>
      </div>
      <div class="checkbox-field">
        <input type="checkbox" id="con-no-prod-data" checked>
        <span>No production data storage</span>
      </div>
      <label style="font-size:12px;color:var(--text);margin:10px 0 8px;display:block;font-weight:600">Custom Constraints</label>
      <div id="custom-constraints"></div>
      <button class="add-row-btn" onclick="addCustomConstraint()">+ Add custom constraint</button>
    </div></div>
  </div>

  <!-- 8. Emergency -->
  <div class="accordion" id="sec-emergency">
    <div class="accordion-header" onclick="toggleAccordion(this)">
      <h3><span class="chevron">&#9654;</span> Emergency</h3>
      <span class="section-status" id="status-emergency" style="display:none"></span>
    </div>
    <div class="accordion-body"><div class="accordion-content">
      <div class="checkbox-field">
        <input type="checkbox" id="em-kill-switch" checked>
        <span>Kill switch enabled</span>
      </div>
      <div class="field">
        <label>Max Consecutive Denials Before Halt</label>
        <input type="number" id="em-max-denials" value="3" min="1">
      </div>
      <div class="field">
        <label>Emergency Contact</label>
        <input type="text" id="em-contact" placeholder="security-team@example.com">
      </div>
      <div class="field">
        <label>Notification Webhook URL</label>
        <input type="text" id="em-webhook" placeholder="https://hooks.example.com/notify">
      </div>
    </div></div>
  </div>

</div><!-- /form-panel -->

<!-- ── Right: YAML Preview ─────────────────────────────────────── -->
<div class="preview-panel">
  <div class="preview-header">
    <h2>YAML Preview</h2>
    <div class="preview-actions">
      <button class="btn btn-small" onclick="copyYAML()">Copy</button>
      <button class="btn btn-small btn-primary" onclick="downloadYAML()">Download</button>
    </div>
  </div>
  <div class="preview-body">
    <div class="yaml-output" id="yaml-output"></div>
  </div>
</div>

</div><!-- /main -->

<!-- ── Import Modal ────────────────────────────────────────────── -->
<div class="modal-overlay" id="import-modal">
  <div class="modal">
    <h3>Import YAML</h3>
    <p style="color:var(--muted);font-size:12px;margin-bottom:10px">Paste your ROE YAML below, or select a file.</p>
    <textarea id="import-textarea" placeholder="Paste YAML here..."></textarea>
    <div style="margin-top:8px">
      <input type="file" id="import-file" accept=".yaml,.yml" style="font-size:12px;color:var(--muted)">
    </div>
    <div class="modal-actions">
      <button class="btn" onclick="closeImportModal()">Cancel</button>
      <button class="btn btn-primary" onclick="doImport()">Import</button>
    </div>
  </div>
</div>

<!-- ── Toast ────────────────────────────────────────────────────── -->
<div class="toast" id="toast"></div>

<script>
/* ================================================================
   ROE Creator — JavaScript
   ================================================================ */

/* ── Accordion toggle ──────────────────────────────────────────── */
function toggleAccordion(header) {
  header.parentElement.classList.toggle('open');
}

/* ── Toast notification ────────────────────────────────────────── */
function showToast(msg, type) {
  var t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'toast ' + type + ' show';
  setTimeout(function() { t.classList.remove('show'); }, 2500);
}

/* ── Dynamic row helpers ───────────────────────────────────────── */
function removeRow(btn) {
  btn.closest('.dynamic-row').remove();
  generateYAML();
}

function makeRemoveBtn() {
  return '<button class="btn-remove" onclick="removeRow(this)" title="Remove">&times;</button>';
}

/* -- Blackout periods -- */
function addBlackoutRow(from, to) {
  var list = document.getElementById('blackout-list');
  var row = document.createElement('div');
  row.className = 'dynamic-row';
  row.innerHTML =
    '<div class="field" style="flex:1"><label>From</label><input type="datetime-local" class="bo-from" value="' + (from || '') + '"></div>' +
    '<div class="field" style="flex:1"><label>To</label><input type="datetime-local" class="bo-to" value="' + (to || '') + '"></div>' +
    makeRemoveBtn();
  list.appendChild(row);
}

/* -- In-scope networks -- */
function addInScopeNetwork(cidr, ports, desc) {
  var list = document.getElementById('in-scope-networks');
  var row = document.createElement('div');
  row.className = 'dynamic-row';
  row.innerHTML =
    '<div class="field" style="flex:2"><label>CIDR</label><input type="text" class="isn-cidr" placeholder="10.0.0.0/24" value="' + (cidr || '') + '"></div>' +
    '<div class="field" style="flex:2"><label>Ports</label><input type="text" class="isn-ports" placeholder="80, 443, 8080" value="' + (ports || '') + '"></div>' +
    '<div class="field" style="flex:3"><label>Description</label><input type="text" class="isn-desc" placeholder="Web subnet" value="' + (desc || '') + '"></div>' +
    makeRemoveBtn();
  list.appendChild(row);
}

/* -- In-scope domains -- */
function addInScopeDomain(pattern, desc) {
  var list = document.getElementById('in-scope-domains');
  var row = document.createElement('div');
  row.className = 'dynamic-row';
  row.innerHTML =
    '<div class="field" style="flex:2"><label>Pattern</label><input type="text" class="isd-pattern" placeholder="*.app.example.com" value="' + (pattern || '') + '"></div>' +
    '<div class="field" style="flex:3"><label>Description</label><input type="text" class="isd-desc" placeholder="Description" value="' + (desc || '') + '"></div>' +
    makeRemoveBtn();
  list.appendChild(row);
}

/* -- Out-of-scope networks -- */
function addOutScopeNetwork(cidr, reason) {
  var list = document.getElementById('out-scope-networks');
  var row = document.createElement('div');
  row.className = 'dynamic-row';
  row.innerHTML =
    '<div class="field" style="flex:2"><label>CIDR</label><input type="text" class="osn-cidr" placeholder="10.0.2.0/24" value="' + (cidr || '') + '"></div>' +
    '<div class="field" style="flex:3"><label>Reason <span class="req">*</span></label><input type="text" class="osn-reason" placeholder="Production database" value="' + (reason || '') + '"></div>' +
    makeRemoveBtn();
  list.appendChild(row);
}

/* -- Out-of-scope services -- */
function addOutScopeService(type, protocols) {
  var list = document.getElementById('out-scope-services');
  var row = document.createElement('div');
  row.className = 'dynamic-row';
  row.innerHTML =
    '<div class="field" style="flex:1"><label>Type</label>' +
    '<select class="oss-type">' +
    '<option value="database"' + (type === 'database' ? ' selected' : '') + '>database</option>' +
    '<option value="email"' + (type === 'email' ? ' selected' : '') + '>email</option>' +
    '<option value="dns"' + (type === 'dns' ? ' selected' : '') + '>dns</option>' +
    '<option value="ldap"' + (type === 'ldap' ? ' selected' : '') + '>ldap</option>' +
    '<option value="ssh"' + (type === 'ssh' ? ' selected' : '') + '>ssh</option>' +
    '</select></div>' +
    '<div class="field" style="flex:2"><label>Protocols</label><input type="text" class="oss-proto" placeholder="postgresql, mysql" value="' + (protocols || '') + '"></div>' +
    makeRemoveBtn();
  list.appendChild(row);
}

/* -- Out-of-scope domains -- */
function addOutScopeDomain(pattern, reason) {
  var list = document.getElementById('out-scope-domains');
  var row = document.createElement('div');
  row.className = 'dynamic-row';
  row.innerHTML =
    '<div class="field" style="flex:2"><label>Pattern</label><input type="text" class="osd-pattern" placeholder="*.internal.example.com" value="' + (pattern || '') + '"></div>' +
    '<div class="field" style="flex:3"><label>Reason</label><input type="text" class="osd-reason" placeholder="Not authorized" value="' + (reason || '') + '"></div>' +
    makeRemoveBtn();
  list.appendChild(row);
}

/* Category options shared by allowed/denied */
var CATEGORIES = [
  'reconnaissance', 'web_application_testing', 'network_exploitation',
  'social_engineering', 'physical_testing', 'wireless_testing',
  'credential_testing', 'api_testing', 'authentication_testing',
  'denial_of_service', 'data_exfiltration', 'lateral_movement',
  'privilege_escalation', 'exploitation'
];

function categoryOptions(selected) {
  var opts = '';
  for (var i = 0; i < CATEGORIES.length; i++) {
    opts += '<option value="' + CATEGORIES[i] + '"' + (CATEGORIES[i] === selected ? ' selected' : '') + '>' + CATEGORIES[i] + '</option>';
  }
  return opts;
}

/* -- Allowed actions -- */
function addAllowedAction(cat, methods, constraints) {
  var list = document.getElementById('allowed-actions');
  var row = document.createElement('div');
  row.className = 'dynamic-row';
  row.style.flexDirection = 'column';
  row.style.alignItems = 'stretch';
  var constraintId = 'ac-' + Date.now() + '-' + Math.random().toString(36).substr(2, 5);
  var constraintHtml = '';
  if (constraints && typeof constraints === 'object') {
    var keys = Object.keys(constraints);
    for (var i = 0; i < keys.length; i++) {
      constraintHtml += '<div class="kv-row"><input class="kv-key" placeholder="key" value="' + esc(keys[i]) + '"><input class="kv-val" placeholder="value" value="' + esc(String(constraints[keys[i]])) + '"><button class="btn-remove" onclick="this.parentElement.remove();generateYAML()" title="Remove">&times;</button></div>';
    }
  }
  row.innerHTML =
    '<div style="display:flex;gap:8px;align-items:flex-end">' +
    '<div class="field" style="flex:1"><label>Category</label><select class="aa-cat">' + categoryOptions(cat) + '<option value="_custom">-- custom --</option></select></div>' +
    '<div class="field" style="flex:2"><label>Methods (comma-separated)</label><input type="text" class="aa-methods" placeholder="sql_injection, xss, csrf" value="' + (methods || '') + '"></div>' +
    '<button class="btn-remove" onclick="removeRow(this)" title="Remove" style="margin-bottom:6px">&times;</button>' +
    '</div>' +
    '<div style="margin-top:6px"><label style="font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:0.5px;font-weight:600">Constraints</label>' +
    '<div class="kv-list" id="' + constraintId + '">' + constraintHtml + '</div>' +
    '<button class="add-row-btn" onclick="addKV(\\'' + constraintId + '\\')">+ Add constraint</button>' +
    '</div>';
  list.appendChild(row);
}

/* -- Denied actions -- */
function addDeniedAction(cat, reason) {
  var list = document.getElementById('denied-actions');
  var row = document.createElement('div');
  row.className = 'dynamic-row';
  row.innerHTML =
    '<div class="field" style="flex:1"><label>Category</label>' +
    '<select class="da-cat">' + categoryOptions(cat) + '<option value="_custom">-- custom --</option></select></div>' +
    '<div class="field" style="flex:2"><label>Reason</label><input type="text" class="da-reason" placeholder="Could impact production" value="' + (reason || '') + '"></div>' +
    makeRemoveBtn();
  list.appendChild(row);
  /* if category wasn't in our list, set the custom option */
  if (cat && CATEGORIES.indexOf(cat) === -1) {
    var sel = row.querySelector('.da-cat');
    var opt = document.createElement('option');
    opt.value = cat;
    opt.textContent = cat;
    opt.selected = true;
    sel.insertBefore(opt, sel.lastElementChild);
  }
}

/* -- Custom constraints KV -- */
function addCustomConstraint(k, v) {
  addKV('custom-constraints', k, v);
}

function addKV(containerId, k, v) {
  var c = document.getElementById(containerId);
  var row = document.createElement('div');
  row.className = 'kv-row';
  row.innerHTML =
    '<input class="kv-key" placeholder="key" value="' + (k || '') + '">' +
    '<input class="kv-val" placeholder="value" value="' + (v || '') + '">' +
    '<button class="btn-remove" onclick="this.parentElement.remove();generateYAML()" title="Remove">&times;</button>';
  c.appendChild(row);
}

/* ── Escape helper ─────────────────────────────────────────────── */
function esc(s) {
  if (!s) return '';
  return s.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

/* ================================================================
   YAML GENERATION — custom toYAML, no library
   ================================================================ */
function needsQuoting(s) {
  if (s === '') return true;
  if (s === 'true' || s === 'false' || s === 'null' || s === 'yes' || s === 'no') return true;
  if (/^[\\d]/.test(s) && !isNaN(Number(s))) return true;
  if (/[:{}&*?|\\-<>=!%@,\\[\\]#]/.test(s)) return true;
  if (/^\\s|\\s$/.test(s)) return true;
  return false;
}

function yamlVal(v) {
  if (v === true) return 'true';
  if (v === false) return 'false';
  if (v === null || v === undefined) return 'null';
  if (typeof v === 'number') return String(v);
  var s = String(v);
  /* try to detect numeric strings that should stay strings (e.g., dates) */
  if (needsQuoting(s)) return '"' + s.replace(/\\\\/g, '\\\\\\\\').replace(/"/g, '\\\\"') + '"';
  return s;
}

function toYAML(obj, indent) {
  if (indent === undefined) indent = 0;
  var pad = '';
  for (var p = 0; p < indent; p++) pad += '  ';
  var lines = [];

  if (Array.isArray(obj)) {
    if (obj.length === 0) return pad + '[]';
    /* Check if simple array (all primitives) */
    var allPrimitive = true;
    for (var i = 0; i < obj.length; i++) {
      if (typeof obj[i] === 'object' && obj[i] !== null) { allPrimitive = false; break; }
    }
    if (allPrimitive) {
      var items = [];
      for (var i = 0; i < obj.length; i++) items.push(yamlVal(obj[i]));
      return '[' + items.join(', ') + ']';
    }
    for (var i = 0; i < obj.length; i++) {
      if (typeof obj[i] === 'object' && obj[i] !== null && !Array.isArray(obj[i])) {
        var keys = Object.keys(obj[i]);
        if (keys.length > 0) {
          var first = keys[0];
          var firstVal = obj[i][first];
          var restLines = '';
          for (var k = 1; k < keys.length; k++) {
            var rv = obj[i][keys[k]];
            if (typeof rv === 'object' && rv !== null) {
              restLines += pad + '  ' + keys[k] + ':\\n' + toYAMLInner(rv, indent + 2) + '\\n';
            } else {
              restLines += pad + '  ' + keys[k] + ': ' + yamlVal(rv) + '\\n';
            }
          }
          if (typeof firstVal === 'object' && firstVal !== null) {
            lines.push(pad + '- ' + first + ':\\n' + toYAMLInner(firstVal, indent + 2));
          } else {
            lines.push(pad + '- ' + first + ': ' + yamlVal(firstVal));
          }
          if (restLines) lines.push(restLines.replace(/\\n$/, ''));
        }
      } else {
        lines.push(pad + '- ' + yamlVal(obj[i]));
      }
    }
    return lines.join('\\n');
  }

  if (typeof obj === 'object' && obj !== null) {
    var keys = Object.keys(obj);
    for (var i = 0; i < keys.length; i++) {
      var key = keys[i];
      var val = obj[key];
      if (typeof val === 'object' && val !== null) {
        if (Array.isArray(val) && val.length > 0 && typeof val[0] !== 'object') {
          lines.push(pad + key + ': ' + toYAML(val, indent + 1));
        } else {
          lines.push(pad + key + ':');
          lines.push(toYAMLInner(val, indent + 1));
        }
      } else {
        lines.push(pad + key + ': ' + yamlVal(val));
      }
    }
    return lines.join('\\n');
  }

  return pad + yamlVal(obj);
}

function toYAMLInner(obj, indent) {
  if (indent === undefined) indent = 0;
  var pad = '';
  for (var p = 0; p < indent; p++) pad += '  ';
  var lines = [];

  if (Array.isArray(obj)) {
    if (obj.length === 0) return pad + '[]';
    var allPrimitive = true;
    for (var i = 0; i < obj.length; i++) {
      if (typeof obj[i] === 'object' && obj[i] !== null) { allPrimitive = false; break; }
    }
    if (allPrimitive) {
      return pad + '[' + obj.map(function(v) { return yamlVal(v); }).join(', ') + ']';
    }
    for (var i = 0; i < obj.length; i++) {
      if (typeof obj[i] === 'object' && obj[i] !== null && !Array.isArray(obj[i])) {
        var keys = Object.keys(obj[i]);
        if (keys.length > 0) {
          var first = keys[0];
          var firstVal = obj[i][first];
          if (typeof firstVal === 'object' && firstVal !== null) {
            lines.push(pad + '- ' + first + ':');
            lines.push(toYAMLInner(firstVal, indent + 2));
          } else {
            lines.push(pad + '- ' + first + ': ' + yamlVal(firstVal));
          }
          for (var k = 1; k < keys.length; k++) {
            var rv = obj[i][keys[k]];
            if (typeof rv === 'object' && rv !== null) {
              lines.push(pad + '  ' + keys[k] + ':');
              lines.push(toYAMLInner(rv, indent + 2));
            } else {
              lines.push(pad + '  ' + keys[k] + ': ' + yamlVal(rv));
            }
          }
        }
      } else {
        lines.push(pad + '- ' + yamlVal(obj[i]));
      }
    }
    return lines.join('\\n');
  }

  if (typeof obj === 'object' && obj !== null) {
    var keys = Object.keys(obj);
    for (var i = 0; i < keys.length; i++) {
      var key = keys[i];
      var val = obj[key];
      if (typeof val === 'object' && val !== null) {
        if (Array.isArray(val) && val.length > 0 && typeof val[0] !== 'object') {
          lines.push(pad + key + ': ' + '[' + val.map(function(v) { return yamlVal(v); }).join(', ') + ']');
        } else {
          lines.push(pad + key + ':');
          lines.push(toYAMLInner(val, indent + 1));
        }
      } else {
        lines.push(pad + key + ': ' + yamlVal(val));
      }
    }
    return lines.join('\\n');
  }

  return pad + yamlVal(obj);
}

/* ── Build ROE object from form ────────────────────────────────── */
function buildROE() {
  var roe = {};

  /* Metadata */
  var meta = {};
  var eid = v('meta-engagement-id');
  if (eid) meta.engagement_id = eid;
  var cl = v('meta-client');
  if (cl) meta.client = cl;
  var ts = v('meta-tester');
  if (ts) meta.tester = ts;
  var ab = v('meta-approved-by');
  if (ab) meta.approved_by = ab;
  var cf = v('meta-classification');
  if (cf) meta.classification = cf;
  if (Object.keys(meta).length) roe.metadata = meta;

  /* Schedule */
  var sched = {};
  var vf = v('sched-valid-from');
  if (vf) sched.valid_from = toISOish(vf);
  var vu = v('sched-valid-until');
  if (vu) sched.valid_until = toISOish(vu);
  var ah = v('sched-hours');
  if (ah) sched.allowed_hours = ah;
  var tz = v('sched-timezone');
  if (tz) sched.timezone = tz;
  /* blackouts */
  var brows = document.querySelectorAll('#blackout-list .dynamic-row');
  if (brows.length) {
    var bds = [];
    brows.forEach(function(r) {
      var bf = r.querySelector('.bo-from').value;
      var bt = r.querySelector('.bo-to').value;
      if (bf || bt) bds.push({from: toISOish(bf), to: toISOish(bt)});
    });
    if (bds.length) sched.blackout_dates = bds;
  }
  if (Object.keys(sched).length) roe.schedule = sched;

  /* Scope */
  var scope = {};
  /* in_scope */
  var inScope = {};
  var inNets = [];
  document.querySelectorAll('#in-scope-networks .dynamic-row').forEach(function(r) {
    var cidr = r.querySelector('.isn-cidr').value.trim();
    if (!cidr) return;
    var obj = {cidr: cidr};
    var desc = r.querySelector('.isn-desc').value.trim();
    if (desc) obj.description = desc;
    var ports = parsePorts(r.querySelector('.isn-ports').value);
    if (ports.length) obj.ports = ports;
    inNets.push(obj);
  });
  if (inNets.length) inScope.networks = inNets;

  var inDoms = [];
  document.querySelectorAll('#in-scope-domains .dynamic-row').forEach(function(r) {
    var pat = r.querySelector('.isd-pattern').value.trim();
    if (!pat) return;
    var obj = {pattern: pat};
    var desc = r.querySelector('.isd-desc').value.trim();
    if (desc) obj.description = desc;
    inDoms.push(obj);
  });
  if (inDoms.length) inScope.domains = inDoms;
  if (Object.keys(inScope).length) scope.in_scope = inScope;

  /* out_of_scope */
  var outScope = {};
  var outNets = [];
  document.querySelectorAll('#out-scope-networks .dynamic-row').forEach(function(r) {
    var cidr = r.querySelector('.osn-cidr').value.trim();
    if (!cidr) return;
    var obj = {cidr: cidr};
    var rsn = r.querySelector('.osn-reason').value.trim();
    if (rsn) obj.reason = rsn;
    outNets.push(obj);
  });
  if (outNets.length) outScope.networks = outNets;

  var outSvcs = [];
  document.querySelectorAll('#out-scope-services .dynamic-row').forEach(function(r) {
    var tp = r.querySelector('.oss-type').value;
    var obj = {type: tp};
    var proto = r.querySelector('.oss-proto').value.trim();
    if (proto) obj.protocols = proto.split(',').map(function(s) { return s.trim(); }).filter(Boolean);
    outSvcs.push(obj);
  });
  if (outSvcs.length) outScope.services = outSvcs;

  var outDoms = [];
  document.querySelectorAll('#out-scope-domains .dynamic-row').forEach(function(r) {
    var pat = r.querySelector('.osd-pattern').value.trim();
    if (!pat) return;
    var obj = {pattern: pat};
    var rsn = r.querySelector('.osd-reason').value.trim();
    if (rsn) obj.reason = rsn;
    outDoms.push(obj);
  });
  if (outDoms.length) outScope.domains = outDoms;
  if (Object.keys(outScope).length) scope.out_of_scope = outScope;

  if (Object.keys(scope).length) roe.scope = scope;

  /* Actions */
  var actions = {};
  var allowed = [];
  document.querySelectorAll('#allowed-actions .dynamic-row').forEach(function(r) {
    var cat = r.querySelector('.aa-cat').value;
    if (cat === '_custom') return;
    var obj = {category: cat};
    var methods = r.querySelector('.aa-methods').value.trim();
    if (methods) obj.methods = methods.split(',').map(function(s) { return s.trim(); }).filter(Boolean);
    /* constraints */
    var kvList = r.querySelector('.kv-list');
    if (kvList) {
      var kvs = {};
      kvList.querySelectorAll('.kv-row').forEach(function(kr) {
        var k = kr.querySelector('.kv-key').value.trim();
        var vl = kr.querySelector('.kv-val').value.trim();
        if (k) kvs[k] = inferType(vl);
      });
      if (Object.keys(kvs).length) obj.constraints = kvs;
    }
    allowed.push(obj);
  });
  if (allowed.length) actions.allowed = allowed;

  var denied = [];
  document.querySelectorAll('#denied-actions .dynamic-row').forEach(function(r) {
    var cat = r.querySelector('.da-cat').value;
    if (cat === '_custom') return;
    var obj = {category: cat};
    var rsn = r.querySelector('.da-reason').value.trim();
    if (rsn) obj.reason = rsn;
    denied.push(obj);
  });
  if (denied.length) actions.denied = denied;

  if (Object.keys(actions).length) roe.actions = actions;

  /* Constraints */
  var constraints = {};
  var mc = v('con-max-connections');
  if (mc) constraints.max_concurrent_connections = parseInt(mc, 10);
  var rl = v('con-rate-limit');
  if (rl) constraints.global_rate_limit = rl;
  constraints.no_persistent_changes = document.getElementById('con-no-persistent').checked;
  constraints.no_production_data_storage = document.getElementById('con-no-prod-data').checked;
  /* custom */
  document.querySelectorAll('#custom-constraints .kv-row').forEach(function(kr) {
    var k = kr.querySelector('.kv-key').value.trim();
    var vl = kr.querySelector('.kv-val').value.trim();
    if (k) constraints[k] = inferType(vl);
  });
  roe.constraints = constraints;

  /* Emergency */
  var em = {};
  em.kill_switch = document.getElementById('em-kill-switch').checked;
  var md = v('em-max-denials');
  if (md) em.max_consecutive_denials = parseInt(md, 10);
  var ec = v('em-contact');
  if (ec) em.escalation_contact = ec;
  var wh = v('em-webhook');
  if (wh) em.notification_webhook = wh;
  roe.emergency = em;

  return {roe: roe};
}

/* ── Helpers ───────────────────────────────────────────────────── */
function v(id) { return document.getElementById(id).value.trim(); }

function toISOish(dtLocal) {
  if (!dtLocal) return '';
  /* datetime-local gives "2024-01-15T09:00", we append :00Z */
  if (dtLocal.length === 16) return dtLocal + ':00Z';
  return dtLocal;
}

function parsePorts(s) {
  if (!s) return [];
  return s.split(',').map(function(p) { return parseInt(p.trim(), 10); }).filter(function(n) { return !isNaN(n); });
}

function inferType(s) {
  if (s === 'true') return true;
  if (s === 'false') return false;
  if (s !== '' && !isNaN(Number(s)) && !/^0\\d/.test(s)) return Number(s);
  return s;
}

/* ================================================================
   YAML GENERATION (main entry)
   ================================================================ */
function generateYAML() {
  var obj = buildROE();
  var raw = toYAML(obj, 0);
  document.getElementById('yaml-output').innerHTML = highlightYAML(raw);
  updateSectionStatuses();
}

/* ── Syntax highlighting ───────────────────────────────────────── */
function highlightYAML(text) {
  var lines = text.split('\\n');
  var out = [];
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i];
    /* escape HTML */
    line = line.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    /* comment */
    if (/^\\s*#/.test(line)) {
      out.push('<span class="y-comment">' + line + '</span>');
      continue;
    }
    /* key: value */
    line = line.replace(/^(\\s*)(- )/, '$1<span class="y-dash">- </span>');
    line = line.replace(/^((?:\\s|<[^>]+>)*)([\\w_][\\w_.-]*)(:)/,
      function(m, pre, key, colon) { return pre + '<span class="y-key">' + key + '</span>' + colon; });
    /* inline values */
    line = line.replace(/: "((?:[^"\\\\]|\\\\.)*)"/, function(m, s) { return ': <span class="y-str">&quot;' + s + '&quot;</span>'; });
    line = line.replace(/: (true|false)(?=$|\\s)/, function(m, b) { return ': <span class="y-bool">' + b + '</span>'; });
    line = line.replace(/: (\\d+(?:\\.\\d+)?)(?=$|\\s)/, function(m, n) { return ': <span class="y-num">' + n + '</span>'; });
    /* array inline items */
    line = line.replace(/\\[([^\\]]+)\\]/g, function(m, inner) {
      var items = inner.split(',').map(function(s) {
        s = s.trim();
        if (/^\\d+$/.test(s)) return '<span class="y-num">' + s + '</span>';
        if (/^".*"$/.test(s)) return '<span class="y-str">' + s + '</span>';
        return '<span class="y-str">' + s + '</span>';
      });
      return '[' + items.join(', ') + ']';
    });
    out.push(line);
  }
  return out.join('\\n');
}

/* ── Section status indicators ─────────────────────────────────── */
function updateSectionStatuses() {
  /* Metadata */
  var metaOk = v('meta-engagement-id') && v('meta-client');
  setStatus('status-metadata', metaOk);
  /* Schedule */
  var schedOk = v('sched-valid-from') && v('sched-valid-until');
  setStatus('status-schedule', schedOk);
  /* In-scope */
  var hasNet = document.querySelectorAll('#in-scope-networks .dynamic-row').length > 0;
  setStatus('status-in-scope', hasNet);
}

function setStatus(id, ok) {
  var el = document.getElementById(id);
  if (ok) {
    el.className = 'section-status complete';
    el.textContent = 'Complete';
  } else {
    el.className = 'section-status incomplete';
    el.textContent = 'Required';
  }
}

/* ================================================================
   IMPORT / EXPORT
   ================================================================ */
function copyYAML() {
  var obj = buildROE();
  var raw = toYAML(obj, 0);
  navigator.clipboard.writeText(raw).then(function() {
    showToast('YAML copied to clipboard', 'success');
  }).catch(function() {
    showToast('Copy failed', 'error');
  });
}

function downloadYAML() {
  var obj = buildROE();
  var raw = toYAML(obj, 0);
  var blob = new Blob([raw], {type: 'text/yaml'});
  var a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'roe_spec.yaml';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  showToast('Downloaded roe_spec.yaml', 'success');
}

/* ── Import ────────────────────────────────────────────────────── */
function showImportModal() {
  document.getElementById('import-modal').classList.add('show');
  document.getElementById('import-textarea').value = '';
  document.getElementById('import-file').value = '';
}
function closeImportModal() {
  document.getElementById('import-modal').classList.remove('show');
}

document.getElementById('import-file').addEventListener('change', function(e) {
  var file = e.target.files[0];
  if (!file) return;
  var reader = new FileReader();
  reader.onload = function(ev) {
    document.getElementById('import-textarea').value = ev.target.result;
  };
  reader.readAsText(file);
});

function doImport() {
  var yaml = document.getElementById('import-textarea').value.trim();
  if (!yaml) { showToast('No YAML to import', 'error'); return; }
  try {
    var parsed = parseSimpleYAML(yaml);
    var roe = parsed.roe || parsed;
    fillFormFromROE(roe);
    closeImportModal();
    generateYAML();
    showToast('YAML imported successfully', 'success');
  } catch(err) {
    showToast('Parse error: ' + err.message, 'error');
  }
}

/* ── Simple YAML parser (handles our ROE subset) ───────────────── */
function parseSimpleYAML(text) {
  var lines = text.split('\\n');
  var root = {};
  var stack = [{obj: root, indent: -1}];

  for (var i = 0; i < lines.length; i++) {
    var raw = lines[i];
    /* skip comments and empty lines */
    if (/^\\s*#/.test(raw) || /^\\s*$/.test(raw)) continue;

    var indent = raw.search(/\\S/);
    var line = raw.trim();

    /* pop stack to correct level */
    while (stack.length > 1 && stack[stack.length - 1].indent >= indent) {
      stack.pop();
    }
    var current = stack[stack.length - 1].obj;

    /* array item */
    if (line.startsWith('- ')) {
      var content = line.substring(2).trim();
      /* ensure parent is array */
      if (!Array.isArray(current)) continue;
      if (content.indexOf(':') !== -1) {
        /* key: value on same line as dash */
        var obj = {};
        var cp = content.indexOf(':');
        var k = content.substring(0, cp).trim();
        var val = content.substring(cp + 1).trim();
        obj[k] = parseYAMLValue(val);
        current.push(obj);
        stack.push({obj: obj, indent: indent});
      } else {
        current.push(parseYAMLValue(content));
      }
      continue;
    }

    /* key: value */
    var colonPos = line.indexOf(':');
    if (colonPos === -1) continue;
    var key = line.substring(0, colonPos).trim();
    var value = line.substring(colonPos + 1).trim();

    if (value === '' || value === '|' || value === '>') {
      /* Check if next line starts a list */
      var nextI = i + 1;
      while (nextI < lines.length && /^\\s*$/.test(lines[nextI])) nextI++;
      if (nextI < lines.length && lines[nextI].trim().startsWith('- ')) {
        var arr = [];
        current[key] = arr;
        stack.push({obj: arr, indent: indent});
      } else {
        var child = {};
        current[key] = child;
        stack.push({obj: child, indent: indent});
      }
    } else {
      current[key] = parseYAMLValue(value);
    }
  }
  return root;
}

function parseYAMLValue(s) {
  if (s === '' || s === '~' || s === 'null') return null;
  if (s === 'true' || s === 'yes') return true;
  if (s === 'false' || s === 'no') return false;
  /* inline array [a, b, c] */
  if (s.charAt(0) === '[' && s.charAt(s.length - 1) === ']') {
    var inner = s.substring(1, s.length - 1);
    if (inner.trim() === '') return [];
    return inner.split(',').map(function(v) {
      v = v.trim();
      if (v.charAt(0) === '"' && v.charAt(v.length - 1) === '"') return v.substring(1, v.length - 1);
      if (v.charAt(0) === "'" && v.charAt(v.length - 1) === "'") return v.substring(1, v.length - 1);
      if (!isNaN(Number(v)) && v !== '') return Number(v);
      return v;
    });
  }
  /* quoted string */
  if ((s.charAt(0) === '"' && s.charAt(s.length - 1) === '"') ||
      (s.charAt(0) === "'" && s.charAt(s.length - 1) === "'")) {
    return s.substring(1, s.length - 1);
  }
  /* number */
  if (!isNaN(Number(s)) && s !== '') return Number(s);
  return s;
}

/* ── Fill form from parsed ROE ─────────────────────────────────── */
function fillFormFromROE(roe) {
  /* Clear dynamic lists */
  var lists = ['blackout-list','in-scope-networks','in-scope-domains',
               'out-scope-networks','out-scope-services','out-scope-domains',
               'allowed-actions','denied-actions','custom-constraints'];
  lists.forEach(function(id) { document.getElementById(id).innerHTML = ''; });

  /* Metadata */
  var m = roe.metadata || {};
  document.getElementById('meta-engagement-id').value = m.engagement_id || '';
  document.getElementById('meta-client').value = m.client || '';
  document.getElementById('meta-tester').value = m.tester || '';
  document.getElementById('meta-approved-by').value = m.approved_by || '';
  if (m.classification) document.getElementById('meta-classification').value = m.classification;

  /* Schedule */
  var s = roe.schedule || {};
  if (s.valid_from) document.getElementById('sched-valid-from').value = toLocalDT(s.valid_from);
  if (s.valid_until) document.getElementById('sched-valid-until').value = toLocalDT(s.valid_until);
  document.getElementById('sched-hours').value = s.allowed_hours || '';
  if (s.timezone) document.getElementById('sched-timezone').value = s.timezone;
  if (s.blackout_dates && Array.isArray(s.blackout_dates)) {
    s.blackout_dates.forEach(function(b) {
      addBlackoutRow(toLocalDT(b.from || ''), toLocalDT(b.to || ''));
    });
  }

  /* In-scope */
  var isc = (roe.scope || {}).in_scope || {};
  if (isc.networks) isc.networks.forEach(function(n) {
    var ports = Array.isArray(n.ports) ? n.ports.join(', ') : '';
    addInScopeNetwork(n.cidr || '', ports, n.description || '');
  });
  if (isc.domains) isc.domains.forEach(function(d) {
    addInScopeDomain(d.pattern || d, d.description || '');
  });

  /* Out-of-scope */
  var osc = (roe.scope || {}).out_of_scope || {};
  if (osc.networks) osc.networks.forEach(function(n) {
    addOutScopeNetwork(n.cidr || '', n.reason || '');
  });
  if (osc.services) osc.services.forEach(function(sv) {
    var proto = Array.isArray(sv.protocols) ? sv.protocols.join(', ') : '';
    addOutScopeService(sv.type || '', proto);
  });
  if (osc.domains) osc.domains.forEach(function(d) {
    addOutScopeDomain(d.pattern || d, d.reason || '');
  });

  /* Allowed */
  var act = roe.actions || {};
  if (act.allowed) act.allowed.forEach(function(a) {
    var methods = Array.isArray(a.methods) ? a.methods.join(', ') : '';
    addAllowedAction(a.category || '', methods, a.constraints || null);
  });
  if (act.denied) act.denied.forEach(function(d) {
    addDeniedAction(d.category || '', d.reason || '');
  });

  /* Constraints */
  var c = roe.constraints || {};
  document.getElementById('con-max-connections').value = c.max_concurrent_connections || '';
  document.getElementById('con-rate-limit').value = c.global_rate_limit || '';
  document.getElementById('con-no-persistent').checked = c.no_persistent_changes !== false;
  document.getElementById('con-no-prod-data').checked = c.no_production_data_storage !== false;
  /* custom */
  var stdKeys = ['max_concurrent_connections','global_rate_limit','no_persistent_changes','no_production_data_storage'];
  Object.keys(c).forEach(function(k) {
    if (stdKeys.indexOf(k) === -1) addCustomConstraint(k, String(c[k]));
  });

  /* Emergency */
  var em = roe.emergency || {};
  document.getElementById('em-kill-switch').checked = em.kill_switch !== false;
  document.getElementById('em-max-denials').value = em.max_consecutive_denials || 3;
  document.getElementById('em-contact').value = em.escalation_contact || '';
  document.getElementById('em-webhook').value = em.notification_webhook || '';
}

function toLocalDT(iso) {
  if (!iso) return '';
  /* strip trailing Z or timezone for datetime-local input */
  return iso.replace(/Z$/, '').replace(/[+-]\\d{2}:\\d{2}$/, '').substring(0, 16);
}

/* ── Validation ────────────────────────────────────────────────── */
function validateForm() {
  var ok = true;
  var fields = document.querySelectorAll('[data-required]');
  fields.forEach(function(f) {
    if (!f.value.trim()) {
      f.classList.add('error');
      ok = false;
    } else {
      f.classList.remove('error');
    }
  });
  /* check at least one in-scope network */
  if (document.querySelectorAll('#in-scope-networks .dynamic-row').length === 0) {
    ok = false;
  }

  if (ok) {
    showToast('Validation passed — all required fields complete', 'success');
  } else {
    showToast('Validation failed — check highlighted fields', 'error');
    /* open metadata section if fields missing */
    if (!v('meta-engagement-id') || !v('meta-client')) {
      document.getElementById('sec-metadata').classList.add('open');
    }
    if (!v('sched-valid-from') || !v('sched-valid-until')) {
      document.getElementById('sec-schedule').classList.add('open');
    }
    if (document.querySelectorAll('#in-scope-networks .dynamic-row').length === 0) {
      document.getElementById('sec-in-scope').classList.add('open');
    }
  }
  return ok;
}

/* ── Keyboard shortcuts ────────────────────────────────────────── */
document.addEventListener('keydown', function(e) {
  if ((e.ctrlKey || e.metaKey) && e.key === 's') {
    e.preventDefault();
    downloadYAML();
  }
  if ((e.ctrlKey || e.metaKey) && e.shiftKey && (e.key === 'C' || e.key === 'c')) {
    e.preventDefault();
    copyYAML();
  }
});

/* ── Auto-update on input ──────────────────────────────────────── */
document.addEventListener('input', function() {
  generateYAML();
});
document.addEventListener('change', function() {
  generateYAML();
});

/* ── Clear error class on focus ────────────────────────────────── */
document.addEventListener('focusin', function(e) {
  if (e.target.classList) e.target.classList.remove('error');
});

/* ── Initial render ────────────────────────────────────────────── */
generateYAML();
</script>
</body>
</html>"""
