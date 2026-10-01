/** assessments.js — authorized testing modes (passive / static only). */
(async function () {
  const user = await Auth.initAuthenticatedPage('assessments.html');
  if (!user) return;

  const healthEl = document.getElementById('api-health');
  try {
    const health = await Api.get('/api/health/');
    healthEl.innerHTML = health.ok
      ? '<span class="hud-online"><span class="status-light"></span> API and database reachable</span>'
      : '<span class="text-dim">API is up but the database is not. Code scans may fail until MySQL is back.</span>';
  } catch (e) {
    healthEl.textContent = e.message || 'API health check failed.';
  }

  let modes = [];
  let selected = null;
  try {
    const data = await Api.get('/api/assessments/modes/');
    modes = data.modes || [];
    if (data.notice) {
      healthEl.insertAdjacentHTML(
        'beforeend',
        `<p class="text-dim mt-8">${Utils.escapeHtml(data.notice)}</p>`
      );
    }
  } catch (e) {
    document.getElementById('run-blurb').textContent = e.message || 'Could not load modes.';
    return;
  }

  const select = document.getElementById('mode-select');
  select.innerHTML = '<option value="">Select a test…</option>' + modes.map((m) =>
    `<option value="${Utils.escapeHtml(m.id)}">${Utils.escapeHtml(m.name)} — ${Utils.escapeHtml(m.receives)}</option>`
  ).join('');

  function fieldHtml(name) {
    if (name === 'url') {
      return `<label>Target URL<input class="input mt-8 mb-16" name="url" placeholder="https://example.com" autocomplete="off"></label>`;
    }
    if (name === 'bearer_token') {
      return `<label>Optional bearer token (not stored)<input class="input mt-8 mb-16" name="bearer_token" type="password" autocomplete="off"></label>`;
    }
    if (name === 'host') {
      return `<label>Hostname (optional, for DNS)<input class="input mt-8 mb-16" name="host" placeholder="example.com" autocomplete="off"></label>`;
    }
    if (name === 'scope_notes') {
      return `<label>Scope / rules of engagement<textarea class="input mt-8 mb-16" name="scope_notes" placeholder="In-scope hosts, time window, contacts"></textarea></label>`;
    }
    if (name === 'source') {
      return `<label>Source or config paste<textarea class="input mt-8 mb-16" name="source" placeholder="Paste code or IaC"></textarea></label>`;
    }
    if (name === 'config_text') {
      return `<label>Configuration<textarea class="input mt-8 mb-16" name="config_text" placeholder="JSON policy, Dockerfile, or Compose"></textarea></label>`;
    }
    if (name === 'spec_text') {
      return `<label>OpenAPI JSON<textarea class="input mt-8 mb-16" name="spec_text" placeholder="{}"></textarea></label>`;
    }
    if (name === 'package') {
      return `<label>APK / IPA / zip<input class="input mt-8 mb-16" name="package" type="file" accept=".apk,.ipa,.zip"></label>`;
    }
    return '';
  }

  function selectMode(id) {
    selected = modes.find((m) => m.id === id) || null;
    const form = document.getElementById('run-form');
    const btn = document.getElementById('run-btn');
    if (!selected) {
      form.hidden = true;
      btn.disabled = true;
      document.getElementById('run-blurb').textContent = 'Pick a mode to load the matching form.';
      return;
    }
    form.hidden = false;
    btn.disabled = false;
    document.getElementById('run-title').textContent = selected.name;
    document.getElementById('run-blurb').textContent = selected.testing;
    document.getElementById('run-fields').innerHTML = (selected.inputs || []).map(fieldHtml).join('');
    const own = document.getElementById('own-wrap');
    own.style.display = selected.requires_ownership ? 'flex' : 'none';
    document.getElementById('run-result').innerHTML = '';
    select.value = selected.id;
  }

  select.addEventListener('change', () => selectMode(select.value));

  function renderFindings(data) {
    const rows = (data.findings || []).map((f) => `
      <div class="finding-row">
        <div><span class="sev-${Utils.escapeHtml(f.severity || 'info')}">${Utils.escapeHtml((f.severity || 'info').toUpperCase())}</span>
        <strong> ${Utils.escapeHtml(f.title || '')}</strong></div>
        <p class="text-dim mt-8">${Utils.escapeHtml(f.detail || '')}</p>
        ${f.evidence ? `<pre class="net-result mt-8">${Utils.escapeHtml(f.evidence)}</pre>` : ''}
      </div>
    `).join('') || '<p class="text-dim">No findings.</p>';
    const extra = data.next
      ? `<p class="mt-16"><a href="${Utils.escapeHtml(data.next)}">Open Projects for full SAST/SCA →</a></p>`
      : '';
    return `<div class="card page-enter"><div class="card-header"><h3>Results</h3></div>
      <p class="text-dim mb-16">${Utils.escapeHtml(data.summary || '')}</p>${rows}${extra}</div>`;
  }

  document.getElementById('run-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    if (!selected) return;
    const form = ev.target;
    const fd = new FormData(form);
    const box = document.getElementById('run-result');
    const btn = document.getElementById('run-btn');
    btn.disabled = true;
    box.innerHTML = '<p class="terminal-log">running assessment…</p>';
    const payload = {};
    (selected.inputs || []).forEach((name) => {
      if (name === 'package') return;
      payload[name] = fd.get(name);
    });
    try {
      let data;
      if (selected.id === 'mobile') {
        const send = new FormData();
        send.append('mode', selected.id);
        send.append('confirm_owned', fd.get('confirm_owned') === 'on' ? 'true' : 'false');
        send.append('payload', '{}');
        const file = fd.get('package');
        if (file && file.size) send.append('package', file);
        data = await Api.postForm('/api/assessments/run/', send);
      } else {
        data = await Api.post('/api/assessments/run/', {
          mode: selected.id,
          confirm_owned: fd.get('confirm_owned') === 'on',
          payload,
        });
      }
      box.innerHTML = renderFindings(data);
    } catch (e) {
      box.innerHTML = `<p class="terminal-log">${Utils.escapeHtml(e.message || 'Assessment failed.')}</p>`;
    } finally {
      btn.disabled = false;
    }
  });

  const q = new URLSearchParams(location.search).get('mode');
  if (q && modes.some((m) => m.id === q)) selectMode(q);
})();
