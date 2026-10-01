/** network.js — defensive Network lab: session IP, DNS, local ports, HTTP headers. */
(async function () {
  const user = await Auth.initAuthenticatedPage('network.html');
  if (!user) return;

  const toolSel = document.getElementById('net-tool');
  function showTool(id) {
    document.querySelectorAll('.net-panel').forEach((el) => {
      el.hidden = el.dataset.tool !== id;
    });
  }
  if (toolSel) {
    showTool(toolSel.value);
    toolSel.addEventListener('change', () => showTool(toolSel.value));
  }

  function dump(obj) {
    return Utils.escapeHtml(JSON.stringify(obj, null, 2));
  }

  try {
    const self = await Api.get('/api/network/self/');
    const kind = self.classification?.kind || 'unknown';
    document.getElementById('self-result').innerHTML =
      `<div><strong>${Utils.escapeHtml(self.client_ip || '—')}</strong> · ${Utils.escapeHtml(kind)}</div>` +
      `<p class="text-dim mt-8">${Utils.escapeHtml(self.note || '')}</p>`;
  } catch (e) {
    document.getElementById('self-result').textContent = e.message || 'Could not load session address.';
  }

  document.getElementById('ip-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const ip = new FormData(ev.target).get('ip');
    const box = document.getElementById('ip-result');
    box.textContent = 'Checking…';
    try {
      const data = await Api.post('/api/network/ip/', { ip });
      box.innerHTML = dump(data);
    } catch (e) {
      box.textContent = e.message || 'Could not classify that address.';
    }
  });

  document.getElementById('dns-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const host = new FormData(ev.target).get('host');
    const box = document.getElementById('dns-result');
    box.textContent = 'Resolving…';
    try {
      const data = await Api.post('/api/network/dns/', { host });
      const rec = data.records || {};
      box.innerHTML =
        `<div>Host: <strong>${Utils.escapeHtml(data.host)}</strong></div>` +
        `<div>A: ${Utils.escapeHtml((rec.a || []).join(', ') || '—')}</div>` +
        `<div>AAAA: ${Utils.escapeHtml((rec.aaaa || []).join(', ') || '—')}</div>` +
        `<div>PTR: ${Utils.escapeHtml((rec.ptr || []).join(', ') || '—')}</div>`;
    } catch (e) {
      box.textContent = e.message || 'Lookup failed.';
    }
  });

  document.getElementById('ports-btn').addEventListener('click', async () => {
    const box = document.getElementById('ports-result');
    box.innerHTML = '<p class="text-dim">Checking 127.0.0.1…</p>';
    try {
      const data = await Api.post('/api/network/local-ports/', {});
      const rows = (data.ports || []).map((row) =>
        `<div class="port-row"><span>${row.port}</span><span class="${row.open ? 'port-open' : 'port-closed'}">${row.open ? 'open' : 'closed'}</span></div>`
      ).join('');
      box.innerHTML = `<p class="text-dim mb-16">${Utils.escapeHtml(data.scope || '')} Open: ${data.open_count}</p>${rows}`;
    } catch (e) {
      box.textContent = e.message || 'Could not check local ports.';
    }
  });

  document.getElementById('headers-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const form = new FormData(ev.target);
    const box = document.getElementById('headers-result');
    box.innerHTML = '<p class="text-dim">Fetching headers…</p>';
    try {
      const data = await Api.post('/api/network/headers/', {
        url: form.get('url'),
        confirm_owned: form.get('confirm_owned') === 'on',
      });
      const missing = (data.missing || []).map((h) => Utils.escapeHtml(h)).join(', ') || 'none of the core set';
      const rows = (data.security_headers || []).map((row) =>
        `<div class="port-row"><span>${Utils.escapeHtml(row.header)}</span><span class="${row.present ? 'port-open' : 'port-closed'}">${row.present ? Utils.escapeHtml(row.value || 'present') : 'missing'}</span></div>`
      ).join('');
      box.innerHTML =
        `<p class="text-dim mb-16">HTTP ${data.status_code} · ${Utils.escapeHtml(data.final_url || '')}</p>` +
        `<p class="mb-16">Missing: ${missing}</p>${rows}`;
    } catch (e) {
      box.textContent = e.message || 'Header check failed.';
    }
  });
})();
