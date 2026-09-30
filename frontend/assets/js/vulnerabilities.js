/** vulnerabilities.js - findings/secrets/dependencies table with filters,
 * search, pagination, and a finding-details modal. Results are scoped to a
 * project/scan so one folder's secrets are not shown after scanning another. */
(async function () {
  const user = await Auth.initAuthenticatedPage('vulnerabilities.html');
  if (!user) return;

  const CATEGORIES = ['injection', 'xss', 'authentication', 'access_control', 'cryptography', 'secrets',
    'vulnerable_dependency', 'insecure_configuration', 'infrastructure_as_code', 'container_security',
    'deserialization', 'ssrf', 'path_traversal', 'information_disclosure', 'other'];
  document.getElementById('filter-category').innerHTML += CATEGORIES.map(c => `<option value="${c}">${c.replace(/_/g, ' ')}</option>`).join('');

  let currentTab = 'findings';
  let currentPage = 1;
  let scanId = Utils.getQueryParam('scan');
  let projectId = Utils.getQueryParam('project');
  let compareDiff = { new: [], still_open: [], resolved: [] };
  let compareTab = 'new';
  let activeFinding = null;

  async function loadProjects() {
    const select = document.getElementById('filter-project');
    try {
      const data = await Api.get('/api/projects/?page_size=100');
      select.innerHTML = '<option value="">All Projects</option>' + (data.results || []).map((p) =>
        `<option value="${p.id}">${Utils.escapeHtml(p.name)}</option>`
      ).join('');
      if (projectId) select.value = String(projectId);
    } catch (e) { /* dropdown stays empty */ }
  }

  function showBackToEditor() {
    if (!projectId) return;
    const wrap = document.getElementById('back-to-editor-wrap');
    const link = document.getElementById('back-to-editor-link');
    if (wrap && link) {
      link.href = `editor.html?project=${projectId}`;
      wrap.style.display = 'block';
    }
  }

  async function loadScopeLabel() {
    const el = document.getElementById('findings-scope');
    if (scanId) {
      try {
        const scan = await Api.get(`/api/scans/${scanId}/`);
        projectId = String(scan.project);
        const select = document.getElementById('filter-project');
        if (select.querySelector(`option[value="${projectId}"]`)) select.value = projectId;
        el.style.display = 'block';
        const scope = scan.scope_path ? ` Scoped to ${scan.scope_path}.` : '';
        el.textContent = `Showing results for scan #${scan.id} (${scan.status}) in this project.${scope}`;
        showBackToEditor();
        loadCompare(scanId);
        return;
      } catch (e) { /* fall through */ }
    }
    document.getElementById('compare-card').style.display = 'none';
    if (projectId) {
      const name = document.getElementById('filter-project').selectedOptions[0]?.textContent || 'this project';
      el.style.display = 'block';
      el.textContent = `Showing the latest completed scan for ${name}.`;
      showBackToEditor();
      return;
    }
    el.style.display = 'none';
  }

  function buildQuery() {
    const params = new URLSearchParams();
    params.set('page', currentPage);
    params.set('page_size', 25);
    const search = document.getElementById('search-input').value.trim();
    const severity = document.getElementById('filter-severity').value;
    const status = document.getElementById('filter-status').value;
    const category = document.getElementById('filter-category').value;
    const project = document.getElementById('filter-project').value || projectId;
    if (search) params.set('search', search);
    if (severity) params.set('severity', severity);
    if (status && currentTab !== 'dependencies') params.set('status', status);
    if (category && currentTab === 'findings') params.set('category', category);
    if (scanId) params.set('scan', scanId);
    if (project) params.set('project', project);
    return params.toString();
  }

  function secretAsFindingRow(s) {
    return {
      id: s.id,
      kind: 'secret',
      severity: s.severity,
      title: s.secret_type,
      project_name: s.project_name,
      scanner: 'secrets',
      category: 'secrets',
      file_path: s.file_path,
      line_start: s.line_number,
      status: s.status,
      first_detected_at: s.created_at,
    };
  }

  async function load() {
    const body = document.getElementById('findings-body');
    body.innerHTML = `<tr><td colspan="8" class="text-dim">Loading...</td></tr>`;
    const qs = buildQuery();
    try {
      if (currentTab === 'findings') {
        const [code, secrets] = await Promise.all([
          Api.get(`/api/findings/?${qs}`),
          Api.get(`/api/secret-findings/?${qs}`),
        ]);
        const rows = [...(code.results || []), ...(secrets.results || []).map(secretAsFindingRow)];
        const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
        rows.sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9));
        document.getElementById('result-count').textContent = `${rows.length} result${rows.length === 1 ? '' : 's'}`;
        renderRows(rows);
        renderPagination({ num_pages: 1 });
        return;
      }
      const endpoint = { secrets: '/api/secret-findings/', dependencies: '/api/dependencies/' }[currentTab];
      const data = await Api.get(`${endpoint}?${qs}`);
      document.getElementById('result-count').textContent = `${data.count} result${data.count === 1 ? '' : 's'}`;
      renderRows(data.results);
      renderPagination(data);
    } catch (e) {
      body.innerHTML = `<tr><td colspan="8" class="text-dim">Failed to load.</td></tr>`;
    }
  }

  function projectCell(row) {
    return `<td class="text-dim">${Utils.escapeHtml(row.project_name || '')}</td>`;
  }

  function renderRows(rows) {
    const body = document.getElementById('findings-body');
    const head = document.querySelector('#findings-table thead tr');
    if (!rows.length) {
      body.innerHTML = `<tr><td colspan="8" class="empty-state">No results for this project or scan. Run a scan from a project, or <a href="team.html">invite a teammate</a> so they can see shared work.</td></tr>`;
      return;
    }
    if (currentTab === 'findings') {
      head.innerHTML = '<th>Severity</th><th>Title</th><th>Project</th><th>Scanner</th><th>File</th><th>Line</th><th>Status</th><th>First Seen</th>';
      body.innerHTML = rows.map((f) => `
        <tr style="cursor:pointer;" onclick="openFindingDetail(${f.id}, '${f.kind === 'secret' ? 'secret' : 'finding'}')">
          <td>${Utils.severityBadge(f.severity)}</td>
          <td>${Utils.escapeHtml(f.title)}</td>
          ${projectCell(f)}
          <td class="mono text-dim">${Utils.escapeHtml(f.scanner || f.category || '')}</td>
          <td class="mono text-dim" style="max-width:220px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${Utils.escapeHtml(f.file_path)}</td>
          <td>${f.line_start || '-'}</td>
          <td>${Utils.statusBadge(f.status)}</td>
          <td class="text-dim">${Utils.timeAgo(f.first_detected_at)}</td>
        </tr>`).join('');
    } else if (currentTab === 'secrets') {
      head.innerHTML = '<th>Severity</th><th>Type</th><th>Project</th><th>File</th><th>Line</th><th>Masked Value</th><th>Status</th><th>Detected</th>';
      body.innerHTML = rows.map((s) => `
        <tr style="cursor:pointer;" onclick="openFindingDetail(${s.id}, 'secret')">
          <td>${Utils.severityBadge(s.severity)}</td>
          <td>${Utils.escapeHtml(s.secret_type)}</td>
          ${projectCell(s)}
          <td class="mono text-dim">${Utils.escapeHtml(s.file_path)}</td>
          <td>${s.line_number || '-'}</td>
          <td class="mono">${Utils.escapeHtml(s.masked_value)}</td>
          <td>${Utils.statusBadge(s.status)}</td>
          <td class="text-dim">${Utils.timeAgo(s.created_at)}</td>
        </tr>`).join('');
    } else {
      head.innerHTML = '<th>Severity</th><th>Package</th><th>Project</th><th>Version</th><th>Ecosystem</th><th>Vulnerability</th><th>Fixed Version</th><th>Manifest</th>';
      body.innerHTML = rows.map((d) => `
        <tr>
          <td>${d.severity ? Utils.severityBadge(d.severity) : '<span class="badge badge-neutral">-</span>'}</td>
          <td>${Utils.escapeHtml(d.package_name)}</td>
          ${projectCell(d)}
          <td class="mono">${Utils.escapeHtml(d.version)}</td>
          <td>${d.ecosystem}</td>
          <td class="mono text-dim">${Utils.escapeHtml(d.vulnerability_id || '-')}</td>
          <td class="mono">${Utils.escapeHtml(d.fixed_version || '-')}</td>
          <td class="text-dim">${Utils.escapeHtml(d.manifest_file)}</td>
        </tr>`).join('');
    }
  }

  function renderPagination(data) {
    const totalPages = data.num_pages;
    const wrap = document.getElementById('pagination');
    if (totalPages <= 1) { wrap.innerHTML = ''; return; }
    let html = '';
    for (let i = 1; i <= totalPages; i++) {
      if (i === 1 || i === totalPages || Math.abs(i - currentPage) <= 2) {
        html += `<button class="btn btn-sm ${i === currentPage ? 'btn-primary' : ''}" data-page="${i}">${i}</button>`;
      } else if (Math.abs(i - currentPage) === 3) {
        html += `<span class="text-faint">...</span>`;
      }
    }
    wrap.innerHTML = html;
    Utils.qsa('[data-page]', wrap).forEach((btn) => btn.addEventListener('click', () => { currentPage = Number(btn.dataset.page); load(); }));
  }

  function syncUrl() {
    const params = new URLSearchParams();
    if (projectId) params.set('project', projectId);
    if (scanId) params.set('scan', scanId);
    const qs = params.toString();
    history.replaceState(null, '', qs ? `${location.pathname}?${qs}` : location.pathname);
  }

  Utils.qsa('.pill').forEach((pill) => {
    pill.addEventListener('click', () => {
      Utils.qsa('.pill').forEach((p) => p.classList.remove('active'));
      pill.classList.add('active');
      currentTab = pill.dataset.category;
      currentPage = 1;
      load();
    });
  });

  document.getElementById('filter-project').addEventListener('change', () => {
    projectId = document.getElementById('filter-project').value;
    scanId = '';
    currentPage = 1;
    syncUrl();
    loadScopeLabel();
    load();
  });

  ['search-input', 'filter-severity', 'filter-status', 'filter-category'].forEach((id) => {
    const el = document.getElementById(id);
    el.addEventListener(id === 'search-input' ? 'input' : 'change', Utils.debounce(() => { currentPage = 1; load(); }, 300));
  });

  window.openFindingDetail = async function (id, kind) {
    kind = kind || 'finding';
    try {
      const finding = kind === 'secret'
        ? await Api.get(`/api/secret-findings/${id}/`)
        : await Api.get(`/api/findings/${id}/`);
      const title = finding.title || finding.secret_type;
      const filePath = finding.file_path || '';
      const line = finding.line_start || finding.line_number || 0;
      const pid = finding.project || projectId;
      activeFinding = { id, kind, project: pid, file_path: filePath, line, status: finding.status };
      document.getElementById('detail-title').textContent = title;
      document.getElementById('detail-body').innerHTML = kind === 'secret' ? `
        <div class="flex gap-8 mb-16">${Utils.severityBadge(finding.severity)}${Utils.statusBadge(finding.status)}</div>
        <table style="width:100%; font-size:13.5px;">
          <tr><td class="text-dim" style="width:140px; padding:4px 0;">Project</td><td>${Utils.escapeHtml(finding.project_name || '')}</td></tr>
          <tr><td class="text-dim" style="padding:4px 0;">Type</td><td>${Utils.escapeHtml(finding.secret_type)}</td></tr>
          <tr><td class="text-dim" style="padding:4px 0;">File</td><td class="mono">${Utils.escapeHtml(filePath)}</td></tr>
          <tr><td class="text-dim" style="padding:4px 0;">Line</td><td>${line || '-'}</td></tr>
          <tr><td class="text-dim" style="padding:4px 0;">Masked</td><td class="mono">${Utils.escapeHtml(finding.masked_value || '')}</td></tr>
        </table>
      ` : `
        <div class="flex gap-8 mb-16">${Utils.severityBadge(finding.severity)}<span class="badge badge-neutral">${finding.confidence} confidence</span>${Utils.statusBadge(finding.status)}</div>
        <table style="width:100%; font-size:13.5px;">
          <tr><td class="text-dim" style="width:140px; padding:4px 0;">Project</td><td>${Utils.escapeHtml(finding.project_name || '')}</td></tr>
          <tr><td class="text-dim" style="padding:4px 0;">Scanner</td><td class="mono">${finding.scanner}</td></tr>
          <tr><td class="text-dim" style="padding:4px 0;">Rule ID</td><td class="mono">${Utils.escapeHtml(finding.rule_id)}</td></tr>
          <tr><td class="text-dim" style="padding:4px 0;">Category</td><td>${finding.category.replace(/_/g,' ')}</td></tr>
          <tr><td class="text-dim" style="padding:4px 0;">CWE</td><td>${finding.cwe || '-'}</td></tr>
          <tr><td class="text-dim" style="padding:4px 0;">OWASP</td><td>${finding.owasp_category || '-'}</td></tr>
          <tr><td class="text-dim" style="padding:4px 0;">File</td><td class="mono">${Utils.escapeHtml(finding.file_path)}</td></tr>
          <tr><td class="text-dim" style="padding:4px 0;">Line</td><td>${finding.line_start || '-'}${finding.line_end && finding.line_end !== finding.line_start ? '–' + finding.line_end : ''}</td></tr>
          <tr><td class="text-dim" style="padding:4px 0;">First Detected</td><td>${Utils.formatDate(finding.first_detected_at)}</td></tr>
          <tr><td class="text-dim" style="padding:4px 0;">Last Detected</td><td>${Utils.formatDate(finding.last_detected_at)}</td></tr>
        </table>
        ${finding.code_snippet ? `<div class="mt-16"><label>Code Snippet</label><pre class="mono" style="background:var(--bg-input); padding:12px; border-radius:8px; overflow-x:auto; font-size:12.5px;">${Utils.escapeHtml(finding.code_snippet)}</pre></div>` : ''}
        <div class="mt-16"><label>Description</label><p style="font-size:13.5px;">${Utils.escapeHtml(finding.description || 'No description provided.')}</p></div>
        <div class="mt-16"><label>Why it matters</label><p style="font-size:13.5px;">This finding was flagged as <strong>${finding.severity}</strong> severity by ${finding.scanner}. Review the affected code path for exploitability in your application's context.</p></div>
        <div class="mt-16"><label>Remediation</label><p style="font-size:13.5px;">${Utils.escapeHtml(finding.remediation || 'Review the flagged code and apply standard secure-coding practices for this issue type.')}</p></div>
        ${finding.references && finding.references.length ? `<div class="mt-16"><label>References</label><ul style="font-size:13px;">${finding.references.map(r => `<li><a href="${Utils.escapeHtml(r)}" target="_blank" rel="noopener">${Utils.escapeHtml(r)}</a></li>`).join('')}</ul></div>` : ''}
      `;
      document.getElementById('detail-status-select').value = finding.status;
      document.getElementById('detail-save-status').onclick = async () => {
        try {
          const endpoint = kind === 'secret' ? `/api/secret-findings/${id}/status/` : `/api/findings/${id}/status/`;
          await Api.patch(endpoint, { status: document.getElementById('detail-status-select').value });
          Toast.success('Status updated.');
          document.getElementById('detail-modal').classList.remove('open');
          load();
        } catch (e) { Toast.error(e.message || 'Failed to update status.'); }
      };
      document.getElementById('detail-modal').classList.add('open');
    } catch (e) {
      Toast.error('Failed to load finding.');
    }
  };
  document.getElementById('close-detail').addEventListener('click', () => document.getElementById('detail-modal').classList.remove('open'));

  async function statusEndpoint(finding) {
    return finding.kind === 'secret'
      ? `/api/secret-findings/${finding.id}/status/`
      : `/api/findings/${finding.id}/status/`;
  }

  document.getElementById('detail-open-editor').addEventListener('click', () => {
    if (!activeFinding || !activeFinding.file_path) { Toast.error('No file on this finding.'); return; }
    const qs = new URLSearchParams({
      project: String(activeFinding.project),
      path: activeFinding.file_path,
    });
    if (activeFinding.line) qs.set('line', String(activeFinding.line));
    location.href = `editor.html?${qs.toString()}`;
  });

  document.getElementById('detail-mark-fixed').addEventListener('click', async () => {
    if (!activeFinding) return;
    try {
      await Api.patch(await statusEndpoint(activeFinding), { status: 'resolved' });
      Toast.success('Marked fixed.');
      document.getElementById('detail-modal').classList.remove('open');
      load();
    } catch (e) {
      Toast.error(e.message || 'Could not mark fixed.');
    }
  });

  async function startScopedScan(scopePath) {
    const pid = activeFinding && activeFinding.project;
    if (!pid) { Toast.error('No project on this finding.'); return; }
    try {
      const data = await Api.post(`/api/projects/${pid}/scan/`, {
        scan_type: 'full',
        enable_sast: true,
        enable_sca: true,
        enable_secrets: true,
        enable_iac: true,
        enable_container: true,
        generate_report: true,
        scope_path: scopePath,
      });
      location.href = `scanner.html?project=${pid}&scan=${data.scan.id}`;
    } catch (e) {
      Toast.error(e.message || 'Could not start rescan.');
    }
  }

  document.getElementById('detail-rescan-file').addEventListener('click', () => {
    if (!activeFinding || !activeFinding.file_path) { Toast.error('No file on this finding.'); return; }
    startScopedScan(activeFinding.file_path);
  });

  document.getElementById('detail-rescan-folder').addEventListener('click', () => {
    if (!activeFinding || !activeFinding.file_path) { Toast.error('No file on this finding.'); return; }
    const parts = activeFinding.file_path.replace(/\\/g, '/').split('/');
    const folder = parts.length > 1 ? parts.slice(0, -1).join('/') : activeFinding.file_path;
    startScopedScan(folder);
  });

  async function loadCompare(id) {
    const card = document.getElementById('compare-card');
    try {
      const data = await Api.get(`/api/scans/${id}/vs-previous/`);
      if (!data.previous) {
        card.style.display = 'block';
        document.getElementById('compare-summary').textContent = 'This is the first completed scan for this project.';
        document.getElementById('compare-stats').innerHTML = '';
        document.getElementById('compare-body').innerHTML = '<tr><td colspan="4" class="text-dim">Nothing to compare yet.</td></tr>';
        return;
      }
      compareDiff = {
        new: data.new_findings || [],
        still_open: data.still_open_findings || [],
        resolved: data.resolved_findings || [],
      };
      card.style.display = 'block';
      const scopeNote = data.scope_path ? ` File/folder scope: ${data.scope_path}.` : '';
      document.getElementById('compare-summary').textContent =
        `Compared with scan #${data.previous.id}.${scopeNote} Score change: ${data.security_score_delta ?? 0}.`;
      document.getElementById('compare-stats').innerHTML = `
        <div class="stat-card high"><div class="stat-label">New</div><div class="stat-value">${data.new_count || 0}</div></div>
        <div class="stat-card"><div class="stat-label">Still open</div><div class="stat-value">${data.still_open_count || 0}</div></div>
        <div class="stat-card low"><div class="stat-label">Resolved</div><div class="stat-value">${data.resolved_count || 0}</div></div>
      `;
      renderCompare();
    } catch (e) {
      card.style.display = 'none';
    }
  }

  function renderCompare() {
    const rows = compareDiff[compareTab] || [];
    const body = document.getElementById('compare-body');
    if (!rows.length) {
      body.innerHTML = '<tr><td colspan="4" class="text-dim">None in this group.</td></tr>';
      return;
    }
    body.innerHTML = rows.map((f) => `
      <tr style="cursor:pointer;" onclick="openFindingDetail(${f.id}, '${f.kind === 'secret' ? 'secret' : 'finding'}')">
        <td>${Utils.severityBadge(f.severity)}</td>
        <td>${Utils.escapeHtml(f.title || f.secret_type || '')}</td>
        <td class="mono text-dim">${Utils.escapeHtml(f.file_path || '')}</td>
        <td>${f.line_start || f.line_number || '-'}</td>
      </tr>
    `).join('');
  }

  Utils.qsa('#compare-card .pill').forEach((pill) => {
    pill.addEventListener('click', () => {
      Utils.qsa('#compare-card .pill').forEach((p) => p.classList.remove('active'));
      pill.classList.add('active');
      compareTab = pill.dataset.diff;
      renderCompare();
    });
  });

  await loadProjects();
  await loadScopeLabel();
  load();
})();
