/** reports.js - generate and list downloadable reports. */
(async function () {
  const user = await Auth.initAuthenticatedPage('reports.html');
  if (!user) return;

  function extractCreatedReport(data) {
    if (!data) return null;
    if (data.report && data.report.id) return data.report;
    if (data.data && data.data.report && data.data.report.id) return data.data.report;
    if (data.id && data.report_type) return data;
    return null;
  }

  function isPdfBytes(buffer) {
    if (!buffer || buffer.byteLength < 4) return false;
    const b = new Uint8Array(buffer);
    return b[0] === 0x25 && b[1] === 0x50 && b[2] === 0x44 && b[3] === 0x46; // %PDF
  }

  async function loadScanOptions() {
    try {
      const data = await Api.get('/api/scans/?status=completed&page_size=100&ordering=-created_at');
      const select = document.getElementById('report-scan-select');
      if (!data.results.length) {
        select.innerHTML = '<option value="">No completed scans yet</option>';
        return;
      }
      select.innerHTML = data.results.map((s) => `<option value="${s.id}">#${s.id} - ${Utils.escapeHtml(s.project_name)} (${Utils.timeAgo(s.created_at)})</option>`).join('');
    } catch (e) { /* ignore */ }
  }

  function renderReports(results) {
    const body = document.getElementById('reports-body');
    if (!results.length) {
      body.innerHTML = `<tr><td colspan="6" class="text-dim">No reports generated yet.</td></tr>`;
      return;
    }
    body.innerHTML = results.map((r) => `
      <tr>
        <td class="mono">#${r.id}</td>
        <td>${Utils.escapeHtml(r.project_name)}</td>
        <td>${r.report_type.toUpperCase()}</td>
        <td><span class="badge badge-${{ready:'low',generating:'medium',failed:'critical'}[r.status]}">${r.status}</span></td>
        <td class="text-dim">${Utils.timeAgo(r.created_at)}</td>
        <td>${r.status === 'ready' ? `<button type="button" class="btn btn-sm" data-report-id="${r.id}" data-report-type="${r.report_type}">Download ${r.report_type.toUpperCase()}</button>` : '-'}</td>
      </tr>`).join('');
  }

  async function loadReports() {
    const body = document.getElementById('reports-body');
    try {
      const data = await Api.get('/api/reports/?page_size=50');
      renderReports(data.results || []);
      return data.results || [];
    } catch (e) {
      body.innerHTML = `<tr><td colspan="6" class="text-dim">Failed to load reports.</td></tr>`;
      return [];
    }
  }

  async function downloadReport(id, reportType) {
    try {
      const res = await fetch(Api.downloadUrl(`/api/reports/${id}/download/`), {
        headers: { Authorization: `Bearer ${Api.getAccessToken()}` },
      });
      if (!res.ok) throw new Error('Download failed.');
      const buffer = await res.arrayBuffer();
      const pdf = isPdfBytes(buffer);
      if (reportType === 'pdf' && !pdf) {
        Toast.error('That file was JSON, not a PDF. Download the row marked PDF.');
        return;
      }
      const ext = (reportType === 'pdf' || pdf) ? 'pdf' : 'json';
      const blob = new Blob([buffer], { type: ext === 'pdf' ? 'application/pdf' : 'application/json' });
      const filename = `security_report_${id}.${ext}`;
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (e) {
      Toast.error('Failed to download report.');
    }
  }

  document.getElementById('reports-body').addEventListener('click', (e) => {
    const btn = e.target.closest('[data-report-id]');
    if (!btn) return;
    e.preventDefault();
    downloadReport(btn.getAttribute('data-report-id'), btn.getAttribute('data-report-type'));
  });

  document.getElementById('generate-report-btn').addEventListener('click', async () => {
    const scanId = document.getElementById('report-scan-select').value;
    const reportType = document.getElementById('report-type-select').value;
    if (!scanId) { Toast.error('Select a scan first.'); return; }
    const btn = document.getElementById('generate-report-btn');
    btn.disabled = true; btn.textContent = 'Generating...';
    try {
      const data = await Api.post(`/api/reports/${scanId}/generate/`, { report_type: reportType });
      const created = extractCreatedReport(data);
      const results = await loadReports();
      const reportId = (created && created.id) || (results.find((r) => r.report_type === reportType) || {}).id;
      if (!reportId) {
        Toast.error('Report was created but could not be downloaded.');
        return;
      }
      Toast.success(`${reportType.toUpperCase()} report generated.`);
      await downloadReport(reportId, reportType);
    } catch (e) {
      Toast.error(e.message || 'Failed to generate report.');
    } finally {
      btn.disabled = false; btn.textContent = 'Generate Report';
    }
  });

  loadScanOptions();
  loadReports();
})();
