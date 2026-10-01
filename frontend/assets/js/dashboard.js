/** dashboard.js - overview stats + hand-rolled canvas trend sparkline
 * (kept dependency-free per the "vanilla JS only" frontend requirement). */
(async function () {
  const user = await Auth.initAuthenticatedPage('dashboard.html');
  if (!user) return;

  const go = document.getElementById('dash-go');
  if (go) {
    go.addEventListener('change', () => {
      if (go.value) location.href = go.value;
    });
  }

  try {
    const summary = await Api.get('/api/dashboard/summary/');
    renderSummary(summary);
    renderLatestScans(summary.latest_scans);
  } catch (e) {
    Toast.error('Failed to load dashboard summary.');
    const box = document.getElementById('summary-stats');
    if (box) box.innerHTML = `<div class="card" style="grid-column:1/-1;"><p class="terminal-log">${Utils.escapeHtml(e.message || 'Could not load metrics.')}</p></div>`;
  }

  try {
    const trend = await Api.get('/api/dashboard/trend/');
    renderTrend(trend.trend);
  } catch (e) { /* non-fatal */ }

  function renderSummary(s) {
    document.getElementById('summary-stats').innerHTML = `
      <div class="stat-card"><div class="stat-label">Projects</div><div class="stat-value">${s.total_projects}</div></div>
      <div class="stat-card"><div class="stat-label">Scans</div><div class="stat-value">${s.total_scans}</div></div>
      <div class="stat-card"><div class="stat-label">Open findings</div><div class="stat-value">${s.open_vulnerabilities}</div></div>
      <div class="stat-card"><div class="stat-label">Avg. score</div><div class="stat-value" style="color:${Utils.scoreColor(s.average_security_score)}">${s.average_security_score ?? '-'}</div></div>
    `;
    document.getElementById('stat-critical').textContent = s.critical_count;
    document.getElementById('stat-high').textContent = s.high_count;
    document.getElementById('stat-medium').textContent = s.medium_count;
    document.getElementById('stat-low').textContent = s.low_count;
  }

  function renderLatestScans(scans) {
    const body = document.getElementById('latest-scans-body');
    if (!scans.length) {
      body.innerHTML = `<tr><td colspan="5" class="text-dim">No scans yet. <a href="projects.html">Create a project</a> to get started.</td></tr>`;
      return;
    }
    body.innerHTML = scans.map((s) => `
      <tr style="cursor:pointer;" onclick="location.href='vulnerabilities.html?scan=${s.id}&project=${s.project_id}'">
        <td>${Utils.escapeHtml(s.project_name)}</td>
        <td><span class="badge badge-${scanStatusClass(s.status)}">${s.status}</span></td>
        <td style="color:${Utils.scoreColor(s.security_score)}; font-weight:700;">${s.security_score ?? '-'}</td>
        <td>${s.total_findings}</td>
        <td class="text-dim">${Utils.timeAgo(s.created_at)}</td>
      </tr>
    `).join('');
  }

  function scanStatusClass(status) {
    return { completed: 'low', running: 'medium', queued: 'info', preparing: 'medium', failed: 'critical', cancelled: 'neutral' }[status] || 'neutral';
  }

  function renderTrend(points) {
    const canvas = document.getElementById('trend-chart');
    if (!points || points.length < 2) {
      document.getElementById('trend-empty').style.display = 'block';
      return;
    }
    const ctx = canvas.getContext('2d');
    const dpr = window.devicePixelRatio || 1;
    const width = canvas.clientWidth || 600;
    const height = 90;
    canvas.width = width * dpr; canvas.height = height * dpr;
    ctx.scale(dpr, dpr);

    const values = points.map((p) => p.security_score ?? 0);
    const max = 100, min = 0;
    const stepX = width / (values.length - 1);

    ctx.clearRect(0, 0, width, height);
    ctx.strokeStyle = 'rgba(57,255,136,.12)';
    ctx.lineWidth = 1;
    for (let g = 0; g <= 4; g++) {
      const gy = (height / 4) * g;
      ctx.beginPath(); ctx.moveTo(0, gy); ctx.lineTo(width, gy); ctx.stroke();
    }
    ctx.strokeStyle = '#39ff88';
    ctx.lineWidth = 2;
    ctx.shadowColor = 'rgba(57,255,136,.45)';
    ctx.shadowBlur = 8;
    ctx.beginPath();
    values.forEach((v, i) => {
      const x = i * stepX;
      const y = height - ((v - min) / (max - min)) * (height - 10) - 5;
      i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    });
    ctx.stroke();
    ctx.shadowBlur = 0;

    const gradient = ctx.createLinearGradient(0, 0, 0, height);
    gradient.addColorStop(0, 'rgba(57,255,136,.28)');
    gradient.addColorStop(1, 'rgba(57,255,136,0)');
    ctx.lineTo(width, height); ctx.lineTo(0, height); ctx.closePath();
    ctx.fillStyle = gradient; ctx.fill();
  }
})();
