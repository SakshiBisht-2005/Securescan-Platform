/** admin.js - custom admin dashboard: users, scanner status, failed scans, audit log. */
(async function () {
  const user = await Auth.requireAdmin();
  if (!user) return;
  Auth.renderTopbar('admin.html');

  async function loadHealth() {
    try {
      const health = await Api.get('/api/dashboard/admin/system-health/');
      document.getElementById('admin-stats').innerHTML = `
        <div class="stat-card"><div class="stat-label">👥 Total Users</div><div class="stat-value">${health.users.total}</div></div>
        <div class="stat-card"><div class="stat-label">✅ Active Users</div><div class="stat-value">${health.users.active}</div></div>
        <div class="stat-card"><div class="stat-label">📁 Total Projects</div><div class="stat-value">${health.projects.total}</div></div>
        <div class="stat-card"><div class="stat-label">🔍 Total Scans</div><div class="stat-value">${health.scans.total}</div></div>
        <div class="stat-card critical"><div class="stat-label">❌ Failed Scans</div><div class="stat-value">${health.scans.failed}</div></div>
      `;
      document.getElementById('scanners-body').innerHTML = health.scanner_status.map((s) => `
        <tr><td class="mono">${s.name}</td><td>${s.category}</td>
        <td>${s.available ? '<span class="badge badge-success">Available</span>' : '<span class="badge badge-neutral">Unavailable</span>'}</td></tr>
      `).join('');
      document.getElementById('failed-scans-body').innerHTML = health.recent_failed_scans.length
        ? health.recent_failed_scans.map((s) => `<tr><td class="mono">#${s.id}</td><td>${Utils.escapeHtml(s.project)}</td><td class="text-dim">${Utils.escapeHtml(s.error)}</td><td class="text-dim">${Utils.timeAgo(s.created_at)}</td></tr>`).join('')
        : '<tr><td colspan="4" class="text-dim">No failed scans. 🎉</td></tr>';
    } catch (e) { Toast.error('Failed to load system health.'); }
  }

  async function loadUsers() {
    try {
      const data = await Api.get('/api/auth/admin/users/?page_size=100');
      document.getElementById('users-body').innerHTML = data.results.map((u) => `
        <tr>
          <td>${Utils.escapeHtml(u.username)}</td>
          <td class="text-dim">${Utils.escapeHtml(u.email)}</td>
          <td><span class="badge badge-neutral">${u.role}</span></td>
          <td>${u.is_active ? '<span class="badge badge-success">Active</span>' : '<span class="badge badge-critical">Disabled</span>'}</td>
          <td class="text-dim">${Utils.formatDate(u.date_joined)}</td>
          <td>${u.id === user.id ? '' : `<button class="btn btn-sm" data-toggle="${u.id}" data-active="${u.is_active}">${u.is_active ? 'Disable' : 'Enable'}</button>`}</td>
        </tr>
      `).join('');
      Utils.qsa('[data-toggle]').forEach((btn) => btn.addEventListener('click', async () => {
        const id = btn.dataset.toggle;
        const isActive = btn.dataset.active === 'true';
        try {
          await Api.post(`/api/auth/admin/users/${id}/${isActive ? 'disable' : 'enable'}/`, {});
          Toast.success('User updated.');
          loadUsers();
        } catch (e) { Toast.error(e.message || 'Failed to update user.'); }
      }));
    } catch (e) { Toast.error('Failed to load users.'); }
  }

  async function loadAudit() {
    try {
      const data = await Api.get('/api/audit-logs/?page_size=50');
      document.getElementById('audit-body').innerHTML = data.results.length
        ? data.results.map((a) => `<tr><td>${Utils.escapeHtml(a.username || 'system')}</td><td class="mono">${a.action}</td><td class="text-dim">${a.object_type} ${a.object_id}</td><td class="text-dim">${a.ip_address || '-'}</td><td class="text-dim">${Utils.timeAgo(a.timestamp)}</td></tr>`).join('')
        : '<tr><td colspan="5" class="text-dim">No audit events yet.</td></tr>';
    } catch (e) { Toast.error('Failed to load audit log.'); }
  }

  Utils.qsa('.pill').forEach((pill) => {
    pill.addEventListener('click', () => {
      Utils.qsa('.pill').forEach((p) => p.classList.remove('active'));
      pill.classList.add('active');
      Utils.qsa('.admin-tab').forEach((t) => t.style.display = 'none');
      document.getElementById(`tab-${pill.dataset.tab}`).style.display = 'block';
      if (pill.dataset.tab === 'audit') loadAudit();
    });
  });

  loadHealth();
  loadUsers();
})();
