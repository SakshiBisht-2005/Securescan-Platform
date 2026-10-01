/** project-detail.js - single project overview/upload/import/history/settings. */
(async function () {
  const user = await Auth.initAuthenticatedPage('projects.html');
  if (!user) return;

  const projectId = Utils.getQueryParam('id');
  if (!projectId) { location.href = 'projects.html'; return; }

  let project = null;

  function apiBaseUrl() {
    return window.SECURESCAN_API_BASE || location.origin;
  }

  function ciSnippet(apiBase, id) {
    return [
      'Copy examples/github-actions/securescan.yml',
      'to .github/workflows/securescan.yml in the source repo.',
      '',
      'GitHub repository secrets:',
      '  SECURESCAN_URL=' + apiBase,
      '  SECURESCAN_TOKEN=<generate below>',
      '  SECURESCAN_PROJECT_ID=' + id,
      '',
      'Optional: SECURESCAN_FAIL_ON=high  (critical|high|medium|low|never)',
    ].join('\n');
  }

  async function loadProject() {
    try {
      project = await Api.get(`/api/projects/${projectId}/`);
      document.getElementById('project-title').textContent = project.name;
      document.getElementById('project-name-crumb').textContent = project.name;
      document.getElementById('open-editor-btn').href = `editor.html?project=${projectId}`;
      document.getElementById('run-scan-btn').href = `scanner.html?project=${projectId}`;
      document.getElementById('s-name').value = project.name;
      document.getElementById('s-description').value = project.description || '';
      document.getElementById('s-exclusions').value = (project.exclusion_patterns || []).join('\n');
      document.getElementById('s-weekly-scan').checked = !!project.weekly_scan_enabled;
      document.getElementById('team-role-label').textContent = project.my_role
        ? `Your role on this project: ${project.my_role}`
        : '';
      const canManage = ['owner', 'admin'].includes(project.my_role);
      document.getElementById('team-invite-form').style.display = canManage ? 'block' : 'none';
      document.getElementById('delete-project-btn').style.display = project.my_role === 'owner' ? 'inline-flex' : 'none';
      loadTeam();
      const tokenStatus = document.getElementById('ci-token-status');
      tokenStatus.textContent = project.has_ci_token
        ? `CI token on file (starts with ${project.ci_token_prefix || 'ssci_'}).`
        : 'No CI token yet.';
      const apiBase = apiBaseUrl();
      document.getElementById('ci-webhook-url').textContent =
        `GitHub webhook URL: ${apiBase}/api/webhooks/github/${projectId}/  (application/json, secret = CI token)`;
      document.getElementById('ci-workflow').value = ciSnippet(apiBase, projectId);
    } catch (e) {
      Toast.error('Project not found.');
      setTimeout(() => location.href = 'projects.html', 1200);
    }
  }

  async function loadStats() {
    try {
      const stats = await Api.get(`/api/projects/${projectId}/statistics/`);
      document.getElementById('project-stats').innerHTML = `
        <div class="stat-card"><div class="stat-label">🎯 Security Score</div><div class="stat-value" style="color:${Utils.scoreColor(stats.latest_security_score)}">${stats.latest_security_score ?? '-'}</div></div>
        <div class="stat-card critical"><div class="stat-label">Critical</div><div class="stat-value">${stats.critical_count}</div></div>
        <div class="stat-card high"><div class="stat-label">High</div><div class="stat-value">${stats.high_count}</div></div>
        <div class="stat-card"><div class="stat-label">🔑 Secrets</div><div class="stat-value">${stats.secrets_detected}</div></div>
        <div class="stat-card"><div class="stat-label">📦 Vulnerable Deps</div><div class="stat-value">${stats.vulnerable_dependencies}</div></div>
      `;
      const catBox = document.getElementById('category-breakdown');
      if (!stats.findings_by_category.length) {
        catBox.innerHTML = '<p class="text-dim">No open findings yet. Run a scan to get started.</p>';
      } else {
        catBox.innerHTML = stats.findings_by_category.map((c) => `
          <div class="flex justify-between items-center" style="padding:8px 0; border-bottom:1px solid var(--border);">
            <span>${Utils.escapeHtml(c.category.replace(/_/g, ' '))}</span><span class="badge badge-neutral">${c.count}</span>
          </div>`).join('');
      }
    } catch (e) { /* non-fatal */ }
  }

  async function loadScans() {
    try {
      const data = await Api.get(`/api/scans/?project=${projectId}&page_size=50`);
      const body = document.getElementById('scans-body');
      if (!data.results.length) {
        body.innerHTML = `<tr><td colspan="9" class="text-dim">No scans yet.</td></tr>`;
        return;
      }
      body.innerHTML = data.results.map((s) => `
        <tr>
          <td class="mono">#${s.id}</td>
          <td>${s.scan_type}</td>
          <td class="text-dim">${s.trigger_source || 'ui'}</td>
          <td><span class="badge badge-${{completed:'low',running:'medium',queued:'info',preparing:'medium',failed:'critical',cancelled:'neutral'}[s.status]||'neutral'}">${s.status}</span></td>
          <td style="color:${Utils.scoreColor(s.security_score)}">${s.security_score ?? '-'}</td>
          <td>${s.total_findings}</td>
          <td>${s.duration_seconds ? s.duration_seconds.toFixed(1) + 's' : '-'}</td>
          <td class="text-dim">${Utils.timeAgo(s.created_at)}</td>
          <td><a href="vulnerabilities.html?scan=${s.id}&project=${projectId}" class="btn btn-sm">View</a></td>
        </tr>
      `).join('');
    } catch (e) { /* non-fatal */ }
  }

  Utils.qsa('.pill').forEach((pill) => {
    pill.addEventListener('click', () => {
      Utils.qsa('.pill').forEach((p) => p.classList.remove('active'));
      pill.classList.add('active');
      Utils.qsa('.tab-panel').forEach((t) => t.style.display = 'none');
      document.getElementById(`tab-${pill.dataset.tab}`).style.display = 'block';
    });
  });

  document.getElementById('upload-btn').addEventListener('click', async () => {
    const fileInput = document.getElementById('zip-file');
    if (!fileInput.files.length) { Toast.error('Choose a .zip file first.'); return; }
    const formData = new FormData();
    formData.append('file', fileInput.files[0]);
    const btn = document.getElementById('upload-btn');
    btn.disabled = true; btn.textContent = 'Uploading...';
    try {
      const data = await Api.postForm(`/api/projects/${projectId}/upload/`, formData);
      Toast.success(`Indexed ${data.files_indexed} files.`);
    } catch (e) {
      Toast.error(e.message || 'Upload failed.');
    } finally {
      btn.disabled = false; btn.textContent = 'Upload & Index';
    }
  });

  document.getElementById('import-btn').addEventListener('click', async () => {
    const url = document.getElementById('repo-url').value.trim();
    const branch = document.getElementById('repo-branch').value.trim() || 'main';
    if (!url) { Toast.error('Repository URL is required.'); return; }
    const btn = document.getElementById('import-btn');
    btn.disabled = true; btn.textContent = 'Cloning...';
    try {
      const data = await Api.post(`/api/projects/${projectId}/repository/`, { repository_url: url, branch });
      Toast.success(`Cloned and indexed ${data.files_indexed} files.`);
    } catch (e) {
      Toast.error(e.message || 'Import failed.');
    } finally {
      btn.disabled = false; btn.textContent = 'Clone & Index';
    }
  });

  document.getElementById('save-settings-btn').addEventListener('click', async () => {
    try {
      await Api.put(`/api/projects/${projectId}/`, {
        name: document.getElementById('s-name').value.trim(),
        description: document.getElementById('s-description').value,
        exclusion_patterns: document.getElementById('s-exclusions').value.split('\n').map(s => s.trim()).filter(Boolean),
        weekly_scan_enabled: document.getElementById('s-weekly-scan').checked,
      });
      Toast.success('Settings saved.');
      loadProject();
    } catch (e) {
      Toast.error(e.message || 'Failed to save settings.');
    }
  });

  document.getElementById('ci-token-btn').addEventListener('click', async () => {
    if (project?.has_ci_token && !confirm('This replaces the existing CI token. GitHub secrets and webhooks must be updated.')) {
      return;
    }
    const btn = document.getElementById('ci-token-btn');
    btn.disabled = true;
    try {
      const data = await Api.post(`/api/projects/${projectId}/ci-token/`, {});
      const box = document.getElementById('ci-token-once');
      box.classList.add('show');
      box.innerHTML = '<p class="text-dim" style="margin-bottom:8px;">Copy this token now. It will not be shown again.</p>'
        + '<code class="mono">' + Utils.escapeHtml(data.token) + '</code>';
      Toast.success('CI token generated.');
      loadProject();
    } catch (e) {
      Toast.error(e.message || 'Could not generate CI token.');
    } finally {
      btn.disabled = false;
    }
  });

  document.getElementById('delete-project-btn').addEventListener('click', async () => {
    if (!confirm('Delete this project and all its scan data? This cannot be undone.')) return;
    try {
      await Api.del(`/api/projects/${projectId}/`);
      Toast.success('Project deleted.');
      setTimeout(() => location.href = 'projects.html', 800);
    } catch (e) {
      Toast.error(e.message || 'Failed to delete project.');
    }
  });

  loadProject();
  loadStats();
  loadScans();

  async function loadTeam() {
    const body = document.getElementById('team-body');
    if (!body) return;
    try {
      const data = await Api.get(`/api/projects/${projectId}/members/`);
      const members = data.members || [];
      const invites = data.invites || [];
      const canManage = ['owner', 'admin'].includes(data.my_role || project?.my_role);
      const rows = members.map((m) => {
        const locked = m.role === 'owner';
        const actions = locked
          ? ''
          : (canManage
            ? `<select data-member="${m.id}" class="member-role" style="max-width:140px;">
                <option value="developer"${m.role === 'developer' ? ' selected' : ''}>Developer</option>
                <option value="analyst"${m.role === 'analyst' ? ' selected' : ''}>Analyst</option>
                <option value="admin"${m.role === 'admin' ? ' selected' : ''}>Project admin</option>
              </select>
              <button class="btn btn-sm" data-remove="${m.id}">Remove</button>`
            : Utils.escapeHtml(m.role));
        return `<tr>
          <td>${Utils.escapeHtml(m.username)} <span class="text-dim">${Utils.escapeHtml(m.email || '')}</span></td>
          <td>${locked ? 'owner' : actions}</td>
          <td></td>
        </tr>`;
      });
      invites.forEach((inv) => {
        const link = inv.accept_link
          ? `<button class="btn btn-sm" data-copy="${Utils.escapeHtml(inv.accept_link)}">Copy link</button>`
          : '';
        rows.push(`<tr>
          <td class="text-dim">${Utils.escapeHtml(inv.email)} (pending)</td>
          <td>${Utils.escapeHtml(inv.role)}</td>
          <td>${canManage ? `${link} <button class="btn btn-sm" data-cancel-invite="${inv.id}">Cancel</button>` : ''}</td>
        </tr>`);
      });
      body.innerHTML = rows.join('') || `<tr><td colspan="3" class="text-dim">No members yet.</td></tr>`;
      Utils.qsa('.member-role', body).forEach((sel) => {
        sel.addEventListener('change', async () => {
          try {
            await Api.patch(`/api/projects/${projectId}/members/${sel.dataset.member}/`, { role: sel.value });
            Toast.success('Role updated.');
          } catch (e) {
            Toast.error(e.message || 'Could not change role.');
            loadTeam();
          }
        });
      });
      Utils.qsa('[data-remove]', body).forEach((btn) => {
        btn.addEventListener('click', async () => {
          if (!confirm('Remove this teammate from the project?')) return;
          try {
            await Api.del(`/api/projects/${projectId}/members/${btn.dataset.remove}/`);
            Toast.success('Removed.');
            loadTeam();
          } catch (e) {
            Toast.error(e.message || 'Could not remove member.');
          }
        });
      });
      Utils.qsa('[data-copy]', body).forEach((btn) => {
        btn.addEventListener('click', async () => {
          try {
            await navigator.clipboard.writeText(btn.dataset.copy);
            Toast.success('Invite link copied.');
          } catch (e) {
            Toast.error('Copy failed.');
          }
        });
      });
      Utils.qsa('[data-cancel-invite]', body).forEach((btn) => {
        btn.addEventListener('click', async () => {
          try {
            await Api.del(`/api/projects/${projectId}/invites/${btn.dataset.cancelInvite}/`);
            Toast.success('Invite cancelled.');
            loadTeam();
          } catch (e) {
            Toast.error(e.message || 'Could not cancel invite.');
          }
        });
      });
    } catch (e) {
      body.innerHTML = `<tr><td colspan="3" class="text-dim">Could not load team.</td></tr>`;
    }
  }

  const inviteBtn = document.getElementById('invite-btn');
  if (inviteBtn) {
    inviteBtn.addEventListener('click', async () => {
      const email = document.getElementById('invite-email').value.trim();
      const role = document.getElementById('invite-role').value;
      if (!email) { Toast.error('Email is required.'); return; }
      try {
        const data = await Api.post(`/api/projects/${projectId}/members/`, { email, role });
        if (data.member) Toast.success('Teammate added. They will see this project when they log in.');
        else if (data.email_sent) Toast.success('Invite email sent.');
        else Toast.success('Invite created. Copy the link below and send it to them.');
        const debug = document.getElementById('invite-debug');
        if (data.accept_link) {
          debug.style.display = 'block';
          debug.innerHTML = 'Share this link: <code class="mono">' + Utils.escapeHtml(data.accept_link) + '</code>';
        } else if (data.member) {
          debug.style.display = 'block';
          debug.textContent = 'They already have an account and can open this project now.';
        }
        document.getElementById('invite-email').value = '';
        loadTeam();
      } catch (e) {
        Toast.error(e.message || 'Invite failed.');
      }
    });
  }
})();
