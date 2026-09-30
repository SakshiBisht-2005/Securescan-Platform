/** projects.js - project list, create, search. */
(async function () {
  const user = await Auth.initAuthenticatedPage('projects.html');
  if (!user) return;

  let allProjects = [];

  async function load() {
    try {
      const data = await Api.get('/api/projects/?page_size=100');
      allProjects = data.results;
      render(allProjects);
    } catch (e) {
      Toast.error('Failed to load projects.');
    }
  }

  function render(projects) {
    const grid = document.getElementById('projects-grid');
    if (!projects.length) {
      grid.innerHTML = `<div class="empty-state" style="grid-column:1/-1;"><div class="empty-icon">📁</div><h3>No projects yet</h3><p>Create your first project to start scanning.</p></div>`;
      return;
    }
    grid.innerHTML = projects.map((p) => `
      <div class="card" style="cursor:pointer;" onclick="location.href='project.html?id=${p.id}'">
        <div class="flex justify-between items-center mb-16">
          <h3 style="margin:0;">${Utils.escapeHtml(p.name)}</h3>
          <span class="badge badge-${statusClass(p.latest_scan_status)}">${p.latest_scan_status || 'no scans'}</span>
        </div>
        <p class="text-dim" style="min-height:36px; font-size:13.5px;">${Utils.escapeHtml(p.description || 'No description.')}</p>
        <div class="flex justify-between items-center mt-16 text-faint" style="font-size:12.5px;">
          <span>${Utils.escapeHtml(p.language || 'Unknown language')}</span>
          <span>${p.my_role ? Utils.escapeHtml(p.my_role) + ' · ' : ''}Updated ${Utils.timeAgo(p.updated_at)}</span>
        </div>
      </div>
    `).join('');
  }

  function statusClass(status) {
    return { completed: 'low', running: 'medium', queued: 'info', preparing: 'medium', failed: 'critical' }[status] || 'neutral';
  }

  document.getElementById('search-input').addEventListener('input', Utils.debounce((e) => {
    const q = e.target.value.toLowerCase();
    render(allProjects.filter((p) => p.name.toLowerCase().includes(q) || (p.description || '').toLowerCase().includes(q)));
  }, 250));

  const modal = document.getElementById('new-project-modal');
  document.getElementById('new-project-btn').addEventListener('click', () => modal.classList.add('open'));
  document.getElementById('close-modal').addEventListener('click', () => modal.classList.remove('open'));
  document.getElementById('cancel-modal').addEventListener('click', () => modal.classList.remove('open'));

  document.getElementById('submit-new-project').addEventListener('click', async () => {
    const name = document.getElementById('p-name').value.trim();
    if (!name) { Toast.error('Project name is required.'); return; }
    try {
      const data = await Api.post('/api/projects/', {
        name,
        description: document.getElementById('p-description').value,
        language: document.getElementById('p-language').value,
        default_branch: document.getElementById('p-branch').value || 'main',
      });
      Toast.success('Project created.');
      modal.classList.remove('open');
      location.href = `project.html?id=${data.id}`;
    } catch (e) {
      Toast.error(e.message || 'Failed to create project.');
    }
  });

  load();
  loadPendingInvites();

  async function loadPendingInvites() {
    const box = document.getElementById('pending-invites');
    if (!box) return;
    try {
      const data = await Api.get('/api/auth/invites/');
      const invites = data.invites || [];
      if (!invites.length) { box.style.display = 'none'; return; }
      box.style.display = 'block';
      box.innerHTML = invites.map((inv) => `
        <div class="card flex justify-between items-center mb-8">
          <div>
            <strong>${Utils.escapeHtml(inv.project_name)}</strong>
            <span class="text-dim"> as ${Utils.escapeHtml(inv.role)}</span>
          </div>
          <button class="btn btn-sm btn-primary" data-token="${Utils.escapeHtml(inv.token)}">Accept invite</button>
        </div>
      `).join('');
      Utils.qsa('[data-token]', box).forEach((btn) => {
        btn.addEventListener('click', async () => {
          try {
            const joined = await Api.post('/api/auth/invites/accept/', { token: btn.dataset.token });
            Toast.success('Joined project.');
            location.href = `project.html?id=${joined.project_id}`;
          } catch (e) {
            Toast.error(e.message || 'Could not accept invite.');
          }
        });
      });
    } catch (e) { /* ignore */ }
  }
})();
