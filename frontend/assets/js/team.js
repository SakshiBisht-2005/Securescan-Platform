/** team.js — invite teammates onto projects you administer. */
(async function () {
  const user = await Auth.initAuthenticatedPage('team.html');
  if (!user) return;

  async function loadPending() {
    const box = document.getElementById('pending-invites');
    try {
      const data = await Api.get('/api/auth/invites/');
      const invites = data.invites || [];
      if (!invites.length) { box.innerHTML = ''; return; }
      box.innerHTML = '<h3>Invites for you</h3>' + invites.map((inv) => `
        <div class="card mb-16 flex justify-between items-center">
          <div><strong>${Utils.escapeHtml(inv.project_name)}</strong>
            <span class="text-dim"> as ${Utils.escapeHtml(inv.role)}</span></div>
          <button class="btn btn-sm btn-primary" data-token="${Utils.escapeHtml(inv.token)}">Accept</button>
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
    } catch (e) { box.innerHTML = ''; }
  }

  function canInvite(role) {
    return role === 'owner' || role === 'admin';
  }

  async function inviteTo(projectId, email, role, resultEl) {
    const data = await Api.post(`/api/projects/${projectId}/members/`, { email, role });
    if (data.member) {
      Toast.success('Teammate added. They will see this project on their next login.');
      resultEl.innerHTML = `<p class="text-dim">${Utils.escapeHtml(data.member.email)} is now a ${Utils.escapeHtml(data.member.role)}.</p>`;
      return;
    }
    Toast.success(data.email_sent ? 'Invite email sent.' : 'Invite created. Copy the link and send it to them.');
    if (data.accept_link) {
      resultEl.innerHTML = `<p class="text-dim mb-8">Share this link with ${Utils.escapeHtml(email)}:</p>
        <input readonly value="${Utils.escapeHtml(data.accept_link)}" class="mono">
        <button class="btn btn-sm mt-8" type="button" data-copy="${Utils.escapeHtml(data.accept_link)}">Copy link</button>`;
      resultEl.querySelector('[data-copy]')?.addEventListener('click', async () => {
        try {
          await navigator.clipboard.writeText(data.accept_link);
          Toast.success('Link copied.');
        } catch (e) {
          Toast.error('Copy failed. Select the link and copy it manually.');
        }
      });
    } else {
      resultEl.innerHTML = '<p class="text-dim">Ask them to sign up with that email, then accept from Projects.</p>';
    }
  }

  async function loadProjects() {
    const root = document.getElementById('team-projects');
    try {
      const data = await Api.get('/api/projects/?page_size=100');
      const projects = data.results || [];
      if (!projects.length) {
        root.innerHTML = `<div class="empty-state card"><h3>Create a project first</h3>
          <p>You need a project before you can invite a teammate.</p>
          <a class="btn btn-primary" href="projects.html">Go to Projects</a></div>`;
        return;
      }
      root.innerHTML = projects.map((p) => `
        <div class="card mb-16" data-project="${p.id}">
          <div class="flex justify-between items-center mb-16">
            <div>
              <h3 style="margin:0;">${Utils.escapeHtml(p.name)}</h3>
              <p class="text-dim" style="margin:4px 0 0;">Your role: ${Utils.escapeHtml(p.my_role || 'member')}</p>
            </div>
            <a class="btn btn-sm" href="project.html?id=${p.id}">Open project</a>
          </div>
          ${canInvite(p.my_role) ? `
            <div class="flex gap-8 items-center">
              <input type="email" data-email placeholder="friend@example.com" style="flex:1;">
              <select data-role style="max-width:180px;">
                <option value="developer">Developer</option>
                <option value="analyst">Analyst</option>
                <option value="admin">Project admin</option>
              </select>
              <button class="btn btn-primary" type="button" data-invite>Invite</button>
            </div>
            <div class="invite-result mt-16"></div>
          ` : `<p class="text-dim">Only the owner or a project admin can invite people to this project.</p>`}
        </div>
      `).join('');
      Utils.qsa('[data-invite]', root).forEach((btn) => {
        btn.addEventListener('click', async () => {
          const card = btn.closest('[data-project]');
          const email = card.querySelector('[data-email]').value.trim();
          const role = card.querySelector('[data-role]').value;
          if (!email) { Toast.error('Enter your teammate’s email.'); return; }
          btn.disabled = true;
          try {
            await inviteTo(card.dataset.project, email, role, card.querySelector('.invite-result'));
          } catch (e) {
            Toast.error(e.message || 'Invite failed.');
          } finally {
            btn.disabled = false;
          }
        });
      });
    } catch (e) {
      root.innerHTML = '<p class="text-dim">Could not load projects.</p>';
    }
  }

  await loadPending();
  await loadProjects();
})();
