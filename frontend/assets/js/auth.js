/** auth.js - login/register/password flows + route guarding + shared app shell. */
const Auth = (() => {
  let currentUser = null;

  async function requireAuth() {
    if (!Api.getAccessToken()) {
      location.href = 'login.html';
      return null;
    }
    try {
      const data = await Api.get('/api/auth/me/');
      currentUser = data.user;
      return currentUser;
    } catch (e) {
      if (e.status === 0) {
        if (typeof Toast !== 'undefined') Toast.error(e.message || 'API is unreachable.');
        return null;
      }
      Api.clearTokens();
      location.href = 'login.html';
      return null;
    }
  }

  async function requireAdmin() {
    const user = await requireAuth();
    if (user && user.role !== 'ADMIN') {
      Toast.error('Administrator access required.');
      location.href = 'dashboard.html';
      return null;
    }
    return user;
  }

  function getCurrentUser() { return currentUser; }

  function logout() {
    Api.post('/api/auth/logout/', { refresh: Api.getRefreshToken() }).catch(() => {});
    Api.clearTokens();
    location.href = 'login.html';
  }

  const MODE_KEY = 'securescan_ops_mode';
  const NETWORK_PAGES = { 'network.html': true };

  function getOpsMode(activePage) {
    if (activePage && NETWORK_PAGES[activePage]) {
      localStorage.setItem(MODE_KEY, 'network');
      return 'network';
    }
    return localStorage.getItem(MODE_KEY) === 'network' ? 'network' : 'code';
  }

  function setOpsMode(mode) {
    localStorage.setItem(MODE_KEY, mode);
    location.href = mode === 'network' ? 'network.html' : 'dashboard.html';
  }

  function closeDrops(except) {
    document.querySelectorAll('.drop.open').forEach((el) => {
      if (el !== except) el.classList.remove('open');
    });
    const nd = document.getElementById('notif-dropdown');
    if (nd && nd !== except) nd.classList.remove('open');
  }

  function renderTopbar(activePage) {
    const mount = document.getElementById('app-topbar');
    if (!mount) return;
    const mode = getOpsMode(activePage);

    const codeLinks = [
      ['dashboard.html', 'Dashboard', '▣'],
      ['projects.html', 'Projects', '▤'],
      ['assessments.html', 'Assessments', '▦'],
      ['vulnerabilities.html', 'Findings', '⚠'],
      ['team.html', 'Team', '👥'],
      ['reports.html', 'Reports', '☰'],
      ['profile.html', 'Profile', '◉'],
    ];
    const networkLinks = [
      ['network.html', 'Network lab', '◎'],
      ['assessments.html', 'Assessments', '▦'],
      ['profile.html', 'Profile', '◉'],
    ];
    const links = mode === 'network' ? networkLinks : codeLinks;
    if (currentUser && currentUser.role === 'ADMIN') links.push(['admin.html', 'Admin', '⚙']);

    const jumpOpts = links.map(([href, label]) =>
      `<option value="${href}" ${activePage === href ? 'selected' : ''}>${label}</option>`
    ).join('');
    const sideHtml = links.map(([href, label, ico]) =>
      `<a href="${href}" class="${activePage === href ? 'active' : ''}"><span class="nav-ico">${ico}</span>${label}</a>`
    ).join('');
    const isEditor = !!document.querySelector('.editor-app');
    const initial = (currentUser?.username || '?')[0].toUpperCase();

    mount.innerHTML = `
      <button class="icon-btn" id="nav-toggle" title="Menu" type="button">☰</button>
      <div class="brand"><img class="logo-3d" src="assets/img/securescan-shield-3d.png" alt="" width="26" height="26"> SecureScan</div>
      ${isEditor ? `<nav>${links.map(([href, label]) => `<a href="${href}" class="${activePage === href ? 'active' : ''}">${label}</a>`).join('')}</nav>` : `
      <div class="topbar-tools">
        <label class="sr-only" for="ops-mode-select">Workspace</label>
        <select id="ops-mode-select" class="select-compact" title="Workspace">
          <option value="code" ${mode === 'code' ? 'selected' : ''}>Code workspace</option>
          <option value="network" ${mode === 'network' ? 'selected' : ''}>Network lab</option>
        </select>
        <label class="sr-only" for="nav-jump">Jump to</label>
        <select id="nav-jump" class="select-compact" title="Jump to page">${jumpOpts}</select>
      </div>`}
      <div class="hud-lights" title="API health"><span class="status-light" id="api-live"></span> <span id="api-live-label">link</span></div>
      <div class="hud-clock" id="hud-clock"></div>
      <div class="topbar-right">
        <div class="drop" id="quick-drop">
          <button class="icon-btn" id="quick-toggle" type="button" title="New">＋</button>
          <div class="drop-panel">
            <div class="drop-label">Create</div>
            <a href="projects.html">New project</a>
            <a href="assessments.html">Run assessment</a>
            <a href="reports.html">Generate report</a>
          </div>
        </div>
        <button class="icon-btn" id="theme-toggle" title="Toggle theme" type="button">🌓</button>
        <div class="drop" id="notif-drop">
          <button class="icon-btn" id="notif-bell" title="Notifications" type="button">🔔<span class="badge-dot" id="notif-badge" style="display:none;"></span></button>
          <div id="notif-dropdown" class="drop-panel" style="width:320px; max-height:400px; overflow-y:auto; right:0;">
            <div class="drop-label">Notifications</div>
            <div id="notif-list"></div>
          </div>
        </div>
        <div class="drop" id="user-drop">
          <div class="avatar" id="user-avatar" title="${Utils.escapeHtml(currentUser?.username || '')}">${initial}</div>
          <div class="drop-panel">
            <div class="drop-label">${Utils.escapeHtml(currentUser?.username || 'Account')}</div>
            <a href="profile.html">Profile</a>
            ${currentUser?.role === 'ADMIN' ? '<a href="admin.html">Admin</a>' : ''}
            <button class="drop-item" type="button" id="logout-btn">Log out</button>
          </div>
        </div>
      </div>
    `;

    if (!document.querySelector('.scanline')) {
      const scan = document.createElement('div');
      scan.className = 'scanline';
      scan.setAttribute('aria-hidden', 'true');
      document.body.prepend(scan);
    }
    const main = document.querySelector('.main-content');
    if (main) main.classList.add('page-enter');

    if (!isEditor) {
      let sidebar = document.querySelector('.app-sidebar');
      if (!sidebar) {
        sidebar = document.createElement('aside');
        sidebar.className = 'app-sidebar';
        const shell = document.querySelector('.app-shell');
        if (shell) {
          shell.insertBefore(sidebar, shell.firstChild);
          const col = shell.querySelector(':scope > div');
          if (col) col.classList.add('app-main');
        }
      }
      sidebar.innerHTML = `
        <div class="side-brand"><img class="logo-3d" src="assets/img/securescan-shield-3d.png" alt="" width="26" height="26"> SecureScan</div>
        <div class="select-shell" style="padding:0 8px 14px;">
          <label for="ops-mode-side">Workspace</label>
          <select id="ops-mode-side">
            <option value="code" ${mode === 'code' ? 'selected' : ''}>Code</option>
            <option value="network" ${mode === 'network' ? 'selected' : ''}>Network</option>
          </select>
        </div>
        <nav>${sideHtml}</nav>
        <div class="side-status"><span class="status-light" id="side-live"></span> ${mode === 'network' ? 'network lab' : 'code scan'} ready</div>
      `;
      const applyMode = (value) => setOpsMode(value);
      const topSel = document.getElementById('ops-mode-select');
      const sideSel = document.getElementById('ops-mode-side');
      if (topSel) topSel.addEventListener('change', () => applyMode(topSel.value));
      if (sideSel) sideSel.addEventListener('change', () => applyMode(sideSel.value));
      const toggle = document.getElementById('nav-toggle');
      if (toggle) toggle.addEventListener('click', () => sidebar.classList.toggle('open'));
    }

    const jump = document.getElementById('nav-jump');
    if (jump) {
      jump.addEventListener('change', () => {
        if (jump.value) location.href = jump.value;
      });
    }

    const clock = document.getElementById('hud-clock');
    if (clock) {
      const tick = () => {
        clock.textContent = new Date().toISOString().replace('T', ' ').slice(0, 19) + 'Z';
      };
      tick();
      setInterval(tick, 1000);
    }

    document.getElementById('theme-toggle').addEventListener('click', Utils.toggleTheme);
    document.getElementById('logout-btn')?.addEventListener('click', logout);

    ['quick-drop', 'user-drop'].forEach((id) => {
      const wrap = document.getElementById(id);
      if (!wrap) return;
      const trigger = wrap.querySelector('.icon-btn, .avatar');
      trigger?.addEventListener('click', (e) => {
        e.stopPropagation();
        const open = wrap.classList.contains('open');
        closeDrops();
        wrap.classList.toggle('open', !open);
      });
    });
    document.addEventListener('click', () => closeDrops());
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') closeDrops();
    });

    pingHealth();
    setInterval(pingHealth, 30000);
    NotificationBell.init();
  }

  async function pingHealth() {
    const light = document.getElementById('api-live');
    const label = document.getElementById('api-live-label');
    const side = document.getElementById('side-live');
    try {
      const health = await Api.get('/api/health/');
      const ok = !!health.ok;
      [light, side].forEach((el) => {
        if (!el) return;
        el.classList.toggle('crit', !ok);
        el.classList.toggle('warn', false);
      });
      if (label) label.textContent = ok ? 'online' : 'db down';
    } catch (e) {
      [light, side].forEach((el) => {
        if (!el) return;
        el.classList.add('crit');
      });
      if (label) label.textContent = 'offline';
    }
  }

  async function initAuthenticatedPage(activePage) {
    const user = await requireAuth();
    if (!user) return null;
    renderTopbar(activePage);
    return user;
  }

  return { requireAuth, requireAdmin, getCurrentUser, logout, renderTopbar, initAuthenticatedPage, getOpsMode, setOpsMode };
})();
