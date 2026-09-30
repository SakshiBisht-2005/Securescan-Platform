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

  function renderTopbar(activePage) {
    const mount = document.getElementById('app-topbar');
    if (!mount) return;
    const mode = getOpsMode(activePage);
    const codeLinks = [
      ['dashboard.html', 'Dashboard', '▣'],
      ['projects.html', 'Projects', '▤'],
      ['vulnerabilities.html', 'Findings', '⚠'],
      ['team.html', 'Team', '👥'],
      ['reports.html', 'Reports', '☰'],
      ['profile.html', 'Profile', '◉'],
    ];
    const networkLinks = [
      ['network.html', 'Network lab', '◎'],
      ['profile.html', 'Profile', '◉'],
    ];
    const links = mode === 'network' ? networkLinks : codeLinks;
    if (currentUser && currentUser.role === 'ADMIN') links.push(['admin.html', 'Admin', '⚙']);

    const navHtml = links.map(([href, label]) =>
      `<a href="${href}" class="${activePage === href ? 'active' : ''}">${label}</a>`
    ).join('');
    const sideHtml = links.map(([href, label, ico]) =>
      `<a href="${href}" class="${activePage === href ? 'active' : ''}"><span class="nav-ico">${ico}</span>${label}</a>`
    ).join('');

    const isEditor = !!document.querySelector('.editor-app');
    mount.innerHTML = `
      <button class="icon-btn" id="nav-toggle" title="Menu" type="button">☰</button>
      <div class="brand"><img class="logo-3d" src="assets/img/securescan-shield-3d.png" alt="" width="26" height="26"> SecureScan</div>
      ${isEditor ? `<nav>${navHtml}</nav>` : '<div class="hud-kicker" style="margin:0;flex:1;">Ops console</div>'}
      <div class="hud-lights"><span class="status-light"></span> online</div>
      <div class="hud-clock" id="hud-clock"></div>
      <div class="topbar-right">
        <button class="icon-btn" id="theme-toggle" title="Toggle theme">🌓</button>
        <div style="position:relative;">
          <button class="icon-btn" id="notif-bell" title="Notifications">🔔<span class="badge-dot" id="notif-badge" style="display:none;"></span></button>
          <div id="notif-dropdown" style="display:none; position:absolute; right:0; top:44px; width:320px; background:var(--bg-elevated); border:1px solid var(--border); border-radius:4px; box-shadow:var(--shadow); z-index:100; max-height:400px; overflow-y:auto;">
            <div style="padding:12px 14px; font-weight:700; border-bottom:1px solid var(--border); letter-spacing:.08em; text-transform:uppercase; font-size:12px;">Notifications</div>
            <div id="notif-list"></div>
          </div>
        </div>
        <div class="avatar" id="user-avatar" title="${Utils.escapeHtml(currentUser?.username || '')}">${(currentUser?.username || '?')[0].toUpperCase()}</div>
      </div>
    `;

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
        <div class="mode-switch">
          <button type="button" data-ops-mode="code" class="${mode === 'code' ? 'active' : ''}">Code</button>
          <button type="button" data-ops-mode="network" class="${mode === 'network' ? 'active' : ''}">Network</button>
        </div>
        <nav>${sideHtml}</nav>
        <div class="side-status"><span class="status-light"></span> ${mode === 'network' ? 'network lab' : 'code scan'} ready</div>
      `;
      sidebar.querySelectorAll('[data-ops-mode]').forEach((btn) => {
        btn.addEventListener('click', () => setOpsMode(btn.dataset.opsMode));
      });
      const toggle = document.getElementById('nav-toggle');
      if (toggle) {
        toggle.addEventListener('click', () => sidebar.classList.toggle('open'));
      }
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
    document.getElementById('user-avatar').addEventListener('click', () => { if (confirm('Log out?')) logout(); });

    const style = document.createElement('style');
    style.textContent = '#notif-dropdown.open{display:block !important;}';
    document.head.appendChild(style);

    NotificationBell.init();
  }

  async function initAuthenticatedPage(activePage) {
    const user = await requireAuth();
    if (!user) return null;
    renderTopbar(activePage);
    return user;
  }

  return { requireAuth, requireAdmin, getCurrentUser, logout, renderTopbar, initAuthenticatedPage, getOpsMode, setOpsMode };
})();
