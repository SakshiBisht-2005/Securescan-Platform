/** notifications.js - toast notifications + notification bell dropdown. */
const Toast = (() => {
  function ensureContainer() {
    let c = document.getElementById('toast-container');
    if (!c) {
      c = document.createElement('div');
      c.id = 'toast-container';
      document.body.appendChild(c);
    }
    return c;
  }

  function show(message, type = 'info', timeout = 4500) {
    const container = ensureContainer();
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    container.appendChild(toast);
    setTimeout(() => toast.remove(), timeout);
  }

  return {
    success: (m) => show(m, 'success'),
    error: (m) => show(m, 'error'),
    warning: (m) => show(m, 'warning'),
    info: (m) => show(m, 'info'),
  };
})();

const NotificationBell = (() => {
  async function refreshBadge() {
    const badge = document.getElementById('notif-badge');
    if (!badge) return;
    try {
      const data = await Api.get('/api/notifications/unread-count/');
      badge.style.display = data.unread_count > 0 ? 'block' : 'none';
    } catch (e) { /* not logged in yet */ }
  }

  async function loadDropdown() {
    const list = document.getElementById('notif-list');
    if (!list) return;
    list.innerHTML = '<div class="text-dim" style="padding:14px;">Loading...</div>';
    try {
      const data = await Api.get('/api/notifications/?page_size=8');
      if (!data.results.length) {
        list.innerHTML = '<div class="text-dim" style="padding:14px;">No notifications yet.</div>';
        return;
      }
      list.innerHTML = data.results.map((n) => `
        <div style="padding:12px 14px; border-bottom:1px solid var(--border); ${n.is_read ? 'opacity:.6' : ''}">
          <div style="font-weight:600; font-size:13.5px;">${Utils.escapeHtml(n.title)}</div>
          <div class="text-dim" style="font-size:12.5px; margin-top:2px;">${Utils.escapeHtml(n.message || '')}</div>
          <div class="text-faint" style="font-size:11.5px; margin-top:4px;">${Utils.timeAgo(n.created_at)}</div>
        </div>
      `).join('');
      await Api.post('/api/notifications/read-all/', {});
      refreshBadge();
    } catch (e) {
      list.innerHTML = '<div class="text-dim" style="padding:14px;">Could not load notifications.</div>';
    }
  }

  function init() {
    refreshBadge();
    setInterval(refreshBadge, 30000);
    const bell = document.getElementById('notif-bell');
    const dropdown = document.getElementById('notif-dropdown');
    if (bell && dropdown) {
      bell.addEventListener('click', (e) => {
        e.stopPropagation();
        dropdown.classList.toggle('open');
        if (dropdown.classList.contains('open')) loadDropdown();
      });
      document.addEventListener('click', () => dropdown.classList.remove('open'));
      dropdown.addEventListener('click', (e) => e.stopPropagation());
    }
  }

  return { init, refreshBadge };
})();
