/** utils.js - shared helper functions used across pages. */
const Utils = (() => {
  function el(tag, attrs = {}, children = []) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (k === 'class') node.className = v;
      else if (k === 'html') node.innerHTML = v;
      else if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2), v);
      else node.setAttribute(k, v);
    }
    (Array.isArray(children) ? children : [children]).forEach((c) => {
      if (c === null || c === undefined) return;
      node.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
    });
    return node;
  }

  function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  function formatDate(iso) {
    if (!iso) return '-';
    const d = new Date(iso);
    return d.toLocaleString(undefined, { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
  }

  function timeAgo(iso) {
    if (!iso) return '-';
    const diff = (Date.now() - new Date(iso).getTime()) / 1000;
    if (diff < 60) return 'just now';
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return `${Math.floor(diff / 86400)}d ago`;
  }

  function severityBadge(severity) {
    const s = (severity || 'INFO').toLowerCase();
    return `<span class="badge badge-${s}">${severity}</span>`;
  }

  function statusBadge(status) {
    const map = { open: 'badge-critical', resolved: 'badge-success', ignored: 'badge-neutral', false_positive: 'badge-neutral' };
    return `<span class="badge ${map[status] || 'badge-neutral'}">${(status || '').replace('_', ' ')}</span>`;
  }

  function qs(selector, root = document) { return root.querySelector(selector); }
  function qsa(selector, root = document) { return Array.from(root.querySelectorAll(selector)); }

  function getQueryParam(name) {
    return new URLSearchParams(location.search).get(name);
  }

  function safeInternalPath(raw) {
    if (!raw) return null;
    try {
      const url = new URL(raw, location.origin);
      const file = (url.pathname.split('/').pop() || '');
      if (file === 'accept-invite.html' && url.search.includes('token=')) {
        return 'accept-invite.html' + url.search;
      }
      if (url.origin !== location.origin) return null;
      if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
      if (!file.endsWith('.html')) return null;
      return file + url.search + url.hash;
    } catch (e) {
      return null;
    }
  }

  function debounce(fn, wait = 300) {
    let t;
    return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), wait); };
  }

  function scoreColor(score) {
    if (score === null || score === undefined) return 'var(--text-faint)';
    if (score >= 80) return 'var(--low)';
    if (score >= 60) return 'var(--medium)';
    if (score >= 40) return 'var(--high)';
    return 'var(--critical)';
  }

  function initTheme() {
    const saved = localStorage.getItem('securescan_theme');
    if (saved) document.documentElement.setAttribute('data-theme', saved);
  }

  function toggleTheme() {
    const current = document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
    const next = current === 'light' ? 'dark' : 'light';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('securescan_theme', next);
  }

  return { el, escapeHtml, formatDate, timeAgo, severityBadge, statusBadge, qs, qsa, getQueryParam, safeInternalPath, debounce, scoreColor, initTheme, toggleTheme };
})();

Utils.initTheme();
(function loadUiFx() {
  const s = document.createElement('script');
  s.src = 'assets/js/ui-fx.js';
  (document.body || document.head).appendChild(s);
})();
