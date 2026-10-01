/**
 * api.js - central Fetch API client.
 * Handles JWT attach/refresh, the platform's standard {success,data|error}
 * envelope, and consistent error surfacing. No other module should call
 * fetch() directly against the backend.
 */
const API_BASE = window.SECURESCAN_API_BASE || location.origin;
// Same origin as the UI (port 5500 proxies /api to Django). Optional api-config.js override.

const TOKEN_KEY = 'securescan_access_token';
const REFRESH_KEY = 'securescan_refresh_token';

const Api = (() => {
  function getAccessToken() { return localStorage.getItem(TOKEN_KEY); }
  function getRefreshToken() { return localStorage.getItem(REFRESH_KEY); }
  function setTokens(access, refresh) {
    if (access) localStorage.setItem(TOKEN_KEY, access);
    if (refresh) localStorage.setItem(REFRESH_KEY, refresh);
  }
  function clearTokens() {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(REFRESH_KEY);
  }

  async function refreshAccessToken() {
    const refresh = getRefreshToken();
    if (!refresh) throw new Error('No refresh token available');
    const res = await fetch(`${API_BASE}/api/auth/token/refresh/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh }),
    });
    if (!res.ok) throw new Error('Session expired');
    const data = await res.json();
    setTokens(data.access, null);
    return data.access;
  }

  function isPublicAuthPath(path) {
    return (
      path.startsWith('/api/auth/login/')
      || path.startsWith('/api/auth/register/')
      || path.startsWith('/api/auth/password-reset/')
      || path.startsWith('/api/auth/invites/preview/')
      || path.startsWith('/api/auth/invites/join/')
      || path.startsWith('/api/health/')
    );
  }

  async function request(path, { method = 'GET', body, isForm = false, retry = true } = {}) {
    const headers = {};
    const token = getAccessToken();
    if (token && !isPublicAuthPath(path)) headers['Authorization'] = `Bearer ${token}`;
    if (!isForm) headers['Content-Type'] = 'application/json';

    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 45000);
    let res;
    try {
      res = await fetch(`${API_BASE}${path}`, {
        method,
        headers,
        body: body ? (isForm ? body : JSON.stringify(body)) : undefined,
        signal: ctrl.signal,
      });
    } catch (e) {
      clearTimeout(timer);
      if (retry && method === 'GET') {
        return request(path, { method, body, isForm, retry: false });
      }
      const err = new Error(
        e.name === 'AbortError'
          ? 'The API timed out. Keep python start.py running and try again.'
          : 'Cannot reach the API. Keep start.py open. On Cloudflare, use the Public site URL from that window.'
      );
      err.status = 0;
      throw err;
    }
    clearTimeout(timer);

    if (res.status === 401 && retry && getRefreshToken() && !isPublicAuthPath(path)) {
      try {
        await refreshAccessToken();
        return request(path, { method, body, isForm, retry: false });
      } catch (e) {
        clearTokens();
        const onInvite = location.pathname.endsWith('accept-invite.html');
        if (!location.pathname.endsWith('login.html') && !onInvite) {
          location.href = 'login.html';
        }
        throw e;
      }
    }

    let payload;
    const contentType = res.headers.get('content-type') || '';
    if (contentType.includes('application/json')) {
      payload = await res.json();
    } else {
      payload = null;
    }

    if (!res.ok) {
      const message = payload?.error?.message || `Request failed (${res.status})`;
      const err = new Error(message);
      err.code = payload?.error?.code;
      err.details = payload?.error?.details;
      err.status = res.status;
      throw err;
    }

    return payload ? payload.data : null;
  }

  return {
    get: (path) => request(path),
    post: (path, body) => request(path, { method: 'POST', body }),
    put: (path, body) => request(path, { method: 'PUT', body }),
    patch: (path, body) => request(path, { method: 'PATCH', body }),
    del: (path) => request(path, { method: 'DELETE' }),
    postForm: (path, formData) => request(path, { method: 'POST', body: formData, isForm: true }),
    downloadUrl: (path) => `${API_BASE}${path}`,
    getAccessToken, getRefreshToken, setTokens, clearTokens, refreshAccessToken,
    base: API_BASE,
  };
})();
