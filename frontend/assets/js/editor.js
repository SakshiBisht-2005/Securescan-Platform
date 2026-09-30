/** editor.js - browser IDE: file explorer, tabs, Monaco editor, save/create/
 * delete/rename, in-project search, in-place scan, vulnerability indicators.
 * Open files and unsaved edits are kept in sessionStorage so leaving for
 * Findings and coming back does not wipe the editor. */
(async function () {
  const user = await Auth.initAuthenticatedPage('');
  if (!user) return;

  const projectId = Utils.getQueryParam('project');
  if (!projectId) { location.href = 'projects.html'; return; }

  const SESSION_KEY = `securescan_editor_${projectId}`;

  let monacoEditor = null;
  let openTabs = []; // {path, model, dirty, listening}
  let activePath = null;
  let findingsByFile = {};
  let lastCompletedScanId = null;
  let persistTimer = null;
  let scanBusy = false;

  const LANGUAGE_MAP = {
    py: 'python', js: 'javascript', jsx: 'javascript', ts: 'typescript', tsx: 'typescript',
    java: 'java', php: 'php', c: 'c', h: 'c', cpp: 'cpp', go: 'go', rb: 'ruby',
    kt: 'kotlin', swift: 'swift', html: 'html', css: 'css', yml: 'yaml', yaml: 'yaml',
    json: 'json', tf: 'hcl', sh: 'shell', sql: 'sql', md: 'markdown', xml: 'xml',
  };

  function log(text) {
    const el = document.getElementById('output-log');
    el.textContent = `${new Date().toLocaleTimeString()}  ${text}\n` + el.textContent;
  }

  function sessionPayload() {
    return {
      activePath,
      tabs: openTabs.map((t) => ({
        path: t.path,
        content: t.model.getValue(),
        dirty: !!t.dirty,
      })),
    };
  }

  function persistSession() {
    try {
      sessionStorage.setItem(SESSION_KEY, JSON.stringify(sessionPayload()));
    } catch (e) { /* quota / private mode */ }
  }

  function schedulePersist() {
    clearTimeout(persistTimer);
    persistTimer = setTimeout(persistSession, 250);
  }

  function readSession() {
    try {
      const raw = sessionStorage.getItem(SESSION_KEY);
      return raw ? JSON.parse(raw) : null;
    } catch (e) {
      return null;
    }
  }

  async function loadProject() {
    try {
      const project = await Api.get(`/api/projects/${projectId}/`);
      document.getElementById('editor-project-name').textContent = project.name;
    } catch (e) {
      Toast.error('Project not found.');
    }
  }

  async function loadFindingsIndex() {
    try {
      const latest = await Api.get(`/api/scans/?project=${projectId}&status=completed&page_size=1&ordering=-created_at`);
      if (!latest.results.length) return;
      const scanId = latest.results[0].id;
      lastCompletedScanId = scanId;
      const [findings, secrets] = await Promise.all([
        Api.get(`/api/scans/${scanId}/findings/?page_size=200`),
        Api.get(`/api/secret-findings/?scan=${scanId}&page_size=200`).catch(() => ({ results: [] })),
      ]);
      findingsByFile = {};
      (findings.results || []).forEach((f) => {
        if (!f.file_path) return;
        (findingsByFile[f.file_path] = findingsByFile[f.file_path] || []).push(f);
      });
      (secrets.results || []).forEach((s) => {
        if (!s.file_path) return;
        (findingsByFile[s.file_path] = findingsByFile[s.file_path] || []).push({
          severity: s.severity, title: s.secret_type, line_start: s.line_number,
        });
      });
    } catch (e) { /* no completed scans yet */ }
  }

  function renderFileFindings(path) {
    const box = document.getElementById('file-findings');
    const items = findingsByFile[path] || [];
    if (!items.length) { box.innerHTML = '<div class="text-dim">No known findings in this file.</div>'; return; }
    box.innerHTML = items.map((f) => `
      <div style="padding:8px 0; border-bottom:1px solid var(--border);">
        <span class="badge badge-${(f.severity || 'info').toLowerCase()}">${f.severity}</span>
        <div style="font-size:12.5px; margin-top:4px;">${Utils.escapeHtml(f.title)}</div>
        <div class="text-faint" style="font-size:11.5px;">Line ${f.line_start || '-'}</div>
      </div>
    `).join('');
  }

  async function loadTree() {
    try {
      const data = await Api.get(`/api/projects/${projectId}/editor/tree/`);
      renderTree(data.tree || [], document.getElementById('file-tree'));
      if (!(data.tree || []).length) {
        document.getElementById('file-tree').innerHTML = '<div class="text-dim" style="font-size:12.5px;">No files yet. Upload or import a project first.</div>';
      }
    } catch (e) {
      document.getElementById('file-tree').innerHTML = '<div class="text-dim" style="font-size:12.5px;">Could not load files. Try refreshing.</div>';
    }
  }

  function renderTree(nodes, container, depth = 0) {
    container.innerHTML = '';
    nodes.forEach((node) => {
      const item = document.createElement('div');
      item.className = 'file-tree-item';
      item.style.paddingLeft = `${8 + depth * 14}px`;
      const findingCount = (findingsByFile[node.path] || []).length;
      const indicator = findingCount ? `<span class="badge badge-critical" style="padding:1px 6px; font-size:9.5px;">${findingCount}</span>` : '';
      item.innerHTML = `<span>${node.type === 'directory' ? '📁' : '📄'}</span><span style="flex:1; overflow:hidden; text-overflow:ellipsis;">${Utils.escapeHtml(node.name)}</span>${indicator}`;
      if (node.type === 'file') {
        item.addEventListener('click', () => openFile(node.path));
      } else {
        const childWrap = document.createElement('div');
        childWrap.style.display = 'none';
        item.addEventListener('click', () => {
          childWrap.style.display = childWrap.style.display === 'none' ? 'block' : 'none';
        });
        container.appendChild(item);
        renderTree(node.children || [], childWrap, depth + 1);
        container.appendChild(childWrap);
        return;
      }
      container.appendChild(item);
    });
  }

  function guessLanguage(path) {
    const ext = path.split('.').pop().toLowerCase();
    return LANGUAGE_MAP[ext] || 'plaintext';
  }

  function attachDirtyListener(tab) {
    if (tab.listening) return;
    tab.listening = true;
    tab.model.onDidChangeContent(() => {
      tab.dirty = true;
      renderTabs();
      schedulePersist();
    });
  }

  function addTab(path, content, dirty) {
    let tab = openTabs.find((t) => t.path === path);
    if (tab) return tab;
    const model = monaco.editor.createModel(content, guessLanguage(path));
    tab = { path, model, dirty: !!dirty, listening: false };
    attachDirtyListener(tab);
    openTabs.push(tab);
    return tab;
  }

  async function openFile(path, opts = {}) {
    let tab = openTabs.find((t) => t.path === path);
    if (!tab) {
      try {
        const data = await Api.get(`/api/projects/${projectId}/editor/file/?path=${encodeURIComponent(path)}`);
        tab = addTab(path, data.content, false);
        log(`Opened ${path}`);
      } catch (e) {
        Toast.error(e.message || 'Failed to open file.');
        return;
      }
    }
    activePath = path;
    monacoEditor.setModel(tab.model);
    renderTabs();
    renderFileFindings(path);
    persistSession();
    if (opts.focusLine && monacoEditor) {
      const line = Number(opts.focusLine);
      monacoEditor.revealLineInCenter(line);
      monacoEditor.setPosition({ lineNumber: line, column: 1 });
      monacoEditor.focus();
    }
  }

  function renderTabs() {
    const bar = document.getElementById('editor-tabs');
    bar.innerHTML = openTabs.map((t) => `
      <div class="editor-tab ${t.path === activePath ? 'active' : ''}" data-path="${Utils.escapeHtml(t.path)}">
        <span>${Utils.escapeHtml(t.path.split('/').pop())}${t.dirty ? ' •' : ''}</span>
        <span class="close-tab" style="opacity:.6;">✕</span>
      </div>
    `).join('');
    Utils.qsa('.editor-tab', bar).forEach((el) => {
      const path = el.dataset.path;
      el.addEventListener('click', (e) => {
        if (e.target.classList.contains('close-tab')) { closeTab(path); return; }
        openFile(path);
      });
    });
  }

  function closeTab(path) {
    const tab = openTabs.find((t) => t.path === path);
    if (tab && tab.dirty && !confirm(`${path} has unsaved changes. Close anyway?`)) return;
    openTabs = openTabs.filter((t) => t.path !== path);
    if (activePath === path) {
      activePath = openTabs.length ? openTabs[openTabs.length - 1].path : null;
      monacoEditor.setModel(activePath ? openTabs.find(t => t.path === activePath).model : null);
      if (activePath) renderFileFindings(activePath);
    }
    renderTabs();
    persistSession();
  }

  async function saveTab(tab, { silent = false } = {}) {
    await Api.put(`/api/projects/${projectId}/editor/file/`, { path: tab.path, content: tab.model.getValue() });
    tab.dirty = false;
    if (!silent) {
      log(`Saved ${tab.path}`);
      Toast.success('File saved.');
    }
  }

  async function saveActiveFile() {
    if (!activePath) {
      Toast.error('Open a file from the explorer first, or create one with the document icon.');
      return;
    }
    const tab = openTabs.find((t) => t.path === activePath);
    try {
      await saveTab(tab);
      renderTabs();
      persistSession();
    } catch (e) {
      Toast.error(e.message || 'Save failed.');
    }
  }

  async function saveAllDirty({ silent = false } = {}) {
    const dirty = openTabs.filter((t) => t.dirty);
    for (const tab of dirty) {
      try {
        await saveTab(tab, { silent: true });
      } catch (e) {
        if (!silent) Toast.error(`Could not save ${tab.path}: ${e.message || 'error'}`);
        return false;
      }
    }
    if (dirty.length) {
      renderTabs();
      persistSession();
      if (!silent) log(`Saved ${dirty.length} file${dirty.length === 1 ? '' : 's'} before scan.`);
    }
    return true;
  }

  async function restoreSession() {
    const saved = readSession();
    if (!saved || !saved.tabs || !saved.tabs.length) return;
    saved.tabs.forEach((entry) => addTab(entry.path, entry.content, entry.dirty));
    renderTabs();
    const target = saved.activePath && openTabs.some((t) => t.path === saved.activePath)
      ? saved.activePath
      : openTabs[0].path;
    await openFile(target);
    log('Restored open files from your last editor session.');
  }

  function setScanUi(running, percent, stage, status) {
    const box = document.getElementById('editor-scan-status');
    const fill = document.getElementById('editor-scan-fill');
    const pct = document.getElementById('editor-scan-percent');
    const stageEl = document.getElementById('editor-scan-stage');
    const fileBtn = document.getElementById('scan-file-btn');
    const projectBtn = document.getElementById('scan-project-btn');
    if (!running) {
      box.hidden = true;
      fileBtn.disabled = false;
      projectBtn.disabled = false;
      projectBtn.textContent = 'Scan Project';
      return;
    }
    box.hidden = false;
    fileBtn.disabled = true;
    projectBtn.disabled = true;
    projectBtn.textContent = 'Scanning...';
    fill.style.width = `${percent || 0}%`;
    pct.textContent = `${percent || 0}%`;
    if (status === 'queued') stageEl.textContent = 'Waiting for scan worker';
    else stageEl.textContent = stage || 'Preparing files';
  }

  async function startInEditorScan(scopePath) {
    if (scanBusy) return;
    const saved = await saveAllDirty({ silent: false });
    if (!saved) return;
    persistSession();
    scanBusy = true;
    setScanUi(true, 2, scopePath ? `Queueing scan (${scopePath})` : 'Queueing scan');
    log(scopePath ? `Starting scan of ${scopePath}.` : 'Starting project scan. Your files stay open in this editor.');
    try {
      const payload = {
        scan_type: 'full',
        enable_sast: true,
        enable_sca: true,
        enable_secrets: true,
        enable_iac: true,
        enable_container: true,
        generate_report: true,
      };
      if (scopePath) payload.scope_path = scopePath;
      const data = await Api.post(`/api/projects/${projectId}/scan/`, payload);
      const scanId = data.scan.id;
      log(`Scan #${scanId} started.`);
      openScanChannel(scanId, {
        onProgress: (st) => {
          setScanUi(true, st.progress_percent, st.progress_stage, st.status);
        },
        onComplete: async (status) => {
          scanBusy = false;
          setScanUi(false);
          await loadFindingsIndex();
          await loadTree();
          if (activePath) renderFileFindings(activePath);
          persistSession();
          if (status.status === 'completed') {
            lastCompletedScanId = status.id;
            log('Scan completed. Findings for the open file are on the right.');
            Toast.success('Scan completed. Your files are still here.');
          } else {
            log(`Scan ${status.status}.`);
            Toast.error(`Scan ${status.status}.`);
          }
        },
        onError: () => {
          scanBusy = false;
          setScanUi(false);
          Toast.error('Lost connection to scan status.');
        },
      });
    } catch (e) {
      scanBusy = false;
      setScanUi(false);
      Toast.error(e.message || 'Failed to start scan.');
    }
  }

  require.config({ paths: { vs: 'https://cdnjs.cloudflare.com/ajax/libs/monaco-editor/0.49.0/min/vs' } });
  require(['vs/editor/editor.main'], () => {
    monacoEditor = monaco.editor.create(document.getElementById('monaco-container'), {
      value: '// Select a file from the explorer to begin editing.',
      language: 'plaintext',
      theme: document.documentElement.getAttribute('data-theme') === 'light' ? 'vs' : 'vs-dark',
      automaticLayout: true,
      fontSize: 13,
      fontFamily: '"IBM Plex Mono", Consolas, monospace',
      lineNumbers: 'on',
      minimap: { enabled: true },
      renderLineHighlight: 'all',
    });
    monacoEditor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyS, saveActiveFile);
    init();
  });

  document.getElementById('editor-theme-toggle').addEventListener('click', () => {
    Utils.toggleTheme();
    monaco.editor.setTheme(document.documentElement.getAttribute('data-theme') === 'light' ? 'vs' : 'vs-dark');
  });

  function openNewEntryModal(type) {
    document.getElementById('new-entry-title').textContent = type === 'directory' ? 'New Folder' : 'New File';
    document.getElementById('new-entry-path').value = '';
    document.getElementById('new-entry-modal').dataset.type = type;
    document.getElementById('new-entry-modal').classList.add('open');
  }
  document.getElementById('new-file-btn').addEventListener('click', () => openNewEntryModal('file'));
  document.getElementById('new-folder-btn').addEventListener('click', () => openNewEntryModal('directory'));
  document.getElementById('close-new-entry').addEventListener('click', () => document.getElementById('new-entry-modal').classList.remove('open'));
  document.getElementById('cancel-new-entry').addEventListener('click', () => document.getElementById('new-entry-modal').classList.remove('open'));
  document.getElementById('confirm-new-entry').addEventListener('click', async () => {
    const path = document.getElementById('new-entry-path').value.trim();
    const type = document.getElementById('new-entry-modal').dataset.type;
    if (!path) return;
    try {
      await Api.post(`/api/projects/${projectId}/editor/create/`, { path, type, content: '' });
      document.getElementById('new-entry-modal').classList.remove('open');
      await loadTree();
      if (type === 'file') {
        openFile(path);
        log(`Created file ${path}`);
      } else {
        log(`Created folder ${path}`);
      }
    } catch (e) {
      Toast.error(e.message || 'Failed to create.');
    }
  });

  document.getElementById('global-search').addEventListener('keydown', async (e) => {
    if (e.key !== 'Enter') return;
    const q = e.target.value.trim();
    if (q.length < 2) return;
    try {
      const data = await Api.get(`/api/projects/${projectId}/editor/search/?q=${encodeURIComponent(q)}`);
      log(`Search "${q}": ${data.results.length} matches\n` + data.results.slice(0, 30).map(r => `  ${r.path}:${r.line}  ${r.text}`).join('\n'));
    } catch (e2) {
      Toast.error('Search failed.');
    }
  });

  document.getElementById('scan-project-btn').addEventListener('click', startInEditorScan);
  document.getElementById('scan-file-btn').addEventListener('click', () => {
    if (!activePath) { Toast.error('Open a file first.'); return; }
    startInEditorScan(activePath);
  });
  document.getElementById('open-findings-btn').addEventListener('click', () => {
    persistSession();
    const qs = lastCompletedScanId
      ? `project=${projectId}&scan=${lastCompletedScanId}`
      : `project=${projectId}`;
    location.href = `vulnerabilities.html?${qs}`;
  });

  window.addEventListener('beforeunload', () => persistSession());
  setInterval(() => { saveAllDirty({ silent: true }); }, 15000);

  async function init() {
    await loadProject();
    await loadFindingsIndex();
    await loadTree();
    await restoreSession();
    const deepPath = Utils.getQueryParam('path');
    const deepLine = Number(Utils.getQueryParam('line') || 0);
    if (deepPath) {
      await openFile(deepPath, { focusLine: deepLine || undefined });
    }
  }
})();
