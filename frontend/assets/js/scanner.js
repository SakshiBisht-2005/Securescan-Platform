/** scanner.js - scan configuration + live progress via polling. */
(async function () {
  const user = await Auth.initAuthenticatedPage('projects.html');
  if (!user) return;

  const projectId = Utils.getQueryParam('project');
  const existingScanId = Utils.getQueryParam('scan');
  if (!projectId && !existingScanId) { location.href = 'projects.html'; return; }

  const STAGES = [
    ['preparing', 'Preparing files'], ['sast', 'Running SAST'], ['sca', 'Running SCA'],
    ['secrets', 'Scanning secrets'], ['iac', 'Scanning IaC'], ['container', 'Scanning containers'],
    ['normalizing', 'Normalizing results'], ['finalizing', 'Generating report'],
  ];

  function renderStageList(currentStage) {
    const currentIndex = STAGES.findIndex(([key]) => key === currentStage);
    document.getElementById('stage-list').innerHTML = STAGES.map(([key, label], i) => {
      const cls = i < currentIndex ? 'done' : i === currentIndex ? 'active' : '';
      return `<div class="scan-stage ${cls}"><span class="dot"></span>${label}</div>`;
    }).join('');
  }

  async function loadProjectLabel(pid) {
    try {
      const project = await Api.get(`/api/projects/${pid}/`);
      document.getElementById('project-name-label').textContent = project.name;
      document.getElementById('opt-branch').value = project.default_branch || 'main';
      return project;
    } catch (e) { return null; }
  }

  function trackScan(scanId) {
    document.getElementById('config-card').style.pointerEvents = 'none';
    document.getElementById('config-card').style.opacity = '.6';
    document.getElementById('progress-idle').style.display = 'none';
    document.getElementById('progress-active').style.display = 'block';

    openScanChannel(scanId, {
      onProgress: (status) => {
        document.getElementById('progress-fill').style.width = `${status.progress_percent}%`;
        document.getElementById('progress-percent').textContent = `${status.progress_percent}%`;
        const stageEntry = STAGES.find(([key]) => key === status.progress_stage);
        document.getElementById('progress-stage-label').textContent = stageEntry ? stageEntry[1] : status.progress_stage;
        renderStageList(status.progress_stage);
      },
      onComplete: (status) => {
        document.getElementById('progress-active').style.display = 'none';
        document.getElementById('progress-done').style.display = 'block';
        document.getElementById('view-results-btn').href = `vulnerabilities.html?scan=${scanId}&project=${projectId || ''}`;
        const back = document.getElementById('back-to-editor-btn');
        if (back && projectId) back.href = `editor.html?project=${projectId}`;
        if (status.status === 'completed') {
          Toast.success('Scan completed successfully.');
        } else {
          Toast.error(`Scan ${status.status}.`);
        }
      },
      onError: () => Toast.error('Lost connection to scan status.'),
    });
  }

  if (existingScanId) {
    document.getElementById('config-card').style.display = 'none';
    trackScan(existingScanId);
  } else {
    await loadProjectLabel(projectId);
  }

  document.getElementById('start-scan-btn').addEventListener('click', async () => {
    const btn = document.getElementById('start-scan-btn');
    btn.disabled = true; btn.textContent = 'Starting scan...';
    try {
      const payload = {
        scan_type: 'full',
        enable_sast: document.getElementById('opt-sast').checked,
        enable_sca: document.getElementById('opt-sca').checked,
        enable_secrets: document.getElementById('opt-secrets').checked,
        enable_iac: document.getElementById('opt-iac').checked,
        enable_container: document.getElementById('opt-container').checked,
        branch: document.getElementById('opt-branch').value,
        exclusions: document.getElementById('opt-exclusions').value.split('\n').map(s => s.trim()).filter(Boolean),
        severity_threshold: document.getElementById('opt-threshold').value,
        generate_report: document.getElementById('opt-report').checked,
      };
      const data = await Api.post(`/api/projects/${projectId}/scan/`, payload);
      Toast.success('Scan started.');
      trackScan(data.scan.id);
    } catch (e) {
      Toast.error(e.message || 'Failed to start scan.');
      btn.disabled = false; btn.textContent = 'Start Security Scan';
    }
  });
})();
