/** ui-fx.js — presentation only: pointer spotlight, 3D card tilt. */
(function () {
  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  if (window.matchMedia('(pointer: coarse)').matches) return;

  document.addEventListener('pointermove', (e) => {
    const x = (e.clientX / window.innerWidth) * 100;
    const y = (e.clientY / window.innerHeight) * 100;
    document.documentElement.style.setProperty('--spot-x', x + '%');
    document.documentElement.style.setProperty('--spot-y', y + '%');
  });

  function attachTilt(el) {
    if (el.dataset.tiltBound) return;
    el.dataset.tiltBound = '1';
    el.addEventListener('pointermove', (e) => {
      const r = el.getBoundingClientRect();
      const px = (e.clientX - r.left) / r.width - 0.5;
      const py = (e.clientY - r.top) / r.height - 0.5;
      el.style.transform = `perspective(900px) rotateY(${px * 8}deg) rotateX(${-py * 8}deg) translateZ(8px)`;
    });
    el.addEventListener('pointerleave', () => {
      el.style.transform = '';
    });
  }

  function bind() {
    if (document.querySelector('.editor-app')) return;
    document.querySelectorAll('.stat-card, .feature-card, .tilt-3d').forEach(attachTilt);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', bind);
  } else {
    bind();
  }
  const mo = new MutationObserver(bind);
  mo.observe(document.body, { childList: true, subtree: true });
})();
