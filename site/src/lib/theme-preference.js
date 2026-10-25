// Keep theme selection usable when browser storage is unavailable.
(() => {
  if (window.sourceorreryTheme) return;
  const system = window.matchMedia('(prefers-color-scheme: light)');
  const parse = value => ['light', 'dark'].includes(value) ? value : 'auto';
  let preference = 'auto';
  try { preference = parse(window.localStorage.getItem('starlight-theme')); } catch { /* Use system theme. */ }
  function refresh() {
    document.documentElement.dataset.theme = preference === 'auto'
      ? (system.matches ? 'light' : 'dark') : preference;
    document.querySelectorAll('starlight-theme-select select').forEach(select => { select.value = preference; });
  }
  function set(value) {
    preference = parse(value);
    try { window.localStorage.setItem('starlight-theme', preference === 'auto' ? '' : preference); } catch { /* This page still changes. */ }
    refresh();
  }
  window.sourceorreryTheme = Object.freeze({ refresh, set });
  system.addEventListener('change', () => { if (preference === 'auto') refresh(); });
  refresh();
})();
