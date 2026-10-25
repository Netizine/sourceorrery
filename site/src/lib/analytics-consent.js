// Loaded in <head>. Refusing consent prevents the Clarity tag from loading at all.
// ConsentV2 denial alone permits cookieless collection, so it is not our opt-out.
(() => {
  if (window.sourceorreryAnalytics) return;
  const key = 'sourceorrery.analytics.v1';
  const maxAge = 180 * 24 * 60 * 60 * 1000;
  let requested = false;
  let choice = read();

  function browserOptOut() {
    return navigator.globalPrivacyControl === true
      || navigator.doNotTrack === '1' || navigator.doNotTrack === 'yes'
      || window.doNotTrack === '1';
  }

  function read() {
    try {
      const saved = JSON.parse(window.localStorage.getItem(key));
      if (saved?.version !== 1) return null;
      if (saved.choice === 'denied') return 'denied';
      const age = Date.now() - saved.at;
      if (saved.choice === 'granted' && age >= 0 && age < maxAge) return 'granted';
    } catch { /* Unavailable or malformed storage leaves analytics off. */ }
    return null;
  }

  function current() { return browserOptOut() ? 'denied' : choice; }
  function announce() { window.dispatchEvent(new CustomEvent('sourceorrery:privacy-change')); }

  function start() {
    if (requested || current() !== 'granted') return;
    // Local builds and deployment previews must not send visits to the live project.
    if (!['sourceorrery.ai', 'www.sourceorrery.ai'].includes(window.location.hostname)) return;
    requested = true;
    window.clarity = window.clarity || function () {
      (window.clarity.q = window.clarity.q || []).push(arguments);
    };
    window.clarity('consentv2', { ad_Storage: 'denied', analytics_Storage: 'granted' });
    const tag = document.createElement('script');
    tag.id = 'sourceorrery-clarity';
    tag.async = true;
    tag.src = 'https://www.clarity.ms/tag/z20sc8puam';
    document.head.appendChild(tag);
  }

  function stop() {
    if (!requested) return;
    window.clarity?.('consentv2', { ad_Storage: 'denied', analytics_Storage: 'denied' });
    window.clarity?.('stop');
    document.getElementById('sourceorrery-clarity')?.remove();
    // A reload removes the already-loaded collector and all of its listeners.
    // The saved refusal prevents loading on this page and subsequent visits.
    window.location.reload();
  }

  function choose(next) {
    if (!['granted', 'denied'].includes(next)) return;
    choice = browserOptOut() ? 'denied' : next;
    try {
      window.localStorage.setItem(key, JSON.stringify({ version: 1, choice, at: Date.now() }));
    } catch { /* The choice still applies to this page; future pages default off. */ }
    announce();
    if (current() === 'granted') start();
    else stop();
  }

  function refresh() {
    choice = read();
    announce();
    if (current() === 'granted') start();
    else stop();
  }

  window.sourceorreryAnalytics = Object.freeze({
    choice: current,
    browserOptOut,
    choose,
    open: () => window.dispatchEvent(new CustomEvent('sourceorrery:privacy-open')),
  });
  window.addEventListener('storage', (event) => {
    if (event.key === key || event.key === null) refresh();
  });
  window.addEventListener('pageshow', refresh);
  start();
})();
