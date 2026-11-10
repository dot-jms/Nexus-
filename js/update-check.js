(function() {
  if (!('serviceWorker' in navigator)) return;

  const CACHE_KEY = 'nexus-app-version';

  function getStoredVersion() {
    try { return localStorage.getItem(CACHE_KEY) || 'none'; } catch { return 'none'; }
  }
  function setStoredVersion(v) {
    try { localStorage.setItem(CACHE_KEY, v); } catch {}
  }

  // FIX #4: Instead of silently force-reloading mid-session (jarring, loses unsent messages),
  // show a non-disruptive update banner the user can act on themselves.
  let _updateBannerShown = false;
  function showUpdateBanner() {
    if (_updateBannerShown) return;
    _updateBannerShown = true;
    const bar = document.createElement('div');
    bar.id = 'update-bar';
    bar.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:9998;background:var(--accent);color:#fff;font-family:\'Syne\',sans-serif;font-size:13px;font-weight:700;padding:9px 16px;display:flex;align-items:center;justify-content:space-between;gap:12px;box-shadow:0 2px 12px rgba(0,0,0,.4)';
    bar.innerHTML = '<span>✨ A new version of Nexus is available.</span><button onclick="window.location.reload()" style="background:rgba(255,255,255,0.2);border:1px solid rgba(255,255,255,0.4);border-radius:6px;color:#fff;font-family:\'Syne\',sans-serif;font-size:12px;font-weight:700;padding:5px 12px;cursor:pointer">Reload now</button>';
    document.body.appendChild(bar);
  }

  async function checkForUpdate() {
    try {
      const RELAY_BASE = 'wss://nexus.dot-jms.deno.net'.replace(/^ws/, 'http');
      const res = await fetch(RELAY_BASE + '/_version', { cache: 'no-store' });
      if (!res.ok) return;
      const { version } = await res.json();
      const stored = getStoredVersion();
      if (stored === 'none') {
        setStoredVersion(version);
        return;
      }
      if (version !== stored) {
        console.log('[nexus] New version detected:', stored, '→', version);
        setStoredVersion(version);
        if ('caches' in window) {
          const keys = await caches.keys();
          await Promise.all(keys.map(k => caches.delete(k)));
        }
        // FIX #4: Don't force-reload — show a banner instead so users aren't kicked mid-chat
        showUpdateBanner();
      }
    } catch { /* fetch failed — offline or file missing, skip */ }
  }

  // FIX #3: blob: URL service workers are rejected by browsers because the blob origin
  // doesn't match the page origin (scope '/' is unreachable from blob:). The SW registration
  // always silently fails. Fix: write sw.js as a real file via the relay, or skip SW
  // registration here and rely solely on the version-check + banner approach above.
  // The network-first SW was only needed to prevent stale HTML — the /_version check
  // already handles that. Removing the broken blob SW registration entirely.

  // Check on load (2s delay so main app boots first) and on every tab focus
  window.addEventListener('load', () => setTimeout(checkForUpdate, 2000));
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') checkForUpdate();
  });
})();
