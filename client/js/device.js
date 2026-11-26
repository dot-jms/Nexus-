// ══════════════════════════════════════════════
// DEVICE SIGNALS for alt-account detection. NEVER uses the IP address, so VPNs/proxies don't matter.
// 1) a random device id kept in 3 places (localStorage + cookie + IndexedDB; any survivor restores the others)
// 2) hashed hardware fingerprints (GPU, canvas, audio, screen, cores, fonts...). Survives incognito / cleared storage.
// Only hashes leave the browser. Skipped completely while an admin is "being" someone (assume.js).
// ══════════════════════════════════════════════
const NXDEV = { ids: [], fp: [], hw: [], ready: false, lastSent: 0 };
(function () {
  const h53 = (s, seed) => { let a = 0xdeadbeef ^ seed, b = 0x41c6ce57 ^ seed; for (let i = 0; i < s.length; i++) { const c = s.charCodeAt(i); a = Math.imul(a ^ c, 2654435761); b = Math.imul(b ^ c, 1597334677); } a = Math.imul(a ^ (a >>> 16), 2246822507) ^ Math.imul(b ^ (b >>> 13), 3266489909); b = Math.imul(b ^ (b >>> 16), 2246822507) ^ Math.imul(a ^ (a >>> 13), 3266489909); return (4294967296 * (2097151 & b) + (a >>> 0)).toString(16).padStart(14, '0'); };
  const hash = s => h53(s, 1) + h53(s, 7) + h53(s, 13); // 42 hex chars
  const rnd = () => { try { const u = new Uint8Array(16); crypto.getRandomValues(u); return [...u].map(x => x.toString(16).padStart(2, '0')).join(''); } catch (_) { return hash(Math.random() + ':' + Date.now()).slice(0, 32); } };
  const okId = v => typeof v === 'string' && /^[0-9a-f]{16,64}$/.test(v);

  // ── persistent id in 3 stores ──
  const idb = (mode, val) => new Promise(res => {
    try {
      const r = indexedDB.open('nx-dev', 1);
      r.onupgradeneeded = () => r.result.createObjectStore('k');
      r.onerror = () => res(null);
      r.onsuccess = () => { try { const db = r.result, tx = db.transaction('k', mode === 'set' ? 'readwrite' : 'readonly'), st = tx.objectStore('k');
        if (mode === 'set') { st.put(val, 'did'); tx.oncomplete = () => { db.close(); res(true); }; tx.onerror = () => res(null); }
        else { const g = st.get('did'); g.onsuccess = () => { db.close(); res(g.result || null); }; g.onerror = () => res(null); } } catch (_) { res(null); } };
    } catch (_) { res(null); }
  });
  const getCookie = () => { try { const m = document.cookie.match(/(?:^|; )nx_did=([0-9a-f]+)/); return m ? m[1] : null; } catch (_) { return null; } };
  const setCookie = v => { try { document.cookie = 'nx_did=' + v + '; max-age=315360000; path=/; SameSite=Lax'; } catch (_) {} };
  async function deviceIds() {
    const found = [];
    try { found.push(localStorage.getItem('nx-did')); } catch (_) {}
    found.push(getCookie());
    found.push(await idb('get'));
    const ids = [...new Set(found.filter(okId))];
    const id = ids[0] || rnd();
    if (!ids.length) ids.push(id);
    try { localStorage.setItem('nx-did', id); } catch (_) {}
    setCookie(id); await idb('set', id);
    return ids.slice(0, 6);
  }

  // ── hardware fingerprint ──
  function canvasSig() {
    try {
      const c = document.createElement('canvas'); c.width = 240; c.height = 60; const x = c.getContext('2d');
      x.textBaseline = 'alphabetic'; x.fillStyle = '#f60'; x.fillRect(100, 1, 62, 20);
      x.fillStyle = '#069'; x.font = '15px Arial'; x.fillText('Nexus \u{1F427} alt-check 123', 2, 15);
      x.fillStyle = 'rgba(102,204,0,0.7)'; x.font = '18px serif'; x.fillText('Nexus \u{1F427} alt-check 123', 4, 45);
      x.globalCompositeOperation = 'multiply'; x.fillStyle = 'rgb(255,0,255)'; x.beginPath(); x.arc(50, 30, 20, 0, 6.283); x.fill();
      return hash(c.toDataURL());
    } catch (_) { return 'nocanvas'; }
  }
  function glSig() {
    try {
      const c = document.createElement('canvas'), g = c.getContext('webgl') || c.getContext('experimental-webgl');
      if (!g) return { r: 'nogl', p: '' };
      const e = g.getExtension('WEBGL_debug_renderer_info');
      const r = e ? g.getParameter(e.UNMASKED_VENDOR_WEBGL) + '|' + g.getParameter(e.UNMASKED_RENDERER_WEBGL) : g.getParameter(g.VENDOR) + '|' + g.getParameter(g.RENDERER);
      const p = [g.MAX_TEXTURE_SIZE, g.MAX_VERTEX_ATTRIBS, g.MAX_VERTEX_UNIFORM_VECTORS, g.MAX_FRAGMENT_UNIFORM_VECTORS, g.MAX_VARYING_VECTORS, g.MAX_RENDERBUFFER_SIZE, g.ALIASED_LINE_WIDTH_RANGE, g.ALIASED_POINT_SIZE_RANGE].map(k => { try { const v = g.getParameter(k); return v && v.length ? [...v].join(',') : v; } catch (_) { return '?'; } }).join(';') + ';' + (g.getSupportedExtensions() || []).length;
      return { r, p };
    } catch (_) { return { r: 'nogl', p: '' }; }
  }
  function audioSig() {
    return new Promise(res => {
      try {
        const O = window.OfflineAudioContext || window.webkitOfflineAudioContext; if (!O) return res('noaudio');
        const ctx = new O(1, 5000, 44100), o = ctx.createOscillator(), k = ctx.createDynamicsCompressor();
        o.type = 'triangle'; o.frequency.value = 10000;
        [['threshold', -50], ['knee', 40], ['ratio', 12], ['attack', 0], ['release', 0.25]].forEach(([n, v]) => { try { k[n].value = v; } catch (_) {} });
        o.connect(k); k.connect(ctx.destination); o.start(0);
        const t = setTimeout(() => res('audiotimeout'), 1500);
        ctx.oncomplete = ev => { clearTimeout(t); let s = 0; const d = ev.renderedBuffer.getChannelData(0); for (let i = 4500; i < 5000; i++) s += Math.abs(d[i]); res(String(s)); };
        ctx.startRendering();
      } catch (_) { res('audioerr'); }
    });
  }
  function fontSig() {
    try {
      const fonts = ['Arial', 'Verdana', 'Times New Roman', 'Courier New', 'Georgia', 'Comic Sans MS', 'Impact', 'Trebuchet MS', 'Segoe UI', 'Calibri', 'Cambria', 'Consolas', 'Helvetica', 'Helvetica Neue', 'Menlo', 'Monaco', 'Roboto', 'Noto Sans', 'Ubuntu', 'DejaVu Sans', 'Liberation Sans', 'Cantarell', 'Open Sans', 'Lucida Grande', 'Tahoma', 'Palatino', 'Gill Sans', 'Futura', 'Apple Color Emoji', 'Segoe UI Emoji'];
      const s = document.createElement('span'); s.style.cssText = 'position:absolute;left:-9999px;top:-9999px;font-size:72px;visibility:hidden'; s.textContent = 'mmmmmmmmmmlliWQ@#';
      document.body.appendChild(s);
      const base = ['monospace', 'sans-serif', 'serif'].map(b => { s.style.fontFamily = b; return s.offsetWidth + 'x' + s.offsetHeight; });
      const bits = fonts.map(f => ['monospace', 'sans-serif', 'serif'].some((b, i) => { s.style.fontFamily = `'${f}',${b}`; return s.offsetWidth + 'x' + s.offsetHeight !== base[i]; }) ? 1 : 0).join('');
      s.remove(); return bits;
    } catch (_) { return 'nofonts'; }
  }
  async function fingerprints() {
    const n = navigator, dpr = window.devicePixelRatio || 1, sc = window.screen || {};
    // physical pixels: width*dpr stays constant when the page is zoomed, so zoom/resizing can't change it
    const scr = Math.round((sc.width || 0) * dpr) + 'x' + Math.round((sc.height || 0) * dpr) + 'x' + (sc.colorDepth || 0);
    const gl = glSig(), fonts = fontSig(), au = await audioSig();
    const core = [n.hardwareConcurrency || 0, n.deviceMemory || 0, n.platform || '', n.maxTouchPoints || 0, scr].join('|');
    // fp = this browser on this machine (strong). hw = the machine itself, whichever browser (weaker).
    return { fp: hash(['fp1', canvasSig(), au, gl.r, gl.p, core, fonts].join('#')), hw: hash(['hw1', gl.r.split('|').pop(), core, fonts].join('#')) };
  }

  const assuming = () => { try { return !!sessionStorage.getItem('nx-assume'); } catch (_) { return false; } };
  NXDEV.init = (async () => {
    if (assuming()) return;
    try {
      NXDEV.ids = await deviceIds();
      const f = await fingerprints(); NXDEV.fp = [f.fp]; NXDEV.hw = [f.hw];
    } catch (_) {}
    NXDEV.ready = true;
  })();
  NXDEV.get = () => (assuming() || !NXDEV.ids.length) ? null : { ids: NXDEV.ids, fp: NXDEV.fp, hw: NXDEV.hw };
})();
// called after `identified` (and by identify itself if the signals are already computed); at most every 30 min per page
async function nxDeviceReport() {
  try {
    await NXDEV.init;
    const dev = NXDEV.get(); if (!dev || Date.now() - NXDEV.lastSent < 30 * 60 * 1000) return;
    if (wsSend({ type: 'device_report', dev })) NXDEV.lastSent = Date.now();
  } catch (_) {}
}
