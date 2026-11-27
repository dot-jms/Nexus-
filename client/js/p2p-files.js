// ══════════════════════════════════════════════
// P2P ATTACHMENTS
// The server never keeps big files (they are stripped from history), so they live in the browsers that have seen them.
// Problem this fixes: localStorage drops big attachments on every save, so after ONE refresh nobody could serve a file any more.
// Now every attachment a browser sees is kept in IndexedDB (survives refreshes) and any online member who has it serves it.
// Works for every attachment type (image, video, audio, file) in server channels, DMs and group chats.
// ══════════════════════════════════════════════
const NXF = { p: null, seen: new Set(), asked: {}, puts: 0, MAX_FILES: 150, MAX_BYTES: 60e6 };
const nxfKey = (msgId, name) => msgId + '|' + (name || '');
function nxfDB() {
  if (NXF.p) return NXF.p;
  return NXF.p = new Promise(res => {
    try { const r = indexedDB.open('nexus-files', 1); r.onupgradeneeded = () => r.result.createObjectStore('f'); r.onsuccess = () => res(r.result); r.onerror = r.onblocked = () => res(null); }
    catch (_) { res(null); }
  });
}
async function nxfPut(k, rec) {
  try {
    if (!rec || typeof rec.url !== 'string' || rec.url.length > NXF.MAX_BYTES) return;
    const db = await nxfDB(); if (!db) return;
    await new Promise(res => { const tx = db.transaction('f', 'readwrite'); tx.objectStore('f').put({ ...rec, at: Date.now() }, k); tx.oncomplete = tx.onerror = tx.onabort = () => res(); });
    if (++NXF.puts % 20 === 0) nxfPrune();
  } catch (_) {}
}
async function nxfGet(k) {
  try {
    const db = await nxfDB(); if (!db) return null;
    return await new Promise(res => { const rq = db.transaction('f').objectStore('f').get(k); rq.onsuccess = () => res(rq.result || null); rq.onerror = () => res(null); });
  } catch (_) { return null; }
}
async function nxfPrune() {   // keep the newest MAX_FILES
  try {
    const db = await nxfDB(); if (!db) return;
    const rows = await new Promise(res => { const out = []; const rq = db.transaction('f').objectStore('f').openCursor(); rq.onsuccess = () => { const c = rq.result; if (c) { out.push({ k: c.key, at: c.value?.at || 0 }); c.continue(); } else res(out); }; rq.onerror = () => res([]); });
    if (rows.length <= NXF.MAX_FILES) return;
    rows.sort((a, b) => a.at - b.at);
    const tx = db.transaction('f', 'readwrite'), st = tx.objectStore('f');
    rows.slice(0, rows.length - NXF.MAX_FILES).forEach(r => st.delete(r.k));
  } catch (_) {}
}
// called for every attachment that is drawn with real data: keep a copy so we can serve it to others later
function nxfRemember(a, msgId) {
  if (!a || !msgId || typeof a.url !== 'string' || !a.url.startsWith('data:')) return;
  const k = nxfKey(msgId, a.name); if (NXF.seen.has(k)) return; NXF.seen.add(k);
  nxfPut(k, { url: a.url, type: a.type, name: a.name, size: a.size });
}
function nxfPlaceholder(m, a) {
  const ic = a.type === 'video' ? '🎬' : a.type === 'image' ? '🖼️' : a.type === 'audio' ? '🎵' : '📄';
  return `<div class="vid-placeholder" data-msg-id="${esc(m.id)}" data-ch-id="${esc(m.channelId || '')}" data-name="${esc(a.name || '')}" onclick="requestVideo(this.dataset.msgId,this.dataset.chId,this.dataset.name,true)" style="display:flex;align-items:center;gap:10px;background:var(--s3);border:1px solid var(--border2);border-radius:8px;padding:12px 16px;cursor:pointer;max-width:280px"><span style="font-size:20px">${ic}</span><div><div style="font-size:12px;font-weight:700;color:var(--t2)">${esc(a.name || 'attachment')}</div><div style="font-size:10px;color:var(--t3);margin-top:2px">Loading from peers… (click to retry)</div></div></div>`;
}
function nxfFindMsg(msgId) {
  for (const arr of Object.values(S.messages || {})) { const m = (arr || []).find(x => x && x.id === msgId); if (m) return m; }
  for (const arr of Object.values(S.dmMessages || {})) { const m = (arr || []).find(x => x && x.id === msgId); if (m) return m; }
  return null;
}
// a file arrived (from my own cache or from a peer): put it into the message and redraw just that attachment block
function nxfApply(msgId, name, url) {
  const m = nxfFindMsg(msgId); if (!m) return;
  let hit = false;
  m.attachments = (m.attachments || []).map(a => { if (a && (a._stripped || !a.url) && (a.name || '') === (name || '')) { hit = true; return { ...a, url, _stripped: false }; } return a; });
  if (!hit) return;
  document.querySelectorAll(`[data-id="${CSS.escape(String(msgId))}"]`).forEach(row => {
    const box = row.querySelector('.m-atts'); if (!box) return;
    try { const tmp = document.createElement('div'); tmp.innerHTML = buildMsg(m, false); const fresh = tmp.querySelector('.m-atts'); if (fresh) box.innerHTML = fresh.innerHTML; } catch (_) {}
  });
}
// after a message list is drawn: fill every placeholder from the local file cache, else ask peers (once every 20 s at most)
function nxfHydrate() {
  setTimeout(() => {
    document.querySelectorAll('.vid-placeholder[data-msg-id]').forEach(async el => {
      if (el.dataset.nxf) return; el.dataset.nxf = '1';
      const msgId = el.dataset.msgId, name = el.dataset.name || '';
      const rec = await nxfGet(nxfKey(msgId, name));
      if (rec && rec.url) { nxfApply(msgId, name, rec.url); return; }
      requestVideo(msgId, el.dataset.chId, name);
    });
  }, 30);
}
// ── asking peers (the server picks ONE holder per request and tells us when nobody has it) ──
const NXQ = { w: {}, fail: {}, running: false, timer: 0 };
async function nxfHash(url) {   // SHA-256 of the data URL: the sender puts it in the message, receivers verify what a peer sends
  try {
    const h = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(url));
    return [...new Uint8Array(h)].map(b => b.toString(16).padStart(2, '0')).join('');
  } catch (_) { return ''; }
}
function nxfScopeFor(msgId) {   // where does this message live? (decides who may be asked)
  for (const [chId, arr] of Object.entries(S.messages || {})) {
    if ((arr || []).some(x => x && x.id === msgId)) { const sv = (S.servers || []).find(s => (s.channels || []).some(c => c.id === chId)); return sv ? { serverId: sv.id, channelId: chId } : null; }
  }
  for (const [key, arr] of Object.entries(S.dmMessages || {})) {
    if ((arr || []).some(x => x && x.id === msgId)) { const d = dmEntry(key); if (!d) return null; return d.kind === 'group' ? { gid: d.gid } : { dm: true, with: d.name }; }
  }
  return null;
}
function nxfDone(k, ok) {
  if (!_pendingVideoRequests.delete(k)) return;
  (NXQ.w[k] || []).forEach(f => f(ok)); delete NXQ.w[k];
}
function nxfAsk(msgId, name) {   // resolves true when the file arrived (and passed its check), false when nobody had it
  const k = nxfKey(msgId, name), sc = nxfScopeFor(msgId);
  if (!sc || !S.user || !S.wsOk) return Promise.resolve(false);
  return new Promise(res => {
    if (_pendingVideoRequests.has(k)) { (NXQ.w[k] = NXQ.w[k] || []).push(res); return; }
    _pendingVideoRequests.add(k); NXQ.w[k] = [res];
    wsSend({ type: 'video_request', msgId, name, requester: S.user.name, ...sc });
    setTimeout(() => nxfDone(k, false), 45000);
  });
}
// a peer sent a file: verify it against the hash in the message (if there is one), keep it, show it
async function nxfAccept(msgId, name, url, msg) {
  const m = nxfFindMsg(msgId);
  const a = m && (m.attachments || []).find(x => x && (x.name || '') === (name || ''));
  if (a && a.hash && (await nxfHash(url)) !== a.hash) { console.warn('[nexus] a peer sent a file that failed its hash check:', name); return false; }
  nxfPut(nxfKey(msgId, name), { url, type: msg.atype || (a && a.type), name, size: msg.size });
  nxfApply(msgId, name, url);
  try { shortsOnMedia(); } catch (_) {}
  return true;
}
// someone asked for a file: answer from memory or from the file cache, or say we don't have it so the server tries the next person
async function nxfServe(msg) {
  const { msgId, name, requester, rid } = msg || {};
  if (!msgId || typeof requester !== 'string' || !S.user || requester === S.user.name) return;
  let url = null, type, size;
  const m = nxfFindMsg(msgId);
  const a = m && (m.attachments || []).find(x => x && typeof x.url === 'string' && x.url.startsWith('data:') && (!name || x.name === name));
  if (a) { url = a.url; type = a.type; size = a.size; }
  else { const rec = await nxfGet(nxfKey(msgId, name)); if (rec && rec.url) { url = rec.url; type = rec.type; size = rec.size; } }
  if (!url) { if (rid) wsSend({ type: 'video_miss', rid }); return; }
  wsSend({ type: 'video_serve', rid, msgId, channelId: msg.channelId, to: requester, url, name, size, atype: type });
}
// ── background catch-up: nobody has to click or scroll ──
// Every attachment I should have but don't (stripped by the server) is fetched one at a time: from my own cache first,
// then from whoever the server picks. Runs after login, when history arrives, and every 30 s while the tab is open.
function nxfMissing() {
  const out = [], seenK = new Set();
  const add = arr => (arr || []).slice().reverse().forEach(m => {
    if (!m || !m.id) return;
    (m.attachments || []).forEach(a => { const k = nxfKey(m.id, a && a.name); if (a && (a._stripped || !a.url) && !seenK.has(k)) { seenK.add(k); out.push({ id: m.id, name: a.name || '' }); } });
  });
  if (typeof curDM !== 'undefined' && curDM) add(S.dmMessages[curDM]); else if (S.curCh) add(S.messages[S.curCh.id]);   // what I'm looking at first
  Object.values(S.messages || {}).forEach(add); Object.values(S.dmMessages || {}).forEach(add);
  return out;
}
async function nxfSync() {
  if (NXQ.running || !S.user || !S.wsOk) return;
  NXQ.running = true;
  try {
    let asked = 0;
    for (const t of nxfMissing()) {
      if (asked >= 25 || !S.wsOk) break;
      const k = nxfKey(t.id, t.name);
      if ((NXQ.fail[k] || 0) > Date.now()) continue;
      const rec = await nxfGet(k);
      if (rec && rec.url) { nxfApply(t.id, t.name, rec.url); continue; }
      asked++;
      if (!(await nxfAsk(t.id, t.name))) NXQ.fail[k] = Date.now() + 5 * 60e3;   // nobody online has it: try again in 5 min
    }
  } catch (e) { console.warn('[nexus] file sync', e); }
  NXQ.running = false;
}
function nxfSyncSoon(ms) { clearTimeout(NXQ.timer); NXQ.timer = setTimeout(() => { try { nxfSync(); } catch (_) {} }, ms || 1500); }
setInterval(() => { if (document.visibilityState === 'visible' && S.user && S.wsOk) nxfSync(); }, 30000);
document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible') nxfSyncSoon(2000); });
