// ══════════════════════════════════
// WEBSOCKET
// ══════════════════════════════════
let _reconnectDelay = 1000;
let _reconnectTimer = null;
let _reconnectAttempts = 0;
function scheduleReconnect() {
  clearTimeout(_reconnectTimer);
  _reconnectAttempts++;
  // First 2 retries: immediate (handles Deno cold-start / deploy bounce)
  // After that: exponential backoff up to 30s
  const delay = _reconnectAttempts <= 2 ? 300 : Math.min(_reconnectDelay * 1.5, 30000);
  if (_reconnectAttempts > 2) _reconnectDelay = delay;
  // Only show the disconnected banner after the first fast retry fails
  if (_reconnectAttempts > 1) {
    setBanner(`Disconnected — reconnecting…`);
  }
  _reconnectTimer = setTimeout(connectWS, delay);
}
let _identifyTimer = null; // guards against server never replying to identify

function connectWS() {
  // Prevent overlapping reconnect attempts
  if (S.wsConnecting) return;
  S.wsConnecting = true;
  if (S.ws) { try { S.ws.onclose=null; S.ws.close(); } catch(e){} S.ws=null; }
  clearTimeout(_identifyTimer); _identifyTimer = null;
  // Always show 'connecting' state on every attempt — not just the first.
  // Previously only showed on attempt 0, so every retry left the dot grey forever.
  setWS('connecting');
  if (_reconnectAttempts === 0) setBanner('Connecting...');
  let ws;
  try { ws = new WebSocket(WS_URL); }
  catch(e) { S.wsConnecting=false; setWS('error'); setBanner('WebSocket not configured — add your Deno URL.'); return; }
  S.ws = ws;
  ws.onopen = () => {
    if (S.ws !== ws) { ws.close(); return; }
    _reconnectDelay = 1000;
    _reconnectAttempts = 0;
    S.wsConnecting = false; S.wsOk = true; setWS('connected'); hideBanner();
    dbg('✓ WS connected', 'ok');
    wsSend({type:'identify',user:S.user.name,tag:S.user.tag,color:S.user.color,pfp:S.user.pfp||null,token:S.token});
    dbg('→ identify sent', 'info');
    // Identify timeout: if server doesn't send 'identified' within 10s, the
    // connection is silently stuck (e.g. Deno cold-start not finishing). Force reconnect.
    _identifyTimer = setTimeout(() => {
      if (!S.wsOk || S.ws !== ws) return; // already reconnected or closed
      // Check if we actually got identified by seeing if servers loaded
      // A simpler proxy: if S.user is still not synced (no tag update), we may be stuck
      dbg('✕ identify timeout — no identified received, forcing reconnect', 'warn');
      try { ws.onclose = null; ws.close(); } catch(e) {}
      S.ws = null; S.wsConnecting = false; S.wsOk = false;
      setWS('disconnected');
      scheduleReconnect();
    }, 10000);
  };
  ws.onmessage = e => { try { handleIn(JSON.parse(e.data)); } catch(err) { console.error('[nexus] handleIn failed', err); dbg('✕ handler error: '+(err?.message||err),'err'); } };
  ws.onerror = (e) => { clearTimeout(_identifyTimer); S.wsConnecting=false; S.wsOk = false; setWS('error'); dbg('✕ WS error: ' + (e?.message||''), 'err'); };
  ws.onclose = () => {
    if (S.ws !== ws) return; // stale socket, ignore
    clearTimeout(_identifyTimer); _identifyTimer = null;
    S.wsConnecting = false; S.wsOk = false; S.ws = null;
    setWS('disconnected');
    scheduleReconnect();
  };
}

// ── Kick reconnect when tab becomes visible and WS is dead ──────────────────
document.addEventListener('visibilitychange', () => {
  if (!document.hidden && !S.wsOk && !S.wsConnecting && S.user) {
    clearTimeout(_reconnectTimer);
    _reconnectTimer = null;
    dbg('↺ tab visible + WS dead → reconnecting immediately', 'info');
    connectWS();
  }
});
window.addEventListener('focus', () => {
  if (!S.wsOk && !S.wsConnecting && S.user) {
    clearTimeout(_reconnectTimer);
    _reconnectTimer = null;
    _reconnectAttempts = 0;
    connectWS();
  }
});
window.addEventListener('online', () => {
  if (!S.wsOk && !S.wsConnecting && S.user) {
    clearTimeout(_reconnectTimer);
    _reconnectTimer = null;
    _reconnectAttempts = 0;
    connectWS();
  }
});
// ── Pending server creates — resent until relay ACKs ────────────────────────
// Stored in localStorage so they survive page reloads on flaky connections
const _pendingServerCreates = new Map();
// ── Debug overlay logger ─────────────────────────────────────────────────────
function dbg(msg, type='info') {
  if (S.user?.systemRole !== 'admin') return;
  const box = document.getElementById('dbg-lines');
  if (!box) return;
  const el = document.createElement('div');
  el.className = 'dbg-line ' + type;
  const t = new Date().toLocaleTimeString('en',{hour12:false,hour:'2-digit',minute:'2-digit',second:'2-digit'});
  el.textContent = t + ' ' + msg;
  box.appendChild(el);
  if (box.children.length > 60) box.removeChild(box.children[0]);
  box.scrollTop = box.scrollHeight;
  document.getElementById('dbg-overlay').classList.add('has-logs');
}

function _loadPending() {
  try {
    const saved = JSON.parse(localStorage.getItem('nx-pending-creates') || '{}');
    Object.entries(saved).forEach(([id, msg]) => _pendingServerCreates.set(id, msg));
  } catch {}
}
function _savePending() {
  try {
    const obj = {};
    _pendingServerCreates.forEach((msg, id) => obj[id] = msg);
    localStorage.setItem('nx-pending-creates', JSON.stringify(obj));
  } catch {}
}
_loadPending(); // restore on page load

const _pendingRetryCount = new Map(); // serverId → retry count
const _pendingLastSent = new Map();   // serverId → timestamp of last send
function _retryPending() {
  if (!_pendingServerCreates.size) return;
  if (S.ws?.readyState !== 1) return;
  const now = Date.now();
  _pendingServerCreates.forEach((msg, id) => {
    // Don't retry if we sent this less than 3 seconds ago — avoids double-fire
    // when _retryPending is called right after the initial wsSend (e.g. from identified)
    const lastSent = _pendingLastSent.get(id) || 0;
    if (now - lastSent < 3000) return;

    const count = (_pendingRetryCount.get(id) || 0) + 1;
    _pendingRetryCount.set(id, count);
    // FIX: Stop hammering after 10 retries — if we can't register it by then,
    // something is structurally wrong (ownership mismatch, etc). Clear it to stop the loop.
    if (count > 10) {
      console.warn('[nexus] giving up on server_create retry for', id, 'after', count, 'attempts');
      dbg('✕ gave up retrying server_create: ' + id.slice(0,8), 'err');
      _pendingServerCreates.delete(id);
      _pendingLastSent.delete(id);
      _savePending();
      return;
    }
    console.log('[nexus] retrying server_create for', msg.serverId, '(attempt', count, ')');
    dbg('↩ retrying server_create: ' + msg.serverId.slice(0,8) + ' (#' + count + ')', 'warn');
    _pendingLastSent.set(id, now);
    // FIX: use wsSend (readyState-guarded) instead of raw S.ws.send — prevents uncaught throw if socket closes between the outer guard and this line
    wsSend(msg);
  });
}
setInterval(_retryPending, 4000);
// FIX #9: wsSend queues non-ephemeral messages when offline so nothing is
// silently dropped during reconnects. Ephemeral events (typing, presence, etc.)
// are intentionally not queued — they're irrelevant by the time we reconnect.
const _EPHEMERAL_TYPES = new Set([
  'typing','get_history','get_members','get_server_list','get_server_info',
  'identify','join_channel','voice_join','voice_leave','voice_signal',
  'vcall_signal','status_update',
]);
const _wsQueue = [];
function wsSend(o) {
  if (S.ws?.readyState === 1) {
    S.ws.send(JSON.stringify({ ...o, token: S.token }));
    return true;
  }
  // Queue important messages; drop ephemeral ones
  if (!_EPHEMERAL_TYPES.has(o.type)) {
    _wsQueue.push(o);
    if (_wsQueue.length > 200) _wsQueue.shift(); // safety cap
  }
  return false;
}
function _flushWsQueue() {
  while (_wsQueue.length && S.ws?.readyState === 1) {
    const o = _wsQueue.shift();
    S.ws.send(JSON.stringify({ ...o, token: S.token }));
  }
}
