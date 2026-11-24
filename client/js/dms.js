// ══════════════════════════════════════════════
// DIRECT MESSAGES + GROUP CHATS
// ══════════════════════════════════════════════
// A conversation is identified by a KEY: the lowercase username for a 1:1 chat, "g:<id>" for a group chat.
// Everything (S.dmMessages, S.dmReads, curDM, ...) uses the same key, so names that differ only by case can
// never split one conversation into two. The server decides message order/time and what has been read.
let curDM = null;
let _dmContactsLoading = false;
const DMX = {
  typers: {},            // key -> { name: expiresAt }
  snapshot: {},          // key -> where I had read up to when I opened it (for the "New messages" line)
  info: (() => { try { return localStorage.getItem('nx-dm-info') !== '0'; } catch { return true; } })(),
  search: '', filter: '', typingSent: 0, openOnCreate: false,
};
S.dmReads = S.dmReads || {};            // key -> { personName: readUpToTs }
S.dmMyRead = S.dmMyRead || {};          // key -> ts
S.callStates = S.callStates || {};      // key -> { callId, active, participants }
S.userSettings = S.userSettings || { readReceipts: true, typingIndicators: true };

const dk = x => String(x == null ? '' : x).toLowerCase();
const isGroupKey = k => typeof k === 'string' && k.startsWith('g:');
const dmEntry = key => S.dms.find(d => d.key === key);
const dmIsMuted = d => { const m = d?.prefs?.muted; return m === true || (typeof m === 'number' && m > Date.now()); };
const dmSoundOn = () => { try { return localStorage.getItem('nx-dm-sound') !== '0'; } catch { return true; } };

function normDM(d) {
  d.kind = d.kind || (String(d.key || '').startsWith('g:') ? 'group' : 'dm');
  d.key = d.key || (d.kind === 'group' ? 'g:' + d.gid : dk(d.name));
  d.unread = typeof d.unread === 'number' ? d.unread : (d.unread ? 1 : 0);
  d.prefs = d.prefs || { muted: false, pinned: false, hidden: false };
  d.lastTs = d.lastTs || 0; d.last = d.last || '';
  if (d.kind === 'group') d.members = d.members || [];
  return d;
}
// after loading cached data: old versions keyed things by display name
function dmNormalizeState() {
  S.dms = (S.dms || []).map(normDM);
  const msgs = {};
  Object.entries(S.dmMessages || {}).forEach(([k, arr]) => { const nk = isGroupKey(k) ? k : dk(k); msgs[nk] = (msgs[nk] || []).concat(arr || []); });
  S.dmMessages = msgs;
}
function dmReset() {
  curDM = null; DMX.typers = {}; DMX.snapshot = {}; DMX.search = ''; DMX.filter = '';
  S.dmReads = {}; S.dmMyRead = {}; S.callStates = {}; S.userSettings = { readReceipts: true, typingIndicators: true };
}
function dmWire(key) { return isGroupKey(key) ? { gid: key.slice(2) } : { to: dmEntry(key)?.name || key }; }
function dmEnsure(name, pfp, color) {
  const key = dk(name); let d = dmEntry(key);
  if (!d) { d = normDM({ kind: 'dm', key, name, pfp: pfp || null, color: color || null }); S.dms.push(d); }
  else { if (pfp) d.pfp = pfp; if (color) d.color = color; if (name && name !== d.name) d.name = name; }
  return d;
}
function dmShortTime(ts) {
  if (!ts) return '';
  const d = new Date(ts), n = new Date();
  if (d.toDateString() === n.toDateString()) return d.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
  if (d.toDateString() === new Date(n - 864e5).toDateString()) return 'Yesterday';
  return d.toLocaleDateString([], { month: 'short', day: 'numeric' });
}
const dmClock = ts => ts ? new Date(ts).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' }) : '';
function dmDot(d) { return d.online ? (d.status || 'online') : 'off'; }
function dmAv(d, cls = '') {
  if (d.kind === 'group') { const gu = safeUrl(d.pfp || ''); return `<div class="mb-av dm-gav ${cls}" style="background:${gu ? 'transparent' : esc(d.color || '#6c63ff')}">${gu ? `<img src="${gu}" alt="">` : esc((d.name || '?')[0].toUpperCase())}</div>`; }
  const url = safeUrl(d.pfp || profileCache[d.name]?.pfp || '');
  const bg = url ? 'transparent' : (d.color || profileCache[d.name]?.color || COLORS[hash(d.name) % COLORS.length]);
  return `<div class="mb-av ${cls}" style="background:${bg}">${url ? `<img src="${url}" alt="">` : esc(d.name[0].toUpperCase())}<span class="dm-dot ${dmDot(d)}"></span></div>`;
}

// ── panel + rail ──
function toggleDM() { document.getElementById('dm-panel').classList.toggle('open'); if (document.getElementById('dm-panel').classList.contains('open')) { const f = document.getElementById('dm-filter'); if (f) f.value = DMX.filter; } }

function renderRailDMs() {
  const el = document.getElementById('rail-dms'); if (!el) return;
  const visible = S.dms.filter(d => !d.prefs.hidden || d.unread);
  const recent = [...visible].sort((a, b) => (b.unread > 0) - (a.unread > 0) || (b.lastTs || 0) - (a.lastTs || 0)).slice(0, 5);
  const sep = document.getElementById('rail-dms-sep'); if (sep) sep.style.display = recent.length ? '' : 'none';
  el.innerHTML = recent.map(d => {
    const url = safeUrl(d.pfp || (d.kind === 'group' ? '' : profileCache[d.name]?.pfp) || '');
    const bg = url ? 'transparent' : (d.kind === 'group' ? (d.color || '#6c63ff') : (d.color || COLORS[hash(d.name) % COLORS.length]));
    const av = url ? `<img src="${url}" style="width:100%;height:100%;object-fit:cover;border-radius:inherit">` : esc(d.name[0].toUpperCase());
    return `<div class="rail-dm-av${curDM === d.key ? ' act' : ''}${d.unread ? ' unread' : ''}" style="background:${bg}" data-key="${esc(d.key)}" onclick="openDMChat(this.dataset.key)" title="${esc(d.name)}">${av}${d.unread && !dmIsMuted(d) ? `<div class="rail-dm-badge">${d.unread > 9 ? '9+' : d.unread}</div>` : ''}</div>`;
  }).join('');
}

function dmItemHTML(d) {
  const muted = dmIsMuted(d), active = curDM === d.key;
  const pv = d.last || (d.kind === 'group' ? `${d.members.length} members` : 'No messages yet');
  return `<div class="dm-it${active ? ' active' : ''}${d.unread ? ' unread' : ''}${muted ? ' muted' : ''}" data-key="${esc(d.key)}" onclick="openDMChat(this.dataset.key)" oncontextmenu="showDmMenu(event,this.dataset.key)">
    ${dmAv(d)}
    <div class="dm-it-body"><div class="dm-nm">${esc(d.name)}${d.prefs.pinned ? '<span class="dm-ic" title="Pinned">📌</span>' : ''}${muted ? '<span class="dm-ic" title="Muted">🔕</span>' : ''}</div>
    <div class="dm-pv">${esc(pv)}</div></div>
    <div class="dm-meta"><div class="dm-time">${esc(dmShortTime(d.lastTs))}</div>${d.unread ? `<div class="dm-badge${muted ? ' mute' : ''}">${d.unread > 99 ? '99+' : d.unread}</div>` : ''}</div></div>`;
}

function renderDMs() {
  renderRailDMs();
  const homeEl = document.getElementById('home-recent-dms'); if (homeEl) homeEl.innerHTML = dmHomeRecent();
  const el = document.getElementById('dm-list'); if (!el) return;
  const q = dk(DMX.filter.trim());
  const list = S.dms.filter(d => !d.prefs.hidden || d.key === curDM)
    .filter(d => !q || dk(d.name).includes(q) || (d.kind === 'group' && d.members.some(m => dk(m.name).includes(q))));
  const byTime = (a, b) => (b.lastTs || 0) - (a.lastTs || 0);
  const pinned = list.filter(d => d.prefs.pinned).sort(byTime), rest = list.filter(d => !d.prefs.pinned).sort(byTime);
  let html = '';
  if (pinned.length) html += `<div class="dm-sec">Pinned</div>` + pinned.map(dmItemHTML).join('');
  if (rest.length) html += (pinned.length ? `<div class="dm-sec">Conversations</div>` : '') + rest.map(dmItemHTML).join('');
  if (!html) {
    html = q ? `<div class="dm-empty">No conversations match “${esc(DMX.filter)}”.</div>`
      : !S.wsOk ? `<div class="dm-empty">Connecting…</div>`
      : _dmContactsLoading ? `<div class="dm-empty"><div style="margin-bottom:8px;font-size:18px;animation:blink 1.2s infinite">💬</div>Restoring conversations…</div>`
      : `<div class="dm-empty">No conversations yet.<br>Message a friend, or start a group chat.</div>`;
  }
  el.innerHTML = html;
}
function dmFilterInput(v) { DMX.filter = v || ''; renderDMs(); }

// ── new conversation entry points ──
async function sendDMRequest() {
  const name = document.getElementById('dm-in').value.trim().split('#')[0];
  const errEl = document.getElementById('dm-req-err');
  errEl.style.display = 'none';
  if (!name) { errEl.textContent = 'Enter a username.'; errEl.style.display = 'block'; return; }
  if (dk(name) === dk(S.user.name)) { errEl.textContent = "You can't DM yourself."; errEl.style.display = 'block'; return; }
  const btn = document.querySelector('#ndm .auth-btn, #ndm .btn-p');
  const orig = btn?.textContent;
  if (btn) { btn.textContent = 'Checking…'; btn.disabled = true; }
  try {
    const exists = await checkUserExists(name);
    if (!exists) { errEl.textContent = `@${name} doesn't exist.`; errEl.style.display = 'block'; if (btn) { btn.textContent = orig; btn.disabled = false; } return; }
  } catch (e) { /* server unreachable: allow anyway */ }
  if (btn) { btn.textContent = orig; btn.disabled = false; }
  closeM('ndm'); document.getElementById('dm-in').value = '';
  openOrCreateDM(name, null);
}
function checkUserExists(username) {
  return new Promise((resolve) => {
    const ws = new WebSocket(WS_URL);
    ws.onopen = () => ws.send(JSON.stringify({ type: 'check_username', username: username.toLowerCase() }));
    ws.onmessage = (e) => { try { const m = JSON.parse(e.data); if (m.type === 'username_available') { resolve(!m.available); ws.close(); } } catch {} };
    ws.onerror = () => resolve(true);
    setTimeout(() => resolve(true), 5000);
  });
}
function openOrCreateDM(name, pfp) {
  const d = dmEnsure(name, pfp);
  if (d.prefs.hidden) { d.prefs.hidden = false; wsSend({ type: 'dm_prefs_set', conv: d.name, prefs: { hidden: false } }); }
  persist(); renderDMs(); openDMChat(d.key);
}
// older servers' request flow: DMs need no request any more
function recvDMRequest() {} function recvDMAccept() {} function recvDMDecline() {}

// ── opening / closing a conversation ──
function openDMChat(key) {
  key = isGroupKey(key) ? key : dk(key);
  let d = dmEntry(key);
  if (!d) {   // cache was cleared: stub it so the chat opens while history loads
    d = dmEnsure(key); wsSend({ type: 'fetch_dm_history', with: key });
  }
  if (curDM && curDM !== key) dmLeave();
  curDM = key; d.unread = 0; DMX.search = ''; DMX.snapshot[key] = S.dmMyRead[key];   // unread line uses what I'd read BEFORE opening
  if (d.prefs.hidden) { d.prefs.hidden = false; wsSend({ type: 'dm_prefs_set', conv: d.kind === 'group' ? key : d.name, prefs: { hidden: false } }); }
  hideAll();
  document.getElementById('dm-chat').classList.add('show');
  document.getElementById('ch-hd').style.display = 'none';
  document.getElementById('sidebar').style.display = 'none';
  document.getElementById('members').style.display = 'none';
  document.body.classList.add('in-dm');
  document.getElementById('dm-inp-wrap').style.display = '';
  document.getElementById('dm-pending-banner').style.display = 'none';
  const sb = document.getElementById('dm-search-bar'); if (sb) sb.style.display = 'none';
  const si = document.getElementById('dm-search-in'); if (si) si.value = '';
  document.getElementById('dm-ty-bar').innerHTML = '';
  if (d.kind === 'dm') requestProfileNow(d.name);
  renderDMHeader(); renderDMMessages(key); renderDMInfo(); renderDMCallBanner(); renderDMs();
  document.getElementById('dm-panel').classList.remove('open');
  wsSend(isGroupKey(key) ? { type: 'fetch_group_history', gid: key.slice(2) } : { type: 'fetch_dm_history', with: d.name });
  persist();
}
function dmLeave() { const k = curDM; if (k) delete DMX.snapshot[k]; }
function closeDMChat() {
  dmLeave(); curDM = null;
  document.getElementById('dm-chat').classList.remove('show');
  document.getElementById('sidebar').style.display = '';
  if (S.mbOpen) document.getElementById('members').style.display = '';
  document.body.classList.remove('in-dm');
  showWelcome(); renderDMs();
}

// ── header, info panel, banner ──
function dmSubtitle(d) {
  if (d.kind === 'group') { const on = d.members.filter(m => m.online).length; return `${d.members.length} members · ${on} online`; }
  if (d.online) return ({ online: 'Online', idle: 'Idle', dnd: 'Do Not Disturb' }[d.status] || 'Online');
  return d.lastSeen ? 'Offline · last seen ' + timeAgo(d.lastSeen) : 'Offline';
}
function renderDMHeader() {
  const d = dmEntry(curDM); if (!d) return;
  const av = document.getElementById('dm-chat-av');
  if (d.kind === 'group') { const gu = safeUrl(d.pfp || ''); av.style.background = gu ? 'transparent' : (d.color || '#6c63ff'); av.innerHTML = gu ? `<img src="${gu}" style="width:100%;height:100%;object-fit:cover">` : esc(d.name[0].toUpperCase()); }
  else {
    const url = safeUrl(d.pfp || profileCache[d.name]?.pfp || '');
    av.style.background = url ? 'transparent' : (d.color || COLORS[hash(d.name) % COLORS.length]);
    av.innerHTML = url ? `<img src="${url}" style="width:100%;height:100%;object-fit:cover">` : esc(d.name[0].toUpperCase());
  }
  document.getElementById('dm-chat-name').textContent = d.name;
  const sub = document.getElementById('dm-chat-sub'); if (sub) { sub.textContent = dmSubtitle(d); sub.className = 'dm-chat-sub' + (d.kind === 'dm' && d.online ? ' on' : ''); }
  document.getElementById('dm-msg-in').placeholder = d.kind === 'group' ? `Message ${d.name}` : `Message @${d.name}`;
  const info = document.getElementById('dm-info-btn'); if (info) info.classList.toggle('on', DMX.info);
  const call = document.getElementById('dm-call-btn'); if (call) call.title = d.kind === 'group' ? 'Start a group call' : 'Start a voice call';
}
function toggleDMInfo(force) {
  DMX.info = typeof force === 'boolean' ? force : !DMX.info;
  try { localStorage.setItem('nx-dm-info', DMX.info ? '1' : '0'); } catch {}
  renderDMHeader(); renderDMInfo();
}
function dmMutualServers(name) {
  const k = dk(name), out = [];
  S.servers.forEach(sv => { if ((S.members[sv.id] || []).some(m => dk(m.name) === k)) out.push(sv); });
  return out;
}
function renderDMInfo() {
  const el = document.getElementById('dm-info'); if (!el) return;
  const d = dmEntry(curDM);
  if (!d || !DMX.info) { el.style.display = 'none'; return; }
  el.style.display = '';
  const muted = dmIsMuted(d);
  const toggles = `<div class="di-sec">Settings</div>
    <label class="di-row"><span>Pin conversation</span><input type="checkbox" ${d.prefs.pinned ? 'checked' : ''} onchange="dmSetPref('${esc(d.key)}',{pinned:this.checked})"></label>
    <label class="di-row"><span>Mute notifications</span><input type="checkbox" ${muted ? 'checked' : ''} onchange="dmSetPref('${esc(d.key)}',{muted:this.checked})"></label>`;
  if (d.kind === 'dm') {
    const p = profileCache[d.name] || {};
    const url = safeUrl(d.pfp || p.pfp || '');
    const isF = isFriend(d.name);
    const mutual = dmMutualServers(d.name);
    el.innerHTML = `<div class="di-top" style="background:${esc(d.color || p.color || COLORS[hash(d.name) % COLORS.length])}"></div>
      <div class="di-av" style="background:${url ? 'transparent' : esc(d.color || COLORS[hash(d.name) % COLORS.length])}">${url ? `<img src="${url}" alt="">` : esc(d.name[0].toUpperCase())}<span class="dm-dot lg ${dmDot(d)}"></span></div>
      <div class="di-name">${esc(d.name)}</div>
      <div class="di-status ${d.online ? 'on' : ''}">${esc(dmSubtitle(d))}</div>
      ${p.bio ? `<div class="di-sec">About me</div><div class="di-text">${esc(p.bio)}</div>` : ''}
      <div class="di-sec">Member since</div><div class="di-text">${p.createdAt ? esc(new Date(p.createdAt).toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' })) : 'Nexus Member'}</div>
      <div class="di-actions">
        <button class="btn-g" onclick="dmStartCall()">📞 Call</button>
        <button class="btn-g" onclick="openProfilePage(dmEntry(curDM).name)">👤 Profile</button>
        ${isF ? '' : `<button class="btn-p" onclick="sendFriendReqTo(dmEntry(curDM).name)">＋ Add Friend</button>`}
      </div>
      ${mutual.length ? `<div class="di-sec">Mutual servers — ${mutual.length}</div>${mutual.slice(0, 6).map(sv => `<div class="di-srv"><div class="di-srv-ic">${esc(sv.name[0].toUpperCase())}</div><span>${esc(sv.name)}</span></div>`).join('')}` : ''}
      ${toggles}`;
  } else {
    const me = dk(S.user.name), isOwner = dk(d.owner) === me, gu = safeUrl(d.pfp || '');
    el.innerHTML = `<div class="di-top" style="background:${esc(d.color || '#6c63ff')}"></div>
      <div class="di-av group" title="Change group picture" onclick="dmPickGroupPfp()" style="cursor:pointer;background:${gu ? 'transparent' : esc(d.color || '#6c63ff')}">${gu ? `<img src="${gu}" alt="">` : esc(d.name[0].toUpperCase())}</div>
      <div class="di-name">${esc(d.name)} <button class="di-edit" title="Rename group" onclick="dmRenameGroup()">✎</button></div>
      <div class="di-status">${d.members.length} members</div>
      <div class="di-actions">
        <button class="btn-g" onclick="dmStartCall()">📞 Call</button>
        <button class="btn-g" onclick="openNewGroup('add','${esc(d.key)}')">＋ Add people</button>
        <button class="btn-g" onclick="dmPickGroupPfp()">🖼️ Picture</button>${gu ? `<button class="btn-g" onclick="dmClearGroupPfp()">Remove picture</button>` : ''}
      </div>
      <div class="di-sec">Members — ${d.members.length}</div>
      ${[...d.members].sort((a, b) => (dk(b.name) === dk(d.owner)) - (dk(a.name) === dk(d.owner)) || b.online - a.online || a.name.localeCompare(b.name)).map(m => {
        const url = safeUrl(m.pfp || profileCache[m.name]?.pfp || ''); const you = dk(m.name) === me;
        return `<div class="di-mem" data-name="${esc(m.name)}" onclick="openProfilePage(this.dataset.name)">
          <div class="mb-av" style="background:${url ? 'transparent' : esc(m.color || COLORS[hash(m.name) % COLORS.length])}">${url ? `<img src="${url}" alt="">` : esc(m.name[0].toUpperCase())}<span class="dm-dot ${m.online ? (m.status || 'online') : 'off'}"></span></div>
          <div class="di-mem-n">${esc(m.name)}${you ? ' <span class="di-tag">you</span>' : ''}${dk(m.name) === dk(d.owner) ? ' <span class="di-tag own">owner</span>' : ''}</div>
          ${isOwner && !you ? `<button class="fv-act danger di-rm" title="Remove from group" onclick="event.stopPropagation();dmRemoveMember(this.closest('.di-mem').dataset.name)">${FV_ICON.x}</button>` : ''}</div>`; }).join('')}
      ${toggles}
      <div class="di-actions"><button class="btn-g danger-btn" onclick="dmLeaveGroup()">Leave group</button></div>`;
  }
}
// a call is going on in this conversation and I'm not in it
function renderDMCallBanner() {
  const el = document.getElementById('dm-call-banner'); if (!el) return;
  const st = S.callStates[curDM];
  const mine = typeof vcallId !== 'undefined' && vcallId && st && st.callId === vcallId;
  if (!curDM || !st || !st.active || mine) { el.style.display = 'none'; el.innerHTML = ''; return; }
  const names = (st.participants || []).slice(0, 3).map(esc).join(', ');
  el.style.display = '';
  el.innerHTML = `<span class="dcb-ic">📞</span><span class="dcb-t"><b>Call in progress</b>${names ? ' · ' + names : ''}</span><button class="btn-p dcb-join" onclick="dmJoinCall()">Join call</button>`;
}
function dmStartCall() {
  const d = dmEntry(curDM); if (!d) return;
  if (d.kind === 'group') startGroupCall(d.key.slice(2)); else startVoiceCall(d.name);
}
function dmJoinCall() { const st = S.callStates[curDM]; if (st?.callId) joinVoiceCall(st.callId, curDM); }

// ── message list ──
function sysHTML(m) {
  const icons = { created: '✨', added: '➕', removed: '🚫', left: '👋', renamed: '✏️' };
  const icon = m.system === 'call' ? (m.kind === 'ended' ? '📞' : '📵') : (icons[m.kind] || '•');
  const back = m.system === 'call' && m.kind !== 'ended' && dk(m.from) !== dk(S.user.name) ? `<button class="dm-sys-btn" onclick="dmStartCall()">Call back</button>` : '';
  return `<div class="dm-sys ${m.system === 'call' ? 'call ' + esc(m.kind) : ''}" data-id="${esc(m.id)}"><span class="dm-sys-ic">${icon}</span><span class="dm-sys-tx">${esc(m.text)}</span><span class="dm-sys-t">${esc(dmClock(m.ts))}</span>${back}</div>`;
}
function dmReadsMap(key) { const o = {}; Object.entries(S.dmReads[key] || {}).forEach(([n, t]) => { o[dk(n)] = t; }); return o; }
function seenHTML(key, last) {
  if (S.userSettings.readReceipts === false) return '';   // if I hide mine, I don't see theirs either
  if (last._pending) return `<div class="dm-seen dim">Sending…</div>`;
  const d = dmEntry(key), reads = dmReadsMap(key);
  if (d.kind === 'dm') {
    const t = reads[dk(d.name)];
    return t && t >= last.ts ? `<div class="dm-seen" title="Seen ${esc(dmClock(t))}">Seen</div>` : `<div class="dm-seen dim">Delivered</div>`;
  }
  const seen = d.members.filter(m => dk(m.name) !== dk(S.user.name) && (reads[dk(m.name)] || 0) >= last.ts).map(m => m.name);
  if (!seen.length) return `<div class="dm-seen dim">Delivered</div>`;
  return `<div class="dm-seen" title="${esc(seen.join(', '))}">Seen by ${esc(seen.slice(0, 3).join(', '))}${seen.length > 3 ? ` +${seen.length - 3}` : ''}</div>`;
}
function renderDMMessages(key) {
  if (key !== curDM) return;
  const el = document.getElementById('dm-msgs'), d = dmEntry(key); if (!el || !d) return;
  const all = S.dmMessages[key] || [];
  const q = DMX.search.trim().toLowerCase();
  const msgs = q ? all.filter(m => !m.system && String(m.text || '').toLowerCase().includes(q)) : all;
  const cnt = document.getElementById('dm-search-count'); if (cnt) cnt.textContent = q ? `${msgs.length} result${msgs.length === 1 ? '' : 's'}` : '';
  const nearBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 160 || !el.childElementCount;
  if (!msgs.length) {
    el.innerHTML = q ? `<div class="dm-start"><div class="em">🔍</div><div class="t">No messages found</div></div>`
      : `<div class="dm-start"><div class="em">${d.kind === 'group' ? '👥' : '👋'}</div><div class="t">${d.kind === 'group' ? `Welcome to ${esc(d.name)}` : `This is the beginning of your DM with ${esc(d.name)}`}</div></div>`;
    return;
  }
  const snap = DMX.snapshot[key];
  let lastOwn = -1; for (let i = msgs.length - 1; i >= 0; i--) { if (!msgs[i].system && msgs[i].author === S.user.name) { lastOwn = i; break; } }
  let la = '', lt = 0, divider = false; const parts = [];
  msgs.forEach((m, i) => {
    if (m.system) { parts.push(sysHTML(m)); la = ''; return; }
    if (!q && !divider && snap != null && m.ts > snap && m.author !== S.user.name) { parts.push('<div class="dm-newdiv"><span>New messages</span></div>'); divider = true; la = ''; }
    parts.push(buildMsg(m, m.author === la && (m.ts - lt) < 300000)); la = m.author; lt = m.ts;
    if (i === lastOwn && !q) parts.push(seenHTML(key, m));
  });
  el.innerHTML = parts.join('');
  if (nearBottom) el.scrollTop = el.scrollHeight;
}
function dmToggleSearch() {
  const bar = document.getElementById('dm-search-bar'); if (!bar) return;
  const show = bar.style.display === 'none';
  bar.style.display = show ? '' : 'none';
  if (show) document.getElementById('dm-search-in').focus(); else { DMX.search = ''; document.getElementById('dm-search-in').value = ''; renderDMMessages(curDM); }
}
function dmSearchInput(v) { DMX.search = v || ''; renderDMMessages(curDM); }

// ── reading ──
function dmMarkRead(key) {
  key = key || curDM; if (!key || key !== curDM) return;
  if (document.hidden || (document.hasFocus && !document.hasFocus())) return;   // only when I can actually see it
  const d = dmEntry(key); if (!d) return;
  const msgs = (S.dmMessages[key] || []).filter(m => !m._pending && m.ts);
  const newest = msgs.length ? Math.max(...msgs.map(m => m.ts)) : 0;
  if (d.unread) { d.unread = 0; renderDMs(); }
  if (newest && newest > (S.dmMyRead[key] || 0)) {
    S.dmMyRead[key] = newest;
    wsSend(isGroupKey(key) ? { type: 'group_read', gid: key.slice(2), upTo: newest } : { type: 'dm_read', with: d.name, upTo: newest });
  }
}
window.addEventListener('focus', () => { if (curDM) dmMarkRead(curDM); });
document.addEventListener('visibilitychange', () => { if (!document.hidden && curDM) dmMarkRead(curDM); });

// ── typing ──
function onDMType() {
  const inp = document.getElementById('dm-msg-in'); if (!inp) return;
  inp.style.height = 'auto'; inp.style.height = Math.min(inp.scrollHeight, 150) + 'px';
  const btn = document.getElementById('dm-snd-btn'); if (btn) btn.classList.toggle('on', inp.value.trim().length > 0);
  if (curDM && inp.value && S.userSettings.typingIndicators !== false && Date.now() - DMX.typingSent > 3000) {
    DMX.typingSent = Date.now(); wsSend({ type: isGroupKey(curDM) ? 'group_typing' : 'dm_typing', ...dmWire(curDM) });
  }
}
function dmTyping(key, who) {
  if (!key || dk(who) === dk(S.user.name)) return;
  (DMX.typers[key] = DMX.typers[key] || {})[who] = Date.now() + 3500;
  renderDMTyping(key);
  setTimeout(() => renderDMTyping(key), 3600);
}
function renderDMTyping(key) {
  if (key !== curDM) return;
  const now = Date.now(), t = DMX.typers[key] || {};
  const names = Object.keys(t).filter(n => t[n] > now);
  const bar = document.getElementById('dm-ty-bar'); if (!bar) return;
  if (!names.length) { bar.innerHTML = ''; return; }
  const txt = names.length === 1 ? `${esc(names[0])} is typing…` : names.length === 2 ? `${esc(names[0])} and ${esc(names[1])} are typing…` : 'Several people are typing…';
  bar.innerHTML = `<div class="ty-dots"><div class="ty-dot"></div><div class="ty-dot"></div><div class="ty-dot"></div></div><span>${txt}</span>`;
}
function showDMTyping(who) { dmTyping(dk(who), who); }   // older handler name

// ── sending ──
function sendDMMsg() {
  const inp = document.getElementById('dm-msg-in');
  const text = inp.value.trim();
  if (editingMsgId) { if (text) commitEdit(text); else cancelEdit(); inp.value = ''; inp.style.height = 'auto'; const b = document.getElementById('dm-snd-btn'); if (b) b.classList.remove('on'); return; }
  if (!text || !curDM) return;
  const d = dmEntry(curDM); if (!d) return;
  const msg = { id: uid(), author: S.user.name, authorColor: S.user.color, text, ts: Date.now(), reactions: [], attachments: [], _pending: true };
  (S.dmMessages[curDM] = S.dmMessages[curDM] || []).push(msg);
  d.last = text; d.lastTs = msg.ts; d.unread = 0; d.prefs.hidden = false;
  persist(); renderDMMessages(curDM); renderDMs();
  wsSend({ type: isGroupKey(curDM) ? 'group_msg' : 'dm', ...dmWire(curDM), id: msg.id, text, ts: msg.ts });   // server first, then the screen has already updated
  inp.value = ''; inp.style.height = 'auto';
  const b = document.getElementById('dm-snd-btn'); if (b) b.classList.remove('on');
}
// the server's timestamp is the real one (read receipts compare against it)
function onDMAck(msg) {
  const key = msg.gid ? 'g:' + msg.gid : dk(msg.with);
  const m = (S.dmMessages[key] || []).find(x => x.id === msg.id); if (!m) return;
  m.ts = msg.ts; delete m._pending;
  const d = dmEntry(key); if (d && msg.ts > d.lastTs) d.lastTs = msg.ts;
  persist(); renderDMMessages(key); renderDMs();
}
function onDMSync(msg) {   // I sent this from another tab/device
  const key = msg.gid ? 'g:' + msg.gid : dk(msg.with);
  const d = msg.gid ? dmEntry(key) : dmEnsure(msg.with);
  if (!d || !msg.message) return;
  const arr = (S.dmMessages[key] = S.dmMessages[key] || []);
  if (!arr.some(x => x.id === msg.message.id)) arr.push(msg.message);
  d.last = msg.message.text || '[attachment]'; d.lastTs = msg.message.ts;
  persist(); renderDMMessages(key); renderDMs();
}

// ── receiving ──
function dmNotify(d, m, isNew) {
  if (dmIsMuted(d) || S.user.status === 'dnd') return;
  if (dmSoundOn()) playSound('dm');
  const who = m.author || d.name;
  if (d.kind === 'dm' && isNew) showDMPopup(who, m.authorColor, safeUrl(profileCache[who]?.pfp || d.pfp || ''), m.text || '[attachment]');
  else toast(d.kind === 'group' ? `💬 ${who} in ${d.name}` : '💬 DM from ' + who);
  addNotif('💬', d.kind === 'group' ? `${who} in ${d.name}` : 'DM from ' + who, () => { renderDMs(); openDMChat(d.key); });
}
function dmIncoming(key, d, m) {
  const arr = (S.dmMessages[key] = S.dmMessages[key] || []);
  if (arr.some(x => x.id === m.id)) return false;       // outbox replays / echoes
  arr.push(m);
  d.last = m.text || '[attachment]'; d.lastTs = m.ts || Date.now(); d.prefs.hidden = false;
  const viewing = curDM === key && !document.hidden && (!document.hasFocus || document.hasFocus());
  if (curDM !== key || !viewing) d.unread = (d.unread || 0) + 1;
  persist(); renderDMs();
  if (curDM === key) { renderDMMessages(key); if (viewing) dmMarkRead(key); }
  if (S.dmMyRead[key] === undefined) S.dmMyRead[key] = 0;
  const t = DMX.typers[key]; if (t) { delete t[m.author]; renderDMTyping(key); }
  return true;
}
function recvDM(msg) {
  const from = msg.from || msg.author; if (!from) return;
  const key = dk(from), isNew = !dmEntry(key);
  const d = dmEnsure(from, null, msg.authorColor);
  if (msg.authorPfp) { (profileCache[from] = profileCache[from] || { name: from }).pfp = msg.authorPfp; d.pfp = msg.authorPfp; }
  const m = { id: msg.id || uid(), author: from, authorColor: msg.authorColor, text: msg.text, ts: msg.ts || Date.now(), reactions: msg.reactions || [], attachments: msg.attachments || [], replyTo: msg.replyTo };
  if (dmIncoming(key, d, m) && curDM !== key) dmNotify(d, m, isNew);
  else if (curDM === key && document.hidden) dmNotify(d, m, false);
}
function recvGroupMsg(msg) {
  const key = 'g:' + msg.gid, d = dmEntry(key); if (!d || !msg.message) return;
  const m = { ...msg.message, reactions: msg.message.reactions || [], attachments: msg.message.attachments || [] };
  if (dmIncoming(key, d, m) && (curDM !== key || document.hidden)) dmNotify(d, m, false);
}
function recvDMSystem(msg) {
  const key = msg.gid ? 'g:' + msg.gid : dk(msg.with);
  const d = msg.gid ? dmEntry(key) : dmEnsure(msg.with); if (!d || !msg.message) return;
  const arr = (S.dmMessages[key] = S.dmMessages[key] || []);
  if (arr.some(x => x.id === msg.message.id)) return;
  arr.push(msg.message);
  if (msg.message.text) d.last = msg.message.text;
  d.lastTs = msg.message.ts || Date.now(); d.prefs.hidden = false;
  const missed = msg.message.system === 'call' && (msg.message.kind === 'missed' || msg.message.kind === 'cancelled') && dk(msg.message.from) !== dk(S.user.name);
  if (missed && curDM !== key) { d.unread = (d.unread || 0) + 1; if (!dmIsMuted(d)) addNotif('📵', msg.message.text, () => openDMChat(key)); }
  persist(); renderDMs(); if (curDM === key) { renderDMMessages(key); dmMarkRead(key); }
}
function recvDMHistory(msg) {
  const key = msg.gid ? 'g:' + msg.gid : dk(msg.with);
  const d = msg.gid ? dmEntry(key) : dmEnsure(msg.with); if (!d) return;
  const server = msg.messages || [];
  const ids = new Set(server.map(m => m.id));
  const lastTs = server.length ? Math.max(...server.map(m => m.ts || 0)) : 0;
  // keep what I've sent that the server hasn't confirmed yet
  const pending = (S.dmMessages[key] || []).filter(m => m._pending && !ids.has(m.id));
  S.dmMessages[key] = [...server, ...pending].sort((a, b) => (a.ts || 0) - (b.ts || 0));
  if (msg.myRead !== undefined) { S.dmMyRead[key] = msg.myRead; if (curDM === key && DMX.snapshot[key] == null) DMX.snapshot[key] = msg.myRead; }
  S.dmReads[key] = msg.reads || {};
  const real = server.filter(m => !m.system || m.kind === 'missed');
  if (server.length) { const lm = server[server.length - 1]; d.last = lm.text || d.last; d.lastTs = Math.max(d.lastTs || 0, lastTs); }
  persist();
  if (curDM === key) { renderDMMessages(key); dmMarkRead(key); } renderDMs();
}
function recvDMReadUpdate(msg) {
  const key = msg.gid ? 'g:' + msg.gid : dk(msg.with || msg.by);
  const r = (S.dmReads[key] = S.dmReads[key] || {});
  r[msg.by] = Math.max(r[msg.by] || 0, msg.upTo || 0);
  if (curDM === key) renderDMMessages(key);
}
function recvDMReadSelf(msg) {   // I read it on another device
  const key = msg.gid ? 'g:' + msg.gid : dk(msg.with);
  S.dmMyRead[key] = Math.max(S.dmMyRead[key] || 0, msg.upTo || 0);
  const d = dmEntry(key); if (d && d.unread) { d.unread = 0; renderDMs(); persist(); }
}
function recvDMPrefs(msg) {
  const key = isGroupKey(msg.conv) ? msg.conv : dk(msg.conv), d = dmEntry(key); if (!d) return;
  d.prefs = { muted: msg.prefs?.muted || false, pinned: !!msg.prefs?.pinned, hidden: !!msg.prefs?.hidden };
  persist(); renderDMs(); if (curDM === key) renderDMInfo();
}
function recvDMCleared(msg) {
  const key = isGroupKey(msg.conv) ? msg.conv : dk(msg.conv), d = dmEntry(key);
  S.dmMessages[key] = []; if (d) { d.last = ''; d.unread = 0; }
  persist(); renderDMs(); if (curDM === key) renderDMMessages(key);
}
function recvUserSettings(msg) { S.userSettings = { ...S.userSettings, ...(msg.settings || {}) }; if (curDM) renderDMMessages(curDM); const m = document.getElementById('dmp-read'); if (m) dmPrivacySync(); }

function recvDMContacts(msg) {
  _dmContactsLoading = false;
  if (msg.settings) S.userSettings = { ...S.userSettings, ...msg.settings };
  (msg.contacts || []).forEach(c => {
    (profileCache[c.name] = profileCache[c.name] || { name: c.name }); if (c.pfp !== undefined) profileCache[c.name].pfp = c.pfp || null;
    const d = dmEnsure(c.name, c.pfp, c.color);
    d.last = c.last || d.last; d.lastTs = Math.max(d.lastTs || 0, c.lastTs || 0);
    d.unread = c.unread || 0; d.online = !!c.online; d.status = c.status;
    d.prefs = { muted: c.prefs?.muted || false, pinned: !!c.prefs?.pinned, hidden: !!c.prefs?.hidden };
  });
  const serverGroups = new Set();
  (msg.groups || []).forEach(g => {
    const key = 'g:' + g.id; serverGroups.add(key);
    const d = dmEntry(key) || (S.dms.push(normDM({ kind: 'group', key, gid: g.id, name: g.name })), dmEntry(key));
    Object.assign(d, { name: g.name, color: g.color, owner: g.owner, members: g.members, pfp: g.pfp || null, last: g.last || d.last, lastTs: Math.max(d.lastTs || 0, g.lastTs || 0), unread: g.unread || 0, prefs: { muted: g.prefs?.muted || false, pinned: !!g.prefs?.pinned, hidden: !!g.prefs?.hidden } });
    g.members.forEach(m => { (profileCache[m.name] = profileCache[m.name] || { name: m.name }); if (m.pfp !== undefined) profileCache[m.name].pfp = m.pfp; if (m.color) profileCache[m.name].color = m.color; });
  });
  S.dms = S.dms.filter(d => d.kind !== 'group' || serverGroups.has(d.key));   // groups I'm no longer in
  persist(); renderDMs(); if (curDM) { renderDMHeader(); renderDMInfo(); }
}
// ── presence / profile updates reach conversations too ──
function dmPresence(name, p) {
  const k = dk(name); let touched = false;
  S.dms.forEach(d => {
    if (d.kind === 'dm' && d.key === k) { d.online = !!p.online; d.status = p.online ? p.status : undefined; if (p.lastSeen !== undefined) d.lastSeen = p.lastSeen; touched = true; }
    else if (d.kind === 'group') d.members.forEach(m => { if (dk(m.name) === k) { m.online = !!p.online; m.status = p.online ? p.status : undefined; touched = true; } });
  });
  if (touched) { renderDMs(); if (curDM) { renderDMHeader(); renderDMInfo(); } }
  return touched;
}
function dmProfilesUpdated() { if (curDM) { renderDMHeader(); renderDMInfo(); } renderDMs(); }

// ── groups ──
function groupApply(g) {
  const key = 'g:' + g.id;
  let d = dmEntry(key);
  if (!d) { d = normDM({ kind: 'group', key, gid: g.id, name: g.name }); S.dms.push(d); }
  Object.assign(d, { name: g.name, color: g.color, pfp: g.pfp || null, owner: g.owner, members: g.members });
  g.members.forEach(m => { (profileCache[m.name] = profileCache[m.name] || { name: m.name }); if (m.pfp !== undefined) profileCache[m.name].pfp = m.pfp; if (m.color) profileCache[m.name].color = m.color; });
  return d;
}
function recvGroupCreated(msg) {
  const g = msg.group; if (!g) return;
  const known = !!dmEntry('g:' + g.id), d = groupApply(g);
  persist(); renderDMs();
  if (DMX.openOnCreate && dk(g.owner) === dk(S.user.name)) { DMX.openOnCreate = false; openDMChat(d.key); toast('👥 Group created'); }
  else if (!known) { toast(`👥 You were added to “${g.name}”`); addNotif('👥', `You were added to ${g.name}`, () => openDMChat(d.key)); }
}
function recvGroupUpdated(msg) { const g = msg.group; if (!g) return; groupApply(g); persist(); renderDMs(); if (curDM === 'g:' + g.id) { renderDMHeader(); renderDMInfo(); } }
function recvGroupRemoved(msg) {
  const key = 'g:' + msg.gid, d = dmEntry(key); if (!d) return;
  S.dms = S.dms.filter(x => x.key !== key); delete S.dmMessages[key];
  if (curDM === key) closeDMChat();
  persist(); renderDMs();
  if (msg.reason === 'removed') toast(`You were removed from “${d.name}”`);
}
function recvGroupError(msg) { const e = document.getElementById('ng-err'); if (e && document.getElementById('ngroup').classList.contains('open')) { e.textContent = msg.message; e.style.display = 'block'; } else toast('⚠️ ' + msg.message); }

// the "pick people" dialog is shared: create a group / add people to one / invite people to a call
const NG = { mode: 'create', key: null, sel: new Set(), q: '' };
function ngCandidates() {
  let list = S.friends.map(f => ({ name: f.name, pfp: f.pfp, color: f.color, online: f.online === true }));
  if (NG.mode === 'add') { const d = dmEntry(NG.key); const have = new Set((d?.members || []).map(m => dk(m.name))); list = list.filter(f => !have.has(dk(f.name))); }
  if (NG.mode === 'call') {
    const inCall = new Set([...(typeof vcallParticipants !== 'undefined' ? vcallParticipants : []), ...(typeof vcallRinging !== 'undefined' ? vcallRinging.keys() : [])].map(dk)); inCall.add(dk(S.user.name));
    const extra = (dmEntry(curDM)?.members || []).filter(m => !list.some(f => dk(f.name) === dk(m.name))).map(m => ({ name: m.name, pfp: m.pfp, color: m.color, online: m.online }));
    list = list.concat(extra).filter(f => !inCall.has(dk(f.name)));
  }
  return list.sort((a, b) => b.online - a.online || a.name.localeCompare(b.name));
}
function openNewGroup(mode = 'create', key = null) {
  NG.mode = mode; NG.key = key; NG.sel = new Set(); NG.q = '';
  document.getElementById('ng-title').textContent = mode === 'add' ? 'Add people' : mode === 'call' ? 'Invite to call' : 'Create a group chat';
  document.getElementById('ng-sub').textContent = mode === 'create' ? 'Pick friends to chat with (up to 9).' : mode === 'add' ? 'Pick friends to add to this group.' : 'Pick people to ring.';
  document.getElementById('ng-name-row').style.display = mode === 'create' ? '' : 'none';
  document.getElementById('ng-name').value = ''; document.getElementById('ng-search').value = '';
  document.getElementById('ng-err').style.display = 'none';
  document.getElementById('ng-submit').textContent = mode === 'create' ? 'Create group' : mode === 'add' ? 'Add' : 'Invite';
  ngRender(); openM('ngroup');
}
function ngRender() {
  const q = dk(NG.q), list = ngCandidates().filter(f => !q || dk(f.name).includes(q));
  const el = document.getElementById('ng-list');
  el.innerHTML = list.length ? list.map(f => {
    const url = safeUrl(f.pfp || profileCache[f.name]?.pfp || '');
    return `<label class="ng-row"><input type="checkbox" data-name="${esc(f.name)}" ${NG.sel.has(f.name) ? 'checked' : ''} onchange="ngToggle(this)">
      <div class="mb-av" style="background:${url ? 'transparent' : esc(f.color || COLORS[hash(f.name) % COLORS.length])}">${url ? `<img src="${url}" alt="">` : esc(f.name[0].toUpperCase())}<span class="dm-dot ${f.online ? 'online' : 'off'}"></span></div>
      <span class="ng-nm">${esc(f.name)}</span><span class="ng-st">${f.online ? 'Online' : 'Offline'}</span></label>`; }).join('')
    : `<div class="dm-empty">${S.friends.length ? 'Nobody to add.' : 'Add some friends first. Group chats are for friends.'}</div>`;
  const max = NG.mode === 'create' ? 9 : NG.mode === 'add' ? Math.max(0, 10 - (dmEntry(NG.key)?.members.length || 0)) : 4;
  document.getElementById('ng-count').textContent = `${NG.sel.size} selected · up to ${max}`;
  document.getElementById('ng-submit').disabled = NG.sel.size === 0;
}
function ngToggle(cb) {
  const max = NG.mode === 'create' ? 9 : NG.mode === 'add' ? Math.max(0, 10 - (dmEntry(NG.key)?.members.length || 0)) : 4;
  if (cb.checked) { if (NG.sel.size >= max) { cb.checked = false; toast(`That's the limit (${max})`); return; } NG.sel.add(cb.dataset.name); } else NG.sel.delete(cb.dataset.name);
  ngRender();
}
function ngSearch(v) { NG.q = v || ''; ngRender(); }
function ngSubmit() {
  const names = [...NG.sel]; if (!names.length) return;
  document.getElementById('ng-err').style.display = 'none';
  if (NG.mode === 'create') { DMX.openOnCreate = true; wsSend({ type: 'group_create', name: document.getElementById('ng-name').value.trim(), members: names }); }
  else if (NG.mode === 'add') wsSend({ type: 'group_add', gid: NG.key.slice(2), members: names });
  else vcallInvitePeople(names);
  closeM('ngroup');
}
// group picture: pick a file → centre-crop to 96×96 JPEG (kept under the server's limit) → server
function dmPickGroupPfp() {
  const d = dmEntry(curDM); if (!d || d.kind !== 'group') return;
  let inp = document.getElementById('gpfp-file');
  if (!inp) { inp = document.createElement('input'); inp.type = 'file'; inp.accept = 'image/*'; inp.id = 'gpfp-file'; inp.style.display = 'none'; inp.onchange = dmGroupPfpChosen; document.body.appendChild(inp); }
  inp.value = ''; inp.click();
}
async function dmGroupPfpChosen(e) {
  const f = e.target.files && e.target.files[0], d = dmEntry(curDM); if (!f || !d || d.kind !== 'group') return;
  if (!/^image\//.test(f.type)) { toast('That is not an image', 'err'); return; }
  try {
    const url = URL.createObjectURL(f);
    const img = await new Promise((res, rej) => { const i = new Image(); i.onload = () => res(i); i.onerror = rej; i.src = url; });
    URL.revokeObjectURL(url);
    const size = 96, c = document.createElement('canvas'); c.width = c.height = size;
    const s = Math.min(img.width, img.height); c.getContext('2d').drawImage(img, (img.width - s) / 2, (img.height - s) / 2, s, s, 0, 0, size, size);
    let q = 0.82, data = c.toDataURL('image/jpeg', q);
    while (data.length > 22000 && q > 0.3) { q -= 0.1; data = c.toDataURL('image/jpeg', q); }
    if (data.length > 22000) { toast('That picture is too detailed — try another one', 'err'); return; }
    wsSend({ type: 'group_set_pfp', gid: d.key.slice(2), pfp: data });
  } catch (err) { toast('Could not read that image', 'err'); }
}
function dmClearGroupPfp() { const d = dmEntry(curDM); if (d && d.kind === 'group') wsSend({ type: 'group_set_pfp', gid: d.key.slice(2), pfp: null }); }
function dmRenameGroup() {
  const d = dmEntry(curDM); if (!d || d.kind !== 'group') return;
  const name = prompt('Group name:', d.name); if (name === null) return;
  if (name.trim() && name.trim() !== d.name) wsSend({ type: 'group_rename', gid: d.key.slice(2), name: name.trim() });
}
function dmRemoveMember(name) {
  const d = dmEntry(curDM); if (!d || d.kind !== 'group' || !confirm(`Remove ${name} from ${d.name}?`)) return;
  wsSend({ type: 'group_remove', gid: d.key.slice(2), target: name });
}
function dmLeaveGroup(key) {
  const d = dmEntry(key || curDM); if (!d || d.kind !== 'group' || !confirm(`Leave “${d.name}”?`)) return;
  wsSend({ type: 'group_leave', gid: d.key.slice(2) });
}

// ── per-conversation settings ──
function dmSetPref(key, patch) {
  const d = dmEntry(key); if (!d) return;
  d.prefs = { ...d.prefs, ...patch };
  persist(); renderDMs(); if (curDM === key) renderDMInfo();
  wsSend({ type: 'dm_prefs_set', conv: d.kind === 'group' ? d.key : d.name, prefs: patch });
}
function dmClearHistory(key) {
  const d = dmEntry(key); if (!d || !confirm(`Clear your copy of this conversation? ${d.kind === 'group' ? 'Others' : d.name} will still have it.`)) return;
  wsSend({ type: 'dm_clear', conv: d.kind === 'group' ? d.key : d.name });
}
function showDmMenu(e, key) {
  e.preventDefault(); e.stopPropagation();
  document.getElementById('dm-ctx')?.remove();
  const d = dmEntry(key); if (!d) return;
  const ctx = document.createElement('div'); ctx.id = 'dm-ctx'; ctx.className = 'ctx-menu';
  const add = (label, fn, danger) => { const x = document.createElement('div'); x.className = 'sv-dd-item' + (danger ? ' danger' : ''); x.textContent = label; x.onclick = () => { ctx.remove(); fn(); }; ctx.appendChild(x); };
  const sep = () => { const x = document.createElement('div'); x.className = 'sv-dd-sep'; ctx.appendChild(x); };
  const lbl = document.createElement('div'); lbl.className = 'ctx-lbl'; lbl.textContent = d.name; ctx.appendChild(lbl); sep();
  if (d.unread) add('✓ Mark as read', () => { d.unread = 0; S.dmMyRead[key] = Date.now(); persist(); renderDMs(); wsSend(d.kind === 'group' ? { type: 'group_read', gid: d.key.slice(2), upTo: Date.now() } : { type: 'dm_read', with: d.name, upTo: Date.now() }); });
  add(d.prefs.pinned ? '📌 Unpin conversation' : '📌 Pin conversation', () => dmSetPref(key, { pinned: !d.prefs.pinned }));
  if (dmIsMuted(d)) add('🔔 Unmute', () => dmSetPref(key, { muted: false }));
  else { add('🔕 Mute for 1 hour', () => dmSetPref(key, { muted: Date.now() + 36e5 })); add('🔕 Mute for 8 hours', () => dmSetPref(key, { muted: Date.now() + 288e5 })); add('🔕 Mute until I turn it on', () => dmSetPref(key, { muted: true })); }
  sep();
  if (curDM === key) add('🔍 Search in conversation', dmToggleSearch);
  add('🧹 Clear history (for me)', () => dmClearHistory(key));
  if (d.kind === 'group') add('🚪 Leave group', () => dmLeaveGroup(key), true);
  else add('✕ Close conversation', () => { dmSetPref(key, { hidden: true }); if (curDM === key) closeDMChat(); }, true);
  document.body.appendChild(ctx);
  const r = ctx.getBoundingClientRect();
  ctx.style.left = Math.max(4, Math.min(e.clientX, window.innerWidth - r.width - 8)) + 'px';
  ctx.style.top = Math.max(4, Math.min(e.clientY, window.innerHeight - r.height - 8)) + 'px';
  const close = (ev) => { if (ev && ctx.contains(ev.target)) return; ctx.remove(); document.removeEventListener('mousedown', close, true); document.removeEventListener('keydown', esc2, true); };
  const esc2 = (ev) => { if (ev.key === 'Escape') close(); };
  setTimeout(() => { document.addEventListener('mousedown', close, true); document.addEventListener('keydown', esc2, true); }, 0);
}
function dmMoreMenu(ev) { const r = ev.currentTarget.getBoundingClientRect(); showDmMenu({ preventDefault() {}, stopPropagation() {}, clientX: r.right - 200, clientY: r.bottom + 4 }, curDM); }

// ── DM privacy settings (account-wide) ──
function openDMPrivacy() { dmPrivacySync(); openM('dm-privacy'); }
function dmPrivacySync() {
  const set = (id, v) => { const el = document.getElementById(id); if (el) el.checked = v; };
  set('dmp-read', S.userSettings.readReceipts !== false); set('dmp-typing', S.userSettings.typingIndicators !== false); set('dmp-sound', dmSoundOn());
}
function dmPrivacySet(which, on) {
  if (which === 'sound') { try { localStorage.setItem('nx-dm-sound', on ? '1' : '0'); } catch {} return; }
  S.userSettings[which === 'read' ? 'readReceipts' : 'typingIndicators'] = on;
  wsSend({ type: 'user_settings_set', [which === 'read' ? 'readReceipts' : 'typingIndicators']: on });
  if (curDM) renderDMMessages(curDM);
}

// ── popup for a brand-new contact (unchanged look) ──
function showDMPopup(from, color, pfp, preview) {
  document.getElementById('dm-new-popup')?.remove();
  const div = document.createElement('div'); div.id = 'dm-new-popup';
  div.style.cssText = 'position:fixed;top:50%;left:50%;transform:translate(-50%,-50%) scale(.92);background:var(--s1);border:1px solid var(--border2);border-radius:20px;padding:28px 32px;z-index:999;box-shadow:0 40px 100px rgba(0,0,0,.85),0 0 0 1px rgba(88,101,242,.12);text-align:center;min-width:290px;max-width:360px;animation:popIn .22s cubic-bezier(.34,1.56,.64,1) forwards';
  const avBg = pfp ? 'transparent' : (color || 'var(--accent)');
  const avContent = pfp ? `<img src="${pfp}" style="width:100%;height:100%;object-fit:cover;border-radius:50%">` : `<span style="font-size:22px;font-weight:800;color:#fff">${esc(from[0].toUpperCase())}</span>`;
  div.innerHTML = `<div style="width:64px;height:64px;border-radius:50%;background:${avBg};display:flex;align-items:center;justify-content:center;margin:0 auto 14px;border:3px solid var(--accent);overflow:hidden">${avContent}</div>
    <div style="font-size:11px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--accent);margin-bottom:4px">New Message</div>
    <div style="font-size:18px;font-weight:800;margin-bottom:6px">${esc(from)}</div>
    <div style="font-size:13px;color:var(--t2);margin-bottom:18px;max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(preview)}</div>
    <div style="display:flex;gap:8px;justify-content:center"><button class="btn-g" onclick="document.getElementById('dm-new-popup').remove()">Dismiss</button><button class="btn-p" onclick="document.getElementById('dm-new-popup').remove();openDMChat('${esc(dk(from))}')">Open</button></div>`;
  document.body.appendChild(div);
  setTimeout(() => div.remove(), 8000);
}

// ── message actions (delete / react / edit) arriving from other people or my other tabs ──
function recvDMDelete(msg) {
  const key = msg.gid ? 'g:' + msg.gid : dk(dk(msg.from) === dk(S.user.name) ? msg.to : msg.from);
  const arr = S.dmMessages[key]; if (!arr) return;
  const i = arr.findIndex(m => m.id === msg.messageId); if (i < 0) return;
  arr.splice(i, 1); persist(); if (curDM === key) fadeOutMsg(msg.messageId, () => renderDMMessages(key)); renderDMs();
}
function dmApplyReaction(m, emoji, user, on) {   // `on` true/false = set it that way; undefined = flip
  m.reactions = m.reactions || [];
  const r = m.reactions.find(x => x.emoji === emoji);
  const has = !!r && (r.users || []).includes(user);
  const want = typeof on === 'boolean' ? on : !has;
  if (want === has) return;
  if (want) { if (r) { r.count++; r.users = [...(r.users || []), user]; } else m.reactions.push({ emoji, count: 1, users: [user] }); }
  else { r.count = Math.max(0, r.count - 1); r.users = (r.users || []).filter(u => u !== user); if (r.count <= 0) m.reactions = m.reactions.filter(x => x.emoji !== emoji); }
}
function recvDMReaction(msg) {
  const key = msg.gid ? 'g:' + msg.gid : dk(dk(msg.user) === dk(S.user.name) ? msg.to : msg.user);
  const m = (S.dmMessages[key] || []).find(x => x.id === msg.messageId); if (!m) return;
  dmApplyReaction(m, msg.emoji, msg.user, msg.on); persist(); if (curDM === key) renderDMMessages(key);
}
function recvDMEdit(msg) {
  const key = msg.gid ? 'g:' + msg.gid : dk(dk(msg.from) === dk(S.user.name) ? msg.to : msg.from);
  const m = (S.dmMessages[key] || []).find(x => x.id === msg.messageId); if (!m) return;
  m.text = msg.text; m.edited = true; persist(); if (curDM === key) renderDMMessages(key);
}
// what to send for an action on the open conversation
function dmActionMsg(type, extra) { return { type: (isGroupKey(curDM) ? type.replace('dm_', 'group_') : type), ...dmWire(curDM), ...extra }; }

// ── home screen: recent conversations (also used by ui-helpers' showHome) ──
function dmHomeRecent() {
  const recent = [...S.dms].filter(d => !d.prefs.hidden).sort((a, b) => (b.lastTs || 0) - (a.lastTs || 0)).slice(0, 5);
  if (!recent.length) return '<div style="font-size:12px;color:var(--t3);padding:8px 0">No recent conversations.</div>';
  return recent.map(d => {
    const url = safeUrl(d.pfp || (d.kind === 'group' ? '' : profileCache[d.name]?.pfp) || '');
    const bg = url ? 'transparent' : (d.kind === 'group' ? (d.color || '#6c63ff') : COLORS[hash(d.name) % COLORS.length]);
    return `<div class="home-row" data-key="${esc(d.key)}" onclick="openDMChat(this.dataset.key)">
      <div class="home-row-av" style="background:${esc(bg)}">${url ? `<img src="${url}" style="width:100%;height:100%;object-fit:cover;border-radius:inherit">` : esc(d.name[0].toUpperCase())}</div>
      <div style="min-width:0;flex:1"><div style="font-size:13px;font-weight:600">${esc(d.name)}</div><div style="font-size:11px;color:var(--t3);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${esc(d.last || 'No messages yet')}</div></div>
      <svg width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" style="color:var(--t3);flex-shrink:0"><polyline points="9 18 15 12 9 6"/></svg></div>`;
  }).join('');
}
// clicking the name in the header: a person's profile, or a group's info panel
function dmHeaderClick() { const d = dmEntry(curDM); if (!d) return; if (d.kind === 'group') toggleDMInfo(true); else openProfilePage(d.name); }
// the server says a call is (no longer) going on in one of my conversations
function recvCallState(msg) {
  const key = msg.gid ? 'g:' + msg.gid : dk(msg.with);
  if (msg.active) S.callStates[key] = { callId: msg.callId, active: true, participants: msg.participants || [], startedAt: msg.startedAt, answeredAt: msg.answeredAt };
  else if (!S.callStates[key] || S.callStates[key].callId === msg.callId) delete S.callStates[key];
  if (curDM === key) renderDMCallBanner();
}
