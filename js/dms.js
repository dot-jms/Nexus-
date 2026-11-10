// ══════════════════════════════════
// DMs — Request / Accept / Chat
// ══════════════════════════════════
let curDM = null;        // currently open DM convo
let _dmContactsLoading = false; // true while waiting for dm_contacts from server
let pendingDMReq = null; // incoming request waiting for accept/decline

function toggleDM() { document.getElementById('dm-panel').classList.toggle('open'); }

function renderRailDMs() {
  const el = document.getElementById('rail-dms');
  if (!el) return;
  const recent = [...S.dms].sort((a,b)=>(b.lastTs||0)-(a.lastTs||0)).slice(0,5);
  const sep = document.getElementById('rail-dms-sep');
  if (sep) sep.style.display = recent.length ? '' : 'none';
  el.innerHTML = recent.map(dm => {
    const bg = dm.pfp ? 'transparent' : COLORS[hash(dm.name) % COLORS.length];
    const av = dm.pfp ? `<img src="${dm.pfp}" style="width:100%;height:100%;object-fit:cover;border-radius:inherit">` : dm.name[0].toUpperCase();
    const isActive = curDM === dm.name;
    return `<div class="rail-dm-av${isActive?' act':''}${dm.unread?' unread':''}" style="background:${bg}" onclick="openOrCreateDM('${dm.name}',null)" title="${esc(dm.name)}">${av}${dm.unread?'<div class="rail-dm-badge"></div>':''}</div>`;
  }).join('');
}

function renderDMs() {
  renderRailDMs();
  // Refresh home screen if it's currently showing
  if (document.getElementById('home-screen')?.style.display !== 'none' &&
      document.getElementById('home-screen')?.style.display !== '') {
    // Don't re-trigger full showHome (causes flicker), just update DM list
    const recent = [...S.dms].sort((a,b)=>(b.lastTs||0)-(a.lastTs||0)).slice(0,5);
    const dmsEl = document.getElementById('home-recent-dms');
    if (dmsEl) dmsEl.innerHTML = recent.length ? recent.map(dm => {
      const bg = dm.pfp ? 'transparent' : COLORS[hash(dm.name) % COLORS.length];
      const av = dm.pfp ? `<img src="${dm.pfp}" style="width:100%;height:100%;object-fit:cover;border-radius:inherit">` : dm.name[0].toUpperCase();
      return `<div class="home-row" onclick="openOrCreateDM('${dm.name}',null)">
        <div class="home-row-av" style="background:${bg}">${av}</div>
        <div style="min-width:0;flex:1"><div style="font-size:13px;font-weight:600">${esc(dm.name)}</div><div style="font-size:11px;color:var(--t3);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${esc(dm.last||'No messages yet')}</div></div>
        <svg width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" style="color:var(--t3);flex-shrink:0"><polyline points="9 18 15 12 9 6"/></svg>
      </div>`;
    }).join('') : '<div style="font-size:12px;color:var(--t3);padding:8px 0">No recent conversations.</div>';
  }
  const el = document.getElementById('dm-list');
  // Sort by most recent message
  const convos = [...S.dms].sort((a, b) => (b.lastTs || 0) - (a.lastTs || 0));
  let html = '';
  convos.forEach(dm => {
    const bg = dm.pfp ? 'transparent' : COLORS[hash(dm.name) % COLORS.length];
    const av = dm.pfp ? `<img src="${dm.pfp}">` : dm.name[0].toUpperCase();
    const isActive = curDM === dm.name;
    html += `<div class="dm-it${isActive?' active':''}${dm.unread?' unread':''}" onclick="openDMChat('${dm.name}')">
      <div class="mb-av" style="background:${bg};width:30px;height:30px">${av}</div>
      <div style="min-width:0;flex:1">
        <div class="dm-nm">${esc(dm.name)}</div>
        <div class="dm-pv">${esc(dm.last || 'No messages yet')}</div>
      </div>
      <div class="dm-unread"></div>
    </div>`;
  });
  if (!html) {
    if (!S.wsOk) {
      html = `<div style="padding:24px 16px;font-size:12px;color:var(--t3);text-align:center">Connecting…</div>`;
    } else if (_dmContactsLoading) {
      html = `<div style="padding:24px 16px;font-size:12px;color:var(--t3);text-align:center">
        <div style="margin-bottom:8px;font-size:18px;animation:blink 1.2s infinite">💬</div>
        Restoring conversations…
      </div>`;
    } else {
      html = `<div style="padding:24px 16px;font-size:12px;color:var(--t3);text-align:center">No conversations yet.<br>Click someone's profile to message them!</div>`;
    }
  }
  el.innerHTML = html;
}

// ── Open or create a DM conversation (no request needed) ──
async function sendDMRequest() {
  const name = document.getElementById('dm-in').value.trim().split('#')[0];
  const errEl = document.getElementById('dm-req-err');
  errEl.style.display = 'none';
  if (!name) { errEl.textContent = 'Enter a username.'; errEl.style.display = 'block'; return; }
  if (name.toLowerCase() === S.user.name.toLowerCase()) { errEl.textContent = "You can't DM yourself."; errEl.style.display = 'block'; return; }
  // Check user exists on server before opening
  const btn = document.querySelector('#ndm .auth-btn, #ndm .btn-p');
  const orig = btn?.textContent;
  if (btn) { btn.textContent = 'Checking…'; btn.disabled = true; }
  try {
    const exists = await checkUserExists(name);
    if (!exists) {
      errEl.textContent = `@${name} doesn't exist.`;
      errEl.style.display = 'block';
      if (btn) { btn.textContent = orig; btn.disabled = false; }
      return;
    }
  } catch(e) {
    // Server unreachable — allow anyway (offline fallback)
  }
  if (btn) { btn.textContent = orig; btn.disabled = false; }
  closeM('ndm');
  document.getElementById('dm-in').value = '';
  openOrCreateDM(name, null);
}

function checkUserExists(username) {
  return new Promise((resolve) => {
    const ws = new WebSocket(WS_URL);
    ws.onopen = () => ws.send(JSON.stringify({ type: 'check_username', username: username.toLowerCase() }));
    ws.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data);
        if (msg.type === 'username_available') {
          // available=true means user does NOT exist
          resolve(!msg.available);
          ws.close();
        }
      } catch {}
    };
    ws.onerror = () => resolve(true); // fail open
    setTimeout(() => resolve(true), 5000); // timeout = fail open
  });
}

function openOrCreateDM(name, pfp) {
  if (!S.dms.find(d => d.name === name)) {
    S.dms.push({ id: uid(), name, last: '', status: 'accepted', pfp: pfp || null, lastTs: 0 });
    persist();
  } else {
    const dm = S.dms.find(d => d.name === name);
    dm.status = 'accepted'; // upgrade any old pending entry
    if (pfp) dm.pfp = pfp;
  }
  renderDMs();
  openDMChat(name);
  document.getElementById('dm-panel').classList.add('open');
}

// Kept for WS handler compatibility — now just silently accepted
function recvDMRequest(msg) {
  openOrCreateDM(msg.from, msg.fromPfp || null);
}
function openDMRequest(name) { openDMChat(name); }
function acceptDMRequest() { closeM('dm-req-modal'); }
function declineDMRequest() { closeM('dm-req-modal'); }
function recvDMAccept(msg) {
  const dm = S.dms.find(d => d.name === msg.from);
  if (dm) { dm.status = 'accepted'; dm.pfp = msg.fromPfp || null; persist(); renderDMs(); }
}
function recvDMDecline(msg) { /* no-op — requests gone */ }

// ── Opening a DM conversation ──
function openDMChat(name) {
  let dm = S.dms.find(d => d.name === name);
  if (!dm) {
    // Cache was cleared — create a stub entry so the chat can open while history loads
    dm = { id: uid(), name, last: '', status: 'accepted', pfp: null, lastTs: 0 };
    S.dms.push(dm);
    // Ask server for this contact's profile info
    wsSend({ type: 'fetch_dm_history', with: name });
  }
  curDM = name;
  dm.unread = false;
  // Switch main view
  hideAll();
  document.getElementById('dm-chat').classList.add('show');
  document.getElementById('ch-hd').style.display = 'none';
  // Hide channel sidebar and members panel — they belong to servers, not DMs
  document.getElementById('sidebar').style.display = 'none';
  document.getElementById('members').style.display = 'none';
  document.body.classList.add('in-dm');
  // Set header
  const bg = dm.pfp ? 'transparent' : COLORS[hash(name) % COLORS.length];
  const av = dm.pfp ? `<img src="${dm.pfp}" style="width:100%;height:100%;object-fit:cover">` : name[0].toUpperCase();
  document.getElementById('dm-chat-av').style.background = bg;
  document.getElementById('dm-chat-av').innerHTML = av;
  document.getElementById('dm-chat-name').textContent = name;
  // Always show input — no request system
  document.getElementById('dm-inp-wrap').style.display = '';
  document.getElementById('dm-pending-banner').style.display = 'none';
  renderDMMessages(name);
  renderDMs();
  document.getElementById('dm-panel').classList.remove('open');
  // Fetch server history in background (syncs messages across devices + gets offline msgs)
  wsSend({ type: 'fetch_dm_history', with: name });
}

function recvDMContacts(msg) {
  _dmContactsLoading = false;
  // Server sends a list of users we've exchanged DMs with.
  // Upsert every entry: add missing ones and refresh metadata on existing ones.
  const contacts = msg.contacts || [];
  let changed = false;
  contacts.forEach(c => {
    // Seed profileCache with latest pfp so buildMsg always renders the current avatar
    if (!profileCache[c.name]) profileCache[c.name] = {};
    if (c.pfp !== undefined) profileCache[c.name].pfp = c.pfp || null;
    const existing = S.dms.find(d => d.name === c.name);
    if (existing) {
      // Update pfp and last-message preview in case they changed
      if (c.pfp !== undefined && existing.pfp !== c.pfp) { existing.pfp = c.pfp || null; changed = true; }
      if (c.lastTs && c.lastTs > (existing.lastTs || 0)) {
        existing.last = c.last || existing.last;
        existing.lastTs = c.lastTs;
        changed = true;
      }
    } else {
      S.dms.push({ id: uid(), name: c.name, last: c.last || '', status: 'accepted', pfp: c.pfp || null, lastTs: c.lastTs || 0 });
      changed = true;
    }
  });
  if (changed) { persist(); renderDMs(); }
}

function showDMTyping(who) {
  if (curDM !== who) return; // not the open conversation
  const bar = document.getElementById('dm-ty-bar');
  if (!bar) return;
  bar.innerHTML = `<div class="ty-dots"><div class="ty-dot"></div><div class="ty-dot"></div><div class="ty-dot"></div></div><span>${esc(who)} is typing…</span>`;
  clearTimeout(bar._t);
  bar._t = setTimeout(() => { bar.innerHTML = ''; }, 3500);
}

function closeDMChat() {
  curDM = null;
  document.getElementById('dm-chat').classList.remove('show');
  document.getElementById('sidebar').style.display = '';
  if (S.mbOpen) document.getElementById('members').style.display = '';
  document.body.classList.remove('in-dm');
  showWelcome();
}

// ── DM messages ──
function renderDMMessages(name) {
  const el = document.getElementById('dm-msgs'); el.innerHTML = '';
  const msgs = S.dmMessages[name] || [];
  if (!msgs.length) {
    el.innerHTML = `<div style="text-align:center;padding:40px 0;color:var(--t3)"><div style="font-size:28px;margin-bottom:8px">👋</div><div style="font-weight:700;color:var(--t2);font-size:13px">This is the beginning of your DM with ${esc(name)}</div></div>`;
    return;
  }
  let la = '', lt = 0;
  const dmParts = [];
  msgs.forEach(m => {
    const grp = m.author === la && (m.ts - lt) < 300000;
    dmParts.push(buildMsg(m, grp));
    la = m.author; lt = m.ts;
  });
  el.innerHTML = dmParts.join('');
  el.scrollTop = el.scrollHeight;
}

function sendDMMsg() {
  const inp = document.getElementById('dm-msg-in');
  const text = inp.value.trim();
  // Handle ongoing edit commit via DM input
  if (editingMsgId) { if (text) commitEdit(text); else cancelEdit(); inp.value = ''; inp.style.height = 'auto'; const btn = document.getElementById('dm-snd-btn'); if (btn) btn.classList.remove('on'); return; }
  if (!text || !curDM) return;
  let dm = S.dms.find(d => d.name === curDM); if (!dm) { dm = {id:uid(),name:curDM,last:'',status:'accepted',pfp:null,lastTs:0}; S.dms.push(dm); }
  const msg = { id: uid(), author: S.user.name, authorColor: S.user.color, authorPfp: S.user.pfp || null, text, ts: Date.now(), reactions: [], attachments: [] };
  if (!S.dmMessages[curDM]) S.dmMessages[curDM] = [];
  S.dmMessages[curDM].push(msg);
  dm.last = text; dm.lastTs = Date.now(); persist();
  renderDMMessages(curDM); renderDMs();
  wsSend({ type: 'dm', to: curDM, from: S.user.name, ...msg });
  inp.value = ''; inp.style.height = 'auto';
}

function recvDM(msg) {
  const from = msg.from || msg.author;
  if (!from) return;
  const isNew = !S.dms.find(d => d.name === from);
  let dm = S.dms.find(d => d.name === from);
  if (!dm) {
    dm = { id: uid(), name: from, last: '', status: 'accepted', pfp: msg.authorPfp || null, lastTs: 0 };
    S.dms.unshift(dm); // new conversations go to the top
  }
  dm.status = 'accepted';
  dm.pfp = msg.authorPfp || dm.pfp || null;
  if (!S.dmMessages[from]) S.dmMessages[from] = [];
  S.dmMessages[from].push({ id: msg.id || uid(), author: from, authorColor: msg.authorColor, authorPfp: msg.authorPfp, text: msg.text, ts: msg.ts || Date.now(), reactions: [], attachments: msg.attachments || [] });
  dm.last = msg.text || '[attachment]';
  dm.lastTs = msg.ts || Date.now();
  if (curDM !== from) dm.unread = true;
  persist(); renderDMs();
  if (curDM === from) { renderDMMessages(from); return; }
  playSound('dm');
  if (isNew) {
    // Big popup for a brand-new contact
    showDMPopup(from, msg.authorColor, msg.authorPfp, msg.text || '[attachment]');
  } else {
    toast('💬 DM from ' + from);
  }
  addNotif('💬', 'DM from ' + from, () => { renderDMs(); openDMChat(from); });
}

function showDMPopup(from, color, pfp, preview) {
  document.getElementById('dm-new-popup')?.remove();
  const div = document.createElement('div');
  div.id = 'dm-new-popup';
  div.style.cssText = 'position:fixed;top:50%;left:50%;transform:translate(-50%,-50%) scale(.92);background:var(--s1);border:1px solid var(--border2);border-radius:20px;padding:28px 32px;z-index:999;box-shadow:0 40px 100px rgba(0,0,0,.85),0 0 0 1px rgba(124,109,250,.12);text-align:center;min-width:290px;max-width:360px;animation:popIn .22s cubic-bezier(.34,1.56,.64,1) forwards';
  const avBg = pfp ? 'transparent' : (color || 'var(--accent)');
  const avContent = pfp ? `<img src="${pfp}" style="width:100%;height:100%;object-fit:cover;border-radius:50%">` : `<span style="font-size:22px;font-weight:800;color:#fff">${from[0].toUpperCase()}</span>`;
  div.innerHTML = `
    <div style="width:64px;height:64px;border-radius:50%;background:${avBg};display:flex;align-items:center;justify-content:center;margin:0 auto 14px;border:3px solid var(--accent);overflow:hidden">${avContent}</div>
    <div style="font-size:11px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--accent);margin-bottom:4px">New Message</div>
    <div style="font-size:17px;font-weight:800;margin-bottom:6px">${esc(from)}</div>
    <div style="font-size:13px;color:var(--t2);margin-bottom:20px;word-break:break-word;line-height:1.4">"${esc(preview.slice(0,80))}${preview.length>80?'…':''}"</div>
    <div style="display:flex;gap:10px;justify-content:center">
      <button onclick="document.getElementById('dm-new-popup').remove();openDMChat('${esc(from)}')" style="background:var(--accent);border:none;border-radius:10px;padding:10px 22px;font-family:'Syne',sans-serif;font-size:13px;font-weight:700;color:#fff;cursor:pointer">Reply</button>
      <button onclick="document.getElementById('dm-new-popup').remove()" style="background:var(--s3);border:1px solid var(--border2);border-radius:10px;padding:10px 18px;font-family:'Syne',sans-serif;font-size:13px;font-weight:600;color:var(--t2);cursor:pointer">Dismiss</button>
    </div>`;
  document.body.appendChild(div);
  setTimeout(() => { if (div.parentNode) div.remove(); }, 12000);
}

function recvDMHistory(msg) {
  // Merge server DM history into local — dedupe by id
  const name = msg.with;
  if (!name || !msg.messages?.length) return;
  const local = S.dmMessages[name] || [];
  const ids = new Set(local.map(m => m.id));
  const merged = [...local];
  (msg.messages || []).forEach(m => {
    if (!ids.has(m.id)) { merged.push(m); ids.add(m.id); }
  });
  merged.sort((a, b) => a.ts - b.ts);
  S.dmMessages[name] = merged;
  // Update last message preview
  const dm = S.dms.find(d => d.name === name);
  if (dm && merged.length) {
    dm.last = merged[merged.length - 1].text || '[attachment]';
    dm.lastTs = merged[merged.length - 1].ts;
  }
  persist();
  if (curDM === name) renderDMMessages(name);
  renderDMs();
}

let _dmTySent = false;
function onDMType() {
  const inp = document.getElementById('dm-msg-in');
  inp.style.height = 'auto';
  inp.style.height = Math.min(inp.scrollHeight, 120) + 'px';
  const btn = document.getElementById('dm-snd-btn');
  if (btn) btn.classList.toggle('on', inp.value.trim().length > 0);
  // Warn near 2000 char limit
  const len = inp.value.length;
  let warn = document.getElementById('dm-char-warn');
  if (len > 1800) {
    if (!warn) { warn = document.createElement('div'); warn.id = 'dm-char-warn'; warn.style.cssText='font-size:10px;color:var(--yellow);text-align:right;padding:0 14px 4px;font-family:DM Mono,monospace'; document.getElementById('dm-inp-wrap').prepend(warn); }
    warn.textContent = (2000 - len) + ' left';
    warn.style.color = len > 1950 ? 'var(--red)' : 'var(--yellow)';
  } else if (warn) { warn.remove(); }
  // Send DM typing indicator
  if (curDM && !_dmTySent) {
    _dmTySent = true;
    wsSend({ type: 'dm_typing', to: curDM, from: S.user.name });
    setTimeout(() => { _dmTySent = false; }, 3000);
  }
}
