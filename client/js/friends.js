// ══════════════════════════════════════════════
// FRIENDS
// ══════════════════════════════════════════════
// A full page (Online / All / Pending / Add Friend) instead of a side drawer. Presence (online / idle /
// do-not-disturb / offline + last seen) comes from the server with the friends list and is pushed live, so
// nothing here guesses from member lists any more.
const FV = { tab: 'online', timer: null };
const FV_ICON = {
  chat:  '<svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>',
  user:  '<svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>',
  x:     '<svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.4" viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>',
  check: '<svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="2.6" viewBox="0 0 24 24"><polyline points="20 6 9 17 4 12"/></svg>',
  plus:  '<svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="2.4" viewBox="0 0 24 24"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>',
};

function showFriends(tab) {
  const panel = document.getElementById('friends-view');
  if (panel.style.display === 'flex' && !tab) { closeFriends(); return; }
  document.getElementById('rail-friends').classList.add('act');
  panel.style.display = 'flex';
  // land on Pending when somebody is waiting for an answer
  friendsTab(tab || (pendingIncoming().length ? 'pending' : 'online'));
  askFriendPresence();
  clearInterval(FV.timer);
  FV.timer = setInterval(() => { if (friendsOpen()) { askFriendPresence(); renderFriends(); } }, 30000); // safety net + "last seen" labels
}
function closeFriends() {
  document.getElementById('friends-view').style.display = 'none';
  document.getElementById('rail-friends').classList.remove('act');
  clearInterval(FV.timer);
}
function askFriendPresence() { if (S.wsOk && S.friends.length) wsSend({ type: 'get_presence', names: S.friends.map(f => f.name) }); }
function friendsTab(t) {
  FV.tab = t;
  ['online', 'all', 'pending', 'add'].forEach(x => document.getElementById('fvt-' + x)?.classList.toggle('act', x === t));
  const sb = document.getElementById('fv-searchbar'); if (sb) sb.style.display = t === 'add' ? 'none' : '';
  renderFriends();
  if (t === 'add') setTimeout(() => document.getElementById('fv-add-in')?.focus(), 60);
}

// ── data helpers ──
const pendingIncoming = () => S.friendReqs.filter(r => r.direction === 'in');
const pendingOutgoing = () => S.friendReqs.filter(r => r.direction === 'out');
const isFriend = name => S.friends.some(f => _nk(f.name) === _nk(name));
function friendPresence(f) {
  const on = f.online === true;
  const st = on ? (f.status || 'online') : 'offline';
  const text = on ? ({ online: 'Online', idle: 'Idle', dnd: 'Do Not Disturb' }[st] || 'Online')
                  : (f.lastSeen ? 'Offline · last seen ' + timeAgo(f.lastSeen) : 'Offline');
  return { on, st, text, cls: on ? st : 'off' };
}
function isOnline(name) { const f = S.friends.find(x => _nk(x.name) === _nk(name)); return !!f && f.online === true; }
function timeAgo(ts) {
  const s = Math.max(0, (Date.now() - ts) / 1000);
  if (s < 60) return 'just now';
  if (s < 3600) return Math.floor(s / 60) + 'm ago';
  if (s < 86400) return Math.floor(s / 3600) + 'h ago';
  if (s < 86400 * 7) return Math.floor(s / 86400) + 'd ago';
  return new Date(ts).toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
}
function fvAvatar(name, pfp, color, dotCls) {
  const url = safeUrl(pfp || profileCache[name]?.pfp || '');
  const bg = url ? 'transparent' : (color || profileCache[name]?.color || COLORS[hash(name) % COLORS.length]);
  const inner = url ? `<img src="${url}" alt="">` : esc((name || '?')[0].toUpperCase());
  return `<div class="fv-av" style="background:${bg}">${inner}${dotCls ? `<span class="fv-dot ${dotCls}"></span>` : ''}</div>`;
}
function updateFriendBadge() {
  const n = pendingIncoming().length;
  const b = document.getElementById('fr-badge'); if (b) b.style.display = n ? '' : 'none';
  const t = document.getElementById('fv-pend-n'); if (t) { t.textContent = n; t.style.display = n ? '' : 'none'; }
}
function updateHomeFriends() {
  const el = document.getElementById('home-friends-count'); if (!el) return;
  const online = S.friends.filter(f => f.online === true).length;
  el.textContent = S.friends.length + ' friends' + (online ? ` · ${online} online` : '');
}

// ── rendering ──
function fvRow(f) {
  const p = friendPresence(f);
  return `<div class="fv-row" data-name="${esc(f.name)}" onclick="friendAct(event,'profile')">
    ${fvAvatar(f.name, f.pfp, f.color, p.cls)}
    <div class="fv-info"><div class="fv-name">${esc(f.name)}</div><div class="fv-sub ${p.on ? 'on' : ''}">${esc(p.text)}</div></div>
    <div class="fv-acts">
      <button class="fv-act" title="Message" onclick="friendAct(event,'dm')">${FV_ICON.chat}</button>
      <button class="fv-act" title="View profile" onclick="friendAct(event,'profile')">${FV_ICON.user}</button>
      <button class="fv-act danger" title="Remove friend" onclick="friendAct(event,'remove')">${FV_ICON.x}</button>
    </div></div>`;
}
function fvReqRow(r) {
  const incoming = r.direction === 'in';
  return `<div class="fv-row" data-name="${esc(r.name)}" onclick="friendAct(event,'profile')">
    ${fvAvatar(r.name, r.pfp, r.color)}
    <div class="fv-info"><div class="fv-name">${esc(r.name)}</div><div class="fv-sub">${incoming ? 'Incoming friend request' : 'Outgoing friend request'}</div></div>
    <div class="fv-acts">${incoming
      ? `<button class="fv-act ok" title="Accept" onclick="friendAct(event,'accept')">${FV_ICON.check}</button>
         <button class="fv-act danger" title="Decline" onclick="friendAct(event,'decline')">${FV_ICON.x}</button>`
      : `<button class="fv-act danger" title="Cancel request" onclick="friendAct(event,'cancel')">${FV_ICON.x}</button>`}
    </div></div>`;
}
const fvEmpty = (em, title, sub, btn) => `<div class="fv-empty"><div class="em">${em}</div><b>${title}</b><div>${sub}</div>${btn || ''}</div>`;

function renderFriends() {
  updateFriendBadge(); updateHomeFriends();
  if (!friendsOpen()) return;
  const scroll = document.getElementById('fv-scroll'); if (!scroll) return;
  const q = _nk(document.getElementById('fv-search')?.value.trim());
  const match = x => !q || _nk(x.name).includes(q);
  const byName = (a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: 'base' });
  const friends = [...S.friends].sort(byName);
  const on = friends.filter(f => friendPresence(f).on), off = friends.filter(f => !friendPresence(f).on);
  const incoming = pendingIncoming().filter(match), outgoing = pendingOutgoing().filter(match);

  const nOnline = document.getElementById('fvn-online'); if (nOnline) nOnline.textContent = on.length;
  const nAll = document.getElementById('fvn-all'); if (nAll) nAll.textContent = friends.length;
  const sum = document.getElementById('fv-summary');
  if (sum) sum.textContent = friends.length ? `${on.length} online · ${friends.length} friend${friends.length === 1 ? '' : 's'}` : '';

  let html = '';
  if (FV.tab === 'online') {
    const list = on.filter(match);
    if (list.length) html = `<div class="fv-sec">Online — ${list.length}</div>` + list.map(fvRow).join('');
    else if (!friends.length) html = fvEmpty('👋', 'No friends yet', 'Add people by username and they will show up here.', `<button class="btn-p fv-cta" onclick="friendsTab('add')">Add a friend</button>`);
    else if (q) html = fvEmpty('🔍', 'No matches', `Nobody online matches “${esc(q)}”.`);
    else html = fvEmpty('😴', 'Nobody is online right now', `${friends.length} of your friends ${friends.length === 1 ? 'is' : 'are'} offline.`, `<button class="btn-g fv-cta" onclick="friendsTab('all')">See all friends</button>`);
  } else if (FV.tab === 'all') {
    const a = on.filter(match), b = off.filter(match);
    if (a.length) html += `<div class="fv-sec">Online — ${a.length}</div>` + a.map(fvRow).join('');
    if (b.length) html += `<div class="fv-sec">Offline — ${b.length}</div>` + b.map(fvRow).join('');
    if (!html) html = !friends.length
      ? fvEmpty('👋', 'No friends yet', 'Add people by username and they will show up here.', `<button class="btn-p fv-cta" onclick="friendsTab('add')">Add a friend</button>`)
      : fvEmpty('🔍', 'No matches', `Nobody matches “${esc(q)}”.`);
  } else if (FV.tab === 'pending') {
    if (incoming.length) html += `<div class="fv-sec">Incoming — ${incoming.length}</div>` + incoming.map(fvReqRow).join('');
    if (outgoing.length) html += `<div class="fv-sec">Outgoing — ${outgoing.length}</div>` + outgoing.map(fvReqRow).join('');
    if (!html) html = fvEmpty('📭', 'No pending requests', 'Friend requests you send or receive wait here until they are answered.');
  } else { // add
    html = `<div class="fv-addcard">
      <h3>Add a friend</h3>
      <p>Type their exact username. Usernames are not case sensitive.</p>
      <div class="fv-addrow"><input class="m-inp" id="fv-add-in" placeholder="Enter a username" maxlength="24" autocomplete="off" onkeydown="if(event.key==='Enter')sendFriendReq()">
      <button class="btn-p" onclick="sendFriendReq()">Send Friend Request</button></div>
      <div class="fv-msg" id="fv-add-msg"></div></div>`;
  }
  // keep scroll position + search focus stable across live re-renders
  const top = scroll.scrollTop, hadInput = document.activeElement?.id === 'fv-add-in', val = hadInput ? document.activeElement.value : '';
  scroll.innerHTML = html;
  scroll.scrollTop = top;
  if (hadInput) { const i = document.getElementById('fv-add-in'); if (i) { i.value = val; i.focus(); } }
  renderFriendSuggestions();
}

// People you share a server with who aren't friends yet
function renderFriendSuggestions() {
  const side = document.getElementById('fv-side'); if (!side) return;
  const taken = new Set([_nk(S.user?.name), ...S.friends.map(f => _nk(f.name)), ...S.friendReqs.map(r => _nk(r.name))]);
  const seen = new Map();
  S.servers.forEach(sv => (S.members[sv.id] || []).forEach(m => {
    const k = _nk(m.name); if (!m.name || taken.has(k)) return;
    const prev = seen.get(k);
    if (!prev || (m.online === true && !prev.m.online)) seen.set(k, { m, sv: prev?.sv || sv });
  }));
  const list = [...seen.values()].sort((a, b) => (b.m.online === true) - (a.m.online === true) || a.m.name.localeCompare(b.m.name)).slice(0, 8);
  side.innerHTML = `<div class="fv-sec" style="padding-top:0">People you may know</div>` + (list.length
    ? list.map(({ m, sv }) => `<div class="fv-sugg" data-name="${esc(m.name)}">
        ${fvAvatar(m.name, m.pfp, m.color, m.online === true ? (m.status || 'online') : 'off')}
        <div class="fv-info"><div class="fv-name">${esc(m.name)}</div><div class="fv-sub">in ${esc(sv.name)}</div></div>
        <button class="fv-act ok" title="Send friend request" onclick="friendAct(event,'add')">${FV_ICON.plus}</button></div>`).join('')
    : `<div class="fv-sub" style="line-height:1.5">People from your servers will appear here, with a quick way to add them.</div>`);
}

// ── actions ──
function friendAct(ev, act) {
  ev.stopPropagation();
  const name = ev.currentTarget.closest('[data-name]')?.dataset.name; if (!name) return;
  ({ dm: dmFriend, profile: n => openProfilePage(n), remove: removeFriend, accept: acceptFriend, decline: declineFriend, cancel: cancelFriendReq, add: sendFriendReqTo })[act]?.(name);
}
function sendFriendReqTo(name) {
  name = String(name || '').trim(); if (!name) return false;
  const msgEl = () => document.getElementById('fv-add-msg');
  const say = (t, ok) => { const el = msgEl(); if (el) { el.textContent = t; el.className = 'fv-msg ' + (ok ? 'ok' : 'err'); } };
  if (_nk(name) === _nk(S.user.name)) { say("You can't add yourself.", false); toast("You can't add yourself"); return false; }
  if (isFriend(name)) { say(`You're already friends with ${name}.`, false); toast('Already friends with ' + name); return false; }
  if (pendingOutgoing().some(r => _nk(r.name) === _nk(name))) { say(`You already sent ${name} a request.`, false); toast('Request already sent'); return false; }
  if (!S.wsOk) { say('Not connected to the server.', false); toast('Not connected'); return false; }
  say('Sending…', true);
  wsSend({ type: 'friend_request', to: name });   // the answer comes back as friend_request_result
  return true;
}
function sendFriendReq() {
  const el = document.getElementById('fv-add-in'); if (!el) return;
  const name = el.value.trim(); if (!name) return;
  if (sendFriendReqTo(name)) el.value = '';
}
const FRIEND_FAIL = {
  not_found: n => `No user named “${n}”. Check the spelling.`,
  self: () => "You can't add yourself.",
  already_friends: n => `You're already friends with ${n}.`,
  already_sent: n => `You already sent ${n} a request.`,
  too_many: () => 'You have too many pending requests. Cancel some first.',
  no_request: () => 'That request is no longer available.',
};
function onFriendRequestResult(msg) {
  const el = document.getElementById('fv-add-msg');
  if (msg.ok) {
    if (!S.friendReqs.some(r => _nk(r.name) === _nk(msg.to) && r.direction === 'out'))
      S.friendReqs.push({ name: msg.to, direction: 'out', pfp: msg.pfp || null, color: msg.color || null, ts: Date.now() });
    persist(); renderFriends();
    toast('👥 Friend request sent to ' + msg.to);
    const m = document.getElementById('fv-add-msg'); if (m) { m.textContent = `Friend request sent to ${msg.to}.`; m.className = 'fv-msg ok'; }
  } else {
    const text = (FRIEND_FAIL[msg.reason] || (() => 'That request could not be sent.'))(msg.to);
    if (el) { el.textContent = text; el.className = 'fv-msg err'; }
    toast('⚠️ ' + text);
  }
}
function recvFriendReq(msg) {
  if (isFriend(msg.from)) return;
  if (S.friendReqs.some(r => _nk(r.name) === _nk(msg.from) && r.direction === 'in')) return;
  S.friendReqs.push({ name: msg.from, direction: 'in', pfp: msg.fromPfp || null, color: msg.fromColor || null, ts: Date.now() });
  persist(); renderFriends();
  playSound('friend_request');
  addNotif('👥', msg.from + ' sent you a friend request', () => showFriends('pending'));
}
function onFriendAdded(msg) {
  const f = msg.friend; if (!f?.name) return;
  const i = S.friends.findIndex(x => _nk(x.name) === _nk(f.name));
  if (i >= 0) S.friends[i] = { ...S.friends[i], ...f }; else S.friends.push(f);
  S.friendReqs = S.friendReqs.filter(r => _nk(r.name) !== _nk(f.name));
  persist(); renderFriends();
  if (msg.by && _nk(msg.by) !== _nk(S.user.name)) {   // they accepted MY request
    playSound('friend_accept');
    addNotif('✅', f.name + ' accepted your friend request!', () => showFriends('all'));
    toast('✅ ' + f.name + ' accepted your friend request!');
  }
}
function recvFriendAccept(msg) { onFriendAdded({ friend: { name: msg.from, pfp: msg.fromPfp || null }, by: msg.from }); } // older servers
function acceptFriend(name) {
  const req = S.friendReqs.find(r => r.direction === 'in' && _nk(r.name) === _nk(name)); if (!req) return;
  wsSend({ type: 'friend_accept', to: req.name });            // server first; its friend_added reply fills in presence
  S.friends.push({ name: req.name, pfp: req.pfp || null, color: req.color || null, online: false, status: 'offline' });
  S.friendReqs = S.friendReqs.filter(r => _nk(r.name) !== _nk(name));
  persist(); renderFriends(); toast('✅ Now friends with ' + req.name);
}
function declineFriend(name) {
  wsSend({ type: 'friend_decline', to: name });
  S.friendReqs = S.friendReqs.filter(r => !(r.direction === 'in' && _nk(r.name) === _nk(name)));
  persist(); renderFriends(); toast('Friend request declined');
}
function cancelFriendReq(name) {
  wsSend({ type: 'friend_cancel', to: name });
  S.friendReqs = S.friendReqs.filter(r => !(r.direction === 'out' && _nk(r.name) === _nk(name)));
  persist(); renderFriends(); toast('Friend request cancelled');
}
function removeFriend(name) {
  if (!confirm('Remove ' + name + ' from your friends?')) return;
  wsSend({ type: 'friend_remove', target: name });
  S.friends = S.friends.filter(f => _nk(f.name) !== _nk(name));
  persist(); renderFriends(); toast('Removed ' + name);
}
function dmFriend(name) {
  openOrCreateDM(name, S.friends.find(f => _nk(f.name) === _nk(name))?.pfp || null);
  closeFriends();
}
document.addEventListener('keydown', e => {
  if (e.key === 'Escape' && friendsOpen() && !document.querySelector('.overlay.open') && !document.getElementById('profile-page')?.classList.contains('open')) closeFriends();
});
