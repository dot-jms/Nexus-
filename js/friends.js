// ══════════════════════════════════════════════
// FRIENDS SYSTEM
// ══════════════════════════════════════════════
function showFriends() {
  const panel = document.getElementById('friends-view');
  if (panel.style.display === 'flex') { closeFriends(); return; }
  document.getElementById('rail-friends').classList.add('act');
  panel.style.display = 'flex';
  panel.style.flexDirection = 'column';
  renderFriends();
}

function closeFriends() {
  document.getElementById('friends-view').style.display = 'none';
  document.getElementById('rail-friends').classList.remove('act');
}

function renderFriends() {
  const onlineFriends = S.friends.filter(f => isOnline(f.name));
  const allFriends = S.friends;
  const reqs = S.friendReqs.filter(r => r.direction === 'in');

  document.getElementById('friend-online-count').textContent = onlineFriends.length;
  document.getElementById('friend-reqs-section').style.display = reqs.length ? '' : 'none';

  document.getElementById('friend-reqs-list').innerHTML = reqs.map(r => `
    <div class="friend-row">
      ${friendAvHTML(r.name, r.pfp, r.color)}
      <div style="flex:1"><div class="friend-name">${esc(r.name)}</div><div class="friend-tag">Sent you a friend request</div></div>
      <button class="btn-p" style="font-size:11px;padding:4px 10px;margin-right:4px" onclick="acceptFriend('${r.name}')">Accept</button>
      <button class="btn-g" style="font-size:11px;padding:4px 10px" onclick="declineFriend('${r.name}')">Decline</button>
    </div>`).join('') || '<div style="font-size:12px;color:var(--t3)">No pending requests</div>';

  document.getElementById('friends-online-list').innerHTML = onlineFriends.length ?
    onlineFriends.map(f => friendRowHTML(f)).join('') :
    '<div style="font-size:12px;color:var(--t3);padding:8px 0">No friends online</div>';

  document.getElementById('friends-all-list').innerHTML = allFriends.length ?
    allFriends.map(f => friendRowHTML(f)).join('') :
    '<div style="font-size:12px;color:var(--t3);padding:8px 0">No friends yet. Add some!</div>';
}

function friendAvHTML(name, pfp, color) {
  const bg = pfp ? 'transparent' : (color || COLORS[hash(name)%COLORS.length]);
  const av = pfp ? `<img src="${pfp}">` : name[0].toUpperCase();
  const statusColor = isOnline(name) ? 'var(--green)' : 'var(--t3)';
  return `<div class="friend-av" style="background:${bg}">${av}<div class="friend-status" style="background:${statusColor}"></div></div>`;
}

function friendRowHTML(f) {
  const online = isOnline(f.name);
  return `<div class="friend-row">
    ${friendAvHTML(f.name, f.pfp, f.color)}
    <div style="flex:1"><div class="friend-name">${esc(f.name)}</div><div class="friend-tag">${online?'Online':'Offline'}</div></div>
    <button class="btn-g" style="font-size:11px;padding:4px 10px;margin-right:4px" onclick="dmFriend('${f.name}')">💬 DM</button>
    <button class="btn-g" style="font-size:11px;padding:4px 10px;color:var(--red)" onclick="removeFriend('${f.name}')">✕</button>
  </div>`;
}

function isOnline(name) {
  // Check against WS member lists — if they appear in any server's member list they're online
  return Object.values(S.members).some(list => list.some(m => m.name === name));
}

function sendFriendReqTo(name) {
  if (!name) return;
  if (S.friends.find(f=>f.name===name)) { toast(name+' is already your friend'); return; }
  wsSend({ type:'friend_request', to:name, from:S.user.name, fromColor:S.user.color, fromPfp:S.user.pfp||null });
  toast('👋 Friend request sent to '+name);
}

function sendFriendReq() {
  const name = document.getElementById('friend-search-in').value.trim();
  if (!name) return;
  if (name === S.user.name) { toast("You can't add yourself"); return; }
  if (S.friends.find(f => f.name === name)) { toast('Already friends with ' + name); return; }
  if (!S.wsOk) { toast('Not connected'); return; }
  wsSend({ type: 'friend_request', to: name, from: S.user.name, fromPfp: S.user.pfp||null, fromColor: S.user.color });
  // Add as outgoing pending
  if (!S.friendReqs.find(r => r.name === name)) {
    S.friendReqs.push({ name, direction: 'out', pfp: null });
    persist();
  }
  document.getElementById('friend-search-in').value = '';
  toast('👥 Friend request sent to ' + name);
}

function recvFriendReq(msg) {
  if (S.friends.find(f => f.name === msg.from)) return;
  if (!S.friendReqs.find(r => r.name === msg.from)) {
    S.friendReqs.push({ name: msg.from, direction: 'in', pfp: msg.fromPfp||null, color: msg.fromColor||null });
    persist(); if(document.getElementById('friends-view').style.display!=='none') renderFriends();
    playSound('friend_request');
    addNotif('👥', msg.from + ' sent you a friend request', () => showFriends());
    const badge = document.getElementById('fr-badge');
    badge.style.display = '';
  }
}

function acceptFriend(name) {
  const req = S.friendReqs.find(r => r.name === name && r.direction === 'in');
  if (!req) return;
  S.friends.push({ name, pfp: req.pfp||null, color: req.color||null });
  S.friendReqs = S.friendReqs.filter(r => r.name !== name);
  persist(); renderFriends();
  wsSend({ type: 'friend_accept', to: name, from: S.user.name, fromPfp: S.user.pfp||null });
  document.getElementById('fr-badge').style.display = S.friendReqs.filter(r=>r.direction==='in').length ? '' : 'none';
  toast('✅ Now friends with ' + name);
}

function declineFriend(name) {
  S.friendReqs = S.friendReqs.filter(r => r.name !== name);
  persist(); renderFriends();
  document.getElementById('fr-badge').style.display = S.friendReqs.filter(r=>r.direction==='in').length ? '' : 'none';
  wsSend({ type: 'friend_decline', to: name, from: S.user.name });
  toast('❌ Friend request declined');
}

function recvFriendAccept(msg) {
  if (!S.friends.find(f => f.name === msg.from)) {
    S.friends.push({ name: msg.from, pfp: msg.fromPfp||null });
    S.friendReqs = S.friendReqs.filter(r => r.name !== msg.from);
    persist(); if(document.getElementById('friends-view').style.display!=='none') renderFriends();
    playSound('friend_accept');
    addNotif('✅', msg.from + ' accepted your friend request!', () => showFriends());
    toast('✅ ' + msg.from + ' accepted your friend request!');
  }
}

function removeFriend(name) {
  if (!confirm('Remove ' + name + ' from friends?')) return;
  S.friends = S.friends.filter(f => f.name !== name);
  persist(); renderFriends(); toast('Removed ' + name);
  wsSend({ type: 'friend_remove', target: name });
}

function dmFriend(name) {
  openOrCreateDM(name, S.friends.find(f=>f.name===name)?.pfp||null);
  document.getElementById('friends-view').style.display = 'none';
}
