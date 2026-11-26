// ══════════════════════════════════════════════
// ADMIN PANEL v2 — click-driven (no IDs to paste, no typing usernames)
// Loaded AFTER admin.js / admin-tabs.js: it replaces their panel + renderers, the server messages are unchanged.
// ══════════════════════════════════════════════
const AD = { sec: 'people', user: null, svId: null, chId: null, chName: '', pendingRename: null };
const $a = id => document.getElementById(id);
const admAcct = n => (typeof _adminAccounts !== 'undefined' ? _adminAccounts : []).find(a => a.name.toLowerCase() === String(n).toLowerCase());
const admSv = id => (typeof _adminServers !== 'undefined' ? _adminServers : []).find(s => s.id === id);
const admDate = t => t ? new Date(t).toLocaleDateString('en', { month: 'short', day: 'numeric', year: 'numeric' }) : '?';
function admCanAssume(a) {
  if (!a || a.name.toLowerCase() === (S.user?.name || '').toLowerCase()) return false;
  if (isSystemAdmin()) return true;
  return isCoAdmin() && a.systemRole !== 'admin' && !a.coAdmin;
}
function admStatus(t, bad) { const el = $a('adm-status'); if (el) { el.textContent = t || ''; el.style.color = bad ? 'var(--red)' : 'var(--t2)'; } }
function _adminResult(t, c) { admStatus(t, c && /red/.test(c)); }
function _adminMsgResult(t, c) { admStatus(t, c && /red/.test(c)); }
function _adminSvResult(t, c) { admStatus(t, c && /red/.test(c)); }
const admAv = a => a.pfp ? `<img src="${a.pfp}">` : `<span>${esc((a.name[0] || '?').toUpperCase())}</span>`;
const admBadges = a => (a.systemRole === 'admin' ? '<i class="adm-b adm-b1">⚡ Admin</i>' : a.coAdmin ? '<i class="adm-b adm-b2">★ Co-Admin</i>' : '') + (a.frozen ? '<i class="adm-b adm-b3">🧊 Frozen</i>' : '');

// ── styles ───────────────────────────────────
(function () {
  const st = document.createElement('style');
  st.textContent = `
.adm-box{width:min(940px,96vw)!important;height:min(86vh,740px);max-height:none!important;display:flex;flex-direction:column;padding:0!important;overflow:hidden}
.adm-head{display:flex;align-items:center;gap:10px;padding:12px 16px;border-bottom:1px solid var(--border);flex-shrink:0}
.adm-logo{width:32px;height:32px;border-radius:9px;background:linear-gradient(135deg,#5865f2,#c084fc);display:flex;align-items:center;justify-content:center;font-size:16px}
.adm-body{display:flex;flex:1;min-height:0}
.adm-nav{width:150px;flex-shrink:0;border-right:1px solid var(--border);padding:10px 8px;display:flex;flex-direction:column;gap:3px}
.adm-nav div{padding:8px 10px;border-radius:8px;font-size:13px;font-weight:600;color:var(--t2);cursor:pointer;transition:background .15s,color .15s}
.adm-nav div:hover{background:var(--s3);color:var(--t1)}.adm-nav div.on{background:rgba(88,101,242,.18);color:var(--accent)}
.adm-main{flex:1;min-width:0;overflow-y:auto;padding:14px 16px}
.adm-foot{padding:7px 16px;border-top:1px solid var(--border);font-size:12px;min-height:30px;flex-shrink:0;color:var(--t3)}
.adm-bar{display:flex;gap:6px;margin-bottom:10px}.adm-bar .m-inp{flex:1}
.adm-list{display:flex;flex-direction:column;gap:5px}
.adm-row{display:flex;align-items:center;gap:10px;background:var(--s3);border:1px solid var(--border);border-radius:9px;padding:8px 10px;cursor:pointer;transition:border-color .15s,transform .15s}
.adm-row:hover{border-color:var(--accent)}
.adm-av{width:36px;height:36px;border-radius:50%;overflow:hidden;flex-shrink:0;display:flex;align-items:center;justify-content:center;color:#fff;font-weight:700}
.adm-av img{width:100%;height:100%;object-fit:cover}
.adm-nm{font-size:13px;font-weight:700;display:flex;align-items:center;gap:5px;flex-wrap:wrap}
.adm-sub{font-size:11px;color:var(--t3);margin-top:1px}
.adm-dot{width:8px;height:8px;border-radius:50%;background:var(--green)}
.adm-b{font-style:normal;font-size:9px;font-weight:700;border-radius:99px;padding:1px 6px;border:1px solid}
.adm-b1{background:rgba(88,101,242,.2);color:var(--accent);border-color:rgba(88,101,242,.3)}
.adm-b2{background:rgba(52,211,153,.15);color:var(--green);border-color:rgba(52,211,153,.3)}
.adm-b3{background:rgba(96,165,250,.12);color:#60a5fa;border-color:rgba(96,165,250,.3)}
.adm-sec{background:var(--s3);border:1px solid var(--border);border-radius:10px;margin-bottom:8px}
.adm-sec>summary{padding:10px 12px;font-size:13px;font-weight:700;cursor:pointer;list-style:none;display:flex;justify-content:space-between}
.adm-sec>summary::after{content:'▾';color:var(--t3);transition:transform .2s}.adm-sec[open]>summary::after{transform:rotate(180deg)}
.adm-sec>div{padding:0 12px 12px;display:flex;flex-direction:column;gap:7px}
.adm-sec.danger{border-color:rgba(248,113,113,.35)}.adm-sec.danger>summary{color:#f87171}
.adm-btns{display:flex;gap:5px;flex-wrap:wrap}.adm-btns .btn-g,.adm-btns .btn-p{font-size:12px}
.adm-line{display:flex;gap:5px;flex-wrap:wrap}.adm-line .m-inp{flex:1;min-width:110px}
.adm-red{color:#f87171!important}
.adm-hero{display:flex;align-items:center;gap:12px;margin-bottom:12px;flex-wrap:wrap}
.adm-hero .adm-av{width:54px;height:54px;font-size:22px}
.adm-be{background:linear-gradient(135deg,#5865f2,#c084fc)!important;border:none!important;color:#fff!important;font-weight:700}
.adm-back{margin-bottom:10px}
.adm-h{font-size:11px;font-weight:700;color:var(--t3);letter-spacing:.08em;text-transform:uppercase;margin:12px 0 6px}
.adm-card{background:var(--s3);border:1px solid var(--border);border-radius:9px;padding:8px 10px;font-size:12px}
.adm-msg{display:flex;gap:6px;align-items:baseline;padding:4px 0;border-bottom:1px solid var(--border);font-size:12px}
.adm-msg .t{flex:1;min-width:0;word-break:break-word}
.adm-note{background:rgba(251,146,60,.07);border:1px solid rgba(251,146,60,.2);border-radius:7px;padding:6px 9px;font-size:11px}
@media(max-width:640px){.adm-body{flex-direction:column}.adm-nav{width:auto;flex-direction:row;border-right:0;border-bottom:1px solid var(--border);overflow-x:auto}.adm-nav div{white-space:nowrap}}
`;
  document.head.appendChild(st);
})();

// ── shell ────────────────────────────────────
const ADM_NAV = [['people', '👥 People'], ['servers', '🌐 Servers'], ['live', '📡 Live'], ['log', '🔨 Bans & Log'], ['send', '📢 Broadcast']];
function admBuild() {
  const ov = $a('admin-panel-modal');
  if (!ov || ov.dataset.v2) return;
  ov.dataset.v2 = '1';
  ov.innerHTML = `<div class="modal adm-box">
    <div class="adm-head"><div class="adm-logo">⚡</div>
      <div style="flex:1"><div style="font-size:15px;font-weight:800">Admin Panel</div>
      <div id="admin-maint-badge" style="display:none;font-size:10px;background:rgba(248,113,113,.2);color:#f87171;border:1px solid rgba(248,113,113,.3);border-radius:99px;padding:1px 8px;width:max-content">🔧 MAINTENANCE MODE</div></div>
      <button class="btn-g" style="padding:5px 11px" onclick="closeM('admin-panel-modal')">✕</button></div>
    <div class="adm-body"><div class="adm-nav">${ADM_NAV.map(([k, l]) => `<div data-k="${k}" onclick="admGo('${k}')">${l}</div>`).join('')}</div>
      <div class="adm-main" id="adm-main"></div></div>
    <div class="adm-foot" id="adm-status">Tip: click a person or a server to manage it.</div>
    <input type="file" id="admin-pfp-file" accept="image/*" style="display:none" onchange="onAdminPfpChange(event)">
    <input type="color" id="adm-color" style="display:none" onchange="admColorPicked(this.value)"></div>`;
}
function openAdminPanel() {
  if (!isPlatformPower()) { toast('No access'); return; }
  admBuild(); admGo(AD.sec || 'people'); openM('admin-panel-modal');
}
function adminTab(t) { admGo({ servers: 'servers', online: 'live', stats: 'live', bans: 'log', audit: 'log', alert: 'send', danger: 'send' }[t] || 'people'); }
function admGo(sec) {
  AD.user = null; AD.svId = null;
  AD.sec = sec;
  document.querySelectorAll('.adm-nav div').forEach(d => d.classList.toggle('on', d.dataset.k === sec));
  const m = $a('adm-main'); if (!m) return;
  if (sec === 'people') { admPeopleShell(); adminLoadAccounts(); }
  else if (sec === 'servers') { admServersShell(); wsSend({ type: 'admin_list_servers' }); }
  else if (sec === 'live') { admLiveShell(); admLiveLoad(); }
  else if (sec === 'log') { admLogShell(); adminLoadBans(); adminLoadFrozen(); adminLoadAuditLog(); }
  else if (sec === 'send') admSendShell();
}
const admLoading = '<div class="adm-sub" style="padding:8px 0">Loading…</div>';

function adminLoadAccounts() { const b = $a('admin-acct-list'); if (b) b.innerHTML = admLoading; wsSend({ type: 'admin_list_accounts' }); }
// ══ PEOPLE ═══════════════════════════════════
function admPeopleShell() {
  if (AD.user) { admUserView(); return; }
  $a('adm-main').innerHTML = `<div class="adm-bar"><input id="admin-acct-search" class="m-inp" placeholder="🔍 Search people…" oninput="adminFilterAccounts()"><button class="btn-g" onclick="adminLoadAccounts()">↻</button></div><div id="admin-acct-list" class="adm-list">${admLoading}</div>`;
  if (typeof _adminAccounts !== 'undefined' && _adminAccounts.length) renderAdminAccounts(_adminAccounts);
}
function adminFilterAccounts() {
  const q = ($a('admin-acct-search')?.value || '').toLowerCase();
  renderAdminAccounts(q ? _adminAccounts.filter(a => a.name.toLowerCase().includes(q)) : _adminAccounts);
}
function renderAdminAccounts(accounts) {
  if (AD.pendingRename && !admAcct(AD.user) && admAcct(AD.pendingRename)) AD.user = AD.pendingRename;
  if (AD.user) { if ($a('adm-main') && AD.sec === 'people') admUserHead(); return; }
  const box = $a('admin-acct-list'); if (!box) return;
  if (!accounts.length) { box.innerHTML = '<div class="adm-sub">No one found.</div>'; return; }
  const sorted = [...accounts].sort((a, b) => (b.online - a.online) || a.name.localeCompare(b.name));
  box.innerHTML = sorted.map(a => `<div class="adm-row" data-n="${esc(a.name)}" onclick="admOpenUser(this.dataset.n)">
    <div class="adm-av" style="background:${esc(a.color || '#5865f2')}">${admAv(a)}</div>
    <div style="flex:1;min-width:0"><div class="adm-nm">${a.online ? '<span class="adm-dot"></span>' : ''}${esc(a.name)}<span class="adm-sub" style="font-family:'DM Mono',monospace">#${a.tag || '0000'}</span>${admBadges(a)}</div>
    <div class="adm-sub">Joined ${admDate(a.createdAt)}</div></div>
    ${admCanAssume(a) ? `<button class="btn-g adm-be" data-n="${esc(a.name)}" onclick="event.stopPropagation();admBe(this.dataset.n)">🎭 Be</button>` : ''}</div>`).join('');
}
function admOpenUser(name) {
  AD.user = name; AD.sec = 'people';
  wsSend({ type: 'admin_list_servers' });
  admUserView();
  wsSend({ type: 'admin_get_notes', target: name });
  wsSend({ type: 'admin_list_user_servers', target: name });
}
function adminViewDMsFor(name) { admBuild(); openM('admin-panel-modal'); AD.sec = 'people'; document.querySelectorAll('.adm-nav div').forEach(d => d.classList.toggle('on', d.dataset.k === 'people')); admOpenUser(name); setTimeout(admDMs, 150); }
function admUserHead() {
  const a = admAcct(AD.user), h = $a('adm-uhead'); if (!h) return;
  if (!a) { h.innerHTML = `<div class="adm-nm" style="font-size:18px">${esc(AD.user)}</div>`; return; }
  h.innerHTML = `<div class="adm-av" style="background:${esc(a.color || '#5865f2')}">${admAv(a)}</div>
    <div style="flex:1;min-width:0"><div class="adm-nm" style="font-size:17px">${a.online ? '<span class="adm-dot"></span>' : ''}${esc(a.name)}<span class="adm-sub">#${a.tag || '0000'}</span>${admBadges(a)}</div>
    <div class="adm-sub">Joined ${admDate(a.createdAt)} · ${a.online ? 'online now' : 'offline'}${a.bio ? ' · “' + esc(a.bio.slice(0, 60)) + '”' : ''}</div></div>
    ${admCanAssume(a) ? `<button class="btn-p adm-be" onclick="admBe(AD.user)">🎭 Be ${esc(a.name)}</button>` : ''}`;
}
function admUserView() {
  const a = admAcct(AD.user) || {};
  const isTop = isSystemAdmin();
  $a('adm-main').innerHTML = `<button class="btn-g adm-back" onclick="AD.user=null;admPeopleShell();adminLoadAccounts()">← All people</button>
  <div class="adm-hero" id="adm-uhead"></div>
  <details class="adm-sec" open><summary>🔨 Moderation</summary><div>
    <div class="adm-line"><select id="adm-ban-dur" class="m-inp" style="max-width:120px"><option>30m</option><option>2h</option><option selected>1d</option><option>7d</option><option>30d</option><option>permanent</option></select><input id="adm-ban-reason" class="m-inp" placeholder="Reason (shown to them)" maxlength="120"><button class="btn-g adm-red" onclick="admBan()">🔨 Ban</button><button class="btn-g" onclick="wsSend({type:'admin_unban',target:AD.user})">✅ Unban</button></div>
    <div class="adm-btns"><button class="btn-g" onclick="admFreeze()">🧊 Freeze (can't post)</button><button class="btn-g" onclick="wsSend({type:'admin_unfreeze_user',target:AD.user})">🔥 Unfreeze</button><button class="btn-g adm-red" onclick="admLogout()">🚪 Force logout</button></div></div></details>
  <details class="adm-sec"><summary>🖼 Profile</summary><div class="adm-btns">
    <button class="btn-g" onclick="admRename()">✏️ Rename</button><button class="btn-g" onclick="admTag()">🏷 Tag</button><button class="btn-g" onclick="$a('adm-color').click()">🎨 Colour</button><button class="btn-g" onclick="admBio()">📝 Bio</button><button class="btn-g" onclick="admPfp()">🖼 Change picture</button><button class="btn-g" onclick="wsSend({type:'admin_wipe_user_pfp',target:AD.user})">🚫 Remove picture</button>
    <button class="btn-g" onclick="openProfilePage(AD.user)">👤 Open profile</button></div></details>
  <details class="adm-sec"><summary>🌐 Servers</summary><div>
    <div id="adm-usv">${admLoading}</div>
    <div class="adm-line"><select id="adm-addsv" class="m-inp"><option value="">Add to server…</option></select><button class="btn-g" onclick="admAddTo()">➕ Add</button></div></div></details>
  <details class="adm-sec"><summary>💬 Messages</summary><div>
    <textarea id="adm-sysdm" class="m-inp" rows="2" maxlength="2000" placeholder="Write a message…" style="resize:vertical"></textarea>
    <div class="adm-btns"><button class="btn-p" onclick="admSysDm()">📨 Send as System DM</button></div>
    <div class="adm-line"><select id="adm-pa-sv" class="m-inp" onchange="admFillCh('adm-pa-sv','adm-pa-ch')"><option value="">Server…</option></select><select id="adm-pa-ch" class="m-inp"><option value="">Channel…</option></select><button class="btn-g" style="color:#c084fc" onclick="admPostAs()">🎭 Post as them</button></div>
    <div class="adm-line"><select id="adm-purge-sv" class="m-inp"><option value="">Server…</option></select><button class="btn-g adm-red" onclick="admPurge()">🧹 Delete all their messages there</button></div></div></details>
  <details class="adm-sec"><summary>🔍 Their DMs</summary><div><div class="adm-btns"><button class="btn-g" onclick="admDMs()">Load DM history</button></div><div id="admin-dm-result" style="max-height:340px;overflow-y:auto"></div></div></details>
  <details class="adm-sec"><summary>📌 Private notes</summary><div><textarea id="adm-note" class="m-inp" rows="2" maxlength="1000" placeholder="Only admins see this…" style="resize:vertical"></textarea><div class="adm-btns"><button class="btn-g" onclick="admNote()">Save note</button></div><div id="adm-notes" style="display:flex;flex-direction:column;gap:4px"></div></div></details>
  <details class="adm-sec danger"><summary>☢️ Account</summary><div class="adm-btns">
    <button class="btn-g" onclick="admPw()">🔑 Reset password</button>
    ${isTop ? `<button class="btn-g" onclick="wsSend({type:'appoint_coadmin',target:AD.user,appoint:true})">⭐ Make Co-Admin</button><button class="btn-g" onclick="wsSend({type:'appoint_coadmin',target:AD.user,appoint:false})">✕ Remove Co-Admin</button>` : ''}
    <button class="btn-g adm-red" onclick="admNuke()">💥 Delete account forever</button></div></details>`;
  admUserHead(); admFillSvSelects();
}
function admFillSvSelects() {
  const svs = typeof _adminServers !== 'undefined' ? _adminServers : [];
  const opts = '<option value="">Server…</option>' + svs.map(s => `<option value="${esc(s.id)}">${esc(s.name)}</option>`).join('');
  ['adm-pa-sv', 'adm-purge-sv'].forEach(id => { const e = $a(id); if (e) { const v = e.value; e.innerHTML = opts; e.value = v; } });
  const e = $a('adm-addsv'); if (e) e.innerHTML = '<option value="">Add to server…</option>' + svs.map(s => `<option value="${esc(s.id)}">${esc(s.name)}</option>`).join('');
}
function admFillCh(svSel, chSel) {
  const s = admSv($a(svSel).value), c = $a(chSel);
  c.innerHTML = '<option value="">Channel…</option>' + (s?.channels || []).filter(x => x.type !== 'voice').map(x => `<option value="${esc(x.id)}"># ${esc(x.name)}</option>`).join('');
}
function admBe(name) {
  const a = admAcct(name);
  if (!a || !admCanAssume(a)) { toast('You can’t be that user'); return; }
  if (!confirm(`Become ${name}? You'll see exactly what they see and everything you do happens as them. Use “Exit” at the top to come back.`)) return;
  admStatus('Switching to ' + name + '…');
  wsSend({ type: 'admin_assume', target: name });
}
function admAssumeStart(msg) {
  try {
    const real = JSON.stringify({ token: S.token, user: S.user });
    sessionStorage.setItem('nx-assume', JSON.stringify({ name: msg.user.name, real }));
    sessionStorage.setItem('nx-session', JSON.stringify({ token: msg.token, user: msg.user }));
  } catch (e) { toast('Could not switch: ' + e.message); return; }
  location.reload();
}
function admBan() {
  const dur = $a('adm-ban-dur').value, reason = $a('adm-ban-reason').value.trim();
  if (!confirm(`Ban ${AD.user} for ${dur}?`)) return;
  wsSend({ type: 'admin_ban', target: AD.user, duration: dur, reason });
}
function admFreeze() { const r = prompt('Reason (shown to them)?', ''); if (r === null) return; wsSend({ type: 'admin_freeze_user', target: AD.user, reason: r.trim() || 'No reason given' }); }
function admLogout() { if (confirm(`Log ${AD.user} out everywhere?`)) wsSend({ type: 'admin_force_logout', target: AD.user }); }
function admRename() {
  const n = prompt(`New username for ${AD.user}:`); if (!n || n === AD.user) return;
  if (!/^[a-zA-Z0-9_.\-]{2,24}$/.test(n)) { admStatus('Invalid username (2–24 letters, numbers, _ . -)', true); return; }
  AD.pendingRename = n; wsSend({ type: 'admin_rename_user', target: AD.user, newName: n }); setTimeout(adminLoadAccounts, 700);
}
function adminRenameUser() { admRename(); }
function admTag() { const t = prompt('New tag for ' + AD.user + ' (e.g. 0042):'); if (t) wsSend({ type: 'admin_set_tag', target: AD.user, tag: t.trim() }); }
function admColorPicked(hex) { wsSend({ type: 'admin_set_color', target: AD.user, color: hex }); setTimeout(adminLoadAccounts, 500); }
function admBio() { const b = prompt('New bio for ' + AD.user + ':', admAcct(AD.user)?.bio || ''); if (b !== null) wsSend({ type: 'admin_set_bio', target: AD.user, bio: b.trim() }); }
function admPfp() { _pfpCropTarget = 'admin_target'; _adminPfpTarget = AD.user; $a('admin-pfp-file').click(); }
function adminSetPfp() { admPfp(); }
function admPw() { const p = prompt('New password for ' + AD.user + ' (min 4 characters):'); if (p && p.length >= 4) wsSend({ type: 'admin_reset_password', target: AD.user, newPassword: p }); else if (p) admStatus('Password too short', true); }
function admNuke() {
  if (prompt(`This permanently deletes ${AD.user} and their data.\nType their name to confirm:`) !== AD.user) { admStatus('Cancelled — name did not match.'); return; }
  wsSend({ type: 'admin_nuke_account', target: AD.user });
  setTimeout(() => { AD.user = null; admPeopleShell(); adminLoadAccounts(); }, 900);
}
function admAddTo() { const id = $a('adm-addsv').value; if (!id) { admStatus('Pick a server first', true); return; } wsSend({ type: 'admin_add_member', target: AD.user, serverId: id }); setTimeout(() => wsSend({ type: 'admin_list_user_servers', target: AD.user }), 500); }
function admKickFrom(id) { if (!confirm(`Remove ${AD.user} from that server?`)) return; wsSend({ type: 'admin_kick_from_server', target: AD.user, serverId: id }); setTimeout(() => wsSend({ type: 'admin_list_user_servers', target: AD.user }), 500); }
function admSysDm() { const t = $a('adm-sysdm').value.trim(); if (!t) { admStatus('Write something first', true); return; } wsSend({ type: 'admin_broadcast_dm', target: AD.user, text: t }); $a('adm-sysdm').value = ''; }
function admPostAs() {
  const ch = $a('adm-pa-ch').value, t = $a('adm-sysdm').value.trim();
  if (!ch) { admStatus('Pick a server and channel', true); return; }
  if (!t) { admStatus('Write the message above first', true); return; }
  wsSend({ type: 'admin_impersonate_send', asUser: AD.user, channelId: ch, text: t }); $a('adm-sysdm').value = '';
}
function admPurge() { const sv = $a('adm-purge-sv').value; if (!sv) { admStatus('Pick a server', true); return; } if (confirm(`Delete ALL of ${AD.user}'s messages in that server?`)) wsSend({ type: 'admin_purge_user_messages', target: AD.user, serverId: sv }); }
function admDMs() { const el = $a('admin-dm-result'); if (el) el.innerHTML = admLoading; wsSend({ type: 'admin_view_dms', target: AD.user }); }
function admNote() { const t = $a('adm-note').value.trim(); if (!t) return; wsSend({ type: 'admin_add_note', target: AD.user, note: t }); $a('adm-note').value = ''; setTimeout(() => wsSend({ type: 'admin_get_notes', target: AD.user }), 400); }
function renderAdminNotes(target, notes) {
  const box = $a('adm-notes'); if (!box) return;
  box.innerHTML = notes.length ? notes.map((n, i) => `<div class="adm-note"><div style="display:flex;justify-content:space-between;color:var(--t3);font-size:10px;margin-bottom:2px"><span>${esc(n.by || '?')} · ${n.at ? new Date(n.at).toLocaleString('en', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : ''}</span><span style="cursor:pointer;color:var(--red)" onclick="adminDeleteNote(AD.user,${i})">✕</span></div>${esc(n.text || '')}</div>`).join('') : '<div class="adm-sub">No notes yet.</div>';
}
function renderAdminUserServers(target, servers) {
  const box = $a('adm-usv'); if (!box) return;
  box.innerHTML = servers.length ? servers.map(s => `<div class="adm-card" style="display:flex;align-items:center;gap:8px"><b style="flex:1">${esc(s.name)}</b><span class="adm-sub">owner: ${esc(s.ownerId || '?')}</span><button class="btn-g adm-red" style="font-size:11px" data-id="${esc(s.id)}" onclick="admKickFrom(this.dataset.id)">Remove</button></div>`).join('') : `<div class="adm-sub">${esc(target)} isn't in any servers.</div>`;
}
function admShowDMs(msg) {
  const el = $a('admin-dm-result'); if (!el) return;
  const dms = msg.dms || [];
  el.innerHTML = dms.length ? dms.map(d => `<div class="adm-card" style="margin-bottom:8px"><div style="display:flex;align-items:center;margin-bottom:5px"><b style="flex:1">💬 with ${esc(d.name)}</b><button class="btn-g adm-red" style="font-size:10px" data-b="${esc(d.name)}" onclick="admDelDm(this)">🗑 Delete thread</button></div>
    ${(d.messages || []).slice(-20).map(m => `<div class="adm-msg"><b style="min-width:70px;color:var(--t2)">${esc(m.author || '?')}</b><span class="t">${esc(m.text || '[attachment]')}</span></div>`).join('') || '<div class="adm-sub">No messages</div>'}</div>`).join('') : '<div class="adm-sub">No DM conversations.</div>';
}
function admDelDm(btn) { const b = btn.dataset.b; if (!confirm(`Delete the whole DM thread between ${AD.user} and ${b}?`)) return; wsSend({ type: 'admin_delete_dm_history', userA: AD.user, userB: b }); btn.closest('.adm-card').remove(); }

// ══ SERVERS ══════════════════════════════════
function admServersShell() {
  if (AD.svId) { admSvView(); return; }
  $a('adm-main').innerHTML = `<div class="adm-bar"><input id="admin-sv-search" class="m-inp" placeholder="🔍 Search by name or owner…" oninput="adminFilterServers()"><button class="btn-g" onclick="wsSend({type:'admin_list_servers'})">↻</button></div><div id="admin-sv-list" class="adm-list">${admLoading}</div>`;
  if (typeof _adminServers !== 'undefined' && _adminServers.length) renderAdminServers(_adminServers);
}
function adminLoadServers() { wsSend({ type: 'admin_list_servers' }); }
function adminFilterServers() {
  const q = ($a('admin-sv-search')?.value || '').toLowerCase();
  renderAdminServers(q ? _adminServers.filter(s => (s.name || '').toLowerCase().includes(q) || (s.ownerId || '').toLowerCase().includes(q)) : _adminServers);
}
function renderAdminServers(servers) {
  if (AD.sec !== 'servers') { if (AD.user) admFillSvSelects(); return; }
  if (AD.svId) { admSvView(); return; }
  const box = $a('admin-sv-list'); if (!box) return;
  box.innerHTML = servers.length ? servers.map(s => `<div class="adm-row" data-id="${esc(s.id)}" onclick="admOpenSv(this.dataset.id)">
    <div class="adm-av" style="background:var(--accent)">${esc((s.name || '?')[0].toUpperCase())}</div>
    <div style="flex:1;min-width:0"><div class="adm-nm">${esc(s.name)}${s.isPublic === false ? '<i class="adm-b adm-b3">🔒 private</i>' : ''}</div>
    <div class="adm-sub">Owner ${esc(s.ownerId || '?')} · ${s.memberCount || 0} members · ${s.channelCount || 0} channels · ${admDate(s.createdAt)}</div></div></div>`).join('') : '<div class="adm-sub">No servers found.</div>';
}
function admOpenSv(id) { AD.svId = id; admSvView(); }
function admSvView() {
  const s = admSv(AD.svId);
  if (!s) { AD.svId = null; admServersShell(); return; }
  const chs = s.channels || [];
  $a('adm-main').innerHTML = `<button class="btn-g adm-back" onclick="AD.svId=null;AD.chId=null;admServersShell()">← All servers</button>
  <div class="adm-hero"><div class="adm-av" style="background:var(--accent)">${esc((s.name || '?')[0].toUpperCase())}</div><div style="flex:1"><div class="adm-nm" style="font-size:17px">${esc(s.name)}</div><div class="adm-sub">Owner ${esc(s.ownerId || '?')} · ${s.memberCount || 0} members · ${s.isPublic === false ? 'private' : 'public'}${s.desc ? ' · ' + esc(s.desc.slice(0, 60)) : ''}</div></div></div>
  <div class="adm-btns" style="margin-bottom:6px"><button class="btn-g" onclick="admSvRename()">✏️ Rename</button><button class="btn-g" onclick="admSvDesc()">📝 Description</button><button class="btn-g" onclick="admSvPublic(${s.isPublic === false})">${s.isPublic === false ? '🌐 Make public' : '🔒 Make private'}</button><button class="btn-g" onclick="adminTransferOwnership(AD.svId);admSvRefresh()">↗ Transfer</button><button class="btn-g" onclick="admSvClone()">🧬 Clone</button><button class="btn-g adm-red" onclick="admSvDelete()">🗑 Delete</button></div>
  <div class="adm-h">Channels</div><div class="adm-list">${chs.map(c => `<div class="adm-card" style="display:flex;align-items:center;gap:6px;flex-wrap:wrap" data-c="${esc(c.id)}" data-n="${esc(c.name)}"><b style="flex:1;min-width:90px">${c.type === 'voice' ? '🔊' : '#'} ${esc(c.name)}</b>
    <button class="btn-g" style="font-size:11px" onclick="admChView(this.parentNode)">👁 View</button><button class="btn-g" style="font-size:11px" title="Lock" onclick="admChLock(this.parentNode,true)">🔒</button><button class="btn-g" style="font-size:11px" title="Unlock" onclick="admChLock(this.parentNode,false)">🔓</button><button class="btn-g" style="font-size:11px" title="Slowmode" onclick="admChSlow(this.parentNode)">🐌</button><button class="btn-g" style="font-size:11px" title="Export JSON" onclick="admChExport(this.parentNode)">⬇️</button><button class="btn-g adm-red" style="font-size:11px" title="Wipe history" onclick="admChWipe(this.parentNode)">🧹</button><button class="btn-g adm-red" style="font-size:11px" title="Delete channel" onclick="admChDel(this.parentNode)">✕</button></div>`).join('') || '<div class="adm-sub">No channels.</div>'}</div>
  <div class="adm-line" style="margin-top:6px"><input id="adm-newch" class="m-inp" placeholder="new-channel-name"><select id="adm-newch-t" class="m-inp" style="max-width:90px;flex:0"><option value="text">text</option><option value="voice">voice</option></select><button class="btn-p" onclick="admChAdd()">➕ Add channel</button></div>
  <div class="adm-h">Members</div><div class="adm-line"><select id="adm-mem" class="m-inp">${(_adminAccounts || []).map(a => `<option>${esc(a.name)}</option>`).join('')}</select><button class="btn-g" onclick="admMem('admin_add_member')">➕ Add</button><button class="btn-g adm-red" onclick="admMem('admin_kick_from_server')">👢 Kick</button></div>
  <div id="admin-ch-view-result" style="display:none;margin-top:12px"></div>`;
  if (!(_adminAccounts || []).length) wsSend({ type: 'admin_list_accounts' });
}
function admSvRefresh() { setTimeout(() => wsSend({ type: 'admin_list_servers' }), 600); }
function admSvRename() { const n = prompt('New server name:', admSv(AD.svId)?.name || ''); if (n && n.trim()) { wsSend({ type: 'admin_rename_server', serverId: AD.svId, name: n.trim() }); admSvRefresh(); } }
function admSvDesc() { const d = prompt('Server description:', admSv(AD.svId)?.desc || ''); if (d !== null) { wsSend({ type: 'admin_set_server_desc', serverId: AD.svId, desc: d.trim() }); admSvRefresh(); } }
function admSvPublic(v) { wsSend({ type: 'admin_set_server_public', serverId: AD.svId, isPublic: v }); admSvRefresh(); }
function admSvClone() { const n = prompt('Name for the clone:', (admSv(AD.svId)?.name || '') + ' (copy)'); if (n && n.trim()) { wsSend({ type: 'admin_clone_server', serverId: AD.svId, name: n.trim() }); admSvRefresh(); } }
function admSvDelete() { adminForceDeleteServer(AD.svId); AD.svId = null; admServersShell(); admSvRefresh(); }
function admChAdd() { const n = $a('adm-newch').value.trim().toLowerCase().replace(/\s+/g, '-'); if (!n) { admStatus('Give the channel a name', true); return; } wsSend({ type: 'admin_add_channel', serverId: AD.svId, name: n, chType: $a('adm-newch-t').value }); admSvRefresh(); }
function admMem(type) { wsSend({ type, target: $a('adm-mem').value, serverId: AD.svId }); admSvRefresh(); }
function admChView(el) { AD.chId = el.dataset.c; AD.chName = el.dataset.n; const b = $a('admin-ch-view-result'); b.style.display = 'block'; b.innerHTML = admLoading; wsSend({ type: 'admin_view_channel', channelId: AD.chId }); }
function admChLock(el, locked) { wsSend({ type: 'admin_lock_channel', channelId: el.dataset.c, locked }); }
function admChSlow(el) { const s = prompt('Slowmode seconds (0 = off):', '0'); if (s !== null) wsSend({ type: 'admin_set_slowmode', channelId: el.dataset.c, seconds: Math.max(0, Math.min(3600, parseInt(s) || 0)) }); }
function admChExport(el) { wsSend({ type: 'admin_export_channel', channelId: el.dataset.c }); }
function admChWipe(el) { if (confirm(`Wipe ALL history in #${el.dataset.n}?`)) wsSend({ type: 'admin_wipe_channel', channelId: el.dataset.c }); }
function admChDel(el) { if (confirm(`Delete channel #${el.dataset.n}?`)) { wsSend({ type: 'admin_delete_channel', serverId: AD.svId, channelId: el.dataset.c }); admSvRefresh(); } }
function admShowChannel(msg) {
  const box = $a('admin-ch-view-result'); if (!box) return;
  AD.chId = msg.channelId || AD.chId;
  const ms = (msg.messages || []).slice(-80);
  box.style.display = 'block';
  box.innerHTML = `<div class="adm-h" style="margin-top:0">#${esc(AD.chName || 'channel')} — last ${ms.length} message(s)</div><div class="adm-card" style="max-height:300px;overflow-y:auto">` + (ms.length ? ms.map(m => `<div class="adm-msg" data-m="${esc(m.id || '')}">
    <b style="color:${esc(m.authorColor || 'var(--accent)')}">${esc(m.author || '?')}</b><span class="adm-sub">${m.ts ? new Date(m.ts).toLocaleTimeString('en', { hour: '2-digit', minute: '2-digit' }) : ''}</span>
    <span class="t">${esc((m.text || '').slice(0, 300))}${(m.attachments || []).length ? ' <i class="adm-sub">[attachment]</i>' : ''}</span>
    ${m.id ? `<span style="cursor:pointer" title="Edit" onclick="admMsgEdit(this.parentNode)">✎</span><span style="cursor:pointer;color:var(--red)" title="Delete" onclick="admMsgDel(this.parentNode)">🗑</span>` : ''}</div>`).join('') : '<div class="adm-sub">No messages.</div>') + '</div>';
}
function admMsgDel(el) { if (!confirm('Delete this message?')) return; wsSend({ type: 'admin_delete_message', channelId: AD.chId, messageId: el.dataset.m }); el.remove(); }
function admMsgEdit(el) { const t = prompt('Replace the text with:', el.querySelector('.t').textContent.trim()); if (t === null) return; wsSend({ type: 'admin_edit_message', channelId: AD.chId, messageId: el.dataset.m, text: t }); setTimeout(() => wsSend({ type: 'admin_view_channel', channelId: AD.chId }), 500); }

// ══ LIVE ═════════════════════════════════════
function admLiveShell() {
  $a('adm-main').innerHTML = `<div class="adm-bar" style="justify-content:space-between"><b>Right now</b><button class="btn-g" onclick="admLiveLoad()">↻ Refresh</button></div>
  <div id="admin-stats-grid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(120px,1fr));gap:8px">${admLoading}</div><div id="admin-stats-meta" class="adm-sub" style="margin-top:6px;font-family:'DM Mono',monospace"></div>
  <div class="adm-h">Voice calls (join silently)</div><div id="admin-calls-list" class="adm-list">${admLoading}</div>
  <div class="adm-h">Online users</div><div id="admin-online-list" class="adm-list">${admLoading}</div>`;
}
function admLiveLoad() { wsSend({ type: 'admin_get_stats' }); wsSend({ type: 'admin_list_online' }); wsSend({ type: 'admin_list_calls' }); if (!(_adminAccounts || []).length) wsSend({ type: 'admin_list_accounts' }); }
function adminLoadOnline() { wsSend({ type: 'admin_list_online' }); wsSend({ type: 'admin_list_calls' }); }
function renderAdminOnline(users) {
  const box = $a('admin-online-list'); if (!box) return;
  box.innerHTML = users.length ? users.map(u => { const a = admAcct(u.name) || u; return `<div class="adm-row" data-n="${esc(u.name)}" onclick="admOpenUserFrom(this.dataset.n)"><span class="adm-dot"></span><div style="flex:1" class="adm-nm">${esc(u.name || '?')}<span class="adm-sub">#${u.tag || '0000'}</span>${admBadges(u)}</div>${admCanAssume(a) ? `<button class="btn-g adm-be" data-n="${esc(u.name)}" onclick="event.stopPropagation();admBe(this.dataset.n)">🎭 Be</button>` : ''}</div>`; }).join('') : '<div class="adm-sub">Nobody online.</div>';
}
function admOpenUserFrom(n) { admGo('people'); admOpenUser(n); }

// ══ BANS & LOG ═══════════════════════════════
function admLogShell() {
  $a('adm-main').innerHTML = `<div class="adm-h" style="margin-top:0">Ban someone</div><div class="adm-line"><input id="adm-lb-u" class="m-inp" placeholder="Username" maxlength="24"><select id="adm-lb-d" class="m-inp" style="max-width:110px;flex:0"><option>30m</option><option>2h</option><option selected>1d</option><option>7d</option><option>30d</option><option>permanent</option></select><input id="adm-lb-r" class="m-inp" placeholder="Reason" maxlength="120"><button class="btn-g adm-red" onclick="admQuickBan()">🔨 Ban</button></div>
  <div class="adm-h">Active bans</div><div id="admin-bans-list" class="adm-list">${admLoading}</div>
  <div class="adm-h">Frozen accounts</div><div id="admin-frozen-list" class="adm-list">${admLoading}</div>
  <div class="adm-h" style="display:flex;justify-content:space-between;align-items:center">Audit log <span class="adm-btns"><button class="btn-g" style="font-size:10px" onclick="adminLoadAuditLog()">↻</button><button class="btn-g adm-red" style="font-size:10px" onclick="adminClearAuditLog()">Clear</button></span></div><div id="admin-audit-list" class="adm-list">${admLoading}</div>`;
}
function admQuickBan() {
  const t = $a('adm-lb-u').value.trim(); if (!t) { admStatus('Enter a username', true); return; }
  const d = $a('adm-lb-d').value; if (!confirm(`Ban ${t} for ${d}?`)) return;
  wsSend({ type: 'admin_ban', target: t, duration: d, reason: $a('adm-lb-r').value.trim() }); setTimeout(adminLoadBans, 500);
}

// ══ BROADCAST ════════════════════════════════
function admSendShell() {
  $a('adm-main').innerHTML = `<details class="adm-sec" open><summary>📢 Popup alert to everyone</summary><div><input id="admin-alert-title" class="m-inp" placeholder="Title" maxlength="80"><textarea id="admin-alert-body" class="m-inp" rows="2" maxlength="500" placeholder="Message" style="resize:vertical"></textarea><div class="adm-btns"><button class="btn-p" onclick="adminSendAlert()">Send alert</button></div><div id="admin-alert-result" class="adm-sub"></div></div></details>
  <details class="adm-sec"><summary>📣 Announcement (unread badge)</summary><div><textarea id="admin-announce-text" class="m-inp" rows="2" maxlength="500" placeholder="Text" style="resize:vertical"></textarea><div class="adm-btns"><button class="btn-p" onclick="adminSendAnnouncement()">Send to all</button></div></div></details>
  <details class="adm-sec"><summary>✉️ Mass DM everyone</summary><div><textarea id="admin-massdm-text" class="m-inp" rows="2" maxlength="2000" placeholder="Message" style="resize:vertical"></textarea><div class="adm-btns"><button class="btn-g adm-red" onclick="adminMassDm()">Send mass DM</button></div></div></details>
  <details class="adm-sec"><summary>🗒 Message of the day</summary><div><textarea id="admin-motd-text" class="m-inp" rows="2" maxlength="500" placeholder="Message of the day" style="resize:vertical"></textarea><div class="adm-btns"><button class="btn-p" onclick="adminSetMotd()">💾 Save</button><button class="btn-g" onclick="adminClearMotd()">✕ Clear</button></div><div id="admin-motd-result" class="adm-sub"></div></div></details>
  <details class="adm-sec danger"><summary>🔧 Maintenance mode</summary><div><div class="adm-sub">Blocks everyone except admins.</div><div class="adm-btns"><button class="btn-g adm-red" onclick="adminSetMaintenance(true)">Enable</button><button class="btn-g" onclick="adminSetMaintenance(false)">Disable</button></div></div></details>`;
}
