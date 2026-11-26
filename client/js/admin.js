// ══════════════════════════════════════════════
// ADMIN SYSTEM
// ══════════════════════════════════════════════
function isSystemAdmin() { return S.user?.systemRole === 'admin'; }
function isCoAdmin()     { return S.user?.coAdmin === true; }
function isPlatformPower() { return isSystemAdmin() || isCoAdmin(); }

// Admin has mod powers in ANY server
function hasPlatformModPower(sv) {
  if (!sv) return false;
  return isPlatformPower();
}

function openAdminPanel() {
  if (!isPlatformPower()) { toast('No access'); return; }
  adminTab('users');
  openM('admin-panel-modal');
}

function adminTab(tab) {
  const tabs = ['users','accounts','servers','bans','messages','dms','online','audit','stats','alert','danger'];
  document.querySelectorAll('#admin-panel-modal .sv-stg-tab').forEach((el, i) => {
    el.classList.toggle('active', tabs[i] === tab);
  });
  document.querySelectorAll('#admin-panel-modal .sv-stg-pane').forEach(el => el.classList.remove('active'));
  document.getElementById('admin-pane-' + tab).classList.add('active');
  if (tab === 'accounts') adminLoadAccounts();
  if (tab === 'servers')  adminLoadServers();
  if (tab === 'bans')   { adminLoadBans(); adminLoadFrozen(); }
  if (tab === 'online')   adminLoadOnline();
  if (tab === 'audit')    adminLoadAuditLog();
  if (tab === 'stats')    adminLoadStats();
}

let _adminAccounts = [];
function adminLoadAccounts() {
  const box = document.getElementById('admin-acct-list');
  box.innerHTML = '<div style="font-size:12px;color:var(--t3);padding:8px 0">Loading...</div>';
  wsSend({ type: 'admin_list_accounts' });
}
function adminFilterAccounts() {
  const q = (document.getElementById('admin-acct-search')?.value || '').toLowerCase();
  const filtered = q ? _adminAccounts.filter(a => a.name.toLowerCase().includes(q)) : _adminAccounts;
  renderAdminAccounts(filtered);
}
function renderAdminAccounts(accounts) {
  const box = document.getElementById('admin-acct-list');
  if (!box) return;
  if (!accounts.length) { box.innerHTML = '<div style="font-size:12px;color:var(--t3);padding:8px 0">No accounts found.</div>'; return; }
  box.innerHTML = accounts.map(a => {
    const avBg = a.color || '#5865f2';
    const avContent = a.pfp
      ? `<img src="${a.pfp}" style="width:100%;height:100%;object-fit:cover;border-radius:50%">`
      : `<span style="font-size:13px;font-weight:700;color:#fff">${esc(a.name[0]?.toUpperCase()||'?')}</span>`;
    const roleBadge = a.systemRole === 'admin'
      ? `<span style="font-size:9px;background:rgba(88,101,242,.2);color:var(--accent);border:1px solid rgba(88,101,242,.3);border-radius:99px;padding:1px 6px;font-weight:700">⚡ Admin</span>`
      : a.coAdmin
        ? `<span style="font-size:9px;background:rgba(52,211,153,.15);color:var(--green);border:1px solid rgba(52,211,153,.3);border-radius:99px;padding:1px 6px;font-weight:700">★ Co-Admin</span>` : '';
    const frozenBadge = a.frozen
      ? `<span style="font-size:9px;background:rgba(96,165,250,.1);color:#60a5fa;border:1px solid rgba(96,165,250,.3);border-radius:99px;padding:1px 6px">🧊 Frozen</span>` : '';
    const onlineDot = a.online
      ? `<span style="display:inline-block;width:7px;height:7px;border-radius:50%;background:var(--green);flex-shrink:0"></span>` : '';
    const joined = a.createdAt ? new Date(a.createdAt).toLocaleDateString('en',{month:'short',day:'numeric',year:'numeric'}) : '?';
    return `<div style="display:flex;align-items:center;gap:8px;background:var(--s3);border:1px solid var(--border);border-radius:8px;padding:7px 10px">
      <div style="width:34px;height:34px;border-radius:50%;background:${avBg};display:flex;align-items:center;justify-content:center;flex-shrink:0;overflow:hidden;cursor:pointer" onclick="openProfilePage('${esc(a.name)}')">${avContent}</div>
      <div style="flex:1;min-width:0;cursor:pointer" onclick="openProfilePage('${esc(a.name)}')">
        <div style="font-size:13px;font-weight:700;display:flex;align-items:center;gap:4px;flex-wrap:wrap">
          ${onlineDot}${esc(a.name)}<span style="font-size:10px;color:var(--t3);font-family:'DM Mono',monospace">#${a.tag||'0000'}</span>${roleBadge}${frozenBadge}
        </div>
        <div style="font-size:10px;color:var(--t3);margin-top:1px">Joined ${joined}</div>
      </div>
      <div style="display:flex;gap:3px;flex-shrink:0">
        <button class="btn-g" style="font-size:10px;padding:3px 7px" title="View DM history" onclick="adminViewDMsFor('${esc(a.name)}')">💬 DMs</button>
        <button class="btn-g" style="font-size:10px;padding:3px 7px" title="Target in Users tab" onclick="document.getElementById('admin-user-in').value='${esc(a.name)}';adminTab('users');_adminResult('Targeting ${esc(a.name)} — use actions below.','var(--accent)')">Target →</button>
      </div>
    </div>`;
  }).join('');
}

function adminViewDMsFor(username) {
  document.getElementById('admin-dm-user').value = username;
  adminTab('dms');
  adminViewDMs();
}
function adminAppointCoadmin(appoint) {
  if (!isSystemAdmin()) { toast('Only Puck can appoint Co-Admins'); return; }
  const target = document.getElementById('admin-user-in').value.trim();
  if (!target) { toast('Enter a username'); return; }
  wsSend({ type: 'appoint_coadmin', target, appoint });
}

function adminBanUser() {
  if (!isPlatformPower()) { toast('No access'); return; }
  const target = document.getElementById('admin-ban-user').value.trim();
  const duration = document.getElementById('admin-ban-dur').value.trim() || '1d';
  const reason = document.getElementById('admin-ban-reason').value.trim();
  if (!target) { toast('Enter a username'); return; }
  if (!confirm('Ban ' + target + ' for ' + duration + '?')) return;
  wsSend({ type: 'admin_ban', target, duration, reason });
}

function adminUnbanUser() {
  if (!isPlatformPower()) { toast('No access'); return; }
  const target = document.getElementById('admin-ban-user').value.trim();
  if (!target) { toast('Enter a username'); return; }
  wsSend({ type: 'admin_unban', target });
}

function adminViewDMs() {
  if (!isPlatformPower()) { toast('No access'); return; }
  const target = document.getElementById('admin-dm-user').value.trim();
  if (!target) { toast('Enter a username'); return; }
  document.getElementById('admin-dm-result').textContent = 'Loading…';
  wsSend({ type: 'admin_view_dms', target });
}

function adminDeleteServerByInput() {
  if (!isPlatformPower()) { toast('No access'); return; }
  const sid = document.getElementById('admin-user-in').value.trim();
  if (!sid) { toast('Enter a server ID'); return; }
  if (!confirm('Delete server ' + sid + '? This cannot be undone.')) return;
  wsSend({ type: 'admin_delete_server', serverId: sid });
}

// Admin can delete any server from the dropdown (bypasses ownership check)
function adminForceDeleteServer(serverId) {
  if (!isPlatformPower()) return;
  if (!confirm('Force-delete this server? This cannot be undone.')) return;
  wsSend({ type: 'admin_delete_server', serverId });
  const sv = S.servers.find(s => s.id === serverId);
  if (sv) { (sv.channels||[]).forEach(ch => delete S.messages[ch.id]); S.servers = S.servers.filter(s => s.id !== serverId); persist(); renderSvs(); }
  if (S.curSv?.id === serverId) { S.curSv = null; S.curCh = null; showWelcome(); }
}

// Admin ban from member context menu (with duration picker)
function adminCtxBan() {
  if (!isPlatformPower() || !ctxTargetMember) return;
  document.getElementById('member-ctx').style.display = 'none';
  const dur = prompt('Ban duration (e.g. 1h, 7d, permanent):', '1d');
  if (!dur) return;
  const reason = prompt('Reason (optional):') || '';
  wsSend({ type: 'admin_ban', target: ctxTargetMember, duration: dur, reason });
}

function getMemberRole(sv, memberName) {
  if (!sv) return 'member';
  // Case-insensitive owner check — ownerId may be display name, memberName may vary
  if (sv.ownerId && sv.ownerId.toLowerCase() === (memberName || '').toLowerCase()) return 'owner';
  return (sv.memberRoles || {})[memberName] || 'member';
}

function roleLabel(sv, memberName) {
  const id = getMemberRole(sv, memberName); if (id === 'member') return '';
  const r = getEffectiveRole(sv, id); if (!r) return '';
  const c = pfHex(r.color, '#9090a8'), ic = r.icon ? esc(r.icon) : (id === 'owner' ? '👑' : id === 'mod' ? '🛡' : '●');
  return `<span class="role-badge" style="background:${c}22;color:${c};border:1px solid ${c}44">${ic} ${esc(r.name)}</span>`;
}

// ── Server header dropdown ──
function toggleSvDropdown(e) {
  e.stopPropagation();
  if (!S.curSv) return;
  const dd = document.getElementById('sv-dropdown');
  if (dd.classList.contains('open')) { dd.classList.remove('open'); return; }
  buildSvDropdown();
  dd.classList.add('open');
}

function buildSvDropdown() {
  const sv = S.curSv; if (!sv) return;
  const myRole = getMyRole(sv);
  const isOwner = myRole === 'owner';
  const isMod   = myRole === 'mod' || isOwner;
  const dd = document.getElementById('sv-dropdown');
  dd.innerHTML = '';

  const item = (icon, label, fn, danger=false) => {
    const d = document.createElement('div');
    d.className = 'sv-dd-item' + (danger ? ' danger' : '');
    d.innerHTML = `${icon}<span>${label}</span>`;
    d.onclick = () => { dd.classList.remove('open'); fn(); };
    dd.appendChild(d);
  };
  const sep = () => { const d=document.createElement('div'); d.className='sv-dd-sep'; dd.appendChild(d); };
  const sec = (t) => { const d=document.createElement('div'); d.className='sv-dd-section'; d.textContent=t; dd.appendChild(d); };

  sec('Server');
  item(`<svg width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M19.07 4.93a10 10 0 0 1 0 14.14M4.93 4.93a10 10 0 0 0 0 14.14"/></svg>`, 'Mark as Read', ()=>toast('✅ All caught up'));

  if (isMod) {
    sep(); sec('Moderation');
    item(`<svg width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`, 'Manage Members', ()=>openSvSettings('members'));
    if (hasPerm(sv,'manage_channels'))
      item(`<svg width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>`, 'Add Channel', ()=>openM('ach'));
  }

  if (isOwner) {
    sep(); sec('Owner');
    item(`<svg width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>`, 'Server Settings', ()=>openSvSettings('overview'));
    item(`<svg width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z"/></svg>`, 'Manage Roles', ()=>openSvSettings('roles'));
    item(`<svg width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>`, 'Invite Link', ()=>showInviteModal());
    item(`<svg width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polygon points="23 7 16 12 23 17 23 7"/><rect x="1" y="5" width="15" height="14" rx="2" ry="2"/></svg>`, 'Shorts Feed', ()=>openShorts(sv.id, S.curCh?.id||null, S.curCh?.name||''));
    item(`<svg width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><path d="M8 14s1.5 2 4 2 4-2 4-2"/><line x1="9" y1="9" x2="9.01" y2="9"/><line x1="15" y1="9" x2="15.01" y2="9"/></svg>`, 'Custom Emojis', ()=>openCustomEmojis());
    sep();
    item(`<svg width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4h6v2"/></svg>`, 'Delete Server', ()=>deleteServer(), true);
  }

  if (!isOwner) {
    sep();
    item(`<svg width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>`, 'Leave Server', ()=>leaveServer(), true);
  }
  // Platform admin/co-admin can force-delete any server
  if (isPlatformPower() && !isOwner) {
    sep();
    item(`<svg width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/><path d="M9 6V4h6v2"/></svg>`, '⚡ Force Delete Server', ()=>adminForceDeleteServer(sv.id), true);
  }
}

// ── Open server settings at a specific tab ──
function openSvSettings(tab) {
  const sv = S.curSv; if (!sv) return;
  // Populate overview
  const iconEl = document.getElementById('stg-sv-icon');
  if (sv.icon) iconEl.innerHTML = `<img src="${sv.icon}" style="width:100%;height:100%;object-fit:cover">`;
  else { iconEl.textContent = svInit(sv.name); iconEl.style.background = sv.color; iconEl.style.color = '#fff'; }
  stgIconData = null;
  document.getElementById('stg-sv-name').value = sv.name;
  document.getElementById('stg-sv-desc').value = sv.desc || '';
  // Build color picker
  const colorGrid = document.getElementById('stg-sv-color-grid');
  colorGrid.innerHTML = COLORS.map(c =>
    `<div style="width:28px;height:28px;border-radius:50%;background:${c};cursor:pointer;border:3px solid ${c===(sv._pendingColor||sv.color)?'#fff':'transparent'};transition:border .1s" onclick="selectSvColor('${c}',this)"></div>`
  ).join('');
  sv._pendingColor = sv.color; // init pending to current
  setSvVis(sv.isPublic ? 'public' : 'private', true);
  buildRolesPane();
  buildMembersPane();
  svStgTab(tab);
  openM('sv-settings');
}

function svStgTab(tab) {
  document.querySelectorAll('.sv-stg-tab').forEach((el,i)=>{
    const tabs=['overview','roles','members'];
    el.classList.toggle('active', tabs[i]===tab);
  });
  document.querySelectorAll('.sv-stg-pane').forEach(el=>el.classList.remove('active'));
  document.getElementById('pane-'+tab).classList.add('active');
}

async function onStgIcon(e) {
  const f=e.target.files[0]; if(!f) return;
  const raw = await toUrl(f);
  try {
    stgIconData = await compressImage(raw, IMG_LIMITS.icon);
  } catch(err) {
    toast('⚠️ Server icon is too large. Try a simpler image.'); return;
  }
  const el=document.getElementById('stg-sv-icon');
  el.innerHTML=`<img src="${stgIconData}" style="width:100%;height:100%;object-fit:cover">`;
}

function selectSvColor(color, el) {
  if (S.curSv) S.curSv._pendingColor = color;
  document.querySelectorAll('#stg-sv-color-grid div').forEach(d => d.style.border = '3px solid transparent');
  el.style.border = '3px solid #fff';
}

function setSvVis(v, silent=false) {
  document.getElementById('vis-public').classList.toggle('sel', v==='public');
  document.getElementById('vis-private').classList.toggle('sel', v==='private');
  if (S.curSv) S.curSv._pendingVis = v; // always set so saveSvOverview reads correctly
}

function saveSvOverview() {
  const sv = S.curSv; if (!sv || (sv.ownerId||'').toLowerCase() !== (S.user.name||'').toLowerCase()) return;
  const name = document.getElementById('stg-sv-name').value.trim();
  if (!name) { toast('Server name cannot be empty'); return; }
  sv.name = name;
  sv.desc = document.getElementById('stg-sv-desc').value.trim();
  sv.isPublic = sv._pendingVis !== 'private';
  if (sv._pendingColor) sv.color = sv._pendingColor;
  if (stgIconData) sv.icon = stgIconData;
  persist(); renderSvs(); document.getElementById('sv-nm').textContent = sv.name;
  const visLabel = sv.isPublic ? '🌐 Public' : '🔒 Private';
  toast('✅ Server updated — ' + visLabel);
  closeM('sv-settings');
  wsSend({type:'server_update', serverId:sv.id, name:sv.name, desc:sv.desc, icon:sv.icon||null, color:sv.color, isPublic:sv.isPublic, memberCount:sv.memberCount||1, createdAt:sv.createdAt||Date.now(), channels:sv.channels||[], ownerId:sv.ownerId});
  // If made public, also re-announce so relay's in-memory map is updated immediately
  if (sv.isPublic) {
    wsSend({type:'announce_servers', servers:[{id:sv.id, name:sv.name, desc:sv.desc||'', icon:sv.icon||null, color:sv.color, memberCount:sv.memberCount||1, createdAt:sv.createdAt||Date.now(), channels:sv.channels||[], ownerId:sv.ownerId}]});
  }
}

// ── ROLES PANE ──
const RE = { color: '#9090a8', color2: '#9090a8', fx: 'none', icon: '', hoist: false, owner: false };
const ROLE_PRESETS = [
  { n: 'Staff',   color: '#f59e0b', color2: '#f59e0b', fx: 'glow',     icon: '🛡', hoist: true },
  { n: 'VIP',     color: '#fbbf24', color2: '#f472b6', fx: 'gradient', icon: '✨', hoist: true },
  { n: 'Legend',  color: '#00f5a0', color2: '#00d9f5', fx: 'shimmer',  icon: '💎', hoist: true },
  { n: 'Rainbow', color: '#ff5f6d', color2: '#4facfe', fx: 'rainbow',  icon: '🌈', hoist: false },
  { n: 'Regular', color: '#c9cdd6', color2: '#c9cdd6', fx: 'none',     icon: '',   hoist: false },
  { n: 'Newbie',  color: '#8b8d94', color2: '#8b8d94', fx: 'none',     icon: '',   hoist: false },
];
function buildRolesPane() {
  const sv = S.curSv; if (!sv) return;
  if (!sv.roles) sv.roles = [];
  const list = document.getElementById('stg-roles-list');
  const ids = ['owner', 'mod', ...sv.roles.map(r => r.id), 'member']; // top to bottom = highest to lowest
  list.innerHTML = ids.map(id => {
    const r = getEffectiveRole(sv, id); if (!r) return '';
    const at = roleFxAttrs(r), builtin = DEFAULT_ROLES.some(d => d.id === id), ci = sv.roles.findIndex(x => x.id === id), eid = esc(id);
    const count = id === 'owner' ? 1 :
      Object.values(sv.memberRoles || {}).filter(v => v === id).length + (id === 'member' ? ((S.members[sv.id] || []).length + 1 - Object.keys(sv.memberRoles || {}).length) : 0);
    const mv = ci >= 0 ? `<div class="role-act-btn" onclick="moveRole('${eid}',-1)" title="Move up (higher in the list)">▲</div><div class="role-act-btn" onclick="moveRole('${eid}',1)" title="Move down">▼</div>` : '';
    const del = !builtin ? `<div class="role-act-btn del" onclick="deleteRole('${eid}')" title="Delete">🗑</div>` : '';
    return `<div class="role-row">
      <div class="role-dot" style="background:${pfHex(r.color, '#9090a8')}"></div>
      <div class="role-row-name"><span class="${at.cls}" style="${at.style}">${r.icon ? esc(r.icon) + ' ' : ''}${esc(r.name)}</span>${r.hoist ? '<span class="role-tag">own group</span>' : ''}</div>
      <div class="role-row-count">${count} member${count !== 1 ? 's' : ''}</div>
      <div class="role-row-acts">${mv}<div class="role-act-btn" onclick="editRole('${eid}')" title="Edit">✏️</div>${del}</div>
    </div>`;
  }).join('');
  document.getElementById('role-editor').style.display = 'none';
  editingRoleId = null;
}

function moveRole(id, dir) {
  const sv = S.curSv; if (!sv || !sv.roles) return;
  const i = sv.roles.findIndex(r => r.id === id), j = i + dir; if (i < 0 || j < 0 || j >= sv.roles.length) return;
  [sv.roles[i], sv.roles[j]] = [sv.roles[j], sv.roles[i]];
  wsSend({ type: 'roles_update', serverId: sv.id, roles: sv.roles });
  try { persist(); buildRolesPane(); renderMbs(); } catch (e) { console.error(e); }
}

function reLoad(r, isOwner) {
  RE.color = pfHex(r.color, '#9090a8'); RE.color2 = pfHex(r.color2, RE.color); RE.fx = ROLE_FX.some(f => f.id === r.fx) ? r.fx : 'none';
  RE.icon = r.icon || ''; RE.hoist = r.hoist === true; RE.owner = !!isOwner;
  editingRoleColor = RE.color;
  document.getElementById('role-name-in').value = r.name || '';
  document.getElementById('re-icon').value = RE.icon;
  document.getElementById('re-hoist').classList.toggle('on', RE.hoist);
  document.getElementById('re-perms').style.display = isOwner ? 'none' : '';
  document.getElementById('re-presets').innerHTML = ROLE_PRESETS.map((p, i) => `<button type="button" class="re-chip" onclick="rePreset(${i})">${p.icon ? p.icon + ' ' : ''}${p.n}</button>`).join('');
  buildRoleColorGrid(RE.color); buildPermList(isOwner ? null : r.perms); reUpdate();
  document.getElementById('role-editor').style.display = 'block';
}
function openCreateRole() { editingRoleId = '__new__'; reLoad({ name: '', color: COLORS[0], color2: COLORS[0], fx: 'none', icon: '', hoist: false, perms: [] }, false); }
function editRole(id) {
  const sv = S.curSv; if (!sv) return;
  const role = getEffectiveRole(sv, id); if (!role) return;
  editingRoleId = id; reLoad(role, id === 'owner');
}
function cancelRoleEdit() { document.getElementById('role-editor').style.display = 'none'; editingRoleId = null; }

function reUpdate() { // read the text inputs, redraw the live preview + effect chips
  RE.icon = (document.getElementById('re-icon').value || '').trim().slice(0, 4);
  RE.hoist = document.getElementById('re-hoist').classList.contains('on');
  document.getElementById('re-fx').innerHTML = ROLE_FX.map(f => `<button type="button" class="re-chip${RE.fx === f.id ? ' on' : ''}" onclick="reFx('${f.id}')">${f.n}</button>`).join('');
  document.getElementById('re-c1').value = RE.color; document.getElementById('re-c2').value = RE.color2;
  document.getElementById('re-c2-wrap').style.display = (RE.fx === 'gradient' || RE.fx === 'shimmer') ? '' : 'none';
  const nm = (document.getElementById('role-name-in').value.trim() || 'Role name'), at = roleFxAttrs(RE), c = RE.color;
  document.getElementById('re-preview').innerHTML = `<span class="role-badge" style="background:${c}22;color:${c};border:1px solid ${c}44">${RE.icon ? esc(RE.icon) : '●'} ${esc(nm)}</span>
    <span class="m-auth ${at.cls}" style="${at.style}">${esc(S.user?.name || 'You')}</span><span class="re-sample">Hey, this is how the name looks in chat</span>`;
}
function reColor(which, v) { v = pfHex(v, RE.color); if (which === 1) { RE.color = v; editingRoleColor = v; document.querySelectorAll('#role-color-grid .av-opt').forEach(x => x.classList.toggle('sel', x.dataset.c === v)); } else RE.color2 = v; reUpdate(); }
function reFx(id) { RE.fx = id; reUpdate(); }
function rePreset(i) {
  const p = ROLE_PRESETS[i]; if (!p) return;
  RE.color = p.color; RE.color2 = p.color2; RE.fx = p.fx; RE.icon = p.icon; RE.hoist = p.hoist; editingRoleColor = p.color;
  document.getElementById('re-icon').value = p.icon; document.getElementById('re-hoist').classList.toggle('on', p.hoist);
  const nin = document.getElementById('role-name-in'); if (!nin.value.trim() && editingRoleId === '__new__') nin.value = p.n;
  buildRoleColorGrid(p.color); reUpdate();
}

function buildRoleColorGrid(selected) {
  const g = document.getElementById('role-color-grid'); g.innerHTML = '';
  COLORS.forEach(c => {
    const d = document.createElement('div'); d.className = 'av-opt' + (c === (selected || editingRoleColor) ? ' sel' : '');
    d.style.background = c; d.dataset.c = c; d.textContent = '●';
    d.onclick = () => { document.querySelectorAll('#role-color-grid .av-opt').forEach(x => x.classList.remove('sel')); d.classList.add('sel'); RE.color = c; editingRoleColor = c; if (RE.color2 === RE.color || RE.fx === 'none') RE.color2 = c; reUpdate(); };
    g.appendChild(d);
  });
}

function buildPermList(activePerms) {
  const pl = document.getElementById('perm-list'); pl.innerHTML = '';
  ALL_PERMS.forEach(p => {
    const on = activePerms ? activePerms.includes(p.id) : false;
    pl.innerHTML += `<div class="perm-row">
      <div><div class="perm-label">${p.label}</div><div class="perm-sub">${p.sub}</div></div>
      <div class="toggle-switch${on ? ' on' : ''}" data-perm="${p.id}" onclick="togglePerm(this)"></div>
    </div>`;
  });
}
function togglePerm(el) { el.classList.toggle('on'); }

function saveRole() {
  const sv = S.curSv; if (!sv) return;
  const name = document.getElementById('role-name-in').value.trim();
  if (!name) { toast('Role needs a name'); return; }
  reUpdate();
  const perms = RE.owner ? ['*'] : [...document.querySelectorAll('#perm-list .toggle-switch.on')].map(el => el.dataset.perm);
  const look = { name, color: RE.color, color2: RE.color2, fx: RE.fx, icon: RE.icon, hoist: RE.hoist, perms };
  if (!sv.roles) sv.roles = [];
  if (DEFAULT_ROLES.some(r => r.id === editingRoleId)) { // built-in: only this server's overrides change
    if (!sv.roleOverrides) sv.roleOverrides = {};
    sv.roleOverrides[editingRoleId] = look;
    wsSend({ type: 'roles_update', serverId: sv.id, overrides: sv.roleOverrides });
  } else {
    if (editingRoleId === '__new__') sv.roles.push({ id: uid(), ...look });
    else { const i = sv.roles.findIndex(x => x.id === editingRoleId); if (i >= 0) sv.roles[i] = { id: editingRoleId, ...look }; }
    wsSend({ type: 'roles_update', serverId: sv.id, roles: sv.roles });
  }
  try { persist(); buildRolesPane(); renderMbs(); if (S.curCh) renderMsgs(S.curCh.id); } catch (e) { console.error(e); }
  toast('✅ Role "' + name + '" saved');
}

function deleteRole(id) {
  const sv = S.curSv; if (!sv) return;
  if (!confirm('Delete this role?')) return;
  sv.roles = (sv.roles || []).filter(r => r.id !== id);
  Object.keys(sv.memberRoles || {}).forEach(m => { if (sv.memberRoles[m] === id) delete sv.memberRoles[m]; });
  wsSend({ type: 'roles_update', serverId: sv.id, roles: sv.roles });
  persist(); buildRolesPane(); renderMbs();
}

// ── MEMBERS PANE ──
function buildMembersPane() {
  const sv = S.curSv; if (!sv) return;
  const isOwner = (sv.ownerId||'').toLowerCase() === (S.user.name||'').toLowerCase();
  const allMembers = [S.user.name, ...(S.members[sv.id]||[]).map(m=>m.name).filter(n=>n!==S.user.name)];
  const allRoles = [...DEFAULT_ROLES, ...(sv.roles||[])];
  const el = document.getElementById('stg-member-list');

  el.innerHTML = allMembers.map(name => {
    const mdata = name===S.user.name ? S.user : (S.members[sv.id]||[]).find(m=>m.name===name)||{name,color:COLORS[hash(name)%COLORS.length]};
    const avBg = mdata.pfp?'transparent':(mdata.color||COLORS[hash(name)%COLORS.length]);
    const avContent = mdata.pfp?`<img src="${mdata.pfp}">`:`${name[0].toUpperCase()}`;
    const currentRole = getMemberRole(sv, name);
    const isThisOwner = (sv.ownerId||'').toLowerCase() === (name||'').toLowerCase();

    const roleSelectHTML = (isOwner && !isThisOwner) ? `
      <select class="role-select" onchange="assignRole('${name}',this.value)">
        ${allRoles.filter(r=>r.id!=='owner').map(r=>`<option value="${r.id}"${currentRole===r.id?' selected':''}>${r.name}</option>`).join('')}
      </select>` : `<span class="role-badge ${currentRole==='owner'?'owner':currentRole==='mod'?'mod':''}" style="${currentRole!=='owner'&&currentRole!=='mod'?`background:transparent;color:var(--t3);border:none`:''}">${currentRole==='owner'?'👑 Owner':currentRole==='mod'?'🛡 Mod':currentRole}</span>`;

    return `<div class="member-row">
      <div class="member-row-av" style="background:${avBg}">${avContent}</div>
      <div class="member-row-name">${esc(name)}</div>
      ${roleSelectHTML}
      ${isOwner && !isThisOwner ? `<div class="role-act-btn del" onclick="kickMember('${name}')" title="Kick">⚡</div>` : ''}
    </div>`;
  }).join('');
}

function assignRole(memberName, roleId) {
  const sv = S.curSv; if (!sv || (sv.ownerId||'').toLowerCase()!==(S.user.name||'').toLowerCase()) return;
  if (!sv.memberRoles) sv.memberRoles = {};
  if (roleId === 'member') delete sv.memberRoles[memberName];
  else sv.memberRoles[memberName] = roleId;
  persist(); renderMbs();
  wsSend({type:'role_assign', serverId:sv.id, target:memberName, role:roleId});
  toast(`✅ ${memberName} → ${roleId}`);
}

// ── MEMBER CONTEXT MENU ──
function openMemberCtx(memberName, e) {
  const sv = S.curSv; if (!sv) return;
  const myRole = getMyRole(sv);
  if (myRole!=='owner' && myRole!=='mod') return; // only power users see this
  ctxTargetMember = memberName;
  const ctx = document.getElementById('member-ctx');
  document.getElementById('ctx-member-name').textContent = memberName;
  const isMod = getMemberRole(sv, memberName) === 'mod';
  document.getElementById('ctx-mod-item').textContent = isMod ? '🛡 Remove Mod' : '🛡 Make Moderator';
  // Only owner can assign roles / toggle mod
  const isOwner = (sv.ownerId||'').toLowerCase() === (S.user.name||'').toLowerCase();
  document.getElementById('ctx-role-item').style.display = isOwner ? '' : 'none';
  document.getElementById('ctx-mod-item').style.display = isOwner ? '' : 'none';
  document.getElementById('ctx-admin-ban').style.display = isPlatformPower() ? '' : 'none';
  ctx.style.display = 'block';
  const x = Math.min(e.clientX, window.innerWidth-190);
  const y = Math.min(e.clientY, window.innerHeight-200);
  ctx.style.left = x+'px'; ctx.style.top = y+'px';
  e.preventDefault(); e.stopPropagation();
}

function ctxAssignRole() {
  document.getElementById('member-ctx').style.display='none';
  openSvSettings('members');
}

function ctxToggleMod() {
  const sv = S.curSv; if (!sv || !ctxTargetMember) return;
  document.getElementById('member-ctx').style.display='none';
  const cur = getMemberRole(sv, ctxTargetMember);
  assignRole(ctxTargetMember, cur==='mod'?'member':'mod');
}

function ctxKick() {
  document.getElementById('member-ctx').style.display='none';
  if (ctxTargetMember) kickMember(ctxTargetMember);
}

function ctxBan() {
  const sv = S.curSv; if (!sv || !ctxTargetMember) return;
  document.getElementById('member-ctx').style.display='none';
  if (!confirm(`Ban ${ctxTargetMember} from "${sv.name}"? They won't be able to rejoin.`)) return;
  if (!sv.banned) sv.banned = [];
  sv.banned.push(ctxTargetMember);
  kickMember(ctxTargetMember, true);
  toast(`🚫 ${ctxTargetMember} banned`);
}

function kickMember(name, silent=false) {
  const sv = S.curSv; if (!sv) return;
  if (!sv.memberRoles) sv.memberRoles={};
  delete sv.memberRoles[name];
  // Remove from local members list
  if (S.members[sv.id]) S.members[sv.id] = S.members[sv.id].filter(m=>m.name!==name);
  persist(); renderMbs(); buildMembersPane();
  if (!silent) toast(`⚡ ${name} kicked`);
  wsSend({type:'kick_member', serverId:sv.id, target:name});
}

// ── SERVER LIFECYCLE (owner only) ──
function deleteServer() {
  const sv = S.curSv; if (!sv) return;
  if ((sv.ownerId||'').toLowerCase() !== (S.user.name||'').toLowerCase()) { toast('Only the server owner can delete it'); return; }
  if (!confirm(`Permanently delete "${sv.name}"? This cannot be undone.`)) return;
  wsSend({type:'server_delete', serverId:sv.id}); // server first, UI second
  _pendingServerCreates.delete(sv.id); _pendingRetryCount.delete(sv.id); _pendingLastSent.delete(sv.id); _savePending();
  try {
    (sv.channels||[]).forEach(ch => delete S.messages[ch.id]);
    S.servers = S.servers.filter(s=>s.id!==sv.id);
    persist(); closeM('sv-settings');
    S.curSv = null; S.curCh = null;
    renderSvs();
    document.getElementById('sv-nm').textContent='—';
    document.getElementById('ch-list').innerHTML='';
    document.getElementById('members').innerHTML='';
    showWelcome();
    toast('🗑 Server deleted');
  } catch (e) { console.error('[nexus] delete UI error', e); toast('⚠️ Deleted, but the screen failed to update: ' + e.message); }
}

function leaveServer() {
  const sv = S.curSv; if (!sv) return;
  if ((sv.ownerId||'').toLowerCase() === (S.user.name||'').toLowerCase()) { toast("You own this server — delete it instead"); return; }
  if (!confirm(`Leave "${sv.name}"?`)) return;
  S.servers = S.servers.filter(s=>s.id!==sv.id);
  persist(); S.curSv=null; S.curCh=null; renderSvs();
  document.getElementById('sv-nm').textContent='—';
  document.getElementById('ch-list').innerHTML='';
  document.getElementById('members').innerHTML='';
  showWelcome();
  toast('👋 Left server');
  wsSend({type:'leave_server', serverId:sv.id, user:S.user.name});
}
