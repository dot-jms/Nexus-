// ── MEMBERS (real, from WS) ──
// ── presence helpers ──
const _nk = n => String(n || '').toLowerCase();           // names are matched case-insensitively everywhere
// One entry per person (the server already does this; this protects against older data / races). If a person
// appears twice, the online one wins.
function dedupeMembers(list) {
  const map = new Map();
  (list || []).forEach(m => {
    if (!m || !m.name) return;
    const k = _nk(m.name), prev = map.get(k);
    if (!prev || (m.online !== false && prev.online === false)) map.set(k, { ...(prev || {}), ...m });
  });
  return [...map.values()];
}
// Apply one person's presence everywhere we show it: every loaded member list and the friends list.
function applyPresence(name, p, quiet) {
  const k = _nk(name); let touched = false;
  Object.values(S.members || {}).forEach(list => (list || []).forEach(m => {
    if (_nk(m.name) !== k) return;
    m.online = !!p.online; m.status = p.online ? p.status : undefined;
    if (p.lastSeen !== undefined) m.lastSeen = p.lastSeen;
    touched = true;
  }));
  const f = (S.friends || []).find(x => _nk(x.name) === k);
  if (f) { f.online = !!p.online; f.status = p.online ? p.status : 'offline'; if (p.lastSeen !== undefined) f.lastSeen = p.lastSeen; touched = true; }
  if (typeof dmPresence === 'function' && dmPresence(name, p)) touched = true;
  if (touched && !quiet) {
    if (S.curSv) renderMbs();
    if (friendsOpen()) renderFriends();
  }
  return touched;
}
// Ask the server for a server's member list. Every request has a number; replies older than the newest one we
// already applied are ignored, so a slow reply can never overwrite a newer list.
const _memReq = {}, _memApplied = {};
function requestMembers(svId) {
  if (!svId) return;
  _memReq[svId] = (_memReq[svId] || 0) + 1;
  wsSend({ type: 'get_members', serverId: svId, reqId: _memReq[svId] });
}
function friendsOpen() { const v = document.getElementById('friends-view'); return !!v && v.style.display !== 'none'; }

function renderMbs() {
  const el=document.getElementById('members'); let html='';
  if(!S.curSv){ el.innerHTML='<div class="mb-empty">No server selected</div>'; return; }
  const sv=S.curSv;
  // Build one entry per person. I am always shown (online, with my own status) and never twice.
  const byKey=new Map();
  dedupeMembers(S.members[sv.id]||[]).forEach(m=>byKey.set(_nk(m.name),m));
  const meKey=_nk(S.user.name), mine=byKey.get(meKey)||{};
  byKey.set(meKey,{...mine,name:S.user.name,color:S.user.color,pfp:S.user.pfp||null,online:true,status:S.user.status});
  const all=[...byKey.values()];
  if(!all.length){ el.innerHTML='<div class="mb-empty">No members</div>'; return; }

  const renderGroup=(title,members,isOffline=false)=>{
    if(!members.length) return;
    html+=`<div class="mb-cat">${title} — ${members.length}</div>`;
    members.forEach(m=>{
      const avContent=safeUrl(m.pfp)?`<img src="${safeUrl(m.pfp)}" alt="">`:`${esc(m.name[0].toUpperCase())}`;
      const avBg=safeUrl(m.pfp)?'transparent':(m.color||COLORS[hash(m.name)%COLORS.length]);
      const badge=roleLabel(sv,m.name);
      const myRole=getMyRole(sv);
      const canCtx=(myRole==='owner'||myRole==='mod')&&_nk(m.name)!==meKey;
      const statusBg=isOffline?'var(--t3)':(m.status==='idle'?'var(--yellow)':m.status==='dnd'?'var(--red)':m.status==='invisible'?'var(--t3)':'var(--green)');
      const offlineStyle=isOffline?'opacity:0.5;':'';
      html+=`<div class="mb-it" style="${offlineStyle}" onclick="openProfilePage('${esc(m.name)}')" oncontextmenu="${canCtx?`openMemberCtx('${esc(m.name)}',event)`:''}" onmouseenter="showUserHover('${esc(m.name)}',this)" onmouseleave="if(!event.relatedTarget?.closest('.user-hover-popup'))hideUserHover()" title="Click for profile${canCtx?' · Right-click for options':''}">
        <div class="mb-av" style="background:${avBg}">${avContent}<div class="mb-st" style="background:${statusBg}"></div></div>
        <div style="flex:1;min-width:0"><div class="mb-nm">${esc(m.name)}</div></div>
        <div class="mb-role">${badge}</div>
      </div>`;
    });
  };

  // Only an explicit online:true counts as online (a missing flag used to mean "online")
  const online=all.filter(m=>m.online===true);
  const offline=all.filter(m=>m.online!==true);
  const byRole=(arr)=>{
    const r=m=>getMemberRole(sv,m.name);
    return arr.filter(m=>r(m)==='owner').concat(arr.filter(m=>r(m)==='mod'),arr.filter(m=>r(m)!=='owner'&&r(m)!=='mod'));
  };
  if(online.length) renderGroup('Online',byRole(online));
  if(offline.length) renderGroup('Offline',byRole(offline),true);
  el.innerHTML=html;
}
function toggleMb(){S.mbOpen=!S.mbOpen;document.getElementById('members').style.display=S.mbOpen?'':'none';}

// Keep the list honest without depending on every individual event arriving: refresh the current server's
// members when the tab becomes visible again and every 45s while it's open, and make sure connections that
// died silently are noticed (below) so the server stops showing us online when we're not.
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState !== 'visible' || !S.wsOk || !S.user) return;
  if (S.curSv) requestMembers(S.curSv.id);
  if ((S.friends || []).length) wsSend({ type: 'get_presence', names: S.friends.map(f => f.name) });
});
setInterval(() => { if (document.visibilityState === 'visible' && S.wsOk && S.user && S.curSv) requestMembers(S.curSv.id); }, 45000);
