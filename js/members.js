// ── MEMBERS (real, from WS) ──
function renderMbs() {
  const el=document.getElementById('members'); el.innerHTML='';
  if(!S.curSv){ el.innerHTML='<div class="mb-empty">No server selected</div>'; return; }
  const sv=S.curSv;
  const mbs=S.members[sv.id]||[];
  // Self is always online
  const self={name:S.user.name,color:S.user.color,pfp:S.user.pfp||null,online:true};
  const all=[self,...mbs.filter(m=>m.name!==S.user.name)];
  if(!all.length){ el.innerHTML='<div class="mb-empty">No members</div>'; return; }

  const renderGroup=(title,members,isOffline=false)=>{
    if(!members.length) return;
    el.innerHTML+=`<div class="mb-cat">${title} — ${members.length}</div>`;
    members.forEach(m=>{
      const avContent=m.pfp?`<img src="${m.pfp}" alt="">`:`${m.name[0].toUpperCase()}`;
      const avBg=m.pfp?'transparent':(m.color||COLORS[hash(m.name)%COLORS.length]);
      const badge=roleLabel(sv,m.name);
      const myRole=getMyRole(sv);
      const canCtx=(myRole==='owner'||myRole==='mod')&&m.name!==S.user.name;
      const statusBg=isOffline?'var(--t3)':(m.status==='idle'?'var(--yellow)':m.status==='dnd'?'var(--red)':m.status==='invisible'?'var(--t3)':'var(--green)');
      const offlineStyle=isOffline?'opacity:0.5;':'';
      el.innerHTML+=`<div class="mb-it" style="${offlineStyle}" onclick="openProfilePage('${esc(m.name)}')" oncontextmenu="${canCtx?`openMemberCtx('${esc(m.name)}',event)`:''}" onmouseenter="showUserHover('${esc(m.name)}',this)" onmouseleave="if(!event.relatedTarget?.closest('.user-hover-popup'))hideUserHover()" title="Click for profile${canCtx?' · Right-click for options':''}">
        <div class="mb-av" style="background:${avBg}">${avContent}<div class="mb-st on" style="background:${statusBg}"></div></div>
        <div style="flex:1;min-width:0"><div class="mb-nm">${esc(m.name)}</div></div>
        <div class="mb-role">${badge}</div>
      </div>`;
    });
  };

  // Group by role AND online status: online first, then offline
  const online=all.filter(m=>m.online!==false);
  const offline=all.filter(m=>m.online===false);

  // Within online: sort by role
  const onOwners=online.filter(m=>getMemberRole(sv,m.name)==='owner');
  const onMods=online.filter(m=>getMemberRole(sv,m.name)==='mod');
  const onOthers=online.filter(m=>getMemberRole(sv,m.name)!=='owner'&&getMemberRole(sv,m.name)!=='mod');
  // Within offline: sort by role
  const offOwners=offline.filter(m=>getMemberRole(sv,m.name)==='owner');
  const offMods=offline.filter(m=>getMemberRole(sv,m.name)==='mod');
  const offOthers=offline.filter(m=>getMemberRole(sv,m.name)!=='owner'&&getMemberRole(sv,m.name)!=='mod');

  if(online.length) {
    renderGroup('Online',onOwners.concat(onMods,onOthers));
  }
  if(offline.length) {
    // Show offline by role sub-group or flat depending on size
    renderGroup('Offline',offOwners.concat(offMods,offOthers),true);
  }
}
function toggleMb(){S.mbOpen=!S.mbOpen;document.getElementById('members').style.display=S.mbOpen?'':'none';}
