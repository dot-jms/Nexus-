// ══════════════════════════════════
// SERVERS
// ══════════════════════════════════
function renderSvs() {
  const el=document.getElementById('sv-list'); el.innerHTML='';
  S.servers.forEach(sv=>{
    const d=document.createElement('div');
    d.className='sv-ic'+(S.curSv?.id===sv.id?' act':'');
    d.title=sv.name;
    if(sv.icon){ d.innerHTML=`<div class="sv-pip"></div><img src="${sv.icon}" alt="">`; }
    else { d.innerHTML=`<div class="sv-pip"></div>${svInit(sv.name)}`; }
    d.onclick=()=>selectSv(sv.id);
    d.oncontextmenu=(e)=>{ e.preventDefault(); showRailCtx(sv, e); };
    el.appendChild(d);
  });
}

function selectSv(id) {
  S.curSv=S.servers.find(s=>s.id===id); if(!S.curSv) return;
  document.getElementById('sv-nm').textContent=S.curSv.name;
  document.getElementById('rail-discover').classList.remove('act');
  renderSvs(); renderChs(); renderMbs();
  // Request member list from server
  wsSend({type:'get_members',serverId:id});
  const first=(S.curSv.channels||[]).find(c=>c.type==='text');
  first?selectCh(first.id):showWelcome();
}

function createSv() {
  const name=document.getElementById('sv-in').value.trim(); if(!name) return;
  const sv={ id:uid(), name, desc:document.getElementById('sv-desc').value.trim(),
    color:COLORS[Math.floor(Math.random()*COLORS.length)], icon:svIconData||null,
    ownerId: S.user.name,
    ownerIdLower: S.user.name.toLowerCase(),
    isOwner: true,
    memberRoles: {},
    roles: [],
    banned: [],
    channels:[
      {id:uid(),name:'general',type:'text',desc:'General chat'},
      {id:uid(),name:'random',type:'text',desc:'Anything goes'},
      {id:uid(),name:'announcements',type:'text',desc:'News'},
    ], isPublic:true, memberCount:1, createdAt:Date.now(),
  };
  S.servers.push(sv); persist(); closeM('csv'); renderSvs(); selectSv(sv.id);
  toast('🎉 "'+name+'" created');
  playSound('server_join');
  const _createMsg = {type:'server_create',serverId:sv.id,name,desc:sv.desc,icon:null,color:sv.color,isPublic:true,memberCount:1,createdAt:sv.createdAt||Date.now(),channels:sv.channels,ownerId:sv.ownerId};
  _pendingServerCreates.set(sv.id, _createMsg);
  _pendingLastSent.set(sv.id, Date.now()); // prevent immediate retry from identified handler
  _savePending();
  wsSend(_createMsg);
  if(sv.icon) setTimeout(()=>wsSend({type:'server_update',serverId:sv.id,name,desc:sv.desc||'',icon:sv.icon,color:sv.color,isPublic:true,memberCount:sv.memberCount||1,createdAt:sv.createdAt||Date.now(),channels:sv.channels,ownerId:sv.ownerId}),600);
  document.getElementById('sv-in').value=''; document.getElementById('sv-desc').value='';
  svIconData=null; document.getElementById('sv-icon-preview').innerHTML='🖼️';
}

function svInit(n){ return n.split(' ').map(w=>w[0]).join('').slice(0,3).toUpperCase(); }

// ── Rail server right-click context menu ──
function showRailCtx(sv, e) {
  // Remove any existing rail ctx
  document.getElementById('rail-ctx')?.remove();
  const isOwner = (sv.ownerId||'').toLowerCase() === (S.user.name||'').toLowerCase();
  const ctx = document.createElement('div');
  ctx.id = 'rail-ctx';
  ctx.className = 'ctx-menu';
  const x = Math.min(e.clientX + 8, window.innerWidth - 200);
  const y = Math.min(e.clientY, window.innerHeight - 160);
  ctx.style.left = x + 'px'; ctx.style.top = y + 'px';

  const ctxItem = (label, fn, danger=false) => {
    const d = document.createElement('div');
    d.className = 'sv-dd-item' + (danger ? ' danger' : '');
    d.textContent = label;
    d.onclick = () => { ctx.remove(); fn(); };
    ctx.appendChild(d);
  };
  const ctxSep = () => { const d=document.createElement('div'); d.className='sv-dd-sep'; ctx.appendChild(d); };

  // Server name label
  const lbl = document.createElement('div');
  lbl.style.cssText = 'padding:6px 10px 4px;font-size:11px;font-weight:700;color:var(--t3);letter-spacing:.06em;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:170px';
  lbl.textContent = sv.name;
  ctx.appendChild(lbl);
  ctxSep();

  ctxItem('🏠 Go to Server', () => selectSv(sv.id));
  if (isOwner) {
    ctxItem('⚙️ Server Settings', () => { selectSv(sv.id); openSvSettings('overview'); });
    ctxSep();
    ctxItem('🗑 Delete Server', () => {
      if (!confirm(`Permanently delete "${sv.name}"? This cannot be undone.`)) return;
      const wasCur = S.curSv?.id === sv.id;
      // Server first, UI second (an error while redrawing must not stop the delete being sent)
      wsSend({type:'server_delete', serverId:sv.id});
      _pendingServerCreates.delete(sv.id); _pendingRetryCount.delete(sv.id); _pendingLastSent.delete(sv.id); _savePending();
      try {
        (sv.channels||[]).forEach(ch => delete S.messages[ch.id]);
        S.servers = S.servers.filter(s=>s.id!==sv.id);
        persist(); S.curSv=null; S.curCh=null; renderSvs();
        document.getElementById('sv-nm').textContent='—';
        document.getElementById('ch-list').innerHTML='';
        document.getElementById('members').innerHTML='';
        showWelcome();
        toast('🗑 Server deleted');
      } catch (e) { console.error('[nexus] delete UI error', e); toast('⚠️ Deleted, but the screen failed to update: ' + e.message); }
    }, true);
  } else {
    ctxSep();
    ctxItem('👋 Leave Server', () => {
      if (!confirm(`Leave "${sv.name}"?`)) return;
      S.servers = S.servers.filter(s=>s.id!==sv.id);
      persist(); S.curSv=null; S.curCh=null; renderSvs();
      document.getElementById('sv-nm').textContent='—';
      document.getElementById('ch-list').innerHTML='';
      document.getElementById('members').innerHTML='';
      showWelcome();
      toast('👋 Left server');
      wsSend({type:'leave_server', serverId:sv.id, user:S.user.name});
    }, true);
  }

  document.body.appendChild(ctx);
  // Close on outside click
  setTimeout(() => {
    document.addEventListener('click', () => ctx.remove(), { once: true });
  }, 0);
}
