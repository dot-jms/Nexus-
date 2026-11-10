// ══════════════════════════════════
// DISCOVER
// ══════════════════════════════════
function showDiscover() {
  hideAll();
  document.getElementById('discover').classList.add('show');
  document.getElementById('rail-discover').classList.add('act');
  document.querySelectorAll('.sv-ic').forEach(el=>el.classList.remove('act'));
  S.curSv=null; S.curCh=null;
  document.getElementById('sv-nm').textContent='Discover';
  document.getElementById('ch-list').innerHTML='';
  document.getElementById('members').innerHTML='';
  // Request from server
  wsSend({type:'get_server_list'});
  // Also show locally known servers as a fallback
  renderDiscover();
}

function setDiscFilter(f) {
  discFilter=f;
  document.querySelectorAll('.disc-filter').forEach(el=>el.classList.toggle('active',el.dataset.f===f));
  renderDiscover();
}

function filterDiscover() { renderDiscover(); }

function renderDiscover() {
  const el=document.getElementById('disc-body');
  const query=document.getElementById('disc-search').value.trim().toLowerCase();

  // Merge local servers (public) + WS-provided servers
  const localPublic=S.servers.filter(sv=>sv.isPublic===true).map(sv=>({
    id:sv.id, name:sv.name, desc:sv.desc||'', icon:sv.icon||null, color:sv.color,
    memberCount:sv.memberCount||1, createdAt:sv.createdAt||Date.now(), isOwner:sv.isOwner,
  }));

  let all=[...S.discServers];
  // Merge in local if not already present
  localPublic.forEach(ls=>{ if(!all.find(s=>s.id===ls.id)) all.push(ls); });

  // Filter by query
  if(query) all=all.filter(s=>s.name.toLowerCase().includes(query)||s.desc.toLowerCase().includes(query));

  // Sort
  if(discFilter==='popular') all.sort((a,b)=>(b.memberCount||0)-(a.memberCount||0));
  else if(discFilter==='new') all.sort((a,b)=>(b.createdAt||0)-(a.createdAt||0));
  else if(discFilter==='joined') all=all.filter(s=>S.servers.find(x=>x.id===s.id));
  else all.sort((a,b)=>(b.memberCount||0)-(a.memberCount||0)); // default: popular

  if(!all.length) {
    el.innerHTML=`<div class="disc-empty"><div class="disc-empty-icon">🔭</div><div class="disc-empty-text">${query?'No servers found':'No servers yet'}</div><div class="disc-empty-sub">${query?'Try a different search term':'Be the first to create one!'}</div></div>`;
    return;
  }

  el.innerHTML='';
  const title=document.createElement('div');
  title.className='disc-section-title';
  title.textContent=discFilter==='joined'?'Your Servers':discFilter==='new'?'Newest Servers':discFilter==='popular'?'Most Popular':'All Servers';
  el.appendChild(title);

  const grid=document.createElement('div'); grid.className='disc-grid';
  all.forEach(sv=>{ grid.innerHTML+=discCard(sv); });
  el.appendChild(grid);
}

function discCard(sv) {
  const joined=!!S.servers.find(s=>s.id===sv.id);
  const isOwned = (sv.ownerId||'').toLowerCase() === (S.user?.name||'').toLowerCase();
  const bannerStyle=sv.banner?`background-image:url('${sv.banner}');background-size:cover;background-position:center`:`background:linear-gradient(135deg,${sv.color||'#6c63ff'}22,${sv.color||'#6c63ff'}44)`;
  const iconHTML=sv.icon?`<img src="${sv.icon}" alt="">`:(svInit(sv.name||'?'));
  // FIX #12: Store only the server ID in the button's data attribute instead of
  // inlining the full JSON object. This prevents breakage (and potential XSS) when
  // server names/descriptions contain single quotes, backticks, or HTML characters.
  return `<div class="disc-card">
    <div class="disc-card-banner" style="${bannerStyle}"></div>
    <div class="disc-card-body">
      <div class="disc-card-header">
        <div class="disc-card-icon" style="background:${sv.color||'#6c63ff'}">${iconHTML}</div>
      </div>
      <div class="disc-card-name">${esc(sv.name)}</div>
      <div class="disc-card-desc">${esc(sv.desc||'No description.')}</div>
      <div class="disc-card-footer">
        <div class="disc-card-members">${(sv.memberCount||0).toLocaleString()} members</div>
        <button class="disc-join-btn${(joined||isOwned)?' joined':''}" data-svid="${esc(sv.id)}" onclick="joinDiscoverSvById(this)">${isOwned?'Your server':joined?'Joined':'Join'}</button>
      </div>
    </div>
  </div>`;
}

function joinDiscoverSvById(btn) {
  // FIX #12: Retrieve the server object from our local cache by ID — no inline data.
  const svId = btn.dataset.svid;
  const sv = S.discServers.find(s=>s.id===svId) || S.servers.find(s=>s.id===svId);
  if (!sv) { toast('Server not found — try refreshing'); return; }
  joinDiscoverSv(sv, btn);
}

function joinDiscoverSv(sv, btn) {
  const existing = S.servers.find(s=>s.id===sv.id);
  if(existing){ selectSv(existing.id); return; }
  // Request full server info (including channels) from relay before joining
  wsSend({type:'get_server_info', serverId:sv.id});
  // Optimistically add with available data, channels will be synced via server_info response
  const newSv={...sv,
    channels:sv.channels||[],
    memberCount:(sv.memberCount||0)+1,
    memberRoles: sv.memberRoles||{},
    roles: sv.roles||[],
    banned: sv.banned||[],
  };
  S.servers.push(newSv); persist(); renderSvs();
  btn.textContent='Joined'; btn.classList.add('joined');
  playSound('server_join');
  toast('✅ Joined "'+sv.name+'"');
  wsSend({type:'join_server',serverId:sv.id,user:S.user.name,userName:S.user.name,color:S.user.color,pfp:S.user.pfp||null});
  selectSv(sv.id);
}
