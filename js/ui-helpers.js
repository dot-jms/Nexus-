// ── UI ──
function hideAll(){
  document.getElementById('welcome').style.display='none';
  document.getElementById('home-screen').style.display='none';
  document.getElementById('discover').classList.remove('show');
  document.getElementById('chat-wrap').classList.remove('show');
  document.getElementById('ch-hd').style.display='none';
  document.getElementById('dm-chat').classList.remove('show');
  document.getElementById('friends-view').style.display='none';
  document.getElementById('rail-friends').classList.remove('act');
}
function showWelcome(){
  hideAll();
  const el = document.getElementById('welcome');
  el.style.display = '';
  el.classList.remove('view-enter'); void el.offsetWidth; el.classList.add('view-enter');
}
function showHome() {
  hideAll();
  document.getElementById('sidebar').style.display = 'none';
  document.getElementById('members').style.display = 'none';
  const _hs = document.getElementById('home-screen');
  _hs.style.display = 'flex'; _hs.style.flexDirection = 'column';
  _hs.classList.remove('view-enter'); void _hs.offsetWidth; _hs.classList.add('view-enter');
  // Greeting
  const hr = new Date().getHours();
  const greet = hr < 12 ? 'Good morning' : hr < 18 ? 'Good afternoon' : 'Good evening';
  document.getElementById('home-greeting').textContent = greet + ', ' + (S.user?.name || '') + '.';
  // Friends count
  const online = S.friends.filter(f => f.online).length;
  document.getElementById('home-friends-count').textContent = S.friends.length + ' friends' + (online ? ` · ${online} online` : '');
  // Recent DMs
  const dmsEl = document.getElementById('home-recent-dms');
  const recent = [...S.dms].sort((a,b)=>(b.lastTs||0)-(a.lastTs||0)).slice(0,5);
  dmsEl.innerHTML = recent.length ? recent.map(dm => {
    const bg = dm.pfp ? 'transparent' : COLORS[hash(dm.name) % COLORS.length];
    const av = dm.pfp ? `<img src="${dm.pfp}" style="width:100%;height:100%;object-fit:cover;border-radius:inherit">` : dm.name[0].toUpperCase();
    return `<div class="home-row" onclick="openOrCreateDM('${dm.name}',null)">
      <div class="home-row-av" style="background:${bg}">${av}</div>
      <div style="min-width:0;flex:1"><div style="font-size:13px;font-weight:600">${esc(dm.name)}</div><div style="font-size:11px;color:var(--t3);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${esc(dm.last||'No messages yet')}</div></div>
      <svg width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" style="color:var(--t3);flex-shrink:0"><polyline points="9 18 15 12 9 6"/></svg>
    </div>`;
  }).join('') : '<div style="font-size:12px;color:var(--t3);padding:8px 0">No recent conversations.</div>';
  // Servers
  const svsEl = document.getElementById('home-servers');
  svsEl.innerHTML = S.servers.length ? S.servers.slice(0,8).map(sv => {
    const bg = sv.icon ? 'transparent' : (sv.color || '#6c63ff');
    const ic = sv.icon ? `<img src="${sv.icon}" style="width:100%;height:100%;object-fit:cover;border-radius:inherit">` : sv.name[0].toUpperCase();
    return `<div class="home-row" onclick="selectSv('${sv.id}')">
      <div class="home-row-av" style="background:${bg};font-size:12px;font-weight:800">${ic}</div>
      <div style="min-width:0;flex:1"><div style="font-size:13px;font-weight:600">${esc(sv.name)}</div><div style="font-size:11px;color:var(--t3)">${sv.memberCount||1} member${(sv.memberCount||1)!==1?'s':''}</div></div>
      <svg width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" style="color:var(--t3);flex-shrink:0"><polyline points="9 18 15 12 9 6"/></svg>
    </div>`;
  }).join('') : '<div style="font-size:12px;color:var(--t3);padding:8px 0">No servers yet.</div>';
}
function showChat(){ hideAll(); document.getElementById('chat-wrap').classList.add('show'); document.getElementById('ch-hd').style.display='flex'; document.getElementById('sidebar').style.display=''; if (S.mbOpen) document.getElementById('members').style.display=''; document.body.classList.remove('in-dm'); }
function scrollBot(){ requestAnimationFrame(()=>{const el=document.getElementById('msgs');el.scrollTop=el.scrollHeight;}); }
function updSnd(){const ok=document.getElementById('msg-in').value.trim()||S.files.length;document.getElementById('snd-btn').classList.toggle('on',!!ok);}
function openM(id){document.getElementById(id).classList.add('open');}
function closeM(id){document.getElementById(id).classList.remove('open');}
function updateUser(){
  if(!S.user) return;
  const av=document.getElementById('u-av');
  if(S.user.pfp){ av.innerHTML=`<img src="${S.user.pfp}" alt="pfp"><div class="u-dot" id="u-dot"></div>`; av.style.background='transparent'; }
  else{ av.style.background=S.user.color; av.innerHTML=S.user.name[0].toUpperCase()+'<div class="u-dot" id="u-dot"></div>'; }
  document.getElementById('u-nm').textContent=S.user.name;
  const tagEl = document.getElementById('u-tg');
  const adminBadge = isSystemAdmin() ? ' <span style="font-size:9px;background:#6c63ff;color:#fff;padding:1px 5px;border-radius:4px;font-weight:700;letter-spacing:.05em">ADMIN</span>' : isCoAdmin() ? ' <span style="font-size:9px;background:#a855f7;color:#fff;padding:1px 5px;border-radius:4px;font-weight:700;letter-spacing:.05em">CO-ADMIN</span>' : '';
  tagEl.innerHTML = '#'+S.user.tag + adminBadge;
  // Show/hide admin panel button in u-acts
  let adminBtn = document.getElementById('admin-panel-btn');
  if (isPlatformPower()) {
    if (!adminBtn) {
      adminBtn = document.createElement('button');
      adminBtn.id = 'admin-panel-btn';
      adminBtn.className = 'ib';
      adminBtn.title = 'Admin Panel';
      adminBtn.innerHTML = '⚡';
      adminBtn.style.cssText = 'color:#fbbf24;font-size:14px';
      adminBtn.onclick = openAdminPanel;
      const uActs = document.getElementById('u-acts');
      if (uActs) uActs.prepend(adminBtn);
    }
  } else if (adminBtn) {
    adminBtn.remove();
  }
}
function toast(msg,type){const c=document.getElementById('toasts'),t=document.createElement('div');t.className='toast'+(type?' '+type:'');const icons={ok:'✓ ',err:'✕ ',warn:'⚠ '};t.textContent=(icons[type]||'')+msg;c.appendChild(t);setTimeout(()=>t.remove(),3200);}

// ── FORMATTERS ──
function fmtTxt(t){if(!t)return'';return fmtCustomEmoji(esc(t).replace(/@(\w+)/g,'<span class="mention">@$1</span>').replace(/`([^`]+)`/g,'<code>$1</code>').replace(/\n/g,'<br>'));}
function fmtDate(ts){const d=new Date(ts),n=new Date();if(d.toDateString()===n.toDateString())return'Today';const y=new Date(n);y.setDate(y.getDate()-1);if(d.toDateString()===y.toDateString())return'Yesterday';return d.toLocaleDateString('en-US',{month:'long',day:'numeric',year:'numeric'});}
function fmtTime(ts){return new Date(ts).toLocaleTimeString('en-US',{hour:'2-digit',minute:'2-digit'});}
function fmtB(b){return b<1024?b+'B':b<1048576?(b/1024).toFixed(1)+'KB':(b/1048576).toFixed(1)+'MB';}
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');}
// Only allow inline media data: URLs or http(s) with no attribute-breaking chars (stops XSS via attachment/pfp URLs)
function safeUrl(u){u=String(u||'');return /^(data:(image|video|audio)\/[\w.+-]+;base64,[A-Za-z0-9+\/=]+|https?:\/\/[^\s"'<>`\\]+)$/.test(u)?u:'';}
function safeId(i){return /^[\w.-]{0,64}$/.test(String(i))?String(i):'';}
function uid(){return Math.random().toString(36).slice(2)+Date.now().toString(36);}
function hash(s){let h=0;for(let i=0;i<s.length;i++){h=((h<<5)-h)+s.charCodeAt(i);h|=0;}return Math.abs(h);}

// ── PERSIST ──
function persist(){if(!S.user)return;lsSet('nx-data-'+S.user.name.toLowerCase(),{servers:S.servers,messages:S.messages,dms:S.dms,dmMessages:S.dmMessages,friends:S.friends,friendReqs:S.friendReqs});}
function lsGet(k){try{return JSON.parse(localStorage.getItem(k));}catch{return null;}}
function lsSet(k,v){try{localStorage.setItem(k,JSON.stringify(v));sessionStorage.setItem(k,JSON.stringify(v));}catch{}}
// ssGet: fallback read from sessionStorage (survives Ctrl+Shift+R hard refresh which wipes localStorage)
function ssGet(k){try{return JSON.parse(sessionStorage.getItem(k));}catch{return null;}}

// ── EVENTS ──
document.getElementById('msg-in').addEventListener('input',function(){this.style.height='auto';this.style.height=Math.min(this.scrollHeight,150)+'px';updSnd();onType();});
document.getElementById('msg-in').addEventListener('keydown',e=>{if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();sendMsg();}if(e.key==='Escape'&&editingMsgId){cancelEdit();}});
document.addEventListener('click',e=>{
  if(!e.target.closest('#main-emoji-picker')&&!e.target.closest('#emoji-trigger')) document.getElementById('main-emoji-picker').classList.remove('open');
  if(!e.target.closest('#react-picker')&&!e.target.closest('.ma')) closeReactPicker();
  if(!e.target.closest('#dm-panel')&&!e.target.closest('[onclick="toggleDM()"]')) document.getElementById('dm-panel').classList.remove('open');
  if(!e.target.closest('#sv-hd')) document.getElementById('sv-dropdown').classList.remove('open');
  if(!e.target.closest('#member-ctx')&&!e.target.closest('.mb-it')) document.getElementById('member-ctx').style.display='none';
});
document.querySelectorAll('.overlay').forEach(o=>o.addEventListener('click',e=>{if(e.target===o)o.classList.remove('open');}));
