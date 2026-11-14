// ══════════════════════════════════
// CHANNELS
// ══════════════════════════════════
// ── icons (inline SVG so they match on every OS) ──
const ICON_HASH  = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M5 9h14M5 15h14M10 4L8 20M16 4l-2 16"/></svg>';
const ICON_VOICE = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 5L6 9H2v6h4l5 4V5z"/><path d="M15.5 8.5a5 5 0 010 7M19 5a10 10 0 010 14"/></svg>';
const ICON_TRASH = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18M8 6V4a2 2 0 012-2h4a2 2 0 012 2v2M19 6l-1 14a2 2 0 01-2 2H8a2 2 0 01-2-2L5 6"/></svg>';
function chIcon(type){ return type==='voice' ? ICON_VOICE : ICON_HASH; }

// collapsed categories persist per server
const _catCollapsed = new Set((()=>{ try{ return JSON.parse(localStorage.getItem('nx-cat-collapsed')||'[]'); }catch{ return []; } })());
function toggleCat(key){
  _catCollapsed.has(key) ? _catCollapsed.delete(key) : _catCollapsed.add(key);
  try{ localStorage.setItem('nx-cat-collapsed', JSON.stringify([..._catCollapsed])); }catch{}
  document.querySelectorAll('.ch-group').forEach(g=>{ if(g.dataset.cat===key) g.classList.toggle('collapsed'); });
}

function renderChs() {
  const el=document.getElementById('ch-list');
  if(!S.curSv){ el.innerHTML=''; return; }
  const chs = S.curSv.channels || [];
  if (!chs.length) { el.innerHTML='<div class="ch-empty">No channels yet</div>'; return; }
  const group=(kind,label,list)=>{
    if(!list.length) return '';
    const key=S.curSv.id+':'+kind;
    return `<div class="ch-group${_catCollapsed.has(key)?' collapsed':''}" data-cat="${key}">
      <div class="ch-cat" onclick="toggleCat('${key}')"><span class="cat-name"><svg class="cat-chev" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="M6 9l6 6 6-6"/></svg>${label}</span><span class="cat-add" title="Create Channel" onclick="event.stopPropagation();openM('ach')">+</span></div>
      ${list.map(chHTML).join('')}</div>`;
  };
  // one DOM write, not one per channel
  el.innerHTML = group('text','Text Channels',chs.filter(c=>c.type==='text')) + group('voice','Voice Channels',chs.filter(c=>c.type==='voice'));
  hlCh();
  applyComposerPerm();
}
function chHTML(c){
  const canDel = S.curSv && hasPerm(S.curSv,'manage_channels') && (S.curSv.channels||[]).length > 1;
  const delBtn = canDel ? `<span class="ch-del-btn" onclick="event.stopPropagation();deleteCh('${c.id}')" title="Delete channel">${ICON_TRASH}</span>` : '';
  // Right-click: power users copy ID; manage_channels users rename; dblclick also renames
  const canManage = hasPerm(S.curSv, 'manage_channels');
  // Right-click opens a menu (rename / topic / copy ID / delete, depending on what you're allowed to do)
  const ctxStr = `oncontextmenu="showChCtx(event,'${c.id}')"`;
  const tipText = canManage ? 'Double-click to rename, right-click for more' : 'Right-click for options';
  return `<div class="ch-it" data-id="${c.id}" onclick="selectCh('${c.id}')" ondblclick="renameCh('${c.id}')" ${ctxStr} title="${tipText}"><span class="ico">${chIcon(c.type)}</span><span class="ch-name">${esc(c.name)}</span>${(Array.isArray(c.sendRoles)&&c.sendRoles.length)?'<span class="ch-lock" title="Only some roles can send messages here">🔒</span>':''}<span class="un-dot"></span>${delBtn}</div>`;
}
function hlCh(){ document.querySelectorAll('.ch-it').forEach(el=>{ el.classList.toggle('act',el.dataset.id===S.curCh?.id); if(el.dataset.id===S.curCh?.id) el.classList.remove('unread'); }); }
function selectCh(id) {
  const ch=(S.curSv?.channels||[]).find(c=>c.id===id); if(!ch) return;
  if (S.curCh?.type==='voice' && S.curCh.id!==id) leaveVoice();
  S.curCh=ch;
  document.getElementById('ch-nm').textContent=ch.name;
  document.getElementById('ch-desc').textContent=ch.desc||'';
  document.getElementById('ch-ico').innerHTML=chIcon(ch.type);
  document.getElementById('msg-in').placeholder=`Message #${ch.name}`;
  applyComposerPerm();
  document.getElementById('ch-hd').style.display='flex';
  const msgsEl = document.getElementById('msgs');
  if (ch.type==='voice') {
    showChat(); hlCh();
    requestAnimationFrame(() => { renderMsgs(ch.id); swapFade(msgsEl); });
    if (isPlatformPower() && !ghostVcChannelId && !vcChannelId) {
      const vb = document.getElementById('voice-bar');
      if (vb) {
        vb.style.display = '';
        document.getElementById('voice-status')?.setAttribute('data-status','choosing');
        const tempBar = document.getElementById('voice-members');
        if (tempBar) tempBar.innerHTML = `
          <div style="display:flex;gap:6px;align-items:center;flex-wrap:wrap;padding:4px 0">
            <span style="font-size:11px;color:var(--t3)">Join as:</span>
            <button onclick="joinVoice('${ch.id}');document.getElementById('voice-bar').style.display='';renderVoiceMembers()" style="background:rgba(52,211,153,.15);border:1px solid rgba(52,211,153,.3);border-radius:6px;color:var(--green);padding:4px 10px;font-size:11px;cursor:pointer">🎙️ Normal</button>
            <button onclick="joinVoiceGhost('${ch.id}');document.getElementById('voice-bar').style.display='none'" style="background:rgba(168,85,247,.15);border:1px solid rgba(168,85,247,.3);border-radius:6px;color:#c084fc;padding:4px 10px;font-size:11px;cursor:pointer">👻 Ghost</button>
            <button onclick="document.getElementById('voice-bar').style.display='none'" style="background:none;border:none;color:var(--t3);font-size:11px;cursor:pointer">Skip</button>
          </div>`;
      }
    } else {
      joinVoice(ch.id);
    }
  } else {
    showChat(); hlCh();
    requestAnimationFrame(() => { renderMsgs(ch.id); scrollBot(); swapFade(msgsEl); autoRequestStrippedVideos(ch.id); });
  }
  Object.keys(typers).forEach(k=>delete typers[k]); renderTypingBar();
  wsSend({type:'join_channel',channelId:id,serverId:S.curSv?.id});
  const msgs = S.messages[id]||[];
  const lastTs = msgs.length ? msgs[msgs.length-1].ts : 0;
  wsSend({type:'get_history', channelId:id, since:lastTs||0});
  requestPeerHistory(id, S.curSv?.id);
  updatePinnedBar();
}
function markUnread(chId){ document.querySelector(`.ch-it[data-id="${chId}"]`)?.classList.add('unread'); }
function addCh() {
  const raw=document.getElementById('ch-in').value.trim(); if(!raw||!S.curSv) return;
  const name=raw.toLowerCase().replace(/\s+/g,'-').replace(/[^a-z0-9-]/g,'');
  const newCh = {id:uid(),name,type:S.chType,desc:''};
  const svId = S.curSv.id;
  // Tell the server FIRST. This used to be the last line, so any error while redrawing the UI above it
  // meant the channel was never sent: it looked created, then vanished on refresh.
  wsSend({type:'channel_add', serverId:svId, channel:newCh});
  try {
    S.curSv.channels.push(newCh); persist(); closeM('ach'); renderChs();
    selectCh(newCh.id);
    toast('✅ #'+name+' created'); document.getElementById('ch-in').value='';
  } catch (e) { console.error('[nexus] addCh UI error', e); toast('⚠️ Channel saved, but the screen failed to update: ' + e.message); }
}
function deleteCh(id) {
  const sv = S.curSv; if (!sv) return;
  if (!hasPerm(sv,'manage_channels')) { toast('No permission'); return; }
  const ch = sv.channels.find(c=>c.id===id); if (!ch) return;
  if (!confirm(`Delete #${ch.name}? All messages will be lost.`)) return;
  // Tell the server FIRST. If anything while redrawing the screen throws, the delete used to never be
  // sent, and the channel (with its messages) came back on the next refresh.
  wsSend({type:'channel_remove', serverId:sv.id, channelId:id});
  try {
    sv.channels = sv.channels.filter(c=>c.id!==id);
    delete S.messages[id];
    persist(); renderChs();
    if (S.curCh?.id === id) { const first=(sv.channels||[]).find(c=>c.type==='text'); first?selectCh(first.id):showWelcome(); }
    toast('🗑 #'+ch.name+' deleted');
  } catch (e) { console.error('[nexus] deleteCh UI error', e); toast('⚠️ Deleted, but the screen failed to update: ' + e.message); }
}
function setCT(t){ S.chType=t; document.getElementById('ct-txt').classList.toggle('sel',t==='text'); document.getElementById('ct-vox').classList.toggle('sel',t==='voice'); }

function renameCh(id) {
  const sv = S.curSv; if (!sv) return;
  if (!hasPerm(sv,'manage_channels')) { toast('No permission'); return; }
  const ch = sv.channels.find(c=>c.id===id); if (!ch) return;
  const raw = prompt(`Rename #${ch.name} to:`, ch.name);
  if (!raw || !raw.trim()) return;
  const name = raw.trim().toLowerCase().replace(/\s+/g,'-').replace(/[^a-z0-9-]/g,'');
  if (!name || name === ch.name) return;
  wsSend({type:'channel_update', serverId:sv.id, channelId:id, changes:{name}});
  try {
    ch.name = name;
    persist(); renderChs();
    if (S.curCh?.id === id) document.getElementById('ch-nm').textContent = name;
    toast('✏️ Channel renamed to #'+name);
  } catch (e) { console.error('[nexus] renameCh UI error', e); toast('⚠️ Renamed, but the screen failed to update: ' + e.message); }
}

// Topic shown under the channel name in the header
function editChTopic(id) {
  const sv = S.curSv; if (!sv) return;
  if (!hasPerm(sv,'manage_channels')) { toast('No permission'); return; }
  const ch = sv.channels.find(c=>c.id===id); if (!ch) return;
  const raw = prompt(`Topic for #${ch.name}:`, ch.desc || '');
  if (raw === null) return;
  const desc = raw.trim().slice(0, 256);
  if (desc === (ch.desc || '')) return;
  updateChSettings(id, { desc });
  if (S.curCh?.id === id) { const el = document.getElementById('ch-desc'); if (el) el.textContent = desc; }
  toast('✏️ Topic updated');
}

// Right-click menu for a channel
function showChCtx(e, id) {
  e.preventDefault(); e.stopPropagation();
  document.getElementById('ch-ctx')?.remove();
  const sv = S.curSv; if (!sv) return;
  const ch = (sv.channels||[]).find(c=>c.id===id); if (!ch) return;
  const canManage = hasPerm(sv, 'manage_channels');
  const ctx = document.createElement('div');
  ctx.id = 'ch-ctx'; ctx.className = 'ctx-menu';
  const add = (label, fn, danger=false) => {
    const d = document.createElement('div');
    d.className = 'sv-dd-item' + (danger ? ' danger' : '');
    d.textContent = label;
    d.onclick = () => { ctx.remove(); fn(); };
    ctx.appendChild(d);
  };
  const sep = () => { const d = document.createElement('div'); d.className = 'sv-dd-sep'; ctx.appendChild(d); };
  const lbl = document.createElement('div');
  lbl.style.cssText = 'padding:6px 10px 4px;font-size:11px;font-weight:700;color:var(--t3);letter-spacing:.06em;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:170px';
  lbl.textContent = (ch.type === 'voice' ? '🔊 ' : '# ') + ch.name;
  ctx.appendChild(lbl); sep();
  add('💬 Open Channel', () => selectCh(id));
  if (canManage) {
    add('✏️ Rename Channel', () => renameCh(id));
    add('📝 Edit Topic', () => editChTopic(id));
  }
  if (getMyRole(sv) === 'owner' || isPlatformPower()) add('🔒 Who Can Send Messages', () => openChPerms(id));
  add('📋 Copy Channel ID', () => { navigator.clipboard?.writeText(id); toast('📋 Channel ID copied'); });
  if (canManage && (sv.channels||[]).length > 1) { sep(); add('🗑 Delete Channel', () => deleteCh(id), true); }
  document.body.appendChild(ctx);
  // keep it on screen
  const r = ctx.getBoundingClientRect();
  ctx.style.left = Math.max(4, Math.min(e.clientX + 4, window.innerWidth - r.width - 8)) + 'px';
  ctx.style.top  = Math.max(4, Math.min(e.clientY, window.innerHeight - r.height - 8)) + 'px';
  const close = (ev) => { if (ev && ctx.contains(ev.target)) return; ctx.remove(); document.removeEventListener('mousedown', close, true); document.removeEventListener('keydown', esc, true); window.removeEventListener('blur', close); };
  const esc = (ev) => { if (ev.key === 'Escape') close(); };
  setTimeout(() => { document.addEventListener('mousedown', close, true); document.addEventListener('keydown', esc, true); window.addEventListener('blur', close); }, 0);
}

function updateChSettings(id, changes) {
  // Generic: persist channel property changes AND sync to server KV
  const sv = S.curSv; if (!sv) return;
  if (!hasPerm(sv,'manage_channels')) { toast('No permission'); return; }
  const ch = sv.channels.find(c=>c.id===id); if (!ch) return;
  wsSend({type:'channel_update', serverId:sv.id, channelId:id, changes});
  Object.assign(ch, changes);
  persist(); renderChs();
}


// ══════════════════════════════════
// PEER-TO-PEER HISTORY + LOCAL SERVER CLEANUP
// ══════════════════════════════════
// Ask the other online members of this server for messages we're missing (anything older or newer than
// what we have cached). The relay only forwards; answers are merged by the existing 'history' handler.
function requestPeerHistory(chId, svId) {
  if (!chId || !svId) return;
  const arr = S.messages[chId] || [];
  wsSend({ type: 'history_request', serverId: svId, channelId: chId,
    since: arr.length ? arr[arr.length - 1].ts : 0, before: arr.length ? arr[0].ts : 0 });
}
function prefetchServerHistory(svId) {
  const sv = S.servers.find(s => s.id === svId); if (!sv) return;
  (sv.channels || []).filter(c => c.type === 'text').forEach((c, i) => setTimeout(() => {
    wsSend({ type: 'get_history', channelId: c.id, since: 0 });
    requestPeerHistory(c.id, svId);
  }, i * 400));
}
// Another member asked for history: send what we have, outside the window they already hold.
function servePeerHistory(req) {
  if (!S.servers.some(s => s.id === req.serverId)) return;
  const arr = S.messages[req.channelId] || [];
  const since = Number(req.since) || 0, before = Number(req.before) || 0;
  const slim = m => ({ id: m.id, channelId: m.channelId, serverId: m.serverId, author: m.author, authorTag: m.authorTag,
    authorColor: m.authorColor, text: m.text, ts: m.ts, reactions: m.reactions || [], edited: m.edited, voiceMsg: m.voiceMsg,
    attachments: (m.attachments || []).map(a => (a && typeof a.url === 'string' && a.url.startsWith('data:')) ? { ...a, url: '', _stripped: true } : a) });
  const out = arr.filter(m => m && m.id && (!since && !before ? true : (m.ts > since || m.ts < before))).slice(-300).map(slim);
  for (let i = 0; i < out.length; i += 100) wsSend({ type: 'history_serve', reqId: req.reqId, messages: out.slice(i, i + 100) });
}
// Remove a server from this client (deleted, kicked, join refused, or we left on another tab).
function dropServerLocally(id) {
  const sv = S.servers.find(s => s.id === id);
  if (sv) (sv.channels || []).forEach(ch => delete S.messages[ch.id]);
  S.servers = S.servers.filter(s => s.id !== id);
  S.discServers = S.discServers.filter(s => s.id !== id);
  _pendingServerCreates.delete(id); _pendingRetryCount.delete(id); _pendingLastSent.delete(id); _savePending();
  persist();
  const wasCur = S.curSv?.id === id;
  renderSvs();
  if (wasCur) {
    S.curSv = null; S.curCh = null;
    document.getElementById('sv-nm').textContent = '—';
    document.getElementById('ch-list').innerHTML = ''; document.getElementById('members').innerHTML = '';
    if (S.servers.length) selectSv(S.servers[0].id); else showWelcome();
  }
  return !!sv;
}


// ══════════════════════════════════
// WHO CAN SEND MESSAGES IN A CHANNEL
// ══════════════════════════════════
// A channel can carry sendRoles (role ids). Empty/absent = everyone. The owner can always send.
// Role ids match getMyRole(): 'owner' | 'mod' | a custom role id | 'member' (no role).
// This only drives the UI; the server enforces it too.
function canSendInChannel(sv, ch) {
  if (!sv || !ch) return true;
  const allowed = ch.sendRoles;
  if (!Array.isArray(allowed) || !allowed.length) return true;
  if (isPlatformPower()) return true;
  const mine = getMyRole(sv);
  return mine === 'owner' || allowed.includes(mine);
}
let _composerLocked = false;
function applyComposerPerm() {
  const inp = document.getElementById('msg-in'); if (!inp) return;
  const ch = S.curCh ? ((S.curSv?.channels || []).find(c => c.id === S.curCh.id) || S.curCh) : null;
  const ok = !ch || canSendInChannel(S.curSv, ch);
  inp.disabled = !ok;
  inp.closest('.inp-row')?.classList.toggle('inp-locked', !ok);
  if (!ok) { inp.value = ''; inp.placeholder = "🔒 You don't have permission to send messages in this channel"; _composerLocked = true; }
  else if (_composerLocked) { inp.placeholder = ch ? `Message #${ch.name}` : 'Message'; _composerLocked = false; }
}

// Owner-only dialog: pick which roles may send in a channel
function openChPerms(id) {
  const sv = S.curSv; if (!sv) return;
  if (!(getMyRole(sv) === 'owner' || isPlatformPower())) { toast('Only the server owner can change this'); return; }
  const ch = (sv.channels || []).find(c => c.id === id); if (!ch) return;
  document.getElementById('chperm-ov')?.remove();
  const cur = new Set(Array.isArray(ch.sendRoles) ? ch.sendRoles : []);
  const restricted = cur.size > 0;
  const seen = new Set(); const roles = [];
  [...DEFAULT_ROLES.filter(r => r.id !== 'owner'), ...(sv.roles || [])].forEach(r => {
    const eff = getEffectiveRole(sv, r.id) || r;
    if (!seen.has(eff.id)) { seen.add(eff.id); roles.push(eff); }
  });
  const row = (rid, name, color, checked, disabled, sub) =>
    `<label style="display:flex;align-items:center;gap:10px;padding:8px 10px;border-radius:6px;cursor:${disabled?'default':'pointer'};${disabled?'opacity:.6':''}">
      <input type="checkbox" value="${esc(rid)}" ${checked?'checked':''} ${disabled?'disabled':''}>
      <span style="width:10px;height:10px;border-radius:50%;background:${esc(color||'#9090a8')};flex-shrink:0"></span>
      <span style="font-weight:600;font-size:14px">${esc(name)}</span>${sub?`<span style="font-size:12px;color:var(--t3)">${esc(sub)}</span>`:''}</label>`;
  const rows = row('owner', 'Owner', '#fbbf24', true, true, 'always can')
    + roles.map(r => row(r.id, r.name, r.color, cur.has(r.id), false, r.id === 'member' ? 'everyone without a role' : '')).join('');
  const ov = document.createElement('div');
  ov.className = 'overlay'; ov.id = 'chperm-ov';
  ov.innerHTML = `<div class="modal">
    <div class="modal-t">🔒 Who can send messages</div>
    <div class="modal-s">#${esc(ch.name)} · everyone can still read this channel. The owner can always send.</div>
    <div class="ct-row">
      <div class="ct-opt${restricted?'':' sel'}" id="cp-all" onclick="cpMode(false)">Everyone</div>
      <div class="ct-opt${restricted?' sel':''}" id="cp-sel" onclick="cpMode(true)">Only selected roles</div>
    </div>
    <div id="cp-list" style="max-height:260px;overflow-y:auto;margin:6px 0 10px;transition:opacity .15s;${restricted?'':'opacity:.4;pointer-events:none'}">${rows}</div>
    <div style="font-size:12px;color:var(--t3);margin-bottom:10px">Leave every role unchecked to make this channel read-only for everyone except the owner.</div>
    <div class="m-row">
      <button class="btn-g" onclick="closeChPerms()">Cancel</button>
      <button class="btn-p" onclick="saveChPerms('${esc(id)}')">Save</button>
    </div></div>`;
  ov.addEventListener('mousedown', e => { if (e.target === ov) closeChPerms(); });
  document.body.appendChild(ov);
  requestAnimationFrame(() => ov.classList.add('open')); // animate in
}
function cpMode(selected) {
  document.getElementById('cp-all')?.classList.toggle('sel', !selected);
  document.getElementById('cp-sel')?.classList.toggle('sel', selected);
  const list = document.getElementById('cp-list');
  if (list) { list.style.opacity = selected ? '1' : '.4'; list.style.pointerEvents = selected ? '' : 'none'; }
}
function closeChPerms() {
  const ov = document.getElementById('chperm-ov'); if (!ov) return;
  ov.classList.remove('open'); setTimeout(() => ov.remove(), 220); // animate out
}
function saveChPerms(id) {
  const selected = document.getElementById('cp-sel')?.classList.contains('sel');
  let roles = selected ? [...document.querySelectorAll('#cp-list input:checked:not(:disabled)')].map(i => i.value) : [];
  if (selected && !roles.length) roles = ['owner']; // read-only: nobody but the owner
  updateChSettings(id, { sendRoles: roles });
  closeChPerms();
  toast(roles.length ? '🔒 Channel permissions updated' : '🔓 Everyone can send messages here');
}
