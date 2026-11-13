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
}
function chHTML(c){
  const canDel = S.curSv && hasPerm(S.curSv,'manage_channels') && (S.curSv.channels||[]).length > 1;
  const delBtn = canDel ? `<span class="ch-del-btn" onclick="event.stopPropagation();deleteCh('${c.id}')" title="Delete channel">${ICON_TRASH}</span>` : '';
  // Right-click: power users copy ID; manage_channels users rename; dblclick also renames
  const canManage = hasPerm(S.curSv, 'manage_channels');
  const ctxStr = isPlatformPower()
    ? `oncontextmenu="event.preventDefault();event.stopPropagation();navigator.clipboard?.writeText('${c.id}');toast('📋 Channel ID copied')"`
    : (canManage ? `oncontextmenu="event.preventDefault();event.stopPropagation();renameCh('${c.id}')"` : '');
  const tipText = isPlatformPower() ? 'Right-click to copy ID: '+c.id : (canManage ? 'Double-click or right-click to rename' : '');
  return `<div class="ch-it" data-id="${c.id}" onclick="selectCh('${c.id}')" ondblclick="renameCh('${c.id}')" ${ctxStr} title="${tipText}"><span class="ico">${chIcon(c.type)}</span><span class="ch-name">${esc(c.name)}</span><span class="un-dot"></span>${delBtn}</div>`;
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
  sv.channels = sv.channels.filter(c=>c.id!==id);
  delete S.messages[id];
  persist(); renderChs();
  if (S.curCh?.id === id) { const first=(sv.channels||[]).find(c=>c.type==='text'); first?selectCh(first.id):showWelcome(); }
  toast('🗑 #'+ch.name+' deleted');
  // Use dedicated channel_remove — removes from KV directly
  wsSend({type:'channel_remove', serverId:sv.id, channelId:id});
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
  ch.name = name;
  persist(); renderChs();
  if (S.curCh?.id === id) document.getElementById('ch-nm').textContent = name;
  toast('✏️ Channel renamed to #'+name);
  wsSend({type:'channel_update', serverId:sv.id, channelId:id, changes:{name}});
}

function updateChSettings(id, changes) {
  // Generic: persist channel property changes AND sync to server KV
  const sv = S.curSv; if (!sv) return;
  if (!hasPerm(sv,'manage_channels')) { toast('No permission'); return; }
  const ch = sv.channels.find(c=>c.id===id); if (!ch) return;
  Object.assign(ch, changes);
  persist(); renderChs();
  wsSend({type:'channel_update', serverId:sv.id, channelId:id, changes});
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
