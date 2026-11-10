// ══════════════════════════════════
// CHANNELS
// ══════════════════════════════════
function renderChs() {
  const el=document.getElementById('ch-list'); el.innerHTML='';
  if(!S.curSv) return;
  const chs = S.curSv.channels || [];
  if (!chs.length) { el.innerHTML='<div style="padding:16px;font-size:12px;color:var(--t3);text-align:center">No channels yet</div>'; return; }
  const txt=chs.filter(c=>c.type==='text');
  const vox=chs.filter(c=>c.type==='voice');
  if(txt.length){ el.innerHTML+=`<div class="ch-cat"><span>Text Channels</span><span class="cat-add" onclick="openM('ach')">+</span></div>`; txt.forEach(c=>el.innerHTML+=chHTML(c,'#')); }
  if(vox.length){ el.innerHTML+=`<div class="ch-cat"><span>Voice Channels</span><span class="cat-add" onclick="openM('ach')">+</span></div>`; vox.forEach(c=>el.innerHTML+=chHTML(c,'🔊')); }
  hlCh();
}
function chHTML(c,ico){
  const canDel = S.curSv && hasPerm(S.curSv,'manage_channels') && (S.curSv.channels||[]).length > 1;
  const delBtn = canDel ? `<span class="ch-del-btn" onclick="event.stopPropagation();deleteCh('${c.id}')" title="Delete channel">🗑</span>` : '';
  // Right-click: power users copy ID; manage_channels users rename; dblclick also renames
  const canManage = hasPerm(S.curSv, 'manage_channels');
  const ctxStr = isPlatformPower()
    ? `oncontextmenu="event.preventDefault();event.stopPropagation();navigator.clipboard?.writeText('${c.id}');toast('📋 Channel ID copied')"`
    : (canManage ? `oncontextmenu="event.preventDefault();event.stopPropagation();renameCh('${c.id}')"` : '');
  const tipText = isPlatformPower() ? 'Right-click to copy ID: '+c.id : (canManage ? 'Double-click or right-click to rename' : '');
  return `<div class="ch-it" data-id="${c.id}" onclick="selectCh('${c.id}')" ondblclick="renameCh('${c.id}')" ${ctxStr} title="${tipText}"><span class="ico">${ico}</span><span style="flex:1">${esc(c.name)}</span><span class="un-dot"></span>${delBtn}</div>`;
}
function hlCh(){ document.querySelectorAll('.ch-it').forEach(el=>{ el.classList.toggle('act',el.dataset.id===S.curCh?.id); if(el.dataset.id===S.curCh?.id) el.classList.remove('unread'); }); }
function selectCh(id) {
  const ch=(S.curSv?.channels||[]).find(c=>c.id===id); if(!ch) return;
  if (S.curCh?.type==='voice' && S.curCh.id!==id) leaveVoice();
  S.curCh=ch;
  document.getElementById('ch-nm').textContent=ch.name;
  document.getElementById('ch-desc').textContent=ch.desc||'';
  document.getElementById('ch-ico').textContent=ch.type==='voice'?'🔊':'#';
  document.getElementById('msg-in').placeholder=`Message #${ch.name}`;
  document.getElementById('ch-hd').style.display='flex';
  const msgsEl = document.getElementById('msgs');
  if (msgsEl) msgsEl.classList.add('switching');
  if (ch.type==='voice') {
    showChat(); hlCh();
    requestAnimationFrame(() => { renderMsgs(ch.id); if(msgsEl) msgsEl.classList.remove('switching'); });
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
    requestAnimationFrame(() => { renderMsgs(ch.id); scrollBot(); if(msgsEl) msgsEl.classList.remove('switching'); autoRequestStrippedVideos(ch.id); });
  }
  Object.keys(typers).forEach(k=>delete typers[k]); renderTypingBar();
  wsSend({type:'join_channel',channelId:id,serverId:S.curSv?.id});
  const msgs = S.messages[id]||[];
  const lastTs = msgs.length ? msgs[msgs.length-1].ts : 0;
  wsSend({type:'get_history', channelId:id, since:lastTs||0});
  updatePinnedBar();
}
function markUnread(chId){ document.querySelector(`.ch-it[data-id="${chId}"]`)?.classList.add('unread'); }
function addCh() {
  const raw=document.getElementById('ch-in').value.trim(); if(!raw||!S.curSv) return;
  const name=raw.toLowerCase().replace(/\s+/g,'-').replace(/[^a-z0-9-]/g,'');
  const newCh = {id:uid(),name,type:S.chType,desc:''};
  S.curSv.channels.push(newCh); persist(); closeM('ach'); renderChs();
  selectCh(newCh.id);
  toast('✅ #'+name+' created'); document.getElementById('ch-in').value='';
  // Use dedicated channel_add — writes directly to KV on server
  wsSend({type:'channel_add', serverId:S.curSv.id, channel:newCh});
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
