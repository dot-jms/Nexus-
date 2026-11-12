// ══════════════════════════════════
// MESSAGES
// ══════════════════════════════════
function renderMsgs(chId) {
  const msgs=S.messages[chId]||[];
  const el=document.getElementById('msgs'); el.innerHTML='';
  if(!msgs.length){ const n=esc(S.curCh?.name||''); el.innerHTML=`<div class="ch-intro"><div class="ch-intro-ico">${chIcon(S.curCh?.type)}</div><h3>Welcome to #${n}!</h3><p>This is the start of the #${n} channel.</p></div>`; return; }
  let ld='',la='',lt=0;
  const parts=[];
  msgs.forEach(m=>{ const d=fmtDate(m.ts); if(d!==ld){parts.push(`<div class="day-sep">${d}</div>`);ld=d;la='';lt=0;} const grp=m.author===la&&(m.ts-lt)<300000; parts.push(buildMsg(m,grp)); la=m.author;lt=m.ts; });
  el.innerHTML=parts.join('');
  scrollBot();
}

// ── message toolbar icons ──
const MI = {
  react:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M8 14s1.5 2 4 2 4-2 4-2"/><path d="M9 9h.01M15 9h.01"/></svg>',
  reply:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 17l-5-5 5-5"/><path d="M20 18v-2a4 4 0 00-4-4H4"/></svg>',
  pin:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="17" x2="12" y2="22"/><path d="M5 17h14v-3l-2-5V3H7v6l-2 5v3z"/></svg>',
  edit:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 013 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>',
  del:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18M8 6V4a2 2 0 012-2h4a2 2 0 012 2v2M19 6l-1 14a2 2 0 01-2 2H8a2 2 0 01-2-2L5 6M10 11v6M14 11v6"/></svg>'
};

function buildMsg(m,grp) {
  m={...m,id:safeId(m.id),channelId:safeId(m.channelId)};
  const ac=m.authorColor||COLORS[hash(m.author)%COLORS.length];
  const init=(m.author||'?')[0].toUpperCase();
  const isMe=m.author===S.user?.name;
  // Always use the latest known pfp — profileCache is updated on every profile_update broadcast.
  // Falls back to the pfp snapshotted at send time, then to initials.
  let livePfp = isMe ? (S.user.pfp||null) : (profileCache[m.author]?.pfp !== undefined ? profileCache[m.author].pfp : m.authorPfp);
  livePfp=safeUrl(livePfp);
  const avInner=livePfp?`<img src="${livePfp}" alt="">`:`<span>${init}</span>`;
  let atts='';
  (m.attachments||[]).forEach(a=>{
    a={...a,url:safeUrl(a.url)};
    if(a.type==='image') atts+=`<div class="m-img"><img src="${a.url}" alt="${esc(a.name)}" loading="lazy" onclick="openLB('${a.url}')"></div>`;
    else if(a.type==='video') {
      if(a._stripped || !a.url) {
        // Video not cached locally — show click-to-load placeholder
        atts+=`<div class="vid-placeholder" data-msg-id="${m.id}" data-ch-id="${m.channelId}" data-name="${esc(a.name)}" onclick="requestVideo('${m.id}','${m.channelId}','${esc(a.name)}')" style="display:flex;align-items:center;gap:10px;background:var(--s3);border:1px solid var(--border2);border-radius:8px;padding:12px 16px;cursor:pointer;max-width:280px;transition:all .13s"><span style="font-size:24px">🎬</span><div><div style="font-size:12px;font-weight:700;color:var(--t2)">${esc(a.name||'Video')}</div><div style="font-size:10px;color:var(--t3);margin-top:2px">Click to load from another user</div></div></div>`;
      } else {
        atts+=`<div class="m-vid"><video controls><source src="${a.url}"></video></div>`;
      }
    }
    else if(a.type==='audio') {
      const aid = 'att-audio-' + (a.url||'').slice(-8).replace(/[^a-z0-9]/gi,'');
      atts += `<div class="audio-att" id="${aid}">
        <div class="audio-att-icon"><svg width="13" height="13" fill="currentColor" viewBox="0 0 24 24"><path d="M9 18V5l12-2v13"/><circle cx="6" cy="18" r="3"/><circle cx="18" cy="16" r="3"/></svg></div>
        <div class="audio-att-body">
          <div class="audio-att-name">${esc(a.name)}</div>
          <div class="audio-att-track">
            <button class="audio-att-btn" onclick="playAttAudio('${aid}','${a.url}',this)">
              <svg class="play-icon" width="10" height="10" fill="currentColor" viewBox="0 0 24 24"><polygon points="5 3 19 12 5 21 5 3"/></svg>
              <svg class="pause-icon" width="10" height="10" fill="currentColor" viewBox="0 0 24 24" style="display:none"><rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/></svg>
            </button>
            <div class="audio-att-bar"><div class="audio-att-prog" id="${aid}-prog"></div></div>
            <div class="audio-att-time" id="${aid}-time">0:00</div>
          </div>
        </div>
      </div>`;
    }
    else atts+=`<div class="m-file"><div class="f-ico">📄</div><div><div class="f-nm">${esc(a.name)}</div><div class="f-sz">${a.size||''}</div></div></div>`;
  });
  let reacts='';
  if((m.reactions||[]).length){ reacts='<div class="m-reacts">'+m.reactions.map(r=>`<div class="react${r.users?.includes(S.user?.name)?' me':''}" onclick="toggleReact('${m.id}','${r.emoji}')">${r.emoji}<span>${r.count}</span></div>`).join('')+'</div>'; }
  const lead = grp
    ? `<div class="m-gutter"><span class="m-gtime">${fmtClock(m.ts)}</span></div>`
    : `<div class="m-av" style="background:${livePfp?'transparent':ac}" onmouseenter="showUserHover('${esc(m.author)}',this)" onmouseleave="if(!event.relatedTarget?.closest('.user-hover-popup'))hideUserHover()" onclick="openProfilePage('${esc(m.author)}')">${avInner}</div>`;
  return `<div class="msg${grp?' grouped':''}" data-id="${m.id}">
    ${lead}
    <div class="m-body">
      ${!grp?`<div class="m-head"><span class="m-auth" onmouseenter="showUserHover('${esc(m.author)}',this)" onmouseleave="if(!event.relatedTarget?.closest('.user-hover-popup'))hideUserHover()" onclick="openProfilePage('${esc(m.author)}')">${esc(m.author)}</span><span class="m-time">${fmtStamp(m.ts)}</span></div>`:''}
      ${m.voiceMsg ? buildVoiceMsg(m) : `<div class="m-txt">${fmtTxt(m.text)}${m.edited?'<span class="m-edited">(edited)</span>':''}</div>`}${atts?`<div class="m-atts">${atts}</div>`:''}${reacts}
    </div>
    <div class="m-acts">
      <div class="ma" title="Add Reaction" onclick="openReactPicker('${m.id}',event)">${MI.react}</div>
      <div class="ma" title="Reply" onclick="replyTo('${esc(m.author)}')">${MI.reply}</div>
      ${!curDM?`<div class="ma" title="Pin Message" onclick="pinMsg('${m.id}')">${MI.pin}</div>`:''}
      ${(isMe||isPlatformPower())?`<div class="ma" title="Edit" onclick="startEditMsg('${m.id}')">${MI.edit}</div>`:''}
      ${(isMe||isPlatformPower())?`<div class="ma danger" title="Delete" onclick="delMsg('${m.id}')">${MI.del}</div>`:''}
    </div>
  </div>`;
}

function sendMsg() {
  const inp=document.getElementById('msg-in'); const text=inp.value.trim();
  if(!text&&!S.files.length) return;
  if (editingMsgId) { if(text) commitEdit(text); else cancelEdit(); inp.value=''; inp.style.height='auto'; updSnd(); return; }
  if(!S.curCh){toast('Pick a channel first');return;}
  const msg={id:uid(),channelId:S.curCh.id,serverId:S.curSv?.id,author:S.user.name,authorTag:S.user.tag,authorColor:S.user.color,authorPfp:S.user.pfp||null,text,attachments:S.files.map(f=>({name:f.name,url:f.url,type:f.mt,size:fmtB(f.size)})),ts:Date.now(),reactions:[]};
  addMsg(msg);
  // Fast path: append single message node instead of full re-render
  appendMsgDOM(msg);
  wsSend({type:'message',...msg});
  inp.value=''; inp.style.height='auto'; S.files=[];
  const p=document.getElementById('att-prev'); p.innerHTML=''; p.classList.remove('show');
  updSnd();
}

function appendMsgDOM(m) {
  const el = document.getElementById('msgs');
  if (!el) return;
  // Check if grouped (same author within 5 min)
  const msgs = S.messages[m.channelId] || [];
  const prev = msgs[msgs.length - 2]; // -2 because we already pushed current
  const grp = prev && prev.author === m.author && (m.ts - prev.ts) < 300000;
  const div = document.createElement('div');
  div.innerHTML = buildMsg(m, grp);
  const node = div.firstElementChild;
  if (node) {
    node.classList.add('new');
    el.appendChild(node);
    scrollBot();
  }
}
function addMsg(m){ if(!S.messages[m.channelId]) S.messages[m.channelId]=[]; S.messages[m.channelId].push(m); persist(); }
function delMsg(id){ if(curDM){const arr=S.dmMessages[curDM];if(!arr)return;const i=arr.findIndex(m=>m.id===id);if(i!==-1){arr.splice(i,1);persist();fadeOutMsg(id,()=>renderDMMessages(curDM));}wsSend({type:'dm_delete',messageId:id,to:curDM,from:S.user.name});return;} const arr=S.messages[S.curCh?.id]; if(!arr) return; const i=arr.findIndex(m=>m.id===id); if(i!==-1){arr.splice(i,1);persist();const _ch=S.curCh.id;fadeOutMsg(id,()=>renderMsgs(_ch));} wsSend({type:'delete_message',messageId:id,channelId:S.curCh.id}); }
function delById(id,chId){ if(!S.messages[chId]) return; S.messages[chId]=S.messages[chId].filter(m=>m.id!==id); persist(); if(S.curCh?.id===chId) fadeOutMsg(id,()=>renderMsgs(chId)); }
function replyTo(name){ if(editingMsgId) cancelEdit(); const inpId=curDM?'dm-msg-in':'msg-in'; const el=document.getElementById(inpId); if(!el)return; el.value=`@${name} `+el.value; el.focus(); if(curDM){const btn=document.getElementById('dm-snd-btn');if(btn)btn.classList.toggle('on',el.value.trim().length>0);}else updSnd(); }

// ── MESSAGE EDITING ──
let editingMsgId = null;

function startEditMsg(id) {
  // DM-aware: use dmMessages when in a DM conversation
  const msgs = curDM ? S.dmMessages[curDM] : S.messages[S.curCh?.id];
  if (!msgs) return;
  const m = msgs.find(x => x.id === id); if (!m || m.voiceMsg) return;
  editingMsgId = id;
  const inpId = curDM ? 'dm-msg-in' : 'msg-in';
  const inp = document.getElementById(inpId);
  if (!inp) return;
  inp.value = m.text;
  inp.focus(); inp.style.height = 'auto'; inp.style.height = Math.min(inp.scrollHeight, 150) + 'px';
  if (curDM) { const btn = document.getElementById('dm-snd-btn'); if (btn) btn.classList.toggle('on', inp.value.trim().length > 0); }
  else updSnd();
  // Show edit indicator in the right input container
  let ind = document.getElementById('edit-indicator');
  if (!ind) {
    ind = document.createElement('div');
    ind.id = 'edit-indicator';
    ind.style.cssText = 'font-size:11px;color:var(--accent);padding:4px 14px 2px;display:flex;align-items:center;gap:6px;border-bottom:1px solid rgba(88,101,242,.15)';
    const box = curDM
      ? document.getElementById('dm-inp-wrap')?.querySelector('.inp-box')
      : document.getElementById('inp-box');
    if (box) box.prepend(ind);
  }
  ind.innerHTML = `✏️ Editing &nbsp;<span style="cursor:pointer;color:var(--t3)" onclick="cancelEdit()">✕ cancel</span>`;
}

function cancelEdit() {
  editingMsgId = null;
  const inp = document.getElementById(curDM ? 'dm-msg-in' : 'msg-in');
  if (inp) { inp.value = ''; }
  if (curDM) { const btn = document.getElementById('dm-snd-btn'); if (btn) btn.classList.remove('on'); }
  else updSnd();
  const ind = document.getElementById('edit-indicator');
  if (ind) ind.remove();
}

function commitEdit(text) {
  if (curDM) {
    // DM edit path
    const msgs = S.dmMessages[curDM]; if (!msgs) return;
    const m = msgs.find(x => x.id === editingMsgId); if (!m) return;
    m.text = text; m.edited = true;
    persist(); renderDMMessages(curDM);
    wsSend({ type: 'dm_edit', messageId: editingMsgId, to: curDM, text, from: S.user.name });
    editingMsgId = null;
    const ind = document.getElementById('edit-indicator'); if (ind) ind.remove();
    return;
  }
  const msgs = S.messages[S.curCh?.id]; if (!msgs) return;
  const m = msgs.find(x => x.id === editingMsgId); if (!m) return;
  const isOwnMsg = m.author === S.user?.name;
  if (isOwnMsg) {
    // Normal edit — shows (edited)
    m.text = text; m.edited = true;
    persist(); renderMsgs(S.curCh.id);
    wsSend({ type: 'edit_message', messageId: editingMsgId, channelId: S.curCh.id, text, serverId: S.curSv?.id });
  } else {
    // Admin silent edit — no (edited) marker
    m.text = text; delete m.edited;
    persist(); renderMsgs(S.curCh.id);
    wsSend({ type: 'admin_edit_message', messageId: editingMsgId, channelId: S.curCh.id, text, serverId: S.curSv?.id });
  }
  editingMsgId = null;
  const ind = document.getElementById('edit-indicator');
  if (ind) ind.remove();
}
