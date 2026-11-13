// ══════════════════════════════════
// EMOJI PICKER (full)
// ══════════════════════════════════
function buildFullEmoji() {
  const catsEl=document.getElementById('ep-cats');
  const gridEl=document.getElementById('ep-grid-wrap');
  const catIcons={'Smileys':'😀','People':'👋','Animals':'🐶','Food':'🍎','Travel':'🚗','Activities':'⚽','Objects':'📱','Symbols':'❤'};
  catsEl.innerHTML='';
  Object.keys(EMOJI_DATA).forEach((cat,i)=>{
    const btn=document.createElement('div');
    btn.className='ep-cat-btn'+(i===0?' active':'');
    btn.textContent=catIcons[cat]||cat[0];
    btn.title=cat;
    btn.onclick=()=>{
      document.querySelectorAll('.ep-cat-btn').forEach(x=>x.classList.remove('active'));
      btn.classList.add('active');
      renderEmojiGrid(cat);
      document.getElementById('ep-search').value='';
    };
    catsEl.appendChild(btn);
  });
  renderEmojiGrid(Object.keys(EMOJI_DATA)[0]);
}

function renderEmojiGrid(cat) {
  const el=document.getElementById('ep-grid-wrap'); el.innerHTML='';
  const title=document.createElement('div'); title.className='ep-section-title'; title.textContent=cat; el.appendChild(title);
  const grid=document.createElement('div'); grid.className='ep-grid';
  (EMOJI_DATA[cat]||[]).forEach(em=>{ const d=document.createElement('div'); d.className='ep-em'; d.textContent=em; d.title=em; d.onclick=()=>insertEmoji(em); grid.appendChild(d); });
  el.appendChild(grid);
}

function filterEmoji() {
  const q=document.getElementById('ep-search').value.trim().toLowerCase();
  const el=document.getElementById('ep-grid-wrap'); el.innerHTML='';
  if(!q){ renderEmojiGrid(document.querySelector('.ep-cat-btn.active')?.title||Object.keys(EMOJI_DATA)[0]); return; }
  const all=Object.values(EMOJI_DATA).flat();
  const results=all.filter(em=>em.includes(q)||q.split('').every(c=>em.includes(c)));
  const title=document.createElement('div'); title.className='ep-section-title'; title.textContent=`Search results (${results.length})`; el.appendChild(title);
  const grid=document.createElement('div'); grid.className='ep-grid';
  results.forEach(em=>{ const d=document.createElement('div'); d.className='ep-em'; d.textContent=em; d.onclick=()=>insertEmoji(em); grid.appendChild(d); });
  el.appendChild(grid);
  if(!results.length){ el.innerHTML=`<div style="padding:20px;text-align:center;color:var(--t3);font-size:12px">No emoji found</div>`; }
}

function insertEmoji(em) {
  const picker=document.getElementById('main-emoji-picker');
  // If the picker was opened for a reaction, route to reaction instead of text input
  if (picker._forReaction) {
    picker._forReaction = false;
    picker.classList.remove('open');
    if (reactPickerMsgId) toggleReact(reactPickerMsgId, em);
    return;
  }
  const inp=document.getElementById('msg-in');
  const start=inp.selectionStart, end=inp.selectionEnd;
  inp.value=inp.value.slice(0,start)+em+inp.value.slice(end);
  inp.selectionStart=inp.selectionEnd=start+em.length;
  inp.focus(); updSnd();
  picker.classList.remove('open');
}

function toggleMainEmoji() { document.getElementById('main-emoji-picker').classList.toggle('open'); }

// ── REACTION PICKER ──
function buildReactPicker() {
  const el=document.getElementById('react-picker');
  // Quick reactions row
  const quick=['👍','❤️','😂','🔥','✨','🚀','😮','😢','🙌','💯','🤔','👀'];
  quick.forEach(em=>{ const d=document.createElement('div'); d.className='rp-em'; d.textContent=em; d.onclick=()=>{ if(reactPickerMsgId) toggleReact(reactPickerMsgId,em); closeReactPicker(); }; el.appendChild(d); });
  // "more" button
  const more=document.createElement('div'); more.className='rp-em'; more.textContent='➕'; more.title='More';
  more.onclick=()=>{ closeReactPicker(); openFullEmojiForReaction(); };
  el.appendChild(more);
}

function openReactPicker(msgId, e) {
  e.stopPropagation();
  reactPickerMsgId=msgId;
  const picker=document.getElementById('react-picker');
  picker.classList.add('open');
  picker.style.position='fixed';
  const rect=e.target.getBoundingClientRect();
  requestAnimationFrame(() => {
    const ph = picker.offsetHeight || 56;
    const pw = picker.offsetWidth || 260;
    // Try above first, fall back to below if not enough room
    let top = rect.top - ph - 8;
    if (top < 8) top = rect.bottom + 8;
    // Clamp horizontal
    let left = rect.left;
    if (left + pw > window.innerWidth - 8) left = window.innerWidth - pw - 8;
    if (left < 8) left = 8;
    picker.style.top = top + 'px';
    picker.style.left = left + 'px';
    picker.style.bottom = 'auto';
    picker.style.transform = 'none';
  });
}

function closeReactPicker(){ document.getElementById('react-picker').classList.remove('open'); reactPickerMsgId=null; }

function openFullEmojiForReaction() {
  const picker = document.getElementById('main-emoji-picker');
  // Position it near the message chat area
  picker.style.position = 'fixed';
  picker.style.bottom = '70px';
  picker.style.left = '50%';
  picker.style.transform = 'translateX(-50%)';
  picker._forReaction = true;
  picker.classList.add('open');
}

function toggleReact(id, emoji) {
  if (curDM) {
    // DM reaction path
    const msgs = S.dmMessages[curDM]; if (!msgs) return;
    const m = msgs.find(x => x.id === id); if (!m) return;
    if (!m.reactions) m.reactions = [];
    let r = m.reactions.find(x => x.emoji === emoji);
    if (r) {
      if (r.users?.includes(S.user.name)) {
        r.count = Math.max(0, r.count - 1);
        r.users = r.users.filter(u => u !== S.user.name);
        if (r.count <= 0) m.reactions = m.reactions.filter(x => x.emoji !== emoji);
      } else { r.count++; r.users = [...(r.users || []), S.user.name]; }
    } else {
      m.reactions.push({ emoji, count: 1, users: [S.user.name] });
    }
    persist(); renderDMMessages(curDM);
    wsSend({ type: 'dm_reaction', to: curDM, messageId: id, emoji, user: S.user.name });
    return;
  }
  if (!S.curCh) return;
  const msgs = S.messages[S.curCh.id]; if (!msgs) return;
  const m = msgs.find(x => x.id === id); if (!m) return;
  if (!m.reactions) m.reactions = [];
  let r = m.reactions.find(x => x.emoji === emoji);
  if (r) {
    if (r.users?.includes(S.user.name)) {
      r.count = Math.max(0, r.count - 1);
      r.users = r.users.filter(u => u !== S.user.name);
      if (r.count <= 0) m.reactions = m.reactions.filter(x => x.emoji !== emoji);
    } else {
      r.count++; r.users = [...(r.users || []), S.user.name];
    }
  } else {
    m.reactions.push({ emoji, count: 1, users: [S.user.name] });
  }
  persist(); renderMsgs(S.curCh.id);
  wsSend({ type: 'reaction', channelId: S.curCh.id, messageId: id, emoji, user: S.user.name });
}
