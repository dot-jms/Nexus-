// ══════════════════════════════════
// STATUS
// ══════════════════════════════════
function toggleStatusMenu(e) {
  e.stopPropagation();
  document.getElementById('status-menu').classList.toggle('open');
}
function setStatus(s) {
  S.user.status = s;
  const dot = document.getElementById('u-dot');
  dot.className = 'u-dot' + (s === 'online' ? '' : ' ' + s);
  document.getElementById('status-menu').classList.remove('open');
  wsSend({ type: 'status_update', user: S.user.name, status: s });
  toast('Status set to ' + s);
  // Update status dots in member lists
  if (S.curSv) renderMbs();
}
document.addEventListener('click', e => {
  if (!e.target.closest('#status-menu') && !e.target.closest('[title="Set Status"]'))
    document.getElementById('status-menu')?.classList.remove('open');
});

// ══════════════════════════════════
// PINNED MESSAGES
// ══════════════════════════════════
function pinMsg(msgId) {
  if (!S.curCh || !S.curSv) return;
  if (!S.curSv.pins) S.curSv.pins = {};
  if (!S.curSv.pins[S.curCh.id]) S.curSv.pins[S.curCh.id] = [];
  const msgs = S.messages[S.curCh.id] || [];
  const m = msgs.find(x => x.id === msgId);
  if (!m) return;
  const already = S.curSv.pins[S.curCh.id].find(p => p.id === msgId);
  if (already) { toast('Already pinned'); return; }
  S.curSv.pins[S.curCh.id].push({ id: m.id, text: m.text, author: m.author, ts: m.ts });
  persist(); updatePinnedBar(); toast('📌 Message pinned');
  wsSend({ type: 'pin_message', serverId: S.curSv.id, channelId: S.curCh.id, msgId, author: m.author, text: m.text, ts: m.ts });
}

function updatePinnedBar() {
  if (!S.curSv || !S.curCh) { document.getElementById('pinned-bar').classList.remove('show'); return; }
  const pins = (S.curSv.pins || {})[S.curCh.id] || [];
  const bar = document.getElementById('pinned-bar');
  if (pins.length) {
    bar.classList.add('show');
    document.getElementById('pinned-bar-text').textContent = `${pins.length} pinned message${pins.length > 1 ? 's' : ''}`;
  } else {
    bar.classList.remove('show');
  }
}

function showPinnedMessages() {
  if (!S.curSv || !S.curCh) return;
  const pins = (S.curSv.pins || {})[S.curCh.id] || [];
  const el = document.getElementById('pins-list');
  if (!pins.length) { el.innerHTML = '<div style="color:var(--t3);font-size:13px;text-align:center;padding:20px">No pinned messages</div>'; }
  else {
    el.innerHTML = pins.map(p => `
      <div style="background:var(--s3);border:1px solid var(--border);border-radius:8px;padding:10px 12px">
        <div style="font-size:11px;color:var(--t3);margin-bottom:4px">${esc(p.author)} · ${fmtTime(p.ts)}</div>
        <div style="font-size:13px;color:var(--t2)">${fmtTxt(p.text)}</div>
        <div style="margin-top:6px"><button class="btn-g" style="font-size:11px;padding:3px 8px" onclick="unpinMsg('${p.id}')">Unpin</button></div>
      </div>`).join('');
  }
  openM('pins-modal');
}

function unpinMsg(msgId) {
  if (!S.curSv || !S.curCh) return;
  if (!S.curSv.pins) return;
  if (!S.curSv.pins[S.curCh.id]) return;
  S.curSv.pins[S.curCh.id] = S.curSv.pins[S.curCh.id].filter(p => p.id !== msgId);
  persist(); updatePinnedBar(); closeM('pins-modal'); showPinnedMessages(); toast('📌 Unpinned');
  wsSend({ type: 'unpin_message', serverId: S.curSv.id, channelId: S.curCh.id, msgId });
}
