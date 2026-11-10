// ══════════════════════════════════════════════
// MESSAGE SEARCH
// ══════════════════════════════════════════════
function openSearch() {
  if (!S.curCh) { toast('Select a channel first'); return; }
  document.getElementById('search-in').value = '';
  document.getElementById('search-results').innerHTML = '';
  openM('search-modal');
  setTimeout(() => document.getElementById('search-in').focus(), 100);
}

function runSearch() {
  const q = document.getElementById('search-in').value.trim().toLowerCase();
  const el = document.getElementById('search-results');
  if (!q) { el.innerHTML = ''; return; }
  const msgs = S.messages[S.curCh?.id] || [];
  const results = msgs.filter(m => m.text?.toLowerCase().includes(q)).slice(-30).reverse();
  if (!results.length) { el.innerHTML = '<div style="text-align:center;padding:20px;font-size:12px;color:var(--t3)">No messages found</div>'; return; }
  el.innerHTML = results.map(m => {
    const hi = esc(m.text).replace(new RegExp(esc(q),'gi'), s => `<span class="search-highlight">${s}</span>`);
    return `<div class="search-result" onclick="jumpToMsg('${m.id}')">
      <div class="search-result-meta">${esc(m.author)} · ${fmtTime(m.ts)}</div>
      <div class="search-result-text">${hi}</div>
    </div>`;
  }).join('');
}

function jumpToMsg(id) {
  closeM('search-modal');
  const el = document.querySelector(`.msg[data-id="${id}"]`);
  if (el) { el.scrollIntoView({ behavior: 'smooth', block: 'center' }); el.style.background='rgba(108,99,255,.15)'; setTimeout(()=>el.style.background='',1500); }
}
