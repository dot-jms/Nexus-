// ── Bedrock announcement (shown once per browser) ──
const BEDROCK_NEWS_KEY = 'nx-news-bedrock-1';
function showBedrockNews(force){
  try { if (!force && localStorage.getItem(BEDROCK_NEWS_KEY)) return; } catch(_) {}
  document.getElementById('bedrock-news').classList.add('open');
}
function closeBedrockNews(){
  document.getElementById('bedrock-news').classList.remove('open');
  try { localStorage.setItem(BEDROCK_NEWS_KEY, '1'); } catch(_) {}
}

function bootApp() {
  document.getElementById('auth-screen').style.display='none';
  document.getElementById('app').classList.add('vis');
  migrateServers();
  updateUser(); renderSvs(); buildFullEmoji(); buildReactPicker(); renderDMs();
  document.getElementById('dbg-overlay').style.display = S.user?.systemRole === 'admin' ? 'flex' : 'none';
  _reconnectDelay = 1000;
  _reconnectAttempts = 0;
  S.wsConnecting = false;
  connectWS();
  // Watchdog: if not connected after 4s (e.g. Ctrl+Shift+R cleared session storage
  // mid-flight or WS handshake stalled), force a clean retry
  setTimeout(() => {
    if (!S.wsOk && S.user) {
      S.wsConnecting = false;
      clearTimeout(_reconnectTimer);
      _reconnectAttempts = 0;
      connectWS();
    }
  }, 4000);
  checkInviteHash();
  reqNotifPermission();
  setTimeout(showBedrockNews, 1500);
  // Global Escape key: close topmost open modal
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') {
      const open = document.querySelector('.overlay.open');
      if (open) { open.classList.remove('open'); return; }
      if (curDM) { closeDMChat(); return; }
    }
    // Ctrl/Cmd+K: jump to DM search
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
      e.preventDefault();
      openM('ndm');
      setTimeout(() => document.getElementById('dm-in')?.focus(), 80);
    }
  });
  // Update friend request badge
  setTimeout(()=>{ const inReqs=S.friendReqs.filter(r=>r.direction==='in'); document.getElementById('fr-badge').style.display=inReqs.length?'':'none'; }, 100);
  if(S.servers.length) selectSv(S.servers[0].id);
}
