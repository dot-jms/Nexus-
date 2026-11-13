// ══════════════════════════════════════════════
// SHORTS FEED
// ══════════════════════════════════════════════
let curShortsServerId = null;

let curShortsChannelId = null;

function openShortsRail() {
  const sv = S.curSv || S.servers[0];
  if (!sv) { toast('Join a server to see Shorts'); return; }
  const chId = S.curCh?.type === 'text' ? S.curCh.id : (sv.channels||[]).find(c=>c.type==='text')?.id || null;
  const chName = S.curCh?.name || '';
  openShorts(sv.id, chId, chName);
}

function openShorts(serverId, channelId=null, channelName='') {
  curShortsServerId = serverId;
  curShortsChannelId = channelId;
  const sv = S.servers.find(s => s.id === serverId);
  const label = channelId && channelName ? `#${channelName} · Shorts` : (sv?.name || 'Server') + ' · Shorts';
  document.getElementById('shorts-sv-name').textContent = label;
  document.getElementById('shorts-view').style.display = 'block';
  document.getElementById('rail-shorts').classList.add('act');
  renderShorts();
}

function openAddShort() {
  // Must open above shorts-view — modal z-index is 160
  openM('add-short-modal');
}

function closeShorts() {
  document.getElementById('shorts-view').style.display = 'none';
  document.getElementById('rail-shorts').classList.remove('act');
  document.querySelectorAll('.short-card iframe').forEach(f => { const s = f.src; f.src = ''; setTimeout(()=> f.src = s, 10); });
  document.getElementById('short-comment-panel')?.remove();
}

// Arrow key navigation for shorts
document.addEventListener('keydown', e => {
  if (document.getElementById('shorts-view')?.style.display === 'none') return;
  if (document.getElementById('short-comment-panel')) return; // comment box open
  const feed = document.getElementById('shorts-feed');
  if (!feed) return;
  const h = feed.clientHeight;
  const cur = Math.round(feed.scrollTop / h);
  const total = feed.querySelectorAll('.short-card').length;
  if (e.key === 'ArrowDown' && cur < total - 1) {
    e.preventDefault();
    feed.scrollTo({ top: (cur+1)*h, behavior:'smooth' });
  } else if (e.key === 'ArrowUp' && cur > 0) {
    e.preventDefault();
    feed.scrollTo({ top: (cur-1)*h, behavior:'smooth' });
  } else if (e.key === 'Escape') {
    closeShorts();
  }
});

function renderShorts() {
  const sv = S.servers.find(s => s.id === curShortsServerId);
  let shorts = (sv?.shorts || []).slice().reverse();
  // Filter by channel if set
  if (curShortsChannelId) shorts = shorts.filter(s => s.channelId === curShortsChannelId || !s.channelId);

  // Inject cached P2P videos from message history as ephemeral shorts
  // Only include videos we actually have the data URL for (data:video/*)
  const cachedShorts = [];
  const channels = curShortsChannelId
    ? [curShortsChannelId]
    : (sv?.channels || []).filter(c => c.type === 'text').map(c => c.id);
  const existingIds = new Set(shorts.map(s => s._msgId).filter(Boolean));
  channels.forEach(chId => {
    (S.messages[chId] || []).forEach(m => {
      (m.attachments || []).forEach(a => {
        if (!a.url || !a.url.startsWith('data:')) return;
        // Accept any video-ish MIME type
        const isVideo = /^data:video\//i.test(a.url) || /^data:audio\/mp4/i.test(a.url);
        if (!isVideo) return;
        const syntheticId = `_cached_${m.id}_${a.name}`;
        if (existingIds.has(syntheticId)) return; // already in shorts list
        cachedShorts.push({
          id: syntheticId,
          _msgId: syntheticId,
          _cached: true,
          url: a.url,
          caption: a.name || '',
          author: m.author,
          channelId: chId,
          ts: m.ts,
          likes: [],
          comments: [],
        });
      });
    });
  });

  // Merge: posted shorts first (newest first), then cached videos (newest first)
  const allShorts = [...shorts, ...cachedShorts.sort((a,b) => b.ts - a.ts)];

  const feed = document.getElementById('shorts-feed');
  if (!allShorts.length) {
    const chMsg = curShortsChannelId ? 'No shorts in this channel yet' : 'No Shorts Yet';
    feed.innerHTML = `<div class="short-card"><div style="text-align:center;color:var(--t2);padding:20px"><div style="font-size:48px;margin-bottom:16px">🎬</div><div style="font-size:18px;font-weight:700;margin-bottom:8px">${chMsg}</div><div style="font-size:14px;opacity:.7">Post one with the + Post Short button!</div></div></div>`;
    return;
  }
  feed.innerHTML = allShorts.map((s, i) => buildShortCard(s, i)).join('');
  // Progress dots
  const prog = document.getElementById('shorts-progress');
  if (prog) {
    prog.innerHTML = allShorts.map((_, i) => `<div class="shorts-prog-dot${i===0?' act':''}" onclick="shortsGoTo(${i})" data-idx="${i}"></div>`).join('');
  }
  // Scroll handler: pause all videos, play+restart current, sync dots
  let _shortsScrollTimer = null;
  feed.onscroll = () => {
    clearTimeout(_shortsScrollTimer);
    _shortsScrollTimer = setTimeout(() => {
      const h = feed.clientHeight;
      const idx = Math.round(feed.scrollTop / h);
      document.querySelectorAll('.shorts-prog-dot').forEach((d,i) => d.classList.toggle('act', i===idx));
      // Pause + restart all videos, play only the current one
      feed.querySelectorAll('video[data-short-video]').forEach((v, vi) => {
        v.pause();
        if (vi === idx) { v.currentTime = 0; v.play().catch(()=>{}); }
      });
    }, 80);
  };
  // Autoplay first video after render
  setTimeout(() => {
    const firstVid = feed.querySelector('video[data-short-video]');
    if (firstVid) { firstVid.currentTime = 0; firstVid.play().catch(()=>{}); }
  }, 100);
}

function shortsGoTo(idx) {
  const feed = document.getElementById('shorts-feed');
  if (!feed) return;
  feed.scrollTo({ top: idx * feed.clientHeight, behavior: 'smooth' });
}

function buildShortCard(s, i) {
  const embedUrl = s._cached ? null : getEmbedUrl(s.url);
  let mediaHTML;
  if (embedUrl) {
    mediaHTML = `<iframe src="${embedUrl}" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" allowfullscreen loading="lazy"></iframe>`;
  } else if (s._cached || s.url.startsWith('data:') || s.url.match(/\.(mp4|webm|mov|ogg)($|\?)/i)) {
    // NO muted — user wants sound. Loop + autoplay handled by JS scroll manager.
    mediaHTML = `<video src="${esc(s.url)}" loop playsinline controls preload="metadata" style="width:100%;height:100%;object-fit:cover" data-short-video></video>`;
  } else {
    mediaHTML = `<div style="color:var(--t2);text-align:center;padding:20px"><div style="font-size:40px">🔗</div><div style="font-size:13px;margin-top:8px;margin-bottom:12px">Unsupported URL</div><a href="${esc(s.url)}" target="_blank" style="color:var(--accent-h);font-size:13px;font-weight:600">Open Link ↗</a></div>`;
  }
  const likes = (s.likes||[]).length;
  const liked = (s.likes||[]).includes(S.user?.name);
  const comments = (s.comments||[]).length;
  const cachedBadge = s._cached ? `<div style="position:absolute;top:10px;left:10px;background:rgba(0,0,0,.55);border-radius:6px;padding:2px 8px;font-size:10px;color:#fff;font-weight:700;letter-spacing:.05em">📦 CACHED</div>` : '';
  const likeColor = liked ? '#ef4444' : 'currentColor';
  const actions = `<div class="short-actions">
        <div class="short-action-btn" onclick="event.stopPropagation();toggleShortLike('${s.id}')">
          <svg width="22" height="22" fill="${liked?'#ef4444':'none'}" stroke="${likeColor}" stroke-width="2" viewBox="0 0 24 24"><path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"/></svg>
        </div><div class="short-action-count" style="margin-top:-14px;margin-bottom:4px">${likes||''}</div>
        <div class="short-action-btn" onclick="event.stopPropagation();openShortComments('${s.id}')">
          <svg width="22" height="22" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
        </div><div class="short-action-count" style="margin-top:-14px;margin-bottom:4px">${comments||''}</div>
        <div class="short-action-btn" onclick="event.stopPropagation();shareShort('${s.id}')">
          <svg width="22" height="22" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>
        </div>
      </div>`;
  return `<div class="short-wrap" data-short="${s.id}" data-idx="${i}"><div class="short-card">
    <div class="short-card-media">${mediaHTML}${cachedBadge}</div>
    <div class="short-overlay">
      <div class="short-caption">${esc(s.caption||'')}</div>
      <div class="short-author">@${esc(s.author)}</div>
    </div>
    ${actions}
  </div></div>`;
}

function getEmbedUrl(url) {
  try {
    const ytMatch = url.match(/(?:youtube\.com\/watch\?v=|youtu\.be\/)([a-zA-Z0-9_-]{11})/);
    if (ytMatch) return `https://www.youtube.com/embed/${ytMatch[1]}?autoplay=1&mute=1&loop=1&playlist=${ytMatch[1]}&rel=0&modestbranding=1`;
    const ytShort = url.match(/youtube\.com\/shorts\/([a-zA-Z0-9_-]{11})/);
    if (ytShort) return `https://www.youtube.com/embed/${ytShort[1]}?autoplay=1&mute=1&loop=1&playlist=${ytShort[1]}&rel=0`;
    return null;
  } catch { return null; }
}

function postShort() {
  const url = document.getElementById('short-url-in').value.trim();
  const caption = document.getElementById('short-caption-in').value.trim();
  if (!url) { toast('Enter a video URL'); return; }
  const sv = S.servers.find(s => s.id === curShortsServerId);
  if (!sv) return;
  if (!sv.shorts) sv.shorts = [];
  const s = { id: uid(), url, caption, author: S.user.name, channelId: curShortsChannelId||null, ts: Date.now(), likes: [], comments: [] };
  sv.shorts.push(s);
  persist(); closeM('add-short-modal'); renderShorts();
  document.getElementById('short-url-in').value = '';
  document.getElementById('short-caption-in').value = '';
  wsSend({ type: 'short_post', serverId: sv.id, short: s });
  toast('🎬 Short posted!');
}

function toggleShortLike(shortId) {
  const sv = S.servers.find(s => s.id === curShortsServerId); if (!sv) return;
  const s = (sv.shorts||[]).find(x => x.id === shortId); if (!s) return;
  if (!s.likes) s.likes = [];
  const idx = s.likes.indexOf(S.user.name);
  if (idx >= 0) s.likes.splice(idx,1); else s.likes.push(S.user.name);
  persist(); renderShorts();
  wsSend({ type: 'short_like', serverId: sv.id, shortId, user: S.user.name, liked: idx < 0 });
}

let _shortCommentOverlayId = null;

function openShortComments(shortId) {
  const sv = S.servers.find(s => s.id === curShortsServerId); if (!sv) return;
  const s = (sv.shorts||[]).find(x => x.id === shortId); if (!s) return;
  // Remove any existing comment panel
  const existing = document.getElementById('short-comment-panel');
  if (existing) existing.remove();
  _shortCommentOverlayId = 'sc-' + shortId;
  const comments = s.comments || [];
  const overlay = document.createElement('div');
  overlay.id = 'short-comment-panel';
  overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:200;display:flex;align-items:flex-end';
  overlay.addEventListener('click', e => { if (e.target === overlay) overlay.remove(); });
  overlay.innerHTML = `
    <div style="width:100%;background:var(--s2);border-radius:20px 20px 0 0;padding:20px;max-height:65vh;display:flex;flex-direction:column">
      <div style="font-weight:700;font-size:15px;margin-bottom:14px;flex-shrink:0">💬 Comments (${comments.length})</div>
      <div id="sc-list" style="flex:1;overflow-y:auto;display:flex;flex-direction:column;gap:10px;margin-bottom:14px;min-height:40px">
        ${comments.length ? comments.map(cm => `<div><span style="font-weight:700;font-size:13px">${esc(cm.author)}</span> <span style="font-size:13px;color:var(--t2)">${esc(cm.text)}</span><div style="font-size:10px;color:var(--t3);margin-top:2px">${fmtTime(cm.ts)}</div></div>`).join('') : '<div style="font-size:13px;color:var(--t3)">No comments yet. Be first!</div>'}
      </div>
      <div style="display:flex;gap:8px;flex-shrink:0">
        <input class="m-inp" id="sc-inp" placeholder="Add a comment..." style="flex:1;margin-bottom:0" onkeydown="if(event.key==='Enter'){event.preventDefault();submitShortComment('${shortId}');}">
        <button class="btn-p" style="white-space:nowrap" id="sc-post-btn">Post</button>
      </div>
    </div>`;
  document.body.appendChild(overlay);
  document.getElementById('sc-post-btn').addEventListener('click', () => submitShortComment(shortId));
  setTimeout(() => document.getElementById('sc-inp')?.focus(), 80);
}

function submitShortComment(shortId) {
  const inp = document.getElementById('sc-inp');
  if (!inp) return;
  const text = inp.value.trim();
  if (!text) return;
  const sv = S.servers.find(s => s.id === curShortsServerId); if (!sv) return;
  const s = (sv.shorts||[]).find(x => x.id === shortId); if (!s) return;
  if (!s.comments) s.comments = [];
  const cm = { id: uid(), author: S.user.name, text, ts: Date.now() };
  s.comments.push(cm); persist(); renderShorts();
  wsSend({ type: 'short_comment', serverId: sv.id, shortId, comment: cm });
  // Refresh the comment list in panel instead of closing
  const list = document.getElementById('sc-list');
  if (list) {
    list.innerHTML = (s.comments||[]).map(c => `<div><span style="font-weight:700;font-size:13px">${esc(c.author)}</span> <span style="font-size:13px;color:var(--t2)">${esc(c.text)}</span><div style="font-size:10px;color:var(--t3);margin-top:2px">${fmtTime(c.ts)}</div></div>`).join('');
    list.scrollTop = list.scrollHeight;
  }
  const header = document.querySelector('#short-comment-panel [style*="font-weight:700"]');
  if (header) header.textContent = `💬 Comments (${s.comments.length})`;
  inp.value = '';
  inp.focus();
}

function shareShort(shortId) {
  const sv = S.servers.find(s => s.id === curShortsServerId); if (!sv) return;
  const s = (sv.shorts||[]).find(x => x.id === shortId); if (!s) return;
  navigator.clipboard.writeText(s.url).then(() => toast('🔗 Link copied!')).catch(() => toast('Could not copy'));
}
