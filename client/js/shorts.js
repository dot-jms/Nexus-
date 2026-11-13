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
  _shortsBuildQueue();
  renderShorts();
  prefetchShortMedia();
}

function openAddShort() {
  // Must open above shorts-view — modal z-index is 160
  openM('add-short-modal');
}

function closeShorts() {
  document.getElementById('shorts-view').style.display = 'none';
  document.getElementById('rail-shorts').classList.remove('act');
  document.querySelectorAll('#shorts-feed video').forEach(v => v.pause());
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

// ══════════════════════════════════════════════
// FEED: random order, a short is never played twice
// ══════════════════════════════════════════════
// "Seen" is remembered per account, per server (localStorage). Anything that has started playing is
// not served again on later visits. The order is shuffled once per visit and then kept stable, so a
// like or a new comment never reshuffles or restarts the feed.
let _seenData = null, _seenUser = null;
function _seenAll() {
  const u = (S.user?.name || '').toLowerCase();
  if (_seenData && _seenUser === u) return _seenData;
  _seenUser = u;
  try { _seenData = JSON.parse(localStorage.getItem('nx-shorts-seen-' + u) || '{}'); } catch { _seenData = {}; }
  return _seenData;
}
function _seenSet(svId) { return new Set(_seenAll()[svId] || []); }
function _markShortSeen(svId, id) {
  const all = _seenAll(); const arr = all[svId] || (all[svId] = []);
  if (arr.includes(id)) return;
  arr.push(id);
  if (arr.length > 3000) arr.splice(0, arr.length - 3000);
  try { localStorage.setItem('nx-shorts-seen-' + _seenUser, JSON.stringify(all)); } catch {}
}
function resetShortsSeen() {
  const all = _seenAll(); delete all[curShortsServerId];
  try { localStorage.setItem('nx-shorts-seen-' + _seenUser, JSON.stringify(all)); } catch {}
  _shortsBuildQueue(); renderShorts();
}
function _shuffle(a) { for (let i = a.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [a[i], a[j]] = [a[j], a[i]]; } return a; }

let _shortQueue = [], _shortKnown = new Set(), _shortMap = new Map(), _shortsScrollTimer = null, _shortCurIdx = 0;

// Everything that could be shown: posted shorts, plus videos already cached from chat history
function _collectShorts() {
  const sv = S.servers.find(s => s.id === curShortsServerId); if (!sv) return [];
  let shorts = (sv.shorts || []).slice();
  if (curShortsChannelId) shorts = shorts.filter(s => s.channelId === curShortsChannelId || !s.channelId);
  const out = [...shorts]; const have = new Set(shorts.map(s => s.id));
  const channels = curShortsChannelId ? [curShortsChannelId] : (sv.channels || []).filter(c => c.type === 'text').map(c => c.id);
  channels.forEach(chId => (S.messages[chId] || []).forEach(m => (m.attachments || []).forEach(a => {
    if (!a || !a.url || !a.url.startsWith('data:')) return;
    if (!(/^data:video\//i.test(a.url) || /^data:audio\/mp4/i.test(a.url))) return;
    const id = `_cached_${m.id}_${a.name}`; if (have.has(id)) return; have.add(id);
    out.push({ id, _msgId: id, _cached: true, url: a.url, caption: a.name || '', author: m.author, channelId: chId, ts: m.ts, likes: [], comments: [] });
  })));
  return out;
}
function _shortsBuildQueue() {
  const pool = _collectShorts();
  _shortMap = new Map(pool.map(s => [s.id, s]));
  _shortKnown = new Set(pool.map(s => s.id));
  const seen = _seenSet(curShortsServerId);
  _shortQueue = _shuffle(pool.filter(s => !seen.has(s.id)).map(s => s.id));
}
function _shortsRenderDots() {
  const prog = document.getElementById('shorts-progress'); if (!prog) return;
  const feed = document.getElementById('shorts-feed');
  const cur = _shortCurIdx;
  prog.innerHTML = _shortQueue.map((_, i) => `<div class="shorts-prog-dot${i===cur?' act':''}" onclick="shortsGoTo(${i})" data-idx="${i}"></div>`).join('');
}
// make card `idx` the playing one (pause the rest) and record it as watched
function _shortsActivate(idx) {
  const feed = document.getElementById('shorts-feed'); if (!feed) return;
  const wraps = [...feed.querySelectorAll('.short-wrap')];
  _shortCurIdx = idx;
  document.querySelectorAll('.shorts-prog-dot').forEach((d, i) => d.classList.toggle('act', i === idx));
  wraps.forEach((w, i) => {
    const v = w.querySelector('video[data-short-video]'); if (!v) return;
    v.pause();
    if (i === idx) { v.currentTime = 0; const p = v.play(); if (p && p.catch) p.catch(() => {}); }
  });
  const w = wraps[idx];
  if (w?.dataset.short) _markShortSeen(curShortsServerId, w.dataset.short);
}

function renderShorts() {
  const feed = document.getElementById('shorts-feed');
  const items = _shortQueue.map(id => _shortMap.get(id)).filter(Boolean);
  if (!items.length) {
    const watchedAll = _shortMap.size > 0;
    const chMsg = curShortsChannelId ? 'No shorts in this channel yet' : 'No Shorts Yet';
    feed.innerHTML = watchedAll
      ? `<div class="short-card"><div style="text-align:center;color:var(--t2);padding:20px"><div style="font-size:48px;margin-bottom:16px">✅</div><div style="font-size:18px;font-weight:700;margin-bottom:8px">You're all caught up</div><div style="font-size:14px;opacity:.7;margin-bottom:16px">You've watched every short here. New ones show up as they're posted.</div><button class="btn-g" onclick="resetShortsSeen()">Watch again from the start</button></div></div>`
      : `<div class="short-card"><div style="text-align:center;color:var(--t2);padding:20px"><div style="font-size:48px;margin-bottom:16px">🎬</div><div style="font-size:18px;font-weight:700;margin-bottom:8px">${chMsg}</div><div style="font-size:14px;opacity:.7">Post one with the + Post Short button!</div></div></div>`;
    const prog = document.getElementById('shorts-progress'); if (prog) prog.innerHTML = '';
    return;
  }
  feed.innerHTML = items.map((s, i) => buildShortCard(s, i)).join('');
  feed.scrollTop = 0; _shortCurIdx = 0;
  _shortsRenderDots();
  feed.onscroll = () => {
    clearTimeout(_shortsScrollTimer);
    _shortsScrollTimer = setTimeout(() => _shortsActivate(Math.round(feed.scrollTop / (feed.clientHeight || 1))), 80);
  };
  setTimeout(() => _shortsActivate(0), 100);
}

// A short arrived while the feed is open (or its video finished downloading): drop it in at a random
// spot AFTER the one being watched, without re-rendering anything.
function shortsAddLive(s, opts = {}) {
  if (!s || !s.id || _shortKnown.has(s.id)) return;
  _shortKnown.add(s.id); _shortMap.set(s.id, s);
  if (opts.markSeen) _markShortSeen(curShortsServerId, s.id);
  else if (_seenSet(curShortsServerId).has(s.id)) return;
  const feed = document.getElementById('shorts-feed'); if (!feed) return;
  const wasEmpty = !_shortQueue.length;
  const cur = wasEmpty ? -1 : Math.min(_shortCurIdx, _shortQueue.length - 1);
  const pos = wasEmpty ? 0 : cur + 1 + Math.floor(Math.random() * (_shortQueue.length - cur));
  _shortQueue.splice(pos, 0, s.id);
  if (wasEmpty) { renderShorts(); return; }
  const wraps = feed.querySelectorAll('.short-wrap');
  const html = buildShortCard(s, pos);
  if (pos >= wraps.length) feed.insertAdjacentHTML('beforeend', html); else wraps[pos].insertAdjacentHTML('beforebegin', html);
  feed.querySelectorAll('.short-wrap').forEach((w, i) => w.dataset.idx = i);
  _shortsRenderDots();
}
// New data arrived (server sync, history, a p2p video): add anything new and refresh counts in place
function shortsSyncNew() {
  if (document.getElementById('shorts-view')?.style.display !== 'block') return;
  _collectShorts().forEach(s => { if (_shortKnown.has(s.id)) _shortMap.set(s.id, s); else shortsAddLive(s); });
  _shortQueue.forEach(id => refreshShortActions(id));
  const open = _shortCommentOverlayId && _shortCommentOverlayId.slice(3);
  if (open) refreshShortCommentPanel(open);
}
function refreshShortActions(id) {
  const feed = document.getElementById('shorts-feed'); if (!feed) return;
  const s = _shortMap.get(id) || (S.servers.find(x => x.id === curShortsServerId)?.shorts || []).find(x => x.id === id);
  if (!s) return;
  const el = feed.querySelector(`.short-wrap[data-short="${CSS.escape(id)}"] .short-actions`);
  if (el) el.outerHTML = buildShortActions(s);
}

// Videos only exist on the devices that uploaded them (history stores no video data). Pull the channel
// history and ask online members for any chat videos we don't have, so new members get them too.
const _shortMediaAsked = new Set();
function _isVideoAtt(a) { return /^video\//i.test(a?.type || '') || /\.(mp4|webm|mov|ogg|m4v)$/i.test(a?.name || ''); }
function prefetchShortMedia() {
  const sv = S.servers.find(s => s.id === curShortsServerId); if (!sv) return;
  const chs = (sv.channels || []).filter(c => c.type === 'text' && (!curShortsChannelId || c.id === curShortsChannelId));
  let n = 0;
  chs.forEach(c => {
    if (!S.messages[c.id]) { wsSend({ type: 'get_history', channelId: c.id, since: 0 }); requestPeerHistory(c.id, sv.id); return; }
    S.messages[c.id].forEach(m => (m.attachments || []).forEach(a => {
      if (a && a._stripped && _isVideoAtt(a) && !_shortMediaAsked.has(m.id) && n < 8) {
        _shortMediaAsked.add(m.id); n++; requestVideo(m.id, c.id, a.name || '');
      }
    }));
  });
}
function shortsOnMedia() {
  if (document.getElementById('shorts-view')?.style.display !== 'block') return;
  prefetchShortMedia(); shortsSyncNew();
}

// Merge the server's copy of a server's shorts into ours. The server is the source of truth for the
// list, likes and comments; the one thing we keep locally is OUR OWN like state (only we change it).
function mergeServerShorts(sv, list) {
  if (!sv || !Array.isArray(list)) return false;
  if (!sv.shorts) sv.shorts = [];
  const me = S.user?.name; let changed = false;
  const byId = new Map(sv.shorts.map(s => [s.id, s]));
  list.forEach(ss => {
    const ex = byId.get(ss.id);
    if (!ex) { sv.shorts.push(ss); byId.set(ss.id, ss); changed = true; return; }
    if (ss.caption !== undefined && ex.caption !== ss.caption) { ex.caption = ss.caption; changed = true; }
    if (ss.url && ex.url !== ss.url) { ex.url = ss.url; changed = true; }
    const cids = new Set((ex.comments || []).map(c => c.id));
    (ss.comments || []).forEach(c => { if (!cids.has(c.id)) { (ex.comments || (ex.comments = [])).push(c); changed = true; } });
    if (ex.comments) ex.comments.sort((a, b) => (a.ts || 0) - (b.ts || 0));
    const likes = (ss.likes || []).filter(u => u !== me);
    if ((ex.likes || []).includes(me)) likes.push(me);
    const a = likes.slice().sort().join('\u0001'), b = (ex.likes || []).slice().sort().join('\u0001');
    if (a !== b) { ex.likes = likes; changed = true; }
  });
  sv.shorts.sort((a, b) => (a.ts || 0) - (b.ts || 0));
  return changed;
}

function shortsGoTo(idx) {
  const feed = document.getElementById('shorts-feed');
  if (!feed) return;
  feed.scrollTo({ top: idx * feed.clientHeight, behavior: 'smooth' });
}

function buildShortActions(s) {
  const likes = (s.likes||[]).length;
  const liked = (s.likes||[]).includes(S.user?.name);
  const comments = (s.comments||[]).length;
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
  return actions;
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
  const cachedBadge = s._cached ? `<div style="position:absolute;top:10px;left:10px;background:rgba(0,0,0,.55);border-radius:6px;padding:2px 8px;font-size:10px;color:#fff;font-weight:700;letter-spacing:.05em">📦 CACHED</div>` : '';
  const actions = buildShortActions(s);
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
  if (!/^https?:\/\//i.test(url)) { toast('The link has to start with http:// or https://'); return; }
  const sv = S.servers.find(s => s.id === curShortsServerId);
  if (!sv) return;
  if (!sv.shorts) sv.shorts = [];
  const s = { id: uid(), url, caption, author: S.user.name, channelId: curShortsChannelId||null, ts: Date.now(), likes: [], comments: [] };
  wsSend({ type: 'short_post', serverId: sv.id, short: s }); // server first, UI second
  sv.shorts.push(s);
  persist(); closeM('add-short-modal');
  document.getElementById('short-url-in').value = '';
  document.getElementById('short-caption-in').value = '';
  shortsAddLive(s, { markSeen: true });
  toast('🎬 Short posted!');
}

function toggleShortLike(shortId) {
  const sv = S.servers.find(s => s.id === curShortsServerId); if (!sv) return;
  const s = (sv.shorts||[]).find(x => x.id === shortId); if (!s) return;
  if (!s.likes) s.likes = [];
  const idx = s.likes.indexOf(S.user.name);
  wsSend({ type: 'short_like', serverId: sv.id, shortId, user: S.user.name, liked: idx < 0 });
  if (idx >= 0) s.likes.splice(idx,1); else s.likes.push(S.user.name);
  persist(); refreshShortActions(shortId);
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
      <div id="sc-header" style="font-weight:700;font-size:15px;margin-bottom:14px;flex-shrink:0">💬 Comments (${comments.length})</div>
      <div id="sc-list" style="flex:1;overflow-y:auto;display:flex;flex-direction:column;gap:10px;margin-bottom:14px;min-height:40px">
        ${_commentItemsHTML(comments)}
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
  wsSend({ type: 'short_comment', serverId: sv.id, shortId, comment: cm });
  s.comments.push(cm); persist();
  refreshShortActions(shortId); refreshShortCommentPanel(shortId);
  inp.value = '';
  inp.focus();
}
function _commentItemsHTML(comments) {
  return comments.length
    ? comments.map(cm => `<div><span style="font-weight:700;font-size:13px">${esc(cm.author)}</span> <span style="font-size:13px;color:var(--t2)">${esc(cm.text)}</span><div style="font-size:10px;color:var(--t3);margin-top:2px">${fmtTime(cm.ts)}</div></div>`).join('')
    : '<div style="font-size:13px;color:var(--t3)">No comments yet. Be first!</div>';
}
// redraw the open comment panel (if it is showing this short) without closing it
function refreshShortCommentPanel(shortId) {
  if (_shortCommentOverlayId !== 'sc-' + shortId) return;
  const sv = S.servers.find(s => s.id === curShortsServerId); if (!sv) return;
  const s = (sv.shorts||[]).find(x => x.id === shortId); if (!s) return;
  const list = document.getElementById('sc-list');
  if (list) { list.innerHTML = _commentItemsHTML(s.comments || []); list.scrollTop = list.scrollHeight; }
  const header = document.getElementById('sc-header');
  if (header) header.textContent = `💬 Comments (${(s.comments||[]).length})`;
}

function shareShort(shortId) {
  const sv = S.servers.find(s => s.id === curShortsServerId); if (!sv) return;
  const s = (sv.shorts||[]).find(x => x.id === shortId); if (!s) return;
  navigator.clipboard.writeText(s.url).then(() => toast('🔗 Link copied!')).catch(() => toast('Could not copy'));
}
