// ── TYPING ──
function onType(){ if(!S.tySent&&S.curCh){S.tySent=true;wsSend({type:'typing',channelId:S.curCh.id,author:S.user.name});setTimeout(()=>{S.tySent=false;},3000);} }
// FIX #10: Per-user typing timers. A single shared timer (the old S.tyTimer)
// would reset for ALL users whenever anyone typed, causing stale "is typing" states.
const typers = {};
const _tyTimers = {}; // per-user timer handles
function showTyping(who, channelId) {
  if (S.curCh?.id !== channelId) return;
  typers[who] = Date.now();
  renderTypingBar();
  clearTimeout(_tyTimers[who]);
  _tyTimers[who] = setTimeout(() => { delete typers[who]; delete _tyTimers[who]; renderTypingBar(); }, 3500);
}
function renderTypingBar() {
  const el = document.getElementById('ty-bar');
  const names = Object.keys(typers);
  if (!names.length) { el.innerHTML = ''; return; }
  const txt = names.length === 1 ? `${esc(names[0])} is typing...`
    : names.length === 2 ? `${esc(names[0])} and ${esc(names[1])} are typing...`
    : `${names.length} people are typing...`;
  el.innerHTML = `<div class="ty-dots"><div class="ty-dot"></div><div class="ty-dot"></div><div class="ty-dot"></div></div><span>${txt}</span>`;
}

// ── FILES ──
async function onFiles(e) {
  const files = [...e.target.files];
  e.target.value = '';
  for (const f of files) {
    let mt = 'file';
    if (f.type.startsWith('image/')) { mt = 'image'; }
    else if (f.type.startsWith('video/')) { mt = 'video'; if (f.size > 50*1024*1024) { toast('⚠️ Videos must be under 50 MB.'); continue; } }
    else if (f.type.startsWith('audio/') || /\.(mp3|wav|ogg|m4a|flac|aac)$/i.test(f.name)) { mt = 'audio'; if (f.size > 4*1024*1024) { toast('⚠️ Audio files must be under 4 MB.'); continue; } }
    else { if (f.size > 2*1024*1024) { toast('⚠️ Files must be under 2 MB.'); continue; } }

    // Show a loading placeholder in the attachment preview immediately
    const loadId = 'load-' + Math.random().toString(36).slice(2);
    const loadEl = document.createElement('div');
    loadEl.className = 'att-p att-loading'; loadEl.id = loadId;
    loadEl.innerHTML = `<span>${mt==='video'?'🎬':mt==='audio'?'🎵':'📄'}</span><span style="color:var(--t2)">${esc(f.name)}</span><span style="color:var(--t3);font-size:10px;font-family:'DM Mono',monospace" id="${loadId}-pct">reading…</span>`;
    const prevEl = document.getElementById('att-prev');
    if (prevEl) { prevEl.appendChild(loadEl); prevEl.classList.add('show'); }

    // Read file with progress for large files
    let url;
    try {
      url = await new Promise((res, rej) => {
        const r = new FileReader();
        r.onprogress = ev => { if (ev.lengthComputable) { const pct = Math.round(ev.loaded/ev.total*100); const el = document.getElementById(loadId+'-pct'); if (el) el.textContent = pct+'%'; } };
        r.onload = ev => res(ev.target.result);
        r.onerror = () => rej(new Error('read failed'));
        r.readAsDataURL(f);
      });
    } catch(err) {
      loadEl.remove(); toast('⚠️ Failed to read ' + f.name); continue;
    }

    if (mt === 'image') {
      try {
        const pctEl = document.getElementById(loadId+'-pct'); if (pctEl) pctEl.textContent = 'compressing…';
        url = await compressImage(url, IMG_LIMITS.chat);
      } catch(err) {
        loadEl.remove();
        if (err.message === 'too_large') { toast('⚠️ Image is too large even after compression (max ~700 KB).'); }
        continue;
      }
    }

    loadEl.remove();
    S.files.push({ name: f.name, size: f.size, url, mt });
    renderPrev(); updSnd();
  }
}
function renderPrev() {
  const el = document.getElementById('att-prev'); el.innerHTML = '';
  S.files.forEach((f,i) => {
    const d = document.createElement('div'); d.className = 'att-p';
    const icon = f.mt==='image' ? `<img src="${f.url}">` : f.mt==='audio' ? '🎵' : f.mt==='video' ? '🎬' : '📄';
    d.innerHTML = f.mt==='image'
      ? `<img src="${f.url}"><span>${esc(f.name)}</span><span class="att-rm" onclick="rmF(${i})">×</span>`
      : `<span>${icon}</span><span>${esc(f.name)}</span><span class="att-rm" onclick="rmF(${i})">×</span>`;
    el.appendChild(d);
  });
  el.classList.toggle('show', S.files.length > 0);
}
function rmF(i){S.files.splice(i,1);renderPrev();updSnd();}
function toUrl(f){return new Promise(res=>{const r=new FileReader();r.onload=e=>res(e.target.result);r.readAsDataURL(f);});}

// ── IMAGE LIMITS ──────────────────────────────────────────────────────────────
// Chat attachments: compress to max 800px, JPEG 0.82, hard-reject if still >700KB
// Server icons:     compress to max 128px, JPEG 0.80
// Profile pics:     already run through the crop canvas (256px) — re-compress to 0.80
// These limits protect the WS relay from getting OOM-killed by a single large image.
const IMG_LIMITS = {
  chat:   { maxPx: 800,  quality: 0.82, maxBytes: 700 * 1024  },
  icon:   { maxPx: 128,  quality: 0.80, maxBytes: 150 * 1024  },
  pfp:    { maxPx: 192,  quality: 0.72, maxBytes: 40 * 1024   },  // KV 64KB limit
};

async function compressImage(dataUrl, opts) {
  const { maxPx, quality, maxBytes } = opts;
  return new Promise((res, rej) => {
    const img = new Image();
    img.onload = () => {
      let w = img.naturalWidth, h = img.naturalHeight;
      if (w > maxPx || h > maxPx) {
        const ratio = Math.min(maxPx / w, maxPx / h);
        w = Math.round(w * ratio); h = Math.round(h * ratio);
      }
      const c = document.createElement('canvas');
      c.width = w; c.height = h;
      c.getContext('2d').drawImage(img, 0, 0, w, h);
      const out = c.toDataURL('image/jpeg', quality);
      if (out.length > maxBytes) {
        // Try once more at half quality before giving up
        const retry = c.toDataURL('image/jpeg', quality * 0.55);
        if (retry.length > maxBytes) { rej(new Error('too_large')); return; }
        res(retry);
      } else {
        res(out);
      }
    };
    img.onerror = () => rej(new Error('bad_image'));
    img.src = dataUrl;
  });
}
function openLB(url){document.getElementById('lb-img').src=url;document.getElementById('lightbox').classList.add('open');}
