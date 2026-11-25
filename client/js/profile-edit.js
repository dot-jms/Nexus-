// ══════════════════════════════════════════════════════════════════
// PICTURE CROPPER + PROFILE EDITOR
// The cropper is one canvas engine used for profile pictures, banners and group pictures: the preview and the saved
// picture are produced by the exact same crDraw(), so what you see is what you get. Geometry is stored as fractions of
// the frame, so it is resolution independent (preview 300px, output 256px, ...).
// ══════════════════════════════════════════════════════════════════
const CR_MIN = 0.25, CR_MAX = 6;
const CR = { img: null, w: 0, h: 0, rot: 0, flip: false, zoom: 1, ox: 0, oy: 0, bg: 'blur', bgColor: '#1e1f22', cfg: null, cw: 300, ch: 300, ptrs: new Map(), pinch: 0, raf: 0, bound: false };
const peEl = id => document.getElementById(id);

// ---- pure geometry (unit-tested) ----
function crDims(st) { const q = ((st.rot % 360) + 360) % 180 !== 0; return { sw: q ? st.h : st.w, sh: q ? st.w : st.h }; }
function crCover(st, W, H) { const d = crDims(st); return Math.max(W / d.sw, H / d.sh); }
function crContainZoom(st, W, H) { const d = crDims(st), a = W / d.sw, b = H / d.sh; return Math.min(a, b) / Math.max(a, b); }
function crClamp(st, W, H) {
  const d = crDims(st), s = crCover(st, W, H) * st.zoom, dw = d.sw * s, dh = d.sh * s;
  const lx = dw >= W ? (dw - W) / 2 : W / 2, ly = dh >= H ? (dh - H) / 2 : H / 2; // zoomed in: never expose an edge; zoomed out: stay in the frame
  st.ox = Math.max(-lx / W, Math.min(lx / W, st.ox)); st.oy = Math.max(-ly / H, Math.min(ly / H, st.oy));
}
function crDrawOriented(c, img, st, scale, cx, cy) {
  c.save(); c.translate(cx, cy); c.rotate(st.rot * Math.PI / 180); if (st.flip) c.scale(-1, 1);
  c.drawImage(img, -st.w * scale / 2, -st.h * scale / 2, st.w * scale, st.h * scale); c.restore();
}
function crDraw(ctx, img, st, W, H) {
  ctx.imageSmoothingEnabled = true; ctx.imageSmoothingQuality = 'high';
  ctx.clearRect(0, 0, W, H);
  if (st.bg === 'color') { ctx.fillStyle = st.bgColor; ctx.fillRect(0, 0, W, H); }
  else if (st.bg === 'blur') { // cheap blur that works everywhere (no ctx.filter): draw tiny, scale up smoothly
    const tw = 24, th = Math.max(6, Math.round(24 * H / W)), t = document.createElement('canvas'); t.width = tw; t.height = th;
    const tc = t.getContext('2d');
    if (tc) { crDrawOriented(tc, img, st, crCover(st, tw, th), tw / 2, th / 2); ctx.drawImage(t, 0, 0, W, H); ctx.fillStyle = 'rgba(0,0,0,.28)'; ctx.fillRect(0, 0, W, H); }
  }
  crDrawOriented(ctx, img, st, crCover(st, W, H) * st.zoom, W / 2 + st.ox * W, H / 2 + st.oy * H);
}
function crFr() { return { W: CR.cfg ? CR.cfg.aspect : 1, H: 1 }; }

// ---- state changes ----
function crSchedule() { if (!CR.raf) CR.raf = requestAnimationFrame(crRender); }
function crPanBy(dx, dy) { const f = crFr(); CR.ox += dx; CR.oy += dy; crClamp(CR, f.W, f.H); crSchedule(); }
function crSetZoom(z, ax, ay) { // anchor (ax,ay) = a point in frame fractions from the centre that stays put (cursor / pinch centre)
  ax = ax || 0; ay = ay || 0; const f = crFr(), nz = Math.max(CR_MIN, Math.min(CR_MAX, z)), r = nz / CR.zoom;
  CR.ox = ax - (ax - CR.ox) * r; CR.oy = ay - (ay - CR.oy) * r; CR.zoom = nz; crClamp(CR, f.W, f.H); crSchedule();
}
function crSliderIn(v) { crSetZoom(CR_MIN * Math.pow(CR_MAX / CR_MIN, Number(v) / 1000)); }
function crNudgeZoom(dir) { crSetZoom(CR.zoom * (dir > 0 ? 1.15 : 1 / 1.15)); }
function crRotate(d) { CR.rot = (CR.rot + d + 360) % 360; const f = crFr(); crClamp(CR, f.W, f.H); crSchedule(); }
function crFlip() { CR.flip = !CR.flip; crSchedule(); }
function crFit() { const f = crFr(); CR.zoom = Math.max(CR_MIN, crContainZoom(CR, f.W, f.H)); CR.ox = CR.oy = 0; crSchedule(); }
function crFill() { CR.zoom = 1; CR.ox = CR.oy = 0; crSchedule(); }
function crReset() { CR.rot = 0; CR.flip = false; crFill(); }
function crSetBg(b) { CR.bg = b; crSchedule(); }
function crSetBgColor(v) { CR.bgColor = v; CR.bg = 'color'; crSchedule(); }

function crRender() {
  CR.raf = 0; const cv = peEl('cr-canvas'); if (!cv || !CR.img) return;
  const c = cv.getContext && cv.getContext('2d'); if (!c) return;
  crDraw(c, CR.img, CR, cv.width, cv.height);
  document.querySelectorAll('#cr-pv canvas').forEach(p => { const x = p.getContext('2d'); if (x) { x.clearRect(0, 0, p.width, p.height); x.drawImage(cv, 0, 0, p.width, p.height); } });
  const lbl = peEl('cr-zoom-lbl'); if (lbl) lbl.textContent = Math.round(CR.zoom * 100) + '%';
  const z = peEl('cr-zoom'); if (z) z.value = Math.round(1000 * Math.log(CR.zoom / CR_MIN) / Math.log(CR_MAX / CR_MIN));
  document.querySelectorAll('#cr-bg button').forEach(b => b.classList.toggle('on', b.dataset.bg === CR.bg));
}
function crLayout() {
  const cfg = CR.cfg, stage = peEl('cr-stage'), cv = peEl('cr-canvas'); if (!cfg || !stage || !cv) return;
  const modal = stage.parentElement, avail = Math.max(160, (modal.clientWidth || 480) - 48), w = Math.min(cfg.stageW, avail), h = Math.round(w / cfg.aspect), dpr = Math.min(2, window.devicePixelRatio || 1);
  stage.style.width = w + 'px'; stage.style.height = h + 'px'; cv.width = Math.round(w * dpr); cv.height = Math.round(h * dpr); CR.cw = w; CR.ch = h; crSchedule();
}
function crBind() {
  if (CR.bound) return; CR.bound = true; const st = peEl('cr-stage');
  st.addEventListener('pointerdown', e => { try { st.setPointerCapture(e.pointerId); } catch (_) {} CR.ptrs.set(e.pointerId, { x: e.clientX, y: e.clientY }); CR.pinch = 0; st.classList.add('drag'); st.focus({ preventScroll: true }); });
  st.addEventListener('pointermove', e => {
    const p = CR.ptrs.get(e.pointerId); if (!p) return; const r = st.getBoundingClientRect();
    if (CR.ptrs.size === 1) { crPanBy((e.clientX - p.x) / r.width, (e.clientY - p.y) / r.height); }
    else if (CR.ptrs.size === 2) {
      CR.ptrs.set(e.pointerId, { x: e.clientX, y: e.clientY }); const [a, b] = [...CR.ptrs.values()], d = Math.hypot(a.x - b.x, a.y - b.y);
      if (CR.pinch) crSetZoom(CR.zoom * d / CR.pinch, ((a.x + b.x) / 2 - r.left) / r.width - 0.5, ((a.y + b.y) / 2 - r.top) / r.height - 0.5);
      CR.pinch = d; return;
    }
    CR.ptrs.set(e.pointerId, { x: e.clientX, y: e.clientY });
  });
  const up = e => { CR.ptrs.delete(e.pointerId); CR.pinch = 0; if (!CR.ptrs.size) st.classList.remove('drag'); };
  st.addEventListener('pointerup', up); st.addEventListener('pointercancel', up);
  st.addEventListener('wheel', e => { e.preventDefault(); const r = st.getBoundingClientRect(); crSetZoom(CR.zoom * Math.exp(-e.deltaY * 0.0015), (e.clientX - r.left) / r.width - 0.5, (e.clientY - r.top) / r.height - 0.5); }, { passive: false });
  st.addEventListener('keydown', e => {
    const k = e.key, m = { ArrowLeft: [-.02, 0], ArrowRight: [.02, 0], ArrowUp: [0, -.02], ArrowDown: [0, .02] }[k];
    if (m) { e.preventDefault(); crPanBy(m[0], m[1]); }
    else if (k === '+' || k === '=') { e.preventDefault(); crNudgeZoom(1); } else if (k === '-') { e.preventDefault(); crNudgeZoom(-1); }
    else if (k === '0') crReset(); else if (k === 'r' || k === 'R') crRotate(90);
  });
  window.addEventListener('resize', () => { if (peEl('pfp-crop-modal').classList.contains('open')) crLayout(); });
}

// ---- open / apply ----
function openCropper(source, cfg) {
  cfg = Object.assign({ kind: 'pfp', aspect: 1, outW: 256, outH: 256, maxChars: 44000, stageW: 300, shape: 'circle', title: 'Profile picture', alpha: true, onApply: null, target: 'profile' }, cfg || {});
  const isFile = typeof source !== 'string';
  if (isFile && !/^image\//.test(source.type || '')) { toast('⚠️ That file is not an image'); return; }
  const url = isFile ? URL.createObjectURL(source) : source, img = new Image();
  img.onload = () => { if (isFile) URL.revokeObjectURL(url); crStart(img, cfg); };
  img.onerror = () => { if (isFile) URL.revokeObjectURL(url); toast('⚠️ Could not read that image. Try a JPEG, PNG or WebP.'); };
  img.src = url;
}
function crStart(img, cfg) {
  CR.img = img; CR.w = img.naturalWidth || img.width; CR.h = img.naturalHeight || img.height; CR.cfg = cfg;
  CR.rot = 0; CR.flip = false; CR.zoom = 1; CR.ox = CR.oy = 0; CR.bg = 'blur'; CR.ptrs.clear();
  peEl('cr-title').textContent = cfg.title;
  peEl('cr-mask').className = 'cr-mask ' + cfg.shape;
  const pv = peEl('cr-pv'); pv.className = 'cr-pv ' + cfg.shape;
  pv.innerHTML = cfg.kind === 'banner' ? '<canvas width="180" height="60"></canvas>' : [64, 40, 24].map(s => `<div style="text-align:center"><canvas width="${s}" height="${s}"></canvas><div>${s}px</div></div>`).join('');
  document.querySelectorAll('#cr-bg button[data-bg="clear"]').forEach(b => { b.style.display = cfg.alpha ? '' : 'none'; });
  crBind(); openM('pfp-crop-modal'); crLayout();
}
async function crEncode() {
  const cfg = CR.cfg, mimes = CR.bg === 'clear' ? ['image/webp', 'image/png'] : ['image/webp', 'image/jpeg'];
  for (const k of [1, .875, .75, .625, .5]) {
    const W = Math.round(cfg.outW * k), H = Math.round(cfg.outH * k), c = document.createElement('canvas'); c.width = W; c.height = H;
    const x = c.getContext('2d'); if (!x) throw new Error('no_canvas');
    crDraw(x, CR.img, CR, W, H);
    for (const m of mimes) for (const q of (m === 'image/png' ? [1] : [.92, .82, .72, .6, .48, .36])) {
      const d = c.toDataURL(m, q); if (d.indexOf('data:' + m) !== 0) break; // this browser cannot encode that format
      if (d.length <= cfg.maxChars) return d;
    }
  }
  throw new Error('too_large');
}
async function commitPfpCrop() { // name kept: the Apply button, and old tests, call this
  const btn = peEl('cr-apply'); if (btn.disabled) return; btn.disabled = true;
  try {
    const data = await crEncode(), cfg = CR.cfg;
    if (typeof cfg.onApply === 'function') cfg.onApply(data);
    else if (cfg.target === 'signup') { suPfpData = data; const pv = peEl('su-pfp-preview'); if (pv) pv.innerHTML = `<img src="${data}" alt="pfp">`; }
    else if (cfg.target === 'admin_target' && _adminPfpTarget) {
      wsSend({ type: 'admin_set_pfp', target: _adminPfpTarget, pfp: data });
      const r = peEl('admin-users-result'); if (r) r.textContent = `✅ PFP updated for ${_adminPfpTarget}`; _adminPfpTarget = null;
    }
    else peSetPfp(data);
    closeM('pfp-crop-modal');
  } catch (err) { toast(err.message === 'too_large' ? '⚠️ Still too large. Try zooming out, or turn off Transparent.' : '⚠️ Could not process the image'); }
  finally { btn.disabled = false; }
}
function pfpOpenFile(file, target) { window._pfpCropTarget = target; openCropper(file, { target, kind: 'pfp', title: 'Profile picture' }); }
function peOpenAvatarCropper(src) { openCropper(src, { target: 'profile', kind: 'pfp', title: 'Profile picture' }); }
function peOpenBannerCropper(src) { openCropper(src, { target: 'banner', kind: 'banner', aspect: 3, outW: 480, outH: 160, maxChars: 46000, stageW: 440, shape: 'rect', alpha: false, title: 'Banner image', onApply: peSetBanner }); }
function onPfpChange(e) { const f = e.target.files[0]; e.target.value = ''; if (f) peOpenAvatarCropper(f); }
function onBannerChange(e) { const f = e.target.files[0]; e.target.value = ''; if (f) peOpenBannerCropper(f); }

// ══════════════════════════════════════════════════════════════════
// PROFILE EDITOR
// ══════════════════════════════════════════════════════════════════
const PE = { d: null, o: null, tab: 'look', bound: false };
let peMyBanner = null; // my own banner image (kept out of S.user so it never lands in the saved session)
function peApplyOwnExt(msg) { // server → me, right after login
  if (!S.user) return; S.user.ext = pfNormExt(msg.ext); peMyBanner = pfSafeImg(msg.banner) || null;
  try { lsSet('nx-session', { token: S.token, user: S.user }); } catch (_) {}
}
function buildProfileModal() {} // markup now lives in index.html; kept so old callers still work
function peClone(x) { return JSON.parse(JSON.stringify(x)); }
function peHandle(v) { v = (v || '').trim(); const m = v.match(/^https?:\/\/[^/]+\/(?:@|profile\/|user\/)?([^/?#]+)/i); return (m ? m[1] : v).replace(/^@/, ''); }

function peBuildOnce() {
  if (PE.bound) return; PE.bound = true;
  peEl('pe-links').innerHTML = PF_SOCIALS.map(s => `<div class="pe-inp-row"><span title="${s.label}">${s.icon}</span><input class="m-inp" id="profile-${s.k}-in" placeholder="${s.label}: ${s.ph}" maxlength="100" oninput="peIn()"></div>`).join('');
  peEl('pe-tints').innerHTML = '<div class="pe-sw none" onclick="peTint(null)" title="No tint">✕</div>' + PF_TINTS.map(c => `<div class="pe-sw" style="background:${c}" data-c="${c}" onclick="peTint('${c}')"></div>`).join('') + '<input type="color" class="pe-color" id="pe-tint-custom" oninput="peTint(this.value)" title="Any colour">';
  document.addEventListener('paste', e => {
    const crop = peEl('pfp-crop-modal').classList.contains('open'), ed = peEl('profile-edit-modal').classList.contains('open'); if (!crop && !ed) return;
    const f = [...((e.clipboardData && e.clipboardData.files) || [])].find(x => /^image\//.test(x.type)); if (!f) return; e.preventDefault();
    if (crop) openCropper(f, CR.cfg); else peOpenAvatarCropper(f);
  });
  const m = peEl('profile-edit-modal'), clr = () => m.querySelectorAll('.pe-drop').forEach(x => x.classList.remove('pe-drop')), has = e => e.dataTransfer && [...e.dataTransfer.types].includes('Files');
  ['dragenter', 'dragover'].forEach(t => m.addEventListener(t, e => { if (!has(e)) return; e.preventDefault(); clr(); const z = e.target.closest('[data-drop]'); (z || m.firstElementChild).classList.add('pe-drop'); }));
  m.addEventListener('dragleave', e => { if (e.target === m) clr(); });
  m.addEventListener('drop', e => { clr(); const f = [...((e.dataTransfer && e.dataTransfer.files) || [])].find(x => /^image\//.test(x.type)); if (!f) return; e.preventDefault(); const z = e.target.closest('[data-drop]'); if (z && z.dataset.drop === 'banner') peOpenBannerCropper(f); else peOpenAvatarCropper(f); });
}

function openProfileEdit() {
  const u = S.user; peBuildOnce();
  PE.o = { color: u.color, pfp: u.pfp || null, banner: peMyBanner, ext: pfNormExt(u.ext), bio: u.bio || '', socials: Object.assign({}, u.socials || {}) };
  PE.d = peClone(PE.o);
  const av = peEl('profile-modal-av'); av._pendingPfp = null; av._removed = false; av.onclick = peAvatarUpload;
  peEl('profile-modal-name').textContent = '· ' + u.name; peEl('profile-modal-tag').textContent = ' #' + (u.tag || '0000');
  peEl('profile-bio-in').value = PE.d.bio; peEl('pe-pron-in').value = PE.d.ext.pronouns; peEl('pe-loc-in').value = PE.d.ext.location;
  PF_SOCIALS.forEach(s => { const i = peEl('profile-' + s.k + '-in'); if (i) i.value = PE.d.socials[s.k] || ''; });
  const grid = peEl('profile-av-grid'); grid.innerHTML = '';
  const addSw = (c, sel, id) => { const d = document.createElement('div'); d.className = 'av-opt' + (sel ? ' sel' : ''); d.style.background = c; d.dataset.c = c; if (id) d.id = id; d.onclick = () => peColorPick(c); grid.appendChild(d); };
  COLORS.forEach(c => addSw(c, c === u.color)); if (!COLORS.includes(u.color)) addSw(u.color, true, 'pe-custom-sw');
  peEl('pe-color-custom').value = pfHex(u.color, '#5865f2');
  peTab('look'); peSync(); openM('profile-edit-modal');
}
function peColorPick(c) { PE.d.color = c; document.querySelectorAll('#profile-av-grid .av-opt').forEach(x => x.classList.toggle('sel', x.dataset.c === c)); peEl('pe-color-custom').value = pfHex(c, '#5865f2'); peRender(); }
function peColorCustom(v) {
  let sw = peEl('pe-custom-sw'); if (!sw) { sw = document.createElement('div'); sw.className = 'av-opt'; sw.id = 'pe-custom-sw'; sw.onclick = () => peColorPick(sw.dataset.c); peEl('profile-av-grid').appendChild(sw); }
  sw.dataset.c = v; sw.style.background = v; peColorPick(v);
}
function peTab(t) {
  PE.tab = t; document.querySelectorAll('#pe-tabs .pe-tab').forEach(b => b.classList.toggle('on', b.dataset.tab === t));
  ['look', 'style', 'about', 'links'].forEach(k => { const p = peEl('pe-p-' + k); if (p) p.style.display = k === t ? '' : 'none'; });
}
function peReadDom() { // inputs → draft
  const d = PE.d, e = d.ext, v = id => { const x = peEl(id); return x ? x.value : ''; };
  d.bio = v('profile-bio-in').slice(0, 160); e.pronouns = v('pe-pron-in').slice(0, 24); e.location = v('pe-loc-in').slice(0, 30);
  if (e.banner.kind === 'color') e.banner.c1 = v('pe-b-c1') || e.banner.c1;
  else if (e.banner.kind === 'gradient') { e.banner.c1 = v('pe-b-g1') || e.banner.c1; e.banner.c2 = v('pe-b-g2') || e.banner.c2; e.banner.angle = Number(v('pe-b-ang')) || 0; }
  if (e.frame.kind !== 'none') { e.frame.c1 = v('pe-fr-c1') || e.frame.c1; e.frame.c2 = v('pe-fr-c2') || e.frame.c2; }
  if (e.nameFx.kind !== 'none') { e.nameFx.c1 = v('pe-nf-c1') || e.nameFx.c1; e.nameFx.c2 = v('pe-nf-c2') || e.nameFx.c2; }
  PF_SOCIALS.forEach(s => { const i = peEl('profile-' + s.k + '-in'); if (i) d.socials[s.k] = i.value.trim(); });
}
function peIn() { peReadDom(); peRender(); }
function peSync() { // draft → controls (chips, colour inputs, which sub-panels show)
  const e = PE.d.ext, b = e.banner, set = (id, v) => { const x = peEl(id); if (x) x.value = v; };
  const chips = (id, list, cur, fn) => { peEl(id).innerHTML = list.map(o => `<button class="pe-chip${o[0] === cur ? ' on' : ''}" onclick="${fn}('${o[0]}')">${o[1]}</button>`).join(''); };
  chips('pe-banner-kinds', [['default', 'Default'], ['color', 'Colour'], ['gradient', 'Gradient'], ['image', 'Image']], b.kind, 'peBannerKind');
  chips('pe-frames', PF_FRAMES.map(f => [f.id, f.n]), e.frame.kind, 'peFrameKind'); chips('pe-names', PF_NAMEFX.map(f => [f.id, f.n]), e.nameFx.kind, 'peNameKind');
  peEl('pe-banner-presets').innerHTML = PF_BANNERS.map(p => `<button class="pe-preset${p.c1 === b.c1 && p.c2 === b.c2 ? ' on' : ''}" style="background:linear-gradient(135deg,${p.c1},${p.c2})" onclick="peBannerPreset('${p.id}')">${p.n}</button>`).join('');
  set('pe-b-c1', b.c1); set('pe-b-g1', b.c1); set('pe-b-g2', b.c2); set('pe-b-ang', b.angle);
  set('pe-fr-c1', e.frame.c1); set('pe-fr-c2', e.frame.c2); set('pe-nf-c1', e.nameFx.c1); set('pe-nf-c2', e.nameFx.c2);
  const show = (id, on) => { const x = peEl(id); if (x) x.style.display = on ? '' : 'none'; };
  show('pe-b-color', b.kind === 'color'); show('pe-b-grad', b.kind === 'gradient'); show('pe-b-img', b.kind === 'image');
  show('pe-frame-cols', e.frame.kind !== 'none'); show('pe-name-cols', e.nameFx.kind !== 'none');
  const two = (list, id, k) => { const f = list.find(x => x.id === k); const c2 = peEl(id); if (c2) c2.style.display = f && f.two ? '' : 'none'; };
  two(PF_FRAMES, 'pe-fr-c2', e.frame.kind); two(PF_NAMEFX, 'pe-nf-c2', e.nameFx.kind);
  show('pe-b-edit', !!PE.d.banner); show('pe-b-rm', !!PE.d.banner); show('pe-av-edit', !!PE.d.pfp); show('pe-av-rm', !!PE.d.pfp);
  document.querySelectorAll('#pe-tints .pe-sw[data-c]').forEach(x => x.classList.toggle('on', x.dataset.c === e.cardTint));
  const tc = peEl('pe-tint-custom'); if (tc && e.cardTint) tc.value = e.cardTint;
  peRender();
}
function peRender() { // avatar, counters, interests, live preview, dirty flag
  const d = PE.d, e = d.ext, u = S.user, av = peEl('profile-modal-av');
  if (av) { av.style.background = d.pfp ? 'transparent' : pfHex(d.color, '#5865f2'); av.innerHTML = (d.pfp ? `<img src="${safeUrl(d.pfp)}" alt="">` : esc((u.name || '?')[0].toUpperCase())) + '<div class="av-overlay">Change</div>'; }
  const bc = peEl('pe-bio-count'); if (bc) bc.textContent = (d.bio || '').length + ' / 160';
  const ic = peEl('pe-int-count'); if (ic) ic.textContent = e.interests.length + ' / 8';
  peEl('pe-int-tags').innerHTML = e.interests.map((t, i) => `<span class="pe-tag">${esc(t)}<button onclick="peIntDel(${i})" aria-label="Remove">✕</button></span>`).join('');
  peEl('pe-int-sugg').innerHTML = e.interests.length >= 8 ? '' : PF_INTERESTS.filter(t => !e.interests.some(x => x.toLowerCase() === t.toLowerCase())).map(t => `<button class="pe-chip" onclick="peIntAdd('${t}')">+ ${t}</button>`).join('');
  const fr = pfFrameAttrs(e, d.color), nf = pfNameAttrs(e), links = pfSocialLinks(d.socials);
  peEl('pe-preview').innerHTML = `<div class="pv-card" style="${pfCardCss(e)}"><div class="pv-banner" style="${pfBannerCss(e, d.color, d.banner)}"></div>
    <div class="pv-av ${fr.cls}" style="${fr.style}background:${d.pfp ? 'transparent' : pfHex(d.color, '#5865f2')}">${d.pfp ? `<img src="${safeUrl(d.pfp)}" alt="">` : esc((u.name || '?')[0].toUpperCase())}</div>
    <div class="pv-body"><div class="pv-name ${nf.cls}" style="${nf.style}">${esc(u.name)}</div><div class="pv-tag">#${esc(u.tag || '0000')}${e.pronouns ? ' · ' + esc(e.pronouns) : ''}</div>
    ${e.location ? `<div class="pv-meta">📍 ${esc(e.location)}</div>` : ''}
    ${d.bio ? `<div class="pv-sec"><div class="pv-sec-t">About me</div><div class="pv-bio">${esc(d.bio)}</div></div>` : ''}
    ${e.interests.length ? `<div class="pv-sec"><div class="pv-sec-t">Interests</div><div class="pp-chips">${e.interests.map(t => `<span class="pp-chip">${esc(t)}</span>`).join('')}</div></div>` : ''}
    ${links.length ? `<div class="pv-sec"><div class="pv-sec-t">Links</div>${links.map(l => `<span class="pv-link">${l.icon} ${esc(l.text)}</span>`).join('')}</div>` : ''}</div></div>`;
  const dirty = peEl('pe-dirty'); if (dirty) dirty.classList.toggle('on', peIsDirty());
}
function peIsDirty() { return !!PE.d && JSON.stringify(PE.d) !== JSON.stringify(PE.o); }
function peClose() { if (peIsDirty() && !confirm('Discard your changes?')) return; closeM('profile-edit-modal'); }

// avatar
function peAvatarUpload() { peEl('pfp-file-in').click(); }
function peAvatarEdit() { if (PE.d.pfp) peOpenAvatarCropper(PE.d.pfp); else peAvatarUpload(); }
function peAvatarRemove() { const av = peEl('profile-modal-av'); PE.d.pfp = null; av._pendingPfp = null; av._removed = true; peSync(); }
function peSetPfp(data) { const av = peEl('profile-modal-av'); PE.d.pfp = data; av._pendingPfp = data; av._removed = false; peSync(); }
// banner
function peBannerKind(k) { peReadDom(); PE.d.ext.banner.kind = k; peSync(); }
function peBannerPreset(id) { const p = PF_BANNERS.find(x => x.id === id); if (!p) return; const b = PE.d.ext.banner; b.kind = 'gradient'; b.c1 = p.c1; b.c2 = p.c2; peSync(); }
function peBannerUpload() { peEl('pe-banner-file').click(); }
function peBannerEdit() { if (PE.d.banner) peOpenBannerCropper(PE.d.banner); else peBannerUpload(); }
function peSetBanner(data) { PE.d.banner = data; PE.d.ext.banner.kind = 'image'; peSync(); }
function peBannerRemove() { PE.d.banner = null; if (PE.d.ext.banner.kind === 'image') PE.d.ext.banner.kind = 'default'; peSync(); }
// style
function peFrameKind(k) { peReadDom(); PE.d.ext.frame.kind = k; peSync(); }
function peNameKind(k) { peReadDom(); PE.d.ext.nameFx.kind = k; peSync(); }
function peTint(c) { PE.d.ext.cardTint = c; peSync(); }
function peResetStyle() { const e = PE.d.ext, d = pfExtDefaults(); e.banner = d.banner; e.frame = d.frame; e.nameFx = d.nameFx; e.cardTint = null; if (PE.d.banner) PE.d.banner = null; peSync(); }
function peRandom() {
  const pick = a => a[Math.floor(Math.random() * a.length)], e = PE.d.ext, p = pick(PF_BANNERS), c = () => pick(PF_TINTS);
  e.banner = { kind: 'gradient', c1: p.c1, c2: p.c2, angle: Math.floor(Math.random() * 361) };
  e.frame = { kind: pick(PF_FRAMES.filter(f => f.id !== 'none')).id, c1: c(), c2: c() }; e.nameFx = { kind: pick(PF_NAMEFX.filter(f => f.id !== 'none')).id, c1: c(), c2: c() };
  e.cardTint = Math.random() < .7 ? c() : null; peSync();
}
// interests
function peIntAdd(t) { t = (t || '').replace(/[<>]/g, '').trim().slice(0, 20); const a = PE.d.ext.interests; if (!t || a.length >= 8 || a.some(x => x.toLowerCase() === t.toLowerCase())) return; a.push(t); peEl('pe-int-in').value = ''; peRender(); }
function peIntDel(i) { PE.d.ext.interests.splice(i, 1); peRender(); }
function peIntCommit() { const i = peEl('pe-int-in'); if (i && i.value.trim()) peIntAdd(i.value); }
function peIntKey(e) {
  if (e.key === 'Enter' || e.key === ',') { e.preventDefault(); peIntCommit(); }
  else if (e.key === 'Backspace' && !e.target.value && PE.d.ext.interests.length) { PE.d.ext.interests.pop(); peRender(); }
}

function saveProfile() {
  const sel = document.querySelector('#profile-av-grid .av-opt.sel'), _color = (sel && sel.dataset.c) || S.user.color;
  const av = peEl('profile-modal-av');
  let _pfp = S.user.pfp; if (av._pendingPfp) _pfp = av._pendingPfp; else if (av._removed) _pfp = null;
  if (PE.d) peReadDom();
  const val = id => { const x = peEl(id); return x ? x.value.trim() : ''; };
  const socials = {};
  PF_SOCIALS.forEach(s => {
    let v = val('profile-' + s.k + '-in');
    if (s.k === 'website') { if (v && !/^https?:\/\//i.test(v)) v = 'https://' + v; } else v = peHandle(v);
    socials[s.k] = v;
  });
  const payload = { type: 'profile_update', user: S.user.name, color: _color, pfp: _pfp, bio: val('profile-bio-in').slice(0, 160), socials };
  let ext = null;
  if (PE.d) {
    ext = pfNormExt(PE.d.ext); if (ext.banner.kind === 'image' && !PE.d.banner) ext.banner.kind = 'default';
    payload.ext = ext; if (PE.d.banner !== PE.o.banner) payload.bannerImg = PE.d.banner;
  }
  wsSend(payload);
  if (PE.d) PE.o = peClone(PE.d);
  try {
    S.user.color = _color; S.user.pfp = _pfp || null; S.user.bio = payload.bio; S.user.socials = socials;
    if (ext) { S.user.ext = ext; peMyBanner = PE.d.banner; }
    if (typeof profileCache !== 'undefined' && profileCache[S.user.name]) Object.assign(profileCache[S.user.name], { color: _color, pfp: _pfp || null, bio: payload.bio, socials, ext: ext || profileCache[S.user.name].ext, bannerImg: peMyBanner });
    lsSet('nx-session', { token: S.token, user: S.user }); persist();
    updateUser(); closeM('profile-edit-modal'); toast('✅ Profile updated');
    Object.values(S.messages).forEach(arr => { arr.forEach(m => { if (m.author === S.user.name) { m.authorColor = S.user.color; m.authorPfp = S.user.pfp || null; } }); });
    Object.values(S.dmMessages).forEach(arr => { arr.forEach(m => { if (m.author === S.user.name) { m.authorColor = S.user.color; m.authorPfp = S.user.pfp || null; } }); });
    refreshAvatars(S.user.name);
    if (curDM) renderDMMessages(curDM);
  } catch (e) { console.error('[nexus] saveProfile UI error', e); toast('⚠️ Saved, but the screen failed to update: ' + e.message); }
}
