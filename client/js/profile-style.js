// ══════════════════════════════════════════════════════════════════
// PROFILE STYLE — banner / avatar frame / name effect / card tint helpers.
// Shared by the profile page, the hover card and the editor's live preview, so all three always look the same.
// Everything here is pure (strings in, strings out) and only ever lets validated hex colours into CSS.
// ══════════════════════════════════════════════════════════════════
const PF_HEX = /^#(?:[0-9a-f]{3}|[0-9a-f]{6})$/i;
function pfHex(c, fb) {
  if (typeof c !== 'string' || !PF_HEX.test(c)) return fb;
  const h = c.toLowerCase();
  return h.length === 4 ? '#' + h[1] + h[1] + h[2] + h[2] + h[3] + h[3] : h;
}
function pfSafeImg(u) { return typeof u === 'string' && u.length < 200000 && /^data:image\/(?:jpeg|png|webp);base64,[A-Za-z0-9+/=]+$/.test(u) ? u : ''; }

const PF_BANNERS = [
  { id: 'aurora', n: 'Aurora',   c1: '#00c9a7', c2: '#845ec2' },
  { id: 'sunset', n: 'Sunset',   c1: '#ff9a44', c2: '#fc6076' },
  { id: 'ocean',  n: 'Ocean',    c1: '#2193b0', c2: '#6dd5ed' },
  { id: 'candy',  n: 'Candy',    c1: '#f472b6', c2: '#818cf8' },
  { id: 'forest', n: 'Forest',   c1: '#134e5e', c2: '#71b280' },
  { id: 'ember',  n: 'Ember',    c1: '#f12711', c2: '#f5af19' },
  { id: 'night',  n: 'Midnight', c1: '#0f2027', c2: '#4b6cb7' },
  { id: 'mint',   n: 'Mint',     c1: '#a8ff78', c2: '#38ef7d' },
  { id: 'grape',  n: 'Grape',    c1: '#4776e6', c2: '#8e54e9' },
  { id: 'rose',   n: 'Rosé',     c1: '#ee9ca7', c2: '#ffdde1' },
  { id: 'lava',   n: 'Lava',     c1: '#232526', c2: '#e52d27' },
  { id: 'neon',   n: 'Neon',     c1: '#00f5a0', c2: '#00d9f5' },
];
const PF_FRAMES = [
  { id: 'none', n: 'None', two: false }, { id: 'ring', n: 'Ring', two: false }, { id: 'gradient', n: 'Gradient', two: true },
  { id: 'glow', n: 'Glow', two: false }, { id: 'neon', n: 'Neon', two: true }, { id: 'dashed', n: 'Dashed', two: false },
];
const PF_NAMEFX = [
  { id: 'none', n: 'Plain', two: false }, { id: 'gradient', n: 'Gradient', two: true },
  { id: 'glow', n: 'Glow', two: false }, { id: 'shimmer', n: 'Shimmer', two: true },
];
const PF_TINTS = ['#5865f2', '#eb459e', '#f59e0b', '#10b981', '#06b6d4', '#ef4444', '#a855f7', '#64748b'];
const PF_INTERESTS = ['Gaming', 'Music', 'Coding', 'Art', 'Anime', 'Movies', 'Reading', 'Fitness', 'Travel', 'Cooking'];
// handle-style links. `url` builds the address from the (encoded) handle; website is stored as typed.
const PF_SOCIALS = [
  { k: 'website',   label: 'Website',     ph: 'https://yoursite.com', icon: '🌐' },
  { k: 'twitter',   label: 'X / Twitter', ph: '@handle',    icon: '𝕏',  url: h => 'https://twitter.com/' + h },
  { k: 'github',    label: 'GitHub',      ph: 'username',   icon: '🐙', url: h => 'https://github.com/' + h },
  { k: 'youtube',   label: 'YouTube',     ph: '@channel',   icon: '▶️', url: h => 'https://youtube.com/@' + h },
  { k: 'twitch',    label: 'Twitch',      ph: 'username',   icon: '🎮', url: h => 'https://twitch.tv/' + h },
  { k: 'instagram', label: 'Instagram',   ph: 'username',   icon: '📸', url: h => 'https://instagram.com/' + h },
  { k: 'bluesky',   label: 'Bluesky',     ph: 'name.bsky.social', icon: '🦋', url: h => 'https://bsky.app/profile/' + h },
];

function pfExtDefaults() {
  return {
    pronouns: '', location: '', interests: [],
    banner: { kind: 'default', c1: '#5865f2', c2: '#eb459e', angle: 135 },
    frame:  { kind: 'none', c1: '#5865f2', c2: '#eb459e' },
    nameFx: { kind: 'none', c1: '#5865f2', c2: '#eb459e' },
    cardTint: null,
  };
}
// Fills in defaults and validates everything; always returns a fresh object (safe to mutate).
function pfNormExt(e) {
  const d = pfExtDefaults(); e = e && typeof e === 'object' ? e : {};
  const sub = (x, dd, kinds) => { x = x && typeof x === 'object' ? x : {}; return { kind: kinds.includes(x.kind) ? x.kind : dd.kind, c1: pfHex(x.c1, dd.c1), c2: pfHex(x.c2, dd.c2) }; };
  const txt = (v, n) => (typeof v === 'string' ? v.replace(/[\u0000-\u001f\u007f<>]/g, '').replace(/\s+/g, ' ').trim().slice(0, n) : '');
  const b = sub(e.banner, d.banner, ['default', 'color', 'gradient', 'image']);
  const ang = Math.round(Number(e.banner && e.banner.angle));
  b.angle = Number.isFinite(ang) ? Math.max(0, Math.min(360, ang)) : 135;
  const seen = new Set(), interests = [];
  (Array.isArray(e.interests) ? e.interests : []).forEach(x => { const t = txt(x, 20); if (t && !seen.has(t.toLowerCase()) && interests.length < 8) { seen.add(t.toLowerCase()); interests.push(t); } });
  return {
    pronouns: txt(e.pronouns, 24), location: txt(e.location, 30), interests, banner: b,
    frame: sub(e.frame, d.frame, PF_FRAMES.map(f => f.id)), nameFx: sub(e.nameFx, d.nameFx, PF_NAMEFX.map(f => f.id)),
    cardTint: pfHex(e.cardTint, null),
  };
}

// CSS `background` for a banner element. `color` is the person's avatar colour (used for the default look).
function pfBannerCss(ext, color, bannerImg) {
  const e = pfNormExt(ext), c = pfHex(color, '#5865f2'), b = e.banner;
  if (b.kind === 'color') return `background:${b.c1}`;
  if (b.kind === 'gradient') return `background:linear-gradient(${b.angle}deg,${b.c1},${b.c2})`;
  const img = pfSafeImg(bannerImg);
  if (b.kind === 'image' && img) return `background:url('${img}') center/cover no-repeat`;
  return `background:linear-gradient(160deg,${c}cc 0%,${c}22 100%),${c}33`;
}
// class + inline custom properties for an avatar element (profile.css draws the frame from them)
function pfFrameAttrs(ext, innerColor, allowed) {
  const f = pfNormExt(ext).frame;
  if (allowed === false || f.kind === 'none') return { cls: '', style: '' };
  return { cls: 'fr-' + f.kind, style: `--fr1:${f.c1};--fr2:${f.c2};--av-in:${pfHex(innerColor, '#1e1f22')};` };
}
function pfNameAttrs(ext, allowed) {
  const n = pfNormExt(ext).nameFx;
  if (allowed === false || n.kind === 'none') return { cls: '', style: '' };
  return { cls: 'nf-' + n.kind, style: `--nf1:${n.c1};--nf2:${n.c2};` };
}
// background for the whole card (a soft wash of the chosen tint over the normal surface)
function pfCardCss(ext) {
  const t = pfNormExt(ext).cardTint;
  return t ? `background:linear-gradient(180deg,${t}38 0,${t}12 220px),var(--bg-user-panel)` : '';
}
// the links a profile shows, as ready-to-render entries (hrefs are built from encoded handles)
function pfSocialLinks(socials) {
  const s = socials && typeof socials === 'object' ? socials : {}, out = [];
  PF_SOCIALS.forEach(def => {
    let v = typeof s[def.k] === 'string' ? s[def.k].trim() : '';
    if (!v) return;
    if (def.k === 'website') {
      // older profiles may hold "mysite.io" without a scheme; anything else (odd schemes, junk) is not shown as a link
      if (!/^https?:\/\//i.test(v)) { if (/^[\w-]+(\.[\w-]+)+([\/?#]\S*)?$/.test(v)) v = 'https://' + v; else return; }
      out.push({ k: def.k, icon: def.icon, text: v.replace(/^https?:\/\//i, ''), href: v });
    } else {
      v = v.replace(/^@/, '');
      if (!v) return;
      out.push({ k: def.k, icon: def.icon, text: (def.k === 'twitter' || def.k === 'youtube' ? '@' : '') + v, href: def.url(encodeURIComponent(v)) });
    }
  });
  return out;
}


// ── Frames + name effects are an admin / co-admin perk: nobody else gets them, whatever is stored. ──
function pfCanStyle(p) { return !!p && (p.systemRole === 'admin' || p.coAdmin === true); }
function pfStyleFor(name) { // who is this, may they have a frame / name effect, and what is it
  if (!name) return { ok: false };
  const me = (typeof S !== 'undefined') ? S.user : null, isMe = !!me && name === me.name;
  const p = isMe ? me : (typeof profileCache !== 'undefined' ? profileCache[name] : null);
  if (!isMe && (!p || p.ext === undefined) && typeof _needProfile === 'function') _needProfile(name); // arrives via applyProfiles
  return p ? { ok: pfCanStyle(p), ext: p.ext, color: p.color } : { ok: false };
}
function pfSetVars(el, css) { String(css || '').split(';').forEach(kv => { const i = kv.indexOf(':'); if (i > 0) el.style.setProperty(kv.slice(0, i).trim(), kv.slice(i + 1).trim()); }); }
// Puts the frame on every avatar and the name effect on every name that is on screen (chat, member list).
// Idempotent, so it is simply re-run whenever those lists change (see the observer below) or profiles arrive.
function pfApplyCls(el, prefix, cls, css, vars) {   // only touches the element when something really differs (no flicker)
  const cur = [...el.classList].filter(c => c.indexOf(prefix) === 0);
  const want = {}; String(css || '').split(';').forEach(kv => { const k = kv.indexOf(':'); if (k > 0) want[kv.slice(0, k).trim()] = kv.slice(k + 1).trim(); });
  const same = cur.length === (cls ? 1 : 0) && (!cls || cur[0] === cls) && vars.every(v => (el.style.getPropertyValue(v) || '') === (want[v] || ''));
  if (same) return;
  cur.forEach(c => el.classList.remove(c)); vars.forEach(v => el.style.removeProperty(v));
  if (cls) { el.classList.add(cls); pfSetVars(el, css); }
}
// the same look as inline markup, so buildMsg / renderMbs can paint it in the very first frame
function pfInline(name) {
  const none = { fr: '', frs: '', nf: '', nfs: '' };
  try {
    const s = pfStyleFor(name); if (!s.ok) return none;
    const f = pfFrameAttrs(s.ext, s.color, true), n = pfNameAttrs(s.ext, true);
    return { fr: f.cls, frs: f.style, nf: n.cls, nfs: n.style };
  } catch (_) { return none; }
}
function pfDecorate() {
  document.querySelectorAll('.m-av[data-author], .mb-av[data-name]').forEach(el => {
    const s = pfStyleFor(el.dataset.author || el.dataset.name);
    const a = s.ok ? pfFrameAttrs(s.ext, s.color, true) : { cls: '', style: '' };
    pfApplyCls(el, 'fr-', a.cls, a.style, ['--fr1', '--fr2', '--av-in']);
  });
  document.querySelectorAll('.m-auth[data-author], .mb-nm[data-name]').forEach(el => {
    const s = pfStyleFor(el.dataset.author || el.dataset.name);
    const a = s.ok ? pfNameAttrs(s.ext, true) : { cls: '', style: '' };   // no personal effect: the role's own look (if any) stays
    pfApplyCls(el, 'nf-', a.cls, a.style, ['--nf1', '--nf2']);
  });
}
(function () {
  let t = false; const run = () => { t = false; try { pfDecorate(); } catch (e) { console.error(e); } };
  // a MutationObserver callback runs as a microtask, BEFORE the browser paints: decorate right there (no requestAnimationFrame gap)
  const arm = () => { if (typeof MutationObserver === 'undefined') return; const mo = new MutationObserver(() => { if (!t) { t = true; (typeof queueMicrotask === 'function' ? queueMicrotask : (f => Promise.resolve().then(f)))(run); } });
    ['msgs', 'dm-msgs', 'members'].forEach(id => { const el = document.getElementById(id); if (el) mo.observe(el, { childList: true, subtree: true }); }); };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', arm); else arm();
})();
