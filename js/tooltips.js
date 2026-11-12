// ── Tooltips ─────────────────────────────────────────────
// One floating bubble for icon buttons. Elements keep using the normal
// `title` attribute; on first hover it is moved to data-tip so the browser's
// slow native tooltip doesn't also appear.
(() => {
  const SCOPE = '#rail, .ch-hd, .dm-chat-hd, .u-acts, .m-acts, .in-l, .in-r';
  const tip = document.createElement('div');
  tip.id = 'tip';
  document.body.appendChild(tip);
  let cur = null;

  function hide(){ tip.classList.remove('show'); cur = null; }
  function show(el){
    const text = el.dataset.tip;
    if (!text) return hide();
    tip.textContent = text;
    tip.className = '';
    const r = el.getBoundingClientRect();
    const side = el.closest('#rail') ? 'right' : el.closest('.ch-hd, .dm-chat-hd') ? 'bottom' : 'top';
    tip.classList.add(side);
    const tw = tip.offsetWidth, th = tip.offsetHeight, gap = 12;
    let x, y;
    if (side === 'right')  { x = r.right + gap;                 y = r.top + r.height/2 - th/2; }
    if (side === 'top')    { x = r.left + r.width/2 - tw/2;      y = r.top - th - gap + 4; }
    if (side === 'bottom') { x = r.left + r.width/2 - tw/2;      y = r.bottom + gap - 4; }
    x = Math.max(8, Math.min(x, innerWidth - tw - 8));
    y = Math.max(8, Math.min(y, innerHeight - th - 8));
    tip.style.left = x + 'px'; tip.style.top = y + 'px';
    tip.classList.add('show');
    cur = el;
  }

  document.addEventListener('mouseover', e => {
    const el = e.target.closest?.('[title], [data-tip]');
    if (!el || !el.closest(SCOPE)) { if (cur) hide(); return; }
    if (el.hasAttribute('title')) { el.dataset.tip = el.getAttribute('title'); el.removeAttribute('title'); }
    if (el !== cur) show(el);
  });
  document.addEventListener('mouseout', e => { if (cur && !cur.contains(e.relatedTarget)) hide(); });
  document.addEventListener('mousedown', hide);
  document.addEventListener('scroll', hide, true);
})();
