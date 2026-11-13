// ── PROFILE EDIT ──
function buildProfileModal() {
  // no-op — profile modal is opened on demand via openProfileEdit()
}

function openProfileEdit() {
  const av = document.getElementById('profile-modal-av');
  av.style.background = S.user.color;
  if (S.user.pfp) av.innerHTML = `<img src="${S.user.pfp}" alt="pfp"><div class="av-overlay">Change</div>`;
  else { av.innerHTML = `${S.user.name[0].toUpperCase()}<div class="av-overlay">Change</div>`; }
  // All users can change their PFP
  av.style.cursor = 'pointer';
  av.onclick = () => document.getElementById('pfp-file-in').click();
  const lockNotice = document.getElementById('pfp-lock-notice');
  if (lockNotice) lockNotice.style.display = 'none';
  document.getElementById('profile-modal-name').textContent = S.user.name;
  document.getElementById('profile-modal-tag').textContent = '#' + S.user.tag;
  if (document.getElementById('profile-bio-in')) document.getElementById('profile-bio-in').value = S.user.bio||'';
  if (document.getElementById('profile-website-in')) document.getElementById('profile-website-in').value = S.user.socials?.website||'';
  if (document.getElementById('profile-twitter-in')) document.getElementById('profile-twitter-in').value = S.user.socials?.twitter||'';
  const grid = document.getElementById('profile-av-grid'); grid.innerHTML = '';
  COLORS.forEach(col => {
    const d = document.createElement('div');
    d.className = 'av-opt' + (col === S.user.color ? ' sel' : '');
    d.style.background = col; d.dataset.c = col;
    d.textContent = S.user.name[0].toUpperCase();
    d.onclick = () => { document.querySelectorAll('#profile-av-grid .av-opt').forEach(x => x.classList.remove('sel')); d.classList.add('sel'); };
    grid.appendChild(d);
  });
  openM('profile-edit-modal');
}

let pfpCropState = { x:0, y:0, zoom:1, src:null, dragging:false, startX:0, startY:0, startImgX:0, startImgY:0 };

function onPfpChange(e) {
  const f = e.target.files[0]; if (!f) return;
  e.target.value = '';
  const reader = new FileReader();
  reader.onload = ev => {
    _pfpCropTarget = 'profile';
    pfpCropState = { x:0, y:0, zoom:1, src:ev.target.result, dragging:false };
    const img = document.getElementById('pfp-crop-img');
    img.src = ev.target.result;
    document.getElementById('pfp-crop-zoom').value = 1;
    img.onload = () => { pfpCropApply(); };
    openM('pfp-crop-modal');
    setTimeout(initCropEvents, 50);
  };
  reader.readAsDataURL(f);
}

function pfpCropApply() {
  const wrap = document.getElementById('pfp-crop-wrap');
  const img = document.getElementById('pfp-crop-img');
  const z = pfpCropState.zoom;
  const ww = wrap.offsetWidth, wh = wrap.offsetHeight;
  const iw = img.naturalWidth * z, ih = img.naturalHeight * z;
  // Clamp position
  pfpCropState.x = Math.min(0, Math.max(ww - iw, pfpCropState.x));
  pfpCropState.y = Math.min(0, Math.max(wh - ih, pfpCropState.y));
  img.style.width = iw + 'px'; img.style.height = ih + 'px';
  img.style.left = pfpCropState.x + 'px'; img.style.top = pfpCropState.y + 'px';
  img.style.transform = '';
}

function pfpCropZoom(val) {
  pfpCropState.zoom = parseFloat(val);
  pfpCropApply();
}

// Drag to reposition — initialized once when first needed
let _cropEventsInit = false;
function initCropEvents() {
  if (_cropEventsInit) return;
  _cropEventsInit = true;
  let drag = false, sx = 0, sy = 0, ox = 0, oy = 0;
  function start(ex, ey) { drag = true; sx = ex; sy = ey; ox = pfpCropState.x; oy = pfpCropState.y; }
  function move(ex, ey) {
    if (!drag) return;
    pfpCropState.x = ox + (ex - sx); pfpCropState.y = oy + (ey - sy);
    pfpCropApply();
  }
  function end() { drag = false; }
  const w = document.getElementById('pfp-crop-wrap');
  w.addEventListener('mousedown', e => { e.preventDefault(); start(e.clientX, e.clientY); });
  window.addEventListener('mousemove', e => move(e.clientX, e.clientY));
  window.addEventListener('mouseup', end);
  w.addEventListener('touchstart', e => { e.preventDefault(); start(e.touches[0].clientX, e.touches[0].clientY); }, {passive:false});
  window.addEventListener('touchmove', e => { if(drag) { e.preventDefault(); move(e.touches[0].clientX, e.touches[0].clientY); }}, {passive:false});
  window.addEventListener('touchend', end);
  w.addEventListener('wheel', e => {
    e.preventDefault();
    const slider = document.getElementById('pfp-crop-zoom');
    const newVal = Math.min(4, Math.max(1, pfpCropState.zoom - e.deltaY * 0.002));
    pfpCropState.zoom = newVal; slider.value = newVal; pfpCropApply();
  }, {passive:false});
}

async function commitPfpCrop() {
  const canvas = document.createElement('canvas');
  const size = 256; canvas.width = size; canvas.height = size;
  const ctx = canvas.getContext('2d');
  const img = document.getElementById('pfp-crop-img');
  const wrap = document.getElementById('pfp-crop-wrap');
  const ww = wrap.offsetWidth, wh = wrap.offsetHeight;
  const z = pfpCropState.zoom;
  // Correct: pixels in natural image covered by the 300px circle at this zoom
  const natW = img.naturalWidth, natH = img.naturalHeight;
  const clipX = Math.max(0, -pfpCropState.x / z);
  const clipY = Math.max(0, -pfpCropState.y / z);
  const clipW = Math.min(natW - clipX, ww / z);
  const clipH = Math.min(natH - clipY, wh / z);
  ctx.drawImage(img, clipX, clipY, clipW, clipH, 0, 0, size, size);
  // Re-encode at pfp quality limit (0.80) — the raw 256px canvas at 0.88 can still
  // be ~120–180 KB from a high-detail source image. compressImage also enforces the
  // 150 KB hard cap with a retry at half-quality.
  let data;
  try {
    data = await compressImage(canvas.toDataURL('image/jpeg', 1.0), IMG_LIMITS.pfp);
  } catch(err) {
    toast('⚠️ PFP image is too complex to compress within limits. Try a simpler image.');
    return;
  }

  if (_pfpCropTarget === 'signup') {
    suPfpData = data;
    const p = document.getElementById('su-pfp-preview');
    p.innerHTML = `<img src="${suPfpData}" alt="pfp">`;
  } else if (_pfpCropTarget === 'admin_target' && _adminPfpTarget) {
    wsSend({ type: 'admin_set_pfp', target: _adminPfpTarget, pfp: data });
    document.getElementById('admin-users-result').textContent = `✅ PFP updated for ${_adminPfpTarget}`;
    _adminPfpTarget = null;
  } else {
    // 'profile' — set pending pfp on edit modal
    const av = document.getElementById('profile-modal-av');
    av.innerHTML = `<img src="${data}" alt="pfp"><div class="av-overlay">Change</div>`;
    av._pendingPfp = data;
  }
  closeM('pfp-crop-modal');
}

function saveProfile() {
  const selColor = document.querySelector('#profile-av-grid .av-opt.sel')?.dataset.c || S.user.color;
  const av = document.getElementById('profile-modal-av');
  // Any user can update their own PFP
  const newPfp = av._pendingPfp ? av._pendingPfp : S.user.pfp;
  const bio = (document.getElementById('profile-bio-in')?.value||'').slice(0,160);
  const website = document.getElementById('profile-website-in')?.value.trim()||'';
  const twitter = document.getElementById('profile-twitter-in')?.value.trim().replace('@','')||'';
  S.user.color = selColor; S.user.pfp = newPfp||null;
  S.user.bio = bio; S.user.socials = {website, twitter};
  lsSet('nx-session', {token:S.token, user:S.user}); persist();
  updateUser(); closeM('profile-edit-modal'); toast('✅ Profile updated');
  Object.values(S.messages).forEach(arr => {
    arr.forEach(m => { if(m.author===S.user.name){m.authorColor=S.user.color;m.authorPfp=S.user.pfp||null;} });
  });
  Object.values(S.dmMessages).forEach(arr => {
    arr.forEach(m => { if(m.author===S.user.name){m.authorColor=S.user.color;m.authorPfp=S.user.pfp||null;} });
  });
  if (S.curCh) renderMsgs(S.curCh.id);
  if (curDM) renderDMMessages(curDM);
  wsSend({type:'profile_update', user:S.user.name, color:S.user.color, pfp:S.user.pfp||null, bio, socials:{website,twitter}});
}
