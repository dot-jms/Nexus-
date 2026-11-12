// ══════════════════════════════════════════════════════════════════
// PROFILE PAGE — view any user's profile
// ══════════════════════════════════════════════════════════════════
const profileCache = {}; // username → profile data

function openProfilePage(username) {
  const data = profileCache[username] || buildLocalProfile(username);
  renderProfilePage(data);
  document.getElementById('profile-page').classList.add('open');
}

function buildLocalProfile(username) {
  // Build from local state: server members, DM contacts, etc.
  const isSelf = username === S.user?.name;
  if (isSelf) return { name: S.user.name, tag: S.user.tag, color: S.user.color, pfp: S.user.pfp, bio: S.user.bio||'', socials: S.user.socials||{}, systemRole: S.user.systemRole, coAdmin: S.user.coAdmin };
  // Check members list
  for (const svId in S.members) {
    const m = (S.members[svId]||[]).find(x=>x.name===username);
    if (m) return m;
  }
  // Check DM contacts
  const dm = S.dms.find(d=>d.name===username);
  if (dm) return { name: dm.name, color: COLORS[hash(dm.name)%COLORS.length], pfp: dm.pfp, bio:'', socials:{} };
  return { name: username, color: COLORS[hash(username)%COLORS.length], pfp: null, bio:'', socials:{} };
}

function renderProfilePage(u) {
  const isSelf = u.name === S.user?.name;
  const isPuck = S.user?.systemRole === 'admin';
  // Banner gradient from user color
  const bannerGrad = document.getElementById('pp-banner-grad');
  bannerGrad.style.background = `linear-gradient(160deg, ${u.color||'#5865f2'}cc 0%, ${u.color||'#5865f2'}22 100%)`;
  document.getElementById('pp-banner').style.background = `${u.color||'#5865f2'}33`;
  // Avatar
  const avEl = document.getElementById('pp-av');
  avEl.style.background = u.pfp ? 'transparent' : (u.color||COLORS[0]);
  avEl.innerHTML = u.pfp ? `<img src="${u.pfp}" style="width:100%;height:100%;object-fit:cover">` : esc(u.name[0]?.toUpperCase()||'?');
  // Edit/admin button area
  const editBtn = document.getElementById('pp-edit-btn');
  if (isSelf) {
    editBtn.innerHTML = `<button class="btn-g" style="font-size:12px;padding:7px 14px" onclick="closeProfilePage();openProfileEdit()">✏️ Edit Profile</button>`;
  } else if (isPuck) {
    // Puck can edit anyone's username and PFP from their profile
    editBtn.innerHTML = `
      <div style="display:flex;gap:6px">
        <button class="btn-g" style="font-size:11px;padding:6px 10px" onclick="puckEditUsername('${esc(u.name)}')">✏️ Username</button>
        <button class="btn-g" style="font-size:11px;padding:6px 10px" onclick="puckEditPfp('${esc(u.name)}')">🖼 PFP</button>
      </div>`;
  } else {
    editBtn.innerHTML = '';
  }
  // Name / tag
  document.getElementById('pp-name').textContent = u.name;
  document.getElementById('pp-tag').textContent = '#' + (u.tag||'????');
  // Badges
  let badgeHtml = '';
  if (u.systemRole==='admin') badgeHtml += `<span class="pp-badge" style="background:rgba(88,101,242,.2);color:var(--accent);border:1px solid rgba(88,101,242,.3)">⚡ Admin</span>`;
  if (u.coAdmin) badgeHtml += `<span class="pp-badge" style="background:rgba(168,85,247,.2);color:#c084fc;border:1px solid rgba(168,85,247,.3)">⭐ Co-Admin</span>`;
  if (isSelf) badgeHtml += `<span class="pp-badge" style="background:rgba(52,211,153,.12);color:var(--green);border:1px solid rgba(52,211,153,.2)">You</span>`;
  document.getElementById('pp-badges').innerHTML = badgeHtml;
  // Bio section
  const bioSection = document.getElementById('pp-bio-section');
  if (u.bio) { document.getElementById('pp-bio').textContent = u.bio; bioSection.style.display = ''; }
  else bioSection.style.display = 'none';
  // Socials section
  const socSection = document.getElementById('pp-socials-section');
  let soc = '';
  if (u.socials?.website) soc += `<a class="pp-social" href="${esc(u.socials.website)}" target="_blank" rel="noopener">🌐 ${esc(u.socials.website.replace(/^https?:\/\//,''))}</a>`;
  if (u.socials?.twitter) soc += `<a class="pp-social" href="https://twitter.com/${esc(u.socials.twitter)}" target="_blank" rel="noopener">𝕏 @${esc(u.socials.twitter)}</a>`;
  if (soc) { document.getElementById('pp-socials').innerHTML = soc; socSection.style.display = ''; }
  else socSection.style.display = 'none';
  // Member since
  const joined = document.getElementById('pp-joined');
  if (joined) joined.textContent = u.createdAt ? new Date(u.createdAt).toLocaleDateString('en-US',{month:'long',year:'numeric'}) : 'Nexus Member';
  // Action buttons
  const actEl = document.getElementById('pp-actions');
  if (isSelf) {
    actEl.innerHTML = '';
    actEl.style.display = 'none';
  } else {
    actEl.style.display = 'flex';
    const isFriend = S.friends.find(f=>f.name===u.name);
    actEl.innerHTML = `
      <button class="btn-p" style="flex:1" onclick="closeProfilePage();ppDM('${esc(u.name)}')">💬 Message</button>
      ${!isFriend ? `<button class="btn-g" onclick="closeProfilePage();ppAddFriend('${esc(u.name)}')">+ Friend</button>` : `<button class="btn-g" style="color:var(--green);cursor:default">✓ Friends</button>`}
      <button class="btn-g" style="color:var(--accent)" onclick="closeProfilePage();ppCall('${esc(u.name)}')">📞 Call</button>
    `;
  }
}

function closeProfilePage() {
  document.getElementById('profile-page').classList.remove('open');
}

// Admin-only: Puck can rename any user
function puckEditUsername(targetName) {
  closeProfilePage();
  const newName = prompt(`New username for ${targetName}:`, targetName);
  if (!newName || newName === targetName) return;
  if (!/^[a-zA-Z0-9_.\-]{2,24}$/.test(newName)) { toast('⚠️ Invalid username format'); return; }
  wsSend({ type: 'admin_rename_user', target: targetName, newName });
  toast('⏳ Renaming...');
}

// Admin-only: Puck can set PFP for any user
function puckEditPfp(targetName) {
  closeProfilePage();
  _pfpCropTarget = 'admin_target';
  _adminPfpTarget = targetName;
  document.getElementById('admin-pfp-file').click();
}

function onAdminPfpChange(e) {
  const f = e.target.files[0]; if (!f) return;
  e.target.value = '';
  const reader = new FileReader();
  reader.onload = ev => {
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

// Admin panel: rename via input field
function adminRenameUser() {
  const target = document.getElementById('admin-user-in').value.trim();
  if (!target) { _adminResult('Enter a username.', 'var(--red)'); return; }
  const newName = prompt(`New username for ${target}:`);
  if (!newName || newName === target) return;
  if (!/^[a-zA-Z0-9_.\-]{2,24}$/.test(newName)) { _adminResult('⚠️ Invalid username format.', 'var(--red)'); return; }
  wsSend({ type: 'admin_rename_user', target, newName });
  _adminResult('⏳ Sending rename request…');
}

// Admin panel: set PFP via input field
function adminSetPfp() {
  const target = document.getElementById('admin-user-in').value.trim();
  if (!target) { _adminResult('Enter a username first.', 'var(--red)'); return; }
  _pfpCropTarget = 'admin_target';
  _adminPfpTarget = target;
  document.getElementById('admin-pfp-file').click();
}

// ── HOVER USER POPUPS ──
let _hoverTimer = null;
let _hoverPopup = null;

function showUserHover(username, anchorEl) {
  clearTimeout(_hoverTimer);
  _hoverTimer = setTimeout(() => {
    const u = profileCache[username] || buildLocalProfile(username);
    if (_hoverPopup) _hoverPopup.remove();
    const popup = document.createElement('div');
    popup.className = 'user-hover-popup';
    popup.id = 'user-hover-popup';
    const color = u.color || COLORS[hash(username)%COLORS.length];
    const avContent = u.pfp ? `<img src="${u.pfp}">` : esc((username[0]||'?').toUpperCase());
    const avBg = u.pfp ? 'transparent' : color;
    let badgesHtml = '';
    if (u.systemRole==='admin') badgesHtml += `<span class="pp-badge" style="font-size:9px;background:rgba(88,101,242,.2);color:var(--accent);border:1px solid rgba(88,101,242,.3)">⚡ Admin</span>`;
    if (u.coAdmin) badgesHtml += `<span class="pp-badge" style="font-size:9px;background:rgba(168,85,247,.2);color:#c084fc;border:1px solid rgba(168,85,247,.3)">⭐ Co-Admin</span>`;
    popup.innerHTML = `
      <div class="uhp-banner" style="background:linear-gradient(135deg,${color}cc,${color}33)">
        <div class="uhp-av" style="background:${avBg}">${avContent}</div>
      </div>
      <div class="uhp-body">
        <div class="uhp-name">${esc(username)}</div>
        <div class="uhp-tag">#${esc(u.tag||'????')}</div>
        ${badgesHtml ? `<div class="uhp-badges">${badgesHtml}</div>` : ''}
        ${u.bio ? `<div class="uhp-bio">${esc(u.bio)}</div>` : ''}
        <button class="uhp-view-btn" onclick="hideUserHover();openProfilePage('${esc(username)}')">View Profile →</button>
      </div>`;
    document.body.appendChild(popup);
    _hoverPopup = popup;
    // Position near anchor
    const rect = anchorEl.getBoundingClientRect();
    let top = rect.bottom + 6;
    let left = rect.left;
    if (left + 260 > window.innerWidth - 10) left = window.innerWidth - 270;
    if (top + 220 > window.innerHeight - 10) top = rect.top - 226;
    popup.style.top = top + 'px';
    popup.style.left = left + 'px';
    requestAnimationFrame(() => popup.classList.add('show'));
    popup.addEventListener('mouseleave', hideUserHover);
  }, 500);
}

function hideUserHover() {
  clearTimeout(_hoverTimer);
  if (_hoverPopup) {
    _hoverPopup.classList.remove('show');
    const p = _hoverPopup;
    setTimeout(() => { if(p.parentNode) p.remove(); }, 160);
    _hoverPopup = null;
  }
}
