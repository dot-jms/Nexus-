// ══════════════════════════════════════════════════════════════════
// PROFILE PAGE — view any user's profile
// ══════════════════════════════════════════════════════════════════
const profileCache = {}; // username → profile data

let _openProfileName = null;
function openProfilePage(username) {
  _openProfileName = username;
  const cached = profileCache[username];
  const data = (cached && cached.name) ? cached : buildLocalProfile(username);
  renderProfilePage(data);
  document.getElementById('profile-page').classList.add('open');
  // Show what we have instantly, then ask the server for the full, current profile (picture, bio,
  // "member since"): member lists and live updates don't carry all of it.
  if (username !== S.user?.name) requestProfileNow(username);
}

// ── public profiles on demand ──
// People whose avatar/profile we don't have (authors of old messages, people who left the server, ...) are
// requested once, in batches, so an avatar no longer depends on which server's member list is loaded.
const _profileAsked = new Set(), _profilePending = new Set(), _profileFull = new Set(); // _profileFull: names whose banner image is wanted too
let _profileTimer = null;
function _needProfile(name) {
  if (!name || _profileAsked.has(name) || name === S.user?.name) return;
  _profilePending.add(name);
  clearTimeout(_profileTimer); _profileTimer = setTimeout(flushProfileRequests, 150);
}
function flushProfileRequests() {
  if (!_profilePending.size || S.ws?.readyState !== 1) return; // retried when the connection (re)identifies
  const names = [..._profilePending].slice(0, 60);
  names.forEach(n => { _profilePending.delete(n); _profileAsked.add(n); });
  const full = names.filter(n => _profileFull.has(n)), rest = names.filter(n => !_profileFull.has(n));
  full.forEach(n => _profileFull.delete(n));
  if (rest.length) wsSend({ type: 'get_profiles', names: rest });
  for (let i = 0; i < full.length; i += 3) wsSend({ type: 'get_profiles', names: full.slice(i, i + 3), full: true });
  if (_profilePending.size) { clearTimeout(_profileTimer); _profileTimer = setTimeout(flushProfileRequests, 150); }
}
function requestProfileNow(name) { _profileAsked.delete(name); _profileFull.add(name); _profilePending.add(name); flushProfileRequests(); }
function applyProfiles(list) {
  let changed = false;
  (list || []).forEach(p => {
    if (!p?.name) return;
    profileCache[p.name] = { ...(profileCache[p.name] || {}), ...p };
    if (p.name === S.user?.name) { if (p.ext) S.user.ext = p.ext; if (p.bannerImg !== undefined && typeof peMyBanner !== 'undefined') peMyBanner = p.bannerImg; }
    Object.values(S.members || {}).forEach(arr => {
      const m = arr.find(x => x.name === p.name);
      if (m) Object.assign(m, { pfp: p.pfp, color: p.color, bio: p.bio, socials: p.socials, createdAt: p.createdAt });
    });
    const dm = S.dms.find(d => d.kind !== 'group' && dk(d.name) === dk(p.name)); if (dm) dm.pfp = p.pfp;
    changed = true;
  });
  if (!changed) return;
  refreshAvatars();
  try { pfDecorate(); } catch (_) {}
  if (S.curSv) renderMbs();
  dmProfilesUpdated();
  // an open profile page for one of them now gets the fresh data
  if (document.getElementById('profile-page')?.classList.contains('open') && _openProfileName) {
    const d = profileCache[_openProfileName]; if (d?.name) renderProfilePage(d);
  }
}
// Patch avatars already on screen from the cache, in place (a full re-render would jump the scroll position)
function refreshAvatars(onlyName) {
  document.querySelectorAll('#msgs .m-av[data-author]').forEach(el => {
    const a = el.dataset.author; if (onlyName && a !== onlyName) return;
    const isMe = a === S.user?.name, c = profileCache[a];
    const pfp = safeUrl(isMe ? (S.user.pfp || null) : (c && c.pfp !== undefined ? c.pfp : null));
    if (pfp) { el.style.background = 'transparent'; if (!el.querySelector('img') || el.querySelector('img').getAttribute('src') !== pfp) el.innerHTML = `<img src="${pfp}" alt="">`; }
    else if (isMe || (c && c.pfp === null)) { if (c?.color || isMe) el.style.background = (isMe ? S.user.color : c.color); el.innerHTML = `<span>${esc((a || '?')[0].toUpperCase())}</span>`; }
  });
}

function buildLocalProfile(username) {
  // Build from local state: server members, DM contacts, etc.
  const isSelf = username === S.user?.name;
  if (isSelf) return { name: S.user.name, tag: S.user.tag, color: S.user.color, pfp: S.user.pfp, bio: S.user.bio||'', socials: S.user.socials||{}, ext: S.user.ext, bannerImg: (typeof peMyBanner !== 'undefined' ? peMyBanner : null), systemRole: S.user.systemRole, coAdmin: S.user.coAdmin, createdAt: S.user.createdAt };
  // Check members list
  for (const svId in S.members) {
    const m = (S.members[svId]||[]).find(x=>x.name===username);
    if (m) return m;
  }
  // Check DM contacts
  const dm = S.dms.find(d=>d.kind!=='group' && dk(d.name)===dk(username));
  if (dm) return { name: dm.name, color: COLORS[hash(dm.name)%COLORS.length], pfp: dm.pfp, bio:'', socials:{} };
  return { name: username, color: COLORS[hash(username)%COLORS.length], pfp: null, bio:'', socials:{} };
}

function renderProfilePage(u) {
  const isSelf = u.name === S.user?.name;
  const isPuck = S.user?.systemRole === 'admin';
  // Banner gradient from user color
  const ext = pfNormExt(u.ext), bannerGrad = document.getElementById('pp-banner-grad');
  bannerGrad.style.background = '';
  document.getElementById('pp-banner').style.cssText = pfBannerCss(ext, u.color, u.bannerImg);
  const card = document.querySelector('#profile-page .profile-page-card'); if (card) card.style.cssText = pfCardCss(ext);
  // Avatar
  const avEl = document.getElementById('pp-av');
  avEl.style.background = safeUrl(u.pfp) ? 'transparent' : (u.color||COLORS[0]);
  avEl.innerHTML = safeUrl(u.pfp) ? `<img src="${safeUrl(u.pfp)}" style="width:100%;height:100%;object-fit:cover">` : esc(u.name[0]?.toUpperCase()||'?');
  const fr = pfFrameAttrs(ext, u.color || COLORS[0], pfCanStyle(u));
  avEl.className = ('pp-av ' + fr.cls).trim(); avEl.style.cssText += ';' + fr.style;
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
  const nameEl = document.getElementById('pp-name'), nf = pfNameAttrs(ext, pfCanStyle(u));
  nameEl.textContent = u.name; nameEl.className = ('pp-name ' + nf.cls).trim(); nameEl.style.cssText = nf.style;
  document.getElementById('pp-tag').textContent = '#' + (u.tag||'????');
  const meta = document.getElementById('pp-meta');
  if (meta) { meta.innerHTML = (ext.pronouns ? `<span>${esc(ext.pronouns)}</span>` : '') + (ext.location ? `<span>📍 ${esc(ext.location)}</span>` : ''); }
  const intSec = document.getElementById('pp-interests-section');
  if (intSec) { document.getElementById('pp-interests').innerHTML = ext.interests.map(t => `<span class="pp-chip">${esc(t)}</span>`).join(''); intSec.style.display = ext.interests.length ? '' : 'none'; }
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
  const soc = pfSocialLinks(u.socials).map(l => `<a class="pp-social" href="${esc(l.href)}" target="_blank" rel="noopener noreferrer">${l.icon} ${esc(l.text)}</a>`).join('');
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
  const f = e.target.files[0]; e.target.value = ''; if (f) pfpOpenFile(f, 'admin_target');
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
    const u = (profileCache[username]?.name ? profileCache[username] : null) || buildLocalProfile(username);
    if (_hoverPopup) _hoverPopup.remove();
    const popup = document.createElement('div');
    popup.className = 'user-hover-popup';
    popup.id = 'user-hover-popup';
    const color = u.color || COLORS[hash(username)%COLORS.length];
    const avContent = u.pfp ? `<img src="${u.pfp}">` : esc((username[0]||'?').toUpperCase());
    const avBg = u.pfp ? 'transparent' : color;
    const hx = pfNormExt(u.ext), hfr = pfFrameAttrs(hx, color, pfCanStyle(u)), hnf = pfNameAttrs(hx, pfCanStyle(u));
    if (!u.ext && !_profileAsked.has(username)) { _profileAsked.add(username); _profilePending.add(username); flushProfileRequests(); } // their style arrives for next time
    let badgesHtml = '';
    if (u.systemRole==='admin') badgesHtml += `<span class="pp-badge" style="font-size:9px;background:rgba(88,101,242,.2);color:var(--accent);border:1px solid rgba(88,101,242,.3)">⚡ Admin</span>`;
    if (u.coAdmin) badgesHtml += `<span class="pp-badge" style="font-size:9px;background:rgba(168,85,247,.2);color:#c084fc;border:1px solid rgba(168,85,247,.3)">⭐ Co-Admin</span>`;
    popup.innerHTML = `
      <div class="uhp-banner" style="${u.ext ? pfBannerCss(hx, color, null) : `background:linear-gradient(135deg,${color}cc,${color}33)`}">
        <div class="uhp-av ${hfr.cls}" style="background:${avBg};${hfr.style}">${avContent}</div>
      </div>
      <div class="uhp-body">
        <div class="uhp-name ${hnf.cls}" style="${hnf.style}">${esc(username)}</div>
        <div class="uhp-tag">#${esc(u.tag||'????')}${hx.pronouns ? ' · ' + esc(hx.pronouns) : ''}</div>
        ${badgesHtml ? `<div class="uhp-badges">${badgesHtml}</div>` : ''}
        ${u.bio ? `<div class="uhp-bio">${esc(u.bio)}</div>` : ''}
        <button class="uhp-view-btn" onclick="hideUserHover();openProfilePage('${esc(username)}')">View Profile →</button>
      </div>`;
    if (hx.cardTint) popup.style.cssText += ';' + pfCardCss(hx);
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
