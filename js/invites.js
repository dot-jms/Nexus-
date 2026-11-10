// ══════════════════════════════════
// INVITE LINKS
// ══════════════════════════════════
function showInviteModal() {
  if (!S.curSv) return;
  document.getElementById('invite-sv-name').textContent = S.curSv.name;
  // Encode server info into a URL hash invite link
  const inviteData = btoa(JSON.stringify({ id: S.curSv.id, name: S.curSv.name }));
  const link = window.location.href.split('#')[0] + '#invite=' + inviteData;
  document.getElementById('invite-link-box').textContent = link;
  openM('invite-modal');
}

function copyInviteLink() {
  const txt = document.getElementById('invite-link-box').textContent;
  navigator.clipboard.writeText(txt).then(() => toast('📋 Copied!')).catch(() => toast('Select and copy manually'));
}

function checkInviteHash() {
  const hash = window.location.hash;
  if (!hash.startsWith('#invite=')) return;
  try {
    const data = JSON.parse(atob(hash.slice(8)));
    window.location.hash = '';
    if (!data.id || !data.name) return;
    if (S.servers.find(s => s.id === data.id)) { toast('Already in ' + data.name); return; }
    // Queue a join after login
    S._pendingInvite = data;
    toast('🔗 Invite link detected for "' + data.name + '"! Join from Discover.');
  } catch(e) {}
}
