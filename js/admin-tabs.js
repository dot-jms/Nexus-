// ── Admin broadcast alert ──
function adminSendAlert() {
  if (S.user?.systemRole !== 'admin') return;
  const title = document.getElementById('admin-alert-title').value.trim();
  const body = document.getElementById('admin-alert-body').value.trim();
  const resEl = document.getElementById('admin-alert-result');
  if (!title) { resEl.textContent = '⚠️ Add a title.'; return; }
  if (!body) { resEl.textContent = '⚠️ Add a message body.'; return; }
  wsSend({ type: 'platform_alert', title, body });
  resEl.textContent = '✅ Alert sent to everyone!';
  document.getElementById('admin-alert-title').value = '';
  document.getElementById('admin-alert-body').value = '';
}

// ── NEW ADMIN FUNCTIONS ──────────────────────────────────────────────────────

function _adminResult(text, color) {
  const el = document.getElementById('admin-users-result');
  if (el) { el.textContent = text; el.style.color = color || 'var(--t3)'; }
}
function _adminMsgResult(text, color) {
  const el = document.getElementById('admin-msgs-result');
  if (el) { el.textContent = text; el.style.color = color || 'var(--t3)'; }
}
function _adminSvResult(text, color) {
  const el = document.getElementById('admin-sv-result');
  if (el) { el.textContent = text; el.style.color = color || 'var(--t3)'; }
}

// ── Users tab ─────────────────────────────────────────────────────────────────
function adminPickColor() {
  const target = document.getElementById('admin-user-in').value.trim();
  if (!target) { _adminResult('Enter a username first.', 'var(--red)'); return; }
  document.getElementById('admin-color-pick').click();
}
function adminApplyColor(hex) {
  const target = document.getElementById('admin-user-in').value.trim();
  if (!target) return;
  wsSend({ type: 'admin_set_color', target, color: hex });
  _adminResult(`⏳ Setting color for ${target}…`);
}
function adminResetPassword() {
  const target = document.getElementById('admin-user-in').value.trim();
  if (!target) { _adminResult('Enter a username first.', 'var(--red)'); return; }
  const newPw = prompt(`New password for ${target} (min 4 chars):`);
  if (!newPw) return;
  if (newPw.length < 4) { _adminResult('⚠️ Password must be at least 4 characters.', 'var(--red)'); return; }
  if (!confirm(`Reset password for ${target}?`)) return;
  wsSend({ type: 'admin_reset_password', target, newPassword: newPw });
  _adminResult(`⏳ Resetting password for ${target}…`);
}
function adminForceLogout() {
  const target = document.getElementById('admin-user-in').value.trim();
  if (!target) { _adminResult('Enter a username first.', 'var(--red)'); return; }
  if (!confirm(`Force logout ${target}? Their sessions will be invalidated immediately.`)) return;
  wsSend({ type: 'admin_force_logout', target });
  _adminResult(`⏳ Force-logging out ${target}…`);
}
function adminFreezeUser() {
  const target = document.getElementById('admin-user-in').value.trim();
  if (!target) { _adminResult('Enter a username first.', 'var(--red)'); return; }
  const reason = prompt(`Reason for freezing ${target} (they can still connect but can't send messages):`);
  if (reason === null) return;
  wsSend({ type: 'admin_freeze_user', target, reason: reason || 'No reason given' });
  _adminResult(`⏳ Freezing ${target}…`);
}
function adminUnfreezeUser() {
  const target = document.getElementById('admin-user-in').value.trim();
  if (!target) { _adminResult('Enter a username first.', 'var(--red)'); return; }
  wsSend({ type: 'admin_unfreeze_user', target });
  _adminResult(`⏳ Unfreezing ${target}…`);
}
function adminSetBio() {
  const target = document.getElementById('admin-user-in').value.trim();
  if (!target) { _adminResult('Enter a username first.', 'var(--red)'); return; }
  const bio = prompt(`New bio for ${target} (leave blank to clear):`);
  if (bio === null) return;
  wsSend({ type: 'admin_set_bio', target, bio });
  _adminResult(`⏳ Setting bio for ${target}…`);
}
function adminWipeUserPfp() {
  const target = document.getElementById('admin-user-in').value.trim();
  if (!target) { _adminResult('Enter a username first.', 'var(--red)'); return; }
  if (!confirm(`Wipe PFP for ${target}?`)) return;
  wsSend({ type: 'admin_wipe_user_pfp', target });
  _adminResult(`⏳ Wiping PFP for ${target}…`);
}
function adminKickFromServer() {
  const target = document.getElementById('admin-user-in').value.trim();
  const serverId = document.getElementById('admin-server-id-in').value.trim();
  if (!target) { _adminResult('Enter a username first.', 'var(--red)'); return; }
  if (!serverId) { _adminResult('Enter a Server ID.', 'var(--red)'); return; }
  if (!confirm(`Kick ${target} from server ${serverId}?`)) return;
  wsSend({ type: 'admin_kick_from_server', target, serverId });
  _adminResult(`⏳ Kicking ${target}…`);
}
function adminAddMember() {
  const target = document.getElementById('admin-user-in').value.trim();
  const serverId = document.getElementById('admin-server-id-in').value.trim();
  if (!target) { _adminResult('Enter a username first.', 'var(--red)'); return; }
  if (!serverId) { _adminResult('Enter a Server ID.', 'var(--red)'); return; }
  wsSend({ type: 'admin_add_member', target, serverId });
  _adminResult(`⏳ Adding ${target} to server…`);
}
function adminSendSystemDM() {
  const target = document.getElementById('admin-user-in').value.trim();
  const text   = document.getElementById('admin-sysdm-text').value.trim();
  if (!target) { _adminResult('Enter a username first.', 'var(--red)'); return; }
  if (!text)   { _adminResult('Enter a message.', 'var(--red)'); return; }
  wsSend({ type: 'admin_broadcast_dm', target, text });
  document.getElementById('admin-sysdm-text').value = '';
  _adminResult(`✅ System DM sent to ${target}.`, 'var(--green)');
}

// ── Servers tab ───────────────────────────────────────────────────────────────
let _adminServers = [];
function adminLoadServers() {
  const box = document.getElementById('admin-sv-list');
  if (box) box.innerHTML = '<div style="font-size:12px;color:var(--t3);padding:8px 0">Loading…</div>';
  wsSend({ type: 'admin_list_servers' });
}
function adminFilterServers() {
  const q = (document.getElementById('admin-sv-search')?.value || '').toLowerCase();
  const filtered = q ? _adminServers.filter(s =>
    s.name.toLowerCase().includes(q) || (s.ownerId||'').toLowerCase().includes(q)
  ) : _adminServers;
  renderAdminServers(filtered);
}
function renderAdminServers(servers) {
  const box = document.getElementById('admin-sv-list');
  if (!box) return;
  if (!servers.length) { box.innerHTML = '<div style="font-size:12px;color:var(--t3);padding:8px 0">No servers found.</div>'; return; }
  box.innerHTML = servers.map(s => {
    const created = s.createdAt ? new Date(s.createdAt).toLocaleDateString('en',{month:'short',day:'numeric',year:'numeric'}) : '?';
    return `<div style="background:var(--s3);border:1px solid var(--border);border-radius:8px;padding:10px 12px">
      <div style="display:flex;align-items:center;justify-content:space-between;gap:8px">
        <div style="flex:1;min-width:0">
          <div style="font-size:13px;font-weight:700;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${esc(s.name)}</div>
          <div style="font-size:10px;color:var(--t3);font-family:'DM Mono',monospace;margin-top:1px;cursor:pointer" onclick="document.getElementById('admin-edit-sv-id').value='${esc(s.id)}';navigator.clipboard?.writeText('${esc(s.id)}').then(()=>toast('Server ID copied + filled in Edit panel!'))" title="Click to copy and fill Edit panel">${esc(s.id)} 📋</div>
          <div style="font-size:10px;color:var(--t3);margin-top:2px">Owner: <strong>${esc(s.ownerId||'?')}</strong> · ${s.memberCount||0} members · ${s.channelCount||0} channels · ${created}</div>
        </div>
        <div style="display:flex;gap:4px;flex-shrink:0;flex-wrap:wrap;justify-content:flex-end">
          <button class="btn-g" style="font-size:10px;padding:3px 7px" onclick="adminTransferOwnership('${esc(s.id)}')">↗ Transfer</button>
          <button class="btn-g" style="font-size:10px;padding:3px 7px;color:var(--red)" onclick="adminForceDeleteServer('${esc(s.id)}')">🗑 Delete</button>
        </div>
      </div>
    </div>`;
  }).join('');
}
function adminTransferOwnership(serverId) {
  const newOwner = prompt('Transfer ownership to (username):');
  if (!newOwner) return;
  if (!confirm(`Transfer server ${serverId} to ${newOwner}?`)) return;
  wsSend({ type: 'admin_transfer_ownership', serverId, newOwner });
}
function adminAddChannel() {
  // Legacy — now handled by adminAddChannelFromEdit
  adminAddChannelFromEdit();
}
function adminAddChannelFromEdit() {
  const svId = document.getElementById('admin-edit-sv-id').value.trim();
  const name = document.getElementById('admin-ac-name').value.trim();
  const chType = document.getElementById('admin-ac-type').value;
  if (!svId) { _adminSvResult('Paste a Server ID in the Edit panel above.', 'var(--red)'); return; }
  if (!name) { _adminSvResult('Enter a channel name.', 'var(--red)'); return; }
  wsSend({ type: 'admin_add_channel', serverId: svId, name, chType });
  _adminSvResult(`⏳ Adding #${name}…`);
}
function adminDeleteChannel() {
  adminDeleteChannelFromEdit();
}
function adminDeleteChannelFromEdit() {
  const svId = document.getElementById('admin-edit-sv-id').value.trim();
  const chId = document.getElementById('admin-dc-chid').value.trim();
  if (!svId) { _adminSvResult('Paste a Server ID in the Edit panel above.', 'var(--red)'); return; }
  if (!chId) { _adminSvResult('Enter a Channel ID to delete.', 'var(--red)'); return; }
  if (!confirm(`Delete channel ${chId} from server ${svId}? All history will be wiped.`)) return;
  wsSend({ type: 'admin_delete_channel', serverId: svId, channelId: chId });
  _adminSvResult(`⏳ Deleting channel…`);
}
// adminEditMessage — uses separate ch/id fields (kept for compatibility)
function adminEditMessage() {
  const chId  = document.getElementById('admin-edit-msg-ch')?.value?.trim() || document.getElementById('admin-del-msg-ch').value.trim();
  const msgId = document.getElementById('admin-edit-msg-id')?.value?.trim() || document.getElementById('admin-del-msg-id').value.trim();
  const text  = document.getElementById('admin-edit-msg-text').value.trim();
  if (!chId || !msgId || !text) { _adminMsgResult('Channel ID, Message ID, and new text are required.', 'var(--red)'); return; }
  wsSend({ type: 'admin_edit_message', channelId: chId, messageId: msgId, text });
  _adminMsgResult('⏳ Editing message…');
}
// New consolidated version — reuses the delete fields so users only fill IDs once
function adminEditMsgFromFields() {
  const chId  = document.getElementById('admin-del-msg-ch').value.trim();
  const msgId = document.getElementById('admin-del-msg-id').value.trim();
  const text  = document.getElementById('admin-edit-msg-text').value.trim();
  if (!chId || !msgId) { _adminMsgResult('Enter Channel ID and Message ID above.', 'var(--red)'); return; }
  if (!text) { _adminMsgResult('Enter replacement text.', 'var(--red)'); return; }
  wsSend({ type: 'admin_edit_message', channelId: chId, messageId: msgId, text });
  _adminMsgResult('⏳ Editing message…');
}
function adminRenameServer() {
  const svId = document.getElementById('admin-edit-sv-id').value.trim();
  const name = document.getElementById('admin-rn-name').value.trim();
  if (!svId || !name) { _adminSvResult('Server ID and new name required.', 'var(--red)'); return; }
  wsSend({ type: 'admin_rename_server', serverId: svId, name });
  _adminSvResult(`⏳ Renaming server…`);
}

// ── New admin functions added in latest expansion ────────────────────────────

function adminSetUserTag() {
  const target = document.getElementById('admin-user-in').value.trim();
  if (!target) { _adminResult('Enter a username first.', 'var(--red)'); return; }
  const tag = prompt(`New 4-digit tag for ${target} (e.g. 1337):`);
  if (tag === null) return;
  if (!/^\d{4}$/.test(tag)) { _adminResult('⚠️ Tag must be exactly 4 digits.', 'var(--red)'); return; }
  wsSend({ type: 'admin_set_tag', target, tag });
  _adminResult(`⏳ Setting tag for ${target}…`);
}

function adminImpersonateSend() {
  const target = document.getElementById('admin-user-in').value.trim();
  const chId   = document.getElementById('admin-imp-ch').value.trim();
  const text   = document.getElementById('admin-sysdm-text').value.trim();
  if (!target) { _adminResult('Enter a username first.', 'var(--red)'); return; }
  if (!chId)   { _adminResult('Enter a Channel ID in the impersonate field.', 'var(--red)'); return; }
  if (!text)   { _adminResult('Enter message text in the System DM textarea.', 'var(--red)'); return; }
  if (!confirm(`Post as ${target} in channel ${chId}?\n\n"${text.slice(0,100)}"`)) return;
  wsSend({ type: 'admin_impersonate_send', asUser: target, channelId: chId, text });
  _adminResult(`⏳ Posting as ${target}…`);
}

function adminViewUserServers() {
  const target = document.getElementById('admin-user-in').value.trim();
  if (!target) { _adminResult('Enter a username first.', 'var(--red)'); return; }
  wsSend({ type: 'admin_list_user_servers', target });
  _adminResult(`⏳ Loading servers for ${target}…`);
}
function renderAdminUserServers(target, servers) {
  const box = document.getElementById('admin-notes-display');
  if (!box) return;
  if (!servers.length) {
    box.innerHTML = `<div style="font-size:11px;color:var(--t3)">${esc(target)} is not in any servers.</div>`;
    return;
  }
  box.innerHTML = `<div style="font-size:10px;font-weight:700;color:var(--t3);text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px">${esc(target)}'s Servers (${servers.length})</div>` +
    servers.map(s =>
      `<div style="background:var(--s3);border:1px solid var(--border);border-radius:6px;padding:6px 9px;font-size:11px;display:flex;align-items:center;justify-content:space-between;gap:6px">
        <div><strong>${esc(s.name)}</strong><span style="font-size:10px;color:var(--t3);margin-left:6px;font-family:'DM Mono',monospace;cursor:pointer" onclick="navigator.clipboard?.writeText('${esc(s.id)}');toast('ID copied!')">${esc(s.id)}</span></div>
        <span style="font-size:10px;color:var(--t3)">${esc(s.ownerId||'?')}</span>
      </div>`
    ).join('');
}

function adminGetNotes() {
  const target = document.getElementById('admin-user-in').value.trim();
  if (!target) { _adminResult('Enter a username first.', 'var(--red)'); return; }
  wsSend({ type: 'admin_get_notes', target });
  _adminResult(`⏳ Loading notes for ${target}…`);
}
function adminAddNote() {
  const target = document.getElementById('admin-user-in').value.trim();
  const note   = document.getElementById('admin-note-text').value.trim();
  if (!target) { _adminResult('Enter a username first.', 'var(--red)'); return; }
  if (!note)   { _adminResult('Enter a note.', 'var(--red)'); return; }
  wsSend({ type: 'admin_add_note', target, note });
  document.getElementById('admin-note-text').value = '';
  _adminResult(`⏳ Saving note for ${target}…`);
}
function renderAdminNotes(target, notes) {
  const box = document.getElementById('admin-notes-display');
  if (!box) return;
  if (!notes.length) {
    box.innerHTML = `<div style="font-size:11px;color:var(--t3)">No notes for ${esc(target)}.</div>`;
    return;
  }
  box.innerHTML = `<div style="font-size:10px;font-weight:700;color:var(--t3);text-transform:uppercase;letter-spacing:.08em;margin-bottom:5px">Notes for ${esc(target)}</div>` +
    notes.map((n, i) => {
      const ts = n.at ? new Date(n.at).toLocaleString('en',{month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'}) : '?';
      return `<div style="background:rgba(251,146,60,.07);border:1px solid rgba(251,146,60,.2);border-radius:6px;padding:7px 9px;font-size:11px">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:3px">
          <span style="font-size:10px;color:var(--t3)">by ${esc(n.by||'?')} · ${ts}</span>
          <button class="btn-g" style="font-size:9px;padding:2px 6px;color:var(--red)" onclick="adminDeleteNote('${esc(target)}',${i})">✕</button>
        </div>
        <div>${esc(n.text||'')}</div>
      </div>`;
    }).join('');
}
function adminDeleteNote(target, index) {
  if (!confirm('Delete this note?')) return;
  wsSend({ type: 'admin_delete_note', target, index });
}

// ── Danger tab ────────────────────────────────────────────────────────────────
function adminNukeAccount() {
  const target = document.getElementById('admin-nuke-user').value.trim();
  if (!target) { toast('⚠️ Enter a username to nuke.'); return; }
  if (target.toLowerCase() === 'puck') { toast('⚠️ Cannot nuke Puck.'); return; }
  const conf = prompt(`Type DELETE to permanently nuke account '${target}'. THIS CANNOT BE UNDONE.`);
  if (conf !== 'DELETE') { toast('Nuke cancelled.'); return; }
  wsSend({ type: 'admin_nuke_account', target });
  toast(`💥 Nuking ${target}…`);
}

function adminSetMaintenance(enabled) {
  const badge = document.getElementById('admin-maint-badge');
  if (enabled) {
    if (!confirm('Enable maintenance mode? ALL non-admin users will be kicked immediately and cannot reconnect.')) return;
    if (badge) badge.style.display = 'inline-block';
  } else {
    if (badge) badge.style.display = 'none';
  }
  wsSend({ type: 'admin_set_maintenance', enabled });
  toast(enabled ? '⏳ Enabling maintenance mode…' : '⏳ Disabling maintenance mode…');
}

// ── Alert tab ─────────────────────────────────────────────────────────────────
function adminSendAnnouncement() {
  const text = document.getElementById('admin-announce-text').value.trim();
  if (!text) { toast('⚠️ Enter announcement text.'); return; }
  if (!confirm(`Send this announcement to all connected users?\n\n"${text.slice(0,100)}"`)) return;
  wsSend({ type: 'admin_send_unread_announce', text });
  document.getElementById('admin-announce-text').value = '';
  toast('📣 Announcement sent.');
}

function adminMassDm() {
  const text = document.getElementById('admin-massdm-text').value.trim();
  if (!text) { toast('⚠️ Enter a message for the mass DM.'); return; }
  if (!confirm(`Send this DM to EVERY registered user?\n\n"${text.slice(0,100)}"\n\nThis will create a system DM conversation with every account.`)) return;
  wsSend({ type: 'admin_mass_dm', text });
  document.getElementById('admin-massdm-text').value = '';
  toast('⏳ Sending mass DM…');
}

// ── Servers tab new actions ────────────────────────────────────────────────────
function adminSetServerDesc() {
  const svId = document.getElementById('admin-edit-sv-id').value.trim();
  const desc = document.getElementById('admin-sv-desc-text').value.trim();
  if (!svId) { _adminSvResult('Enter a Server ID.', 'var(--red)'); return; }
  wsSend({ type: 'admin_set_server_desc', serverId: svId, desc });
  _adminSvResult('⏳ Updating description…');
}

function adminSetServerPublic(isPublic) {
  const svId = document.getElementById('admin-edit-sv-id').value.trim();
  if (!svId) { _adminSvResult('Enter a Server ID.', 'var(--red)'); return; }
  wsSend({ type: 'admin_set_server_public', serverId: svId, isPublic });
  _adminSvResult(`⏳ Setting server to ${isPublic ? 'public' : 'private'}…`);
}

function adminCloneServer() {
  const svId = prompt('Server ID to clone:');
  if (!svId) return;
  const name = prompt('Name for the cloned server:');
  if (!name) return;
  wsSend({ type: 'admin_clone_server', serverId: svId, name });
  toast(`⏳ Cloning server as "${name}"…`);
}

// ── Messages tab new actions ───────────────────────────────────────────────────
function adminSetSlowmode() {
  const chId = document.getElementById('admin-slow-ch-id').value.trim();
  const secs = parseInt(document.getElementById('admin-slow-secs').value) || 0;
  if (!chId) { _adminMsgResult('Enter a Channel ID.', 'var(--red)'); return; }
  if (secs < 0 || secs > 3600) { _adminMsgResult('Seconds must be 0–3600.', 'var(--red)'); return; }
  wsSend({ type: 'admin_set_slowmode', channelId: chId, seconds: secs });
  _adminMsgResult(`⏳ Setting slowmode to ${secs}s…`);
}

function adminExportChannel() {
  const chId = document.getElementById('admin-view-ch-id').value.trim();
  if (!chId) { _adminMsgResult('Enter a Channel ID.', 'var(--red)'); return; }
  wsSend({ type: 'admin_export_channel', channelId: chId });
  _adminMsgResult('⏳ Requesting export…');
}
function adminDownloadExport(msg) {
  const data = JSON.stringify(msg.messages || [], null, 2);
  const blob = new Blob([data], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `nexus-channel-${msg.channelId}-export.json`;
  a.click();
  URL.revokeObjectURL(a.href);
  _adminMsgResult(`✅ Exported ${(msg.messages||[]).length} messages.`, 'var(--green)');
}

// ── Audit log ─────────────────────────────────────────────────────────────────
function adminLoadAuditLog() {
  const box = document.getElementById('admin-audit-list');
  if (box) box.innerHTML = '<div style="font-size:12px;color:var(--t3)">Loading…</div>';
  wsSend({ type: 'admin_get_audit_log', limit: 100 });
}
function adminClearAuditLog() {
  if (!confirm('Clear the entire audit log? This cannot be undone.')) return;
  wsSend({ type: 'admin_clear_audit_log' });
  const box = document.getElementById('admin-audit-list');
  if (box) box.innerHTML = '<div style="font-size:12px;color:var(--t3)">Audit log cleared.</div>';
}
function renderAdminAuditLog(entries) {
  const box = document.getElementById('admin-audit-list');
  if (!box) return;
  if (!entries.length) { box.innerHTML = '<div style="font-size:12px;color:var(--t3)">No audit entries found.</div>'; return; }
  const actionColors = {
    ban: '#f87171', nuke_account: '#f87171', mass_dm: '#c084fc',
    impersonate_send: '#fb923c', maintenance_toggle: '#f87171',
    send_announcement: '#60a5fa', unban: 'var(--green)',
  };
  box.innerHTML = entries.map(e => {
    const ts = e.at ? new Date(e.at).toLocaleString('en',{month:'short',day:'numeric',hour:'2-digit',minute:'2-digit',second:'2-digit'}) : '?';
    const color = actionColors[e.action] || 'var(--t2)';
    const details = Object.entries(e)
      .filter(([k]) => !['action','by','at'].includes(k))
      .map(([k,v]) => `<span style="color:var(--t3)">${esc(k)}:</span> ${esc(String(v).slice(0,80))}`)
      .join(' · ');
    return `<div style="background:var(--s3);border:1px solid var(--border);border-radius:6px;padding:7px 10px;font-size:11px">
      <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:${details?'3':'0'}px">
        <span style="font-weight:700;color:${color}">${esc(e.action||'?')}</span>
        <span style="color:var(--t3)">by <strong style="color:var(--t2)">${esc(e.by||'?')}</strong></span>
        <span style="font-size:10px;color:var(--t3);margin-left:auto;font-family:'DM Mono',monospace">${ts}</span>
      </div>
      ${details ? `<div style="font-size:10px;color:var(--t3)">${details}</div>` : ''}
    </div>`;
  }).join('');
}

// ── Bans tab ──────────────────────────────────────────────────────────────────
function adminLoadBans() {
  const box = document.getElementById('admin-bans-list');
  if (box) box.innerHTML = '<div style="font-size:12px;color:var(--t3)">Loading…</div>';
  wsSend({ type: 'admin_list_bans' });
}
function renderAdminBans(bans) {
  const box = document.getElementById('admin-bans-list');
  if (!box) return;
  if (!bans.length) { box.innerHTML = '<div style="font-size:12px;color:var(--t3)">No active bans 🎉</div>'; return; }
  box.innerHTML = bans.map(b => {
    const until = b.until === -1 ? 'Permanent' : `Until ${new Date(b.until).toLocaleString()}`;
    return `<div style="display:flex;align-items:center;justify-content:space-between;background:var(--s3);border:1px solid var(--border);border-radius:6px;padding:7px 10px;gap:8px">
      <div style="flex:1;min-width:0">
        <div style="font-size:12px;font-weight:700">${esc(b.username)}</div>
        <div style="font-size:10px;color:var(--t3)">${esc(b.reason||'No reason')} · ${until}</div>
      </div>
      <button class="btn-g" style="font-size:10px;padding:3px 8px;flex-shrink:0" onclick="adminQuickUnban('${esc(b.username)}')">Unban</button>
    </div>`;
  }).join('');
}
function adminQuickUnban(username) {
  wsSend({ type: 'admin_unban', target: username });
  toast(`Unbanning ${username}…`);
  setTimeout(adminLoadBans, 800);
}
function adminLoadFrozen() {
  const box = document.getElementById('admin-frozen-list');
  if (box) box.innerHTML = '<div style="font-size:12px;color:var(--t3)">Loading…</div>';
  wsSend({ type: 'admin_list_frozen' });
}
function renderAdminFrozen(frozen) {
  const box = document.getElementById('admin-frozen-list');
  if (!box) return;
  if (!frozen.length) { box.innerHTML = '<div style="font-size:12px;color:var(--t3)">No frozen users 🎉</div>'; return; }
  box.innerHTML = frozen.map(f => {
    return `<div style="display:flex;align-items:center;justify-content:space-between;background:rgba(96,165,250,.07);border:1px solid rgba(96,165,250,.2);border-radius:6px;padding:7px 10px;gap:8px">
      <div style="flex:1;min-width:0">
        <div style="font-size:12px;font-weight:700">🧊 ${esc(f.username)}</div>
        <div style="font-size:10px;color:var(--t3)">${esc(f.reason||'No reason')} · by ${esc(f.by||'?')}</div>
      </div>
      <button class="btn-g" style="font-size:10px;padding:3px 8px;flex-shrink:0" onclick="adminQuickUnfreeze('${esc(f.username)}')">Unfreeze</button>
    </div>`;
  }).join('');
}
function adminQuickUnfreeze(username) {
  wsSend({ type: 'admin_unfreeze_user', target: username });
  toast(`Unfreezing ${username}…`);
  setTimeout(adminLoadFrozen, 800);
}

// ── Messages tab ──────────────────────────────────────────────────────────────
function adminViewChannel() {
  const chId = document.getElementById('admin-view-ch-id').value.trim();
  if (!chId) { _adminMsgResult('Enter a channel ID.', 'var(--red)'); return; }
  wsSend({ type: 'admin_view_channel', channelId: chId });
  _adminMsgResult('Loading…');
}
function adminWipeChannel() {
  const chId = document.getElementById('admin-wipe-ch-id').value.trim();
  if (!chId) { _adminMsgResult('Enter a channel ID.', 'var(--red)'); return; }
  if (!confirm(`Wipe ALL messages from channel ${chId}? This cannot be undone.`)) return;
  wsSend({ type: 'admin_wipe_channel', channelId: chId });
  _adminMsgResult(`⏳ Wiping channel ${chId}…`);
}
function adminLockChannel(locked) {
  const chId = document.getElementById('admin-lock-ch-id').value.trim();
  if (!chId) { _adminMsgResult('Enter a channel ID.', 'var(--red)'); return; }
  wsSend({ type: 'admin_lock_channel', channelId: chId, locked });
  _adminMsgResult(`⏳ ${locked ? 'Locking' : 'Unlocking'} channel…`);
}
function adminPurgeUserMessages() {
  const target   = document.getElementById('admin-purge-user').value.trim();
  const serverId = document.getElementById('admin-purge-sv').value.trim();
  if (!target || !serverId) { _adminMsgResult('Username and Server ID required.', 'var(--red)'); return; }
  if (!confirm(`Delete ALL messages from ${target} in server ${serverId}? This cannot be undone.`)) return;
  wsSend({ type: 'admin_purge_user_messages', target, serverId });
  _adminMsgResult(`⏳ Purging messages from ${target}…`);
}
function adminDeleteMessage() {
  const chId  = document.getElementById('admin-del-msg-ch').value.trim();
  const msgId = document.getElementById('admin-del-msg-id').value.trim();
  if (!chId || !msgId) { _adminMsgResult('Channel ID and Message ID required.', 'var(--red)'); return; }
  if (!confirm('Delete this message?')) return;
  wsSend({ type: 'admin_delete_message', channelId: chId, messageId: msgId });
  _adminMsgResult('⏳ Deleting message…');
}
function adminEditMessage() {
  // Uses the same Channel ID / Message ID fields as Delete — fill those, then click Edit
  adminEditMsgFromFields();
}
function adminDeleteDmHistory() {
  const userA = document.getElementById('admin-dmdel-a').value.trim();
  const userB = document.getElementById('admin-dmdel-b').value.trim();
  if (!userA || !userB) { _adminMsgResult('Both usernames required.', 'var(--red)'); return; }
  if (!confirm(`Permanently delete all DMs between ${userA} and ${userB}?`)) return;
  wsSend({ type: 'admin_delete_dm_history', userA, userB });
  _adminMsgResult(`⏳ Deleting DM history between ${userA} and ${userB}…`);
}

// ── Online tab ────────────────────────────────────────────────────────────────
function adminLoadOnline() {
  const box = document.getElementById('admin-online-list');
  if (box) box.innerHTML = '<div style="font-size:12px;color:var(--t3)">Loading…</div>';
  wsSend({ type: 'admin_list_online' });
  wsSend({ type: 'admin_list_calls' });
}
function renderAdminOnline(users) {
  const box = document.getElementById('admin-online-list');
  if (!box) return;
  if (!users.length) { box.innerHTML = '<div style="font-size:12px;color:var(--t3)">No users online.</div>'; return; }
  box.innerHTML = `<div style="font-size:11px;color:var(--t3);margin-bottom:8px">${users.length} user(s) connected right now</div>` +
    users.map(u => {
      const role = u.systemRole==='admin' ? `<span style="font-size:9px;background:rgba(108,99,255,.2);color:var(--accent);border:1px solid rgba(108,99,255,.3);border-radius:99px;padding:1px 5px">⚡ Admin</span>`
        : u.coAdmin ? `<span style="font-size:9px;background:rgba(52,211,153,.15);color:var(--green);border:1px solid rgba(52,211,153,.3);border-radius:99px;padding:1px 5px">★ Co-Admin</span>` : '';
      const frozen = u.frozen ? `<span style="font-size:9px;background:rgba(96,165,250,.15);color:#60a5fa;border:1px solid rgba(96,165,250,.3);border-radius:99px;padding:1px 5px">🧊 Frozen</span>` : '';
      return `<div style="display:flex;align-items:center;gap:8px;background:var(--s3);border:1px solid var(--border);border-radius:6px;padding:7px 10px">
        <div style="width:8px;height:8px;border-radius:50%;background:var(--green);flex-shrink:0"></div>
        <div style="flex:1;min-width:0">
          <div style="font-size:12px;font-weight:700;display:flex;align-items:center;gap:5px;flex-wrap:wrap">${esc(u.name||'?')}<span style="font-size:10px;color:var(--t3)">#${u.tag||'0000'}</span>${role}${frozen}</div>
        </div>
        <button class="btn-g" style="font-size:10px;padding:3px 7px;flex-shrink:0" onclick="document.getElementById('admin-user-in').value='${esc(u.name)}';adminTab('users')">Target →</button>
      </div>`;
    }).join('');
}

function renderAdminCallsList(calls) {
  let box = document.getElementById('admin-calls-list');
  if (!box) return;
  if (!calls.length) {
    box.innerHTML = '<div style="font-size:12px;color:var(--t3)">No active voice calls right now.</div>';
    return;
  }
  box.innerHTML = calls.map(c => {
    const pips = (c.participants || []).map(n =>
      `<span style="background:var(--s3);border:1px solid var(--border);border-radius:99px;padding:2px 8px;font-size:11px">${esc(n)}</span>`
    ).join('');
    const dur = c.startedAt ? Math.floor((Date.now() - c.startedAt) / 1000) : 0;
    const mm = Math.floor(dur/60).toString().padStart(2,'0');
    const ss = (dur%60).toString().padStart(2,'0');
    const alreadyGhosting = ghostVcallId === c.callId;
    return `<div style="background:var(--s3);border:1px solid rgba(168,85,247,.25);border-radius:8px;padding:10px 12px;display:flex;align-items:center;gap:10px">
      <div style="font-size:18px">📞</div>
      <div style="flex:1;min-width:0">
        <div style="font-size:11px;font-weight:700;color:#c084fc;margin-bottom:4px">Active Call · ${mm}:${ss}</div>
        <div style="display:flex;gap:4px;flex-wrap:wrap">${pips}</div>
      </div>
      ${alreadyGhosting
        ? `<button onclick="leaveGhostVcall()" style="background:rgba(248,113,113,.1);border:1px solid rgba(248,113,113,.3);border-radius:7px;color:#f87171;padding:5px 10px;font-size:11px;cursor:pointer;flex-shrink:0">Leave Ghost</button>`
        : `<button onclick="ghostJoinVcall('${esc(c.callId)}')" style="background:rgba(168,85,247,.15);border:1px solid rgba(168,85,247,.35);border-radius:7px;color:#c084fc;padding:5px 12px;font-size:11px;cursor:pointer;font-weight:700;flex-shrink:0">👻 Ghost Join</button>`
      }
    </div>`;
  }).join('');
}

// ── Stats tab ─────────────────────────────────────────────────────────────────
function adminLoadStats() {
  const grid = document.getElementById('admin-stats-grid');
  if (grid) grid.innerHTML = '<div style="font-size:12px;color:var(--t3)">Loading…</div>';
  wsSend({ type: 'admin_get_stats' });
}
function renderAdminStats(stats) {
  const grid = document.getElementById('admin-stats-grid');
  if (!grid) return;
  const items = [
    { label: 'Online Now',       value: stats.onlineNow,      icon: '🟢', color: 'var(--green)' },
    { label: 'Total Accounts',   value: stats.totalAccounts,  icon: '👥', color: 'var(--accent)' },
    { label: 'Total Servers',    value: stats.totalServers,   icon: '🌐', color: '#60a5fa' },
    { label: 'Total Messages',   value: stats.totalMessages,  icon: '💬', color: '#c084fc' },
    { label: 'DM Conversations', value: stats.totalDmConvos,  icon: '📨', color: '#f472b6' },
    { label: 'Active Bans',      value: stats.activeBans,     icon: '🔨', color: '#f87171' },
    { label: 'Frozen Users',     value: stats.frozenUsers,    icon: '🧊', color: '#93c5fd' },
    { label: 'Locked Channels',  value: stats.lockedChannels, icon: '🔒', color: '#fb923c' },
  ];
  grid.innerHTML = items.map(it =>
    `<div style="background:var(--s3);border:1px solid var(--border);border-radius:10px;padding:12px;text-align:center">
      <div style="font-size:20px;margin-bottom:4px">${it.icon}</div>
      <div style="font-size:20px;font-weight:800;color:${it.color}">${(it.value||0).toLocaleString()}</div>
      <div style="font-size:10px;color:var(--t3);margin-top:2px">${it.label}</div>
    </div>`
  ).join('');
  const meta = document.getElementById('admin-stats-meta');
  if (meta) meta.textContent = `Deploy version: ${stats.deployVersion || '?'} · Loaded ${new Date().toLocaleTimeString()}`;
}

// ── Alert tab ─────────────────────────────────────────────────────────────────
function adminSetMotd() {
  const text = document.getElementById('admin-motd-text').value.trim();
  wsSend({ type: 'admin_set_motd', text });
  const el = document.getElementById('admin-motd-result');
  if (el) { el.textContent = text ? '✅ MOTD saved.' : '✅ MOTD cleared.'; el.style.color='var(--green)'; }
}
function adminClearMotd() {
  document.getElementById('admin-motd-text').value = '';
  wsSend({ type: 'admin_set_motd', text: '' });
  const el = document.getElementById('admin-motd-result');
  if (el) { el.textContent = '✅ MOTD cleared.'; el.style.color='var(--green)'; }
}

// Store profile data when we receive profile_update broadcasts
function cacheProfile(data) {
  if (!data.user) return;
  profileCache[data.user] = { ...profileCache[data.user], name: data.user, color: data.color, pfp: data.pfp, bio: data.bio, socials: data.socials };
}
