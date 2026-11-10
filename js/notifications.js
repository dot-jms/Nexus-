// ══════════════════════════════════════════════
// NOTIFICATIONS
// ══════════════════════════════════════════════
const notifications = (function() {
  try {
    const saved = JSON.parse(localStorage.getItem('nx-notifs') || '[]');
    return Array.isArray(saved) ? saved.map(n => ({ ...n, onClick: null })) : [];
  } catch { return []; }
})();
let notifPanelOpen = false;

function _saveNotifs() {
  try {
    const slim = notifications.slice(0,50).map(n => ({ id:n.id, icon:n.icon, text:n.text, ts:n.ts, read:n.read }));
    localStorage.setItem('nx-notifs', JSON.stringify(slim));
  } catch {}
}

function addNotif(icon, text, onClick) {
  notifications.unshift({ id: uid(), icon, text, ts: Date.now(), read: false, onClick });
  if (notifications.length > 50) notifications.pop();
  _saveNotifs();
  updateNotifBadge();
  renderNotifPanel();
  // Browser notification + tab title badge (only when tab is hidden)
  if (document.hidden) {
    _updateTitleBadge();
    if (Notification.permission === 'granted') {
      const n = new Notification('Nexus', { body: text, icon: '/favicon.ico', tag: 'nexus-notif', renotify: true });
      n.onclick = () => { window.focus(); if (onClick) onClick(); n.close(); };
    }
  }
}

let _baseTitleBadge = 0;
function _updateTitleBadge() {
  const unread = notifications.filter(n => !n.read).length;
  _baseTitleBadge = unread;
  document.title = unread > 0 ? `(${unread}) Nexus` : 'Nexus';
}

// Clear title badge when tab becomes visible
document.addEventListener('visibilitychange', () => {
  if (!document.hidden) {
    document.title = 'Nexus';
    _baseTitleBadge = 0;
  }
});

function updateNotifBadge() {
  const unread = notifications.filter(n => !n.read).length;
  const badge = document.getElementById('notif-badge');
  badge.style.display = unread ? '' : 'none';
}

function toggleNotifPanel() {
  notifPanelOpen = !notifPanelOpen;
  const panel = document.getElementById('notif-panel');
  panel.style.display = notifPanelOpen ? 'flex' : 'none';
  // notif bell is now in u-panel
  if (notifPanelOpen) {
    notifications.forEach(n => n.read = true);
    _saveNotifs();
    updateNotifBadge();
    renderNotifPanel();
  }
}

function renderNotifPanel() {
  const el = document.getElementById('notif-list');
  if (!notifications.length) { el.innerHTML = '<div style="padding:20px;text-align:center;font-size:12px;color:var(--t3)">No notifications yet</div>'; return; }
  el.innerHTML = notifications.map(n => `<div class="notif-item${n.read?'':' unread'}" onclick="notifClick('${n.id}')">
    <div style="display:flex;align-items:flex-start;gap:10px">
      <div class="notif-icon">${n.icon}</div>
      <div><div style="font-size:13px;color:var(--t1)">${esc(n.text)}</div><div style="font-size:11px;color:var(--t3);margin-top:2px">${fmtTime(n.ts)}</div></div>
    </div>
  </div>`).join('');
}

function notifClick(id) {
  const n = notifications.find(x => x.id === id);
  if (n?.onClick) n.onClick();
  toggleNotifPanel();
}

function clearNotifs() { notifications.length = 0; _saveNotifs(); updateNotifBadge(); renderNotifPanel(); }

function reqNotifPermission() {
  if (Notification.permission === 'default') Notification.requestPermission();
}
