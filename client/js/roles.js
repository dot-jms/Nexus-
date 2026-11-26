// ══════════════════════════════════════════════
// ROLES & PERMISSIONS SYSTEM
// ══════════════════════════════════════════════

// Role hierarchy: owner > mod > [custom roles] > member
// Permissions available for custom roles / mods
const ALL_PERMS = [
  { id: 'manage_channels',  label: 'Manage Channels',  sub: 'Create, rename, delete channels' },
  { id: 'manage_messages',  label: 'Manage Messages',  sub: 'Delete any message' },
  { id: 'kick_members',     label: 'Kick Members',     sub: 'Remove members from server' },
  { id: 'ban_members',      label: 'Ban Members',      sub: 'Permanently ban members' },
  { id: 'pin_messages',     label: 'Pin Messages',     sub: 'Pin important messages' },
  { id: 'invite_members',   label: 'Create Invites',   sub: 'Generate invite links' },
];

// Default roles every server gets
const DEFAULT_ROLES = [
  { id: 'owner', name: 'Owner',     color: '#fbbf24', perms: ['*'], builtin: true },
  { id: 'mod',   name: 'Moderator', color: '#34d399', perms: ['manage_messages','kick_members','pin_messages','invite_members'], builtin: true },
  { id: 'member',name: 'Member',    color: '#9090a8', perms: ['invite_members'], builtin: true },
];

let editingRoleId = null;      // which role is open in editor
let editingRoleColor = COLORS[0];
let ctxTargetMember = null;    // member name for context menu
let stgIconData = null;        // pending new server icon in settings

// ── helpers ──
function getMyRole(sv) {
  if (!sv) return 'member';
  if (sv.ownerId && sv.ownerId.toLowerCase() === (S.user?.name || '').toLowerCase()) return 'owner';
  const assignment = (sv.memberRoles || {})[S.user.name];
  if (assignment === 'mod') return 'mod';
  // check custom role
  const customRole = (sv.roles || []).find(r => r.id === assignment);
  return customRole ? assignment : 'member';
}

function getEffectiveRole(sv, roleId) {
  // Returns role with any per-server overrides applied
  const override = (sv.roleOverrides || {})[roleId];
  const base = DEFAULT_ROLES.find(r => r.id === roleId) || (sv.roles||[]).find(r=>r.id===roleId);
  if (!base) return null;
  return override ? { ...base, ...override } : base;
}
function hasPerm(sv, perm) {
  // Platform admins/co-admins have all permissions in every server
  if (isPlatformPower()) return true;
  const role = getMyRole(sv);
  if (role === 'owner') return true;
  const allRoles = [...DEFAULT_ROLES.map(r=>getEffectiveRole(sv,r.id)).filter(Boolean), ...(sv.roles||[]).map(r=>getEffectiveRole(sv,r.id)||r)];
  const r = allRoles.find(x => x.id === role);
  return r ? (r.perms.includes('*') || r.perms.includes(perm)) : false;
}


// ── Role appearance: colour, optional second colour, name effect, badge icon, own group in the member list ──
const ROLE_FX = [{ id: 'none', n: 'Plain' }, { id: 'gradient', n: 'Gradient' }, { id: 'glow', n: 'Glow' }, { id: 'shimmer', n: 'Shimmer' }, { id: 'rainbow', n: 'Rainbow' }];
function roleFxAttrs(r) { // { cls, style } for a name written in this role's look
  const c1 = pfHex(r && r.color, '#9090a8'), c2 = pfHex(r && r.color2, c1), fx = r && ROLE_FX.some(f => f.id === r.fx) ? r.fx : 'none';
  return { cls: fx !== 'none' ? 'rfx rfx-' + fx : '', style: `color:${c1};--rf1:${c1};--rf2:${c2};` };
}
function getEffectiveRole(sv, id) { // built-ins merged with this server's overrides, or the custom role itself
  if (!sv || !id) return null;
  const base = DEFAULT_ROLES.find(r => r.id === id);
  if (base) return { ...base, ...((sv.roleOverrides || {})[id] || {}) };
  return (sv.roles || []).find(r => r.id === id) || null;
}
function roleNameAttrs(sv, name) { // the look of a member's name in chat / member list; low roles are grey by default
  if (!sv) return { cls: '', style: '' };
  const r = getEffectiveRole(sv, getMemberRole(sv, name));
  return r ? roleFxAttrs(r) : { cls: '', style: '' };
}
