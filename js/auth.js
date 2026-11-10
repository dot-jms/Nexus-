// ══════════════════════════════════════════════════════════════════════
// AUTH — clean server-side auth, no migration noise
// ══════════════════════════════════════════════════════════════════════
let authWs = null;

function authRequest(msg) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(WS_URL);
    ws.onopen = () => ws.send(JSON.stringify(msg));
    ws.onmessage = (e) => { try { resolve(JSON.parse(e.data)); } catch { reject(); } finally { try { ws.close(); } catch(e){} } };
    ws.onerror = () => reject(new Error('Connection failed'));
    setTimeout(() => { reject(new Error('Timeout')); try { ws.close(); } catch(e){} }, 10000);
  });
}

function initAuth() {
  const grid = document.getElementById('av-grid');
  COLORS.forEach((c, i) => {
    const d = document.createElement('div');
    d.className = 'av-opt' + (i===0?' sel':'');
    d.style.background=c; d.dataset.c=c; d.textContent='A';
    d.onclick=()=>{ document.querySelectorAll('.av-opt').forEach(x=>x.classList.remove('sel')); d.classList.add('sel'); selectedColor=c; };
    grid.appendChild(d);
  });
  document.getElementById('su-user').addEventListener('input', function() {
    document.querySelectorAll('.av-opt').forEach(a=>a.textContent=this.value?this.value[0].toUpperCase():'A');
    const p=document.getElementById('su-pfp-preview');
    if (!suPfpData) p.textContent=this.value?this.value[0].toUpperCase():'?';
  });
  ['login-user','login-pass'].forEach(id=>document.getElementById(id).addEventListener('keydown',e=>{if(e.key==='Enter')doLogin();}));
  ['su-user','su-pass'].forEach(id=>document.getElementById(id).addEventListener('keydown',e=>{if(e.key==='Enter')doSignup();}));

  // Auto-login from saved session token — no prompts, just boot
  // lsGet first; fall back to sessionStorage so Ctrl+Shift+R (hard refresh,
  // which wipes localStorage) doesn't log everyone out.
  const sess = lsGet('nx-session') || ssGet('nx-session');
  if (sess?.token && sess?.user) {
    S.user = sess.user;
    S.token = sess.token;
    // Restore into localStorage in case it was wiped by the hard refresh
    lsSet('nx-session', { token: sess.token, user: sess.user });
    loadUserData();
    bootApp();
  }
}

async function doLogin() {
  const username = document.getElementById('login-user').value.trim();
  const password = document.getElementById('login-pass').value;
  if (!username || !password) { showAuthErr('Please fill in all fields.'); return; }
  const btn = document.querySelector('#form-login .auth-btn');
  btn.textContent = 'Signing in…'; btn.disabled = true;
  try {
    const resp = await authRequest({ type: 'auth_login', username, password });
    if (resp.type === 'auth_ok') {
      onAuthOk(resp);
    } else {
      showAuthErr(resp.message || 'Login failed.');
    }
  } catch(e) {
    showAuthErr('Could not connect to server. Check your internet.');
  }
  btn.textContent = 'Sign in →'; btn.disabled = false;
}

async function doSignup() {
  const username = document.getElementById('su-user').value.trim();
  const password = document.getElementById('su-pass').value;
  if (!username) { showAuthErr('Please choose a username.'); return; }
  if (username.length < 2) { showAuthErr('Username must be at least 2 characters.'); return; }
  if (!/^[a-zA-Z0-9_.\-]{2,24}$/.test(username)) { showAuthErr('Only letters, numbers, underscores, dots, hyphens.'); return; }
  if (!password || password.length < 4) { showAuthErr('Password must be at least 4 characters.'); return; }
  const btn = document.querySelector('#form-signup .auth-btn');
  btn.textContent = 'Creating…'; btn.disabled = true;
  try {
    const resp = await authRequest({ type: 'auth_register', username, password, color: selectedColor, pfp: suPfpData || null });
    if (resp.type === 'auth_ok') {
      onAuthOk(resp);
      toast('👋 Welcome to Nexus, ' + resp.user.name + '!');
    } else {
      showAuthErr(resp.message || 'Registration failed.');
    }
  } catch(e) {
    showAuthErr('Could not connect to server.');
  }
  btn.textContent = 'Create Account →'; btn.disabled = false;
}

function onAuthOk(resp) {
  S.user = { name: resp.user.name, tag: resp.user.tag, color: resp.user.color, pfp: resp.user.pfp || null, systemRole: resp.user.systemRole || 'user', coAdmin: resp.user.coAdmin || false, bio: resp.user.bio || '', socials: resp.user.socials || {} };
  S.token = resp.token;
  lsSet('nx-session', { token: resp.token, user: S.user });
  loadUserData();
  bootApp();
  // First login as Puck — prompt password change
  if (resp.user.systemRole === 'admin' && resp.firstLogin) {
    setTimeout(() => { toast('⚡ Welcome Puck! Change your password in Profile Settings.'); }, 1500);
  }
}

function signOut() {
  if (!confirm('Sign out?')) return;
  // FIX #13: Clear per-user cached data (servers, messages, DMs) in addition to the
  // session token. Without this, the next person using the device inherits all data
  // until the relay overwrites it — a real privacy risk on shared devices.
  try {
    if (S.user?.name) localStorage.removeItem('nx-data-' + S.user.name.toLowerCase());
    localStorage.removeItem('nx-session');
    localStorage.removeItem('nx-pending-creates');
    // Also clear sessionStorage fallback so hard-refresh doesn't resurrect signed-out session
    sessionStorage.removeItem('nx-session');
    if (S.user?.name) sessionStorage.removeItem('nx-data-' + S.user.name.toLowerCase());
  } catch(e) {}
  S.user = null; S.token = null;
  S.servers = []; S.messages = {}; S.dms = []; S.dmMessages = {};
  S.friends = []; S.friendReqs = []; S.members = {};
  S.curSv = null; S.curCh = null; S.wsConnecting = false; S.wsOk = false; curDM = null;
  _wsQueue.length = 0; // FIX #9: also clear any unsent queued messages
  if (S.ws) { try { S.ws.onclose = null; S.ws.close(); } catch(e) {} S.ws = null; }
  document.getElementById('app').classList.remove('vis');
  document.getElementById('auth-screen').style.display = 'flex';
  switchTab('login');
  document.getElementById('login-user').value = '';
  document.getElementById('login-pass').value = '';
  suPfpData = null;
}

// Change password — sent over main authenticated WS
function changePassword() {
  const oldPw = document.getElementById('chpw-old').value;
  const newPw = document.getElementById('chpw-new').value;
  const newPw2 = document.getElementById('chpw-new2').value;
  const errEl = document.getElementById('chpw-err');
  errEl.style.display = 'none'; errEl.style.color = 'var(--red)';
  if (!oldPw || !newPw) { errEl.textContent = 'Fill in all fields.'; errEl.style.display = 'block'; return; }
  if (newPw.length < 4) { errEl.textContent = 'New password must be at least 4 characters.'; errEl.style.display = 'block'; return; }
  if (newPw !== newPw2) { errEl.textContent = 'Passwords do not match.'; errEl.style.display = 'block'; return; }
  if (!S.ws || S.ws.readyState !== WebSocket.OPEN) { errEl.textContent = 'Not connected — check your internet.'; errEl.style.display = 'block'; return; }
  // Send directly on the live socket (already carries token from identify handshake)
  S.ws.send(JSON.stringify({ type: 'auth_change_password', oldPassword: oldPw, newPassword: newPw, token: S.token }));
  errEl.textContent = 'Saving...'; errEl.style.color = 'var(--t3)'; errEl.style.display = 'block';
}


let _pfpCropTarget = 'profile'; // 'profile' | 'signup' | 'admin_target'
let _adminPfpTarget = null; // username when admin is setting someone else's pfp

function onSuPfp(e) {
  const f = e.target.files[0]; if (!f) return;
  e.target.value = '';
  const reader = new FileReader();
  reader.onload = ev => {
    _pfpCropTarget = 'signup';
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

async function onSvIcon(e) {
  const f=e.target.files[0]; if(!f) return;
  const raw = await toUrl(f);
  try {
    svIconData = await compressImage(raw, IMG_LIMITS.icon);
  } catch(err) {
    toast('⚠️ Server icon is too large. Try a simpler image.'); return;
  }
  const p=document.getElementById('sv-icon-preview');
  p.innerHTML=`<img src="${svIconData}" style="width:100%;height:100%;object-fit:cover">`;
}

function switchTab(tab) {
  document.getElementById('tab-login').classList.toggle('active',tab==='login');
  document.getElementById('tab-signup').classList.toggle('active',tab==='signup');
  document.getElementById('form-login').classList.toggle('show',tab==='login');
  document.getElementById('form-signup').classList.toggle('show',tab==='signup');
  showAuthErr('');
}
function togglePw(id,btn){ const el=document.getElementById(id); const h=el.type==='password'; el.type=h?'text':'password'; btn.textContent=h?'Hide':'Show'; }
function showAuthErr(msg){ const el=document.getElementById('auth-err'); el.textContent=msg; el.classList.toggle('show',!!msg); }

// (legacy local auth removed — using server-side auth)

function hashPw(pw){ let h=5381; for(let i=0;i<pw.length;i++){h=((h<<5)+h)+pw.charCodeAt(i);h|=0;} return (h>>>0).toString(36); }
function loadUserData(){
  // Full state reset before loading new user data
  S.servers=[]; S.messages={}; S.dms=[]; S.dmMessages={}; S.members={};
  S.curSv=null; S.curCh=null; S.discServers=[];
  // Load cached servers as fallback — relay will overwrite/merge via identified event
  const d=lsGet('nx-data-'+S.user.name.toLowerCase())||{};
  S.servers=d.servers||[]; // fallback until relay confirms
  S.messages=d.messages||{}; S.dms=d.dms||[]; S.dmMessages=d.dmMessages||{};
  S.friends=d.friends||[]; S.friendReqs=d.friendReqs||[];
}
