// ══════════════════════════════════════════════════════════════════
// VOICE CALLS — server-managed calls (protocol 6), full-mesh WebRTC (max 5), global call dock
// ──────────────────────────────────────────────────────────────────
// The server owns the call: it rings people (even ones who come online while it's ringing), keeps the roster,
// starts the clock when somebody answers and writes the "X started a call · lasted Y" line into the chat.
// This file only (a) asks the server for things, (b) wires WebRTC to everybody in the roster, (c) draws the dock.
// The dock (#call-dock) lives on <body>, not inside #main, so no screen (friends page, DMs, servers) can hide it.
// ══════════════════════════════════════════════════════════════════
let vcallId = null;
let vcallPeers = {};                  // name → { pc, muted }
let vcallParticipants = new Set();    // names of the OTHER people in my call (dms.js reads this)
let vcallRinging = new Map();         // name → { online } — people I've rung who haven't answered yet
let vcallIncoming = new Map();        // callId → { from, color, pfp, gid, groupName, until } — calls ringing for ME
let vcallKey = null;                  // conversation the call belongs to (lowercase name or "g:<gid>")
let vcallState = 'idle';              // idle | calling | connecting | connected
let vcallAnsweredAt = 0;              // LOCAL clock ms when the call was answered (the timer starts here); 0 = nobody answered yet
let vcallLocalStream = null, vcallMuted = false, vcallDeafened = false;
let vcallTimerInterval = null;
let _vcBusy = false;
let vcallPeerState = {};              // lowercase name → { muted, deafened } of the OTHER people (their badge in the dock)

// Ghost DM call state — admin silently listens to someone's voice call
let ghostVcallId = null;          // callId we're ghosting
let ghostVcallParticipants = {};  // name → RTCPeerConnection (receive-only)
let ghostVcallStream = null;      // local mic stream (starts muted)
let ghostVcallRevealed = false;

// ── small helpers ──
const vcSecs = () => vcallAnsweredAt ? Math.max(0, Math.floor((Date.now() - vcallAnsweredAt) / 1000)) : 0;
function vcFmt(s) { const h = Math.floor(s / 3600), m = Math.floor(s % 3600 / 60), x = s % 60; return (h ? h + ':' + String(m).padStart(2, '0') : String(m).padStart(2, '0')) + ':' + String(x).padStart(2, '0'); }
function vcInCall() { return !!vcallId; }
// the timer starts when somebody ANSWERS, not when I dial. The server's clock may differ from mine, so use the
// `now` it sends along to translate its timestamp into my clock.
function vcallMarkAnswered(answeredAt, serverNow) {
  if (vcallAnsweredAt) return;
  let origin = Date.now();
  if (answeredAt) { const skew = serverNow ? serverNow - Date.now() : 0; origin = Math.min(Date.now(), answeredAt - skew); if (!(origin > 0) || Date.now() - origin > 864e5) origin = Date.now(); }
  vcallAnsweredAt = origin; vcallState = 'connected';
  startVcallTimer();
}
function startVcallTimer() {
  clearInterval(vcallTimerInterval);
  vcallTimerInterval = setInterval(vcTick, 1000);
  vcTick();
}
function vcTick() {
  const t = document.getElementById('dock-timer'); if (t) t.textContent = vcFmt(vcSecs());
  const now = Date.now(); let expired = false;
  vcallIncoming.forEach((inc, id) => { const left = Math.max(0, Math.ceil((inc.until - now) / 1000)); const el = document.getElementById('dock-count-' + id); if (el) el.textContent = left + 's'; if (inc.until + 1500 < now) { vcallIncoming.delete(id); expired = true; } });
  if (expired) { ringMaybeStop(); dockRender(); }
}

// ── ring loops (WebAudio; silent where unavailable) ──
// A browser starts an AudioContext "suspended" until the page has had a click or key press, so somebody who just opened
// Nexus (and is being called) would hear nothing. Resume it on the first gesture and every time a ring starts.
let _ringCtx = null, _ringTimer = null, _rbTimer = null;
function ringCtx() {
  try { _ringCtx = _ringCtx || new (window.AudioContext || window.webkitAudioContext)(); if (_ringCtx.state === 'suspended') _ringCtx.resume().catch(() => {}); } catch (e) { _ringCtx = null; }
  return _ringCtx;
}
(function () {
  const evs = ['pointerdown', 'keydown', 'touchstart'];
  const unlock = () => { const c = ringCtx(); if (c && c.state === 'running') evs.forEach(ev => document.removeEventListener(ev, unlock)); };
  evs.forEach(ev => document.addEventListener(ev, unlock, { passive: true }));
})();
function ringTone(freqs, ms, vol) {
  const c = ringCtx(); if (!c) return;
  try {
    const t = c.currentTime, d = ms / 1000, g = c.createGain();
    g.gain.setValueAtTime(0, t); g.gain.linearRampToValueAtTime(vol, t + .02); g.gain.setValueAtTime(vol, t + d - .03); g.gain.linearRampToValueAtTime(0, t + d);
    g.connect(c.destination);
    freqs.forEach(f => { const o = c.createOscillator(); o.frequency.value = f; o.connect(g); o.start(t); o.stop(t + d); });
  } catch (e) {}
}
// incoming call: what the person being called hears
function ringStart() { if (_ringTimer) return; const beep = () => ringTone([480], 350, .05); beep(); _ringTimer = setInterval(beep, 2200); }
function ringStop() { clearInterval(_ringTimer); _ringTimer = null; }
function ringMaybeStop() { if (!vcallIncoming.size) ringStop(); }
// outgoing call: what the CALLER hears while the other phone is ringing (two-tone burst, 2 s on / 4 s off).
// It only plays once the server says somebody is actually being rung (not while they're offline) and stops on answer / hang-up.
function ringbackStart() { if (_rbTimer) return; const burst = () => ringTone([440, 480], 2000, .04); burst(); _rbTimer = setInterval(burst, 6000); }
function ringbackStop() { clearInterval(_rbTimer); _rbTimer = null; }
function ringbackSync() {
  const ringing = !!vcallId && !vcallAnsweredAt && [...vcallRinging.values()].some(r => r.online === true);
  if (ringing) ringbackStart(); else ringbackStop();
}

// ══════════════════ THE DOCK ══════════════════
function dockAv(name, color, pfp) {
  const url = safeUrl(pfp || profileCache[name]?.pfp || '');
  const bg = url ? 'transparent' : (color || profileCache[name]?.color || COLORS[hash(name || '?') % COLORS.length]);
  const low = String(name || '').toLowerCase(), mine = !!S.user && low === S.user.name.toLowerCase();
  const st = vcallId ? (mine ? { muted: vcallMuted, deafened: vcallDeafened } : vcallPeerState[low]) : null;
  const badge = st && (st.deafened ? '🔕' : st.muted ? '🔇' : '');
  return `<div class="vcall-pip-av" title="${esc(name)}${badge ? (st.deafened ? ' (deafened)' : ' (muted)') : ''}" style="background:${bg}">${url ? `<img src="${url}" alt="">` : esc((name || '?')[0].toUpperCase())}${badge ? `<span class="vc-badge">${badge}</span>` : ''}</div>`;
}
function vcallStatusText() {
  if (vcallState === 'connecting') return 'Connecting…';
  if (vcallState === 'calling' || !vcallAnsweredAt) {
    const r = [...vcallRinging.entries()];
    if (r.length === 1) return r[0][1].online === false ? `${r[0][0]} is offline — will ring when they come online` : `Calling ${r[0][0]}… ringing`;
    if (r.length > 1) return `Calling ${r.length} people…`;
    return 'Calling…';
  }
  const names = [...vcallParticipants];
  return names.length ? 'With ' + names.slice(0, 3).map(n => n + (vcallPeerState[String(n).toLowerCase()]?.muted ? ' 🔇' : '')).join(', ') + (names.length > 3 ? ` +${names.length - 3}` : '') : 'In call';
}
function vcChannelName() {
  for (const sv of S.servers || []) { const c = (sv.channels || []).find(x => x.id === vcChannelId); if (c) return `${c.name} · ${sv.name}`; }
  return 'Voice channel';
}
function dockRender() {
  const dock = document.getElementById('call-dock'); if (!dock) return;
  let html = '';
  vcallIncoming.forEach((inc, id) => {
    const left = Math.max(0, Math.ceil((inc.until - Date.now()) / 1000));
    const url = safeUrl(inc.pfp || '');
    html += `<div class="dock-in" data-call="${esc(id)}"><div class="dock-av" style="background:${url ? 'transparent' : esc(inc.color || 'var(--accent)')}">${url ? `<img src="${url}" alt="">` : esc((inc.from || '?')[0].toUpperCase())}</div>
      <div class="dock-info"><div class="dock-t">📞 ${esc(inc.groupName ? inc.groupName : inc.from)}</div><div class="dock-s">${inc.groupName ? esc(inc.from) + ' is calling · ' : 'Incoming voice call · '}<span id="dock-count-${esc(id)}">${left}s</span></div></div>
      <button class="btn-p" data-act="accept" onclick="acceptVcall('${esc(id)}')">Accept</button><button class="btn-g" data-act="decline" onclick="declineVcall('${esc(id)}')">Decline</button></div>`;
  });
  if (vcallId) {
    const ent = typeof dmEntry === 'function' && vcallKey ? dmEntry(vcallKey) : null;
    const title = ent?.kind === 'group' ? ent.name : (vcallState === 'connected' ? 'Voice call' : 'Voice call');
    const others = [...vcallParticipants, ...[...vcallRinging.keys()].filter(n => !vcallParticipants.has(n))];
    const full = 1 + others.length >= 5;
    const sub = vcallState === 'connected' && vcallAnsweredAt ? `<span class="tm" id="dock-timer">${vcFmt(vcSecs())}</span> · ${esc(vcallStatusText())}` : esc(vcallStatusText());
    html += `<div class="dock-pill call${vcallAnsweredAt ? '' : ' ringing'}" id="dock-call">
      <div class="dock-avs">${dockAv(S.user.name, S.user.color, S.user.pfp)}${others.slice(0, 3).map(n => dockAv(n)).join('')}</div>
      <div class="dock-info" onclick="vcallOpenChat()" title="Open the conversation"><div class="dock-t">${esc(title)}</div><div class="dock-s">${sub}</div></div>
      <div class="dock-btns">
        <button class="dock-btn${vcallMuted ? ' off' : ''}" id="dock-mute" onclick="toggleVoiceCallMute()" title="${vcallMuted ? 'Unmute' : 'Mute'}">${vcallMuted ? '🔇' : '🎙️'}</button>
        <button class="dock-btn${vcallDeafened ? ' off' : ''}" id="dock-deafen" onclick="toggleVcallDeafen()" title="${vcallDeafened ? 'Undeafen' : 'Deafen'}">${vcallDeafened ? '🔕' : '🎧'}</button>
        ${full ? '' : `<button class="dock-btn" id="dock-invite" onclick="openNewGroup('call')" title="Invite people">➕</button>`}
        <button class="dock-btn hang" id="dock-hangup" onclick="endVoiceCall()" title="${vcallAnsweredAt ? 'Hang up' : 'Cancel call'}">📵</button>
      </div></div>`;
  } else if (typeof vcChannelId !== 'undefined' && vcChannelId) {
    html += `<div class="dock-pill vc" id="dock-vc"><div class="dock-avs">${dockAv(S.user.name, S.user.color, S.user.pfp)}</div>
      <div class="dock-info"><div class="dock-t">🔊 Voice connected</div><div class="dock-s">${esc(vcChannelName())}</div></div>
      <div class="dock-btns"><button class="dock-btn${vcMuted ? ' off' : ''}" id="dock-vc-mute" onclick="toggleVoiceMute()" title="Mute / unmute">${vcMuted ? '🔇' : '🎙️'}</button>
      <button class="dock-btn hang" id="dock-vc-leave" onclick="leaveVoice()" title="Leave voice">📵</button></div></div>`;
  }
  dock.innerHTML = html;
  dock.style.display = html ? '' : 'none';
  try { ringbackSync(); } catch (e) {}
}
function vcallOpenChat() { if (vcallKey && typeof openDMChat === 'function') openDMChat(vcallKey); }

// ══════════════════ STARTING / ANSWERING ══════════════════
async function vcallGetMic() {
  if (typeof vcChannelId !== 'undefined' && vcChannelId) leaveVoice();     // one microphone: leave the voice channel first
  try { vcallLocalStream = await navigator.mediaDevices.getUserMedia({ audio: true, video: false }); return true; }
  catch (e) { toast('🎤 Microphone access denied', 'err'); return false; }
}
function vcallStopMic() { if (vcallLocalStream) { vcallLocalStream.getTracks().forEach(t => t.stop()); vcallLocalStream = null; } }
function vcallReset() {
  vcallParticipants = new Set(); vcallPeers = {}; vcallRinging = new Map(); vcallPeerState = {};
  vcallMuted = false; vcallDeafened = false; vcallAnsweredAt = 0;
}
async function vcallBegin(wire, key, ringing) {
  if (vcallId || _vcBusy) { toast('You are already in a call'); return; }
  _vcBusy = true;
  try {
    if (!(await vcallGetMic())) return;
    const callId = uid();
    // server first: if the socket is down nothing was sent, so don't pretend we're calling
    if (!wsSend({ type: 'vcall_invite', callId, ...wire })) { vcallStopMic(); toast("You're offline — can't start a call right now", 'warn'); return; }
    try {
      vcallReset(); vcallId = callId; vcallKey = key; vcallState = 'calling';
      (ringing || []).forEach(n => vcallRinging.set(n, { online: null }));
      startWsPing(); dockRender(); if (typeof renderDMCallBanner === 'function') renderDMCallBanner();
    } catch (e) { console.error('[calls] UI update failed', e); }
  } finally { _vcBusy = false; }
}
function startVoiceCall(name) { return vcallBegin({ to: name }, String(name).toLowerCase(), [name]); }
function startGroupCall(gid) { return vcallBegin({ gid }, 'g:' + gid, []); }

// join a call that's already going (the "Join call" banner in the chat)
async function joinVoiceCall(callId, key) {
  if (vcallId || _vcBusy) { toast('You are already in a call'); return; }
  _vcBusy = true;
  try {
    if (!(await vcallGetMic())) return;
    if (!wsSend({ type: 'vcall_join', callId })) { vcallStopMic(); toast("You're offline", 'warn'); return; }
    try { vcallReset(); vcallId = callId; vcallKey = key || null; vcallState = 'connecting'; startWsPing(); dockRender(); if (typeof renderDMCallBanner === 'function') renderDMCallBanner(); } catch (e) { console.error(e); }
  } finally { _vcBusy = false; }
}
async function acceptVcall(callId) {
  const inc = vcallIncoming.get(callId); if (!inc) return;
  if (vcallId || _vcBusy) { toast('Hang up your current call first'); return; }
  _vcBusy = true;
  try {
    if (!(await vcallGetMic())) return;
    if (!wsSend({ type: 'vcall_accept', callId })) { vcallStopMic(); toast("You're offline", 'warn'); return; }
    try {
      vcallIncoming.delete(callId); ringMaybeStop();
      vcallReset(); vcallId = callId; vcallKey = inc.gid ? 'g:' + inc.gid : String(inc.from).toLowerCase(); vcallState = 'connecting';
      startWsPing(); dockRender(); if (typeof renderDMCallBanner === 'function') renderDMCallBanner();
    } catch (e) { console.error(e); }
  } finally { _vcBusy = false; }
}
function declineVcall(callId) {
  wsSend({ type: 'vcall_decline', callId });
  try { vcallIncoming.delete(callId); ringMaybeStop(); dockRender(); } catch (e) { console.error(e); }
}
// the "Invite" dialog (openNewGroup('call')) ends up here
function vcallInvitePeople(names) {
  if (!vcallId) return;
  (names || []).forEach(n => {
    if (1 + vcallParticipants.size + vcallRinging.size >= 5) { toast('Max 5 people in a call'); return; }
    wsSend({ type: 'vcall_invite', callId: vcallId, to: n });
    vcallRinging.set(n, { online: null });
  });
  try { dockRender(); } catch (e) { console.error(e); }
}

// ══════════════════ HANGING UP / CLEANUP ══════════════════
function endVoiceCall() {
  const id = vcallId; if (!id) return;
  wsSend({ type: 'vcall_leave', callId: id });      // leaves for ME; the server ends it when nobody is left
  try { cleanupVcall(); } catch (e) { console.error(e); }
}
function cleanupVcall() {
  clearInterval(vcallTimerInterval); vcallTimerInterval = null;
  Object.entries(vcallPeers).forEach(([id, p]) => { clearTimeout(p.pc?._disconnectTimer); try { p.pc?.close(); } catch (e) {} delete _vcallIceBuffer[id]; });
  vcallStopMic();
  document.querySelectorAll('.vcall-audio-el, [id^="ghost-vcall-audio-"]').forEach(a => a.remove());
  vcallReset(); vcallId = null; vcallKey = null; vcallState = 'idle';
  stopWsPing();
  dockRender(); if (typeof renderDMCallBanner === 'function') renderDMCallBanner();
}
function toggleVoiceCallMute() {
  vcallMuted = !vcallMuted;
  if (vcallLocalStream) vcallLocalStream.getAudioTracks().forEach(t => t.enabled = !vcallMuted);
  vcallSendState(); dockRender();
}
function toggleVcallDeafen() {
  vcallDeafened = !vcallDeafened;
  document.querySelectorAll('.vcall-audio-el').forEach(a => { a.muted = vcallDeafened; });
  vcallSendState(); dockRender();
}
// tell the others (through the server) whether my mic is muted / my headphones are off, for the badge on my avatar
function vcallSendState() { if (vcallId) wsSend({ type: 'vcall_state', callId: vcallId, muted: vcallMuted, deafened: vcallDeafened }); }
// Override toggleVoiceMute to handle both voice channels and calls
function toggleVoiceMute() {
  if (vcallId) { toggleVoiceCallMute(); return; }
  if (!vcLocalStream) return;
  vcMuted = !vcMuted;
  vcLocalStream.getAudioTracks().forEach(t => t.enabled = !vcMuted);
  const btn = document.getElementById('voice-mute-btn');
  if (btn) { btn.style.color = vcMuted ? 'var(--red)' : 'var(--green)'; }
  dockRender();
  toast(vcMuted ? '🔇 Muted' : '🎙️ Unmuted');
}

// ══════════════════ SERVER EVENTS ══════════════════
// somebody is calling ME (also re-sent when I come online while it's still ringing)
function recvVcallInvite(msg) {
  if (!msg.callId || vcallId === msg.callId) return;
  vcallIncoming.set(msg.callId, { from: msg.from, color: msg.fromColor, pfp: msg.fromPfp, gid: msg.gid, groupName: msg.groupName, until: Date.now() + (typeof msg.ringLeftMs === 'number' ? msg.ringLeftMs : 45000) });
  try { dockRender(); ringStart(); } catch (e) { console.error(e); }
  addNotif('📞', (msg.groupName ? `${msg.from} is calling ${msg.groupName}` : msg.from + ' is calling you!'), () => { /* the dock has the Accept button */ });
}
function vcallDismissIncoming(callId) { if (vcallIncoming.delete(callId)) { ringMaybeStop(); dockRender(); } }
function recvVcallMissed(msg) { vcallDismissIncoming(msg.callId); }     // it rang out (or the caller hung up)
function recvVcallHandled(msg) { vcallDismissIncoming(msg.callId); }    // answered/declined on another tab of mine

function recvVcallRinging(msg) {
  if (msg.callId !== vcallId || !msg.to) return;
  vcallRinging.set(msg.to, { online: msg.online !== false });
  dockRender();
}
function recvVcallPeerState(msg) {
  if (msg.callId !== vcallId || !msg.user) return;
  vcallPeerState[String(msg.user).toLowerCase()] = { muted: !!msg.muted, deafened: !!msg.deafened };
  dockRender();
}
function recvVcallNoAnswer(msg) {
  if (msg.callId !== vcallId) return;
  vcallRinging.delete(msg.user); toast(`📵 ${msg.user} didn't answer`); dockRender();
}
function recvVcallDecline(msg) {
  if (msg.callId && msg.callId !== vcallId) return;
  vcallRinging.delete(msg.from); toast('❌ ' + msg.from + ' declined the call'); dockRender();
}
// somebody (also the ghost-reveal path) joined: the newcomer offers to me, I just show them
function recvVcallJoined(msg) {
  if (msg.callId !== vcallId || !msg.user) return;
  vcallRinging.delete(msg.user); vcallParticipants.add(msg.user);
  if (!vcallPeers[msg.user]) vcallPeers[msg.user] = { pc: null, muted: false };
  vcallMarkAnswered(msg.answeredAt, msg.now);
  toast('✅ ' + msg.user + ' joined'); dockRender();
}
function recvVcallAccept(msg) { if (msg.callId === vcallId && msg.from) recvVcallJoined({ callId: msg.callId, user: msg.from, answeredAt: null }); }   // admin ghost reveal
function recvVcallLeft(msg) {
  if (msg.callId !== vcallId) return;
  vcallDropPeer(msg.user); toast('👋 ' + msg.user + ' left the call'); dockRender();
}
function vcallDropPeer(name) {
  const p = vcallPeers[name]; if (p) { clearTimeout(p.pc?._disconnectTimer); try { p.pc?.close(); } catch (e) {} }
  delete vcallPeers[name]; vcallParticipants.delete(name); delete _vcallIceBuffer[name]; delete vcallPeerState[String(name).toLowerCase()];
  document.getElementById('vcall-audio-' + name)?.remove();
}
// I answered / joined: the roster is everybody already in the call. The newcomer offers to ALL of them (full mesh).
async function recvVcallRoster(msg) {
  if (msg.callId !== vcallId) { wsSend({ type: 'vcall_leave', callId: msg.callId }); return; }
  vcallMarkAnswered(msg.answeredAt, msg.now); vcallState = 'connected';
  if (msg.gid && !vcallKey) vcallKey = 'g:' + msg.gid;
  const names = msg.participants || [];
  Object.entries(msg.states || {}).forEach(([k, st]) => { vcallPeerState[String(k).toLowerCase()] = { muted: !!st.muted, deafened: !!st.deafened }; });
  names.forEach(n => vcallParticipants.add(n));
  try { dockRender(); if (typeof renderDMCallBanner === 'function') renderDMCallBanner(); } catch (e) { console.error(e); }
  for (const name of names) {
    if (vcallPeers[name]?.pc) continue;
    try {
      const pc = vcallCreatePeer(name); vcallPeers[name] = { pc, muted: false };
      const offer = await pc.createOffer(); await pc.setLocalDescription(offer);
      wsSend({ type: 'vcall_signal', callId: vcallId, to: name, signal: { sdp: offer } });
    } catch (e) { dbg('vcall offer to ' + name + ' failed: ' + e, 'err'); }
  }
}
function recvVcallEnd(msg) {
  vcallDismissIncoming(msg.callId);
  if (msg.callId !== vcallId) return;
  const why = { ended: '📵 Call ended' + (msg.duration ? ' · ' + vcFmt(Math.round(msg.duration / 1000)) : ''), missed: '📵 No answer', declined: '📵 Call declined', cancelled: '📵 Call cancelled', gone: '📵 That call has already ended' }[msg.reason] || '📵 Call ended';
  toast(why);
  cleanupVcall();
}

// ══════════════════ WebRTC ══════════════════
function vcallCreatePeer(peerId) {
  const cid = vcallId;
  const pc = new RTCPeerConnection(RTC_CONFIG);
  if (vcallLocalStream) vcallLocalStream.getTracks().forEach(t => pc.addTrack(t, vcallLocalStream));
  pc.onicecandidate = e => {
    if (e.candidate) wsSend({ type: 'vcall_signal', callId: cid, to: peerId, signal: { ice: e.candidate } });
  };
  pc.ontrack = e => {
    let audio = document.getElementById('vcall-audio-' + peerId);
    if (!audio) {
      audio = document.createElement('audio');
      audio.id = 'vcall-audio-' + peerId;
      audio.className = 'vcall-audio-el';
      audio.autoplay = true;
      document.body.appendChild(audio);
    }
    audio.muted = vcallDeafened;
    audio.srcObject = e.streams[0];
  };
  // 'disconnected' is transient (network blip, switching WiFi): give it 8s, then try one ICE restart.
  // 'failed' is terminal: drop that peer; if nobody is left, hang up.
  let _iceRestartAttempted = false;
  pc.onconnectionstatechange = () => {
    dbg(`vcall peer ${peerId}: ${pc.connectionState}`, pc.connectionState === 'connected' ? 'ok' : pc.connectionState === 'disconnected' ? 'warn' : 'info');
    if (pc.connectionState === 'disconnected') {
      pc._disconnectTimer = setTimeout(async () => {
        if (pc.connectionState !== 'connected' && !_iceRestartAttempted) {
          _iceRestartAttempted = true;
          try {
            const offer = await pc.createOffer({ iceRestart: true });
            await pc.setLocalDescription(offer);
            wsSend({ type: 'vcall_signal', callId: cid, to: peerId, signal: { sdp: offer } });
            dbg(`vcall ICE restart sent to ${peerId}`, 'warn');
          } catch (e) { dbg('ICE restart failed: ' + e, 'err'); }
        }
      }, 8000);
    } else clearTimeout(pc._disconnectTimer);
    if ((pc.connectionState === 'failed' || pc.connectionState === 'closed') && vcallPeers[peerId]?.pc === pc && vcallId === cid) {
      vcallDropPeer(peerId);
      if (!vcallParticipants.size && !vcallRinging.size && vcallAnsweredAt) endVoiceCall(); else dockRender();
    }
  };
  pc.oniceconnectionstatechange = () => { dbg(`vcall ICE ${peerId}: ${pc.iceConnectionState}`, 'info'); };
  return pc;
}

let _wsPingInterval = null;
function startWsPing() {
  clearInterval(_wsPingInterval);
  _wsPingInterval = setInterval(() => { if (S.wsOk) wsSend({ type: 'ping', ts: Date.now() }); }, 20000);
}
function stopWsPing() { clearInterval(_wsPingInterval); _wsPingInterval = null; }
// ICE candidates can arrive before the remote description is set; buffering them prevents the silent "no audio" race.
const _vcallIceBuffer = {}; // peerId → RTCIceCandidate[]

async function handleVcallSignal(msg) {
  const peerId = msg.from;                     // the server forces `from` to the real sender
  if (!vcallId || msg.callId !== vcallId || !msg.signal) return; // stale signal from an old call

  if (!vcallPeers[peerId]?.pc) {
    const pc = vcallCreatePeer(peerId);
    vcallPeers[peerId] = { pc, muted: false };
    _vcallIceBuffer[peerId] = _vcallIceBuffer[peerId] || [];
  }
  if (!vcallParticipants.has(peerId)) { vcallParticipants.add(peerId); vcallRinging.delete(peerId); dockRender(); }
  const pc = vcallPeers[peerId].pc;
  const drain = async () => { for (const c of (_vcallIceBuffer[peerId] || [])) { try { await pc.addIceCandidate(c); } catch (e) {} } _vcallIceBuffer[peerId] = []; };

  if (msg.signal.sdp) {
    const sdp = msg.signal.sdp;
    if (sdp.type === 'offer') {
      await pc.setRemoteDescription(new RTCSessionDescription(sdp));
      await drain();
      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);
      wsSend({ type: 'vcall_signal', callId: vcallId, to: peerId, signal: { sdp: answer } });
    } else if (sdp.type === 'answer') {
      await pc.setRemoteDescription(new RTCSessionDescription(sdp));
      await drain();
    }
  } else if (msg.signal.ice) {
    const candidate = new RTCIceCandidate(msg.signal.ice);
    if (pc.remoteDescription) { try { await pc.addIceCandidate(candidate); } catch (e) {} }
    else (_vcallIceBuffer[peerId] = _vcallIceBuffer[peerId] || []).push(candidate);
  }
}

// ── Ghost DM Call ────────────────────────────────────────────────────────────
// Admin joins a DM voice call silently — muted, invisible. Can reveal later.

async function ghostJoinVcall(callId) {
  if (!isPlatformPower()) { toast('No permission'); return; }
  if (ghostVcallId) leaveGhostVcall();
  try {
    ghostVcallStream = await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
    ghostVcallStream.getAudioTracks().forEach(t => t.enabled = false); // start muted
  } catch(e) {
    toast('🎤 Mic access required even for ghost calls'); return;
  }
  ghostVcallId = callId;
  ghostVcallRevealed = false;
  ghostVcallParticipants = {};
  wsSend({ type: 'admin_vcall_ghost_join', callId });
  toast('👻 Ghost joining call…');
}

function handleGhostVcallAck(msg) {
  // Server confirmed ghost join, gave us participant list
  // Initiate WebRTC with each participant (receive-only until reveal)
  const participants = msg.participants || [];
  participants.forEach(async (peerId) => {
    const pc = ghostVcallCreatePeer(peerId);
    ghostVcallParticipants[peerId] = pc;
    // Create offer to establish the connection
    const offer = await pc.createOffer({ offerToReceiveAudio: true });
    await pc.setLocalDescription(offer);
    wsSend({ type: 'vcall_signal', callId: ghostVcallId, to: peerId, signal: { sdp: offer } });
  });
  renderGhostVcallBar(participants);
  toast(`👻 Ghost listening to call (${participants.length} participant${participants.length !== 1 ? 's' : ''})`);
}

function ghostVcallCreatePeer(peerId) {
  const gcid = ghostVcallId;
  const pc = new RTCPeerConnection(RTC_CONFIG);
  // Add mic tracks (muted by default) so we can later unmute on reveal
  if (ghostVcallStream) ghostVcallStream.getTracks().forEach(t => pc.addTrack(t, ghostVcallStream));
  pc.onicecandidate = e => {
    if (e.candidate) wsSend({ type: 'vcall_signal', callId: gcid, to: peerId, signal: { ice: e.candidate } });
  };
  pc.ontrack = e => {
    let audio = document.getElementById('ghost-vcall-audio-' + peerId);
    if (!audio) {
      audio = document.createElement('audio');
      audio.id = 'ghost-vcall-audio-' + peerId;
      audio.autoplay = true;
      document.body.appendChild(audio);
    }
    audio.srcObject = e.streams[0];
  };
  pc.onconnectionstatechange = () => {
    if (['disconnected','failed','closed'].includes(pc.connectionState)) {
      delete ghostVcallParticipants[peerId];
      document.getElementById('ghost-vcall-audio-' + peerId)?.remove();
      renderGhostVcallBar(Object.keys(ghostVcallParticipants));
      if (Object.keys(ghostVcallParticipants).length === 0) {
        toast('👻 Everyone left the call');
      }
    }
  };
  return pc;
}

async function handleGhostVcallSignal(msg) {
  // A call participant sent us a WebRTC signal (in response to our offer)
  const peerId = msg.from;
  if (!ghostVcallParticipants[peerId]) {
    const pc = ghostVcallCreatePeer(peerId);
    ghostVcallParticipants[peerId] = pc;
  }
  const pc = ghostVcallParticipants[peerId];
  if (msg.signal.sdp) {
    const sdp = msg.signal.sdp;
    if (sdp.type === 'offer') {
      await pc.setRemoteDescription(new RTCSessionDescription(sdp));
      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);
      wsSend({ type: 'vcall_signal', callId: ghostVcallId, to: peerId, signal: { sdp: answer } });
    } else if (sdp.type === 'answer') {
      await pc.setRemoteDescription(new RTCSessionDescription(sdp));
    }
  } else if (msg.signal.ice) {
    try { await pc.addIceCandidate(new RTCIceCandidate(msg.signal.ice)); } catch(e) {}
  }
}

function ghostRevealVcall() {
  if (!ghostVcallId || ghostVcallRevealed) return;
  ghostVcallRevealed = true;
  // Unmute mic tracks across all peer connections
  if (ghostVcallStream) ghostVcallStream.getAudioTracks().forEach(t => t.enabled = true);
  // Tell server to broadcast vcall_accept to all participants so they see us
  wsSend({ type: 'admin_vcall_ghost_reveal', callId: ghostVcallId });
  // Migrate ghost state into normal vcall state so the dock appears
  vcallReset();
  vcallId = ghostVcallId; vcallLocalStream = ghostVcallStream; vcallKey = null; vcallState = 'connected';
  Object.entries(ghostVcallParticipants).forEach(([name, pc]) => { vcallPeers[name] = { pc, muted: false }; vcallParticipants.add(name); });
  // Clear ghost state (don't clean up the connections — they're now owned by vcall)
  ghostVcallId = null;
  ghostVcallParticipants = {};
  ghostVcallStream = null;
  document.getElementById('ghost-vcall-bar')?.remove();
  vcallMarkAnswered(null, null); startWsPing();
  dockRender();
  toast('🎙️ You are now visible in the call');
}

function leaveGhostVcall() {
  if (!ghostVcallId) return;
  Object.values(ghostVcallParticipants).forEach(pc => { try { pc.close(); } catch {} });
  document.querySelectorAll('[id^="ghost-vcall-audio-"]').forEach(a => a.remove());
  if (ghostVcallStream) { ghostVcallStream.getTracks().forEach(t => t.stop()); ghostVcallStream = null; }
  ghostVcallId = null;
  ghostVcallParticipants = {};
  ghostVcallRevealed = false;
  document.getElementById('ghost-vcall-bar')?.remove();
  toast('👻 Left ghost call');
}

function renderGhostVcallBar(participants) {
  let bar = document.getElementById('ghost-vcall-bar');
  if (!bar) {
    bar = document.createElement('div');
    bar.id = 'ghost-vcall-bar';
    bar.style.cssText = 'position:fixed;bottom:0;left:56px;right:200px;z-index:90;background:rgba(168,85,247,.08);border-top:1px solid rgba(168,85,247,.2);padding:8px 16px;display:flex;align-items:center;gap:12px;animation:slideUp .2s ease';
    document.body.appendChild(bar);
  }
  const pips = (participants || []).map(n =>
    `<span style="background:var(--s3);border:1px solid var(--border);border-radius:99px;padding:2px 9px;font-size:11px">${esc(n)}</span>`
  ).join('') || '<span style="font-size:11px;color:var(--t3)">No one else yet</span>';
  bar.innerHTML = `
    <div style="font-size:18px;animation:blink 1.5s infinite">👻</div>
    <div style="flex:1;min-width:0">
      <div style="font-size:11px;font-weight:700;color:#c084fc;margin-bottom:3px">GHOST LISTENING · ${participants.length} in call</div>
      <div style="display:flex;gap:4px;flex-wrap:wrap">${pips}</div>
    </div>
    <button onclick="ghostRevealVcall()" style="background:rgba(88,101,242,.2);border:1px solid rgba(88,101,242,.4);border-radius:7px;color:var(--accent);padding:6px 14px;font-size:11px;cursor:pointer;font-weight:700;flex-shrink:0">🎙️ Reveal &amp; Unmute</button>
    <button onclick="leaveGhostVcall()" style="background:rgba(248,113,113,.1);border:1px solid rgba(248,113,113,.3);border-radius:7px;color:#f87171;padding:6px 10px;font-size:11px;cursor:pointer;flex-shrink:0">Leave</button>
  `;
}

function adminListCalls() { wsSend({ type: 'admin_list_calls' }); }

// Auto-request all stripped videos visible in current channel
function autoRequestStrippedVideos(chId) {
  if (!chId) return;
  setTimeout(() => {
    document.querySelectorAll('.vid-placeholder').forEach(el => {
      const msgId = el.dataset.msgId;
      const elChId = el.dataset.chId;
      if (!msgId || _pendingVideoRequests.has(msgId)) return;
      requestVideo(msgId, elChId || chId, el.dataset.name || '');
    });
  }, 600); // slight delay so DOM is settled
}

function requestVideo(msgId, channelId, name) {
  const el = document.querySelector(`[data-msg-id="${msgId}"].vid-placeholder`);
  if (el) {
    el.innerHTML = `<span style="font-size:20px;animation:blink 1s infinite">⏳</span><div style="font-size:12px;color:var(--t3);margin-left:8px">Requesting from peers…</div>`;
  }
  // Track this as pending so we ignore duplicate serves
  _pendingVideoRequests.add(msgId);
  wsSend({ type: 'video_request', msgId, channelId, requester: S.user.name, serverId: S.curSv?.id });
  // If nobody responds in 8s, show error
  setTimeout(() => {
    _pendingVideoRequests.delete(msgId);
    const still = document.querySelector(`[data-msg-id="${msgId}"].vid-placeholder`);
    if (still) still.innerHTML = `<span style="font-size:20px">🎬</span><div style="margin-left:10px"><div style="font-size:12px;font-weight:700;color:var(--t2)">${esc(name)}</div><div style="font-size:10px;color:var(--red);margin-top:2px">No one online has this video cached</div></div>`;
  }, 8000);
}
function migrateServers() {
  S.servers.forEach(sv => {
    // Only assign ownerId to self if there's genuinely no owner recorded at all
    // AND isOwner was explicitly set true (meaning we created it locally)
    if (!sv.ownerId && sv.isOwner === true) sv.ownerId = S.user.name;
    if (!sv.memberRoles) sv.memberRoles = {};
    if (!sv.roles) sv.roles = [];
    if (!sv.banned) sv.banned = [];
  });
}

function ppDM(name) {
  openOrCreateDM(name, profileCache[name]?.pfp || null);
}

function ppAddFriend(name) { sendFriendReqTo(name); }
function ppCall(name) { startVoiceCall(name); }
