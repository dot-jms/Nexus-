// ══════════════════════════════════════════════
// VOICE CHANNELS — WebRTC
// ══════════════════════════════════════════════
const vcPeers = {};      // peerId -> RTCPeerConnection
const vcStreams = {};     // peerId -> MediaStream (remote)
let vcLocalStream = null;
let vcChannelId = null;
let vcMuted = false;

// ── Ghost Voice Call ─────────────────────────────────────────────────────────
// Admin can silently observe a voice channel without being seen.
// ghostVcChannelId: which channel we're ghost-listening to
// ghostVcMembers: members currently visible in that channel (from server ack + join/leave events)
// ghostVcRevealed: true once we've unmuted and become visible
let ghostVcChannelId = null;
let ghostVcMembers = {};  // name → true
let ghostVcRevealed = false;
let ghostVcStream = null;

async function joinVoiceGhost(channelId) {
  if (!isPlatformPower()) { toast('No permission for ghost calls'); return; }
  if (ghostVcChannelId) leaveVoiceGhost();
  // Get microphone silently (for listening only — muted by default)
  try {
    ghostVcStream = await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
    ghostVcStream.getAudioTracks().forEach(t => t.enabled = false); // start muted
  } catch(e) {
    toast('🎤 Mic access denied — ghost call requires mic permission even when muted');
    return;
  }
  ghostVcChannelId = channelId;
  ghostVcRevealed = false;
  ghostVcMembers = {};
  wsSend({ type: 'voice_ghost_join', channelId, user: S.user.name, serverId: S.curSv?.id });
  toast('👻 Ghost listening to voice channel…');
}

function handleGhostVoiceAck(msg) {
  if (!ghostVcChannelId) return;
  // Server tells us who's in the channel right now
  (msg.members || []).forEach(m => { ghostVcMembers[m] = true; });
  renderGhostCallBar();
}

function leaveVoiceGhost() {
  if (!ghostVcChannelId) return;
  if (ghostVcRevealed) {
    // If we revealed ourselves, send a real leave
    wsSend({ type: 'voice_leave', channelId: ghostVcChannelId, user: S.user.name });
  }
  if (ghostVcStream) { ghostVcStream.getTracks().forEach(t => t.stop()); ghostVcStream = null; }
  // Close any WebRTC peer connections created for ghost listening
  Object.values(vcPeers).forEach(pc => { try { pc.close(); } catch {} });
  Object.keys(vcPeers).forEach(k => delete vcPeers[k]);
  Object.keys(vcStreams).forEach(k => delete vcStreams[k]);
  document.querySelectorAll('.vc-audio').forEach(a => a.remove());
  ghostVcChannelId = null;
  ghostVcMembers = {};
  ghostVcRevealed = false;
  document.getElementById('ghost-call-bar')?.remove();
  toast('👻 Left ghost call');
}

function ghostReveal() {
  if (!ghostVcChannelId || ghostVcRevealed) return;
  ghostVcRevealed = true;
  // Enable mic
  if (ghostVcStream) ghostVcStream.getAudioTracks().forEach(t => t.enabled = true);
  // Hand off to the real voice channel system
  vcLocalStream = ghostVcStream;
  vcChannelId = ghostVcChannelId;
  vcMuted = false;
  // Broadcast real join
  wsSend({ type: 'voice_reveal', channelId: ghostVcChannelId, serverId: S.curSv?.id });
  // Show normal voice bar
  document.getElementById('voice-bar').style.display = '';
  renderVoiceMembers();
  // Remove ghost bar
  document.getElementById('ghost-call-bar')?.remove();
  toast('🎙️ You are now visible in the voice channel');
}

function renderGhostCallBar() {
  let bar = document.getElementById('ghost-call-bar');
  if (!bar) {
    bar = document.createElement('div');
    bar.id = 'ghost-call-bar';
    bar.style.cssText = 'position:fixed;bottom:0;left:0;right:0;z-index:180;background:rgba(168,85,247,.12);border-top:1px solid rgba(168,85,247,.25);padding:8px 14px;display:flex;align-items:center;gap:10px;font-size:12px';
    document.body.appendChild(bar);
  }
  const memberNames = Object.keys(ghostVcMembers);
  const memberPips = memberNames.length
    ? memberNames.map(n => `<span style="background:var(--s3);border:1px solid var(--border);border-radius:99px;padding:2px 8px;font-size:11px">${esc(n)}</span>`).join('')
    : '<span style="color:var(--t3);font-size:11px">No one else in call</span>';
  bar.innerHTML = `
    <div style="font-size:16px;animation:blink 1.5s infinite">👻</div>
    <div style="flex:1;min-width:0">
      <div style="font-weight:700;color:#c084fc;font-size:11px">GHOST LISTENING · ${memberNames.length} member(s)</div>
      <div style="display:flex;gap:4px;flex-wrap:wrap;margin-top:3px">${memberPips}</div>
    </div>
    <button onclick="ghostReveal()" style="background:rgba(108,99,255,.2);border:1px solid rgba(108,99,255,.4);border-radius:6px;color:var(--accent);padding:5px 12px;font-size:11px;cursor:pointer;font-weight:700">🎙️ Reveal &amp; Unmute</button>
    <button onclick="leaveVoiceGhost()" style="background:rgba(248,113,113,.15);border:1px solid rgba(248,113,113,.3);border-radius:6px;color:#f87171;padding:5px 10px;font-size:11px;cursor:pointer">Leave</button>
  `;
}

const RTC_CONFIG = {
  iceServers: [
    // STUN — used for direct P2P when both peers are on open networks
    { urls: 'stun:stun.l.google.com:19302' },
    { urls: 'stun:stun1.l.google.com:19302' },
    { urls: 'stun:stun2.l.google.com:19302' },
    { urls: 'stun:stun3.l.google.com:19302' },
    // TURN — required when NAT/firewall blocks direct P2P (most real networks)
    // Using free public TURN servers from Open Relay Project
    { urls: 'turn:openrelay.metered.ca:80',      username: 'openrelayproject', credential: 'openrelayproject' },
    { urls: 'turn:openrelay.metered.ca:443',     username: 'openrelayproject', credential: 'openrelayproject' },
    { urls: 'turn:openrelay.metered.ca:443?transport=tcp', username: 'openrelayproject', credential: 'openrelayproject' },
  ],
  iceCandidatePoolSize: 10,
  bundlePolicy: 'max-bundle',
  rtcpMuxPolicy: 'require',
};

async function joinVoice(channelId) {
  if (vcChannelId === channelId) return; // already in
  leaveVoice(); // clean up previous
  try {
    vcLocalStream = await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
  } catch(e) {
    toast('🎤 Microphone access denied — cannot join voice');
    return;
  }
  vcChannelId = channelId;
  document.getElementById('voice-bar').style.display = '';
  renderVoiceMembers();
  // Tell server we joined this voice channel
  wsSend({ type: 'voice_join', channelId, user: S.user.name, serverId: S.curSv?.id });
  toast('🎙️ Joined voice channel');
}

function leaveVoice() {
  if (!vcChannelId) return;
  wsSend({ type: 'voice_leave', channelId: vcChannelId, user: S.user.name });
  // Close all peer connections
  Object.values(vcPeers).forEach(pc => pc.close());
  Object.keys(vcPeers).forEach(k => delete vcPeers[k]);
  Object.keys(vcStreams).forEach(k => delete vcStreams[k]);
  if (vcLocalStream) { vcLocalStream.getTracks().forEach(t => t.stop()); vcLocalStream = null; }
  vcChannelId = null; vcMuted = false;
  document.getElementById('voice-bar').style.display = 'none';
  document.getElementById('voice-members').innerHTML = '';
  // Remove any audio elements
  document.querySelectorAll('.vc-audio').forEach(a => a.remove());
  toast('📵 Left voice channel');
}

function toggleVoiceMute() {
  if (!vcLocalStream) return;
  vcMuted = !vcMuted;
  vcLocalStream.getAudioTracks().forEach(t => t.enabled = !vcMuted);
  const btn = document.getElementById('voice-mute-btn');
  btn.style.color = vcMuted ? 'var(--red)' : 'var(--green)';
  btn.title = vcMuted ? 'Unmute' : 'Mute';
  btn.innerHTML = vcMuted
    ? `<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><line x1="1" y1="1" x2="23" y2="23"/><path d="M9 9v3a3 3 0 0 0 5.12 2.12M15 9.34V4a3 3 0 0 0-5.94-.6"/><path d="M17 16.95A7 7 0 0 1 5 12v-2m14 0v2a7 7 0 0 1-.11 1.23"/><line x1="12" y1="19" x2="12" y2="22"/></svg>`
    : `<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><rect x="9" y="2" width="6" height="12" rx="3"/><path d="M19 10a7 7 0 0 1-14 0"/><line x1="12" y1="19" x2="12" y2="22"/></svg>`;
  toast(vcMuted ? '🔇 Muted' : '🎙️ Unmuted');
}

function renderVoiceMembers() {
  const el = document.getElementById('voice-members');
  // Show local user + any peers we have streams for
  const members = [S.user.name, ...Object.keys(vcStreams)];
  el.innerHTML = members.map(name => {
    const isSelf = name === S.user.name;
    const col = S.user.name === name ? S.user.color : (COLORS[hash(name)%COLORS.length]);
    const av = `<div style="width:28px;height:28px;border-radius:50%;background:${col};display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;color:#fff;flex-shrink:0;border:2px solid ${isSelf?'var(--green)':'var(--border2)'};">${name[0].toUpperCase()}</div>`;
    return `<div style="display:flex;align-items:center;gap:5px">${av}<span style="font-size:11px;font-weight:600;color:var(--t2)">${esc(name)}${isSelf&&vcMuted?' 🔇':''}</span></div>`;
  }).join('');
}

// WebRTC signalling — called when peer joins or offers
async function vcCreateOffer(peerId) {
  const pc = vcGetOrCreatePeer(peerId);
  const offer = await pc.createOffer();
  await pc.setLocalDescription(offer);
  wsSend({ type: 'voice_signal', channelId: vcChannelId, from: S.user.name, to: peerId, signal: { sdp: offer } });
}

function vcGetOrCreatePeer(peerId) {
  if (vcPeers[peerId]) return vcPeers[peerId];
  const pc = new RTCPeerConnection(RTC_CONFIG);
  vcPeers[peerId] = pc;
  // Add local tracks
  if (vcLocalStream) vcLocalStream.getTracks().forEach(t => pc.addTrack(t, vcLocalStream));
  // ICE candidates
  pc.onicecandidate = e => {
    if (e.candidate) {
      wsSend({ type: 'voice_signal', channelId: vcChannelId, from: S.user.name, to: peerId, signal: { ice: e.candidate } });
    }
  };
  // Remote stream
  pc.ontrack = e => {
    vcStreams[peerId] = e.streams[0];
    let audio = document.getElementById('vc-audio-' + peerId);
    if (!audio) {
      audio = document.createElement('audio');
      audio.id = 'vc-audio-' + peerId;
      audio.className = 'vc-audio';
      audio.autoplay = true;
      document.body.appendChild(audio);
    }
    audio.srcObject = e.streams[0];
    renderVoiceMembers();
  };
  pc.onconnectionstatechange = () => {
    if (pc.connectionState === 'disconnected' || pc.connectionState === 'failed' || pc.connectionState === 'closed') {
      delete vcPeers[peerId]; delete vcStreams[peerId];
      const audio = document.getElementById('vc-audio-' + peerId);
      if (audio) audio.remove();
      renderVoiceMembers();
    }
  };
  return pc;
}

async function handleVoiceSignal(msg) {
  const peerId = msg.from;
  if (msg.signal.sdp) {
    const pc = vcGetOrCreatePeer(peerId);
    const sdp = msg.signal.sdp;
    if (sdp.type === 'offer') {
      await pc.setRemoteDescription(new RTCSessionDescription(sdp));
      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);
      wsSend({ type: 'voice_signal', channelId: vcChannelId, from: S.user.name, to: peerId, signal: { sdp: answer } });
    } else if (sdp.type === 'answer') {
      await pc.setRemoteDescription(new RTCSessionDescription(sdp));
    }
  } else if (msg.signal.ice) {
    const pc = vcPeers[peerId];
    if (pc) { try { await pc.addIceCandidate(new RTCIceCandidate(msg.signal.ice)); } catch(e) {} }
  }
}
