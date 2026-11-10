// ── SOUNDS ──────────────────────────────────────────────────────────────────
// Drop any of these .mp3 files into the repo root and they'll play automatically.
// Missing files are silently ignored — no errors, no console noise.
const SOUNDS = {
  message:       'sfx-message.mp3',       // incoming channel message (not your own)
  mention:       'sfx-mention.mp3',       // someone @mentions you
  dm:            'sfx-dm.mp3',            // incoming DM
  dm_request:    'sfx-dm-request.mp3',    // DM request received
  friend_request:'sfx-friend-request.mp3',// friend request received
  friend_accept: 'sfx-friend-accept.mp3', // friend request accepted
  notif:         'sfx-notif.mp3',         // generic notification / toast
  server_join:   'sfx-server-join.mp3',   // you joined a server
  member_join:   'sfx-member-join.mp3',   // someone joined your current server
  member_leave:  'sfx-member-leave.mp3',  // someone left your current server
  kick:          'sfx-kick.mp3',          // you got kicked
  banned:        'sfx-banned.mp3',        // you got banned
  voice_join:    'sfx-voice-join.mp3',    // someone joined a voice channel
  voice_leave:   'sfx-voice-leave.mp3',   // someone left a voice channel
  vcall_invite:  'sfx-vcall-invite.mp3',  // incoming voice call
  vcall_accept:  'sfx-vcall-accept.mp3',  // your call was accepted
  vcall_decline: 'sfx-vcall-decline.mp3', // your call was declined
  vcall_end:     'sfx-vcall-end.mp3',     // call ended
  error:         'sfx-error.mp3',         // error / banned
};
const _audioCache = {};
function playSound(key) {
  const file = SOUNDS[key]; if (!file) return;
  try {
    if (!_audioCache[key]) {
      const a = new Audio(file);
      a.onerror = () => { _audioCache[key] = null; }; // file missing — silence it
      _audioCache[key] = a;
    }
    const a = _audioCache[key]; if (!a) return;
    a.currentTime = 0;
    a.play().catch(() => {}); // autoplay blocked? fine.
  } catch {}
}
