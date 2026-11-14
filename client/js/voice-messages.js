// ══════════════════════════════════════════════
// VOICE MESSAGES
// ══════════════════════════════════════════════
let vmStream = null, vmRecorder = null, vmChunks = [], vmTimer = null, vmSeconds = 0;

function startVoiceRec() {
  if (vmRecorder) return;
  if (!S.curCh) { toast('Select a channel first'); return; }
  if (!canSendInChannel(S.curSv, S.curCh)) { toast("🔒 You don't have permission to send messages in this channel"); return; }
  navigator.mediaDevices.getUserMedia({ audio: true }).then(stream => {
    vmStream = stream;
    vmChunks = []; vmSeconds = 0;
    vmRecorder = new MediaRecorder(stream);
    vmRecorder.ondataavailable = e => vmChunks.push(e.data);
    vmRecorder.onstop = () => {
      const blob = new Blob(vmChunks, { type: 'audio/webm' });
      const reader = new FileReader();
      reader.onload = ev => {
        const dur = vmSeconds;
        const msg = { id: uid(), channelId: S.curCh.id, serverId: S.curSv?.id,
          author: S.user.name, authorTag: S.user.tag, authorColor: S.user.color,
          text: '', voiceMsg: ev.target.result, voiceDur: dur,
          attachments: [], ts: Date.now(), reactions: [] };
        // Check size — base64 audio should be small but guard against huge recordings
        if (ev.target.result.length > 3_000_000) {
          toast('⚠️ Voice message too large — keep it under ~30 seconds'); return;
        }
        addMsg(msg); renderMsgs(msg.channelId); wsSend({type:'message',...msg});
      };
      reader.readAsDataURL(blob);
      stream.getTracks().forEach(t => t.stop()); vmStream = null;
      clearInterval(vmTimer); vmTimer = null;
      document.getElementById('vm-recording').style.display = 'none';
      vmRecorder = null;
    };
    vmRecorder.start();
    document.getElementById('vm-recording').style.display = 'flex';
    vmTimer = setInterval(() => {
      vmSeconds++;
      const m = Math.floor(vmSeconds/60), s = vmSeconds%60;
      document.getElementById('vm-rec-time').textContent = m+':'+(s<10?'0':'')+s;
      if (vmSeconds >= 120) stopVoiceRec(); // 2 min max
    }, 1000);
    toast('🎙️ Recording... release to send');
  }).catch(() => toast('Microphone access denied'));
}

function stopVoiceRec() {
  if (vmRecorder && vmRecorder.state !== 'inactive') vmRecorder.stop();
}

function buildVoiceMsg(m) {
  const dur = m.voiceDur || 0;
  const mm = Math.floor(dur/60), ss = dur%60;
  return `<div class="vm-msg" onclick="playVoiceMsg('${m.id}')">
    <div class="vm-play">▶</div>
    <div style="flex:1">
      <div style="font-size:11px;color:var(--t3);margin-bottom:2px">Voice message</div>
      <div style="background:var(--border2);height:3px;border-radius:3px;overflow:hidden"><div id="vmp-${m.id}" style="height:100%;background:var(--accent);width:0%;transition:width .1s"></div></div>
    </div>
    <div class="vm-dur">${mm}:${ss<10?'0':''}${ss}</div>
  </div>`;
}

const vmAudios = {};
const _attAudios = {};
function playAttAudio(aid, url, btn) {
  if (_attAudios[aid]) {
    _attAudios[aid].pause();
    delete _attAudios[aid];
    btn.querySelector('.play-icon').style.display = '';
    btn.querySelector('.pause-icon').style.display = 'none';
    return;
  }
  const audio = new Audio(url);
  _attAudios[aid] = audio;
  const prog = document.getElementById(aid + '-prog');
  const timeEl = document.getElementById(aid + '-time');
  audio.ontimeupdate = () => {
    if (prog) prog.style.width = (audio.currentTime / (audio.duration||1) * 100) + '%';
    if (timeEl) { const s = Math.floor(audio.currentTime); timeEl.textContent = Math.floor(s/60)+':'+(s%60<10?'0':'')+(s%60); }
  };
  audio.onended = () => {
    delete _attAudios[aid];
    if (prog) prog.style.width = '0%';
    btn.querySelector('.play-icon').style.display = '';
    btn.querySelector('.pause-icon').style.display = 'none';
  };
  btn.querySelector('.play-icon').style.display = 'none';
  btn.querySelector('.pause-icon').style.display = '';
  audio.play();
}
function playVoiceMsg(msgId) {
  const msgs = S.messages[S.curCh?.id] || Object.values(S.messages).flat();
  const m = msgs.find(x => x.id === msgId); if (!m || !m.voiceMsg) return;
  if (vmAudios[msgId]) { vmAudios[msgId].pause(); delete vmAudios[msgId]; return; }
  const audio = new Audio(m.voiceMsg);
  vmAudios[msgId] = audio;
  const bar = document.getElementById('vmp-'+msgId);
  audio.ontimeupdate = () => { if (bar) bar.style.width = (audio.currentTime/audio.duration*100)+'%'; };
  audio.onended = () => { delete vmAudios[msgId]; if (bar) bar.style.width='0%'; };
  audio.play();
}
