// ══════════════════════════════════════════════
// CUSTOM SERVER EMOJIS
// ══════════════════════════════════════════════
let pendingEmojiImg = null;

function openCustomEmojis() {
  if (!S.curSv) return;
  if (!S.curSv.customEmojis) S.curSv.customEmojis = [];
  renderCustomEmojiList();
  pendingEmojiImg = null;
  document.getElementById('emoji-upload-preview').innerHTML = '';
  document.getElementById('custom-emoji-name').value = '';
  openM('custom-emoji-modal');
}

function renderCustomEmojiList() {
  const el = document.getElementById('custom-emoji-list');
  const emojis = S.curSv?.customEmojis || [];
  if (!emojis.length) { el.innerHTML = '<div style="font-size:12px;color:var(--t3)">No custom emojis yet</div>'; return; }
  el.innerHTML = emojis.map(e => {
    const img = e.data
      ? `<img src="${e.data}" class="custom-em" title=":${e.name}:">`
      : `<div style="width:36px;height:36px;background:var(--s3);border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:10px;color:var(--t3)" title=":${e.name}:">?</div>`;
    return `<div title=":${e.name}:" style="display:flex;flex-direction:column;align-items:center;gap:3px">${img}<div style="font-size:10px;color:var(--t3)">:${esc(e.name)}:</div></div>`;
  }).join('');
}

function onCustomEmojiImg(ev) {
  const f = ev.target.files[0]; if (!f) return;
  const reader = new FileReader();
  reader.onload = e => {
    pendingEmojiImg = e.target.result;
    document.getElementById('emoji-upload-preview').innerHTML = `<img src="${pendingEmojiImg}" style="width:48px;height:48px;border-radius:6px;object-fit:cover">`;
  };
  reader.readAsDataURL(f);
  ev.target.value = '';
}

function saveCustomEmoji() {
  if (!pendingEmojiImg) { toast('Pick an image first'); return; }
  const name = document.getElementById('custom-emoji-name').value.trim().toLowerCase().replace(/[^a-z0-9_]/g,'');
  if (!name) { toast('Enter an emoji name'); return; }
  if (!S.curSv.customEmojis) S.curSv.customEmojis = [];
  if (S.curSv.customEmojis.find(e => e.name === name)) { toast('Name already taken'); return; }
  S.curSv.customEmojis.push({ name, data: pendingEmojiImg });
  persist(); renderCustomEmojiList();
  wsSend({ type: 'custom_emoji_add', serverId: S.curSv.id, name, data: pendingEmojiImg });
  pendingEmojiImg = null;
  document.getElementById('emoji-upload-preview').innerHTML = '';
  document.getElementById('custom-emoji-name').value = '';
  toast('✅ :' + name + ': added!');
}

// Render custom emojis in messages
function fmtCustomEmoji(text) {
  const emojis = S.curSv?.customEmojis || [];
  return text.replace(/:([a-z0-9_]+):/g, (match, name) => {
    const e = emojis.find(x => x.name === name);
    if (!e) return match;
    if (e.data) return `<img src="${e.data}" style="width:32px;height:32px;vertical-align:middle;border-radius:4px;margin:0 1px" title=":${name}:">`;
    // Data not cached yet — request it p2p and show placeholder
    if (S.curSv) wsSend({ type: 'emoji_request', serverId: S.curSv.id, name, requester: S.user.name });
    return `<span style="display:inline-block;width:32px;height:32px;vertical-align:middle;background:var(--s3);border-radius:4px;font-size:10px;line-height:32px;text-align:center;margin:0 1px;color:var(--t3)" title=":${name}:">:${name.slice(0,3)}:</span>`;
  });
}
