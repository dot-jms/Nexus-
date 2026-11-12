function handleIn(msg) {
  // BUG 2 FIX: Guard entire handler against unidentified state.
  // WS messages can arrive before identify completes (e.g. server broadcasts during auth).
  // Whitelisted types that are safe before S.user is populated:
  const PRE_AUTH_SAFE = new Set(['auth_ok','auth_error','auth_required','maintenance','identified','user_pfp','pong','motd_update']);
  if (!S.user && !PRE_AUTH_SAFE.has(msg.type)) return;
  switch(msg.type) {
    case 'message':
      if(msg.author!==S.user.name){
        addMsg(msg);
        if(S.curCh?.id===msg.channelId) appendMsgDOM(msg); else markUnread(msg.channelId);
        if(msg.text?.includes('@'+S.user.name)){
          const sv=S.servers.find(s=>s.channels?.some(c=>c.id===msg.channelId));
          addNotif('🔔',msg.author+' mentioned you in '+(sv?.name||'a server'),()=>{if(sv)selectSv(sv.id);});
          playSound('mention');
        } else {
          playSound('message');
        }
      }
      break;
    case 'typing':
      if(msg.author!==S.user.name) showTyping(msg.author, msg.channelId);
      break;
    case 'role_assign': {
      // Update local server's memberRoles
      const sv = S.servers.find(s => s.id === msg.serverId);
      if (sv) {
        if (!sv.memberRoles) sv.memberRoles = {};
        if (msg.role === 'member') delete sv.memberRoles[msg.target];
        else sv.memberRoles[msg.target] = msg.role;
        persist();
        if (S.curSv?.id === msg.serverId) { renderMbs(); buildSvDropdown(); }
      }
      // Notify the person who got the role
      if (msg.target === S.user.name) {
        const roleName = msg.role === 'mod' ? 'Moderator' : msg.role === 'member' ? 'Member' : msg.role;
        const svName = S.servers.find(s=>s.id===msg.serverId)?.name || 'a server';
        addNotif('🛡', `You were made ${roleName} in ${svName}!`, () => { const sv=S.servers.find(s=>s.id===msg.serverId); if(sv)selectSv(sv.id); });
        toast(`🛡 You are now ${roleName} in ${svName}!`);
      }
      break;
    }
    case 'identified':
      // Server sends fresh account data — update role/pfp in case they changed
      clearTimeout(_identifyTimer); _identifyTimer = null; // ← handshake complete, cancel timeout
      dbg('← identified: backend sent ' + (msg.servers?.length||0) + ' server(s)', (msg.servers?.length ? 'ok' : 'warn'));
      // FIX #9: Flush any messages that were queued while we were offline
      setTimeout(_flushWsQueue, 100);
      if (msg.user) {
        S.user.systemRole = msg.user.systemRole || S.user.systemRole;
        S.user.coAdmin    = msg.user.coAdmin    ?? S.user.coAdmin;
        // pfp is sent separately via user_pfp — don't touch it here
        S.user.tag        = msg.user.tag        || S.user.tag;
        S.user.bio        = msg.user.bio        || S.user.bio;
        S.user.socials    = msg.user.socials    || S.user.socials;
        lsSet('nx-session', { token: S.token, user: S.user });
        updateUser();
      }
      // Merge server-side server list into local state
      {
        let svChanged = false;
        (msg.servers||[]).forEach(ss => {
          if (!S.servers.find(sv => sv.id === ss.id)) {
            // Server exists in backend but not locally — restore it
            S.servers.push({
              id: ss.id, name: ss.name, desc: ss.desc || '',
              color: ss.color || '#5865f2', icon: ss.icon || null,
              channels: ss.channels || [],
              isOwner: (ss.ownerId||'').toLowerCase() === (S.user.name||'').toLowerCase(),
              ownerId: ss.ownerId, memberCount: ss.memberCount || 1,
              createdAt: ss.createdAt || Date.now(), memberRoles: {}, roles: [], banned: [],
              isPublic: ss.isPublic !== false,
              pins: ss.pins || {},
              shorts: ss.shorts || [],
              customEmojis: (ss.customEmojiNames||[]).map(n => ({ name: n, data: null })),
            });
            svChanged = true;
          } else {
            // Update existing server with authoritative backend data
            const existing = S.servers.find(sv => sv.id === ss.id);
            if (existing) {
              if (ss.name)              existing.name        = ss.name;
              if (ss.desc !== undefined) existing.desc       = ss.desc;
              if (ss.color)             existing.color       = ss.color;
              if (ss.channels !== undefined) existing.channels = ss.channels; // always sync - empty array means all channels deleted
              if (ss.icon !== undefined) existing.icon       = ss.icon;
              if (ss.memberCount)       existing.memberCount = ss.memberCount;
              if (ss.isPublic !== undefined) existing.isPublic = ss.isPublic;
              // Always trust backend for ownerId — never let client-side value override
              if (ss.ownerId) existing.ownerId = ss.ownerId;
              existing.isOwner = (ss.ownerId||'').toLowerCase() === (S.user.name||'').toLowerCase();
              // Merge persisted pins — server is authoritative, client may have stale cache
              if (ss.pins) existing.pins = { ...(existing.pins||{}), ...ss.pins };
              // Merge shorts — server is authoritative for metadata
              if (ss.shorts?.length) {
                if (!existing.shorts) existing.shorts = [];
                const existingIds = new Set((existing.shorts||[]).map(s => s.id));
                ss.shorts.forEach(s => { if (!existingIds.has(s.id)) existing.shorts.push(s); });
              }
              // Restore custom emoji names — data will be fetched p2p when needed
              if (ss.customEmojiNames?.length) {
                if (!existing.customEmojis) existing.customEmojis = [];
                ss.customEmojiNames.forEach(name => {
                  if (!existing.customEmojis.find(e => e.name === name)) {
                    existing.customEmojis.push({ name, data: null }); // data=null means not yet loaded
                  }
                });
              }
              svChanged = true;
            }
          }
        });
        if (svChanged) {
          persist(); renderSvs();
          S.servers.forEach(sv => wsSend({type:'get_server_info', serverId:sv.id}));
          if (!S.curSv && S.servers.length) selectSv(S.servers[0].id);
        } else if (msg.servers?.length) {
          // Nothing changed structurally but still re-render to ensure UI is current
          renderSvs();
          if (!S.curSv && S.servers.length) selectSv(S.servers[0].id);
        }
      }
      // Retry any pending server creates that haven't been ACKed yet
      setTimeout(_retryPending, 200);
      // Restore DM contact list from server — server now sends dm_contacts proactively on identify,
      // but also request explicitly here as a fallback in case the identify response was large.
      _dmContactsLoading = true; renderDMs();
      wsSend({ type: 'fetch_dm_contacts' });
      // Re-register owned servers the backend doesn't know about
      // (only owners do this — members don't need to re-register joined servers)
      {
        const knownByServer = new Set((msg.servers||[]).map(s=>s.id));
        S.servers.forEach(sv => {
          const iAmOwner = (sv.ownerId||'').toLowerCase() === (S.user?.name||'').toLowerCase() || sv.isOwner === true;
          if (!knownByServer.has(sv.id) && iAmOwner) {
            console.log('[nexus] owned server missing from backend — re-registering:', sv.id, sv.name);
            dbg('⚠ owned server not in backend, re-registering: "' + sv.name + '"', 'warn');
            const reCreateMsg = {type:'server_create', serverId:sv.id, name:sv.name,
              desc:sv.desc||'', icon:null, color:sv.color||'#5865f2', isPublic:sv.isPublic!==false,
              memberCount:sv.memberCount||1, createdAt:sv.createdAt||Date.now(),
              channels:sv.channels||[], ownerId:sv.ownerId||S.user.name};
            _pendingServerCreates.set(sv.id, reCreateMsg);
            _savePending();
            setTimeout(()=>wsSend(reCreateMsg), 400);
          }
        });
      }
      break;
    case 'auth_required':
      dbg('✕ auth_required — session expired', 'err');
      toast('⚠️ Session expired — please sign in again');
      signOut();
      break;
    case 'server_create_ok':
      _pendingServerCreates.delete(msg.serverId);
      _pendingRetryCount.delete(msg.serverId);
      _savePending();
      console.log('[nexus] server_create confirmed by relay:', msg.serverId);
      dbg('✓ server saved to backend: ' + msg.serverId.slice(0,8), 'ok');
      break;
    case 'admin_accounts_list':
      if (isSystemAdmin()) {
        _adminAccounts = msg.accounts || [];
        renderAdminAccounts(_adminAccounts);
        const s = document.getElementById('admin-acct-search');
        if (s) s.value = '';
      }
      break;

    case 'admin_servers_list':
      _adminServers = msg.servers || [];
      renderAdminServers(_adminServers);
      break;

    case 'admin_bans_list':
      renderAdminBans(msg.bans || []);
      break;

    case 'admin_channel_history': {
      const viewBox = document.getElementById('admin-ch-view-result');
      if (!viewBox) break;
      const chMsgs = msg.messages || [];
      const viewChId = msg.channelId || document.getElementById('admin-view-ch-id')?.value?.trim() || '';
      if (!chMsgs.length) {
        viewBox.innerHTML = '<div style="font-size:11px;color:var(--t3)">No messages in this channel.</div>';
      } else {
        viewBox.innerHTML = chMsgs.slice(-80).map(m => {
          const ts = m.ts ? new Date(m.ts).toLocaleTimeString('en',{hour:'2-digit',minute:'2-digit'}) : '';
          const hasImg = (m.attachments||[]).some(a => a.type === 'image');
          const msgId = m.id || '';
          // Clicking the message ID fills the delete/edit fields automatically
          const idClick = msgId ? `onclick="document.getElementById('admin-del-msg-ch').value='${esc(viewChId)}';document.getElementById('admin-del-msg-id').value='${esc(msgId)}';navigator.clipboard?.writeText('${esc(msgId)}');_adminMsgResult('📋 Copied message ID — delete/edit fields filled.','var(--accent)')"` : '';
          return `<div style="padding:4px 0;border-bottom:1px solid var(--border);font-size:11px;display:flex;gap:5px;align-items:baseline;flex-wrap:wrap">
            <span style="color:var(--t3);font-size:9px;font-family:'DM Mono',monospace;cursor:pointer;flex-shrink:0;background:var(--s2);padding:1px 4px;border-radius:3px" title="Click to copy ID + fill edit fields" ${idClick}>${esc(msgId.slice(-8))}</span>
            <span style="color:${esc(m.authorColor||'var(--accent)')};font-weight:700;flex-shrink:0">${esc(m.author||'?')}</span>
            <span style="color:var(--t3);font-size:10px;flex-shrink:0">${ts}</span>
            ${m.text ? `<span style="flex:1;min-width:0;word-break:break-word">${esc(m.text.slice(0,200))}</span>` : ''}
            ${hasImg ? `<span style="color:var(--t3);font-size:10px">[img]</span>` : ''}
          </div>`;
        }).join('');
      }
      viewBox.style.display = 'block';
      const mrEl = document.getElementById('admin-msgs-result');
      if (mrEl) { mrEl.innerHTML = `Showing last ${Math.min(chMsgs.length,80)} of ${chMsgs.length} message(s). <span style="color:var(--accent)">Click a message ID (gray tag) to copy it and auto-fill the delete/edit fields.</span>`; mrEl.style.color='var(--t3)'; }
      break;
    }

    case 'channel_wiped':
      if (msg.channelId && S.messages[msg.channelId]) {
        S.messages[msg.channelId] = [];
        if (S.curCh?.id === msg.channelId) renderMsgs(msg.channelId);
        toast(`🧹 Channel wiped by ${msg.by}`);
      }
      { const mrEl = document.getElementById('admin-msgs-result'); if (mrEl) { mrEl.textContent = '✅ Channel wiped.'; mrEl.style.color='var(--green)'; } }
      break;

    case 'channel_lock_update': {
      // Show/hide lock badge on current channel header
      if (S.curCh?.id === msg.channelId) {
        let lockBadge = document.getElementById('ch-lock-badge');
        if (msg.locked) {
          if (!lockBadge) {
            lockBadge = document.createElement('span');
            lockBadge.id = 'ch-lock-badge';
            lockBadge.style.cssText = 'font-size:10px;background:rgba(248,113,113,.15);color:#f87171;border:1px solid rgba(248,113,113,.3);border-radius:99px;padding:1px 7px;margin-left:6px;vertical-align:middle';
            lockBadge.textContent = '🔒 Locked';
            document.getElementById('ch-name')?.appendChild(lockBadge);
          }
        } else {
          lockBadge?.remove();
        }
        // Block the message input when locked (unless admin)
        const inp = document.getElementById('msg-in');
        if (inp) { inp.disabled = msg.locked && !isPlatformPower(); inp.placeholder = msg.locked ? '🔒 Channel is locked' : 'Message #' + (S.curCh?.name||''); }
      }
      { const mrEl = document.getElementById('admin-msgs-result'); if (mrEl) { mrEl.textContent = `✅ Channel ${msg.locked?'locked':'unlocked'}.`; mrEl.style.color='var(--green)'; } }
      break;
    }

    case 'admin_purge':
      // Remove purged user's messages from local cache
      if (msg.target && msg.serverId === S.curSv?.id) {
        Object.keys(S.messages).forEach(chId => {
          if (S.messages[chId]) S.messages[chId] = S.messages[chId].filter(m => m.author !== msg.target);
        });
        if (S.curCh) renderMsgs(S.curCh.id);
        toast(`🧹 Messages from ${msg.target} purged by admin`);
      }
      { const mrEl = document.getElementById('admin-msgs-result'); if (mrEl) { mrEl.textContent='✅ Messages purged.'; mrEl.style.color='var(--green)'; } }
      break;

    case 'kicked_from_server':
      if (msg.serverId) {
        S.servers = S.servers.filter(s => s.id !== msg.serverId);
        persist();
        if (S.curSv?.id === msg.serverId) {
          S.curSv = null; S.curCh = null;
          renderSvs();
          if (S.servers.length) selectSv(S.servers[0].id);
          else document.getElementById('ch-area').style.display = 'none';
        } else { renderSvs(); }
        toast('👢 You were removed from a server by an admin');
      }
      break;

    case 'server_ownership_transfer': {
      let toSv = S.servers.find(sv => sv.id === msg.serverId);
      const iAmNewOwner = (msg.newOwner||'').toLowerCase() === (S.user?.name||'').toLowerCase();
      if (!toSv && iAmNewOwner && msg.server) {
        // Server transferred to me and I didn't have it — add it now
        toSv = { ...msg.server, ownerId: msg.newOwner, isOwner: true };
        S.servers.push(toSv);
      }
      if (toSv) {
        toSv.ownerId = msg.newOwner;
        toSv.isOwner = iAmNewOwner;
        persist(); renderSvs();
        if (iAmNewOwner) {
          toast(`👑 You are now the owner of "${toSv.name}"!`);
          // Fetch full server info so channels load
          wsSend({ type: 'get_server_info', serverId: toSv.id });
        }
      }
      if (msg.by === S.user?.name) toast(`✅ Ownership transferred to ${msg.newOwner}`);
      break;
    }

    case 'admin_frozen_list':
      renderAdminFrozen(msg.frozen || []);
      break;

    case 'admin_online_list':
      renderAdminOnline(msg.users || []);
      break;

    case 'admin_stats':
      renderAdminStats(msg.stats || {});
      break;

    case 'server_renamed': {
      const rnSv = S.servers.find(sv => sv.id === msg.serverId);
      if (rnSv) {
        rnSv.name = msg.name;
        if (S.curSv?.id === msg.serverId) S.curSv.name = msg.name;
        persist(); renderSvs();
        if (S.curSv?.id === msg.serverId) document.getElementById('sv-nm').textContent = msg.name;
      }
      const svRes = document.getElementById('admin-sv-result');
      if (svRes) { svRes.textContent = `✅ Server renamed to "${msg.name}".`; svRes.style.color='var(--green)'; }
      break;
    }

    case 'server_channel_added': {
      const acSv = S.servers.find(sv => sv.id === msg.serverId);
      if (acSv) {
        if (!acSv.channels) acSv.channels = [];
        acSv.channels.push(msg.channel);
        persist();
        if (S.curSv?.id === msg.serverId) { S.curSv.channels = acSv.channels; renderChs(); }
      }
      const svRes = document.getElementById('admin-sv-result');
      if (svRes) { svRes.textContent = `✅ Channel added.`; svRes.style.color='var(--green)'; }
      break;
    }

    case 'server_channel_updated': {
      // Another client (or the server confirming our own change) updated a channel's properties
      const ucSv = S.servers.find(sv => sv.id === msg.serverId);
      if (ucSv && ucSv.channels) {
        const ucCh = ucSv.channels.find(c => c.id === msg.channelId);
        if (ucCh) {
          Object.assign(ucCh, msg.changes || {});
          persist();
          if (S.curSv?.id === msg.serverId) { S.curSv.channels = ucSv.channels; renderChs(); }
          // Update header if we're currently in this channel
          if (S.curCh?.id === msg.channelId) {
            Object.assign(S.curCh, msg.changes || {});
            if (msg.changes?.name) document.getElementById('ch-nm').textContent = msg.changes.name;
          }
        }
      }
      break;
    }

    case 'server_channel_deleted': {
      const dcSv = S.servers.find(sv => sv.id === msg.serverId);
      if (dcSv && dcSv.channels) {
        dcSv.channels = dcSv.channels.filter(c => c.id !== msg.channelId);
        persist();
        if (S.curSv?.id === msg.serverId) { S.curSv.channels = dcSv.channels; renderChs(); }
        if (S.curCh?.id === msg.channelId) { S.curCh = null; document.getElementById('ch-area').style.display = 'none'; }
      }
      const svRes = document.getElementById('admin-sv-result');
      if (svRes) { svRes.textContent = `✅ Channel deleted.`; svRes.style.color='var(--green)'; }
      break;
    }

    case 'server_updated': {
      const upSv = S.servers.find(sv => sv.id === msg.serverId);
      if (upSv) {
        if (msg.name !== undefined) upSv.name = msg.name;
        if (msg.desc !== undefined) upSv.desc = msg.desc;
        if (msg.icon !== undefined) upSv.icon = msg.icon;
        persist(); renderSvs();
      }
      break;
    }

    case 'account_frozen':
      // Show a persistent frozen banner — user can still use app but can't post
      {
        let fb = document.getElementById('frozen-banner');
        if (!fb) {
          fb = document.createElement('div');
          fb.id = 'frozen-banner';
          fb.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:999;background:rgba(96,165,250,.15);border-bottom:1px solid rgba(96,165,250,.3);padding:8px 16px;display:flex;align-items:center;gap:10px;font-size:13px';
          document.body.prepend(fb);
        }
        fb.innerHTML = `🧊 <strong>Your account has been frozen</strong> by an admin. Reason: ${esc(msg.reason||'No reason given')}. You can read but cannot send messages.`;
        S.frozen = true;
      }
      break;

    case 'account_unfrozen':
      document.getElementById('frozen-banner')?.remove();
      S.frozen = false;
      toast('✅ Your account has been unfrozen.');
      break;

    case 'force_logout':
      toast('🚪 You have been logged out by an admin.');
      setTimeout(() => signOut(), 1500);
      break;

    case 'motd_update':
      if (msg.text) {
        let motdBanner = document.getElementById('motd-banner');
        if (!motdBanner) {
          motdBanner = document.createElement('div');
          motdBanner.id = 'motd-banner';
          motdBanner.style.cssText = 'position:fixed;bottom:16px;right:16px;z-index:998;background:var(--s2);border:1px solid rgba(88,101,242,.4);border-radius:12px;padding:12px 16px;max-width:340px;box-shadow:0 4px 24px rgba(0,0,0,.4);font-size:13px';
          document.body.appendChild(motdBanner);
        }
        motdBanner.innerHTML = `<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px"><strong style="color:var(--accent)">📢 Message of the Day</strong><button onclick="document.getElementById('motd-banner')?.remove()" style="background:none;border:none;color:var(--t3);cursor:pointer;font-size:14px">✕</button></div><div style="color:var(--t2)">${esc(msg.text)}</div><div style="font-size:10px;color:var(--t3);margin-top:6px">— ${esc(msg.by||'Admin')}</div>`;
      } else {
        document.getElementById('motd-banner')?.remove();
      }
      break;

    case 'added_to_server':
      if (msg.server) {
        const sv = msg.server;
        if (!S.servers.find(s => s.id === sv.id)) {
          S.servers.push(sv);
          persist(); renderSvs();
          toast(`➕ You were added to "${sv.name}" by an admin`);
        }
      }
      break;

    case 'maintenance':
      // Server going into maintenance — show blocking screen
      {
        let mb = document.getElementById('maintenance-block');
        if (!mb) {
          mb = document.createElement('div');
          mb.id = 'maintenance-block';
          mb.style.cssText = 'position:fixed;inset:0;z-index:9999;background:var(--bg);display:flex;flex-direction:column;align-items:center;justify-content:center;gap:16px';
          document.body.appendChild(mb);
        }
        mb.innerHTML = `<div style="font-size:48px">🔧</div><div style="font-size:22px;font-weight:800">Maintenance Mode</div><div style="font-size:14px;color:var(--t3);max-width:360px;text-align:center">${esc(msg.message||'Nexus is undergoing maintenance. Please try again soon.')}</div>`;
      }
      break;

    case 'maintenance_update':
      if (!msg.enabled) {
        document.getElementById('maintenance-block')?.remove();
        if (msg.by !== S.user?.name) toast('✅ Maintenance complete — platform is back online');
      } else {
        toast('⚠️ Maintenance mode enabled by admin');
      }
      break;

    case 'slowmode_update': {
      if (S.curCh?.id === msg.channelId) {
        const inp = document.getElementById('msg-in');
        let smBadge = document.getElementById('ch-slowmode-badge');
        if (msg.seconds > 0) {
          if (!smBadge) {
            smBadge = document.createElement('span');
            smBadge.id = 'ch-slowmode-badge';
            smBadge.style.cssText = 'font-size:10px;background:rgba(251,146,60,.15);color:#fb923c;border:1px solid rgba(251,146,60,.3);border-radius:99px;padding:1px 7px;margin-left:6px;vertical-align:middle';
            document.getElementById('ch-name')?.appendChild(smBadge);
          }
          smBadge.textContent = `🐌 ${msg.seconds}s slowmode`;
        } else {
          smBadge?.remove();
        }
      }
      const mrEl = document.getElementById('admin-msgs-result');
      if (mrEl) { mrEl.textContent = msg.seconds > 0 ? `✅ Slowmode set to ${msg.seconds}s.` : '✅ Slowmode disabled.'; mrEl.style.color='var(--green)'; }
      break;
    }

    case 'admin_nuke':
      // Remove nuked user from all local state
      if (msg.target) {
        S.servers = S.servers.filter(sv => sv.ownerId !== msg.target);
        S.dms = (S.dms||[]).filter(d => d.name !== msg.target);
        persist(); renderSvs();
        if (msg.by === S.user?.name) toast(`💥 Account '${msg.target}' nuked.`);
        else if (msg.target === S.user?.name) { toast('Your account has been deleted.'); setTimeout(() => signOut(), 2000); }
      }
      break;

    case 'admin_notes_data':
      renderAdminNotes(msg.target, msg.notes || []);
      break;

    case 'admin_audit_log':
      renderAdminAuditLog(msg.entries || []);
      break;

    case 'admin_user_servers':
      renderAdminUserServers(msg.target, msg.servers || []);
      break;

    case 'admin_channel_export':
      adminDownloadExport(msg);
      break;

    case 'platform_announcement': {
      // Show as a prominent toast + notification
      let annBanner = document.getElementById('platform-announcement');
      if (annBanner) annBanner.remove();
      annBanner = document.createElement('div');
      annBanner.id = 'platform-announcement';
      annBanner.style.cssText = 'position:fixed;top:60px;left:50%;transform:translateX(-50%);z-index:9998;background:linear-gradient(135deg,rgba(88,101,242,.9),rgba(192,132,252,.9));border-radius:12px;padding:14px 20px;max-width:420px;box-shadow:0 4px 32px rgba(0,0,0,.5);font-size:14px;color:#fff;text-align:center';
      annBanner.innerHTML = `<div style="font-weight:700;margin-bottom:4px">📢 Platform Announcement</div><div>${esc(msg.text)}</div><button onclick="this.parentElement.remove()" style="background:rgba(255,255,255,.2);border:none;border-radius:6px;color:#fff;padding:4px 12px;margin-top:8px;cursor:pointer;font-size:12px">Dismiss</button>`;
      document.body.appendChild(annBanner);
      setTimeout(() => annBanner?.remove(), 30000);
      break;
    }
    case 'dm_stubs': {
      // Restore DM conversations after cache clear — backend sends partner names + last msg
      let dmChanged = false;
      (msg.stubs || []).forEach(stub => {
        if (!stub.with || stub.with === S.user?.name) return;
        const existing = S.dms.find(d => d.name === stub.with);
        if (!existing) {
          S.dms.push({ id: uid(), name: stub.with, last: stub.last || '', lastTs: stub.ts || 0, status: 'accepted', pfp: profileCache[stub.with]?.pfp || null });
          dmChanged = true;
        }
      });
      if (dmChanged) { persist(); renderDMs(); }
      break;
    }
    case 'user_pfp':
      if (S.user) {
        // msg.pfp may be null — that means the server confirmed no pfp. Always apply.
        S.user.pfp = msg.pfp || null;
        lsSet('nx-session', { token: S.token, user: S.user });
        updateUser();
      }
      break;
    case 'friends_data':
      if (msg.friends?.length) {
        msg.friends.forEach(sf => {
          if (!S.friends.find(f => f.name === sf.name)) S.friends.push(sf);
        });
      }
      if (msg.friendRequests?.length) {
        msg.friendRequests.forEach(sr => {
          if (!S.friendReqs.find(r => r.name === sr.name)) S.friendReqs.push(sr);
        });
        const inReqs = S.friendReqs.filter(r => r.direction === 'in');
        document.getElementById('fr-badge').style.display = inReqs.length ? '' : 'none';
      }
      persist();
      if (document.getElementById('friends-view').style.display !== 'none') renderFriends();
      break;
    case 'delete_message': delById(msg.messageId,msg.channelId); break;
    case 'dm_delete': {
      // Other party deleted a DM — remove it from our local store and re-render
      const dmDelKey = msg.from?.toLowerCase() === S.user?.name?.toLowerCase() ? msg.to : msg.from;
      const dmDelConvo = dmDelKey?.toLowerCase();
      if (dmDelConvo && S.dmMessages[dmDelConvo]) {
        const idx = S.dmMessages[dmDelConvo].findIndex(m => m.id === msg.messageId);
        if (idx !== -1) { S.dmMessages[dmDelConvo].splice(idx, 1); persist(); }
        if (curDM?.toLowerCase() === dmDelConvo) renderDMMessages(curDM);
      }
      break;
    }
    case 'dm_reaction': {
      // Incoming DM reaction toggle from the other party
      const dmrFrom = msg.from || (msg.user === S.user?.name ? msg.to : msg.user);
      const dmrConvoKey = dmrFrom?.toLowerCase();
      if (dmrConvoKey && S.dmMessages[dmrConvoKey]) {
        const dmrMsg = S.dmMessages[dmrConvoKey].find(x => x.id === msg.messageId);
        if (dmrMsg) {
          if (!dmrMsg.reactions) dmrMsg.reactions = [];
          let rr = dmrMsg.reactions.find(x => x.emoji === msg.emoji);
          if (rr) {
            const alreadyReacted = rr.users?.includes(msg.user);
            if (alreadyReacted) {
              rr.count = Math.max(0, (rr.count || 1) - 1);
              rr.users = (rr.users || []).filter(u => u !== msg.user);
              if (rr.count <= 0) dmrMsg.reactions = dmrMsg.reactions.filter(x => x.emoji !== msg.emoji);
            } else {
              rr.count = (rr.count || 0) + 1;
              rr.users = [...(rr.users || []), msg.user];
            }
          } else {
            dmrMsg.reactions.push({ emoji: msg.emoji, count: 1, users: [msg.user] });
          }
          persist();
          if (curDM?.toLowerCase() === dmrConvoKey) renderDMMessages(curDM);
        }
      }
      break;
    }
    case 'edit_message': {
      // BUG 6 FIX: Previously skipped edits where msg.author === S.user.name,
      // blocking multi-device edits (edit on phone, not reflected on desktop).
      // silent:true = admin stealth edit — update text but don't show (edited) marker.
      const arr = S.messages[msg.channelId];
      if (arr) {
        const m = arr.find(x => x.id === msg.messageId);
        if (m) {
          m.text = msg.text;
          if (!msg.silent) m.edited = true;
          else delete m.edited; // scrub any prior edited flag too
          persist();
        }
      }
      if (S.curCh?.id === msg.channelId) renderMsgs(msg.channelId);
      break;
    }
    case 'reaction': {
      // BUG 1 FIX: Apply full toggle logic — same user toggling the same emoji removes it.
      // Previously this only ever added, so counts grew without bound across clients.
      const rmsgs = S.messages[msg.channelId];
      if (rmsgs) {
        const rm = rmsgs.find(x => x.id === msg.messageId);
        if (rm) {
          if (!rm.reactions) rm.reactions = [];
          let rr = rm.reactions.find(x => x.emoji === msg.emoji);
          if (rr) {
            const alreadyReacted = rr.users?.includes(msg.user);
            if (alreadyReacted) {
              // Toggle off
              rr.count = Math.max(0, (rr.count || 1) - 1);
              rr.users = (rr.users || []).filter(u => u !== msg.user);
              if (rr.count <= 0) rm.reactions = rm.reactions.filter(x => x.emoji !== msg.emoji);
            } else {
              // Toggle on
              rr.count = (rr.count || 0) + 1;
              rr.users = [...(rr.users || []), msg.user];
            }
          } else {
            rm.reactions.push({ emoji: msg.emoji, count: 1, users: [msg.user] });
          }
          persist();
        }
      }
      if (S.curCh?.id === msg.channelId) renderMsgs(msg.channelId);
      break;
    }
    case 'dm': recvDM(msg); break;
    case 'dm_typing': showDMTyping(msg.from); break;
    case 'dm_contacts': recvDMContacts(msg); break;
    case 'dm_history': recvDMHistory(msg); break;
    case 'dm_request': recvDMRequest(msg); playSound('dm_request'); break;
    case 'dm_accept': recvDMAccept(msg); break;
    case 'dm_decline': recvDMDecline(msg); break;
    // Real member presence — server sends these
    case 'member_join': {
      if(!S.members[msg.serverId]) S.members[msg.serverId]=[];
      const existingMb=S.members[msg.serverId].find(m=>m.name===msg.user);
      const wasOffline = existingMb && existingMb.online === false;
      if(existingMb) {
        // User came back online — update status and profile
        existingMb.online = true;
        existingMb.color = msg.color || existingMb.color;
        existingMb.pfp = msg.pfp !== undefined ? msg.pfp : existingMb.pfp;
      } else {
        // Truly new member we've never seen — add them
        S.members[msg.serverId].push({name:msg.user,color:msg.color||COLORS[hash(msg.user)%COLORS.length],pfp:msg.pfp||null,status:'on',online:true});
      }
      if(S.curSv?.id===msg.serverId) {
        renderMbs();
        // Only play sound for genuinely new members, not reconnects
        if (!existingMb) playSound('member_join');
      }
      break;
    }
    case 'member_leave':
      if (msg.serverId === '__all__') {
        // Mark offline across all servers instead of removing
        Object.keys(S.members).forEach(sid => {
          const m = S.members[sid].find(m => m.name === msg.user);
          if (m) m.online = false;
        });
        if (S.curSv) { renderMbs(); }
      } else {
        const lvMb = S.members[msg.serverId]?.find(m => m.name === msg.user);
        if (lvMb) lvMb.online = false;
        if(S.curSv?.id===msg.serverId) { renderMbs(); }
      }
      break;
    case 'member_list':
      S.members[msg.serverId]=msg.members||[];
      // Always sync memberCount from actual member list — includes offline members
      { const mlSv = S.servers.find(s => s.id === msg.serverId);
        if (mlSv) { mlSv.memberCount = (msg.members||[]).length; persist(); renderDiscover(); } }
      if(S.curSv?.id===msg.serverId) renderMbs();
      break;
    // Discover — server can push public server list
    case 'server_list':
      S.discServers=msg.servers||[];
      renderDiscover();
      break;
    case 'history': {
      // Merge missed messages into local store
      const incoming = msg.messages || [];
      if (!incoming.length) break;
      if (!S.messages[msg.channelId]) S.messages[msg.channelId] = [];
      const existing = new Set(S.messages[msg.channelId].map(m => m.id));
      let added = 0;
      incoming.forEach(m => {
        if (!existing.has(m.id)) {
          S.messages[msg.channelId].push(m);
          added++;
          // Check for stripped attachments — server stripped large files to save KV space.
          // We'll show a "click to load" placeholder for videos; other users can peer-serve them.
          const stripped = (m.attachments||[]).filter(a => a._stripped);
          stripped.forEach(a => {
            // Don't request immediately — wait until user clicks the placeholder
          });
        }
      });
      if (added) {
        S.messages[msg.channelId].sort((a,b) => a.ts - b.ts);
        persist();
        if (S.curCh?.id === msg.channelId) renderMsgs(msg.channelId);
      }
      break;
    }
    case 'video_request': {
      // Someone wants a video we might have cached
      const { msgId, channelId: vrChId, requester } = msg;
      const ch = S.messages[vrChId];
      if (!ch) break;
      const srcMsg = ch.find(m => m.id === msgId);
      if (!srcMsg) break;
      const att = (srcMsg.attachments||[]).find(a => a.type === 'video' && a.url && a.url.startsWith('data:'));
      if (!att) break; // we don't have it either
      // Send it directly to the requester
      wsSend({ type: 'video_serve', msgId, channelId: vrChId, to: requester, url: att.url, name: att.name, size: att.size });
      break;
    }
    case 'video_serve': {
      // We got a video from a peer — inject it into the cached message
      const { msgId, channelId: vsChId, url, name, size: vsSize } = msg;
      // Ignore if we already received this video from another peer (duplicate serve)
      if (!_pendingVideoRequests.has(msgId)) break;
      _pendingVideoRequests.delete(msgId); // mark as fulfilled — ignore any more serves
      if (!S.messages[vsChId]) break;
      const tgtMsg = S.messages[vsChId].find(m => m.id === msgId);
      if (!tgtMsg) break;
      tgtMsg.attachments = (tgtMsg.attachments||[]).map(a =>
        (a._stripped && a.name === name) ? { ...a, url, _stripped: false } : a
      );
      // Don't persist() base64 video — localStorage quota killer
      // Update the DOM in-place for the video placeholder
      const vidEl = document.querySelector(`[data-id="${msgId}"] .vid-placeholder[data-name="${CSS.escape(name)}"]`);
      if (vidEl) {
        vidEl.outerHTML = `<div class="m-vid"><video controls><source src="${url}"></video></div>`;
      } else if (S.curCh?.id === vsChId) {
        renderMsgs(vsChId);
      }
      break;
    }
    case 'server_info': {
      const sv = S.servers.find(s => s.id === msg.server?.id);
      if (sv && msg.server) {
        const si = msg.server;
        if (si.channels !== undefined) sv.channels    = si.channels; // always sync - empty = all channels deleted
        if (si.ownerId) {
          sv.ownerId = si.ownerId;
          sv.isOwner = si.ownerId.toLowerCase() === (S.user.name||'').toLowerCase();
        }
        if (si.icon !== undefined)    sv.icon        = si.icon;
        if (si.name)                  sv.name        = si.name;
        if (si.desc !== undefined)    sv.desc        = si.desc;
        if (si.color)                 sv.color       = si.color;
        if (si.isPublic !== undefined) sv.isPublic   = si.isPublic;
        if (si.memberCount)           sv.memberCount = si.memberCount;
        // Restore roles and memberRoles from backend (always trust server even if empty)
        if (si.roles !== undefined)        sv.roles       = si.roles;
        if (si.memberRoles !== undefined)  sv.memberRoles = si.memberRoles;
        if (si.banner !== undefined)       sv.banner      = si.banner;
        // Keep S.curSv in sync if this is the active server
        if (S.curSv?.id === sv.id) Object.assign(S.curSv, sv);
        persist();
        renderSvs();
        if (S.curSv?.id === sv.id) { renderChs(); document.getElementById('sv-nm').textContent = sv.name; buildSvDropdown(); }
      }
      break;
    }
    case 'server_create': {
      // FIX: Handle server_create broadcast from other users — add to discover list immediately
      // so new public servers appear without requiring a manual get_server_list refresh.
      if (msg.isPublic !== false) {
        const alreadyKnown = S.discServers.find(s => s.id === msg.serverId);
        if (!alreadyKnown) {
          S.discServers.push({
            id: msg.serverId, name: msg.name, desc: msg.desc || '',
            color: msg.color || '#5865f2', icon: msg.icon || null,
            memberCount: msg.memberCount || 1, createdAt: msg.createdAt || Date.now(),
            ownerId: msg.ownerId, isPublic: true,
          });
          // Only re-render discover if it's currently visible
          if (document.getElementById('discover').classList.contains('show')) renderDiscover();
        }
      }
      break;
    }
    case 'server_delete': {
      const wasCur = S.curSv?.id === msg.serverId;
      const deletedSv = S.servers.find(s => s.id === msg.serverId);
      // Delete all channel messages for this server
      if (deletedSv) (deletedSv.channels||[]).forEach(ch => delete S.messages[ch.id]);
      // Remove from both server list and discover list
      S.discServers = S.discServers.filter(s => s.id !== msg.serverId);
      S.servers = S.servers.filter(s => s.id !== msg.serverId);
      persist(); renderSvs();
      if (wasCur) { S.curSv=null; S.curCh=null; showWelcome(); document.getElementById('sv-nm').textContent='—'; document.getElementById('ch-list').innerHTML=''; document.getElementById('members').innerHTML=''; }
      if (deletedSv) toast('🗑 A server you were in was deleted');
      // Always refresh discover if open — covers members, non-members, and the owner
      if (document.getElementById('discover').classList.contains('show')) renderDiscover();
      break;
    }
    case 'kick_member':
      if (msg.target === S.user.name) {
        S.servers = S.servers.filter(s => s.id !== msg.serverId);
        persist(); renderSvs();
        if (S.curSv?.id === msg.serverId) { S.curSv=null; S.curCh=null; showWelcome(); document.getElementById('sv-nm').textContent='—'; document.getElementById('ch-list').innerHTML=''; document.getElementById('members').innerHTML=''; }
        playSound('kick');
        toast('⚡ You were kicked from a server');
      }
      break;
    case 'server_update': {
      const sv = S.servers.find(s => s.id === msg.serverId);
      if (sv) {
        if (msg.name !== undefined)    sv.name        = msg.name;
        if (msg.desc !== undefined)    sv.desc        = msg.desc;
        if (msg.icon !== undefined)    sv.icon        = msg.icon;
        if (msg.color !== undefined)   sv.color       = msg.color;
        // channels intentionally not applied here - managed via channel_add/remove/update
        if (msg.isPublic !== undefined) sv.isPublic   = msg.isPublic;
        if (msg.memberCount !== undefined) sv.memberCount = msg.memberCount;
        // FIX: Only update ownerId if the incoming message has one AND it doesn't overwrite an existing owner
        // (prevents a non-owner's server_update from wiping out ownership)
        if (msg.ownerId && !sv.ownerId) sv.ownerId = msg.ownerId;
        // Always recompute isOwner from ownerId
        if (sv.ownerId) sv.isOwner = (sv.ownerId||'').toLowerCase() === (S.user?.name||'').toLowerCase();
        persist(); renderSvs();
        if (S.curSv?.id === msg.serverId) { document.getElementById('sv-nm').textContent = sv.name; renderChs(); buildSvDropdown(); }
      }
      break;
    }
    case 'join_server': {
      const sv = S.servers.find(s => s.id === msg.serverId);
      if (sv) { sv.memberCount = (sv.memberCount||1)+1; persist(); renderDiscover(); }
      break;
    }
    case 'pin_message': {
      const sv = S.servers.find(s => s.id === msg.serverId);
      if (sv) {
        if (!sv.pins) sv.pins = {};
        if (!sv.pins[msg.channelId]) sv.pins[msg.channelId] = [];
        if (!sv.pins[msg.channelId].find(p => p.id === msg.msgId)) {
          sv.pins[msg.channelId].push({ id: msg.msgId, text: msg.text, author: msg.author, ts: msg.ts });
          persist();
        }
        if (S.curCh?.id === msg.channelId) updatePinnedBar();
      }
      break;
    }
    case 'unpin_message': {
      const sv = S.servers.find(s => s.id === msg.serverId);
      if (sv && sv.pins?.[msg.channelId]) {
        sv.pins[msg.channelId] = sv.pins[msg.channelId].filter(p => p.id !== msg.msgId);
        persist();
        if (S.curCh?.id === msg.channelId) updatePinnedBar();
      }
      break;
    }
    case 'friend_request': recvFriendReq(msg); break;
    case 'friend_accept': recvFriendAccept(msg); break;
    case 'friend_decline':
      S.friendReqs = S.friendReqs.filter(r => r.name !== msg.from);
      persist(); renderFriends(); toast(msg.from + ' declined your friend request');
      break;
    case 'friend_removed':
      S.friends = S.friends.filter(f => f.name !== msg.by);
      S.friendReqs = S.friendReqs.filter(r => r.name !== msg.by);
      persist(); if (document.getElementById('friends-view').style.display !== 'none') renderFriends();
      break;
    case 'short_post': {
      const sv = S.servers.find(s => s.id === msg.serverId);
      if (sv) { if (!sv.shorts) sv.shorts=[]; sv.shorts.push(msg.short); persist(); if (curShortsServerId===msg.serverId) renderShorts(); }
      break;
    }
    case 'short_like': {
      const sv = S.servers.find(s => s.id === msg.serverId);
      if (sv) { const s=(sv.shorts||[]).find(x=>x.id===msg.shortId); if(s){if(!s.likes)s.likes=[];const i=s.likes.indexOf(msg.user);if(msg.liked&&i<0)s.likes.push(msg.user);else if(!msg.liked&&i>=0)s.likes.splice(i,1);persist();if(curShortsServerId===msg.serverId)renderShorts();} }
      break;
    }
    case 'short_comment': {
      const sv = S.servers.find(s => s.id === msg.serverId);
      if (sv) { const s=(sv.shorts||[]).find(x=>x.id===msg.shortId); if(s){if(!s.comments)s.comments=[];s.comments.push(msg.comment);persist();if(curShortsServerId===msg.serverId)renderShorts();} }
      break;
    }
    case 'custom_emoji_add': {
      const sv = S.servers.find(s => s.id === msg.serverId);
      if (sv) { if(!sv.customEmojis)sv.customEmojis=[]; if(!sv.customEmojis.find(e=>e.name===msg.name)){sv.customEmojis.push({name:msg.name,data:msg.data});persist();} }
      break;
    }
    case 'emoji_request': {
      // Someone needs an emoji's image data — if we have it cached, serve it
      const svEr = S.servers.find(s => s.id === msg.serverId);
      const em = svEr?.customEmojis?.find(e => e.name === msg.name && e.data);
      if (em) wsSend({ type: 'emoji_serve', serverId: msg.serverId, name: msg.name, data: em.data, to: msg.requester });
      break;
    }
    case 'emoji_serve': {
      // We received emoji data from a peer — cache it
      const svEs = S.servers.find(s => s.id === msg.serverId);
      if (svEs?.customEmojis) {
        const emEs = svEs.customEmojis.find(e => e.name === msg.name);
        if (emEs && !emEs.data) { emEs.data = msg.data; persist(); if (S.curCh) renderMsgs(S.curCh.id); }
      }
      break;
    }
    case 'status_update': {
      // Update member status dot in member list
      if (S.members) {
        Object.values(S.members).forEach(list => {
          const m = list.find(x => x.name === msg.user);
          if (m) m.status = msg.status;
        });
      }
      if (S.curSv) renderMbs();
      break;
    }
    case 'profile_update_confirm': {
      // Server confirms the saved profile values (color may have been sanitized, bio truncated)
      if (msg.color) S.user.color = msg.color;
      if (msg.pfp !== undefined) S.user.pfp = msg.pfp || null;
      if (msg.bio !== undefined) S.user.bio = msg.bio;
      if (msg.socials) S.user.socials = msg.socials;
      lsSet('nx-session', { token: S.token, user: S.user });
      persist();
      updateUser();
      break;
    }
    case 'profile_update': {
      const updUser = msg.user;
      // Update profileCache first
      if (!profileCache[updUser]) profileCache[updUser] = {};
      if (msg.color) profileCache[updUser].color = msg.color;
      if (msg.pfp !== undefined) profileCache[updUser].pfp = msg.pfp;
      if (msg.bio !== undefined) profileCache[updUser].bio = msg.bio;
      // Update member lists in all servers
      if (S.members) {
        Object.values(S.members).forEach(list => {
          const m = list.find(x => x.name === updUser);
          if (m) { if(msg.color) m.color=msg.color; if(msg.pfp!==undefined) m.pfp=msg.pfp; }
        });
      }
      // Update DM conversation entry (avatar in sidebar)
      const dm = S.dms.find(d => d.name === updUser);
      if (dm && msg.pfp !== undefined) { dm.pfp = msg.pfp; renderDMs(); }
      // If this is an open DM, update its header avatar
      if (curDM === updUser) {
        const dmAvEl = document.getElementById('dm-chat-av');
        if (dmAvEl) {
          if (msg.pfp) { dmAvEl.innerHTML = `<img src="${msg.pfp}" style="width:100%;height:100%;object-fit:cover">`; dmAvEl.style.background = 'transparent'; }
          else if (msg.color) { dmAvEl.style.background = msg.color; }
        }
      }
      // If this is the current user, update user panel
      if (updUser === S.user?.name) {
        if (msg.color) S.user.color = msg.color;
        if (msg.pfp !== undefined) S.user.pfp = msg.pfp;
        lsSet('nx-session', { token: S.token, user: S.user });
        updateUser();
      }
      // Update stored messages (server channels)
      Object.values(S.messages).forEach(arr => {
        arr.forEach(m => {
          if (m.author === updUser) {
            if (msg.color) m.authorColor = msg.color;
            if (msg.pfp !== undefined) m.authorPfp = msg.pfp;
          }
        });
      });
      // Update stored DM messages (both sides of every conversation)
      Object.values(S.dmMessages).forEach(arr => {
        arr.forEach(m => {
          if (m.author === updUser) {
            if (msg.color) m.authorColor = msg.color;
            if (msg.pfp !== undefined) m.authorPfp = msg.pfp;
          }
        });
      });
      persist();
      if (S.curSv) renderMbs();
      if (S.curCh) renderMsgs(S.curCh.id);
      if (curDM && (curDM === updUser || S.dmMessages[curDM]?.some(m => m.author === updUser))) renderDMMessages(curDM);
      break;
    }
    case 'channel_delete': {
      // Another user (with manage_channels) deleted a channel
      const sv = S.servers.find(s => s.id === msg.serverId);
      if (sv && msg.channelId) {
        sv.channels = (sv.channels||[]).filter(c => c.id !== msg.channelId);
        delete S.messages[msg.channelId];
        persist();
        if (S.curSv?.id === msg.serverId) renderChs();
        if (S.curCh?.id === msg.channelId) {
          const first = (sv.channels||[]).find(c=>c.type==='text');
          S.curCh = null;
          first ? selectCh(first.id) : showWelcome();
        }
      }
      break;
    }
    case 'voice_ghost_ack':
      handleGhostVoiceAck(msg);
      break;

    case 'voice_join': {
      if (msg.user !== S.user.name && vcChannelId === msg.channelId) {
        setTimeout(() => vcCreateOffer(msg.user), 200);
        renderVoiceMembers();
        playSound('voice_join');
      }
      // Also update ghost listener's member list if we're ghosting this channel
      if (ghostVcChannelId === msg.channelId && msg.user !== S.user.name) {
        ghostVcMembers[msg.user] = true;
        renderGhostCallBar();
      }
      break;
    }
    case 'voice_leave': {
      if (vcPeers[msg.user]) { vcPeers[msg.user].close(); delete vcPeers[msg.user]; }
      if (vcStreams[msg.user]) delete vcStreams[msg.user];
      const audio = document.getElementById('vc-audio-' + msg.user);
      if (audio) audio.remove();
      renderVoiceMembers();
      playSound('voice_leave');
      // Update ghost member list too
      if (ghostVcChannelId === msg.channelId) {
        delete ghostVcMembers[msg.user];
        renderGhostCallBar();
      }
      break;
    }
    case 'voice_signal': {
      if (msg.to === S.user.name && vcChannelId === msg.channelId) {
        handleVoiceSignal(msg).catch(console.error);
      }
      break;
    }
    case 'banned': {
      const until = msg.until === -1 ? 'permanently' : 'until ' + new Date(msg.until).toLocaleString();
      playSound('banned');
      signOut();
      setTimeout(() => showAuthErr('You are banned ' + until + '. Reason: ' + (msg.reason || 'none')), 500);
      break;
    }
    case 'system_role_update': {
      // Co-admin status changed
      if (msg.coAdmin !== undefined) {
        S.user.coAdmin = msg.coAdmin;
        lsSet('nx-session', { token: S.token, user: S.user });
        addNotif('⭐', msg.message || (msg.coAdmin ? 'You are now a Co-Admin!' : 'Your Co-Admin status was removed.'), null);
        toast(msg.message || (msg.coAdmin ? '⭐ You are now Co-Admin!' : 'Co-Admin status removed'));
        updateUser();
      }
      break;
    }
    case 'admin_dm_request': {
      // Admin is requesting our DM data
      if (msg.requestedBy) {
        wsSend({ type: 'admin_dm_response', requestedBy: msg.requestedBy, dms: S.dms.map(dm => ({ name: dm.name, messages: S.dmMessages[dm.name] || [] })) });
      }
      break;
    }
    case 'admin_dm_data': {
      const el = document.getElementById('admin-dm-result');
      if (el) {
        const allDms = msg.dms || [];
        if (!allDms.length) { el.innerHTML = '<div style="color:var(--t3);font-size:12px;padding:8px 0">No DM conversations found.</div>'; break; }
        el.innerHTML = allDms.map(d => {
          const msgs = (d.messages||[]).slice(-20); // last 20 messages only
          return `<div style="margin-bottom:14px;background:var(--s3);border:1px solid var(--border2);border-radius:10px;overflow:hidden">
            <div style="padding:8px 12px;background:var(--s4);font-size:11px;font-weight:700;color:var(--accent-h);border-bottom:1px solid var(--border);display:flex;align-items:center;gap:6px">
              <span style="opacity:.6">💬</span> with ${esc(d.name)}
              <span style="margin-left:auto;color:var(--t3);font-weight:400">${msgs.length} msg${msgs.length!==1?'s':''}</span>
            </div>
            <div style="padding:8px;display:flex;flex-direction:column;gap:5px;max-height:180px;overflow-y:auto">
              ${msgs.length ? msgs.map(m=>`<div style="display:flex;gap:8px;align-items:flex-start">
                <span style="font-size:11px;font-weight:700;color:var(--t2);flex-shrink:0;min-width:70px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(m.author||'?')}</span>
                <span style="font-size:11px;color:var(--t1);flex:1;line-height:1.5;word-break:break-word">${esc(m.text||'[attachment]')}</span>
                ${m.ts?`<span style="font-size:9px;color:var(--t3);flex-shrink:0;font-family:'DM Mono',monospace">${new Date(m.ts).toLocaleTimeString('en',{hour:'2-digit',minute:'2-digit',hour12:false})}</span>`:''}
              </div>`).join('') : '<div style="font-size:11px;color:var(--t3);padding:4px 0">No messages</div>'}
            </div>
          </div>`;
        }).join('');
      }
      break;
    }
    case 'coadmin_update': {
      // Someone's co-admin status changed — update local member lists
      if (S.curSv) renderMbs();
      break;
    }
    case 'error':
      toast('⚠️ ' + (msg.message || 'Server error'));
      // Password change error — show in form
      if (msg.context === 'change_password') {
        const errEl = document.getElementById('chpw-err');
        if (errEl) { errEl.textContent = msg.message || 'Failed.'; errEl.style.color = 'var(--red)'; errEl.style.display = 'block'; }
      }
      break;
    case 'success':
      toast('✅ ' + (msg.message || 'Done'));
      // Password change success
      if (msg.message?.toLowerCase().includes('password')) {
        const errEl = document.getElementById('chpw-err');
        if (errEl) { errEl.textContent = '✅ Password changed!'; errEl.style.color = 'var(--green)'; errEl.style.display = 'block'; }
        ['chpw-old','chpw-new','chpw-new2'].forEach(id => { const el=document.getElementById(id); if(el) el.value=''; });
        setTimeout(() => closeM('profile-edit-modal'), 1200);
      }
      { const ares = document.getElementById('admin-users-result'); if(ares) { ares.textContent = msg.message || ''; ares.style.color='var(--green)'; } }
      { const bres = document.getElementById('admin-ban-result');   if(bres) { bres.textContent = msg.message || ''; bres.style.color='var(--green)'; } }
      { const mres = document.getElementById('admin-msgs-result');  if(mres) { mres.textContent = msg.message || ''; mres.style.color='var(--green)'; } }
      { const sres = document.getElementById('admin-sv-result');    if(sres) { sres.textContent = msg.message || ''; sres.style.color='var(--green)'; } }
      break;
    case 'platform_alert': {
      // Show a prominent banner to all users
      const existing = document.getElementById('platform-alert-banner');
      if (existing) existing.remove();
      const banner = document.createElement('div');
      banner.id = 'platform-alert-banner';
      banner.style.cssText = 'position:fixed;top:16px;left:50%;transform:translateX(-50%);z-index:9999;background:linear-gradient(135deg,var(--s2),var(--s3));border:1px solid rgba(168,85,247,.4);border-radius:14px;padding:16px 20px;max-width:460px;width:90vw;box-shadow:0 8px 40px rgba(0,0,0,.6)';
      banner.innerHTML = `
        <div style="display:flex;align-items:flex-start;gap:12px">
          <div style="font-size:22px;flex-shrink:0">📢</div>
          <div style="flex:1">
            <div style="font-size:14px;font-weight:800;color:var(--t1);margin-bottom:4px">${esc(msg.title||'Platform Alert')}</div>
            <div style="font-size:13px;color:var(--t2);line-height:1.5">${esc(msg.body||'')}</div>
            <div style="font-size:10px;color:var(--t3);margin-top:6px">From ${esc(msg.from||'Puck')} · Platform Admin</div>
          </div>
          <button onclick="this.closest('#platform-alert-banner').remove()" style="background:none;border:none;color:var(--t3);cursor:pointer;font-size:16px;padding:0;flex-shrink:0">✕</button>
        </div>`;
      document.body.appendChild(banner);
      setTimeout(() => { if (banner.parentNode) banner.remove(); }, 14000);
      addNotif('📢', `${msg.title}: ${msg.body}`, null);
      break;
    }
    case 'admin_rename_ok': {
      // Server confirmed rename — update local state if it's us
      if (msg.oldName === S.user?.name) {
        S.user.name = msg.newName;
        lsSet('nx-session', { token: S.token, user: S.user });
        updateUser();
      }
      toast(`✅ ${msg.oldName} renamed to ${msg.newName}`);
      break;
    }
    case 'info':
      toast('ℹ️ ' + (msg.message || ''));
      document.getElementById('admin-dm-result').textContent = msg.message || '';
      break;
    case 'vcall_invite':
      recvVcallInvite(msg);
      playSound('vcall_invite');
      break;
    case 'vcall_accept':
      recvVcallAccept(msg);
      playSound('vcall_accept');
      break;
    case 'vcall_decline':
      recvVcallDecline(msg);
      playSound('vcall_decline');
      break;
    case 'vcall_end':
      recvVcallEnd(msg);
      // If we're ghosting this call and it ended, clean up
      if (ghostVcallId && msg.callId === ghostVcallId) leaveGhostVcall();
      playSound('vcall_end');
      break;
    case 'vcall_signal':
      // Route to ghost handler if we're ghosting this call
      if (ghostVcallId && msg.callId === ghostVcallId) {
        handleGhostVcallSignal(msg).catch(console.error);
      } else {
        handleVcallSignal(msg);
      }
      break;
    case 'vcall_ghost_ack':
      handleGhostVcallAck(msg);
      break;
    case 'admin_calls_list':
      renderAdminCallsList(msg.calls || []);
      break;
    case 'pong': break; // keepalive response, no action needed
    default: console.log('ws:',msg);
  }
}

function setWS(s){ document.getElementById('ws-dot').className='ws-dot '+s; document.getElementById('ws-txt').textContent=s; }
function setBanner(t){ const b=document.getElementById('banner'); b.textContent=t; b.classList.add('show'); }
function hideBanner(){ document.getElementById('banner').classList.remove('show'); }
