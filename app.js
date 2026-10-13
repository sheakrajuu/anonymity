'use strict';

(() => {
  const $ = selector => document.querySelector(selector);
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();
  const MiB = 1024 * 1024;
  const maxFileBytes = 50 * MiB - 16;
  const maxVideoSeconds = 180;
  const rooms = new Map();
  const roomKeys = new Map();
  const mediaCache = new Map();
  const messageFingerprints = new Map();
  let account = null;
  let privateKey = null;
  let currentRoomId = null;
  let suppressRoomAutoSelect = false;
  let filter = '';
  let registerMode = false;
  let selectedFiles = [];
  let activeUpload = null;
  let activeSendCancel = null;
  let activeDownload = null;
  let pollTimer = null;
  let joinMode = false;
  let unlockOnly = false;
  let pendingUser = null;
  let roomRefreshPromise = null;
  let queuedRoomRefresh = false;
  let accountIdVisible = false;

  const base64 = bytes => {
    let binary = '';
    for (let offset = 0; offset < bytes.length; offset += 0x8000) {
      binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
    }
    return btoa(binary);
  };
  const fromBase64 = value => Uint8Array.from(atob(value), character => character.charCodeAt(0));
  const randomBytes = length => crypto.getRandomValues(new Uint8Array(length));
  const makeId = () => crypto.randomUUID();
  const escapeText = value => String(value).replace(/[&<>"]/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[char]));
  const currentRoom = () => currentRoomId ? rooms.get(currentRoomId) : null;
  const roomKey = (roomId, epoch) => roomKeys.get(roomId)?.get(epoch) || null;
  function forgetRoom(roomId) {
    roomKeys.delete(roomId);
    messageFingerprints.delete(roomId);
    if ([...mediaCache.values()].some(cached => cached.roomId === roomId) && $('#viewer').open) closeViewer();
    for (const [mediaId, cached] of mediaCache) {
      if (cached.roomId === roomId) {
        URL.revokeObjectURL(cached.url);
        mediaCache.delete(mediaId);
      }
    }
  }
  const scrollToBottom = () => { const element = $('#msgs'); element.scrollTop = element.scrollHeight; };
  const setAttachMenuOpen = open => {
    $('#attachMenu').hidden = !open;
    $('#attach').setAttribute('aria-expanded', String(open));
  };
  const setRoomMenuOpen = open => {
    $('#roomMenu').hidden = !open;
    $('#roomOptions').setAttribute('aria-expanded', String(open));
  };

  function toast(message) {
    const element = $('#toast');
    element.textContent = message;
    element.classList.add('on');
    clearTimeout(toast.timer);
    toast.timer = setTimeout(() => element.classList.remove('on'), 3200);
  }

  function setView(value) { $('#app').dataset.view = value; }

  function renderAccountControls() {
    const area = $('#accountMeta');
    if (area.dataset.userId === account.id) return;
    area.dataset.userId = account.id;
    $('#openSettings').hidden = false;
    area.textContent = 'Your account is protected.';
  }

  async function leaveCurrentRoom(endRoomIfHost = false) {
    const roomId = currentRoomId;
    if (!roomId) {
      setView('list');
      return;
    }
    const room = currentRoom();
    if (endRoomIfHost && room?.owner_id === account.id && !room.is_permanent) {
      if (!confirm('Leaving as the host will immediately delete this room and all server-held messages and files. Continue?')) return;
      try {
        await api(`/api/rooms/${encodeURIComponent(roomId)}`, { method: 'DELETE' });
        forgetRoom(roomId);
        rooms.delete(roomId);
        toast('You left as host. The temporary room and its server-held data were deleted.');
      } catch (error) {
        toast(error.message);
        return;
      }
    }
    activeSendCancel?.();
    activeDownload?.abort();
    currentRoomId = null;
    suppressRoomAutoSelect = true;
    setView('list');
    $('#who').textContent = '';
    $('#hav').style.display = 'none';
    $('.owner-controls').hidden = true;
    $('#msgs').replaceChildren();
    addText($('#msgs'), 'Choose a conversation to continue.', 'hint');
    $('#t').disabled = true;
    $('#attach').disabled = true;
    $('#f').querySelector('.send').disabled = true;
    renderList();
  }

  async function api(path, options = {}) {
    const response = await fetch(path, { credentials: 'same-origin', ...options });
    if (!response.ok) {
      let message = `Request failed (${response.status}).`;
      try {
        const payload = await response.json();
        if (payload.error) message = payload.error;
      } catch {}
      const error = new Error(message);
      error.status = response.status;
      throw error;
    }
    return response.status === 204 ? null : response.json();
  }

  const jsonOptions = body => ({
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });

  async function derivePassphraseKey(passphrase, salt) {
    const material = await crypto.subtle.importKey('raw', encoder.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' },
      material,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  async function createIdentity(passphrase) {
    const pair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
    const privateBytes = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey));
    const publicKey = await crypto.subtle.exportKey('jwk', pair.publicKey);
    const salt = randomBytes(16);
    const iv = randomBytes(12);
    const wrappingKey = await derivePassphraseKey(passphrase, salt);
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, wrappingKey, privateBytes);
    privateBytes.fill(0);
    return {
      publicKey,
      privateBundle: {
        salt: base64(salt),
        iv: base64(iv),
        ciphertext: base64(new Uint8Array(ciphertext))
      }
    };
  }

  async function unlockIdentity(passphrase, bundle) {
    const wrappingKey = await derivePassphraseKey(passphrase, fromBase64(bundle.salt));
    const clear = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: fromBase64(bundle.iv) },
      wrappingKey,
      fromBase64(bundle.ciphertext)
    );
    try {
      return await crypto.subtle.importKey('pkcs8', clear, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
    } finally {
      new Uint8Array(clear).fill(0);
    }
  }

  async function deriveWrappingKey(senderId, recipientId, roomId, epoch, recipientPublicKey) {
    const publicKey = await crypto.subtle.importKey(
      'jwk',
      recipientPublicKey,
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      []
    );
    const shared = await crypto.subtle.deriveBits({ name: 'ECDH', public: publicKey }, privateKey, 256);
    const material = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: encoder.encode(`${roomId}:${epoch}`),
        info: encoder.encode(`stay-connected-room-key|${senderId}|${recipientId}`)
      },
      material,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  async function packageRoomKey(roomId, epoch, keyBytes, members) {
    const packages = [];
    for (const member of members) {
      const wrappingKey = await deriveWrappingKey(account.id, member.id, roomId, epoch, member.publicKey);
      const nonce = randomBytes(12);
      const additionalData = encoder.encode(`${roomId}|${epoch}|${account.id}|${member.id}`);
      const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: nonce, additionalData },
        wrappingKey,
        keyBytes
      );
      packages.push({
        userId: member.id,
        epoch,
        nonce: base64(nonce),
        ciphertext: base64(new Uint8Array(ciphertext)),
        senderPublicKey: account.publicKey
      });
    }
    return packages;
  }

  async function unwrapPackages(room) {
    const keys = new Map();
    for (const item of room.keyPackages) {
      const senderPublicKey = typeof item.sender_public_key === 'string'
        ? JSON.parse(item.sender_public_key)
        : item.sender_public_key;
      const wrappingKey = await deriveWrappingKey(
        item.sender_id,
        account.id,
        room.id,
        item.epoch,
        senderPublicKey
      );
      const additionalData = encoder.encode(`${room.id}|${item.epoch}|${item.sender_id}|${account.id}`);
      const clear = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: fromBase64(item.nonce), additionalData },
        wrappingKey,
        fromBase64(item.ciphertext)
      );
      keys.set(item.epoch, await crypto.subtle.importKey('raw', clear, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']));
      new Uint8Array(clear).fill(0);
    }
    roomKeys.set(room.id, keys);
  }

  async function encryptEnvelope(room, epoch, content, id = makeId()) {
    const key = roomKey(room.id, epoch);
    if (!key) throw new Error('Conversation key is unavailable. Sign in again or refresh the conversation.');
    const nonce = randomBytes(12);
    const additionalData = encoder.encode(`${room.id}|${epoch}|${id}`);
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce, additionalData },
      key,
      encoder.encode(JSON.stringify(content))
    );
    return { id, epoch, nonce: base64(nonce), ciphertext: base64(new Uint8Array(ciphertext)) };
  }

  async function decryptEnvelope(room, envelope) {
    const key = roomKey(room.id, envelope.epoch);
    if (!key) throw new Error('This device does not have the key for this conversation epoch.');
    const additionalData = encoder.encode(`${room.id}|${envelope.epoch}|${envelope.id}`);
    const clear = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: fromBase64(envelope.nonce), additionalData },
      key,
      fromBase64(envelope.ciphertext)
    );
    return JSON.parse(decoder.decode(clear));
  }

  function updateAvatar(room) {
    const avatar = $('#hav');
    avatar.textContent = (room.name || '?').slice(0, 1).toUpperCase();
    avatar.style.display = 'grid';
    avatar.style.placeItems = 'center';
    avatar.style.background = 'linear-gradient(135deg,#ff8a3d,#7a1208)';
    avatar.style.fontWeight = '800';
  }

  function renderList() {
    const visible = [...rooms.values()].filter(room => room.name.toLowerCase().includes(filter));
    if (!visible.length) {
      $('#list').innerHTML = `<p class="empty">${account
        ? (filter ? 'No conversations match your search.' : 'No active conversations. Use + to create a temporary ID.')
        : 'Sign in or create an account to start private conversations.'}</p>`;
      return;
    }
    $('#list').innerHTML = visible.map(room => {
      return `<button class="row ${room.id === currentRoomId ? 'on' : ''}" data-room="${escapeText(room.id)}">
        <span class="av" style="width:46px;height:46px;display:grid;place-items:center;background:linear-gradient(135deg,#ff8a3d,#7a1208);font-weight:800">${escapeText(room.name.slice(0, 1).toUpperCase())}</span>
        <span class="txt"><b>${escapeText(room.name)}<i>${room.member_count}/${room.max_members} people</i></b>
        <p>${room.is_permanent ? 'Permanent encrypted contact chat' : 'Temporary room · host can delete'}</p></span></button>`;
    }).join('');
  }

  function addText(parent, text, className) {
    const element = document.createElement('div');
    element.className = className;
    element.textContent = text;
    parent.append(element);
    return element;
  }

  function createMediaCard(room, message, item) {
    const card = document.createElement('div');
    card.className = 'media-card';
    addText(card, item.name || 'Encrypted media', '');
    const cached = mediaCache.get(item.id);
    if (cached) {
      if (cached.mime.startsWith('image/')) {
        const image = document.createElement('img');
        image.src = cached.url;
        image.alt = item.name || 'Shared image';
        image.onclick = () => openViewer(cached.url, 'image');
        card.append(image);
      } else if (cached.mime.startsWith('video/')) {
        const video = document.createElement('video');
        video.src = cached.url;
        video.controls = true;
        video.playsInline = true;
        video.preload = 'metadata';
        card.append(video);
      } else {
        const save = document.createElement('button');
        save.type = 'button';
        save.textContent = `Save ${item.name || 'file'}`;
        save.onclick = () => saveBlob(cached.blob, item.name);
        card.append(save);
      }
    } else {
      const button = document.createElement('button');
      button.type = 'button';
      button.dataset.action = 'load-media';
      button.dataset.room = room.id;
      button.dataset.epoch = String(message.epoch);
      button.dataset.media = JSON.stringify(item);
      button.textContent = item.mime.startsWith('image/')
        ? 'Load encrypted photo'
        : item.mime.startsWith('video/') ? 'Load & play encrypted video' : 'Download and decrypt file';
      button.onclick = event => {
        event.stopPropagation();
        loadMedia(button, !item.mime.startsWith('image/') && !item.mime.startsWith('video/'));
      };
      card.append(button);
    }
    const tools = document.createElement('div');
    tools.className = 'message-tools';
    const download = document.createElement('button');
    download.type = 'button';
    download.textContent = 'Save decrypted copy';
    download.dataset.action = 'download-media';
    download.dataset.room = room.id;
    download.dataset.epoch = String(message.epoch);
    download.dataset.media = JSON.stringify(item);
    download.onclick = event => {
      event.stopPropagation();
      loadMedia(download, true);
    };
    tools.append(download);
    card.append(tools);
    return card;
  }

  async function renderMessages(room) {
    const container = $('#msgs');
    const messages = await api(`/api/rooms/${encodeURIComponent(room.id)}/messages`);
    messageFingerprints.set(room.id, `${room.epoch}:${messages.length}:${messages.at(-1)?.id || ''}`);
    container.replaceChildren();
    if (!messages.length) {
      addText(container, 'No messages yet. Send an encrypted message.', 'hint');
      return;
    }
    const fragment = document.createDocumentFragment();
    for (const message of messages) {
      const bubble = document.createElement('article');
      bubble.className = `m ${message.sender_id === account.id ? 'me' : ''}`;
      const sender = room.members.find(member => member.id === message.sender_id);
      try {
        const payload = await decryptEnvelope(room, message);
        if (payload.type === 'text') {
          addText(bubble, payload.text, 'text-message');
        } else if (payload.type === 'media' && Array.isArray(payload.items) && payload.items.length) {
          if (payload.caption) addText(bubble, payload.caption, 'text-message');
          for (const item of payload.items) bubble.append(createMediaCard(room, message, item));
        } else {
          throw new Error('Unknown encrypted message format.');
        }
      } catch (error) {
        addText(bubble, 'Unable to verify or decrypt this message.', 'text-message');
        console.error('Encrypted message could not be verified:', error.message);
      }
      const time = document.createElement('small');
      const participant = room.members.findIndex(member => member.id === message.sender_id);
      const senderLabel = message.sender_id === account.id
        ? 'You'
        : participant >= 0 ? `Participant ${participant + 1}` : 'Former participant';
      time.textContent = `${senderLabel} · ${new Date(message.created_at).toLocaleString()}`;
      bubble.append(time);
      fragment.append(bubble);
    }
    container.append(fragment);
    scrollToBottom();
  }

  async function openRoom(roomId, historyPush = true) {
    const room = rooms.get(roomId);
    if (!room) return;
    if (currentRoomId && currentRoomId !== roomId) activeSendCancel?.();
    suppressRoomAutoSelect = false;
    currentRoomId = roomId;
    if (matchMedia('(max-width:820px)').matches) setView('chat');
    $('.owner-controls').hidden = false;
    updateAvatar(room);
    $('#who').textContent = room.name;
    const isOwner = room.owner_id === account.id;
    $('#shareInvite').hidden = room.is_permanent || !isOwner || !room.inviteCode;
    $('#members').hidden = room.is_permanent || !isOwner;
    $('#roomOptions').hidden = room.is_permanent || !isOwner;
    $('#endRoom').hidden = room.is_permanent || !isOwner;
    $('#blockContact').hidden = !room.is_permanent;
    $('#removeContact').hidden = !room.is_permanent;
    const keyReady = Boolean(roomKey(room.id, room.epoch));
    $('#t').disabled = !keyReady;
    $('#attach').disabled = !keyReady;
    $('#f').querySelector('.send').disabled = !keyReady;
    if (!keyReady) {
      $('#msgs').replaceChildren();
      addText($('#msgs'), 'Waiting for the host to authorize this device with a new conversation key.', 'hint');
      if (isOwner) addText($('#msgs'), 'New participants are waiting for a key rotation.', 'status');
      if (matchMedia('(max-width:820px)').matches) {
        setView('chat');
        if (historyPush) history.pushState({ view: 'chat' }, '');
      }
      return;
    }
    renderList();
    try {
      await renderMessages(room);
    } catch (error) {
      $('#msgs').replaceChildren();
      addText($('#msgs'), error.message, 'hint');
    }
    if (matchMedia('(max-width:820px)').matches) {
      setView('chat');
      if (historyPush) history.pushState({ view: 'chat' }, '');
    }
  }

  function refreshRooms() {
    if (roomRefreshPromise) {
      queuedRoomRefresh = true;
      return roomRefreshPromise;
    }
    roomRefreshPromise = (async () => {
      do {
        queuedRoomRefresh = false;
        await refreshRoomsImpl();
      } while (queuedRoomRefresh);
    })();
    return roomRefreshPromise.finally(() => { roomRefreshPromise = null; });
  }

  async function refreshRoomsImpl() {
    const previous = new Map(rooms);
    const latest = await api('/api/rooms');
    const latestIds = new Set(latest.map(room => room.id));
    for (const [roomId] of previous) {
      if (latestIds.has(roomId)) continue;
      if (currentRoomId === roomId) {
        activeSendCancel?.();
        activeDownload?.abort();
        if ($('#viewer').open) closeViewer();
      }
      roomKeys.delete(roomId);
      messageFingerprints.delete(roomId);
      for (const [mediaId, cached] of mediaCache) {
        if (cached.roomId === roomId) {
          URL.revokeObjectURL(cached.url);
          mediaCache.delete(mediaId);
        }
      }
    }
    rooms.clear();
    for (const room of latest) {
      room.members = room.members.map(member => ({
        ...member,
        publicKey: typeof member.publicKey === 'string' ? JSON.parse(member.publicKey) : member.publicKey
      }));
      rooms.set(room.id, room);
      const old = previous.get(room.id);
      const oldPackages = old?.keyPackages || [];
      const samePackages = oldPackages.length === room.keyPackages.length &&
        oldPackages.every((item, index) => item.epoch === room.keyPackages[index].epoch &&
          item.ciphertext === room.keyPackages[index].ciphertext);
      if (!samePackages || !roomKeys.has(room.id)) {
        try {
          await unwrapPackages(room);
        } catch (error) {
          console.error('Room key package could not be opened:', error.message);
          roomKeys.delete(room.id);
        }
      }
      const roomNeedingRotation = [...rooms.values()].find(room =>
        room.owner_id === account.id && room.epoch > 0 && room.key_count < room.member_count
      );
      if (roomNeedingRotation && roomKey(roomNeedingRotation.id, roomNeedingRotation.epoch)) {
        try {
          const nextEpoch = roomNeedingRotation.epoch + 1;
          const keyBytes = randomBytes(32);
          try {
            const packages = await packageRoomKey(roomNeedingRotation.id, nextEpoch, keyBytes, roomNeedingRotation.members);
            await api(`/api/rooms/${encodeURIComponent(roomNeedingRotation.id)}/rotate`, jsonOptions({
              removeUserIds: [],
              packages
            }));
          } finally {
            keyBytes.fill(0);
          }
          return refreshRoomsImpl();
        } catch (error) {
          console.error('Could not authorize pending participants:', error.message);
          toast('A participant is waiting, but key rotation failed. Retry after reconnecting.');
        }
      }
    }
    renderList();
    if (currentRoomId && !rooms.has(currentRoomId)) currentRoomId = null;
    if (!currentRoomId && rooms.size && !suppressRoomAutoSelect) {
      currentRoomId = rooms.keys().next().value;
      $('.owner-controls').hidden = false;
      updateAvatar(currentRoom());
      $('#who').textContent = currentRoom().name;
      renderList();
    }
    if (!currentRoomId) {
      $('#who').textContent = '';
      $('#hav').style.display = 'none';
      $('.owner-controls').hidden = true;
      $('#msgs').replaceChildren();
      addText($('#msgs'), suppressRoomAutoSelect
        ? 'Choose a conversation to continue.'
        : 'Start a temporary, end-to-end encrypted conversation.', 'hint');
      $('#t').disabled = true;
      $('#attach').disabled = true;
      $('#f').querySelector('.send').disabled = true;
    } else {
      const room = currentRoom();
      updateAvatar(room);
      $('#who').textContent = room.name;
      const isOwner = room.owner_id === account.id;
      $('#shareInvite').hidden = room.is_permanent || !isOwner || !room.inviteCode;
      $('#members').hidden = room.is_permanent || !isOwner;
      $('#roomOptions').hidden = room.is_permanent || !isOwner;
      $('#endRoom').hidden = room.is_permanent || !isOwner;
      $('#blockContact').hidden = !room.is_permanent;
      $('#removeContact').hidden = !room.is_permanent;
      const keyReady = Boolean(roomKey(room.id, room.epoch));
      $('#t').disabled = !keyReady;
      $('#attach').disabled = !keyReady;
      $('#f').querySelector('.send').disabled = !keyReady;
      if (!keyReady) {
        $('#msgs').replaceChildren();
        addText($('#msgs'), 'Waiting for the host to authorize this device with a new conversation key.', 'hint');
      }
      if (keyReady) {
        const messages = await api(`/api/rooms/${encodeURIComponent(room.id)}/messages`);
        const fingerprint = `${room.epoch}:${messages.length}:${messages.at(-1)?.id || ''}`;
        if (messageFingerprints.get(room.id) !== fingerprint) await renderMessages(room);
      }
    }
    renderAccountControls();
  }

  function renderComposerPreview() {
    const preview = $('#selectedPreview');
    preview.replaceChildren();
    preview.hidden = !selectedFiles.length;
    selectedFiles.forEach((entry, index) => {
      const card = document.createElement('div');
      card.className = 'preview-card';
      if (entry.type.startsWith('image/') || entry.type.startsWith('video/')) {
        const media = entry.type.startsWith('image/') ? document.createElement('img') : document.createElement('video');
        media.src = entry.previewUrl;
        if (media.tagName === 'VIDEO') {
          media.muted = true;
          media.playsInline = true;
        }
        card.append(media);
      } else {
        const label = document.createElement('span');
        label.textContent = entry.name;
        card.append(label);
      }
      const remove = document.createElement('button');
      remove.type = 'button';
      remove.className = 'remove';
      remove.innerHTML = '<svg class="ico" aria-hidden="true"><use href="#icon-x"/></svg>';
      remove.setAttribute('aria-label', `Remove ${entry.name}`);
      remove.onclick = () => {
        URL.revokeObjectURL(entry.previewUrl);
        selectedFiles.splice(index, 1);
        renderComposerPreview();
      };
      card.append(remove);
      preview.append(card);
    });
  }

  function clearSelected() {
    for (const entry of selectedFiles) URL.revokeObjectURL(entry.previewUrl);
    selectedFiles = [];
    renderComposerPreview();
  }

  async function detectFormat(file) {
    const bytes = new Uint8Array(await file.slice(0, 16).arrayBuffer());
    if (bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) return 'image/jpeg';
    if (bytes[0] === 0x89 && String.fromCharCode(...bytes.slice(1, 4)) === 'PNG') return 'image/png';
    const head = String.fromCharCode(...bytes.slice(0, 6));
    if (head === 'GIF87a' || head === 'GIF89a') return 'image/gif';
    if (String.fromCharCode(...bytes.slice(0, 4)) === 'RIFF' &&
        String.fromCharCode(...bytes.slice(8, 12)) === 'WEBP') return 'image/webp';
    if (String.fromCharCode(...bytes.slice(4, 8)) === 'ftyp') return 'video/mp4';
    if (bytes[0] === 0x1a && bytes[1] === 0x45 && bytes[2] === 0xdf && bytes[3] === 0xa3) return 'video/webm';
    return null;
  }

  function checkVideoDuration(file) {
    return new Promise((resolve, reject) => {
      const url = URL.createObjectURL(file);
      const video = document.createElement('video');
      video.preload = 'metadata';
      video.onloadedmetadata = () => {
        const seconds = video.duration;
        URL.revokeObjectURL(url);
        video.remove();
        if (!Number.isFinite(seconds) || seconds > maxVideoSeconds) {
          reject(new Error(`Video exceeds the ${maxVideoSeconds}-second limit.`));
        } else resolve(seconds);
      };
      video.onerror = () => {
        URL.revokeObjectURL(url);
        video.remove();
        reject(new Error('The video could not be decoded by this browser.'));
      };
      video.src = url;
    });
  }

  async function selectFiles(files) {
    if (!currentRoom()) return toast('Open a conversation before attaching media.');
    try {
      if (selectedFiles.length + files.length > 10) throw new Error('Choose no more than 10 media files in one message.');
      for (const file of files) {
        if (file.size > maxFileBytes) throw new Error(`${file.name} exceeds the 50 MiB file limit.`);
        let mime = await detectFormat(file);
        if (!mime && (file.type.startsWith('image/') || file.type.startsWith('video/'))) {
          throw new Error(`${file.name} is not a supported image or video format.`);
        }
        if (!mime) mime = /^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/i.test(file.type)
          ? file.type : 'application/octet-stream';
        if (mime.startsWith('video/')) await checkVideoDuration(file);
        selectedFiles.push({ file, name: file.name, type: mime, previewUrl: URL.createObjectURL(file) });
      }
      renderComposerPreview();
      if (selectedFiles.some(entry => entry.type === 'image/gif')) toast('GIF images are shared as a metadata-stripped still image.');
    } catch (error) {
      toast(error.message);
    }
  }

  async function prepareFile(entry) {
    if (!entry.type.startsWith('image/')) return { blob: entry.file, mime: entry.type };
    let bitmap;
    try {
      bitmap = await createImageBitmap(entry.file);
      const canvas = document.createElement('canvas');
      canvas.width = bitmap.width;
      canvas.height = bitmap.height;
      const context = canvas.getContext('2d', { alpha: true });
      context.drawImage(bitmap, 0, 0);
      const blob = await new Promise((resolve, reject) => canvas.toBlob(
        value => value ? resolve(value) : reject(new Error('Could not remove image metadata.')),
        'image/png'
      ));
      if (blob.size > maxFileBytes) throw new Error('The metadata-stripped image exceeds the file-size limit.');
      return { blob, mime: 'image/png' };
    } finally {
      bitmap?.close();
    }
  }

  function xhrUpload(roomId, mediaId, epoch, ciphertext, onProgress) {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      activeUpload = xhr;
      xhr.open('POST', `/api/rooms/${encodeURIComponent(roomId)}/media`);
      xhr.withCredentials = true;
      xhr.setRequestHeader('Content-Type', 'application/octet-stream');
      xhr.setRequestHeader('X-Media-Id', mediaId);
      xhr.setRequestHeader('X-Media-Epoch', String(epoch));
      xhr.upload.onprogress = event => {
        if (event.lengthComputable) onProgress(Math.round(event.loaded / event.total * 100));
      };
      xhr.onload = () => {
        activeUpload = null;
        if (xhr.status >= 200 && xhr.status < 300) resolve();
        else {
          let message = 'Encrypted media upload failed.';
          try { message = JSON.parse(xhr.responseText).error || message; } catch {}
          reject(new Error(message));
        }
      };
      xhr.onerror = () => { activeUpload = null; reject(new Error('Network error while uploading encrypted media.')); };
      xhr.onabort = () => { activeUpload = null; reject(new DOMException('Upload canceled.', 'AbortError')); };
      xhr.send(ciphertext);
    });
  }

  async function deleteUploaded(roomId, ids) {
    await Promise.allSettled(ids.map(id => api(
      `/api/rooms/${encodeURIComponent(roomId)}/media/${encodeURIComponent(id)}`,
      { method: 'DELETE' }
    )));
  }

  function setTransferStatus(label, percent, cancel) {
    const status = $('#composerStatus');
    status.replaceChildren();
    status.hidden = !label;
    if (!label) return;
    const text = document.createElement('span');
    text.textContent = label;
    status.append(text);
    if (Number.isFinite(percent)) {
      const progress = document.createElement('progress');
      progress.max = 100;
      progress.value = percent;
      status.append(progress);
    }
    if (cancel) {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'linkbtn';
      button.textContent = 'Cancel';
      button.onclick = cancel;
      status.append(button);
    }
  }

  async function sendCurrent() {
    const room = currentRoom();
    if (!room) return;
    if (activeSendCancel) return toast('A transfer is already in progress.');
    const text = $('#t').value.trim();
    if (!text && !selectedFiles.length) return;
    const epoch = room.epoch;
    const uploaded = [];
    const media = [];
    let cancelled = false;
    const cancel = () => { cancelled = true; activeUpload?.abort(); };
    activeSendCancel = cancel;
    const checkCancelled = () => {
      if (cancelled) throw new DOMException('Upload canceled.', 'AbortError');
    };
    const status = (label, percent) => setTransferStatus(label, percent, cancel);
    try {
      for (let index = 0; index < selectedFiles.length; index++) {
        const entry = selectedFiles[index];
        status(`Preparing encrypted media ${index + 1} of ${selectedFiles.length}…`);
        const prepared = await prepareFile(entry);
        checkCancelled();
        const plain = new Uint8Array(await prepared.blob.arrayBuffer());
        const digest = base64(new Uint8Array(await crypto.subtle.digest('SHA-256', plain)));
        const keyBytes = randomBytes(32);
        const mediaKey = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt']);
        const id = makeId();
        const iv = randomBytes(12);
        const additionalData = encoder.encode(`${room.id}|${epoch}|${id}|${digest}`);
        const ciphertext = await crypto.subtle.encrypt(
          { name: 'AES-GCM', iv, additionalData },
          mediaKey,
          plain
        );
        plain.fill(0);
        checkCancelled();
        status(`Uploading encrypted media ${index + 1} of ${selectedFiles.length}…`, 0);
        uploaded.push(id);
        await xhrUpload(room.id, id, epoch, ciphertext, value => status(
          `Uploading encrypted media ${index + 1} of ${selectedFiles.length}…`,
          value
        ));
        checkCancelled();
        media.push({
          id,
          name: prepared.mime === 'image/png'
            ? `${entry.name.split(/[\\/]/).pop().replace(/\.[^.]*$/, '')}.png`.slice(0, 120)
            : entry.name.split(/[\\/]/).pop().slice(0, 120),
          mime: prepared.mime,
          size: prepared.blob.size,
          digest,
          key: base64(keyBytes),
          iv: base64(iv)
        });
        keyBytes.fill(0);
      }
      checkCancelled();
      status('Sending end-to-end encrypted message…');
      const payload = media.length
        ? { type: 'media', items: media, ...(text ? { caption: text } : {}) }
        : { type: 'text', text };
      const envelope = await encryptEnvelope(room, epoch, payload);
      await api(`/api/rooms/${encodeURIComponent(room.id)}/messages`, jsonOptions(envelope));
      $('#t').value = '';
      clearSelected();
      setTransferStatus('', NaN);
      if (currentRoomId === room.id) await renderMessages(room);
      renderList();
    } catch (error) {
      if (uploaded.length) await deleteUploaded(room.id, uploaded);
      if (cancelled || error.name === 'AbortError') {
        setTransferStatus('', NaN);
        toast('Transfer canceled.');
        return;
      }
      setTransferStatus(`${error.message} Retry available.`);
      const retry = document.createElement('button');
      retry.type = 'button';
      retry.className = 'linkbtn';
      retry.textContent = 'Retry';
      retry.onclick = () => { setTransferStatus('', NaN); sendCurrent(); };
      $('#composerStatus').append(retry);
    } finally {
      if (activeSendCancel === cancel) activeSendCancel = null;
    }
  }

  async function readCiphertext(roomId, mediaId, onProgress, signal) {
    const response = await fetch(
      `/api/rooms/${encodeURIComponent(roomId)}/media/${encodeURIComponent(mediaId)}`,
      { credentials: 'same-origin', signal }
    );
    if (!response.ok) {
      throw new Error(response.status === 404 ? 'Media is no longer available.' : 'Encrypted media download failed.');
    }
    const total = Number(response.headers.get('content-length')) || 0;
    if (!response.body) {
      const data = await response.arrayBuffer();
      onProgress(100);
      return data;
    }
    const reader = response.body.getReader();
    const parts = [];
    let loaded = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        parts.push(value);
        loaded += value.length;
        if (total) onProgress(Math.round(loaded / total * 100));
      }
    } finally {
      reader.releaseLock();
    }
    const joined = new Uint8Array(loaded);
    let offset = 0;
    for (const part of parts) {
      joined.set(part, offset);
      offset += part.length;
    }
    onProgress(100);
    return joined.buffer;
  }

  async function decryptMedia(room, item, epoch, onProgress, signal) {
    const encrypted = await readCiphertext(room.id, item.id, onProgress, signal);
    const key = await crypto.subtle.importKey('raw', fromBase64(item.key), { name: 'AES-GCM' }, false, ['decrypt']);
    const additionalData = encoder.encode(`${room.id}|${epoch}|${item.id}|${item.digest}`);
    const clear = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: fromBase64(item.iv), additionalData },
      key,
      encrypted
    );
    const digest = base64(new Uint8Array(await crypto.subtle.digest('SHA-256', clear)));
    if (digest !== item.digest) throw new Error('Media integrity verification failed.');
    return new Blob([clear], { type: item.mime });
  }

  function safeFilename(name) {
    const cleaned = String(name || 'shared-media').replace(/[\\/\u0000-\u001f\u007f]/g, '_').slice(0, 120);
    return cleaned || 'shared-media';
  }

  function saveBlob(blob, name) {
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = safeFilename(name);
    anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 60000);
  }

  async function loadMedia(button, download) {
    const item = JSON.parse(button.dataset.media);
    const room = rooms.get(button.dataset.room);
    const epoch = Number(button.dataset.epoch);
    if (!room) return;
    const cached = mediaCache.get(item.id);
    if (cached) {
      if (download) saveBlob(cached.blob, item.name);
      else if (cached.mime.startsWith('image/')) openViewer(cached.url, 'image');
      else if (cached.mime.startsWith('video/')) openViewer(cached.url, 'video');
      else saveBlob(cached.blob, item.name);
      return;
    }
    const card = button.closest('.media-card');
    const status = addText(card, 'Downloading and decrypting…', 'transfer');
    const progress = document.createElement('progress');
    progress.max = 100;
    progress.value = 0;
    status.append(progress);
    activeDownload = new AbortController();
    const controller = activeDownload;
    const cancel = document.createElement('button');
    cancel.type = 'button';
    cancel.className = 'linkbtn';
    cancel.textContent = 'Cancel';
    cancel.onclick = () => controller.abort();
    status.append(cancel);
    button.disabled = true;
    try {
      const blob = await decryptMedia(room, item, epoch, value => { progress.value = value; }, controller.signal);
      const url = URL.createObjectURL(blob);
      mediaCache.set(item.id, { url, blob, mime: item.mime, roomId: room.id });
      if (download) saveBlob(blob, item.name);
      else if (item.mime.startsWith('image/')) openViewer(url, 'image');
      else if (item.mime.startsWith('video/')) openViewer(url, 'video');
      else saveBlob(blob, item.name);
      await renderMessages(room);
    } catch (error) {
      if (error.name !== 'AbortError') toast(error.message);
      button.disabled = false;
      status.textContent = error.name === 'AbortError'
        ? 'Download canceled. Retry available.'
        : `${error.message} Retry available.`;
    } finally {
      if (activeDownload === controller) activeDownload = null;
    }
  }

  function openViewer(url, type) {
    $('#viewerImage').hidden = type !== 'image';
    $('#viewerVideo').hidden = type !== 'video';
    if (type === 'image') $('#viewerImage').src = url;
    else {
      $('#viewerVideo').src = url;
      $('#viewerVideo').play().catch(() => {});
    }
    $('#viewer').showModal();
  }

  function closeViewer() {
    $('#viewerVideo').pause();
    $('#viewerVideo').removeAttribute('src');
    $('#viewer').close();
  }

  async function completeAuthentication(user, passphrase) {
    const bundle = typeof user.privateBundle === 'string' ? JSON.parse(user.privateBundle) : user.privateBundle;
    privateKey = await unlockIdentity(passphrase, bundle);
    account = {
      id: user.id,
      username: user.username,
      publicKey: typeof user.publicKey === 'string' ? JSON.parse(user.publicKey) : user.publicKey
    };
    $('#authPassword').value = '';
    $('#vaultPassphrase').value = '';
    pendingUser = null;
    unlockOnly = false;
    $('#authDialog').close();
    suppressRoomAutoSelect = false;
    await refreshRooms();
    clearInterval(pollTimer);
    pollTimer = setInterval(() => refreshRooms().catch(error => console.error('Conversation refresh failed:', error.message)), 5000);
  }

  function setAuthMode(mode, user = null) {
    registerMode = mode === 'register';
    unlockOnly = mode === 'unlock';
    pendingUser = unlockOnly ? user : null;
    const unlocking = unlockOnly;
    $('#authUser').hidden = unlocking;
    $('#authUser').disabled = unlocking;
    $('#authUser').required = !unlocking;
    $('#authPassword').hidden = unlocking;
    $('#authPassword').disabled = unlocking;
    $('#authPassword').required = !unlocking;
    $('#authIdentity').hidden = !unlocking;
    $('#authIdentity').textContent = unlocking ? `Signed in as ${user.username}` : '';
    $('#authTitle').textContent = unlocking
      ? 'Unlock your encryption key'
      : registerMode ? 'Create account' : 'Sign in';
    $('#authHelp').textContent = unlocking
      ? 'Your account session was restored. Enter your encryption passphrase to unlock this device’s private key. The passphrase is never sent to the server.'
      : 'Your encryption passphrase unlocks this device’s private key and is never sent to the server. Use a different password for your account and encryption passphrase.';
    $('#authSubmit').textContent = unlocking ? 'Unlock' : registerMode ? 'Create account' : 'Sign in';
    $('#authPassword').autocomplete = registerMode ? 'new-password' : 'current-password';
    $('#authMode').hidden = unlocking;
    $('#authMode').textContent = registerMode ? 'Already registered? Sign in' : 'Need an account? Register';
    $('#authStatus').textContent = '';
  }

  async function submitAuth(event) {
    event.preventDefault();
    const button = $('#authSubmit');
    const status = $('#authStatus');
    button.disabled = true;
    status.textContent = unlockOnly ? 'Unlocking this device…' : registerMode ? 'Creating protected account…' : 'Signing in…';
    try {
      const passphrase = $('#vaultPassphrase').value;
      let user = pendingUser;
      if (!unlockOnly) {
        const username = $('#authUser').value.trim().toLowerCase();
        const password = $('#authPassword').value;
        if (password === passphrase) throw new Error('Use different account and encryption passphrases.');
        if (registerMode) {
          if (password.length < 12 || passphrase.length < 12) throw new Error('Both passwords must be 12 or more characters.');
          const identity = await createIdentity(passphrase);
          user = await api('/api/register', jsonOptions({ username, password, ...identity }));
        } else {
          user = await api('/api/login', jsonOptions({ username, password }));
        }
      }
      if (!user) {
        throw new Error('The restored account is unavailable. Sign in again to continue.');
      }
      await completeAuthentication(user, passphrase);
    } catch (error) {
      status.textContent = error.message;
      $('#vaultPassphrase').value = '';
    } finally {
      button.disabled = false;
    }
  }

  async function restoreAuthentication() {
    try {
      const user = await api('/api/me');
      setAuthMode('unlock', user);
      $('#vaultPassphrase').focus();
    } catch (error) {
      setAuthMode('signin');
      if (error.status !== 401) {
        $('#authStatus').textContent = `Could not restore the signed-in account: ${error.message}`;
      }
      $('#authUser').focus();
    }
  }

  function settingsRow(container, name, detail, actions) {
    const row = document.createElement('div');
    row.className = 'settings-row';
    const label = document.createElement('span');
    label.textContent = name;
    const description = document.createElement('small');
    description.textContent = detail;
    label.append(description);
    row.append(label);
    for (const [text, handler] of actions) {
      const button = document.createElement('button');
      button.type = 'button';
      button.textContent = text;
      button.addEventListener('click', handler);
      row.append(button);
    }
    container.append(row);
  }

  function setAccountIdVisible(visible) {
    accountIdVisible = visible;
    $('#settingsAccountId').textContent = visible ? account.id : '••••••••••••••••';
    $('#revealAccountId').textContent = visible ? 'Hide ID' : 'Show ID';
    $('#copySettingsId').hidden = !visible;
  }

  async function loadSettings() {
    setAccountIdVisible(false);
    $('#settingsContacts').replaceChildren();
    $('#settingsBlocks').replaceChildren();
    const [contacts, blocked] = await Promise.all([
      api('/api/contacts'),
      api('/api/blocks')
    ]);
    const blockedIds = new Set(blocked.map(item => item.id));
    if (!contacts.length) addText($('#settingsContacts'), 'No permanent contacts yet.', 'settings-empty');
    for (const contact of contacts) {
      const room = [...rooms.values()].find(item =>
        item.is_permanent && item.members.some(member => member.id === contact.id)
      );
      const actions = [];
      if (room && !blockedIds.has(contact.id)) {
        actions.push(['Open chat', () => {
          $('#settingsDialog').close();
          openRoom(room.id);
        }]);
      }
      actions.push(['Remove', async () => {
        if (!confirm(`Remove ${contact.username} and delete this permanent chat for both people?`)) return;
        try {
          await api(`/api/contacts/${encodeURIComponent(contact.id)}`, { method: 'DELETE' });
          if (room) roomKeys.delete(room.id);
          await refreshRooms();
          await loadSettings();
          toast('Contact and encrypted chat removed.');
        } catch (error) {
          toast(error.message);
        }
      }]);
      if (!blockedIds.has(contact.id)) {
        actions.push(['Block', async () => {
          try {
            await api(`/api/blocks/${encodeURIComponent(contact.id)}`, { method: 'POST' });
            await refreshRooms();
            await loadSettings();
            toast('Contact blocked.');
          } catch (error) {
            toast(error.message);
          }
        }]);
      }
      settingsRow($('#settingsContacts'), contact.username, contact.id, actions);
    }
    if (!blocked.length) addText($('#settingsBlocks'), 'No blocked accounts.', 'settings-empty');
    for (const item of blocked) {
      settingsRow($('#settingsBlocks'), item.username, item.id, [['Unblock', async () => {
        try {
          await api(`/api/blocks/${encodeURIComponent(item.id)}`, { method: 'DELETE' });
          await refreshRooms();
          await loadSettings();
          toast('Account unblocked.');
        } catch (error) {
          toast(error.message);
        }
      }]]);
    }
  }

  async function addContact(event) {
    event.preventDefault();
    const form = $('#addContactForm');
    const button = form.querySelector('button[type="submit"], .go');
    button.disabled = true;
    let room;
    try {
      room = await api('/api/contacts', jsonOptions({ userId: $('#contactUserId').value.trim() }));
      room.members = room.members.map(member => ({
        ...member,
        publicKey: typeof member.publicKey === 'string' ? JSON.parse(member.publicKey) : member.publicKey
      }));
      const keyBytes = randomBytes(32);
      try {
        const packages = await packageRoomKey(room.id, 1, keyBytes, room.members);
        await api(`/api/rooms/${encodeURIComponent(room.id)}/keys`, jsonOptions({ packages }));
      } finally {
        keyBytes.fill(0);
      }
      $('#contactUserId').value = '';
      $('#settingsDialog').close();
      await refreshRooms();
      await openRoom(room.id);
      toast('Permanent end-to-end encrypted chat created.');
    } catch (error) {
      if (room?.members) {
        await api(`/api/contacts/${encodeURIComponent(room.members.find(member => member.id !== account.id)?.id)}`, {
          method: 'DELETE'
        }).catch(() => {});
      }
      toast(error.message);
    } finally {
      button.disabled = false;
    }
  }

  async function blockCurrentContact() {
    const room = currentRoom();
    const contact = room?.members.find(member => member.id !== account.id);
    if (!room?.is_permanent || !contact || !confirm('Block this person? Both of you will lose access to this permanent chat.')) return;
    try {
      await api(`/api/blocks/${encodeURIComponent(contact.id)}`, jsonOptions({}));
      await refreshRooms();
      toast('Contact blocked. Manage blocked accounts in Settings & contacts.');
    } catch (error) {
      toast(error.message);
    }
  }

  async function removeCurrentContact() {
    const room = currentRoom();
    const contact = room?.members.find(member => member.id !== account.id);
    if (!room?.is_permanent || !contact || !confirm('Remove this contact and delete the permanent chat for both people?')) return;
    try {
      await api(`/api/contacts/${encodeURIComponent(contact.id)}`, { method: 'DELETE' });
      roomKeys.delete(room.id);
      await refreshRooms();
      toast('Contact and encrypted chat removed.');
    } catch (error) {
      toast(error.message);
    }
  }

  async function createRoom(event) {
    event.preventDefault();
    const button = $('#df').querySelector('.go');
    button.disabled = true;
    try {
      if (joinMode) {
        const code = $('#joinCode').value.trim();
        const result = await api(`/api/invites/${encodeURIComponent(code)}/join`, jsonOptions({}));
        $('#dlg').close();
        $('#joinCode').value = '';
        await refreshRooms();
        await openRoom(result.roomId);
        if (result.waitingForKeyRotation) toast('You joined. Waiting for the host to create a fresh conversation key.');
        return;
      }
      const room = await api('/api/rooms', jsonOptions({
        name: $('#roomName').value.trim(),
        maxMembers: Number($('#maxMembers').value),
        clearOnEnd: true
      }));
      room.members = room.members.map(member => ({
        ...member,
        publicKey: typeof member.publicKey === 'string' ? JSON.parse(member.publicKey) : member.publicKey
      }));
      const keyBytes = randomBytes(32);
      const packages = await packageRoomKey(room.id, 1, keyBytes, room.members);
      try {
        await api(`/api/rooms/${encodeURIComponent(room.id)}/keys`, jsonOptions({ packages }));
      } catch (error) {
        await api(`/api/rooms/${encodeURIComponent(room.id)}`, { method: 'DELETE' }).catch(() => {});
        throw error;
      } finally {
        keyBytes.fill(0);
      }
      $('#dlg').close();
      await refreshRooms();
      await openRoom(room.id);
      toast('Conversation created. Use Share ID when you are ready to invite people.');
    } catch (error) {
      toast(error.message);
    } finally {
      button.disabled = false;
    }
  }

  function openMembersDialog() {
    const room = currentRoom();
    if (!room || room.owner_id !== account.id) return;
    const select = $('#removeMember');
    select.replaceChildren();
    for (const [index, member] of room.members.entries()) {
      if (member.id === account.id) continue;
      const option = document.createElement('option');
      option.value = member.id;
      option.textContent = `Participant ${index + 1}`;
      select.append(option);
    }
    if (!select.options.length) return toast('No other participants have joined yet.');
    $('#membersDialog').showModal();
  }

  async function rotateMembers(event) {
    event.preventDefault();
    const room = currentRoom();
    const removeId = $('#removeMember').value;
    const removals = [removeId];
    if (!room || room.owner_id !== account.id || !room.members.some(member => member.id === removeId)) return;
    try {
      const next = room.members.filter(member => !removals.includes(member.id));
      if (!next.length) throw new Error('The session must keep its owner.');
      const epoch = room.epoch + 1;
      const keyBytes = randomBytes(32);
      let rotation;
      try {
        const packages = await packageRoomKey(room.id, epoch, keyBytes, next);
        rotation = await api(`/api/rooms/${encodeURIComponent(room.id)}/rotate`, jsonOptions({
          removeUserIds: removals,
          packages
        }));
      } finally {
        keyBytes.fill(0);
      }
      $('#membersDialog').close();
      await refreshRooms();
      toast('Participants removed and the conversation key rotated.');
      if (rotation.inviteCode) showInviteCode(rotation.inviteCode);
    } catch (error) {
      toast(error.message);
    }
  }

  function endRoom() {
    const room = currentRoom();
    if (!room || room.owner_id !== account.id) return;
    $('#endRoomDialog h2').textContent = 'End and delete this conversation?';
    $('#endRoomMessage').textContent = 'This immediately deletes server-held messages, encrypted media, the invite ID, and key packages. Copies participants already saved cannot be remotely erased.';
    $('#endRoomConfirm').textContent = 'End and delete now';
    $('#endRoomDialog').showModal();
  }

  async function confirmEndRoom() {
    const room = currentRoom();
    if (!room || room.owner_id !== account.id) return;
    const button = $('#endRoomConfirm');
    button.disabled = true;
    activeSendCancel?.();
    activeDownload?.abort();
    try {
      await api(`/api/rooms/${encodeURIComponent(room.id)}`, { method: 'DELETE' });
      $('#endRoomDialog').close();
      forgetRoom(room.id);
      rooms.delete(room.id);
      await refreshRooms();
      toast('Conversation ended and server-held data deleted.');
    } catch (error) {
      toast(error.message);
    } finally {
      button.disabled = false;
    }
  }

  async function signOut() {
    const button = $('#signOutConfirm');
    button.disabled = true;
    try {
      await api('/api/logout', { method: 'POST' });
    } catch (error) {
      toast(error.message);
      return;
    } finally {
      button.disabled = false;
    }
    $('#signOutDialog').close();
    clearInterval(pollTimer);
    account = null;
    privateKey = null;
    rooms.clear();
    roomKeys.clear();
    messageFingerprints.clear();
    for (const item of mediaCache.values()) URL.revokeObjectURL(item.url);
    mediaCache.clear();
    clearSelected();
    currentRoomId = null;
    suppressRoomAutoSelect = false;
    $('#accountMeta').textContent = 'Sign in to access private conversations.';
    delete $('#accountMeta').dataset.userId;
    $('#openSettings').hidden = true;
    renderList();
    $('#msgs').replaceChildren();
    $('#who').textContent = '';
    $('#hav').style.display = 'none';
    $('.owner-controls').hidden = true;
    $('#t').disabled = true;
    $('#attach').disabled = true;
    $('#f').querySelector('.send').disabled = true;
    $('#authDialog').showModal();
    setAuthMode('signin');
  }

  function replaceLegacyForm(id, handler) {
    const oldForm = $('#'+id);
    const form = oldForm.cloneNode(true);
    oldForm.replaceWith(form);
    form.addEventListener('submit', handler);
    return form;
  }

  function setDialogMode(join) {
    joinMode = join;
    $('#joinFields').hidden = !join;
    $('#createFields').hidden = join;
    $('#roomDialogTitle').textContent = join ? 'Join a temporary conversation' : 'Create a temporary conversation';
    $('#roomDialogHelp').textContent = join
      ? 'Paste the temporary ID shared by the host. You need an account to join; the ID alone cannot open messages or media.'
      : 'Choose a private name and participant limit. The temporary invite ID is only shown when you choose to share it.';
    $('#roomName').required = !join;
    $('#roomName').disabled = join;
    $('#maxMembers').required = !join;
    $('#maxMembers').disabled = join;
    $('#roomAction').textContent = join ? 'Join conversation' : 'Create temporary ID';
    $('#dialogMode').textContent = join ? 'Create a new session instead' : 'Have an ID? Join instead';
    if (join) $('#joinCode').focus();
  }

  function showInviteCode(code) {
    if (!code) return;
    $('#inviteCodeText').textContent = code;
    $('#inviteDialog').showModal();
  }

  document.addEventListener('click', event => {
    if (!event.target.closest('#attachMenu, #attach')) setAttachMenuOpen(false);
    if (!event.target.closest('#roomMenu, #roomOptions')) setRoomMenuOpen(false);
    const roomButton = event.target.closest('[data-room]');
    if (roomButton) {
      openRoom(roomButton.dataset.room);
      return;
    }
    const picker = event.target.closest('[data-picker]');
    if (picker) {
      setAttachMenuOpen(false);
      $('#'+picker.dataset.picker).click();
      return;
    }
    if (event.target.closest('[data-menu-close]')) {
      setAttachMenuOpen(false);
      return;
    }
    const action = event.target.closest('[data-action]');
    if (action?.dataset.action === 'load-media') loadMedia(action, false);
    if (action?.dataset.action === 'download-media') loadMedia(action, true);
  });

  const legacySearch = $('#q');
  const search = legacySearch.cloneNode(true);
  legacySearch.replaceWith(search);
  search.addEventListener('input', event => {
    filter = event.target.value.trim().toLowerCase();
    renderList();
  });

  $('#newbtn').addEventListener('click', event => {
    event.stopPropagation();
    if (!account) return toast('Sign in to create a conversation.');
    setDialogMode(false);
    $('#dlg').showModal();
  });
  $('#joinbtn').addEventListener('click', event => {
    event.stopPropagation();
    if (!account) return toast('Sign in to join a conversation.');
    setDialogMode(true);
    $('#joinCode').value = '';
    $('#dlg').showModal();
  });
  $('#back').onclick = () => history.back();
  addEventListener('popstate', () => {
    if (currentRoomId) leaveCurrentRoom();
    else setView('list');
  });
  addEventListener('resize', () => { if (!matchMedia('(max-width:820px)').matches) setView('list'); });
  replaceLegacyForm('df', createRoom);
  $('#dc').onclick = () => $('#dlg').close();
  $('#dialogMode').onclick = () => setDialogMode(!joinMode);
  replaceLegacyForm('f', event => {
    event.preventDefault();
    sendCurrent();
  });
  $('#members').onclick = openMembersDialog;
  $('#membersCancel').onclick = () => $('#membersDialog').close();
  $('#membersForm').addEventListener('submit', rotateMembers);
  $('#endRoom').onclick = endRoom;
  $('#leaveRoom').onclick = () => leaveCurrentRoom(true);
  $('#endRoomCancel').onclick = () => $('#endRoomDialog').close();
  $('#endRoomConfirm').onclick = confirmEndRoom;
  $('#roomOptions').onclick = () => setRoomMenuOpen($('#roomMenu').hidden);
  $('#shareInvite').onclick = () => {
    const room = currentRoom();
    if (room?.inviteCode) showInviteCode(room.inviteCode);
  };
  $('#inviteClose').onclick = () => $('#inviteDialog').close();
  $('#copyInvite').onclick = async () => {
    try {
      await navigator.clipboard.writeText($('#inviteCodeText').textContent);
      $('#inviteDialog').close();
      toast('Temporary conversation ID copied.');
    } catch {
      toast('Copy was blocked. Select the temporary ID and copy it manually.');
    }
  };
  $('#attach').onclick = () => {
    setAttachMenuOpen($('#attachMenu').hidden);
  };
  document.addEventListener('keydown', event => {
    if (event.key === 'Escape' && !$('#attachMenu').hidden) setAttachMenuOpen(false);
    if (event.key === 'Escape' && !$('#roomMenu').hidden) setRoomMenuOpen(false);
  });
  for (const id of ['photoInput', 'videoInput', 'fileInput']) {
    $('#'+id).addEventListener('change', event => {
      selectFiles([...event.target.files]);
      event.target.value = '';
    });
  }
  $('#authMode').onclick = () => {
    setAuthMode(registerMode ? 'signin' : 'register');
  };
  $('#authForm').addEventListener('submit', submitAuth);
  $('#settingsClose').onclick = () => $('#settingsDialog').close();
  $('#settingsSignOut').onclick = () => {
    $('#settingsDialog').close();
    $('#signOutDialog').showModal();
  };
  $('#settingsDialog').addEventListener('close', () => setAccountIdVisible(false));
  $('#addContactForm').addEventListener('submit', addContact);
  $('#blockContact').onclick = blockCurrentContact;
  $('#removeContact').onclick = removeCurrentContact;
  $('#copySettingsId').onclick = async () => {
    if (!accountIdVisible) return;
    try {
      await navigator.clipboard.writeText(account.id);
      toast('Permanent account ID copied.');
    } catch {
      toast('Copy was blocked. Select the account ID and copy it manually.');
    }
  };
  $('#viewerClose').onclick = closeViewer;
  $('#viewer').addEventListener('click', event => { if (event.target === $('#viewer')) closeViewer(); });

  $('#openSettings').addEventListener('click', () => {
    if (!account) return;
    $('#settingsDialog').showModal();
    loadSettings().catch(error => toast(error.message));
  });
  $('#revealAccountId').onclick = () => setAccountIdVisible(!accountIdVisible);
  $('#signOutCancel').onclick = () => $('#signOutDialog').close();
  $('#signOutConfirm').onclick = signOut;
  $('#t').disabled = true;
  $('#attach').disabled = true;
  $('#f').querySelector('.send').disabled = true;
  $('#authForm').reset();
  setAuthMode('signin');
  $('#authTitle').textContent = 'Checking sign-in…';
  $('#authHelp').textContent = 'Checking whether this device still has a signed-in account.';
  $('#authDialog').showModal();
  restoreAuthentication();
})();
